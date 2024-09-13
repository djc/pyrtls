use std::io::{Cursor, Read, Write};
use std::net::ToSocketAddrs;
use std::sync::Arc;

use pyo3::exceptions::{PyException, PyValueError};
use pyo3::types::{
    PyAnyMethods, PyByteArray, PyByteArrayMethods, PyBytes, PyTuple, PyTupleMethods,
};
use pyo3::{pyclass, pymethods, Bound, PyAny, PyResult, Python};
use rustls_pemfile::Item;

use crate::{
    extract_alpn_protocols, py_to_cert_der, py_to_key_der, py_to_pem, IoState, SessionState,
    TlsError,
};

/// A `ServerSocket` is a wrapper type that contains both a `socket.socket` and a
/// `ServerConnection` object. It is similar to the `ssl.SSLSocket` class from the
/// standard library and should implement most of the same methods.
#[pyclass]
pub(crate) struct ServerSocket {
    state: SessionState<rustls::ServerConnection>,
}

#[pymethods]
impl ServerSocket {
    /// Bind to the given `address`. `address` must currently be a 2-element tuple
    /// containing a hostname and a port number.
    fn bind(&mut self, address: &Bound<'_, PyTuple>) -> PyResult<()> {
        if address.len() != 2 {
            return Err(PyValueError::new_err(
                "only 2-element address tuples are supported",
            ));
        }

        let host = address.get_item(0)?;
        let host = host.extract::<&str>()?;
        let port = address.get_item(1)?.extract::<u16>()?;
        let addr = match (host, port).to_socket_addrs()?.next() {
            Some(addr) => addr,
            None => {
                return Err(PyValueError::new_err(
                    "unable to convert address to socket address",
                ))
            }
        };

        self.state.socket.bind(&addr.into())?;
        Ok(())
    }

    /// Perform the TLS setup handshake.
    fn do_handshake(&mut self) -> PyResult<()> {
        self.state.do_handshake()
    }

    /// Send data to the socket. The socket must be connected to a remote socket. Returns the
    /// number of bytes sent. Applications are responsible for checking that all data has been
    /// sent; if only some of the data was transmitted, the application needs to attempt delivery
    /// of the remaining data.
    fn send(&mut self, bytes: &Bound<'_, PyBytes>) -> PyResult<usize> {
        self.state.send(bytes)
    }

    /// Receive data from the socket. The return value is a bytes object representing the data
    /// received. The maximum amount of data to be received at once is specified by `size`.
    /// A returned empty bytes object indicates that the client has disconnected.
    fn recv<'p>(&mut self, size: usize, py: Python<'p>) -> PyResult<Bound<'p, PyBytes>> {
        self.state.recv(size, py)
    }
}

/// A `ServerConnection` contains TLS state associated with a single server-side connection.
/// It does not contain any networking state, and is not directly associated with a socket,
/// so I/O happens via the methods on this object directly.
///
/// A `ServerConnection` can be created from a `ServerConfig` `config`.
#[pyclass]
pub(crate) struct ServerConnection {
    inner: rustls::ServerConnection,
}

#[pymethods]
impl ServerConnection {
    #[new]
    fn new(config: &ServerConfig) -> PyResult<Self> {
        Ok(Self {
            inner: rustls::ServerConnection::new(config.inner.clone()).map_err(TlsError::from)?,
        })
    }

    /// Returns `true` if the caller should call `read_tls()` as soon as possible.
    ///
    /// If there is pending plaintext data to read, this returns `false`. If your application
    /// respects this mechanism, only one full TLS message will be buffered by pyrtls.
    fn readable(&self) -> bool {
        self.inner.wants_read()
    }

    /// Read TLS content from `buf` into the internal buffer. Return the number of bytes read, or
    /// `0` once a `close_notify` alert has been received. No additional data is read in this
    /// state.
    ///
    /// Due to internal buffering, `buf` may contain TLS messages in arbitrary-sized chunks (like
    /// a socket or pipe might).
    ///
    /// You should call `process_new_packets()` each time a call to this function succeeds in
    /// order to empty the incoming TLS data buffer.
    ///
    /// Exceptions may be raised to signal backpressure:
    ///
    /// * In order to empty the incoming TLS data buffer, you should call `process_new_packets()`
    ///   each time a call to this function succeeds.
    /// * In order to empty the incoming plaintext data buffer, you should call `read_into()`
    ///   after the call to `process_new_packets()`.
    ///
    /// You should call `process_new_packets()` each time a call to this function succeeds in
    /// order to empty the incoming TLS data buffer
    ///
    /// Mirrors the `RawIO.write()` interface.
    fn read_tls(&mut self, buf: &[u8]) -> PyResult<usize> {
        Ok(self
            .inner
            .read_tls(&mut Cursor::new(buf))
            .map_err(TlsError::from)?)
    }

    /// Processes any new packets read by a previous call to `read_tls()`.
    ///
    /// Errors from this function relate to TLS protocol errors, and are fatal to the connection.
    /// Future calls after an error will do no new work and will return the same error. After an
    /// error is returned from `process_new_packets()`, you should not call `read_tls()` anymore
    /// (it will fill up buffers to no purpose). However, you may call the other methods on the
    /// connection, including `write()` and `write_tls_into()`. Most likely you will want to
    /// call `write_tls_into()` to send any alerts queued by the error and then close the
    /// underlying connection.
    ///
    /// In case of success, yields an `IoState` object with sundry state about the connection.
    fn process_new_packets(&mut self) -> PyResult<IoState> {
        Ok(self
            .inner
            .process_new_packets()
            .map_err(TlsError::from)?
            .into())
    }

    /// Send the plaintext `buf` to the peer, encrypting and authenticating it. Once this
    /// function succeeds you should call `write_tls_into()` which will output the
    /// corresponding TLS records.
    ///
    /// This function buffers plaintext sent before the TLS handshake completes, and sends it as
    /// soon as it can.
    fn write(&mut self, buf: &[u8]) -> PyResult<usize> {
        Ok(self.inner.writer().write(buf).map_err(TlsError::from)?)
    }

    /// Returns `True` if the caller should call `write_tls_into()` as soon as possible.
    fn writable(&self) -> bool {
        self.inner.wants_write()
    }

    /// Writes TLS messages into `buf`.
    ///
    /// On success, this function returns the number of bytes written (after encoding and
    /// encryption).
    ///
    /// After this function returns, the connection buffer may not yet be fully flushed.
    /// `writable()` can be used to check if the output buffer is empty.
    ///
    /// Mirrors the `RawIO.readinto()` interface.
    fn write_tls_into(&mut self, buf: &Bound<'_, PyByteArray>) -> PyResult<usize> {
        let mut buf = unsafe { buf.as_bytes_mut() };
        Ok(self.inner.write_tls(&mut buf).map_err(TlsError::from)?)
    }

    /// Obtain plaintext data received from the peer over this TLS connection.
    ///
    /// If the peer closes the TLS connection cleanly, this returns `0` once all the pending data
    /// has been read. No further data can be received on that connection, so the underlying TCP
    /// connection should be half-closed too.
    ///
    /// If the peer closes the TLS connection uncleanly (a TCP EOF without sending a
    /// `close_notify` alert) this functions raises a `TlsError` exception once any pending data
    /// has been read.
    ///
    /// Note that support for `close_notify` varies in peer TLS libraries: many do not support it
    /// and uncleanly close the TCP connection (this might be vulnerable to truncation attacks
    /// depending on the application protocol). This means applications using pyrtls must both
    /// handle EOF from this function, **and** unexpected EOF of the underlying TCP connection.
    ///
    /// If there are no bytes to read, this raises a `TlsError` exception.
    ///
    /// You may learn the number of bytes available at any time by inspecting the return of
    /// `process_new_packets()`.
    fn read_into(&mut self, buf: &Bound<'_, PyByteArray>) -> PyResult<usize> {
        let buf = unsafe { buf.as_bytes_mut() };
        Ok(self.inner.reader().read(buf).map_err(TlsError::from)?)
    }
}

/// Create a new `ServerConfig` object (similar to `ssl.SSLContext`). A new `ServerConnection` can
/// only be created by passing in a reference to a `ServerConfig` object.
///
/// The important configuration for `ServerConfig` is the certificate to supply to connecting
/// clients, and the private key used to prove ownership of the certificate.
///
/// Positional (mandatory) arguments:
///
/// - `cert_chain`: an iterable, where each value must be of type `bytes` (representing the
///   certificate encoded in DER) or `str` (with the certificate encoded in PEM).
/// - `private_key`: a `bytes` or `str` object, containing the private key encoded in DER or PEM
///   respectively. The private key can be in PKCS#1, PKCS#8, or SEC1 format.
///
/// Other options:
///
/// - `alpn_protocols` must be an iterable containing `bytes` or `str` objects, each representing
///   one ALPN protocol string.
#[pyclass]
pub(crate) struct ServerConfig {
    inner: Arc<rustls::ServerConfig>,
}

#[pymethods]
impl ServerConfig {
    #[new]
    #[pyo3(signature = (cert_chain, private_key, *, alpn_protocols = None))]
    fn new(
        cert_chain: &Bound<'_, PyAny>,
        private_key: &Bound<'_, PyAny>,
        alpn_protocols: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let mut certs = Vec::new();
        for cert in cert_chain.iter()? {
            let cert = cert?;
            if let Ok(cert_der) = py_to_cert_der(&cert) {
                certs.push(cert_der.into_owned());
                continue;
            }

            match py_to_pem(&cert)? {
                Item::X509Certificate(bytes) => certs.push(bytes),
                _ => return Err(PyValueError::new_err("PEM object of invalid type")),
            }
        }

        let key = if let Ok(key_der) = py_to_key_der(private_key) {
            key_der.clone_key()
        } else {
            match py_to_pem(private_key)? {
                Item::Pkcs1Key(key) => key.into(),
                Item::Sec1Key(key) => key.into(),
                Item::Pkcs8Key(key) => key.into(),
                _ => return Err(PyValueError::new_err("PEM object of invalid type")),
            }
        };

        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|err| {
                PyException::new_err(format!("error initializing ServerConfig: {err}"))
            })?;
        config.alpn_protocols = extract_alpn_protocols(alpn_protocols)?;

        Ok(Self {
            inner: Arc::new(config),
        })
    }

    /// Use the `ServerConfig` and the given `sock` to create a `ServerSocket`.
    ///
    /// Returns a `ServerSocket` if successful.
    fn wrap_socket(&self, sock: &Bound<'_, PyAny>) -> PyResult<ServerSocket> {
        let conn = match rustls::ServerConnection::new(self.inner.clone()) {
            Ok(conn) => conn,
            Err(err) => {
                return Err(PyException::new_err(format!(
                    "failed to initialize ServerConnection: {err}"
                )))
            }
        };

        Ok(ServerSocket {
            state: SessionState::new(sock, conn)?,
        })
    }
}
