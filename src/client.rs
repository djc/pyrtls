use std::io::{Cursor, Read, Write};
use std::net::ToSocketAddrs;
use std::sync::Arc;

use pyo3::exceptions::{PyException, PyValueError};
use pyo3::types::{
    PyAnyMethods, PyByteArray, PyByteArrayMethods, PyBytes, PyString, PyStringMethods, PyTuple,
    PyTupleMethods,
};
use pyo3::{pyclass, pymethods, Bound, PyAny, PyResult, Python};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::RootCertStore;
use rustls_platform_verifier::Verifier;

use super::{IoState, SessionState, TlsError};
use crate::{extract_alpn_protocols, py_to_cert_der, py_to_pem, TrustAnchor};

/// A `ClientSocket` is a wrapper type that contains both a `socket.socket` and a
/// `ClientConnection` object. It is similar to the `ssl.SSLSocket` class from the
/// standard library and should implement most of the same methods.
#[pyclass]
pub(crate) struct ClientSocket {
    state: SessionState<rustls::ClientConnection>,
    do_handshake_on_connect: bool,
}

#[pymethods]
impl ClientSocket {
    /// Connect to a remote socket address. `address` must currently be a 2-element
    /// tuple containing a hostname and a port number.
    fn connect(&mut self, address: &Bound<'_, PyTuple>) -> PyResult<()> {
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

        self.state.socket.connect(&addr.into())?;
        if self.do_handshake_on_connect {
            self.state.do_handshake()?;
        }

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
    /// A returned empty bytes object indicates that the server has disconnected.
    fn recv<'p>(&mut self, size: usize, py: Python<'p>) -> PyResult<Bound<'p, PyBytes>> {
        self.state.recv(size, py)
    }
}

/// A `ClientConnection` contains TLS state associated with a single client-side connection.
/// It does not contain any networking state, and is not directly associated with a socket,
/// so I/O happens via the methods on this object directly.
///
/// A `ClientConnection` can be created from a `ClientConfig` `config` and a server name, `name`.
/// The server name must be either a DNS hostname or an IP address (only string forms are
/// currently accepted).
#[pyclass]
pub(crate) struct ClientConnection {
    inner: rustls::ClientConnection,
}

#[pymethods]
impl ClientConnection {
    #[new]
    fn new(config: &ClientConfig, name: &Bound<'_, PyString>) -> PyResult<Self> {
        let name = match ServerName::try_from(name.to_str()?) {
            Ok(n) => n.to_owned(),
            Err(_) => return Err(PyValueError::new_err("invalid hostname")),
        };

        Ok(Self {
            inner: rustls::ClientConnection::new(config.inner.clone(), name)
                .map_err(TlsError::from)?,
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

/// Create a new `ClientConfig` object (similar to `ssl.SSLContext`). A new `ClientConnection` can
/// only be created by passing in a reference to a `ClientConfig` object.
///
/// The most important configuration for `ClientConfig` is the certificate verification process.
/// Three different options are offered to define the desired process:
///
/// - `platform_verifier` (enabled by default) will enable the platform's certificate verifier
///   on platforms that have on, and searching for CA certificates in the system trust store on
///   other platforms (like Linux and FreeBSD).
/// - `mozilla_roots` will enable a built-in set of Mozilla root certificates. This is independent
///   of the operating system, but depends on the pyrtls package to deliver timely updates.
/// - `custom_roots` allows the caller to specify an iterable of trust anchors. Each item must be:
///   - A `TrustAnchor` object, which is a wrapper around a `webpki::TrustAnchor` object
///   - A `bytes` object containing a DER-encoded certificate
///   - A `str` object containing one PEM-encoded certificate
///
/// The `platform_verifier` option cannot currently be combined with `mozilla_roots` or
/// `custom_roots` (this will raise a `ValueError`), but the latter two can be combined.
///
/// Other options:
///
/// - `alpn_protocols` must be an iterable containing `bytes` or `str` objects, each representing
///   one ALPN protocol string.
#[pyclass]
pub(crate) struct ClientConfig {
    inner: Arc<rustls::ClientConfig>,
}

#[pymethods]
impl ClientConfig {
    #[new]
    #[pyo3(signature = (*, platform_verifier = true, mozilla_roots = false, custom_roots = None, alpn_protocols = None))]
    fn new(
        platform_verifier: bool,
        mozilla_roots: bool,
        custom_roots: Option<&Bound<'_, PyAny>>,
        alpn_protocols: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let builder = rustls::ClientConfig::builder();
        let mut config = match (platform_verifier, mozilla_roots, custom_roots) {
            (true, false, None) => builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(Verifier::new())),
            (false, false, None) => {
                return Err(PyValueError::new_err("no certificate verifier specified"));
            }
            (true, _, _) => {
                return Err(PyValueError::new_err(
                    "platform verifier cannot be used with `mozilla_roots` or `custom_roots`",
                ));
            }
            (false, true, custom) | (_, false, custom) => {
                let mut roots = RootCertStore::empty();
                if mozilla_roots {
                    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                }

                if let Some(custom) = custom {
                    for obj in custom.try_iter()? {
                        let obj = obj?;
                        if let Ok(ta) = obj.extract::<TrustAnchor>() {
                            roots.extend([ta.inner].into_iter())
                        } else if let Ok(ta) = py_to_cert_der(&obj) {
                            let (added, _) = roots.add_parsable_certificates([ta]);
                            if added != 1 {
                                return Err(PyValueError::new_err(
                                    "unable to parse trust anchor from DER",
                                ));
                            }
                        } else if let Ok(cert_der) = py_to_pem::<CertificateDer>(&obj) {
                            if roots.add(cert_der).is_err() {
                                return Err(PyValueError::new_err(
                                    "unable to parse trust anchor from PEM",
                                ));
                            }
                        }
                    }
                }

                builder.with_root_certificates(roots)
            }
        }
        .with_no_client_auth();

        config.alpn_protocols = extract_alpn_protocols(alpn_protocols)?;
        Ok(Self {
            inner: Arc::new(config),
        })
    }

    /// Use the `ClientConfig` and the given `sock` to create a `ClientSocket`.
    ///
    /// Returns a `ClientSocket` if successful. Raises a `ValueError` if `server_hostname`
    /// is not a valid server name (either a DNS name or an IP address).
    #[pyo3(signature = (sock, server_hostname, do_handshake_on_connect=true))]
    fn wrap_socket(
        &self,
        sock: &Bound<'_, PyAny>,
        server_hostname: &Bound<'_, PyString>,
        do_handshake_on_connect: bool,
    ) -> PyResult<ClientSocket> {
        let hostname = match ServerName::try_from(server_hostname.to_str()?) {
            Ok(n) => n.to_owned(),
            Err(_) => return Err(PyValueError::new_err("invalid hostname")),
        };

        let conn = match rustls::ClientConnection::new(self.inner.clone(), hostname) {
            Ok(conn) => conn,
            Err(err) => {
                return Err(PyException::new_err(format!(
                    "failed to initialize ClientConnection: {err}"
                )))
            }
        };

        Ok(ClientSocket {
            state: SessionState::new(sock, conn)?,
            do_handshake_on_connect,
        })
    }
}
