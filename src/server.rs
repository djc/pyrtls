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

#[pyclass]
pub(crate) struct ServerSocket {
    state: SessionState<rustls::ServerConnection>,
}

#[pymethods]
impl ServerSocket {
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

    fn do_handshake(&mut self) -> PyResult<()> {
        self.state.do_handshake()
    }

    fn send(&mut self, bytes: &Bound<'_, PyBytes>) -> PyResult<usize> {
        self.state.send(bytes)
    }

    fn recv<'p>(&mut self, size: usize, py: Python<'p>) -> PyResult<Bound<'p, PyBytes>> {
        self.state.recv(size, py)
    }
}

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

    /// Returns `true` if the caller should call `read_tls()` soon
    fn readable(&self) -> bool {
        self.inner.wants_read()
    }

    /// Read TLS content from `buf` into the internal buffer
    ///
    /// You should call `process_new_packets()` each time a call to this function succeeds in
    /// order to empty the incoming TLS data buffer.
    ///
    /// Mirrors the `RawIO.write()` interface.
    fn read_tls(&mut self, buf: &[u8]) -> PyResult<usize> {
        Ok(self
            .inner
            .read_tls(&mut Cursor::new(buf))
            .map_err(TlsError::from)?)
    }

    /// Processes any new packets read by a previous call to `read_tls()`
    fn process_new_packets(&mut self) -> PyResult<IoState> {
        Ok(self
            .inner
            .process_new_packets()
            .map_err(TlsError::from)?
            .into())
    }

    /// Write new plaintext data into the TLS connection
    fn write(&mut self, buf: &[u8]) -> PyResult<usize> {
        Ok(self.inner.writer().write(buf).map_err(TlsError::from)?)
    }

    /// Returns `true` if the caller should call `write_tls_into()` soon
    fn writable(&self) -> bool {
        self.inner.wants_write()
    }

    /// Write TLS messages from the internal buffer into `buf`
    ///
    /// Mirrors the `RawIO.readinto()` interface.
    fn write_tls_into(&mut self, buf: &Bound<'_, PyByteArray>) -> PyResult<usize> {
        let mut buf = unsafe { buf.as_bytes_mut() };
        Ok(self.inner.write_tls(&mut buf).map_err(TlsError::from)?)
    }

    /// Read new plaintext data from the TLS connection
    fn read_into(&mut self, buf: &Bound<'_, PyByteArray>) -> PyResult<usize> {
        let buf = unsafe { buf.as_bytes_mut() };
        Ok(self.inner.reader().read(buf).map_err(TlsError::from)?)
    }
}

#[pyclass]
pub(crate) struct ServerConfig {
    inner: Arc<rustls::ServerConfig>,
}

#[pymethods]
impl ServerConfig {
    #[new]
    #[pyo3(signature = (cert_chain, private_key, alpn_protocols = None))]
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
