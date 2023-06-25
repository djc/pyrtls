use std::io::{Cursor, Read, Write};
use std::net::ToSocketAddrs;
use std::sync::Arc;

use pyo3::exceptions::{PyException, PyValueError};
use pyo3::types::{PyByteArray, PyBytes, PyString, PyTuple};
use pyo3::{pyclass, pymethods, PyAny, PyResult, Python};
use rustls::RootCertStore;
use rustls_native_certs::load_native_certs;

use super::{IoState, SessionState, TlsError};

#[pyclass]
pub(crate) struct ClientSocket {
    state: SessionState<rustls::ClientConnection>,
    do_handshake_on_connect: bool,
}

#[pymethods]
impl ClientSocket {
    fn connect(&mut self, address: &PyTuple) -> PyResult<()> {
        if address.len() != 2 {
            return Err(PyValueError::new_err(
                "only 2-element address tuples are supported",
            ));
        }

        let host = address.get_item(0)?.extract::<&str>()?;
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

    fn do_handshake(&mut self) -> PyResult<()> {
        self.state.do_handshake()
    }

    fn send(&mut self, bytes: &PyBytes) -> PyResult<usize> {
        self.state.send(bytes)
    }

    fn recv<'p>(&mut self, size: usize, py: Python<'p>) -> PyResult<&'p PyBytes> {
        self.state.recv(size, py)
    }
}

#[pyclass]
pub(crate) struct ClientConnection {
    inner: rustls::ClientConnection,
}

#[pymethods]
impl ClientConnection {
    #[new]
    fn new(config: &ClientConfig, name: &PyString) -> PyResult<Self> {
        let name = match name.to_str()?.try_into() {
            Ok(n) => n,
            Err(_) => return Err(PyValueError::new_err("invalid hostname")),
        };

        Ok(Self {
            inner: rustls::ClientConnection::new(config.inner.clone(), name)
                .map_err(TlsError::from)?,
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
    fn write_tls_into(&mut self, buf: &PyByteArray) -> PyResult<usize> {
        let mut buf = unsafe { buf.as_bytes_mut() };
        Ok(self.inner.write_tls(&mut buf).map_err(TlsError::from)?)
    }

    /// Read new plaintext data from the TLS connection
    fn read_into(&mut self, buf: &PyByteArray) -> PyResult<usize> {
        let buf = unsafe { buf.as_bytes_mut() };
        Ok(self.inner.reader().read(buf).map_err(TlsError::from)?)
    }
}

#[pyclass]
pub(crate) struct ClientConfig {
    inner: Arc<rustls::ClientConfig>,
}

#[pymethods]
impl ClientConfig {
    #[new]
    fn new() -> PyResult<Self> {
        let mut roots = RootCertStore::empty();
        for root in load_native_certs()? {
            // TODO: report the error somehow
            let _ = roots.add(&rustls::Certificate(root.0));
        }

        Ok(Self {
            inner: Arc::new(
                rustls::ClientConfig::builder()
                    .with_safe_defaults()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            ),
        })
    }

    #[pyo3(signature = (sock, server_hostname, do_handshake_on_connect=true))]
    fn wrap_socket(
        &self,
        sock: &PyAny,
        server_hostname: &PyString,
        do_handshake_on_connect: bool,
    ) -> PyResult<ClientSocket> {
        let hostname = match server_hostname.to_str()?.try_into() {
            Ok(n) => n,
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
