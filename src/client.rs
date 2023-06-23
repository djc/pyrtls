use std::convert::TryInto;
use std::net::ToSocketAddrs;
use std::sync::Arc;

use pyo3::exceptions::{PyException, PyValueError};
use pyo3::types::{PyBytes, PyString, PyTuple};
use pyo3::{pyclass, pymethods};
use pyo3::{PyAny, PyResult, Python};
use rustls::RootCertStore;
use rustls_native_certs::load_native_certs;

use super::SessionState;

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
        let fd = match sock.call_method0("detach")?.extract::<i32>()? {
            -1 => return Err(PyValueError::new_err("invalid file descriptor number")),
            fd => fd,
        };

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
            state: SessionState::new(fd, conn),
            do_handshake_on_connect,
        })
    }
}

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
