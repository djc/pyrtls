use std::net::ToSocketAddrs;
use std::sync::Arc;

use pyo3::exceptions::{PyException, PyValueError};
use pyo3::types::{PyBytes, PyIterator, PyTuple};
use pyo3::{pyclass, pymethods};
use pyo3::{PyAny, PyObject, PyResult, Python};
use rustls::{Certificate, PrivateKey};

use super::SessionState;

#[pyclass]
pub(crate) struct ServerConfig {
    inner: Arc<rustls::ServerConfig>,
}

#[pymethods]
impl ServerConfig {
    #[new]
    fn new(cert_chain_der: PyObject, private_key_der: &PyBytes, py: Python<'_>) -> PyResult<Self> {
        let iter = PyIterator::from_object(py, &cert_chain_der)?;
        let mut certs = Vec::with_capacity(iter.len()?);
        for cert in iter {
            certs.push(Certificate(
                cert?.extract::<&PyBytes>()?.as_bytes().to_vec(),
            ));
        }

        let key = PrivateKey(private_key_der.as_bytes().to_vec());
        Ok(Self {
            inner: Arc::new(
                rustls::ServerConfig::builder()
                    .with_safe_defaults()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .map_err(|err| {
                        PyException::new_err(format!("error initializing ServerConfig: {err}"))
                    })?,
            ),
        })
    }

    fn wrap_socket(&self, sock: &PyAny) -> PyResult<ServerSocket> {
        let fd = match sock.call_method0("detach")?.extract::<i32>()? {
            -1 => return Err(PyValueError::new_err("invalid file descriptor number")),
            fd => fd,
        };

        let conn = match rustls::ServerConnection::new(self.inner.clone()) {
            Ok(conn) => conn,
            Err(err) => {
                return Err(PyException::new_err(format!(
                    "failed to initialize ServerConnection: {err}"
                )))
            }
        };

        Ok(ServerSocket {
            state: SessionState::new(fd, conn),
        })
    }
}

#[pyclass]
pub(crate) struct ServerSocket {
    state: SessionState<rustls::ServerConnection>,
}

#[pymethods]
impl ServerSocket {
    fn bind(&mut self, address: &PyTuple) -> PyResult<()> {
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

        self.state.socket.bind(&addr.into())?;
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
