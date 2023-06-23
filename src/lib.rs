use std::convert::TryInto;
use std::io::{Read, Write};
use std::net::ToSocketAddrs;
use std::ops::{Deref, DerefMut};
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::Arc;

use pyo3::exceptions::{PyException, PyValueError};
use pyo3::types::{PyBytes, PyIterator, PyModule, PyString, PyTuple};
use pyo3::{pyclass, pymethods, pymodule};
use pyo3::{PyAny, PyObject, PyResult, Python};
use rustls::{Certificate, ConnectionCommon, PrivateKey, RootCertStore};
use rustls_native_certs::load_native_certs;
use socket2::Socket;

#[pyclass]
struct ClientConfig {
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
struct ClientSocket {
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
struct ServerConfig {
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
struct ServerSocket {
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

struct SessionState<C> {
    socket: Socket,
    conn: C,
    read_buf: Vec<u8>,
    readable: usize,
    user_buf: Vec<u8>,
}

impl<C, S> SessionState<C>
where
    C: Deref<Target = ConnectionCommon<S>> + DerefMut,
{
    fn new(fd: RawFd, conn: C) -> Self {
        Self {
            socket: unsafe { Socket::from_raw_fd(fd) },
            conn,
            read_buf: vec![0; 16_384],
            readable: 0,
            user_buf: vec![0; 4_096],
        }
    }

    fn do_handshake(&mut self) -> PyResult<()> {
        let _ = self.conn.complete_io(&mut self.socket)?;
        Ok(())
    }

    fn send(&mut self, bytes: &PyBytes) -> PyResult<usize> {
        let written = self.conn.writer().write(bytes.as_bytes())?;
        let _ = self.conn.complete_io(&mut self.socket)?;
        Ok(written)
    }

    fn recv<'p>(&mut self, size: usize, py: Python<'p>) -> PyResult<&'p PyBytes> {
        self.read()?;
        if self.user_buf.len() < size {
            self.user_buf.resize_with(size, || 0);
        }

        let read = self.conn.reader().read(&mut self.user_buf[..size])?;
        Ok(PyBytes::new(py, &self.user_buf[..read]))
    }

    fn read(&mut self) -> PyResult<()> {
        if self.readable < self.read_buf.len() {
            self.readable += self.socket.read(&mut self.read_buf[self.readable..])?;
        }

        if self.conn.wants_read() {
            let read = self.conn.read_tls(&mut &self.read_buf[..self.readable])?;
            self.read_buf.copy_within(read..self.readable, 0);
            self.readable -= read;
            if read > 0 {
                if let Err(e) = self.conn.process_new_packets() {
                    return Err(PyValueError::new_err(format!("error: {}", e)));
                }
            }
        }

        Ok(())
    }
}

#[pymodule]
fn pyrtls(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<ClientConfig>()?;
    m.add_class::<ClientSocket>()?;
    m.add_class::<ServerConfig>()?;
    m.add_class::<ServerSocket>()?;
    Ok(())
}
