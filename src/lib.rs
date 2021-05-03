use std::io::{self, Read, Write};
use std::net::ToSocketAddrs;
use std::os::unix::io::FromRawFd;
use std::sync::Arc;

use pyo3::exceptions::PyValueError;
use pyo3::proc_macro::{pyclass, pymethods, pymodule};
use pyo3::types::{PyBytes, PyModule, PyString, PyTuple};
use pyo3::{PyAny, PyResult, Python};
use rustls::{ClientSession, Session};
use rustls_native_certs::load_native_certs;
use socket2::Socket;
use webpki::DNSNameRef;

#[pyclass]
struct ClientConfig {
    inner: Arc<rustls::ClientConfig>,
}

#[pymethods]
impl ClientConfig {
    #[new]
    fn new() -> PyResult<Self> {
        let mut inner = rustls::ClientConfig::new();
        inner.root_store = load_native_certs().map_err(|(_, err)| err)?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    #[args(do_handshake_on_connect = "true")]
    fn wrap_socket(
        &self,
        sock: &PyAny,
        do_handshake_on_connect: bool,
        server_hostname: &PyString,
    ) -> PyResult<ClientSocket> {
        let fd = match sock.call_method0("detach")?.extract::<i32>()? {
            -1 => return Err(PyValueError::new_err("invalid file descriptor number")),
            fd => fd,
        };

        let hostname = match DNSNameRef::try_from_ascii_str(server_hostname.to_str()?) {
            Ok(n) => n,
            Err(_) => return Err(PyValueError::new_err("invalid hostname")),
        };

        Ok(ClientSocket {
            socket: unsafe { Socket::from_raw_fd(fd) },
            session: ClientSession::new(&self.inner, hostname),
            write_buf: vec![0; 16_384],
            writable: 0,
            read_buf: vec![0; 16_384],
            readable: 0,
            user_buf: vec![0; 4_096],
            do_handshake_on_connect,
        })
    }
}

#[pyclass]
struct ClientSocket {
    socket: Socket,
    session: ClientSession,
    write_buf: Vec<u8>,
    writable: usize,
    read_buf: Vec<u8>,
    readable: usize,
    user_buf: Vec<u8>,
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

        let host = address.get_item(0).extract::<&str>()?;
        let port = address.get_item(1).extract::<u16>()?;
        let addr = match (host, port).to_socket_addrs()?.next() {
            Some(addr) => addr,
            None => {
                return Err(PyValueError::new_err(
                    "unable to convert address to socket address",
                ))
            }
        };

        self.socket.connect(&addr.into())?;
        if self.do_handshake_on_connect {
            self.do_handshake()?;
        }

        Ok(())
    }

    fn do_handshake(&mut self) -> PyResult<()> {
        while self.session.is_handshaking() {
            self.write()?;
            self.read()?;
        }
        Ok(())
    }

    fn send(&mut self, bytes: &PyBytes) -> PyResult<usize> {
        let written = self.session.write(bytes.as_bytes())?;
        self.write()?;
        Ok(written)
    }

    fn recv<'p>(&mut self, size: usize, py: Python<'p>) -> PyResult<&'p PyBytes> {
        self.read()?;
        if self.user_buf.len() < size {
            self.user_buf.resize_with(size, || 0);
        }

        let read = self.session.read(&mut &mut self.user_buf[..size])?;
        Ok(PyBytes::new(py, &self.user_buf[..read]))
    }
}

impl ClientSocket {
    fn read(&mut self) -> PyResult<()> {
        if self.readable < self.read_buf.len() {
            self.readable += self.socket.read(&mut self.read_buf[self.readable..])?;
        }

        if self.session.wants_read() {
            let read = self
                .session
                .read_tls(&mut &self.read_buf[..self.readable])?;
            self.read_buf.copy_within(read..self.readable, 0);
            self.readable -= read;
            if read > 0 {
                if let Err(e) = self.session.process_new_packets() {
                    return Err(PyValueError::new_err(format!("error: {}", e)));
                }
            }
        }

        Ok(())
    }

    fn write(&mut self) -> Result<(), io::Error> {
        if self.session.wants_write() {
            self.writable += self
                .session
                .write_tls(&mut &mut self.write_buf[self.writable..])?;
        }

        if !self.write_buf.is_empty() {
            let written = self.socket.write(&self.write_buf[..self.writable])?;
            self.write_buf.copy_within(written..self.writable, 0);
            self.writable -= written;
        }

        Ok(())
    }
}

#[pymodule]
fn pyrtls(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<ClientConfig>()?;
    m.add_class::<ClientSocket>()?;
    Ok(())
}
