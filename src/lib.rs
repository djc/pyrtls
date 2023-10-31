use std::error::Error as StdError;
use std::io::{Cursor, Read, Write};
use std::ops::{Deref, DerefMut};
#[cfg(unix)]
use std::os::unix::io::{FromRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{FromRawSocket, RawSocket};

use pyo3::exceptions::PyValueError;
use pyo3::types::{PyBytes, PyModule, PyString};
use pyo3::{pyclass, pymethods, pymodule, PyAny, PyErr, PyResult, Python};
use rustls::{ConnectionCommon, OwnedTrustAnchor};
use rustls_pemfile::Item;
use socket2::Socket;

mod client;
use client::{ClientConfig, ClientConnection, ClientSocket};
mod server;
use server::{ServerConfig, ServerConnection, ServerSocket};

#[pymodule]
fn pyrtls(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<ClientConfig>()?;
    m.add_class::<ClientConnection>()?;
    m.add_class::<ClientSocket>()?;
    m.add_class::<ServerConfig>()?;
    m.add_class::<ServerConnection>()?;
    m.add_class::<ServerSocket>()?;
    Ok(())
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
    fn new(sock: &PyAny, conn: C) -> PyResult<Self> {
        #[cfg(unix)]
        let socket = match sock.call_method0("detach")?.extract::<RawFd>()? {
            -1 => return Err(PyValueError::new_err("invalid file descriptor number")),
            fd => unsafe { Socket::from_raw_fd(fd) },
        };

        #[cfg(windows)]
        let socket = match sock.call_method0("detach")?.extract::<RawSocket>()? {
            // TODO: no clue how Windows expresses an error here?
            fd => unsafe { Socket::from_raw_socket(fd) },
        };

        Ok(Self {
            socket,
            conn,
            read_buf: vec![0; 16_384],
            readable: 0,
            user_buf: vec![0; 4_096],
        })
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

#[pyclass]
#[derive(Clone)]
struct TrustAnchor {
    inner: OwnedTrustAnchor,
}

#[pymethods]
impl TrustAnchor {
    #[new]
    fn new(
        subject: &PyBytes,
        subject_public_key_info: &PyBytes,
        name_constraints: Option<&PyBytes>,
    ) -> Self {
        Self {
            inner: OwnedTrustAnchor::from_subject_spki_name_constraints(
                subject.as_bytes(),
                subject_public_key_info.as_bytes(),
                name_constraints.map(|nc| nc.as_bytes()),
            ),
        }
    }
}

#[pyclass]
struct IoState {
    inner: rustls::IoState,
}

#[pymethods]
impl IoState {
    fn tls_bytes_to_write(&self) -> usize {
        self.inner.tls_bytes_to_write()
    }

    fn plaintext_bytes_to_read(&self) -> usize {
        self.inner.plaintext_bytes_to_read()
    }

    fn peer_has_closed(&self) -> bool {
        self.inner.peer_has_closed()
    }
}

impl From<rustls::IoState> for IoState {
    fn from(value: rustls::IoState) -> Self {
        Self { inner: value }
    }
}

#[pyclass(name = "TLSError")]
struct TlsError {
    inner: Box<dyn StdError + Send + Sync + 'static>,
}

impl<E: StdError + Send + Sync + 'static> From<E> for TlsError {
    fn from(e: E) -> Self {
        Self { inner: Box::new(e) }
    }
}

impl From<TlsError> for PyErr {
    fn from(e: TlsError) -> Self {
        PyValueError::new_err(format!("error: {}", e.inner))
    }
}

fn py_to_pem(obj: &PyAny) -> PyResult<Item> {
    let pem = obj.downcast_exact::<PyString>()?.to_str()?;
    match rustls_pemfile::read_one(&mut Cursor::new(pem)) {
        Ok(Some(item)) => Ok(item),
        Ok(None) => Err(PyValueError::new_err("no data found in PEM string").into()),
        Err(err) => Err(err.into()),
    }
}

fn py_to_der(obj: &PyAny) -> PyResult<&[u8]> {
    let der = obj.downcast_exact::<PyBytes>()?.as_bytes();
    if der.starts_with(b"-----") {
        return Err(PyValueError::new_err("PEM data passed as bytes object").into());
    }

    Ok(der)
}
