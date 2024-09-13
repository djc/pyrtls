use std::error::Error as StdError;
use std::io::{self, Cursor, Read, Write};
use std::ops::{Deref, DerefMut};
#[cfg(unix)]
use std::os::unix::io::{FromRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{FromRawSocket, RawSocket};

use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::types::{
    PyAnyMethods, PyBytes, PyBytesMethods, PyModule, PyModuleMethods, PyString, PyStringMethods,
};
use pyo3::{pyclass, pymethods, pymodule, Bound, PyAny, PyErr, PyResult, Python};
use rustls::ConnectionCommon;
use rustls_pemfile::Item;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use socket2::Socket;

mod client;
use client::{ClientConfig, ClientConnection, ClientSocket};
mod server;
use server::{ServerConfig, ServerConnection, ServerSocket};

#[pymodule]
fn pyrtls(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ClientConfig>()?;
    m.add_class::<ClientConnection>()?;
    m.add_class::<ClientSocket>()?;
    m.add_class::<ServerConfig>()?;
    m.add_class::<ServerConnection>()?;
    m.add_class::<ServerSocket>()?;
    m.add_class::<IoState>()?;
    Ok(())
}

struct SessionState<C> {
    socket: Socket,
    conn: C,
    read_buf: Vec<u8>,
    readable: usize,
    user_buf: Vec<u8>,
    blocking: bool,
}

impl<C, S> SessionState<C>
where
    C: Deref<Target = ConnectionCommon<S>> + DerefMut,
{
    fn new(sock: &Bound<'_, PyAny>, conn: C) -> PyResult<Self> {
        let blocking = sock.call_method0("getblocking")?.extract::<bool>()?;

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
            blocking,
        })
    }

    fn do_handshake(&mut self) -> PyResult<()> {
        let _ = self.conn.complete_io(&mut self.socket)?;
        Ok(())
    }

    fn send(&mut self, bytes: &Bound<'_, PyBytes>) -> PyResult<usize> {
        let written = self.conn.writer().write(bytes.as_bytes())?;
        let _ = self.conn.complete_io(&mut self.socket)?;
        Ok(written)
    }

    fn recv<'p>(&mut self, size: usize, py: Python<'p>) -> PyResult<Bound<'p, PyBytes>> {
        self.read(py)?;
        if self.user_buf.len() < size {
            self.user_buf.resize_with(size, || 0);
        }

        let read = if self.blocking {
            loop {
                match self.conn.reader().read(&mut self.user_buf[..size]) {
                    Ok(n) => break n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        py.check_signals()?;
                        self.read(py)?;
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        } else {
            self.conn.reader().read(&mut self.user_buf[..size])?
        };

        Ok(PyBytes::new_bound(py, &self.user_buf[..read]))
    }

    fn read(&mut self, py: Python<'_>) -> PyResult<()> {
        if self.readable < self.read_buf.len() {
            self.readable += if self.blocking {
                loop {
                    match self.socket.read(&mut self.read_buf[self.readable..]) {
                        Ok(n) => break n,
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            py.check_signals()?;
                            continue;
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
            } else {
                self.socket.read(&mut self.read_buf[self.readable..])?
            }
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
    inner: rustls_pki_types::TrustAnchor<'static>,
}

#[pymethods]
impl TrustAnchor {
    #[new]
    #[pyo3(signature = (subject, subject_public_key_info, name_constraints=None))]
    fn new(
        subject: &Bound<'_, PyBytes>,
        subject_public_key_info: &Bound<'_, PyBytes>,
        name_constraints: Option<&Bound<'_, PyBytes>>,
    ) -> Self {
        Self {
            inner: rustls_pki_types::TrustAnchor {
                subject: subject.as_bytes().into(),
                subject_public_key_info: subject_public_key_info.as_bytes().into(),
                name_constraints: name_constraints.map(|nc| nc.as_bytes().into()),
            }
            .to_owned(),
        }
    }
}

#[pyclass]
struct IoState {
    inner: rustls::IoState,
}

#[pymethods]
impl IoState {
    /// How many bytes could be written by `Connection.write_tls_into()` if called right now.
    /// A non-zero value implies that `Connection.wants_write()` would yield `True`.
    #[getter]
    fn tls_bytes_to_write(&self) -> usize {
        self.inner.tls_bytes_to_write()
    }

    /// How many plaintext bytes are currently buffered in the connection.
    #[getter]
    fn plaintext_bytes_to_read(&self) -> usize {
        self.inner.plaintext_bytes_to_read()
    }

    /// `True` if the peer has sent us a `close_notify` alert. This is the TLS mechanism to
    /// securely half-close a TLS connection, and signifies that the peer will not send any
    /// further data on this connection.
    #[getter]
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

fn extract_alpn_protocols(iter: Option<&Bound<'_, PyAny>>) -> PyResult<Vec<Vec<u8>>> {
    let mut alpn = Vec::with_capacity(match iter {
        Some(ap) => ap.len()?,
        None => 0,
    });

    if let Some(protos) = iter {
        for proto in protos.iter()? {
            let proto = proto?;
            if let Ok(proto) = proto.downcast_exact::<PyBytes>() {
                alpn.push(proto.as_bytes().to_vec());
            } else if let Ok(proto) = proto.downcast_exact::<PyString>() {
                alpn.push(proto.to_str()?.as_bytes().to_vec());
            } else {
                return Err(PyTypeError::new_err("invalid type for ALPN protocol"));
            }
        }
    }

    Ok(alpn)
}

fn py_to_pem(obj: &Bound<'_, PyAny>) -> PyResult<Item> {
    let pem = obj.downcast_exact::<PyString>()?.to_str()?;
    match rustls_pemfile::read_one(&mut Cursor::new(pem)) {
        Ok(Some(item)) => Ok(item),
        Ok(None) => Err(PyValueError::new_err("no data found in PEM string")),
        Err(err) => Err(err.into()),
    }
}

fn py_to_cert_der<'a>(obj: &'a Bound<'a, PyAny>) -> PyResult<CertificateDer<'a>> {
    let der = obj.downcast_exact::<PyBytes>()?.as_bytes();
    if der.starts_with(b"-----") {
        return Err(PyValueError::new_err("PEM data passed as bytes object"));
    }

    Ok(CertificateDer::from(der))
}

fn py_to_key_der<'a>(obj: &'a Bound<'a, PyAny>) -> PyResult<PrivateKeyDer<'a>> {
    let der = obj.downcast_exact::<PyBytes>()?.as_bytes();
    if der.starts_with(b"-----") {
        return Err(PyValueError::new_err("PEM data passed as bytes object"));
    }

    PrivateKeyDer::try_from(der)
        .map_err(|err| PyValueError::new_err(format!("error parsing private key: {}", err)))
}
