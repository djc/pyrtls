use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
use std::os::unix::io::{FromRawFd, RawFd};

use pyo3::exceptions::PyValueError;
use pyo3::pymodule;
use pyo3::types::{PyBytes, PyModule};
use pyo3::{PyResult, Python};
use rustls::ConnectionCommon;
use socket2::Socket;

mod client;
use client::{ClientConfig, ClientSocket};
mod server;
use server::{ServerConfig, ServerSocket};

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
