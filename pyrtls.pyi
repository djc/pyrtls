"""
# pyrtls: rustls-based modern TLS for Python

[Latest version](https://pypi.org/project/pyrtls) |
[Documentation](https://pyrtls.readthedocs.io) |
[CI](https://github.com/djc/pyrtls/actions?query=workflow%3ACI+branch%3Amain)

pyrtls provides bindings to [rustls](https://github.com/rustls/rustls), a modern Rust-based TLS implementation with an API that is
intended to be easy to use to replace the `ssl` module (but not entirely compatible with it).

In addition to being memory-safe, the library is designed to be more secure by default. As such,
it does not implement older protocol versions, cipher suites with known security problems, and
some problematic features of the TLS protocol. For more details, review the [manual](https://docs.rs/rustls/latest/rustls/manual/index.html).

## Warning!

This project is just getting started. While rustls is mature, the Python bindings
are pretty new and not yet feature-complete.
"""

from collections.abc import Iterable
from socket import socket

# lib.rs

class TrustAnchor:
    def __new__(
        cls,
        subject: bytes,
        subject_public_key_info: bytes,
        name_constraints: bytes | None,
    ) -> TrustAnchor: ...

class IoState:
    def tls_bytes_to_write(self) -> int:
        """
        How many bytes could be written by `Connection.write_tls_into()` if called right now.
        A non-zero value implies that `Connection.wants_write()` would yield `True`.
        """

    def plaintext_bytes_to_read(self) -> int:
        """How many plaintext bytes are currently buffered in the connection."""

    def peer_has_closed(self) -> bool:
        """
        `True` if the peer has sent us a `close_notify` alert. This is the TLS mechanism to
        securely half-close a TLS connection, and signifies that the peer will not send any
        further data on this connection.
        """

class TLSError: ...

# client.rs

class ClientSocket:
    """
    A `ClientSocket` is a wrapper type that contains both a `socket.socket` and a
    `ClientConnection` object. It is similar to the `ssl.SSLSocket` class from the
    standard library and should implement most of the same methods.
    """

    def connect(self, address: tuple[str, int]) -> None:
        """
        Connect to a remote socket address. `address` must currently be a 2-element
        tuple containing a hostname and a port number.
        """

    def do_handshake(self) -> None:
        """Perform the TLS setup handshake."""

    def send(self, bytes: bytes) -> int:
        """
        Send data to the socket. The socket must be connected to a remote socket. Returns the
        number of bytes sent. Applications are responsible for checking that all data has been
        sent; if only some of the data was transmitted, the application needs to attempt delivery
        of the remaining data.
        """

    def recv(self, size: int) -> bytes:
        """
        Receive data from the socket. The return value is a bytes object representing the data
        received. The maximum amount of data to be received at once is specified by `size`.
        A returned empty bytes object indicates that the server has disconnected.
        """

class ClientConnection:
    """
    A `ClientConnection` contains TLS state associated with a single client-side connection.
    It does not contain any networking state, and is not directly associated with a socket,
    so I/O happens via the methods on this object directly.

    A `ClientConnection` can be created from a `ClientConfig` `config` and a server name, `name`.
    The server name must be either a DNS hostname or an IP address (only string forms are
    currently accepted).
    """

    def __new__(cls, config: ClientConfig, name: str) -> ClientConnection: ...
    def readable(self) -> bool:
        """
        Returns `true` if the caller should call `read_tls()` as soon as possible.

        If there is pending plaintext data to read, this returns `false`. If your application
        respects this mechanism, only one full TLS message will be buffered by pyrtls.
        """

    def read_tls(self, buf: bytes) -> int:
        """
        Read TLS content from `buf` into the internal buffer. Return the number of bytes read, or
        `0` once a `close_notify` alert has been received. No additional data is read in this
        state.

        Due to internal buffering, `buf` may contain TLS messages in arbitrary-sized chunks (like
        a socket or pipe might).

        You should call `process_new_packets()` each time a call to this function succeeds in
        order to empty the incoming TLS data buffer.

        Exceptions may be raised to signal backpressure:

        * In order to empty the incoming TLS data buffer, you should call `process_new_packets()`
          each time a call to this function succeeds.
        * In order to empty the incoming plaintext data buffer, you should call `read_into()`
          after the call to `process_new_packets()`.

        You should call `process_new_packets()` each time a call to this function succeeds in
        order to empty the incoming TLS data buffer

        Mirrors the `RawIO.write()` interface.
        """

    def process_new_packets(self) -> IoState:
        """
        Processes any new packets read by a previous call to `read_tls()`.

        Errors from this function relate to TLS protocol errors, and are fatal to the connection.
        Future calls after an error will do no new work and will return the same error. After an
        error is returned from `process_new_packets()`, you should not call `read_tls()` anymore
        (it will fill up buffers to no purpose). However, you may call the other methods on the
        connection, including `write()` and `write_tls_into()`. Most likely you will want to
        call `write_tls_into()` to send any alerts queued by the error and then close the
        underlying connection.

        In case of success, yields an `IoState` object with sundry state about the connection.
        """

    def write(self, buf: bytes) -> int:
        """
        Send the plaintext `buf` to the peer, encrypting and authenticating it. Once this
        function succeeds you should call `write_tls_into()` which will output the
        corresponding TLS records.

        This function buffers plaintext sent before the TLS handshake completes, and sends it as
        soon as it can.
        """

    def writable(self) -> bool:
        """Returns `True` if the caller should call `write_tls_into()` as soon as possible."""

    def write_tls_into(self, buf: bytearray) -> int:
        """
        Writes TLS messages into `buf`.

        On success, this function returns the number of bytes written (after encoding and
        encryption).

        After this function returns, the connection buffer may not yet be fully flushed.
        `writable()` can be used to check if the output buffer is empty.

        Mirrors the `RawIO.readinto()` interface.
        """

    def read_into(self, buf: bytearray) -> int:
        """
        Obtain plaintext data received from the peer over this TLS connection.

        If the peer closes the TLS connection cleanly, this returns `0` once all the pending data
        has been read. No further data can be received on that connection, so the underlying TCP
        connection should be half-closed too.

        If the peer closes the TLS connection uncleanly (a TCP EOF without sending a
        `close_notify` alert) this functions raises a `TlsError` exception once any pending data
        has been read.

        Note that support for `close_notify` varies in peer TLS libraries: many do not support it
        and uncleanly close the TCP connection (this might be vulnerable to truncation attacks
        depending on the application protocol). This means applications using pyrtls must both
        handle EOF from this function, **and** unexpected EOF of the underlying TCP connection.

        If there are no bytes to read, this raises a `TlsError` exception.

        You may learn the number of bytes available at any time by inspecting the return of
        `process_new_packets()`.
        """

class ClientConfig:
    """
    Create a new `ClientConfig` object (similar to `ssl.SSLContext`). A new `ClientConnection` can
    only be created by passing in a reference to a `ClientConfig` object.

    The most important configuration for `ClientConfig` is the certificate verification process.
    Three different options are offered to define the desired process:

    - `platform_verifier` (enabled by default) will enable the platform's certificate verifier
      on platforms that have on, and searching for CA certificates in the system trust store on
      other platforms (like Linux and FreeBSD).
    - `mozilla_roots` will enable a built-in set of Mozilla root certificates. This is independent
      of the operating system, but depends on the pyrtls package to deliver timely updates.
    - `custom_roots` allows the caller to specify an iterable of trust anchors. Each item must be:
      - A `TrustAnchor` object, which is a wrapper around a `webpki::TrustAnchor` object
      - A `bytes` object containing a DER-encoded certificate
      - A `str` object containing one PEM-encoded certificate

    The `platform_verifier` option cannot currently be combined with `mozilla_roots` or
    `custom_roots` (this will raise a `ValueError`), but the latter two can be combined.

    Other options:

    - `alpn_protocols` must be an iterable containing `bytes` or `str` objects, each representing
      one ALPN protocol string.
    """

    def __new__(
        cls,
        *,
        platform_verifier: bool = True,
        mozilla_roots: bool = False,
        custom_roots: Iterable[TrustAnchor | bytes | str] | None = None,
        alpn_protocols: Iterable[bytes | str] | None = None,
    ) -> ClientConfig: ...
    def wrap_socket(
        self, sock: socket, server_hostname: str, do_handshake_on_connect: bool = True
    ) -> ClientSocket:
        """
        Use the `ClientConfig` and the given `sock` to create a `ClientSocket`.

        Returns a `ClientSocket` if successful. Raises a `ValueError` if `server_hostname`
        is not a valid server name (either a DNS name or an IP address).
        """

# server.rs

class ServerSocket:
    def bind(self, address: tuple[str, int]) -> None:
        """
        Bind to the given `address`. `address` must currently be a 2-element tuple
        containing a hostname and a port number.
        """

    def do_handshake(self) -> None:
        """Perform the TLS setup handshake."""

    def send(self, bytes: bytes) -> int:
        """
        Send data to the socket. The socket must be connected to a remote socket. Returns the
        number of bytes sent. Applications are responsible for checking that all data has been
        sent; if only some of the data was transmitted, the application needs to attempt delivery
        of the remaining data.
        """

    def recv(self, size: int) -> bytes:
        """
        Receive data from the socket. The return value is a bytes object representing the data
        received. The maximum amount of data to be received at once is specified by `size`.
        A returned empty bytes object indicates that the client has disconnected.
        """

class ServerConnection:
    """
    A `ServerConnection` contains TLS state associated with a single server-side connection.
    It does not contain any networking state, and is not directly associated with a socket,
    so I/O happens via the methods on this object directly.

    A `ServerConnection` can be created from a `ServerConfig` `config`.
    """

    def __new__(cls, config: ServerConfig) -> ServerConnection: ...
    def readable(self) -> bool:
        """
        Returns `true` if the caller should call `read_tls()` as soon as possible.

        If there is pending plaintext data to read, this returns `false`. If your application
        respects this mechanism, only one full TLS message will be buffered by pyrtls.
        """

    def read_tls(self, buf: bytes) -> int:
        """
        Read TLS content from `buf` into the internal buffer. Return the number of bytes read, or
        `0` once a `close_notify` alert has been received. No additional data is read in this
        state.

        Due to internal buffering, `buf` may contain TLS messages in arbitrary-sized chunks (like
        a socket or pipe might).

        You should call `process_new_packets()` each time a call to this function succeeds in
        order to empty the incoming TLS data buffer.

        Exceptions may be raised to signal backpressure:

        * In order to empty the incoming TLS data buffer, you should call `process_new_packets()`
          each time a call to this function succeeds.
        * In order to empty the incoming plaintext data buffer, you should call `read_into()`
          after the call to `process_new_packets()`.

        You should call `process_new_packets()` each time a call to this function succeeds in
        order to empty the incoming TLS data buffer

        Mirrors the `RawIO.write()` interface.
        """

    def process_new_packets(self) -> IoState:
        """
        Processes any new packets read by a previous call to `read_tls()`.

        Errors from this function relate to TLS protocol errors, and are fatal to the connection.
        Future calls after an error will do no new work and will return the same error. After an
        error is returned from `process_new_packets()`, you should not call `read_tls()` anymore
        (it will fill up buffers to no purpose). However, you may call the other methods on the
        connection, including `write()` and `write_tls_into()`. Most likely you will want to
        call `write_tls_into()` to send any alerts queued by the error and then close the
        underlying connection.

        In case of success, yields an `IoState` object with sundry state about the connection.
        """

    def write(self, buf: bytes) -> int:
        """
        Send the plaintext `buf` to the peer, encrypting and authenticating it. Once this
        function succeeds you should call `write_tls_into()` which will output the
        corresponding TLS records.

        This function buffers plaintext sent before the TLS handshake completes, and sends it as
        soon as it can.
        """

    def writable(self) -> bool:
        """Returns `True` if the caller should call `write_tls_into()` as soon as possible."""

    def write_tls_into(self, buf: bytearray) -> int:
        """
        Writes TLS messages into `buf`.

        On success, this function returns the number of bytes written (after encoding and
        encryption).

        After this function returns, the connection buffer may not yet be fully flushed.
        `writable()` can be used to check if the output buffer is empty.

        Mirrors the `RawIO.readinto()` interface.
        """

    def read_into(self, buf: bytearray) -> int:
        """
        Obtain plaintext data received from the peer over this TLS connection.

        If the peer closes the TLS connection cleanly, this returns `0` once all the pending data
        has been read. No further data can be received on that connection, so the underlying TCP
        connection should be half-closed too.

        If the peer closes the TLS connection uncleanly (a TCP EOF without sending a
        `close_notify` alert) this functions raises a `TlsError` exception once any pending data
        has been read.

        Note that support for `close_notify` varies in peer TLS libraries: many do not support it
        and uncleanly close the TCP connection (this might be vulnerable to truncation attacks
        depending on the application protocol). This means applications using pyrtls must both
        handle EOF from this function, **and** unexpected EOF of the underlying TCP connection.

        If there are no bytes to read, this raises a `TlsError` exception.

        You may learn the number of bytes available at any time by inspecting the return of
        `process_new_packets()`.
        """

class ServerConfig:
    """
    Create a new `ServerConfig` object (similar to `ssl.SSLContext`). A new `ServerConnection` can
    only be created by passing in a reference to a `ServerConfig` object.

    The important configuration for `ServerConfig` is the certificate to supply to connecting
    clients, and the private key used to prove ownership of the certificate.

    Positional (mandatory) arguments:

    - `cert_chain`: an iterable, where each value must be of type `bytes` (representing the
      certificate encoded in DER) or `str` (with the certificate encoded in PEM).
    - `private_key`: a `bytes` or `str` object, containing the private key encoded in DER or PEM
      respectively. The private key can be in PKCS#1, PKCS#8, or SEC1 format.

    Other options:

    - `alpn_protocols` must be an iterable containing `bytes` or `str` objects, each representing
      one ALPN protocol string.
    """

    def __new__(
        cls,
        cert_chain: Iterable[bytes | str],
        private_key: bytes | str,
        *,
        alpn_protocols: Iterable[bytes | str] | None = None,
    ) -> ServerConfig: ...
    def wrap_socket(self, sock: socket) -> ServerSocket:
        """
        Use the `ServerConfig` and the given `sock` to create a `ServerSocket`.

        Returns a `ServerSocket` if successful.
        """
