# pyrtls: rustls-based TLS for Python

[![Latest version](https://img.shields.io/pypi/v/pyrtls.svg)](https://pypi.org/project/pyrtls)
[![Documentation](https://readthedocs.org/projects/pyrtls/badge/?version=latest)](https://pyrtls.readthedocs.io)
[![CI](https://github.com/djc/pyrtls/workflows/CI/badge.svg?branch=main)](https://github.com/djc/pyrtls/actions?query=workflow%3ACI+branch%3Amain)

pyrtls provides bindings to [rustls][rustls], a modern Rust-based TLS implementation with an API that is
intended to be easy to use to replace the `ssl` module (but not entirely compatible with it).

In addition to being memory-safe, the library is designed to be more secure by default. As such,
it does not implement older protocol versions, cipher suites with known security problems, and
some problematic features of the TLS protocol. For more details, review the [rustls manual][manual].

> [!WARNING]
> This project is just getting started. While rustls is mature, the Python bindings
> are pretty new and not yet feature-complete. Please consider helping out (see below).

[rustls]: https://github.com/rustls/rustls
[manual]: https://docs.rs/rustls/latest/rustls/manual/index.html

## Why?

To bring the security and performance of rustls to the Python world.

So far this is a side project. Please consider helping out:

* Please help fund this work on [GitHub Sponsors](https://github.com/sponsors/djc)
* Pull requests welcome, of course!
* Feedback through [issues] is highly appreciated
* If you're interested in commercial support, please contact me

[issues]: https://github.com/djc/pyrtls/issues

## Features

- Support for TLS 1.2 and 1.3
- Support for commonly used secure cipher suites
- Support for ALPN protocol negotiation
- Support for Server Name Indication (SNI)
- Support for session resumption

Not implemented
---------------

- TLS 1.1 and older versions of the protocol
- Older cipher suites with security problems
- Using CA certificates directly to authenticate a server/client (often called self-signed
  certificates). The built-in certificate verifier does not support using a trust anchor
  as both a CA certificate and an end-entity certificate, in order to limit complexity and
  risk in path building.
