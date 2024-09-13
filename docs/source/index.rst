pyrtls
======

pyrtls provides a modern Rust-based TLS implementation with an API that is intended to be easy
to use to replace the `ssl` module (but not entirely compatible with it).

In addition to being memory-safe, the library is designed to be more secure by default. As such,
it does not implement older protocol versions, cipher suites with known security problems, and
some problematic features of the TLS protocol. For more details, review the `rustls manual`_.

.. _rustls manual: https://docs.rs/rustls/latest/rustls/manual/index.html

Features
--------

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

API reference
=============

.. toctree::
   :maxdepth: 2

   reference

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
