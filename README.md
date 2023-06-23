# pyrtls: rustls-based TLS for Python

Aims to be more secure, faster replacement for the venerable ssl module.
Uses [rustls](https://github.com/rustls/rustls/) as the backing implementation.

**WARNING**: this is currently a technology preview. There might be bugs. (That said,
it is unlikely that there will be security vulnerabilities, since this library
just implements a thin wrapper over the core rustls library API.)

## Why?

To bring the security and performance of rustls to the Python world.

So far this, this is a side project. Please consider helping out:

* Please help fund this work on [GitHub Sponsors](https://github.com/sponsors/djc)
* Pull requests welcome, of course!
* Feedback through issues is highly appreciated

## Features

* Basic socket wrapper support, similar to the `ssl` module
* (Not yet implemented:) [sans-I/O](https://sans-io.readthedocs.io/how-to-sans-io.html) TLS connection support
* Uses the OS certificate trust store for clients by default
* Better [performance](https://jbp.io/2019/07/01/rustls-vs-openssl-performance.html)
  than OpenSSL

## Limitations

* Basically no features implemented yet
* There's not currently any documentation
