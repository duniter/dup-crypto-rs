# DUP Crypto

![crates.io](https://img.shields.io/crates/v/dup-crypto.svg)
[![codecov](https://codecov.io/gh/duniter/dup-crypto-rs/branch/dev/graph/badge.svg)](https://codecov.io/gh/duniter/dup-crypto-rs)
[![Minimum rustc version](https://img.shields.io/badge/rustc-1.41.0+-yellow.svg)](https://github.com/rust-lang/rust/blob/master/RELEASES.md)

Cryptographic toolkit for the DUBP(1) and DUNP(2) protocols.

(1): DUniter Blockchain Protocol  
(2): DUniter Network Protocol

## Features

* Rust traits to implement to any entity that can be signed.
* Base 16/58/64 encoding/decoding
* Sha256 hash function
* Secure random byte generation
* Scrypt to generate seed from credentials.
* Ed25519 functions to create and use ed25519 keypair.
