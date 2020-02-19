# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.1] - 2020-01-19

### Added

- Read/write DEWIF file content #1
- Aes256 encryption/decryption
- hashs::Hash impl AsRef<[u8]>

### Changed

- Ed25519KeyPair::generate_signator cannot fail.

### Security

- Ed25519KeyPair must not expose seed

## [0.8.0] - 2020-01-16

Initial version.
