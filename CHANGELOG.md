# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->

## [Unreleased] - ReleaseDate

### Changed

- DEWIF: add currency field

## [0.10.0] - 2020-02-20

### Changed

- DEWIF: read_dewif_file_content() now directly returns an Iterator.

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

<!-- next-url -->
[Unreleased]: https://git.duniter.org/libs/dup-crypto-rs/compare/v0.10.0...HEAD
[0.10.0]: https://git.duniter.org/libs/dup-crypto-rs/compare/v0.9.1...v0.10.0
[0.9.1]: https://git.duniter.org/libs/dup-crypto-rs/compare/v0.8.0...v0.9.1
