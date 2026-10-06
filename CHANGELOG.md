# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial public version.

### Changed

- The documents are checked by the shared `check-citations` and `check-doc-site` of `sokar-release` 0.4.1, with
  the tests that read documents, in a `Shared rules` workflow on every push and pull request; the build skips a
  change to documents alone, and its own citation test is gone.
