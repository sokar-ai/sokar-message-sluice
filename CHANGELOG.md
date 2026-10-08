# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.1] - 2026-10-08

### Changed

- The documents are checked by the shared `check-citations` and `check-doc-site` of `sokar-release` 0.4.1, with
  the tests that read documents, in a `Shared rules` workflow on every push and pull request; the build skips a
  change to documents alone, and its own citation test is gone.
- A release refuses to build when anything it builds or packages with is a snapshot, as `check-releases` of
  `sokar-release` 0.4.2 reads it from the effective pom.
- Every module has a `README.md` that links its submodules, and the `Shared rules` workflow holds it with
  `check-readmes` of `sokar-release` 0.4.2.
- The build takes `org.fuin.sokar:sokar-parent` as its parent instead of `org.fuin:pom`, and drops what it gave
  with the same values - the Java release, the plugin and tool versions, the `ci-tools` profile, publishing
  nothing, the NullAway setup of the main compile; the packages are the same, and the tests run on JUnit
  5.14.2, the parent's, instead of 5.12.2.
- The `.rpm` module reads the version back out of the built `.deb` and `.rpm` (`PackageVersionIT`) and fails
  the build when either does not carry the project's version as a package version (a snapshot as
  `~snapshot.<run>`, worked out by the test, not taken from the build), or the `.rpm`'s release is not 1.
- The build takes `sokar-parent` 0.1.2, and with it `sokar-buildtools` 0.4.3.

## [0.4.0] - 2026-10-05

### Added

- Initial public version.
