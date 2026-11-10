# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Podman container provider with environment-recon selection for sandboxes.
- OpenTelemetry spans at the Provider/Sandbox seam, recorded through a shared JSONL contract.

### Changed

- Go toolchain raised to 1.27.3 (crypto/x509 vulnerability fix).

### Fixed

- Stale exit-file removal could follow a sandbox-planted `/run` symlink and delete host files; removal is now contained within the rootfs, and execution aborts when the parent cannot be resolved.
- The temporary image export file was never closed on any return path; it is now closed deterministically.
- Rootfs extraction discarded declared image ownership (UID/GID); ownership is now preserved, and creating a sandbox with a configured user under non-root extraction fails closed instead of degrading silently.
- Sandbox-controlled file reads and the `/etc/passwd` lookup are now contained and bounded.
- Create recovery after a lost response resolved the wrong expected template for providers with a default image; the provider default is now resolved before the recovery comparison.
- The telemetry (traced) provider wrapper dropped the providers' optional Close and default-template interfaces; both are now preserved and delegated.

For releases up to v0.6.2, see the per-version notes in `docs/` (`docs/release-v0.5.0.md` – `docs/release-v0.6.2.md`).
