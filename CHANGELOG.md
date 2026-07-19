# Changelog

All notable changes to wingfoot are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] - 2026-07-19

### Added

- Ship a PEP 561 `py.typed` marker so downstream type checkers (mypy, pyright)
  read wingfoot's type hints instead of treating the package as untyped. ([#5])

### Fixed

- `wingfoot sign` now reports a clean error and exits 1 when the URL cannot be
  reached (DNS failure, connection refused, timeout) instead of dumping a
  `urllib` traceback. ([#4])
- `load_identity` raises an actionable `IdentityError` (with a "re-run
  `wingfoot init`" hint) when the stored identity is corrupt or incomplete, so
  every command that loads it fails cleanly instead of with a raw traceback. ([#6])
- `verify_request` now requires the `expires` parameter and applies the allowed
  clock skew to it, closing a gap where a just-expired signature could still
  verify. ([#3])
- `find_key` no longer crashes when the key directory (JWKS) contains entries
  that are not Ed25519; non-matching keys are skipped. ([#2])

### Documentation

- Add a security policy (`SECURITY.md`), this changelog, and issue /
  pull-request templates.

## [0.1.1] - 2026-07-07

### Fixed

- Bare `wingfoot` (no arguments) prints the full help instead of an argparse
  "arguments are required" error.

### Documentation

- Note the `uv tool` / `pipx` install path for macOS, where PEP 668 blocks a
  global `pip3` install.
- Install from PyPI with `pip install wingfoot` now that the package is published.

## [0.1.0] - 2026-07-07

Initial release.

### Added

- Web Bot Auth signing of outbound HTTP requests with an Ed25519 key, following
  the RFC 9421 HTTP Message Signatures profile.
- A reference verifier and `wingfoot demo`, which runs the unsigned/signed flow
  in a single process, offline and with no setup.
- `wingfoot doctor` — sends a signed request and reports, as a checklist, why it
  was accepted or rejected.
- `wingfoot init`, `directory`, `sign`, `serve`, and `verifier` commands.
- `wingfoot register` — preflights your hosted key directory the way a reviewer
  would, then prints ready-to-paste registration packets for Cloudflare,
  DataDome, and other verifiers.
- A signed key directory response served at
  `/.well-known/http-message-signatures-directory`, so a verifier can trust the
  directory it fetches.
- Drop-in signing for `requests` and `httpx` (`wingfoot.requests_auth()`,
  `wingfoot.httpx_auth()`, `wingfoot.signed_headers()`); both clients are
  optional extras.
- A descriptive default `User-Agent`, since many CDNs block urllib's default
  outright.
- Publish to PyPI on GitHub Release via Trusted Publishing (OIDC).

[Unreleased]: https://github.com/AmirF194/wingfoot/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/AmirF194/wingfoot/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/AmirF194/wingfoot/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/AmirF194/wingfoot/releases/tag/v0.1.0
[#2]: https://github.com/AmirF194/wingfoot/pull/2
[#3]: https://github.com/AmirF194/wingfoot/pull/3
[#4]: https://github.com/AmirF194/wingfoot/pull/4
[#5]: https://github.com/AmirF194/wingfoot/pull/5
[#6]: https://github.com/AmirF194/wingfoot/pull/6
