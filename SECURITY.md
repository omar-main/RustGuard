# Security Policy

RustGuard is an experimental personal VPN and is not independently audited. Do
not report ordinary support questions as vulnerabilities, and do not rely on an
unreleased build to protect sensitive or production traffic.

## Supported versions

Only the newest published release candidate or release receives security fixes.
The `main` branch may contain incomplete work.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting feature for this repository. Do
not open a public issue containing exploit details, private keys, configurations,
network addresses, or logs that may identify a deployment.

Include the affected version, operating system, reproduction steps, impact, and
whether the problem has been reproduced with an official WireGuard peer. Never
include active key material; generate disposable keys for a reproducer.

## Dependency policy

CI runs `cargo deny check` against the committed lockfile. Known vulnerability,
yanked-package, license, and source-policy failures block a release. An advisory
may be ignored only with a narrow entry in `deny.toml`, a written rationale, an
expiry or removal condition, and documentation in the release notes.
