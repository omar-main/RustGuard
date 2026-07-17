# Release candidate evidence

This record summarizes local evidence for commit preparation on 2026-07-17. It
does not claim a GitHub-hosted result before the commit is pushed.

| Gate | Evidence |
| --- | --- |
| Formatting | `cargo fmt --all -- --check` passed |
| Strict lint | Workspace/all-target/all-feature Clippy passed with warnings denied |
| Unit tests | 37 tests passed across all four workspace crates |
| Locked release | Workspace release build passed with the committed lockfile |
| Minimum Rust | Workspace/all-target check passed on Rust 1.85.0 |
| Dependency policy | cargo-deny 0.20.2: advisories, bans, licenses, and sources passed |
| Service assets | Both systemd units parsed and required hardening directives passed |
| Deployment | Fresh install, preserving upgrade, and uninstall passed |
| Single peer | Three-way RustGuard/official-WireGuard matrix passed |
| Client safety | Split/full routing, DNS, kill switch, rollback, and crash recovery passed |
| Lifecycle | Examples, IPC, status, notification, permissions, and recovery passed |
| Multi-peer | Three peers, spoof rejection, roaming, and peer-failure isolation passed |
| Reproducibility | Two archives from identical inputs compared byte-for-byte |

The configured CI matrix repeats these checks on Ubuntu 22.04 and 24.04. Its
remote status remains pending until the commit is pushed. Tagged releases also
receive a GitHub build-provenance attestation.
