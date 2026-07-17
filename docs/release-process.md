# Release process

RustGuard uses a committed `Cargo.lock`, dependency-policy checks, deterministic
archive metadata, SHA-256 checksums, and GitHub build provenance. These controls
make inputs and artifacts inspectable; they are not a third-party security audit.

## Local candidate gate

From a clean checkout of the candidate commit:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo deny check
bash scripts/test_install.sh
sudo bash scripts/test_single_peer.sh
sudo bash scripts/test_client_networking.sh
sudo bash scripts/test_lifecycle.sh
sudo bash scripts/test_multi_peer.sh
bash scripts/build_release.sh
```

Run the Rust checks on both supported Ubuntu releases. Verify a second invocation
of `build_release.sh` from the same commit and toolchain produces the same archive
checksum. The archive records the commit, Rust compiler, source epoch, and lockfile
digest in `PROVENANCE.txt`.

## Publishing

1. Confirm CI is green on the candidate commit.
2. Confirm the version in `Cargo.toml` and release notes agree.
3. Create a signed or annotated `v0.1.0-rc.1` tag on that exact commit.
4. Push the tag. The release workflow rebuilds, tests, checksums, attests, and
   publishes the prerelease assets.
5. Download the published archive and verify its `.sha256` file with
   `sha256sum -c`.

Do not describe a local run as remotely green. GitHub-hosted results and
attestations exist only after the commit and tag are pushed.

The current local gate is recorded in [Release candidate evidence](release-evidence.md).
