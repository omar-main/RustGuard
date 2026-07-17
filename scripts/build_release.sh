#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PROJECT_DIR=$(cd -- "${SCRIPT_DIR}/.." && pwd)
VERSION=${1:-$(sed -n 's/^version = "\([^"]*\)"/\1/p' "${PROJECT_DIR}/Cargo.toml" | head -n1)}
OUTPUT_DIR=${2:-${PROJECT_DIR}/dist}
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "${PROJECT_DIR}" log -1 --format=%ct)}
ARCHIVE="rustguard-${VERSION}-x86_64-unknown-linux-gnu"
STAGING=$(mktemp -d)
trap 'rm -rf -- "${STAGING}"' EXIT

cd "${PROJECT_DIR}"
export SOURCE_DATE_EPOCH
cargo build --workspace --release --locked

mkdir -p "${STAGING}/${ARCHIVE}/bin" "${STAGING}/${ARCHIVE}/systemd" \
    "${STAGING}/${ARCHIVE}/scripts" "${OUTPUT_DIR}"
install -m 0755 target/release/rustguard-client "${STAGING}/${ARCHIVE}/bin/"
install -m 0755 target/release/rustguard-server "${STAGING}/${ARCHIVE}/bin/"
cp -a README.md LICENSE LICENSE-MIT SECURITY.md examples docs "${STAGING}/${ARCHIVE}/"
cp -a scripts/install.sh scripts/uninstall.sh "${STAGING}/${ARCHIVE}/scripts/"
cp -a systemd/*.service "${STAGING}/${ARCHIVE}/systemd/"

{
    echo "version=${VERSION}"
    echo "git_commit=$(git rev-parse HEAD)"
    echo "source_date_epoch=${SOURCE_DATE_EPOCH}"
    echo "rustc=$(rustc --version)"
    echo "cargo_lock_sha256=$(sha256sum Cargo.lock | cut -d' ' -f1)"
} >"${STAGING}/${ARCHIVE}/PROVENANCE.txt"

tar --sort=name --mtime="@${SOURCE_DATE_EPOCH}" --owner=0 --group=0 --numeric-owner \
    -C "${STAGING}" -cf - "${ARCHIVE}" | gzip -n >"${OUTPUT_DIR}/${ARCHIVE}.tar.gz"
(
    cd "${OUTPUT_DIR}"
    sha256sum "${ARCHIVE}.tar.gz" >"${ARCHIVE}.tar.gz.sha256"
)
echo "created ${OUTPUT_DIR}/${ARCHIVE}.tar.gz"
