#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
TEST_ROOT=$(mktemp -d)
trap 'rm -rf -- "${TEST_ROOT}"' EXIT

cd "${PROJECT_DIR}"
cargo build --workspace --release --locked

DESTDIR=${TEST_ROOT} NO_SYSTEMD_RELOAD=1 bash scripts/install.sh
test -x "${TEST_ROOT}/usr/local/bin/rustguard-client"
test -x "${TEST_ROOT}/usr/local/bin/rustguard-server"
test "$(stat -c %a "${TEST_ROOT}/etc/rustguard/client.toml")" = 600
test "$(stat -c %a "${TEST_ROOT}/etc/rustguard")" = 700
test -f "${TEST_ROOT}/etc/systemd/system/rustguard-client.service"

printf '\n# preserved-by-upgrade\n' >>"${TEST_ROOT}/etc/rustguard/client.toml"
DESTDIR=${TEST_ROOT} NO_SYSTEMD_RELOAD=1 bash scripts/install.sh
grep -q preserved-by-upgrade "${TEST_ROOT}/etc/rustguard/client.toml"

DESTDIR=${TEST_ROOT} NO_SYSTEMD_RELOAD=1 bash scripts/uninstall.sh
test ! -e "${TEST_ROOT}/usr/local/bin/rustguard-client"
test ! -e "${TEST_ROOT}/etc/systemd/system/rustguard-client.service"
grep -q preserved-by-upgrade "${TEST_ROOT}/etc/rustguard/client.toml"
echo "install, upgrade, and uninstall test passed"
