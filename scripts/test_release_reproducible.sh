#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
TEST_DIR=$(mktemp -d)
trap 'rm -rf -- "${TEST_DIR}"' EXIT
SOURCE_DATE_EPOCH=$(git -C "${PROJECT_DIR}" log -1 --format=%ct)
export SOURCE_DATE_EPOCH

bash "${PROJECT_DIR}/scripts/build_release.sh" 0.1.0-rc.1 "${TEST_DIR}/first"
bash "${PROJECT_DIR}/scripts/build_release.sh" 0.1.0-rc.1 "${TEST_DIR}/second"
cmp "${TEST_DIR}/first/rustguard-0.1.0-rc.1-x86_64-unknown-linux-gnu.tar.gz" \
    "${TEST_DIR}/second/rustguard-0.1.0-rc.1-x86_64-unknown-linux-gnu.tar.gz"
echo "release archive reproduced byte-for-byte"
