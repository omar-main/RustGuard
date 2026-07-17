#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
TEST_DIR=$(mktemp -d)
trap 'rm -rf -- "${TEST_DIR}"' EXIT

for unit in rustguard-client.service rustguard-server.service; do
    sed -E 's#/usr/local/bin/rustguard-(client|server)([^[:space:]]*)#/bin/true#g' \
        "${PROJECT_DIR}/systemd/${unit}" >"${TEST_DIR}/${unit}"
    chmod 0644 "${TEST_DIR}/${unit}"
done

systemd-analyze verify "${TEST_DIR}"/*.service
grep -q '^CapabilityBoundingSet=CAP_NET_ADMIN$' "${PROJECT_DIR}/systemd/rustguard-client.service"
grep -q '^DeviceAllow=/dev/net/tun rw$' "${PROJECT_DIR}/systemd/rustguard-server.service"
grep -q '^ProtectSystem=strict$' "${PROJECT_DIR}/systemd/rustguard-client.service"
echo "systemd unit syntax and required hardening directives passed"
