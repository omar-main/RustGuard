#!/usr/bin/env bash
set -euo pipefail

DESTDIR=${DESTDIR:-}
BINDIR=${BINDIR:-/usr/local/bin}
SYSCONFDIR=${SYSCONFDIR:-/etc/rustguard}
UNITDIR=${UNITDIR:-/etc/systemd/system}
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PROJECT_DIR=$(cd -- "${SCRIPT_DIR}/.." && pwd)
ARTIFACT_DIR=${RUSTGUARD_ARTIFACT_DIR:-${PROJECT_DIR}/target/release}
if [[ ! -x ${ARTIFACT_DIR}/rustguard-client && -x ${PROJECT_DIR}/bin/rustguard-client ]]; then
    ARTIFACT_DIR=${PROJECT_DIR}/bin
fi

for binary in rustguard-client rustguard-server; do
    [[ -x ${ARTIFACT_DIR}/${binary} ]] || {
        echo "error: missing ${ARTIFACT_DIR}/${binary}; build with cargo build --release --locked" >&2
        exit 1
    }
done

install -D -m 0755 "${ARTIFACT_DIR}/rustguard-client" "${DESTDIR}${BINDIR}/rustguard-client"
install -D -m 0755 "${ARTIFACT_DIR}/rustguard-server" "${DESTDIR}${BINDIR}/rustguard-server"
install -D -m 0644 "${PROJECT_DIR}/systemd/rustguard-client.service" "${DESTDIR}${UNITDIR}/rustguard-client.service"
install -D -m 0644 "${PROJECT_DIR}/systemd/rustguard-server.service" "${DESTDIR}${UNITDIR}/rustguard-server.service"
install -d -m 0700 "${DESTDIR}${SYSCONFDIR}"

for role in client server; do
    destination="${DESTDIR}${SYSCONFDIR}/${role}.toml"
    if [[ ! -e ${destination} ]]; then
        install -m 0600 "${PROJECT_DIR}/examples/${role}.toml" "${destination}"
        echo "installed example ${destination}; replace every key before enabling the service"
    else
        echo "preserved existing ${destination}"
    fi
done

if [[ -z ${DESTDIR} && ${NO_SYSTEMD_RELOAD:-0} != 1 ]] && command -v systemctl >/dev/null; then
    systemctl daemon-reload
fi

echo "RustGuard installed; review ${SYSCONFDIR} before enabling either service"
