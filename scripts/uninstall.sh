#!/usr/bin/env bash
set -euo pipefail

DESTDIR=${DESTDIR:-}
BINDIR=${BINDIR:-/usr/local/bin}
SYSCONFDIR=${SYSCONFDIR:-/etc/rustguard}
UNITDIR=${UNITDIR:-/etc/systemd/system}

if [[ -z ${DESTDIR} ]] && command -v systemctl >/dev/null; then
    systemctl disable --now rustguard-client.service rustguard-server.service 2>/dev/null || true
fi

rm -f -- \
    "${DESTDIR}${BINDIR}/rustguard-client" \
    "${DESTDIR}${BINDIR}/rustguard-server" \
    "${DESTDIR}${UNITDIR}/rustguard-client.service" \
    "${DESTDIR}${UNITDIR}/rustguard-server.service"

if [[ -z ${DESTDIR} && ${NO_SYSTEMD_RELOAD:-0} != 1 ]] && command -v systemctl >/dev/null; then
    systemctl daemon-reload
fi

echo "RustGuard binaries and units removed"
echo "configuration retained in ${SYSCONFDIR}; remove it manually only after preserving any keys you need"
