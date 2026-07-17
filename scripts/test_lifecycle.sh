#!/usr/bin/env bash
# Privileged lifecycle, examples, IPC, recovery, and systemd-notify tests.

set -euo pipefail
umask 077
[[ ${EUID} -eq 0 ]] || { echo "error: run as root" >&2; exit 1; }
for command in ip ping wg nft python3 timeout; do
    command -v "${command}" >/dev/null || { echo "error: missing ${command}" >&2; exit 1; }
done

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CLIENT_BIN=${RUSTGUARD_CLIENT_BIN:-"${ROOT_DIR}/target/debug/rustguard-client"}
SERVER_BIN=${RUSTGUARD_SERVER_BIN:-"${ROOT_DIR}/target/debug/rustguard-server"}
TEST_DIR=$(mktemp -d /tmp/rustguard-lifecycle.XXXXXX)
SERVER_NS="rgls$$"
CLIENT_NS="rglc$$"
SERVER_VETH="rglsv$$"
CLIENT_VETH="rglcv$$"
SERVER_PID=""
CLIENT_PID=""
NOTIFY_PID=""

cleanup() {
    set +e
    for pid in "${CLIENT_PID}" "${SERVER_PID}" "${NOTIFY_PID}"; do
        [[ -n ${pid} ]] && kill "${pid}" 2>/dev/null
    done
    timeout 2 tail --pid="${CLIENT_PID:-1}" -f /dev/null 2>/dev/null
    timeout 2 tail --pid="${SERVER_PID:-1}" -f /dev/null 2>/dev/null
    rm -f /run/rustguard/client.lock /run/rustguard/client.sock \
        /run/rustguard/client.status.json /run/rustguard/server.lock \
        /run/rustguard/server.sock /run/rustguard/server.status.json \
        /run/rustguard/client-rg0.json /run/rustguard/client-rg0.json.new
    ip netns del "${CLIENT_NS}" 2>/dev/null
    ip netns del "${SERVER_NS}" 2>/dev/null
    rm -rf -- "${TEST_DIR}"
}
trap cleanup EXIT INT TERM
rm -f /run/rustguard/client.lock /run/rustguard/client.sock \
    /run/rustguard/client.status.json /run/rustguard/server.lock \
    /run/rustguard/server.sock /run/rustguard/server.status.json \
    /run/rustguard/client-rg0.json /run/rustguard/client-rg0.json.new

mkdir "${TEST_DIR}/bin"
cat >"${TEST_DIR}/bin/resolvectl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"${RUSTGUARD_RESOLVECTL_LOG}"
EOF
chmod 700 "${TEST_DIR}/bin/resolvectl"
cp "${ROOT_DIR}/examples/client.toml" "${TEST_DIR}/client.toml"
cp "${ROOT_DIR}/examples/server.toml" "${TEST_DIR}/server.toml"
chmod 600 "${TEST_DIR}/client.toml" "${TEST_DIR}/server.toml"

ip netns add "${SERVER_NS}"
ip netns add "${CLIENT_NS}"
ip link add "${SERVER_VETH}" type veth peer name "${CLIENT_VETH}"
ip link set "${SERVER_VETH}" netns "${SERVER_NS}"
ip link set "${CLIENT_VETH}" netns "${CLIENT_NS}"
ip -n "${SERVER_NS}" link set lo up
ip -n "${CLIENT_NS}" link set lo up
ip -n "${SERVER_NS}" address add 192.0.2.1/24 dev "${SERVER_VETH}"
ip -n "${CLIENT_NS}" address add 192.0.2.2/24 dev "${CLIENT_VETH}"
ip -n "${SERVER_NS}" link set "${SERVER_VETH}" up
ip -n "${CLIENT_NS}" link set "${CLIENT_VETH}" up

echo "[1/4] role checks, hostname resolution, and invalid-config no-mutation"
ip netns exec "${CLIENT_NS}" env PATH="${TEST_DIR}/bin:${PATH}" \
    RUSTGUARD_RESOLVECTL_LOG="${TEST_DIR}/resolved.log" \
    "${CLIENT_BIN}" --config "${TEST_DIR}/client.toml" check | grep -q "valid client schema"
ip netns exec "${SERVER_NS}" "${SERVER_BIN}" --config "${TEST_DIR}/server.toml" check \
    | grep -q "valid server schema"
sed -i 's/debug_to_file = false/debug_to_file = true/' "${TEST_DIR}/server.toml"
sed 's/192\.0\.2\.1:51820/localhost:51820/' "${TEST_DIR}/client.toml" \
    >"${TEST_DIR}/hostname.toml"
chmod 600 "${TEST_DIR}/hostname.toml"
ip netns exec "${CLIENT_NS}" env PATH="${TEST_DIR}/bin:${PATH}" \
    RUSTGUARD_RESOLVECTL_LOG="${TEST_DIR}/resolved.log" \
    "${CLIENT_BIN}" --config "${TEST_DIR}/hostname.toml" check | grep -q "localhost:51820 -> 127.0.0.1:51820"
sed '/mtu = 1420/a listen_port = 12345' "${TEST_DIR}/client.toml" >"${TEST_DIR}/invalid.toml"
chmod 600 "${TEST_DIR}/invalid.toml"
if ip netns exec "${CLIENT_NS}" "${CLIENT_BIN}" --config "${TEST_DIR}/invalid.toml" up \
    >"${TEST_DIR}/invalid.log" 2>&1; then
    echo "error: invalid role-specific configuration started" >&2
    exit 1
fi
! ip -n "${CLIENT_NS}" link show rg0 >/dev/null 2>&1
[[ ! -e /run/rustguard/client.lock ]]

echo "[2/4] shipped examples, exclusive ownership, live status, and IPC stop"
python3 -c 'import socket; p="'"${TEST_DIR}"'/notify.sock"; s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); s.bind(p); f=open("'"${TEST_DIR}"'/notify.log","w");
for _ in range(2): f.write(s.recv(4096).decode()+"\n"); f.flush()' &
NOTIFY_PID=$!
for _ in {1..20}; do [[ -S "${TEST_DIR}/notify.sock" ]] && break; sleep 0.1; done

ip netns exec "${SERVER_NS}" env NOTIFY_SOCKET="${TEST_DIR}/notify.sock" \
    "${SERVER_BIN}" --config "${TEST_DIR}/server.toml" start >"${TEST_DIR}/server.log" 2>&1 &
SERVER_PID=$!
for _ in {1..50}; do [[ -S /run/rustguard/server.sock ]] && break; sleep 0.1; done
SERVER_DEBUG_LOG=$(find /tmp -maxdepth 1 -type f -name "rustguard-server-${SERVER_PID}-*.log" -print -quit)
[[ -n ${SERVER_DEBUG_LOG} && $(stat -c %a "${SERVER_DEBUG_LOG}") == 600 ]]
ip netns exec "${CLIENT_NS}" env PATH="${TEST_DIR}/bin:${PATH}" \
    RUSTGUARD_RESOLVECTL_LOG="${TEST_DIR}/resolved.log" \
    "${CLIENT_BIN}" --config "${TEST_DIR}/client.toml" up >"${TEST_DIR}/client.log" 2>&1 &
CLIENT_PID=$!
for _ in {1..50}; do [[ -S /run/rustguard/client.sock ]] && break; sleep 0.1; done

ip netns exec "${CLIENT_NS}" ping -n -c 2 -W 2 10.0.0.1 >/dev/null
ip netns exec "${SERVER_NS}" ping -n -c 2 -W 2 10.0.0.2 >/dev/null
CLIENT_STATUS=$(ip netns exec "${CLIENT_NS}" "${CLIENT_BIN}" status)
SERVER_STATUS=$(ip netns exec "${SERVER_NS}" "${SERVER_BIN}" status)
grep -q "process: running" <<<"${CLIENT_STATUS}"
grep -q "handshake: established" <<<"${CLIENT_STATUS}"
grep -Eq "transfer: [1-9][0-9]* bytes sent" <<<"${CLIENT_STATUS}"
grep -q "handshake: established" <<<"${SERVER_STATUS}"
grep -q "READY=1" "${TEST_DIR}/notify.log"

if ip netns exec "${CLIENT_NS}" env PATH="${TEST_DIR}/bin:${PATH}" \
    RUSTGUARD_RESOLVECTL_LOG="${TEST_DIR}/resolved.log" \
    "${CLIENT_BIN}" --config "${TEST_DIR}/client.toml" up >/dev/null 2>&1; then
    echo "error: duplicate client acquired runtime ownership" >&2
    exit 1
fi
if ip netns exec "${SERVER_NS}" "${SERVER_BIN}" recover >/dev/null 2>&1; then
    echo "error: recovery removed an active owner" >&2
    exit 1
fi

ip netns exec "${CLIENT_NS}" "${CLIENT_BIN}" down | grep -q "stopped"
wait "${CLIENT_PID}" || true
CLIENT_PID=""
ip netns exec "${SERVER_NS}" "${SERVER_BIN}" stop | grep -q "stopped"
wait "${SERVER_PID}" || true
SERVER_PID=""
wait "${NOTIFY_PID}" || true
NOTIFY_PID=""
grep -q "STOPPING=1" "${TEST_DIR}/notify.log"
[[ ! -e ${SERVER_DEBUG_LOG} ]]
[[ ! -e /run/rustguard/client.lock && ! -e /run/rustguard/server.lock ]]
! ip -n "${CLIENT_NS}" link show rg0 >/dev/null 2>&1
! ip -n "${SERVER_NS}" link show rg0 >/dev/null 2>&1

echo "[3/4] stopped status and idempotent stale recovery"
if "${CLIENT_BIN}" status >/dev/null 2>&1; then
    echo "error: stopped client reported running" >&2
    exit 1
fi
printf '999999\n' >/run/rustguard/client.lock
: >/run/rustguard/client.sock
: >/run/rustguard/client.status.json
"${CLIENT_BIN}" recover | grep -q "recovered"
"${CLIENT_BIN}" recover | grep -q "recovered"
[[ ! -e /run/rustguard/client.lock && ! -e /run/rustguard/client.sock ]]

echo "[4/4] resolver intent and private runtime modes"
grep -Fxq "dns rg0 10.0.0.1" "${TEST_DIR}/resolved.log"
grep -Fxq "domain rg0 ~." "${TEST_DIR}/resolved.log"
grep -Fxq "revert rg0" "${TEST_DIR}/resolved.log"
[[ $(stat -c %a /run/rustguard) == 700 ]]

echo "all operational lifecycle tests passed"
