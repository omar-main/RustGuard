#!/usr/bin/env bash
# Privileged namespace tests for transactional client networking.

set -euo pipefail
umask 077

[[ ${EUID} -eq 0 ]] || { echo "error: run as root" >&2; exit 1; }
for command in ip nft ping wg python3 timeout; do
    command -v "${command}" >/dev/null || { echo "error: missing ${command}" >&2; exit 1; }
done

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CLIENT_BIN=${RUSTGUARD_CLIENT_BIN:-"${ROOT_DIR}/target/debug/rustguard-client"}
[[ -x ${CLIENT_BIN} ]] || { echo "error: build ${CLIENT_BIN} first" >&2; exit 1; }

TEST_DIR=$(mktemp -d /tmp/rustguard-networking.XXXXXX)
SERVER_NS="rgns$$"
CLIENT_NS="rgnc$$"
SERVER_VETH="rgnsv$$"
CLIENT_VETH="rgncv$$"
CLIENT_PID=""
LISTENER_PIDS=()
JOURNAL=/run/rustguard/client-rg0.json
DNS_LOG="${TEST_DIR}/resolvectl.log"

cleanup() {
    set +e
    if [[ -n ${CLIENT_PID} ]] && kill -0 "${CLIENT_PID}" 2>/dev/null; then
        kill -TERM "${CLIENT_PID}" 2>/dev/null
        timeout 5 tail --pid="${CLIENT_PID}" -f /dev/null 2>/dev/null
        kill -KILL "${CLIENT_PID}" 2>/dev/null
    fi
    for pid in "${LISTENER_PIDS[@]}"; do kill "${pid}" 2>/dev/null; done
    ip netns exec "${CLIENT_NS}" env PATH="${TEST_DIR}/bin:${PATH}" \
        RUSTGUARD_RESOLVECTL_LOG="${DNS_LOG}" "${CLIENT_BIN}" emergency-off >/dev/null 2>&1
    ip netns del "${CLIENT_NS}" 2>/dev/null
    ip netns del "${SERVER_NS}" 2>/dev/null
    rm -rf -- "${TEST_DIR}"
}
trap cleanup EXIT INT TERM

mkdir "${TEST_DIR}/bin"
cat >"${TEST_DIR}/bin/resolvectl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"${RUSTGUARD_RESOLVECTL_LOG}"
EOF
chmod 700 "${TEST_DIR}/bin/resolvectl"

wg genkey >"${TEST_DIR}/server.private"
wg pubkey <"${TEST_DIR}/server.private" >"${TEST_DIR}/server.public"
wg genkey >"${TEST_DIR}/client.private"
wg pubkey <"${TEST_DIR}/client.private" >"${TEST_DIR}/client.public"

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

ip -n "${SERVER_NS}" link add wg0 type wireguard
ip netns exec "${SERVER_NS}" wg set wg0 listen-port 51830 \
    private-key "${TEST_DIR}/server.private" peer "$(<"${TEST_DIR}/client.public")" \
    allowed-ips 10.90.0.2/32
ip -n "${SERVER_NS}" address add 10.90.0.1/24 dev wg0
ip -n "${SERVER_NS}" link set wg0 up

# Unrelated state must survive all graceful and crash recovery paths.
ip -n "${CLIENT_NS}" route add 203.0.113.0/24 dev "${CLIENT_VETH}"
ip netns exec "${CLIENT_NS}" nft add table inet rg_sentinel

write_config() {
    local allowed=$1 kill_switch=$2 dns=$3
    cat >"${TEST_DIR}/client.toml" <<EOF
[interface]
private_key = "$(<"${TEST_DIR}/client.private")"
address = "10.90.0.2/24"
dns = ["10.90.0.1"]
mtu = 1420

[[peer]]
public_key = "$(<"${TEST_DIR}/server.public")"
endpoint = "192.0.2.1:51830"
allowed_ips = ["${allowed}"]
persistent_keepalive = 1

[client]
kill_switch = ${kill_switch}
dns_leak_prevention = ${dns}
allow_lan = false
EOF
    chmod 600 "${TEST_DIR}/client.toml"
}

wait_for_client() {
    for _ in {1..50}; do
        if ip -n "${CLIENT_NS}" link show rg0 >/dev/null 2>&1 && [[ -f ${JOURNAL} ]]; then return; fi
        sleep 0.1
    done
    echo "error: client networking did not become ready" >&2
    sed -n '1,160p' "${TEST_DIR}/client.log" >&2
    exit 1
}

start_client() {
    : >"${TEST_DIR}/client.log"
    ip netns exec "${CLIENT_NS}" env PATH="${TEST_DIR}/bin:${PATH}" \
        RUSTGUARD_RESOLVECTL_LOG="${DNS_LOG}" "${CLIENT_BIN}" \
        --config "${TEST_DIR}/client.toml" up >"${TEST_DIR}/client.log" 2>&1 &
    CLIENT_PID=$!
    wait_for_client
}

stop_client() {
    kill -TERM "${CLIENT_PID}"
    timeout 5 tail --pid="${CLIENT_PID}" -f /dev/null
    wait "${CLIENT_PID}" || true
    CLIENT_PID=""
}

assert_owned_state_absent() {
    [[ ! -e ${JOURNAL} ]] || { echo "error: recovery journal remains" >&2; exit 1; }
    ! ip -n "${CLIENT_NS}" route show exact 192.0.2.1/32 | grep -q .
    ! ip netns exec "${CLIENT_NS}" nft list table inet rustguard_rg0 >/dev/null 2>&1
    ip -n "${CLIENT_NS}" route show exact 203.0.113.0/24 | grep -q .
    ip netns exec "${CLIENT_NS}" nft list table inet rg_sentinel >/dev/null
}

echo "[1/3] exact split routing and graceful rollback"
write_config 10.90.0.1/32 false false
start_client
ip -n "${CLIENT_NS}" route show exact 10.90.0.1/32 | grep -q "dev rg0"
ip -n "${CLIENT_NS}" route show exact 192.0.2.1/32 | grep -q "dev ${CLIENT_VETH}"
ip netns exec "${CLIENT_NS}" ping -n -c 2 -W 2 10.90.0.1 >/dev/null
stop_client
assert_owned_state_absent

echo "[2/3] full routing, resolved DNS, and fail-closed leak policy"
write_config 0.0.0.0/0 true true
start_client
ip -n "${CLIENT_NS}" route show exact 0.0.0.0/1 | grep -q "dev rg0"
ip -n "${CLIENT_NS}" route show exact 128.0.0.0/1 | grep -q "dev rg0"
ip -n "${CLIENT_NS}" route show exact 192.0.2.1/32 | grep -q "dev ${CLIENT_VETH}"
grep -Fxq "dns rg0 10.90.0.1" "${DNS_LOG}"
grep -Fxq "domain rg0 ~." "${DNS_LOG}"
grep -Fxq "default-route rg0 true" "${DNS_LOG}"
ip netns exec "${CLIENT_NS}" ping -n -c 2 -W 2 10.90.0.1 >/dev/null
if ip netns exec "${CLIENT_NS}" ping -n -c 1 -W 1 192.0.2.1 >/dev/null 2>&1; then
    echo "error: physical non-transport traffic escaped the kill switch" >&2
    exit 1
fi

# A DNS-like UDP datagram reaches a tunnel DNS server but not the physical link.
ip netns exec "${SERVER_NS}" timeout 4 python3 -c \
    'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("10.90.0.1",53)); s.recvfrom(64); open("'"${TEST_DIR}"'/dns-tunnel","w").close()' &
LISTENER_PIDS+=("$!")
ip netns exec "${SERVER_NS}" timeout 2 python3 -c \
    'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("192.0.2.1",53)); s.recvfrom(64); open("'"${TEST_DIR}"'/dns-physical","w").close()' &
LISTENER_PIDS+=("$!")
sleep 0.2
ip netns exec "${CLIENT_NS}" python3 -c \
    'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b"dns",("10.90.0.1",53));
try: s.sendto(b"dns",("192.0.2.1",53))
except PermissionError: pass'
for _ in {1..20}; do [[ -e "${TEST_DIR}/dns-tunnel" ]] && break; sleep 0.1; done
[[ -e "${TEST_DIR}/dns-tunnel" ]] || { echo "error: tunnel DNS packet did not arrive" >&2; exit 1; }
sleep 1
[[ ! -e "${TEST_DIR}/dns-physical" ]] || { echo "error: DNS escaped over physical link" >&2; exit 1; }
stop_client
grep -Fxq "revert rg0" "${DNS_LOG}"
assert_owned_state_absent

echo "[3/3] forced-crash recovery from the ownership journal"
write_config 0.0.0.0/0 true true
start_client
kill -KILL "${CLIENT_PID}"
wait "${CLIENT_PID}" 2>/dev/null || true
CLIENT_PID=""
[[ -f ${JOURNAL} ]]
ip netns exec "${CLIENT_NS}" nft list table inet rustguard_rg0 >/dev/null
ip -n "${CLIENT_NS}" route show exact 192.0.2.1/32 | grep -q .
if ip netns exec "${CLIENT_NS}" ping -n -c 1 -W 1 192.0.2.1 >/dev/null 2>&1; then
    echo "error: kill switch opened after the tunnel process crashed" >&2
    exit 1
fi
ip netns exec "${CLIENT_NS}" env PATH="${TEST_DIR}/bin:${PATH}" \
    RUSTGUARD_RESOLVECTL_LOG="${DNS_LOG}" "${CLIENT_BIN}" emergency-off
assert_owned_state_absent

echo "all safe-client-networking namespace tests passed"
