#!/usr/bin/env bash
# Three simultaneous official WireGuard clients, isolation, and roaming.

set -euo pipefail
umask 077
[[ ${EUID} -eq 0 ]] || { echo "error: run as root" >&2; exit 1; }
for command in ip ping wg nft python3 timeout; do
    command -v "${command}" >/dev/null || { echo "error: missing ${command}" >&2; exit 1; }
done

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SERVER_BIN=${RUSTGUARD_SERVER_BIN:-"${ROOT_DIR}/target/debug/rustguard-server"}
TEST_DIR=$(mktemp -d /tmp/rustguard-multi-peer.XXXXXX)
SERVER_NS="rgms$$"
CLIENT_NAMES=("rgm1$$" "rgm2$$" "rgm3$$")
SERVER_LINKS=("rgs1$$" "rgs2$$" "rgs3$$")
CLIENT_LINKS=("rgc1$$" "rgc2$$" "rgc3$$")
SERVER_PID=""

cleanup() {
    set +e
    if [[ -n ${SERVER_PID} ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        kill -TERM "${SERVER_PID}" 2>/dev/null
        timeout 5 tail --pid="${SERVER_PID}" -f /dev/null 2>/dev/null
        kill -KILL "${SERVER_PID}" 2>/dev/null
    fi
    rm -f /run/rustguard/server.lock /run/rustguard/server.sock /run/rustguard/server.status.json
    for namespace in "${CLIENT_NAMES[@]}"; do ip netns del "${namespace}" 2>/dev/null; done
    ip netns del "${SERVER_NS}" 2>/dev/null
    rm -rf -- "${TEST_DIR}"
}
trap cleanup EXIT INT TERM
rm -f /run/rustguard/server.lock /run/rustguard/server.sock /run/rustguard/server.status.json

wg genkey >"${TEST_DIR}/server.private"
wg pubkey <"${TEST_DIR}/server.private" >"${TEST_DIR}/server.public"
for index in 1 2 3; do
    wg genkey >"${TEST_DIR}/client${index}.private"
    wg pubkey <"${TEST_DIR}/client${index}.private" >"${TEST_DIR}/client${index}.public"
done

ip netns add "${SERVER_NS}"
ip -n "${SERVER_NS}" link set lo up
for offset in 0 1 2; do
    index=$((offset + 1))
    namespace=${CLIENT_NAMES[$offset]}
    server_link=${SERVER_LINKS[$offset]}
    client_link=${CLIENT_LINKS[$offset]}
    ip netns add "${namespace}"
    ip link add "${server_link}" type veth peer name "${client_link}"
    ip link set "${server_link}" netns "${SERVER_NS}"
    ip link set "${client_link}" netns "${namespace}"
    ip -n "${SERVER_NS}" address add "192.0.$((index + 1)).1/24" dev "${server_link}"
    ip -n "${SERVER_NS}" link set "${server_link}" up
    ip -n "${namespace}" link set lo up
    ip -n "${namespace}" address add "192.0.$((index + 1)).2/24" dev "${client_link}"
    ip -n "${namespace}" link set "${client_link}" up
done
ip netns exec "${SERVER_NS}" sysctl -q -w net.ipv4.ip_forward=1

cat >"${TEST_DIR}/server.toml" <<EOF
[interface]
private_key = "$(<"${TEST_DIR}/server.private")"
address = "10.100.0.1/24"
listen_port = 51840
mtu = 1420

[server]
require_forwarding = true
require_nat = false

[[peer]]
name = "laptop"
public_key = "$(<"${TEST_DIR}/client1.public")"
allowed_ips = ["10.100.0.2/32"]

[[peer]]
name = "tablet"
public_key = "$(<"${TEST_DIR}/client2.public")"
allowed_ips = ["10.100.0.3/32"]

[[peer]]
name = "phone"
public_key = "$(<"${TEST_DIR}/client3.public")"
allowed_ips = ["10.100.0.4/32"]
EOF
chmod 600 "${TEST_DIR}/server.toml"

echo "[1/5] validated three-peer startup and simultaneous handshakes"
ip netns exec "${SERVER_NS}" "${SERVER_BIN}" --config "${TEST_DIR}/server.toml" check \
    | grep -q "prerequisites: available"
sed 's/require_nat = false/require_nat = true\noutbound_interface = "'"${SERVER_LINKS[0]}"'"/' \
    "${TEST_DIR}/server.toml" >"${TEST_DIR}/missing-nat.toml"
chmod 600 "${TEST_DIR}/missing-nat.toml"
if ip netns exec "${SERVER_NS}" "${SERVER_BIN}" --config "${TEST_DIR}/missing-nat.toml" check \
    >/dev/null 2>&1; then
    echo "error: missing required NAT rule was accepted" >&2
    exit 1
fi
! ip -n "${SERVER_NS}" link show rg0 >/dev/null 2>&1
ip netns exec "${SERVER_NS}" "${SERVER_BIN}" --config "${TEST_DIR}/server.toml" start \
    >"${TEST_DIR}/server.log" 2>&1 &
SERVER_PID=$!
for _ in {1..50}; do [[ -S /run/rustguard/server.sock ]] && break; sleep 0.1; done
[[ -S /run/rustguard/server.sock ]] || { sed -n '1,200p' "${TEST_DIR}/server.log" >&2; exit 1; }

for offset in 0 1 2; do
    index=$((offset + 1))
    namespace=${CLIENT_NAMES[$offset]}
    ip -n "${namespace}" link add wg0 type wireguard
    ip netns exec "${namespace}" wg set wg0 \
        private-key "${TEST_DIR}/client${index}.private" \
        peer "$(<"${TEST_DIR}/server.public")" \
        endpoint "192.0.$((index + 1)).1:51840" \
        allowed-ips 10.100.0.0/24 persistent-keepalive 1
    ip -n "${namespace}" address add "10.100.0.$((index + 1))/32" dev wg0
    ip -n "${namespace}" link set wg0 up
    ip -n "${namespace}" route add 10.100.0.0/24 dev wg0
done
for namespace in "${CLIENT_NAMES[@]}"; do
    ip netns exec "${namespace}" ping -n -c 2 -W 2 10.100.0.1 >/dev/null
done

STATUS=$(ip netns exec "${SERVER_NS}" "${SERVER_BIN}" status)
grep -q "handshake: 3/3 established" <<<"${STATUS}"
for name in laptop tablet phone; do grep -q "peer ${name}: handshake=established" <<<"${STATUS}"; done

echo "[2/5] longest-prefix delivery and cross-peer forwarding"
ip netns exec "${CLIENT_NAMES[0]}" ping -n -c 2 -W 2 10.100.0.3 >/dev/null
ip netns exec "${CLIENT_NAMES[1]}" ping -n -c 2 -W 2 10.100.0.4 >/dev/null
ip netns exec "${CLIENT_NAMES[2]}" ping -n -c 2 -W 2 10.100.0.2 >/dev/null

echo "[3/5] spoofed inner source and unauthenticated outer input are isolated"
ip -n "${CLIENT_NAMES[0]}" address add 10.100.0.3/32 dev wg0
if ip netns exec "${CLIENT_NAMES[0]}" ping -n -I 10.100.0.3 -c 1 -W 1 10.100.0.1 \
    >/dev/null 2>&1; then
    echo "error: peer injected another peer's source address" >&2
    exit 1
fi
ip -n "${CLIENT_NAMES[0]}" address del 10.100.0.3/32 dev wg0
ip netns exec "${CLIENT_NAMES[1]}" python3 -c \
    'import socket,struct; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); p=struct.pack("<IIQ",4,256,0)+bytes(16); [s.sendto(p,("192.0.3.1",51840)) for _ in range(500)]'
ip netns exec "${CLIENT_NAMES[2]}" ping -n -c 2 -W 2 10.100.0.1 >/dev/null
STATUS=$(ip netns exec "${SERVER_NS}" "${SERVER_BIN}" status)
grep -q "peer laptop: handshake=established, endpoint=192.0.2.2:" <<<"${STATUS}"

echo "[4/5] authenticated endpoint roaming"
ip -n "${CLIENT_NAMES[0]}" address del 192.0.2.2/24 dev "${CLIENT_LINKS[0]}"
ip -n "${CLIENT_NAMES[0]}" address add 192.0.2.22/24 dev "${CLIENT_LINKS[0]}"
ip netns exec "${CLIENT_NAMES[0]}" ping -n -c 3 -W 2 10.100.0.1 >/dev/null
STATUS=$(ip netns exec "${SERVER_NS}" "${SERVER_BIN}" status)
grep -q "peer laptop: handshake=established, endpoint=192.0.2.22:" <<<"${STATUS}"

echo "[5/5] one peer failure does not stall the others"
ip -n "${CLIENT_NAMES[1]}" link set wg0 down
ip netns exec "${CLIENT_NAMES[0]}" ping -n -c 2 -W 2 10.100.0.4 >/dev/null
ip netns exec "${CLIENT_NAMES[2]}" ping -n -c 2 -W 2 10.100.0.2 >/dev/null
ip netns exec "${SERVER_NS}" "${SERVER_BIN}" stop >/dev/null
wait "${SERVER_PID}" || true
SERVER_PID=""

echo "all multi-peer server tests passed"
