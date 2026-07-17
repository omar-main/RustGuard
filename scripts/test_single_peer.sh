#!/usr/bin/env bash
# Privileged IPv4 tunnel and WireGuard interoperability tests.

set -euo pipefail
umask 077

if [[ ${EUID} -ne 0 ]]; then
    echo "error: run this test as root" >&2
    exit 1
fi

for command in ip ping wg timeout awk; do
    command -v "${command}" >/dev/null || {
        echo "error: required command '${command}' is missing" >&2
        exit 1
    }
done

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CLIENT_BIN=${RUSTGUARD_CLIENT_BIN:-"${ROOT_DIR}/target/debug/rustguard-client"}
SERVER_BIN=${RUSTGUARD_SERVER_BIN:-"${ROOT_DIR}/target/debug/rustguard-server"}

[[ -x ${CLIENT_BIN} ]] || { echo "error: build ${CLIENT_BIN} first" >&2; exit 1; }
[[ -x ${SERVER_BIN} ]] || { echo "error: build ${SERVER_BIN} first" >&2; exit 1; }

TEST_DIR=$(mktemp -d /tmp/rustguard-single-peer.XXXXXX)
SUFFIX=$$
SERVER_NS="rgs${SUFFIX}"
CLIENT_NS="rgc${SUFFIX}"
SERVER_VETH="rsv${SUFFIX}"
CLIENT_VETH="rcv${SUFFIX}"
SERVER_PID=""
CLIENT_PID=""

cleanup() {
    set +e
    for pid in "${CLIENT_PID}" "${SERVER_PID}"; do
        if [[ -n ${pid} ]] && kill -0 "${pid}" 2>/dev/null; then
            kill -TERM "${pid}" 2>/dev/null
            timeout 5 tail --pid="${pid}" -f /dev/null 2>/dev/null
            kill -KILL "${pid}" 2>/dev/null
        fi
    done
    ip netns del "${CLIENT_NS}" 2>/dev/null
    ip netns del "${SERVER_NS}" 2>/dev/null
    rm -rf -- "${TEST_DIR}"
}
trap cleanup EXIT INT TERM

create_namespaces() {
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
}

stop_process() {
    local variable_name=$1
    local pid=${!variable_name:-}
    if [[ -z ${pid} ]]; then
        return
    fi
    if kill -0 "${pid}" 2>/dev/null; then
        kill -TERM "${pid}"
        if ! timeout 5 tail --pid="${pid}" -f /dev/null; then
            echo "error: process ${pid} did not stop within five seconds" >&2
            exit 1
        fi
        wait "${pid}" || true
    fi
    printf -v "${variable_name}" ''
}

wait_for_link() {
    local namespace=$1
    local interface=$2
    local log=$3
    for _ in {1..50}; do
        if ip -n "${namespace}" link show "${interface}" >/dev/null 2>&1; then
            return
        fi
        sleep 0.1
    done
    echo "error: ${interface} did not appear in ${namespace}" >&2
    sed -n '1,160p' "${log}" >&2
    exit 1
}

assert_ping() {
    local namespace=$1
    local destination=$2
    ip netns exec "${namespace}" ping -n -c 2 -W 2 "${destination}" >/dev/null
}

write_keypair() {
    local prefix=$1
    wg genkey >"${TEST_DIR}/${prefix}.private"
    wg pubkey <"${TEST_DIR}/${prefix}.private" >"${TEST_DIR}/${prefix}.public"
    chmod 600 "${TEST_DIR}/${prefix}.private"
}

assert_idle_cpu() {
    local pid=$1
    local first second delta
    first=$(awk '{print $14 + $15}' "/proc/${pid}/stat")
    sleep 2
    second=$(awk '{print $14 + $15}' "/proc/${pid}/stat")
    delta=$((second - first))
    # Linux commonly exposes 100 ticks/second. Twenty ticks over two idle
    # seconds leaves generous headroom while catching the original busy loop.
    if (( delta > 20 )); then
        echo "error: process ${pid} used ${delta} CPU ticks while idle" >&2
        exit 1
    fi
    echo "idle CPU: ${delta} ticks over two seconds"
}

test_official_client_to_rustguard_server() {
    echo "[1/3] official WireGuard client -> RustGuard server"
    write_keypair server_a
    write_keypair client_a
    cat >"${TEST_DIR}/server-a.toml" <<EOF
[interface]
private_key = "$(<"${TEST_DIR}/server_a.private")"
address = "10.77.0.1/24"
listen_port = 51820
mtu = 1420

[[peer]]
public_key = "$(<"${TEST_DIR}/client_a.public")"
allowed_ips = ["10.77.0.2/32"]
EOF
    chmod 600 "${TEST_DIR}/server-a.toml"

    ip netns exec "${SERVER_NS}" "${SERVER_BIN}" \
        --config "${TEST_DIR}/server-a.toml" start \
        >"${TEST_DIR}/server-a.log" 2>&1 &
    SERVER_PID=$!
    wait_for_link "${SERVER_NS}" rg0 "${TEST_DIR}/server-a.log"

    ip -n "${CLIENT_NS}" link add wg0 type wireguard
    ip netns exec "${CLIENT_NS}" wg set wg0 \
        private-key "${TEST_DIR}/client_a.private" \
        peer "$(<"${TEST_DIR}/server_a.public")" \
        endpoint 192.0.2.1:51820 \
        allowed-ips 10.77.0.0/24 \
        persistent-keepalive 1
    ip -n "${CLIENT_NS}" address add 10.77.0.2/24 dev wg0
    ip -n "${CLIENT_NS}" link set wg0 up

    assert_ping "${CLIENT_NS}" 10.77.0.1
    assert_ping "${SERVER_NS}" 10.77.0.2
    stop_process SERVER_PID
    ip -n "${CLIENT_NS}" link del wg0
}

test_rustguard_client_to_official_server() {
    echo "[2/3] RustGuard client -> official WireGuard server"
    write_keypair server_b
    write_keypair client_b

    ip -n "${SERVER_NS}" link add wg0 type wireguard
    ip netns exec "${SERVER_NS}" wg set wg0 \
        listen-port 51821 \
        private-key "${TEST_DIR}/server_b.private" \
        peer "$(<"${TEST_DIR}/client_b.public")" \
        allowed-ips 10.78.0.2/32
    ip -n "${SERVER_NS}" address add 10.78.0.1/24 dev wg0
    ip -n "${SERVER_NS}" link set wg0 up

    cat >"${TEST_DIR}/client-b.toml" <<EOF
[interface]
private_key = "$(<"${TEST_DIR}/client_b.private")"
address = "10.78.0.2/24"
mtu = 1420

[[peer]]
public_key = "$(<"${TEST_DIR}/server_b.public")"
endpoint = "192.0.2.1:51821"
allowed_ips = ["10.78.0.1/32"]
persistent_keepalive = 1
EOF
    chmod 600 "${TEST_DIR}/client-b.toml"

    ip netns exec "${CLIENT_NS}" "${CLIENT_BIN}" \
        --config "${TEST_DIR}/client-b.toml" up \
        >"${TEST_DIR}/client-b.log" 2>&1 &
    CLIENT_PID=$!
    wait_for_link "${CLIENT_NS}" rg0 "${TEST_DIR}/client-b.log"

    assert_ping "${CLIENT_NS}" 10.78.0.1
    assert_ping "${SERVER_NS}" 10.78.0.2
    stop_process CLIENT_PID
    ip -n "${SERVER_NS}" link del wg0
}

test_rustguard_to_rustguard() {
    echo "[3/3] RustGuard client -> RustGuard server"
    write_keypair server_c
    write_keypair client_c
    cat >"${TEST_DIR}/server-c.toml" <<EOF
[interface]
private_key = "$(<"${TEST_DIR}/server_c.private")"
address = "10.79.0.1/24"
listen_port = 51822
mtu = 1420

[[peer]]
public_key = "$(<"${TEST_DIR}/client_c.public")"
allowed_ips = ["10.79.0.2/32"]
EOF
    cat >"${TEST_DIR}/client-c.toml" <<EOF
[interface]
private_key = "$(<"${TEST_DIR}/client_c.private")"
address = "10.79.0.2/24"
mtu = 1420

[[peer]]
public_key = "$(<"${TEST_DIR}/server_c.public")"
endpoint = "192.0.2.1:51822"
allowed_ips = ["10.79.0.1/32"]
persistent_keepalive = 1
EOF
    chmod 600 "${TEST_DIR}/server-c.toml" "${TEST_DIR}/client-c.toml"

    ip netns exec "${SERVER_NS}" "${SERVER_BIN}" \
        --config "${TEST_DIR}/server-c.toml" start \
        >"${TEST_DIR}/server-c.log" 2>&1 &
    SERVER_PID=$!
    wait_for_link "${SERVER_NS}" rg0 "${TEST_DIR}/server-c.log"
    ip netns exec "${CLIENT_NS}" "${CLIENT_BIN}" \
        --config "${TEST_DIR}/client-c.toml" up \
        >"${TEST_DIR}/client-c.log" 2>&1 &
    CLIENT_PID=$!
    wait_for_link "${CLIENT_NS}" rg0 "${TEST_DIR}/client-c.log"

    assert_ping "${CLIENT_NS}" 10.79.0.1
    assert_ping "${SERVER_NS}" 10.79.0.2
    assert_idle_cpu "${CLIENT_PID}"
    assert_idle_cpu "${SERVER_PID}"
    stop_process CLIENT_PID
    stop_process SERVER_PID
}

create_namespaces
test_official_client_to_rustguard_server
test_rustguard_client_to_official_server
test_rustguard_to_rustguard
echo "all single-peer tunnel tests passed"
