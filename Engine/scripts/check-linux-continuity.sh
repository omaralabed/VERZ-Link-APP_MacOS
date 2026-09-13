#!/bin/bash
# Isolated virtual-link integration check. Never changes the host default route.
set -euo pipefail
umask 077
MODE=${1:-cuts}
POLICY=${VERZ_TEST_POLICY:-continuity}
BOND_BIN=${VERZ_TEST_BOND_BIN:-/opt/verz-link-lab/verz-bond}
CLIENT_BIN=${VERZ_TEST_CLIENT_BIN:-$BOND_BIN}
HTTP_BIN=${VERZ_TEST_HTTP_BIN:-/opt/verz-link-lab/verz-tunnel-http}
RATE=${VERZ_TEST_RATE:-10mbit}
DELAY_LOW=${VERZ_TEST_DELAY_LOW:-10ms}
DELAY_HIGH=${VERZ_TEST_DELAY_HIGH:-30ms}
HTTP_ARGS=()
if [ -n "${VERZ_TEST_STREAM_DELAY_MS:-}" ]; then HTTP_ARGS+=(--stream-delay-ms "$VERZ_TEST_STREAM_DELAY_MS"); fi
if [ -n "${VERZ_TEST_STREAM_REPEATS:-}" ]; then HTTP_ARGS+=(--stream-repeats "$VERZ_TEST_STREAM_REPEATS"); fi
case "$MODE" in cuts|both|low|high) ;; *) echo "Use cuts, both, low, or high" >&2; exit 1;; esac
case "$POLICY" in smart|performance|continuity|data-saver) ;; *) echo "Use a valid VERZ_TEST_POLICY" >&2; exit 1;; esac
PATHS=(vzbc0 vzbc1)
EXPECTED_PATHS=2
if [ "$MODE" = low ]; then PATHS=(vzbc0); EXPECTED_PATHS=1; fi
if [ "$MODE" = high ]; then PATHS=(vzbc1); EXPECTED_PATHS=1; fi
NS=verz-bond-check
RELAY_NS=verz-bond-check-relay
if ip netns list | awk '$1 == "verz-bond-check-relay" { found=1 } END { exit !found }'; then
    echo "Test relay namespace already exists; refusing to overwrite it." >&2; exit 1
fi
if ip netns list | awk '$1 == "verz-bond-check" { found=1 } END { exit !found }'; then
    echo "Test namespace already exists; refusing to overwrite it." >&2; exit 1
fi
for name in vzbh0 vzbh1 vzbc0 vzbc1; do
    if ip link show "$name" >/dev/null 2>&1; then echo "Test interface $name already exists." >&2; exit 1; fi
done
TEST_DIR=$(mktemp -d /tmp/verz-bond-check.XXXXXX)
CLIENT_PID=
PING_PID=
FAULT_PID=
RELAY_PID=
HTTP_PID=
cleanup() {
    for pid in "$FAULT_PID" "$PING_PID" "$CLIENT_PID" "$HTTP_PID" "$RELAY_PID"; do
        if [ -n "$pid" ]; then kill -TERM "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
    done
    ip netns del "$NS" 2>/dev/null || true
    ip netns del "$RELAY_NS" 2>/dev/null || true
    echo "Isolated test namespace removed. Test output: $TEST_DIR"
}
ip netns add "$NS"
trap cleanup EXIT
ip netns add "$RELAY_NS"
ip -n "$NS" link set lo up
ip -n "$RELAY_NS" link set lo up
ip link add vzbh0 type veth peer name vzbc0
ip link set vzbc0 netns "$NS"
ip link set vzbh0 netns "$RELAY_NS"
ip -n "$RELAY_NS" address add 10.203.240.1/30 dev vzbh0
ip -n "$RELAY_NS" link set vzbh0 up
ip -n "$NS" address add 10.203.240.2/30 dev vzbc0
ip -n "$NS" link set vzbc0 up
ip link add vzbh1 type veth peer name vzbc1
ip link set vzbc1 netns "$NS"
ip link set vzbh1 netns "$RELAY_NS"
ip -n "$RELAY_NS" address add 10.203.241.1/30 dev vzbh1
ip -n "$RELAY_NS" link set vzbh1 up
ip -n "$NS" address add 10.203.241.2/30 dev vzbc1
ip -n "$NS" link set vzbc1 up
ip -n "$NS" rule add oif vzbc1 table 202 priority 100
ip -n "$NS" route add table 202 10.203.240.1/32 via 10.203.241.1 dev vzbc1 src 10.203.241.2
# The test deliberately reaches one relay IP over two virtual interfaces.
# Configure reverse-path validation only inside this disposable namespace.
ip netns exec "$NS" sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec "$NS" sysctl -qw net.ipv4.conf.vzbc1.rp_filter=0
# 20 ms RTT versus 60 ms RTT, each limited to 10 Mbps independently.
# Shaping applies ONLY to interfaces created by this test, never eth0/SSH.
ip netns exec "$RELAY_NS" tc qdisc add dev vzbh0 root netem delay "$DELAY_LOW" rate "$RATE"
ip netns exec "$NS" tc qdisc add dev vzbc0 root netem delay "$DELAY_LOW" rate "$RATE"
ip netns exec "$RELAY_NS" tc qdisc add dev vzbh1 root netem delay "$DELAY_HIGH" rate "$RATE"
ip netns exec "$NS" tc qdisc add dev vzbc1 root netem delay "$DELAY_HIGH" rate "$RATE"
ip netns exec "$RELAY_NS" "$BOND_BIN" server --listen 10.203.240.1:39002 \
    --secret-file /etc/verz-link-lab/secret --tun-name vzrelay >"$TEST_DIR/relay.log" 2>&1 &
RELAY_PID=$!
for _ in $(seq 1 50); do
    if ip -n "$RELAY_NS" address show vzrelay 2>/dev/null | grep -q '10.78.0.1'; then break; fi
    sleep 0.1
done
ip netns exec "$RELAY_NS" "$HTTP_BIN" --listen 10.78.0.1:8080 \
    --file /opt/verz-link-lab/verz-bond "${HTTP_ARGS[@]}" >"$TEST_DIR/http.log" 2>&1 &
HTTP_PID=$!
for _ in $(seq 1 50); do
    if ip netns exec "$RELAY_NS" curl --fail --silent --noproxy '*' --max-time 1 http://10.78.0.1:8080/health >/dev/null; then break; fi
    sleep 0.1
done
ip netns exec "$NS" "$CLIENT_BIN" client --relay 10.203.240.1:39002 \
    --interface "${PATHS[@]}" --secret-file /etc/verz-link-lab/secret \
    --policy "$POLICY" >"$TEST_DIR/client.log" 2>&1 &
CLIENT_PID=$!
TUN=
for _ in $(seq 1 100); do
    TUN=$(awk '/TUNNEL CONNECTED:/ {print $3; exit}' "$TEST_DIR/client.log")
    if [ -n "$TUN" ]; then break; fi
    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then sed -n '1,15p' "$TEST_DIR/client.log"; exit 1; fi
    sleep 0.1
done
test -n "$TUN"
for _ in $(seq 1 60); do
    if grep -q "\"healthy_paths\":$EXPECTED_PATHS" "$TEST_DIR/client.log"; then break; fi
    sleep 0.1
done
grep -q "\"healthy_paths\":$EXPECTED_PATHS" "$TEST_DIR/client.log"
ip -n "$NS" route replace 10.78.0.1/32 dev "$TUN"
ip -n "$NS" route add default dev "$TUN"
ip netns exec "$NS" ping -n -D -i 0.02 -c 650 10.78.0.1 >"$TEST_DIR/ping.log" 2>&1 &
PING_PID=$!
(
    if [ "$MODE" != cuts ]; then exit 0; fi
    sleep 2
    echo "Cut first virtual WAN"
    ip -n "$NS" link set vzbc0 down
    sleep 1
    ip -n "$NS" link set vzbc0 up
    sleep 2
    echo "Cut second virtual WAN"
    ip -n "$NS" link set vzbc1 down
    sleep 1
    ip -n "$NS" link set vzbc1 up
    ip -n "$NS" route replace table 202 10.203.240.1/32 via 10.203.241.1 dev vzbc1 src 10.203.241.2
) &
FAULT_PID=$!
ip netns exec "$NS" curl --fail --silent --show-error --noproxy '*' --max-time 40 \
    http://10.78.0.1:8080/stream --output "$TEST_DIR/stream.bin" --write-out 'TCP download: %{speed_download} bytes/sec, %{time_total} seconds\n'
wait "$FAULT_PID"; FAULT_PID=
EXPECTED=$(ip netns exec "$NS" curl --fail --silent --show-error --noproxy '*' --max-time 10 http://10.78.0.1:8080/stream-sha256)
ACTUAL=$(sha256sum "$TEST_DIR/stream.bin" | awk '{print $1}')
test "$EXPECTED" = "$ACTUAL"
kill -0 "$CLIENT_PID"
wait "$PING_PID"; PING_PID=
echo "PASS ($MODE): one real TCP stream completed; SHA-256 matches."
wc -c "$TEST_DIR/stream.bin"
tail -n 4 "$TEST_DIR/ping.log"
awk '/bytes from/ {gsub(/\[|\]/,"",$1); if (last && ($1-last)>max) max=$1-last; last=$1} END {printf "Maximum observed ICMP reply gap: %.3f ms (virtual-link test, not physical Mac acceptance)\n", max*1000}' "$TEST_DIR/ping.log"
