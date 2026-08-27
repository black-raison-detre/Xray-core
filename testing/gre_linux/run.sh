#!/bin/sh
set -eu

if [ "$(uname -s)" != Linux ]; then
  echo "GRE namespace integration requires Linux" >&2
  exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "GRE namespace integration requires root (network namespaces and kernel GRE)" >&2
  exit 2
fi
for command_name in go ip ping ethtool; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "missing required command: $command_name" >&2
    exit 2
  }
done

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
results_dir=${RESULTS_DIR:-"$(mktemp -d /tmp/xray-gre-linux.XXXXXX)"}
router_ns="xray-gre-router-$$"
xray_ns="xray-gre-xray-$$"
xray_pid=
echo_pid=

cleanup() {
  if [ -n "$xray_pid" ]; then kill "$xray_pid" 2>/dev/null || true; fi
  if [ -n "$echo_pid" ]; then kill "$echo_pid" 2>/dev/null || true; fi
  ip netns delete "$router_ns" 2>/dev/null || true
  ip netns delete "$xray_ns" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

mkdir -p "$results_dir"
cd "$project_dir"
CGO_ENABLED=0 go build -tags routeros_gre -trimpath -buildvcs=false -o "$results_dir/xray" ./main
CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$results_dir/gre-echo" ./testing/gre_linux/cmd/echo
CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$results_dir/gre-client" ./testing/gre_linux/cmd/client

ip netns add "$router_ns"
ip netns add "$xray_ns"
ip link add greouter-r type veth peer name greouter-x
ip link set greouter-r netns "$router_ns"
ip link set greouter-x netns "$xray_ns"
ip -n "$router_ns" link set lo up
ip -n "$xray_ns" link set lo up
ip -n "$router_ns" address add 172.31.255.1/30 dev greouter-r
ip -n "$xray_ns" address add 172.31.255.2/30 dev greouter-x
ip -n "$router_ns" link set greouter-r up
ip -n "$xray_ns" link set greouter-x up
ip netns exec "$router_ns" ethtool -K greouter-r tx off tso off gso off gro off >/dev/null
ip netns exec "$xray_ns" ethtool -K greouter-x tx off tso off gso off gro off >/dev/null
ip -n "$router_ns" address add 192.168.50.100/32 dev lo
ip -n "$xray_ns" address add 198.51.100.10/32 dev lo
ip -n "$router_ns" link add gre-xray type gre local 172.31.255.1 remote 172.31.255.2 ttl 64
ip -n "$router_ns" address add 10.255.0.1/30 dev gre-xray
ip -n "$router_ns" link set gre-xray mtu 1400 up
ip -n "$router_ns" route add 198.51.100.10/32 dev gre-xray src 192.168.50.100

cat >"$results_dir/xray.json" <<'EOF'
{
  "log": {"loglevel": "debug"},
  "inbounds": [{
    "tag": "gre-test",
    "protocol": "gre",
    "settings": {
      "localAddress": "172.31.255.2",
      "remoteAddress": "172.31.255.1",
      "allowedInnerSources": ["192.168.50.100/32"],
      "mtu": 1400,
      "icmpMode": "fake"
    }
  }],
  "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}}],
  "routing": {"rules": [{"type": "field", "inboundTag": ["gre-test"], "outboundTag": "direct"}]}
}
EOF

ip netns exec "$xray_ns" "$results_dir/gre-echo" >"$results_dir/echo.log" 2>&1 &
echo_pid=$!
ip netns exec "$xray_ns" "$results_dir/xray" run -c "$results_dir/xray.json" >"$results_dir/xray.log" 2>&1 &
xray_pid=$!

ready=false
attempt=0
while [ "$attempt" -lt 50 ]; do
  if grep -q 'userspace tunnel up' "$results_dir/xray.log"; then ready=true; break; fi
  kill -0 "$xray_pid" 2>/dev/null || { cat "$results_dir/xray.log" >&2; exit 1; }
  attempt=$((attempt + 1))
  sleep 0.1
done
[ "$ready" = true ] || { cat "$results_dir/xray.log" >&2; echo "Xray GRE startup timed out" >&2; exit 1; }

ip netns exec "$router_ns" "$results_dir/gre-client" >"$results_dir/client.log"
cat "$results_dir/client.log"
ip netns exec "$router_ns" ping -c 1 -W 2 -I 192.168.50.100 198.51.100.10 >"$results_dir/icmp.log"
ip -s -n "$router_ns" link show gre-xray >"$results_dir/gre-stats.log"

grep -q 'GRE_NAMESPACE_TRAFFIC_OK' "$results_dir/client.log"
grep -q '1 received' "$results_dir/icmp.log"
echo "GRE_NAMESPACE_OK results=$results_dir"
