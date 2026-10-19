# Private core integration: v26.10.17

`v26.10.17-custom` starts at official upstream release commit
`92ccc939aaf4f8965f369cf0b142e005aeaa11d5`. The previous private branch is
preserved as `v26.7.11-custom` at `075ec011`.

Private behavior carried forward:

- AnyTLS inbound/outbound, user-management CLI integration, and local harness.
- ShadowsocksR outbound and legacy Shadowsocks outbound ciphers, with local
  interoperability harnesses. Legacy ciphers remain unavailable to inbounds.
- Observatory capability and resolver-reachability RPCs, plus locked observation
  snapshots for the GUI and TUN probe mode.
- TUN JSON `icmpMode: fake/probe`, adapted to upstream's new packet stack. Probe
  replies reuse cached Observatory delays, retain at most 256 pending replies,
  and are cancelled/drained when the stack closes.
- RouterOS GRE, IPv4/IPv6 inner packets, strict pseudo-inbound validation, and
  the separate `routeros_gre` build with TUN registration disabled.
- Explicit TLS `allowInsecure` compatibility; certificate verification remains
  enabled by default. Upstream TLS trust-store defaults remain in place.
- Darwin socket-family binding correction and nil Mux packet-reader destination
  support that are still absent from the selected upstream release.
- Presence-aware WireGuard `domainStrategy` compatibility for existing GUI
  profiles. Omitting it preserves upstream defaults; explicit choices retain
  the old family-selection behavior without changing DNS caching or socket
  dialing settings.
- Local `Makefile`, `build.bat`, contributor guidance, and regression coverage.

Upstream-equivalent backports were not replayed. The upstream TUN implementation,
DNS/WFP controls, newer protocols/transports, dependencies, and fixes remain the
base of this branch.

## Configuration compatibility

TUN protobuf fields 9 (`auto_system_dns_to_gateway`) and 10
(`auto_system_wfp_block_leak`) retain upstream meanings. Private `icmp_mode` now
uses field 11. Old private binary protobuf configs must be regenerated from JSON;
their old field 9 would otherwise be interpreted as the upstream DNS option.
The GUI's JSON `icmpMode` key and private Observatory RPC wire contracts are
unchanged.

The paired Xray-GUI still emits WireGuard `domainStrategy`; retain its explicit
family-selection behavior while keeping upstream behavior when it is omitted.
The GUI does not emit the removed `remoteDNS: ["local"]` mode.

## Validation and remaining integration

- [x] Run focused race tests and RouterOS-tagged package tests.
- [x] Run the full Go suite and distinguish external-service failures.
- [x] Build native CLI, Linux/Windows targets, and RouterOS Linux/mipsle.
- [x] Check formatting and obtain independent review of the staged port.
- [ ] Update the paired GUI's vendored core/build input before claiming a
  packaged GUI contains this branch. The GUI repository is outside this port.
- [ ] Validate live TUN/GRE behavior on the actual operating systems and router;
  host tests and cross-compilation do not establish runtime compatibility.

Validation uses Go 1.27.1 on Darwin/arm64. The main port was tested from an
exact staged export: formatting and affected package checks passed; the release
CLI built for Darwin/arm64, Linux/amd64, Linux/arm64, Windows/amd64, and
RouterOS Linux/mipsle (`routeros_gre`, soft-float). The native binary reported
version 26.10.17. Foreign-platform builds are compile-only evidence.

The full `go test -timeout 1h -v ./...` run exited 1. External
`TestQUICNameServer` failed against AdGuard DNS, and `TestECHDial` failed after
DNS to 1.1.1.1 timed out. Darwin process lookup tests also failed under the
sandbox, then all of `./common/net` passed on a permitted rerun outside it.
The full suite is not reported as passing. Full log:
`/private/tmp/xray-migration-staged-full.log`.

## RouterOS GRE shared-stack port

GRE now uses `proxy/tun.NewStack` with `Remote: true` and an explicit ICMP-delay
callback. The raw device reads validated inner packets directly into the stack
and sends GRE/header/payload slices as one datagram. The former gVisor endpoint
queue and receive/send worker pair are gone. Peer/source checks, the exact
RouterOS keepalive, MTU enforcement, routing metadata, sniffing, and payload
counters retain their configuration contracts. The shared stack now also handles
experimental IPv6 extensions and destination options after fragment reassembly.
The old GRE fragmentation generators are test-only peer helpers.

Local checks for this follow-up use
`GOCACHE=/private/tmp/xray-gre-port-gocache`:

- Final `go test -race -tags routeros_gre -timeout 5m ./proxy/gre ./proxy/tun
  ./proxy/wireguard ./infra/conf` passed, including actual GRE dispatcher
  metadata/counter checks, IPv4/IPv6 TCP/UDP, fragmentation, IPv6 extensions, and
  fake/probe ICMP replies. Log:
  `/private/tmp/xray-gre-port-final-focused-complete.log`.
- RouterOS production dependency check: `go list -deps -tags routeros_gre ./main`
  contains no `gvisor.dev/gvisor` packages. gVisor remains a test peer and a module
  dependency; the old internal packetstack is no longer linked by GRE.
- RouterOS Linux/mipsle soft-float, Linux/arm64, and Linux/amd64 release builds
  passed; native Darwin and Windows/amd64 default builds passed. Outputs are
  `/private/tmp/xray-gre-port-linux-{mipsle,arm64,amd64}`,
  `/private/tmp/xray-gre-port-native`, and
  `/private/tmp/xray-gre-port-windows.exe`.
- Linux/amd64 GRE tests cross-compiled to
  `/private/tmp/xray-gre-port-linux.test`. The Linux socket tests are compile-only
  here: this macOS host has no running Docker daemon or Lima instance.
- Changed Go files pass the repository formatter in an isolated scope. The
  whole-checkout formatter also traverses unrelated untracked CodeQL module
  caches and reports dependency sources/templates there; those were untouched.
- Independent working-tree review found no actionable correctness defects. This
  is not staged-snapshot approval or a commit.
- `go test -timeout 1h -v ./...` exited 1: AdGuard `TestQUICNameServer` returned
  no record and panicked; TLS ECH DNS to `1.1.1.1` timed out and produced a
  malformed-ECH-config panic; five Darwin process-lookup tests were denied by
  the sandbox. `go test -count=1 -timeout 1m ./common/net` passed outside the
  sandbox. The full suite is not a pass. Logs:
  `/private/tmp/xray-gre-port-full.log` and
  `/private/tmp/xray-gre-port-common-net-outside.log`.

Remaining device work:

- [ ] Exercise real RouterOS GRE traffic, keepalives, packet loss/reordering,
  IPv4/IPv6 fragmentation/MTU changes, and cancellation under socket backpressure.
- [ ] Measure idle/load CPU and RSS on the same router and workload before
  claiming a quantified CPU/RAM reduction.
