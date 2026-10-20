# Private core integration: v26.10.29

`v26.10.29-custom` rebases the four private commits onto official upstream
release `v26.10.29`, commit `0afec66085a85191e9dd2a4a6646c7c9a94688d1`.
The pre-rebase tip `604f6eae` is preserved as
`recovery/v26.10.17-custom-before-20261029`. The older private branch remains
`v26.7.11-custom` at `075ec011`.

The validation sections below record the original v26.10.17 work. Current
release migration validation is recorded separately at the end of this file.

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
- Nil Mux packet-reader destination support. Upstream v26.10.29 now includes
  the equivalent Darwin socket-family binding correction and HTTP server-first
  fix; their private regression coverage is retained.
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

## HTTP outbound server-first fix

Port [upstream PR #7193](https://github.com/XTLS/Xray-core/pull/7193), which is
still unmerged at the time of this port. The production change matches the PR:
HTTP outbound waits at most 500 ms for an initial payload when its reader
supports timeouts, then opens CONNECT so server-first protocols can receive
their greeting. HTTP/1 tunnel reads retain bytes buffered alongside the CONNECT
response before returning to the raw stream.

Regression coverage includes a server-first loopback scenario followed by
bidirectional traffic, plus deterministic coalesced-response, partial-read, and
unbuffered-response checks. Before the production fix, the scenario timed out
waiting for a greeting and the package test lost the coalesced greeting.
Baseline logs: `/private/tmp/xray-http-7193-baseline.log` (scenario failure;
the first package attempt had a test import error) and
`/private/tmp/xray-http-7193-buffer-baseline.log` (corrected package regression).

Validation uses `GOCACHE=/private/tmp/xray-http-7193-gocache`:

- `go test -race -count=1 -timeout 5m -v ./proxy/http` passed, including the
  coalesced-response regression. Log: `/private/tmp/xray-http-7193-package.log`.
- `go test -race -count=1 -timeout 5m -run
  '^(TestHttp|TestHTTP|TestSocksWithHttpRequest)' -v ./testing/scenarios` passed,
  covering the server-first greeting and existing HTTP/SOCKS paths. Log:
  `/private/tmp/xray-http-7193-scenarios.log`. These scenarios exercise built
  CLI subprocesses; the outer test's race flag does not instrument those
  subprocesses.
- The repository formatter passed for an isolated copy of the three changed
  Go files, and `git diff --check` passed. Unrelated CodeQL caches were excluded.
- Independent working-tree review found no actionable findings. This is not
  staged-snapshot approval or a commit.
- `go test -timeout 1h -v ./...` exited 1. The changed HTTP package and
  server-first scenario passed. Failures were AdGuard QUIC DNS lookup,
  sandbox-denied Darwin process lookups, REALITY fingerprint tests using
  `www.google.com:443` (EOF), a local CONNECT-IP IPv4 QUIC handshake deadline,
  and Cloudflare ECH/DNS timeout. The REALITY path uses VLESS, and the local
  CONNECT-IP test uses its own HTTP/3 implementation; neither runs the changed
  HTTP outbound. The handshake timeout's underlying cause was not established.
  The full suite is not a pass. Log: `/private/tmp/xray-http-7193-full.log`.
- `CGO_ENABLED=0 go build -o /private/tmp/xray-http-7193 -trimpath
  -buildvcs=false -ldflags="-s -w -buildid=" ./main` passed. The native
  Darwin/arm64 binary launched and reported version 26.10.17. Log:
  `/private/tmp/xray-http-7193-build.log`.

### Linux ARM64 VM validation

The same uncommitted source was tested in the existing `xray-linux` Colima VM
on 2026-10-20. The guest reported `Linux aarch64`; its cached
`golang:1.27.1-bookworm` image reported `go1.27.1 linux/arm64`. Tests used cgo
enabled for the race detector. This is Linux ARM64 runtime evidence, not only
a cross-build. The container ran inside that VM with an isolated read-only
source snapshot and writable cache/artifact mounts. The archive SHA-256 matched
on host and guest:
`f4e3cb517352b24f242dfbf66aae552545bb7c2262882d15c562abfdedbbd045`.

- `go test -race -count=1 -timeout 5m -v ./proxy/http` passed.
- `go test -race -count=1 -timeout 5m -run
  '^(TestHttp|TestHTTP|TestSocksWithHttpRequest)' -v ./testing/scenarios` passed,
  including `TestHTTPOutboundServerFirst`, ordinary CONNECT, authentication,
  POST, and SOCKS-to-HTTP paths. CLI subprocesses ran natively on Linux ARM64;
  they were not race-instrumented by the outer test's flag.
- `CGO_ENABLED=0 go build -o /artifacts/xray-linux-arm64 -trimpath
  -buildvcs=false -ldflags='-s -w -buildid=' ./main` passed. The resulting
  binary launched in the VM and reported version 26.10.17; its build metadata
  confirmed `GOOS=linux`, `GOARCH=arm64`, and `CGO_ENABLED=0`.

All three phases exited successfully. The full Linux suite was not run.
Host logs, source manifest, and exact run script:
`/private/tmp/xray-http-7193-linux-c58knge6/` (`run.log`, `package.log`,
`scenarios.log`, `build.log`, `manifest.json`, and `run.sh`). The guest artifact
is `/tmp/xray-http-7193-linux-c58knge6/logs/xray-linux-arm64`.

## v26.10.29 release rebase (2026-10-29)

- Retain upstream protobuf v1.36.11 and its generator tool declarations.
- Keep upstream's segmented TUN packet buffers while retaining the GRE IPv6
  extension parser and extension handling after fragment reassembly.
- Adapt the private ICMP probe test to the new parser signature.
- Keep upstream's HTTP production fix; retain deterministic tunnel-buffer tests
  and read the server-first greeting with `io.ReadFull`.

Validation used Go 1.27.1 on Darwin/arm64 and an isolated export of the staged
source tree `e71c9e3f9e314286546962986c7a145e0a19ac1d`, before these final
prose-only results were added. Commands used
`GOCACHE=/private/tmp/xray-gre-port-gocache` and `GOFLAGS=-mod=readonly`.

- Passed focused race tests for Observatory, Mux, configuration, AnyTLS,
  Shadowsocks/SSR, TUN, WireGuard, HTTP, and TLS packages.
- Passed `go test -race -count=1 -tags routeros_gre -timeout 5m
  ./proxy/gre ./proxy/tun ./proxy/wireguard ./infra/conf`.
- Passed the repository `vformat` and `vprotogen` checks with `-mode check
  -pwd ./`. The generated private protobuf files match upstream's generators.
- Passed native Darwin/arm64, RouterOS Linux/arm64 and Linux/mipsle soft-float,
  and Windows/amd64 release builds. The native binary reports 26.10.29.
  RouterOS production dependencies contain zero gVisor packages.
- The selected HTTP/SOCKS/AnyTLS race scenario suite exited 1. HTTP cases and
  AnyTLS TCP passed; `TestAnyTLSUoT` exposed unsynchronized `accepting` accesses
  in `testing/servers/udp/udp.go` during cleanup. Independent review confirmed
  that helper, scenario, and AnyTLS implementation are unchanged by this rebase.
  This is an existing test-helper race, not a passing scenario suite.
- `go test -timeout 1h -v ./...` exited 1: AdGuard `TestQUICNameServer`
  panicked with `record not found`; Darwin process tests were denied by the
  sandbox; the new `infra/vprotogen` package initially lacked writable module
  cache access. The separate generator check passed after dependency setup,
  and `go test -count=1 -timeout 1m ./common/net` passed outside the sandbox.
  The full suite is not reported as passing.
- Logs are `/private/tmp/xray-v261029-full-retry.log`,
  `/private/tmp/xray-v261029-scenario-retry.log`,
  `/private/tmp/xray-v261029-protogen.log`, and
  `/private/tmp/xray-v261029-common-net.log`; the other validation logs use the
  same `/private/tmp/xray-v261029-` prefix.
- Independent integration review approved the staged behavioral fingerprint
  `61eae40a755867cd73e8d3e5471ff70540a399ff`. The replayed source tree matched
  the reviewed tree exactly before these final prose-only notes were added.
  No live RouterOS, TUN, or packaged-GUI validation was performed for this release.
