# Bugfix-only maintenance (2026-10-19)

Scope: maintain `v26.7.11-custom` at `075ec011` with selected upstream correctness fixes only. Older feature-port and behavior-change tasks below are deferred and require separate authorization; do not merge upstream functionality, TUN rewrites, TLS trust defaults, Lua, or dependency/toolchain migrations as part of this maintenance.

## CA security backport (2026-10-29)

The requested security exception to the toolchain deferral above follows [upstream v26.10.21](https://github.com/XTLS/Xray-core/releases/tag/v26.10.21). This branch uses OS roots and does not contain the bundled RootCAs feature or its fallback dependency, so the dependency-only change in [#7212](https://github.com/XTLS/Xray-core/pull/7212) does not apply here.

Upstream's bundle removed emSign ECC Root CA - C3, emSign ECC Root CA - G3, and emSign Root CA - C1. The reported cracked keys belong to eight intermediate certificates; Go's verifier update blocks those intermediate public keys rather than removing all three roots from the OS store.

- [x] Require Go 1.27.3 or later for the `crypto/x509` distrust fix ([CVE-2026-111943](https://go.dev/issue/82345)). The fix rejects chains containing any of eight distrusted intermediate public keys, including when OS trust stores have not been updated. Existing OS-root and custom-certificate behavior is retained; no dependency versions change.
- [x] Enforce the patched compiler floor in `go.mod`, which is also used by test/release workflows. A Go 1.26.10 floor alone would still allow vulnerable Go 1.27.0-1.27.2; a `toolchain` preference alone would not enforce the floor for downstream consumers.
- [x] Keep Go 1.26's GODEBUG compatibility defaults with `godebug default=go1.26`; the security distrust check is unconditional and remains active.
- [x] Disable automatic toolchain switching in the Windows 7 release job so an outdated patched builder fails the minimum-version check instead of silently switching to a stock compiler without Windows 7 support.
- [x] Confirm `GOTOOLCHAIN=local go list ./transport/internet/tls` refuses the host's Go 1.27.1, while automatic toolchain selection uses Go 1.27.3.
- [x] Run `go test -count=1 -timeout 3m ./transport/internet/tls -skip '^TestECHDial$'` with Go 1.27.3: passed. Build and launch the release-style Darwin/arm64 CLI; `go version -m` confirms Go 1.27.3, `CGO_ENABLED=0`, and the Go 1.26 compatibility defaults.
- [x] Complete independent working-tree source review of `go.mod`, the Windows 7 workflow, and this maintenance record, including TLS/uTLS callers; no actionable findings.
- [x] Run `go test -timeout 1h -v ./...` with Go 1.27.3: exited 1 after 309.5 seconds. `app/dns/TestQUICNameServer` reported no DNS record; `transport/internet/tls/TestECHDial` panicked after the Cloudflare HTTPS request returned EOF. Five Darwin process tests were blocked by sandbox process enumeration; rerunning those five outside the sandbox passed. `TestVlessXtlsVisionReality` and `TestVlessRealityFingerprints` timed out in the scenario suite. The isolated REALITY rerun passed Vision; fingerprint timeouts moved from iOS in the full suite to Firefox/Edge, while iOS passed.
- [x] Compare the REALITY scenarios with Go 1.27.1 and exact HEAD module files via `GOFLAGS=-modfile=/private/tmp/xray-ca-backport/baseline.mod GOTOOLCHAIN=local`. Both the test runner and its helper binary report Go 1.27.1. Vision passed; Firefox/Edge timed out as they did on Go 1.27.3, and QQ also timed out. This reproduces the fingerprint failure class without the backport; the full-suite result remains a failure.

Validation logs and the Darwin test binary are under `/private/tmp/xray-ca-backport/`; the build cache is `/private/tmp/xray-ca-backport-go-cache`. Existing binaries must be rebuilt to receive the standard-library fix. Windows/macOS native platform trust rejection and a chain containing a distrusted intermediate have not been exercised directly; the compiler floor and upstream verifier patch establish the security integration, while the TLS tests establish ordinary certificate behavior.

### Linux VM rerun (2026-10-29)

- [x] Test an isolated snapshot of `da9fbd47580bdac67aaa8ff8e877901a03cfde29` plus the CA-security working-tree changes in the existing ARM64 `xray-linux` VM (2 CPUs, 2 GiB). The 1,161-file manifest SHA-256 is `a956d723dd2354af873629230591b00d6e0efad042b93864aa03c636088421ec`; all file hashes passed before and after validation. The two unrelated untracked CodeQL directories were excluded. Runtime and release-binary metadata confirm Go 1.27.3 Linux/arm64.
- [x] Run the full unfiltered `go test -timeout 1h -v ./...` with `GOFLAGS=-p=1`, `GOMAXPROCS=2`, and `GOMEMLIMIT=1GiB`: exited 1. External `TestQUICNameServer` again reported no DNS record; `TestECHDial` timed out querying `1.1.1.1:53` and panicked with a malformed ECH config. The initial run also failed certificate generation on the read-only snapshot, the VMess AEAD stress timestamp check, REALITY Vision's transfer, and the large KCP transfer. Targeted reruns below passed; the full-suite result remains a failure.
- [x] Pass `go test -count=1 -timeout 3m ./transport/internet/tls -skip '^TestECHDial$'`, `go test -count=1 -timeout 3m ./common/net`, and the full suite's `TestVlessRealityFingerprints` (all six fingerprints).
- [x] Compile the whole certificate package's tests with `go test -c -o /tmp/cert-tests/cert.test ./common/protocol/tls/cert`, then run the binary from writable `/tmp/cert-tests`: passed, including `TestGenerate`. This clears the artificial read-only-working-directory failure without changing source.
- [x] Rerun the whole `proxy/vmess/aead` package with `-count=1 -timeout 3m`: passed, including `TestCreateAuthIDAndDecodeSuperMassive`. Rerun `go test -count=1 -timeout 3m -v ./testing/scenarios -run '^Test(VlessXtlsVisionReality|VMessKCPLarge)$'`: both passed. Supplemental checks took 104.1 seconds measured by the host's monotonic clock; source hashes still matched.
- [x] Build and launch the release-style `CGO_ENABLED=0` Linux/arm64 CLI; build metadata confirms Go 1.27.3. Stop `xray-linux` afterward and verify the default Docker context remains `default`.

VM artifacts, exact runner scripts, snapshot, logs, and Linux binary: `/private/tmp/xray-ca-vm-20261029/` (`report.txt`, `results/full-suite.log`, `followup.log`, `results/xray`). The container reached its 1.5-GiB memory cap with no OOM kill. A backward VM wall-clock jump was observed during the release build, so shell elapsed times are unreliable; it does not establish the cause of the earlier timestamp/transfer failures. Linux results do not exercise Darwin/Windows-specific tests. The separate Darwin process tests already passed outside the host sandbox.

### Offline DNS/DoQ/ECH simulator (2026-10-29)

The host resolves AdGuard through the TUN resolver at `198.18.0.2` to a synthetic address, and routes `1.1.1.1` through `utun4`. The user confirmed the TUN restriction and requested local simulation instead of further Internet probes.

- [x] Replace only the two external test files through temporary Go overlays; keep production code and repository tests unchanged. Run on Go 1.27.3 Linux/arm64 in a Docker container with `--network=none`: only loopback exists, with no route to the Internet. All four selected tests passed (exit 0, 7.657 seconds host-monotonic time).
- [x] Exercise the production DoQ client against an actual loopback QUIC server: TLS verification with a temporary private CA, `doq` ALPN, length-framed DNS, A/AAAA answers, repeated cache hits, and IPv4-only/IPv6-only cached views. The isolated Linux process sets its CA environment before the first system-root load; this trust setup is not designed for arbitrary full-suite ordering.
- [x] Exercise production ECH DNS discovery/configuration against a loopback UDP HTTPS-record server and a real TLS 1.3 ECH-capable HTTPS server. Ten concurrent requests require `ECHAccepted`, verified certificate chains and the inner server name; exactly one DNS query serves the shared cache. The cache update lock is released.
- [x] Check negative controls: a trusted TLS server without ECH keys is rejected with `ECHRejectionError` before HTTP, and local DNS SERVFAIL retains the production fail-closed invalid-config sentinel. The SERVFAIL case checks configuration behavior, not a subsequent TLS handshake.
- [x] Independently review the fixtures, runner, production paths and captured artifacts: no actionable defects. All 1,161 original source hashes and the three overlay fixture hashes match. Restore `xray-linux` to Stopped; Docker context stays `default`.

Simulator code, overlay map, scripts and logs: `/private/tmp/xray-local-dns-sim-20261029/` (`report.txt`, `results/doq.log`, `results/ech.log`). This proves the targeted client paths without external DNS/firewall dependencies; it does not establish full-suite success, public-upstream reachability, native platform behavior, race-detector coverage, or rejection of an actual distrusted intermediate chain.

## Follow-up: Hysteria, WireGuard, and 32-bit observatory

Baseline: `9e6e9a4a`. Keep the existing dependency versions and private configuration behavior.

- [x] Backport Hysteria stalled-write shutdown (`da2248c5`, #7172) and cover concurrent stream write/close.
- [x] Backport the Hysteria 1500-byte UDP receive buffer (`d562d894`, #6788) and cover larger received datagrams.
- [x] Backport WireGuard packet-channel shutdown and packet-view release (`dbb1ea30`, #6778; `60e2a0c5`, #6801), with shutdown regressions. Signal shutdown before stack teardown and use `sync.Once` so repeated closes are safe.
- [x] Port only the burst-observatory duration arithmetic from `d15966c7` (#7155); add accumulated and single-sample RTT overflow regressions.
- [x] Verify the regressions against original implementations: stalled QUIC write, truncated UDP payload, WireGuard send-on-closed-channel panic, and retained packet view all fail with baseline overlays. Run `go test -race -count=1 -timeout 3m ./transport/internet/hysteria ./proxy/hysteria ./proxy/wireguard ./app/observatory/burst` in `xray-linux`; all pass.
- [x] Execute the observatory regression as a 32-bit Linux binary under QEMU in the VM: the original code reports negative averages; the patched full burst suite passes. QEMU 7.0 crashes in the Go runtime with default settings; both binaries run with `GODEBUG=asyncpreemptoff=1 GOMAXPROCS=1`. This is emulation evidence, not RouterOS hardware proof.
- [x] Build and launch the release-style Linux/arm64 CLI with Go 1.27.1; it reports Xray 26.7.11. Independent working-tree review approved all ten Go implementation/test files, with no actionable findings.
- [x] Run `go test -timeout 1h -v ./...` in the Linux VM: exited 1. The four changed packages and `testing/scenarios` passed. `app/dns/TestQUICNameServer` received no record from AdGuard DNS-over-QUIC; `transport/internet/tls/TestECHDial` timed out querying ECH DNS records through `1.1.1.1:53` and panicked with `tls: malformed ECHConfigList`. These external-service failures remain unresolved. Full log: `/private/tmp/xray-followup-validation/linux-logs/full-suite.log`.

Linux validation logs: `/private/tmp/xray-followup-validation/`. The source snapshot manifest is `cf08f43b57df1d46ce71ec21955ef02d970fe0c9878c23643930ace7371e71e4`; subsequent changes to this section record validation only. No dependency versions or private configuration fields changed. Live WireGuard peer, Hysteria interoperability, and RouterOS hardware testing remain unverified.

## Earlier maintenance batch

- [x] Windows ReadV: wait for runtime socket readability before synchronous `WSARecv`, resetting readiness on every multi-buffer read (`ccb69ea5`, #6743). Add a Windows-only idle-read deadline regression with a preceding multi-buffer read.
- [x] Hysteria: make TCP/UDP client-lock waits and authentication honor cancellation, close failed authentication resources, and keep successful connections reusable (`7c2e05dc`, #7119). Preserve the older client lifecycle without importing stopped-instance tracking.
- [x] Hysteria: snapshot the client map before waiting for per-client cleanup so unrelated client creation can proceed (`2bea2df6`, #7122). Add cancellation, local HTTP/3 authentication, connection-lifecycle, and cleanup-lock regressions.
- [x] QUIC sniffing: skip zero-filled tails between cached datagrams, retaining incomplete ClientHello data and domain recovery across padded packets (`5121c28b`, #6882). Reuse the existing QUICv1 fixture without importing the QUICv2 parser refactor.
- [x] Complete independent working-tree review of all six implementation/test files; no actionable findings.
- [x] Run Hysteria race tests: `go test -race -count=1 -timeout 2m ./transport/internet/hysteria` passed. Log: `/private/tmp/xray-bugfix-hysteria-race.log`.

- [x] Confirm both new QUIC padding regressions fail against the original parser using a Go overlay, then pass with the fix. Logs: `/private/tmp/xray-bugfix-quic-baseline.log`, `/private/tmp/xray-bugfix-buf-quic-race.log`.
- [x] Run buffer/QUIC race tests: `go test -race -count=1 -timeout 2m ./common/buf ./common/protocol/quic` passed.
- [x] Cross-compile all three affected packages' tests for Windows/amd64 and build/launch the release-style Darwin/arm64 CLI. Logs: `/private/tmp/xray-bugfix-windows-build.log`, `/private/tmp/xray-bugfix-build.log`.

- [x] Run `go test -timeout 1h -v ./...`: the command exited 1. Changed packages passed; `app/dns/TestQUICNameServer` failed after AdGuard DNS-over-QUIC returned no answer, `transport/internet/tls/TestECHDial` failed after DNS to `1.1.1.1:53` timed out and left an invalid ECH config, and five Darwin process-lookup tests were denied process enumeration by the sandbox. Log: `/private/tmp/xray-bugfix-full.log`.
- [x] Rerun the five failed Darwin process-lookup tests outside the sandbox; all passed. Log: `/private/tmp/xray-bugfix-darwin-process-retest.log`. The full-suite result remains a failure; external DNS/ECH tests were not changed.

Native Windows runtime validation is unavailable on this Darwin host; Windows results are compilation evidence only. Validation uses Go 1.27.1; the module remains at Go 1.26 with unchanged dependencies.

# Connection-stability backports (2026-10-16)

Scope: selected fixes from upstream `main` at `da2248c5` onto `custom` at `14056780`. Defer the TUN stack rewrite, TLS trust defaults, new transports, Lua, and toolchain changes until an upstream release is selected for integration.

- [x] Backport interface-binding failures aborting TCP/UDP dialing, including TUN controllers and missing-interface errors (`fe2ae23f`, #7173).
- [x] Correct the paired Darwin TUN helper to apply only the socket family's binding option; propagating its previous IPv4 fallthrough error would reject valid IPv6 sockets. Add direct IPv4/IPv6 TCP/UDP socket coverage, including dual-stack and IPv6-only sockets.
- [x] Backport Mux session initialization under the session-manager lock to prevent a dispatch/close race (`7da5dae6`, #6871).
- [x] Backport Mux UDP reply source ownership so later frames cannot overwrite earlier buffers (`836a6fed`, #6822); retain support for a nil packet-reader destination.
- [x] Confirm XHTTP already has equivalent synchronized reader publication and late-reader cleanup (`eef6e63b`, #6694); retain the custom implementation and add concurrent Set/Read/Close coverage.
- [x] Confirm gRPC already dials with the reconnect context and resolved TCP destination (`9d9a7a1c`, #6877); no production change needed.
- [x] Run focused race tests for Mux, socket dialing, XHTTP, gRPC, and TUN; rerun socket/TUN packages after review fixes.
- [x] Build and launch the release-style Darwin/arm64 CLI; cross-compile socket/TUN tests for Windows/amd64 and Linux/amd64; build the RouterOS Linux/mipsle CLI with `routeros_gre`.
- [x] Check formatting for all 924 tracked supported Go files and the new tests. The repository-wide vformat command reports only generated CodeQL dependency-cache files; leave those managed artifacts unchanged.
- [x] Complete independent review of the working-tree backports and resolve the missing-interface and unsupported-platform test findings.
- [x] Run `go test -timeout 1h -v ./...`: 90 packages passed; the full command exited 1. External AdGuard DNS-over-QUIC (`TestQUICNameServer`) and Cloudflare ECH (`TestECHDial`, DNS to `1.1.1.1:53`) failed. `TestAnyTLSTCP` also initially failed with local connection refused, then passed in isolation; the harness uses a fixed startup delay rather than listener readiness. Full log: `/private/tmp/xray-stability-full.log`.
- [x] Rerun `TestAnyTLSTCP` alone and the TLS package with only `TestECHDial` skipped; both passed. The full-suite result remains a failure, despite these successful follow-up checks.
- [x] Check the DNS package with the external `TestQUICNameServer` family skipped: the follow-up still exited 1 because `TestDOHNameServerWithCache` compared live DoH results containing the same IPs in a different order. Log: `/private/tmp/xray-stability-dns-retest.log`. DNS tests remain a validation limitation; no DNS implementation or tests were changed.

Validation uses Go 1.27.1 on Darwin/arm64; `go.mod` remains at Go 1.26. Foreign-platform checks are compilation evidence, not runtime or live TUN proof.

# Main branch sync follow-up

Comparison baseline: `custom` and `main` diverged at `50231eaf`; reviewed `main` through `3af7f252` (2026-08-27).

## Runtime fixes to port

- [x] Observatory: sleep for the configured probe interval when no outbound matches `subjectSelector` instead of busy-spinning at 100% CPU (`f124daf5`, #6669).
- [x] Router: port the API data-race refactor (`598bde74`, #6678) without changing custom routing behavior.
- [x] XHTTP: port the closed-state/data-race fix and preserve upload buffer accounting (`77f98eba`, #6665).
- [x] XHTTP: define replayable packet-up request bodies for HTTP/2 GOAWAY retries (`dffc7ada`, #6632).
- [x] Darwin TUN: replace the empty-queue busy-spin with kqueue-backed waiting and retain the upstream close/failure safeguards (`aa3d6589`, #6580).
- [x] Config: port empty-listen, nil-address, VLESS/Trojan validation-order, HTTP target, and Unix-listener fixes (`3af7f252`, #6640).
- [x] WireGuard: port `sendThrough` repair plus `remoteDNS` and TTL handling (`7d214f8b`, `c7e569b0`).
- [x] Routing and sniffing: port iOS process-lookup separation, macOS IPv4-mapped process lookup, and uTP sniffing fixes (`5b1b4105`, `8b419d83`, `9b373e39`).
- [x] Server address reporting: port accurate XHTTP and gRPC `localAddr` handling (`4aba687d`).

## Platform and behavior updates to review

- [ ] Review and port the OpenBSD TPROXY, IPv6, and `SO_REUSEPORT` changes (`a000371b`, `25c11e2d`) if the custom build will retain upstream platform parity.
- [ ] Review the XMC finalmask directional padding and keep-alive implementation (`6ab123bf`) as a behavior-changing transport update.
- [ ] Review the XHTTP default `maxConnections` reduction from 6 to 3 (`18e28390`) for anti-TSPU behavior.
- [ ] Review the unnamed TUN default change from `xray0` to an available `utunN`; the paired GUI supplies `Xray-GUI TUN` explicitly, so its managed path does not use this default (`6ce924ad`).
- [ ] Port Windows TUN `desc` support while retaining custom `icmpMode` (`1d8eb81d`).
- [ ] Port the remaining routing `localOS` feature, REALITY warning, dependency, workflow, and release updates after the runtime fixes.

## Manual integration requirements

- [x] Resolve the TUN protobuf field collision by keeping upstream `desc = 8`, moving custom `icmp_mode` to field 9, and regenerating `proxy/tun/config.pb.go` with repository-compatible protobuf tooling. The paired GUI persists JSON; CLI-produced custom `.pb` configs must be regenerated from JSON.
- [ ] Preserve AnyTLS, ShadowsocksR, GRE, `noListenerInboundProtocols`, `strictPseudoInbounds`, and RouterOS build-tag behavior while applying upstream `infra/conf/xray.go` and TUN changes.
- [x] Combine the upstream and custom TUN README examples and limitations.
- [ ] Update and validate the paired Xray-GUI `third_party/Xray-core` snapshot before claiming the packaged GUI contains the ported fixes.

## Integration validation

- [x] Run focused race tests for Observatory, Router, and XHTTP.
- [x] Run focused TUN/config tests on Darwin and the RouterOS GRE build-tag path.
- [x] Run WireGuard, routing, BitTorrent sniffer, and affected transport package tests.
- [x] Run formatting checks, `git diff --check`, the release-style build, and the full Go suite; report external-network test failures separately from source regressions.

# Resolver reachability review follow-up

- [x] Close idle HTTP/2 connections after every HTTPS or H2C resolver probe so repeated manual checks do not retain connections and transport goroutines.
- [x] Disable HTTP redirects for resolver probes. A redirected request must not change its authority or path while the forced dialer continues connecting to the original resolver.
- [x] Regenerate `command.pb.go` and `command_grpc.pb.go` with the repository-compatible `protoc 33.5` toolchain and matching Go protobuf plugins.
- [x] Remove `t.Fatal` calls that can run inside pipe or HTTP-server goroutines in `resolver_reachability_test.go`; return errors to the main test goroutine instead.

## Validation

- [x] Run `gofmt` on the changed Go files.
- [x] Run `git diff --check`.
- [x] Run `go vet ./app/observatory/command`.
- [x] Run `go test -race -count=1 ./app/observatory/command`.
