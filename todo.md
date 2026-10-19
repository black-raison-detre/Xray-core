# Bugfix-only maintenance (2026-10-19)

Scope: maintain `v26.7.11-custom` at `075ec011` with selected upstream correctness fixes only. Older feature-port and behavior-change tasks below are deferred and require separate authorization; do not merge upstream functionality, TUN rewrites, TLS trust defaults, Lua, or dependency/toolchain migrations as part of this maintenance.

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
