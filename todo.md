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
