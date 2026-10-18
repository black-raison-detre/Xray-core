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

- [ ] Run focused race tests and RouterOS-tagged package tests.
- [ ] Run the full Go suite and distinguish external-service failures.
- [ ] Build native CLI, Linux/Windows targets, and RouterOS Linux/mipsle.
- [ ] Check formatting and obtain independent review of the staged port.
- [ ] Update the paired GUI's vendored core/build input before claiming a
  packaged GUI contains this branch. The GUI repository is outside this port.
- [ ] Validate live TUN/GRE behavior on the actual operating systems and router;
  host tests and cross-compilation do not establish runtime compatibility.
