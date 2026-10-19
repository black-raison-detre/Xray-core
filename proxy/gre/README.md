# Userspace GRE inbound

This package provides a RouterOS-container-oriented GRE inbound without creating a Linux interface, route, or netfilter rule. It carries IPv4 and IPv6 inner packets over an IPv4 GRE transport and is excluded from normal Xray builds.

Enable it explicitly:

```sh
BUILD_TAGS=routeros_gre make build
```

or pass `-tags routeros_gre` to `go build`. The RouterOS build profile excludes the TUN inbound's configuration registration. GRE uses the same lightweight TCP/IP stack as TUN and WireGuard, without creating a kernel TUN interface. Linux runtime use requires `CAP_NET_RAW`.

The raw socket feeds validated inner packets directly into the shared stack, with remote-packet checksum validation enabled. Replies use a single vectored GRE send; the shared stack handles TCP segmentation and UDP/ICMP fragmentation to the configured MTU. There is no gVisor endpoint queue or separate packet-pump goroutine pair. gVisor remains an independent peer in host integration tests, but is absent from the RouterOS executable's dependency graph.

```json
{
  "protocol": "gre",
  "tag": "gre-routeros",
  "settings": {
    "localAddress": "172.31.255.2",
    "remoteAddress": "172.31.255.1",
    "allowedInnerSources": ["192.168.50.100/32", "2001:db8:50::/64", "10.255.0.1/32"],
    "mtu": 1400,
    "userLevel": 0,
    "icmpMode": "fake"
  }
}
```

`icmpMode` accepts `fake` (the default) or `probe`, with the same cached-Observatory behavior as the TUN inbound for ICMP and ICMPv6 echo. Include the RouterOS GRE inner address in `allowedInnerSources` only when its health traffic should be accepted. The default MTU is 1400; configurations that allow IPv6 sources must use an MTU of at least 1280.

The receiver accepts RFC 2784 GREv0 packets with IPv4 (`0x0800`) or IPv6 (`0x86dd`) payloads, either with the base GRE header or a valid checksum field. IPv6 extension headers and fragments are passed to the shared packet stack for validation and reassembly. The receiver also recognizes the exact RouterOS 48-byte IPv4 GRE-in-GRE keepalive, reflects its prebuilt four-byte reply, and does not inject the keepalive into the packet stack. Other nested GRE, GRE routing/key/sequence extensions, PPTP, EoIP, Ethernet, IPv6 outer transport (`gre6`), unconfigured peers, disallowed inner sources, and inner protocols other than TCP, UDP, ICMP, and ICMPv6 are rejected. Reserved receive bits that RFC 2784 requires implementations to ignore are accepted. GRE provides neither encryption nor authentication; confine it to a private transit network.

Local regression checks:

```sh
go test -race -tags routeros_gre ./proxy/gre ./proxy/tun ./proxy/wireguard ./infra/conf
go list -deps -tags routeros_gre ./main
```

The flow tests cover IPv4/IPv6 TCP and UDP, fragmented UDP, IPv6 extension headers, and cached-delay ICMP replies. Linux device tests check cancellation and closing a blocked packet read without requiring a raw socket. Cross-builds and host tests do not establish RouterOS runtime compatibility or quantify CPU/RAM savings; those require the planned real-device test.
