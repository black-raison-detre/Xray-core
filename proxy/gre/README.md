# Userspace GRE inbound

This package provides a RouterOS-container-oriented IPv4 GRE inbound without creating a Linux interface, route, or netfilter rule. It is excluded from normal Xray builds.

Enable it explicitly:

```sh
BUILD_TAGS=routeros_gre make build
```

or pass `-tags routeros_gre` to `go build`. Linux runtime use requires `CAP_NET_RAW`.

```json
{
  "protocol": "gre",
  "tag": "gre-routeros",
  "settings": {
    "localAddress": "172.31.255.2",
    "remoteAddress": "172.31.255.1",
    "allowedInnerSources": ["192.168.50.100/32", "10.255.0.1/32"],
    "mtu": 1400,
    "userLevel": 0,
    "icmpMode": "fake"
  }
}
```

`icmpMode` accepts `fake` (the default) or `probe`, with the same cached-Observatory behavior as the TUN inbound. Include the RouterOS GRE inner address in `allowedInnerSources` only when its ICMP health traffic should be accepted.

The receiver accepts RFC 2784 GREv0 IPv4 packets with either the base header or a valid checksum field. It also recognizes the exact RouterOS 48-byte GRE-in-GRE keepalive, reflects its prebuilt four-byte reply, and does not inject the keepalive into the IPv4 packet stack. Other nested GRE, routing, key, sequence, recursion, PPTP, EoIP, Ethernet, IPv6, unconfigured peers, disallowed inner sources, and inner protocols other than TCP, UDP, and ICMP are rejected. GRE provides neither encryption nor authentication; confine it to a private transit network.
