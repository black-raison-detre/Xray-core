# ShadowsocksR compatibility layer notice

The initial Go structure in this internal directory was derived from
`github.com/v2rayA/shadowsocksR` `v1.0.4`, licensed under the MIT license in
`LICENSE`. It has been substantially adapted for Xray: active registry parity,
bounded streaming decoders, injected clock/random sources, shared legacy
ciphers, protocol parameter handling, and Xray TCP/UDP integration.

The pinned `shadowsocksr-libev` source is used only as an external behavioral
oracle. No source code, linked object, or runtime component from that GPL
project is included here.
