# Linux GRE namespace integration

`run.sh` is an opt-in privileged integration test. It creates two temporary network namespaces joined by a veth pair, uses a kernel GRE interface as the peer, and runs the build-tagged Xray userspace GRE inbound in the other namespace.

Run on Linux as root:

```sh
sudo ./testing/gre_linux/run.sh
```

The test verifies TCP, UDP, a fragmented 4096-byte UDP datagram, TUN-style ICMP echo, GRE interface counters, and namespace cleanup. Results and logs are written under `/tmp/xray-gre-linux.*` unless `RESULTS_DIR` is provided.

This is Linux kernel interoperability proof. It is not RouterOS hardware, WAN egress, ARMv5 runtime, or fail-open RouterOS policy-routing proof.
