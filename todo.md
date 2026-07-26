# Current Observatory capability work

- [x] Require the Observatory feature when TUN uses `icmpMode: probe`; keep `fake` and capability-only API configurations usable without Observatory.
- [x] Make UDP DNS capability-probe timeouts interrupt the real tagged outbound connection, whose deadline methods are currently no-ops.
- [x] Bound outstanding HTTP capability-probe DNS lookups so timed-out requests cannot accumulate blocked resolver goroutines.
- [x] Reject explicit HTTP probe ports outside `1..65535` instead of allowing `uint16` wraparound.
- [x] Regenerate the Observatory protobuf outputs with the repository-compatible `protoc 33.5` toolchain.
