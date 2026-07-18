# Local ShadowsocksR outbound benchmark

This opt-in harness measures the native Xray ShadowsocksR outbound against the
separate C `ss-server` from `shadowsocksr-libev`. All listeners bind to
`127.0.0.1`.

The full profile builds Xray and the C server, runs the C checkout's quick
loopback preflight, checks Xray-to-C interoperability across the active cipher,
protocol, and obfs registries, then measures bidirectional TCP throughput and
memory for four representative SSR stacks. Performance values are observational;
integrity, interoperability, telemetry, process health, and cleanup are the
pass/fail conditions.

The external C preflight is retried up to three times because its local port
startup is race-prone. Xray-to-C cases are not retried.

The full compatibility sweep is a hard gate. If any case fails, the harness
writes the partial result bundle and exits before timed performance profiles so
unsupported or corrupt modes cannot produce misleading benchmark numbers.

## Usage

```sh
./testing/ssr_local/run.sh \
  --ssr-source /Volumes/CaseSensitive/personalWorks/shadowsocksr-libev \
  --results /private/tmp/xray-ssr-local-$(date -u +%Y%m%dT%H%M%SZ)
```

Use `--quick` while developing the harness. It runs one shortened
`aes-256-cfb/origin/plain` Xray case instead of the full compatibility and
performance matrices.

Prebuilt binaries may be selected with `--xray-bin` and `--ssr-server-bin`.
`--ssr-server-bin` skips the source checkout's own quick preflight. Source and
server-binary selection are mutually exclusive.

Useful workload overrides:

```text
--duration 10s
--repetitions 3
--concurrency 1,8,32
--churn 2000
--recovery 65s
--sample-interval 1s
--results /path/to/empty/result-directory
```

## Result bundle

The default location is `testing/ssr_local/results/<UTC timestamp>/`. A bundle
contains repository/build metadata and binary hashes, generated configs,
per-process logs, `compatibility.csv`, `throughput.csv`, `memory.csv`,
`events.log`, and a human-readable `summary.md`. Generated passwords and configs
are local diagnostics and must not be committed.

Loopback results measure host-local protocol and CPU overhead. They are not an
internet throughput prediction. The C server has process-level RSS/CPU samples;
Go heap and goroutine metrics are available only for Xray.
