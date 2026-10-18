# Local AnyTLS diagnostic harness

This harness runs two standalone Xray processes on loopback: one AnyTLS server
and one client with TCP SOCKS and UDP dokodemo-door inbounds. It validates TCP
and UDP-over-TCP behavior, measures bidirectional TCP throughput, and samples
memory for both Xray roles.

The default matrix compares direct loopback with three AnyTLS client modes:

- default session reuse;
- session reuse with `minIdleSession: 0`;
- `minIdleSession: 0` with session reuse disabled.

The balanced defaults take roughly eight minutes after the build completes.

Each AnyTLS mode gets fresh client and server processes so retained sessions and
post-idle memory are not mixed across modes. Performance and memory values are
reported, not used as machine-specific pass/fail thresholds. Startup failures,
process exits, byte corruption, UDP loss, monitoring failures, and incomplete
cleanup do fail the run.

## Usage

Do not invoke this until a benchmark run is intended:

```sh
./testing/anytls_local/run.sh
```

By default the harness builds the current checkout once with the repository's
release-style build flags and launches that executable for both Xray roles.
Prebuilt or different role binaries can be selected with:

```sh
./testing/anytls_local/run.sh --xray-bin /path/to/xray
./testing/anytls_local/run.sh \
  --server-bin /path/to/server-xray \
  --client-bin /path/to/client-xray
```

Useful workload overrides:

```text
--duration 10s
--concurrency 1,8,32
--churn 2000
--recovery 65s
--sample-interval 1s
--results /path/to/result-directory
```

Role-specific binary flags override `--xray-bin`. If a role has no selected
binary, the current checkout is built once and used for every unresolved role.

## Result bundle

The default output is `testing/anytls_local/results/<UTC timestamp>/`. These
directories are ignored by Git and contain generated credentials, so they
should be treated as local diagnostic artifacts. A bundle contains:

- the generated certificate and per-mode Xray JSON configs;
- Xray logs, repository/build metadata, and executable hashes;
- `throughput.csv` and `memory.csv` raw samples;
- `summary.md` with throughput ratios and per-role memory peaks/recovery;
- `events.log` with phase and failure context.

All service, proxy, metrics, TCP payload, and UDP echo listeners bind only to
`127.0.0.1`.
