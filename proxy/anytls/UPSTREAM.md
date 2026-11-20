# AnyTLS upstream integration

The native Xray adapter tracks the session behavior of
[`anytls/anytls-go` v0.0.13](https://github.com/anytls/anytls-go/tree/v0.0.13),
commit `9666872946857b50a74fdb692896d77b53773cb2`.
This is an in-tree port, not a Go module dependency or a claim that the Xray
executable is the upstream reference client.

The integration carries these upstream behaviors:

- Reuse only idle sessions, preferring the newest one. Concurrent requests
  reserve separate sessions; closing a stream makes its healthy session idle.
- `disableSessionReuse: true` bypasses the idle pool and closes the session
  when its stream ends. The existing JSON/protobuf field is preserved.
- Expire transport deadlines before session shutdown, so blocked TLS I/O can
  finish before the transport attempts its TLS shutdown.
- Arm the five-second control-write deadline before waiting for the shared
  transport writer, and discard a session after a failed frame write.
- Deliver received data synchronously before processing the next frame,
  including FIN. `internal/pipe` is copied from this upstream tag, with its
  Go Authors copyright header and BSD license retained.
- Discard late data, FIN, and admission replies for streams already closed,
  instead of terminating an otherwise healthy session.
- Coalesce the initial SETTINGS, SYN, and destination-address PSH; subsequent
  stream opens use separate control writes. Keep the default padding scheme.

Xray retains its TLS/REALITY transport, password/user management, routing,
policy timers, strict frame/config validation, connected/unconnected UoT,
and explicit v1/v2 admission handling. Admission waits remain bounded for
the first v2 stream as well as reused streams. Padding updates remain scoped
to the outbound. Pool shutdown and stream-close callbacks are synchronized
for concurrent Xray handlers.

As in upstream v0.0.13, heartbeat requests are answered, but no active
heartbeat scheduler is added. Bulk data writes have no fixed five-second
timeout: slow readers are allowed, while control writes and session shutdown
can interrupt blocked transport I/O. Existing TCP streams are not replayed
when a session fails.

Focused validation:

```text
go test ./proxy/anytls ./infra/conf
go test ./testing/scenarios -run '^TestAnyTLS' -timeout 15m
```

The HTTPS scenario has an optional five-minute slow-reader workload enabled
with `XRAY_ANYTLS_SUSTAINED=1`. Passing short tests alone does not establish
that the previously observed sustained-transfer stall has been resolved.

`TestAnyTLSUpstreamInterop` tests HTTPS traffic in both directions against the
reference binaries when `XRAY_ANYTLS_UPSTREAM_SERVER` and
`XRAY_ANYTLS_UPSTREAM_CLIENT` point to executables built from this exact tag.
It exercises reuse enabled and disabled without downloading or starting
external software during ordinary test runs.
