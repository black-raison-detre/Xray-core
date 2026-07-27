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
