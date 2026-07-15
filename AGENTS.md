# Repository Guidelines

## Project Structure & Module Organization

Xray-core is a Go module (`github.com/xtls/xray-core`). Runtime subsystems live in `app/`, shared utilities in `common/`, public core/configuration code in `core/`, protocol implementations in `proxy/`, and network transports in `transport/`. Configuration parsing and repository tooling are under `infra/`; CLI entry points are in `main/`. Keep package-level tests beside their code as `*_test.go`. Cross-component scenarios, test servers, and mocks belong in `testing/scenarios/`, `testing/servers/`, and `testing/mocks/`.

## Build, Test, and Development Commands

- `CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main` builds the release-style CLI binary.
- `go test -timeout 1h -v ./...` runs the same full test suite used by CI.
- `go run ./infra/vformat/main.go -mode check -pwd ./` checks formatting without modifying files.
- `go run ./infra/vformat/main.go` formats supported Go files; install `mvdan.cc/gofumpt@latest` first when needed.

Full tests expect `resources/geoip.dat` and `resources/geosite.dat`; CI restores them from cache.

## Coding Style & Naming Conventions

Use standard Go conventions: tabs as produced by the formatter, short lowercase package names, exported identifiers in `PascalCase`, and unexported identifiers in `camelCase`. CI enforces `gofumpt` through `infra/vformat`. Follow the surrounding package's error-wrapping and file-naming patterns. Do not hand-edit generated `*.pb.go` or `*_grpc.pb.go` files; update the colocated `.proto` source and regenerate artifacts while preserving generated headers.

## Testing Guidelines

Use Go's standard `testing` package and name files `*_test.go` and functions `TestXxx`. Add focused tests beside changed code; reserve `testing/scenarios/` for network or multi-component behavior. Run targeted package tests while iterating, then run `go test -timeout 1h -v ./...` before submitting.

## Commit & Pull Request Guidelines

Recent history favors concise, imperative, component-prefixed subjects, for example `TLS client: Handle ...` or `Docker: Add ...`; merged commits commonly include a PR number. Keep commits and PRs narrowly scoped. PR descriptions should explain behavior changes, identify affected protocols or transports, link relevant issues, and list exact validation commands and results. Include screenshots or logs only when they clarify user-visible or runtime behavior.

## Security & Managed Assets

Report vulnerabilities privately through GitHub Security Advisories, following `SECURITY.md`. Treat files in `resources/` as managed runtime/release assets; automated workflows download and verify geodata and Wintun files, so avoid unrelated manual changes.
