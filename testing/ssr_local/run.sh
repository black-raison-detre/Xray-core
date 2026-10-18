#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$REPO_ROOT"
export GOCACHE="${GOCACHE:-/private/tmp/xray-ssr-local-go-cache}"
exec go run ./testing/ssr_local/cmd/harness "$@"
