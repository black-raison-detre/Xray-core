# ShadowsocksR external interoperability

This opt-in harness runs Xray as a pure-Go client against the separate
Apache-licensed Python server at `EthereumD/ShadowsocksRR@1dbffcb`.

```sh
CGO_ENABLED=0 go build -o /private/tmp/xray-ssr-compat ./main
SSR_PYTHON_DIR=/path/to/ShadowsocksRR \
XRAY_BINARY=/private/tmp/xray-ssr-compat \
python3 testing/ssrinterop/run.py
```

It exercises TCP forwarding and UDP echo for the server-supported 12 active
protocols across `plain`, `http_simple`, `http_post`, and
`tls1.2_ticket_auth`, followed by representative cipher-family cases.
`auth_sha1` and `auth_sha1_v2` are intentionally excluded because this pinned
independent server does not implement their active libev client behavior; they
remain pinned C-oracle fixture and fuzz covered only.
