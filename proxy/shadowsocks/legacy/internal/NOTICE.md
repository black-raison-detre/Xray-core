# Legacy block cipher notices

This directory contains narrow pure-Go primitive implementations used only for
wire compatibility with explicitly selected legacy Shadowsocks methods.

- `camellia`: derived from `github.com/aead/camellia` (MIT). See its `LICENSE`.
- `idea`: derived from `github.com/deatil/go-cryptobin/cipher/idea` at
  `v1.1.1001` (Apache-2.0). See its `LICENSE`.
- `rc2`: derived from `golang.org/x/crypto/pkcs12/internal/rc2` at the module
  version pinned by Xray (BSD-3-Clause). See its `LICENSE`.
- `seed`: derived from `github.com/MoonSeongKwang/seed` (MIT). See its
  `LICENSE`.

The ports are intentionally internal and expose only the block-cipher API
needed by the shared legacy stream engine. Known-answer tests are colocated
with each implementation.
