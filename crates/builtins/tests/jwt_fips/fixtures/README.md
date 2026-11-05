# JWT FIPS fixtures

`oracle.json` holds the tokens and keys the `jwt_fips` suite verifies. None
is signed by OpenSSL.

- `rfc`: the RFC 7515 Appendix A.2 (RS256) and A.3 (ES256) examples and the
  RFC 7520 section 4.2 (PS384) example, copied from the published text.
- Everything else: signed with RustCrypto (`rsa`, `p256`, `p384`,
  `ed25519-dalek`) by the standalone crate in `gen/`, with fresh keys on each
  run. It keeps the existing `rfc` block.

```console
cd gen && cargo run --release -- ../oracle.json
```
