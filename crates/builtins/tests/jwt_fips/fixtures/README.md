# JWT FIPS fixtures

`oracle.json` holds tokens and keys from signers independent of OpenSSL, so
the `jwt_fips` suite never verifies a signature OpenSSL produced.

- `rfc`: the RFC 7515 Appendix A.2 (RS256) and A.3 (ES256) examples and the
  RFC 7520 section 4.2 (PS384) example, copied from the published text.
- Everything else: signed with Python `cryptography` by
  `gen/gen_fixtures.py`, with fresh keys on each run.

To regenerate, run the script, then merge the `rfc` block back in from the
previous file:

```console
python3 -I gen/gen_fixtures.py <output-dir>
```
