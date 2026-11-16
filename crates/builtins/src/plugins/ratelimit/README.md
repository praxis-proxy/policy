# Embedded request rate limiter

`ratelimit/limitador` uses in-process [Limitador] counters at the
`ratelimit.pre_identity` and `ratelimit.post_identity` hooks. It lives in
`praxis-policy-builtins` behind the `experimental-ratelimit` feature; the
`builtins` feature does not enable it.

The [rate-limiting guide] covers policy examples, host integration,
counter behavior, denials, and limits. The source is split across
`config.rs` (config validation), `cel.rs` (expression checks),
`factory.rs` (instance construction), and `handler.rs` (request checks).

To run the focused tests or benchmark:

```console
cargo nextest run -p praxis-policy-builtins --features experimental-ratelimit --test ratelimit
cargo bench -p praxis-policy-builtins --features experimental-ratelimit --bench ratelimit_hot_path
```

[rate-limiting guide]: ../../../../../docs/content/rate-limiting.md
[Limitador]: https://github.com/Kuadrant/limitador
