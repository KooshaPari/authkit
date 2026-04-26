# AuthKit

> **Status:** Pre-extraction staging repo. Not a published SDK.

AuthKit (formerly AuthVault) is a pre-extraction staging repository for shared infrastructure crates that will eventually move to **phenoShared**. Despite the name, this repository does **not** currently contain authentication SDK code — that work is planned but not started. The crates currently checked in here are general-purpose Phenotype-org infrastructure being staged for extraction.

If you arrived here looking for a unified OAuth/OIDC/SAML/WebAuthn SDK: that does not exist yet in this repo.

## Current Contents

The `rust/` workspace currently contains five infrastructure crates:

| Crate | Purpose |
|-------|---------|
| `phenotype-bid` | Bid / auction primitives shared across Phenotype services |
| `phenotype-content-hash` | Content-addressable hashing utilities |
| `phenotype-contracts` | Cross-service contract / interface definitions |
| `phenotype-policy-engine` | Rule-based policy evaluation (TOML-configured) |
| `phenotype-security-aggregator` | Security signal aggregation across sources |

Build:

```bash
cd rust && cargo build --workspace && cargo test --workspace
```

## Roadmap

1. **Now:** Stage and stabilize the five infrastructure crates above.
2. **Next:** Extract them into `phenoShared` once their APIs are stable.
3. **Later:** Reuse this repo (or a successor) for actual auth SDK work — at which point the README and crate layout will be rewritten to match.

Until step 3 happens, treat any reference to `authkit-core`, `authkit-provider-*`, or multi-language (TypeScript/Python/Go) auth bindings in older docs as aspirational — none of that code exists here.

## Related Phenotype Projects

- **phenoShared** — destination for the staged crates above
- **bifrost-extensions** — API gateway (separate auth concerns)
- **PhenoPlugins** — plugin system

## License

MIT — see [LICENSE](./LICENSE).
