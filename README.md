# WSTS Blueprint

## Local qualification

Use the Rust toolchain and components owned by [rust-toolchain.toml](rust-toolchain.toml), and provision Foundry on the admitted host using the channel owned by the retained [manual Foundry workflow](.github/workflows/foundry.yml). Solidity dependency configuration remains in [foundry.toml](foundry.toml).

Before merge, merge the fresh default branch into the working branch and run affected source checks and real integration checks through the admitted Beelink launcher. Workflow/docs-only changes use YAML, content, link, diff and static checks.

This comprehensive local qualification reference preserves the former formatting, Solidity dependency/build, Clippy and full Rust test populations:

```bash
beelink-gate auto https://github.com/tangle-network/wsts-blueprint.git "$(git rev-parse HEAD)" -- sh -c 'cargo fmt -- --check && forge --version && forge soldeer update -d && forge update && forge build && cargo clippy --tests --examples -- -D warnings && cargo test'
```

The repository commits a Soldeer lock but no Cargo lock; the Rust commands therefore retain the existing manifest-based dependency resolution. No frozen Rust resolution is claimed.

The manual Foundry workflow remains available with its build-size and Solidity test checks. PR and push CI do not gate merges; publishers and downstream releases retain their own qualification.
