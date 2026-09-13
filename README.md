# tari-ootle-mcp-gateway

A standalone Rust MCP (Model Context Protocol) server for dynamic Tari Ootle template
discovery and wallet transaction execution — an agent can point it at any published
template address, get a real, on-chain-derived tool schema for every function, and call
read or write methods through a `tari_ootle_walletd` instance.

**Full read+write from v1, dynamic (any template), designed to eventually upstream into
[`tari-project/universe`](https://github.com/tari-project/universe)'s existing MCP module**
(`src-tauri/src/mcp/`) — this repo deliberately mirrors that module's tool-registration,
audit-logging, rate-limiting, and transaction-approval conventions so a future port is
mostly a lift-and-adapt, not a rewrite. See `AGENTS.md` for the full design brief, the real
deployed test infra (`tari_ootle_walletd` on proxmox-tari, a funded test account, the public
esmeralda indexer), and the v1 build order.

## Status

Scaffolding.

## Safety model

Read-only template calls execute without approval. Write (`is_mut: true`) calls go through
the same transaction-safety pattern as Tari Universe's own MCP server: rate-limited,
single-in-flight, human-approval-gated, fully audited. A `--unsafe-auto-approve` flag exists
for fully unattended automation — it is loud (startup warning, distinctly audit-tagged
transactions) and never the default.

## License

MIT — see `LICENSE`.
