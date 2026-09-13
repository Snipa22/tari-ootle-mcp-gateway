---
description: go-tari-* ecosystem repo (Rust) — dynamic MCP gateway for Ootle templates + wallet
---

# AGENTS.md

Instructions for AI coding agents (OpenCode, Claude Code, or any `agents.md`-compatible tool)
working in this repository. Read this before making changes.

## Project

- **What this repo is:** a standalone Rust MCP (Model Context Protocol) server that lets an
  agent (1) dynamically discover any published Tari Ootle template's real on-chain ABI and
  (2) execute real read AND write transactions against it through a `tari_ootle_walletd`
  instance — full read+write from v1, dynamic (any template address), per Alex's explicit
  scoping decisions this session.
- **Why it's a standalone repo, not built inside `tari-project/universe` directly:** Alex wants
  this **eventually integrated into Tari Universe** (the Tauri desktop app). Universe's
  `src-tauri/src/mcp/` module already has a mature, production MCP server for L1
  wallet/mining control (rmcp 2.0 + axum, bearer auth, tiered permissions, PIN-gated
  human-approval-dialog transaction flow, rate limiter, audit log) — confirmed real by reading
  `tari-project/universe`'s actual source this session, not guessed. This repo is deliberately
  architected to mirror that module's exact conventions (see "Mirror Universe's MCP module"
  below) so it can be lifted into `src-tauri/src/mcp/tools/ootle.rs` (a new tool category
  alongside the existing `mining`/`wallet`/`chain`/`scheduler`) with minimal rework once ready,
  while shipping something usable standalone right now.
- **Module path / crate name:** `tari-ootle-mcp-gateway` (binary crate; consider splitting a
  `tari-ootle-mcp-core` lib crate for the parts most likely to get lifted into Universe
  verbatim — tool definitions, ABI-to-schema conversion, transaction-safety state machine —
  vs. the standalone-only bits like its own axum server bootstrap and CLI arg parsing).
- **Depends on:**
  - `rmcp` v2.0 (`server`, `macros`, `transport-streamable-http-server` features) — same crate
    Universe uses. Pin the same major version Universe currently depends on
    (`tari-project/universe`'s `src-tauri/Cargo.toml`, check at implementation time — it may
    have moved since this brief was written).
  - `tari_ootle_walletd_client` — **NOT published to crates.io** (confirmed this session).
    Depend on it via a git dependency pinned to a specific commit, same discipline as this
    ecosystem's Go repos pin `go-tari-grpc-lib`:
    ```toml
    tari_ootle_walletd_client = { git = "https://github.com/tari-project/tari-ootle.git", rev = "d89dc92fc824d5e4e217e32044a8a17da7c39366" }
    ```
    Re-verify this commit still builds against whatever `tari_ootle_walletd` binary version is
    actually deployed (see "Real deployed infra" below) before assuming API compatibility —
    the wallet daemon client and server are versioned together in that repo.
  - `axum` (same major version rmcp's `transport-streamable-http-server` feature expects —
    check `rmcp`'s own `Cargo.toml` for which axum version it re-exports/expects; Universe
    aliases it as `axum08` to disambiguate from other axum versions in its dependency tree —
    you likely don't need that alias trick here since this is a fresh, simpler crate graph).
  - `schemars` (JSON Schema derive for tool parameter types, same as Universe).
  - `sha2` (constant-time bearer-token comparison, same pattern as Universe's `auth_middleware`).

## Real deployed infra to build/test against (confirmed live this session, 2026-09-13)

- **`tari_ootle_walletd`**: running on proxmox-tari CT132, `192.168.40.132:12009` (JSON-RPC over
  plain HTTP at `/json_rpc`), network `esmeralda`, `--authentication None` (its own startup log
  prints a real warning: "dangerous... not a temporary local-only test wallet" — this is
  explicitly a disposable testnet-only credential model per that same warning; DO NOT assume
  this same `None`-auth setup is appropriate once Universe integration happens against real
  user funds — Universe's own MCP module solves this correctly with PIN+dialog, not by
  disabling walletd's own auth).
  - Real listening ports elsewhere on the same CT132: `127.0.0.1:18200` is
    `tari_validator_node`'s own JSON-RPC (a DIFFERENT service — validator health, not wallet
    operations; don't confuse the two).
- **Admin API key already minted** for gateway use: sent as `Authorization: Bearer tw_...`
  header on every JSON-RPC call — **retrieve the actual value from Ara/session memory or the
  live `tari_ootle_walletd` instance's `auth.list_api_keys` result, don't hardcode a stale copy
  of it in this repo's own config/tests.** (Real value exists but is deliberately not repeated
  verbatim in this doc file, since AGENTS.md ends up in version control.)
  - Minted via: `auth.request` (params: `{"permissions": ["Admin"], "credentials": "None"}`,
    PascalCase permission tags) to get a bootstrap JWT, then
    `auth.create_api_key` (params: `{"name": "...", "permissions": ["admin"], "confirm_admin":
    true}` — **note the different casing/grammar**: `auth.create_api_key`'s `permissions` field
    uses the lowercase string grammar (`"admin"`, `"webrtc"`, or `"<resource>:<action>[:<entity>]"`,
    see `clients/wallet_daemon_client/src/permissions.rs`'s `Permission`/`Crud` enums), NOT the
    PascalCase enum-tag form `auth.request` uses. Confirmed two genuinely different
    serializations for the same underlying concept — don't assume one grammar works for both
    endpoints.
- **Funded test account**: `mcp-gateway-account`
  (`component_86d532912d9c22b7f4a191d5a00d532c5bc5af3672c651e64094578bef90faf5`), ~999,997,692
  µtTARI balance, created via `accounts.create` + `accounts.create_free_test_coins` (real
  on-chain tx, confirmed committed at epoch 10993). Use this account for real integration tests
  against the live daemon — real funds exist, real transactions can be sent and observed.
  - `accounts.create_free_test_coins` needs `max_fee >= ~2300` (2000 was rejected as
    insufficient — real fee cost was 2308 for that specific transaction; don't hardcode this
    number as a universal minimum, it's transaction-shape-dependent, but it's a useful
    ballpark for what "too low" looks like).
- **Public indexer** (already used by `go-tari-ootle-explorer`, same one `tari_ootle_walletd`
  above points at): `https://ootle-indexer-a.tari.com` — real, live, reachable. Use
  `GET /templates/catalogue` (paginated list) and `GET /templates/{address}` (real ABI:
  `TemplateDefV1` → `functions: Vec<FunctionDef>`, each with `name`, `arguments: Vec<ArgDef>`
  (each `{name, arg_type: Type}`), `output: Type`, `is_mut: bool`) for template discovery — see
  `crates/template_abi/src/template_def.rs` in `tari-project/tari-ootle` for the exact real
  struct shapes, cite the commit hash you verify against.

## Architecture

```
cmd (main.rs)          -> mcp::server (axum bootstrap, bearer auth, --unsafe-auto-approve flag)
                        -> mcp::tools::ootle_discovery (indexer client: catalogue, template ABI -> dynamic tool schemas)
                        -> mcp::tools::ootle_read      (read-only component/substate queries, no approval needed)
                        -> mcp::tools::ootle_transact  (is_mut=true calls: PIN-equivalent + approval + rate-limit + audit, OR auto-approve if --unsafe-auto-approve)
                        -> walletd_client (tari_ootle_walletd_client wrapper: auth, accounts, transactions.submit_instruction, transactions.detect_inputs, transactions.submit_dry_run)
                        -> mcp::audit (same shape as Universe's AuditLog)
                        -> mcp::rate_limiter (same shape as Universe's TransactionRateLimiter)
```

### Mirror Universe's MCP module — read these files from a fresh `tari-project/universe` clone
before writing any Rust in this repo, don't guess the pattern:

- `src-tauri/src/mcp/server.rs` — `McpServerManager` (start/stop/restart, bound-port handling,
  bearer `auth_middleware` with constant-time hash comparison and sliding-expiry token refresh).
  This repo's `mcp::server` should follow the SAME shape, adapted for a standalone binary (no
  `LazyLock<RwLock<...>>` singleton needed if this process only ever runs one server instance
  — but keep the start/stop semantics clean for whenever this gets lifted into Universe's
  actual singleton-manager pattern).
- `src-tauri/src/mcp/tools/mod.rs` — the `#[tool_router]`/`#[tool]` macro pattern, the
  `ServerHandler`/`get_info()` server-metadata pattern, and CRITICALLY the
  audit-log-wrapping-every-tool-call pattern (`audit_tool_call` before AND after each tool body,
  `Instant::now()` timing, `AuditStatus::{Started,Success,Error}`). Every tool in THIS repo
  should follow the identical wrap pattern.
- `src-tauri/src/mcp/tools/transaction.rs` — the FULL transaction-safety state machine:
  single-inflight semaphore (`TXN_DIALOG_GATE`), rate limiter check AFTER acquiring the gate
  (not before — avoids burning rate-limit quota on a request that's about to queue behind
  another), oneshot channel for the approval response, `DIALOG_TIMEOUT_SECS` timeout,
  `respond_to_transaction`/`clear_inflight` public functions. **This repo has no Tauri frontend
  to show a dialog in** — the approval-wait step needs a different concrete mechanism (a second
  MCP tool the same or a different MCP client calls to approve/deny by request_id; a simple
  local HTTP endpoint; a CLI prompt if run interactively — pick ONE, document why, and keep the
  same oneshot-channel/timeout/single-inflight shape so the eventual Universe port only needs
  to swap the "how does approval get signaled" mechanism, not the whole state machine).
- `src-tauri/src/mcp/audit.rs` and `src-tauri/src/mcp/rate_limiter.rs` — port these nearly
  verbatim; they're small, self-contained, and exactly what this repo needs too.

### `--unsafe-auto-approve` flag (Alex's explicit addition to the safety design)

A real, supported mode for full automation — an agent running its own wallet unattended, no
human in the loop. Requirements, non-negotiable per Alex's framing ("add a flag... 😄" — real
but should be loud, not a quiet bypass):

- Must be an explicit CLI flag (`--unsafe-auto-approve`), never a config-file-only toggle a
  future reader could miss, and never the default.
- On startup, if set: print a loud, unmissable warning banner to stdout/log (similar spirit to
  `tari_ootle_walletd`'s own `--authentication None` warning) stating transactions will execute
  with NO human approval.
- Every transaction executed under this mode must be audit-logged with a DISTINCT status/tag
  (e.g. `AuditStatus::AutoApproved`, not silently folded into the normal `Success` path) so a
  later audit-log review can immediately tell which transactions had no human review.
- Still respects the rate limiter and any configured max-transaction-amount cap — auto-approve
  removes the HUMAN gate, not every other safety control.
- The PIN-equivalent check: since this standalone binary has no Tauri PIN manager, decide (and
  document your decision explicitly in code comments) what "the wallet is unlocked/ready"
  means for this binary — likely just "the configured walletd API key is present and the
  daemon responds to an authenticated call," not a literal PIN. Don't silently skip this
  check's spirit just because there's no literal PIN UI to gate on.

## Dynamic tool generation from real on-chain ABIs

1. `ootle_discovery::list_templates()` — thin wrapper over indexer `GET /templates/catalogue`
   (paginated — see `go-tari-ootle-explorer`'s `internal/indexerclient` for the real
   cursor-pagination shape, `after=<template_address>` not offset-based, if useful as a
   reference for the pagination logic even though that repo is Go).
2. `ootle_discovery::get_template_abi(address)` — wrapper over `GET /templates/{address}`,
   returns the real `TemplateDefV1`.
3. **Schema generation**: for each `FunctionDef`, build an MCP tool whose JSON Schema
   parameters are derived from `arguments: Vec<ArgDef>`'s `arg_type: Type` — the real `Type`
   enum (see `template_def.rs`) needs a mapping to JSON Schema types (primitives, `Vec<T>`,
   `Option<T>`, and an `Other { name: String }` catch-all for template-specific types like
   `ResourceAddress`/`ComponentAddress`/`Amount` — represent those as strings in the MCP tool
   schema, since that's how they're represented on the wire in JSON-RPC params anyway per
   `tari_ootle_wallet_cli`'s own `-a` arg parsing convention). Don't try to build a fully
   type-safe Rust binding per template function — the whole point is this is DYNAMIC and works
   for templates that don't exist yet.
4. Route each generated tool call through EITHER `ootle_read` (if `FunctionDef.is_mut == false`
   — no approval needed, safe) OR `ootle_transact` (if `is_mut == true` — full safety pattern
   unless `--unsafe-auto-approve`).
5. Actual execution: build a single-instruction transaction
   (`CallMethod`/`CallFunction` against the target `component_address`/`template_address` +
   `method`/`function` name + the tool-call's args) and submit via
   `transactions.submit_instruction` (the wallet daemon's own high-level convenience method,
   confirmed real in `clients/wallet_daemon_client/src/lib.rs` — prefer this over hand-building
   a full `Transaction` builder chain for v1's single-call case; multi-instruction
   workspace-chained calls across components are a real, valuable v2 feature but out of scope
   for the FIRST working version). For read-only calls, prefer
   `transactions.submit_dry_run` (no fee spent, no state change) over a real submit.

## v1 build order

1. `mcp::audit` + `mcp::rate_limiter` — port from Universe nearly verbatim (small, mechanical,
   low-risk to get exactly right first).
2. `walletd_client` — thin wrapper over `tari_ootle_walletd_client`, config-driven endpoint +
   API key (env var / CLI flag, never hardcoded — same standing rule as every other repo in
   this ecosystem). Real integration test against the live CT132 instance using the funded
   `mcp-gateway-account`.
3. `mcp::server` — axum bootstrap + bearer auth middleware, ported from Universe.
4. `ootle_discovery` tools — indexer client (reuse/adapt patterns from
   `go-tari-ootle-explorer`'s `internal/indexerclient` conceptually, this is a fresh Rust HTTP
   client, not a port of Go code) + ABI-to-JSON-Schema conversion. Real test: fetch a real
   live template's ABI (e.g. `Account` at `0000...0000`) and confirm the generated tool schema
   is sane.
5. `ootle_read` tools — read-only dynamic calls via dry-run. Real test against a live
   `is_mut=false` function on a real template.
6. `ootle_transact` tools — the full safety-gated write path, including the
   `--unsafe-auto-approve` mode. Real test: a real `is_mut=true` call against the funded test
   account, both WITH the approval gate (verify it actually blocks until approved/timed out)
   and WITH `--unsafe-auto-approve` (verify it executes immediately and is distinctly audited).

## Commands

- **Build:** `cargo build --release`
- **Test:** `cargo test`
- **Vet:** `cargo clippy --all-targets -- -D warnings`
- **Format:** `cargo fmt --check` (`cargo fmt` to fix)

Run build + clippy + fmt + test before considering any change complete.

## Conventions

- **Conventional Commits** required.
- **Rebase, never merge.** No merge commits in PR branches.
- **No direct commits/pushes to `main`.** Always via PR — exception: this repo's own initial
  scaffold commit (this file + LICENSE + Cargo.toml skeleton) may land directly on `main` under
  admin-bypass since the repo is brand new; branch protection applied immediately after.
- Follow Universe's real MCP module conventions (see "Mirror Universe's MCP module" above) —
  don't invent a different tool-registration or audit pattern just because this is a different
  repo; the whole point is future portability.
- **No hardcoded infra** — walletd endpoint, API key, indexer URL: all config-driven (env var
  + CLI flag, following this ecosystem's established `TARI_OOTLE_*`-style env var naming and
  flag-over-env-over-default resolution order), never a literal in source beyond a documented
  local-dev fallback.

## Don't

- Don't build this as a Go binary — Rust only, per Alex's explicit stack decision (maximizes
  future Tari Universe upstream-ability).
- Don't skip or weaken the transaction-safety pattern for the "safe" default mode — the whole
  point of mirroring Universe's design is that it's already been thought through carefully
  (PIN-equivalent, single-inflight, rate-limited, audited). `--unsafe-auto-approve` is the
  ESCAPE HATCH, not evidence the default path can be simplified.
- Don't assume `tari_ootle_walletd_client` is on crates.io — it isn't (confirmed this session);
  git-dependency pin only.
- Don't hand-build multi-instruction workspace-chained transactions in v1 — single
  `CallMethod`/`CallFunction` per tool call is the v1 scope; cross-component chaining is a
  real, valuable v2 feature, not required for the first working version.
- Don't reuse the live CT132 `tari_ootle_walletd`'s `--authentication None` setup as a template
  for how Universe integration should eventually handle auth — that's a deliberate testnet-only
  shortcut for THIS repo's own development/testing, not the design for real-funds usage.

## Disclosure

If you (the agent) are making a substantial autonomous contribution, make sure the human
operator adds a disclosure note to the PR. Don't assume this happens automatically — mention
it if it's about to be skipped.
