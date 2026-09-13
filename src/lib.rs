//! `tari-ootle-mcp-gateway` core library.
//!
//! Houses the parts of this gateway most likely to get lifted verbatim into
//! `tari-project/universe`'s `src-tauri/src/mcp/` module once this repo is ready for that
//! integration (see AGENTS.md): the audit log, the transaction rate limiter, the walletd
//! client wrapper, the axum/rmcp server bootstrap + bearer auth (`server`), and the MCP
//! tool router (`tools`). CLI arg parsing (the standalone-only bit) lives in `main.rs`, not
//! here.
//!
//! Split out as a lib (rather than keeping everything in `main.rs`) so these modules'
//! public API is real library API — not binary-only code that would otherwise trip the
//! `dead_code` lint for anything not yet wired up by a later dispatch (e.g. the
//! `ootle_transact` tool that will call `WalletdClientWrapper::submit_instruction`, not
//! built until AGENTS.md's v1 build order step 6).

pub mod audit;
pub mod indexer_client;
pub mod rate_limiter;
pub mod server;
pub mod tools;
pub mod walletd_client;
