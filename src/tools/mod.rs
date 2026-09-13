//! Skeleton MCP tool router for `tari-ootle-mcp-gateway`.
//!
//! This dispatch (AGENTS.md's v1 build order step 3) only wires up the
//! [`TariOotleMcpHandler`] struct, an empty `#[tool_router]` impl block, and
//! `ServerHandler::get_info()` — mirroring `tari-project/universe`'s
//! `src-tauri/src/mcp/tools/mod.rs` pattern (read fresh from a clone of that repo this
//! session, not guessed): the `#[derive(Clone)]` handler struct holding a prebuilt
//! `ToolRouter<Self>` field, and `#[tool_handler(router = (&self.tool_router))]` pointing
//! at that field by reference rather than letting the macro rebuild the router on every
//! call.
//!
//! Real `#[tool]`-decorated functions (`ootle_discovery::list_templates`,
//! `ootle_read::*`, `ootle_transact::*`) land in later dispatches per AGENTS.md's v1 build
//! order steps 4-6 — this file intentionally has zero real tools yet.

use std::sync::Arc;

use rmcp::{
    ServerHandler,
    handler::server::router::tool::ToolRouter,
    model::{Implementation, ProtocolVersion, ServerCapabilities, ServerInfo},
    tool_handler, tool_router,
};

use crate::server::ServerConfig;

/// MCP handler for the Tari Ootle gateway. Holds a prebuilt [`ToolRouter`] (currently
/// empty) and a shared [`ServerConfig`] — the latter not read by any tool yet in this
/// dispatch, but wired through now (per the dispatch brief) so the `--unsafe-auto-approve`
/// flag doesn't need to be retrofitted into every tool's construction path once
/// `ootle_transact` lands.
#[derive(Clone)]
pub struct TariOotleMcpHandler {
    tool_router: ToolRouter<Self>,
    pub config: Arc<ServerConfig>,
}

impl TariOotleMcpHandler {
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self {
            tool_router: Self::tool_router(),
            config,
        }
    }
}

// rmcp 2.0's `#[tool_handler]` defaults to rebuilding the router via `Self::tool_router()`
// on every call; point it at the prebuilt field by reference instead so it's constructed
// once (in `new()`) and borrowed per request. `ToolRouter::{call,list_all,get}` all take
// `&self`, and the parens are required: the macro expands `#router.call(..)`, so a bare
// `&self.tool_router` would bind `&` to the call result, not the field. Same pattern
// Universe's `TariMcpHandler` uses.
#[tool_handler(router = (&self.tool_router))]
impl ServerHandler for TariOotleMcpHandler {
    fn get_info(&self) -> ServerInfo {
        // rmcp 2.0 marked `ServerInfo` (`InitializeResult`) and `Implementation` as
        // `#[non_exhaustive]`, so they must be built via constructors + `with_*` setters
        // rather than struct literals — same as Universe's `get_info()`.
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::V_2025_03_26)
            .with_server_info(
                Implementation::new("tari-ootle-mcp-gateway", env!("CARGO_PKG_VERSION"))
                    .with_title("Tari Ootle MCP Gateway")
                    .with_description(
                        "Dynamic MCP gateway for Tari Ootle templates: discovers any \
                         published template's real on-chain ABI and executes read and \
                         write transactions against it via a tari_ootle_walletd instance.",
                    ),
            )
            .with_instructions(
                "Tari Ootle MCP gateway. Dynamically discovers published Ootle template \
                 ABIs from the public indexer and exposes their functions as MCP tools: \
                 read-only functions (is_mut=false) execute via a fee-free dry run with no \
                 approval required, while mutating functions (is_mut=true) require human \
                 approval before executing a real on-chain transaction, unless this server \
                 was started with --unsafe-auto-approve (which removes the human approval \
                 step but keeps rate limiting and audit logging). No discovery/read/transact \
                 tools are registered in this build yet — this is the server/auth scaffold \
                 only; dynamic tools land in a later release.",
            )
    }
}

#[tool_router]
impl TariOotleMcpHandler {
    // Intentionally empty: zero real `#[tool]`-decorated functions in this dispatch. See
    // AGENTS.md's v1 build order steps 4-6 (`ootle_discovery`, `ootle_read`,
    // `ootle_transact`) for what lands here next.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::ServerConfig;

    fn test_config(unsafe_auto_approve: bool) -> Arc<ServerConfig> {
        Arc::new(ServerConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            bearer_token: "test_token".to_string(),
            unsafe_auto_approve,
        })
    }

    #[test]
    fn handler_construction_threads_unsafe_auto_approve_flag() {
        let handler = TariOotleMcpHandler::new(test_config(true));
        assert!(handler.config.unsafe_auto_approve);

        let handler = TariOotleMcpHandler::new(test_config(false));
        assert!(!handler.config.unsafe_auto_approve);
    }

    #[test]
    fn get_info_describes_this_gateway_not_universes_mining_wallet() {
        let handler = TariOotleMcpHandler::new(test_config(false));
        let info = handler.get_info();
        let description = info
            .server_info
            .description
            .expect("server_info.description should be set");
        assert!(description.contains("Ootle"));
        let instructions = info.instructions.expect("instructions should be set");
        assert!(instructions.contains("is_mut"));
    }

    #[test]
    fn tool_router_starts_empty() {
        let handler = TariOotleMcpHandler::new(test_config(false));
        assert_eq!(handler.tool_router.list_all().len(), 0);
    }
}
