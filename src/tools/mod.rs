//! MCP tool router for `tari-ootle-mcp-gateway`.
//!
//! Steps 1-3 wired up the [`TariOotleMcpHandler`] struct and `ServerHandler::get_info()` —
//! mirroring `tari-project/universe`'s `src-tauri/src/mcp/tools/mod.rs` pattern (read fresh
//! from a clone of that repo this session, not guessed): the `#[derive(Clone)]` handler struct
//! holding a prebuilt `ToolRouter<Self>` field, and `#[tool_handler(router = (&self.tool_router))]`
//! pointing at that field by reference rather than letting the macro rebuild the router on
//! every call.
//!
//! `ootle_discovery` (`discovery.rs`), `ootle_read` (`read.rs`) — AGENTS.md's v1 build order
//! steps 4-5 — and `ootle_transact` (`write.rs`, step 6: is_mut=true writes with the full
//! safety-gated approval/rate-limit/`--unsafe-auto-approve` path) each land as separate
//! `#[tool_router(router = ..., vis = "pub")]` impl blocks in their own files, merged into this
//! handler's single [`ToolRouter`] in [`TariOotleMcpHandler::new`] (the real, documented
//! multi-file `#[tool_router]` merge pattern — confirmed by reading `rmcp-macros` 2.2.0's own
//! doc comment this session, not guessed). Shared address-resolution/arg-encoding/
//! instruction-building plumbing between `read.rs` and `write.rs` lives in `instruction.rs`.

use std::sync::Arc;

use rmcp::{
    ServerHandler,
    handler::server::router::tool::ToolRouter,
    model::{Implementation, ProtocolVersion, ServerCapabilities, ServerInfo},
    tool_handler, tool_router,
};

use crate::server::ServerConfig;

pub mod create;
pub mod discovery;
pub mod instruction;
pub mod read;
pub mod write;

/// MCP handler for the Tari Ootle gateway. Holds a prebuilt [`ToolRouter`] (merged from the
/// empty base router below plus `discovery`'s and `read`'s routers — see module docs) and a
/// shared [`ServerConfig`] — not read by either tool in this dispatch, but wired through
/// already (from steps 1-3) so a future `ootle_transact`'s `--unsafe-auto-approve` handling
/// doesn't need to retrofit this plumbing.
#[derive(Clone)]
pub struct TariOotleMcpHandler {
    tool_router: ToolRouter<Self>,
    pub config: Arc<ServerConfig>,
}

impl TariOotleMcpHandler {
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self {
            tool_router: Self::tool_router()
                + Self::tool_router_discovery()
                + Self::tool_router_read()
                + Self::tool_router_write()
                + Self::tool_router_create(),
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
                 step but keeps rate limiting and audit logging). Constructors (is_mut=false \
                 but returning a Component<TemplateName>) execute as a REAL submit (never a \
                 dry run) with no human-approval gate but a real rate limiter, since they \
                 put no existing balance/state at risk. This build registers \
                 list_ootle_templates, get_ootle_template_abi, call_ootle_read_function \
                 (is_mut=false reads only), call_ootle_write_function (is_mut=true writes, \
                 gated by a single-inflight approval queue unless auto-approve is enabled), \
                 approve_ootle_write (a human or a second MCP client session approves or \
                 denies a pending write by request_id), and call_ootle_create_function (real \
                 constructor calls that create new components).",
            )
    }
}

#[tool_router]
impl TariOotleMcpHandler {
    // Intentionally empty: this handler's own base router contributes zero tools. The real
    // `#[tool]`-decorated functions live in `discovery.rs` (`tool_router_discovery`) and
    // `read.rs` (`tool_router_read`), merged into `Self::new`'s `tool_router` field — see this
    // module's doc comment. A future `ootle_transact` (AGENTS.md step 6) would add a third
    // `tool_router_transact()` the same way.
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
    fn tool_router_registers_all_six_tools() {
        let handler = TariOotleMcpHandler::new(test_config(false));
        let names: Vec<String> = handler
            .tool_router
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        assert_eq!(
            names.len(),
            6,
            "expected exactly 6 registered tools, got {names:?}"
        );
        assert!(names.contains(&"list_ootle_templates".to_string()));
        assert!(names.contains(&"get_ootle_template_abi".to_string()));
        assert!(names.contains(&"call_ootle_read_function".to_string()));
        assert!(names.contains(&"call_ootle_write_function".to_string()));
        assert!(names.contains(&"approve_ootle_write".to_string()));
        assert!(names.contains(&"call_ootle_create_function".to_string()));
    }
}
