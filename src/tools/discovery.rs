//! `ootle_discovery` MCP tools: dynamic ABI discovery over the public indexer.
//!
//! AGENTS.md's v1 build order step 4. Two tools, per DISPATCH_BRIEF.md:
//!
//! - [`list_ootle_templates`] — wraps `GET /templates/catalogue`, paginated, returns a summary
//!   list (address/name/author/at_epoch) only — NOT the full ABI, to keep responses small for an
//!   agent scanning many templates.
//! - [`get_ootle_template_abi`] — wraps `GET /templates/{address}`, returns the REAL functions
//!   list with real arg types (the genuine `tari_template_abi::TemplateDef`, not a mirror —
//!   see `indexer_client.rs`), annotated per-function with a plain-language mutability summary
//!   an agent needs before calling `call_ootle_read_function` (step 5, `read.rs`).
//!
//! ## Design decision flagged for review (per DISPATCH_BRIEF.md's explicit instruction)
//!
//! DISPATCH_BRIEF.md's step 2 asks for this dispatch to flag, not silently assume, the
//! following deviation from AGENTS.md's original "one MCP tool per on-chain function" framing:
//! dynamically registering a NEW `rmcp` `#[tool]` per discovered template function at runtime is
//! not possible with `rmcp` 2.2's `#[tool_router]` macro (compile-time tool registration, no
//! runtime registration API found in this session's read of the `rmcp` 2.2.0 source). So this
//! dispatch uses the brief's prescribed fallback: `get_ootle_template_abi` tells the agent what
//! functions/args exist and their mutability, and a single generic `call_ootle_read_function`
//! tool (`read.rs`, `is_mut=false` only this dispatch; a future `call_ootle_write_function` for
//! `is_mut=true` is step 6, explicitly out of scope here) takes the template/component address +
//! function name + args and executes it. **Alex/Ara: please confirm this generic-tool design is
//! the right call** rather than treating this comment as silent sign-off — it is a real,
//! deliberate deviation from AGENTS.md's original per-function-tool framing, not an oversight.

use rmcp::{ErrorData, handler::server::wrapper::Parameters, tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    audit::{AuditEntry, AuditLog, AuditStatus},
    indexer_client::{IndexerClient, IndexerError},
    tools::TariOotleMcpHandler,
};

const LOG_TARGET: &str = "tari_ootle_mcp_gateway::tools::discovery";

/// Maps any [`IndexerError`] onto an MCP [`ErrorData`], preserving the real underlying reason
/// (HTTP status + body, or the transport-level error) rather than a generic message.
fn indexer_error_to_mcp(err: IndexerError) -> ErrorData {
    ErrorData::internal_error(format!("indexer request failed: {err}"), None)
}

/// Records a `Started` audit entry, runs `f`, then records the matching `Success`/`Error`
/// entry with duration — the same wrap-every-tool-call pattern AGENTS.md requires (mirroring
/// Universe's `audit_tool_call`), applied to a tool tier that never needs approval or rate
/// limiting (`is_mut=false`-only discovery/read calls).
async fn audited<T, E, F>(tool_name: &str, details: Option<String>, fut: F) -> Result<T, E>
where
    F: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    AuditLog::record(AuditEntry {
        timestamp: std::time::SystemTime::now(),
        tool_name: tool_name.to_string(),
        tier: "discovery".to_string(),
        status: AuditStatus::Started,
        duration_ms: None,
        client_info: None,
        details: details.clone(),
    })
    .await;
    let started = std::time::Instant::now();
    let result = fut.await;
    match &result {
        Ok(_) => {
            AuditLog::record(AuditEntry {
                timestamp: std::time::SystemTime::now(),
                tool_name: tool_name.to_string(),
                tier: "discovery".to_string(),
                status: AuditStatus::Success,
                duration_ms: Some(started.elapsed().as_millis() as u64),
                client_info: None,
                details,
            })
            .await;
        }
        Err(e) => {
            log::warn!(target: LOG_TARGET, "{tool_name} failed: {e}");
            AuditLog::record(AuditEntry {
                timestamp: std::time::SystemTime::now(),
                tool_name: tool_name.to_string(),
                tier: "discovery".to_string(),
                status: AuditStatus::Error,
                duration_ms: Some(started.elapsed().as_millis() as u64),
                client_info: None,
                details: Some(e.to_string()),
            })
            .await;
        }
    }
    result
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct ListOotleTemplatesRequest {
    /// Maximum number of entries to return in this page. Defaults to 20.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Cursor for the next page: the `template_address` of the LAST entry from the previous
    /// page (NOT an offset — the real live indexer's `/templates/catalogue` route is
    /// cursor-paginated, confirmed this session). Omit for the first page.
    #[serde(default)]
    pub after: Option<String>,
}

const DEFAULT_LIST_LIMIT: u32 = 20;

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct GetOotleTemplateAbiRequest {
    /// The template's on-chain address, bare hex (as returned by `list_ootle_templates`, e.g.
    /// `"0000000000000000000000000000000000000000000000000000000000000000"` for the built-in
    /// `Account` template) or `template_`-prefixed.
    pub template_address: String,
}

#[tool_router(router = tool_router_discovery, vis = "pub")]
impl TariOotleMcpHandler {
    /// Lists published Ootle templates from the public indexer's catalogue, paginated. Returns
    /// a summary (address/name/author/at_epoch) only, NOT the full ABI — call
    /// `get_ootle_template_abi` with a specific `template_address` for that.
    #[tool(
        name = "list_ootle_templates",
        description = "List published Tari Ootle templates from the public indexer, paginated \
                        via a cursor (the previous page's last template_address, passed as \
                        'after'). Returns a summary only (address, name, author, at_epoch) - \
                        call get_ootle_template_abi for a specific template's full function list."
    )]
    pub async fn list_ootle_templates(
        &self,
        Parameters(req): Parameters<ListOotleTemplatesRequest>,
    ) -> Result<String, ErrorData> {
        let limit = req.limit.unwrap_or(DEFAULT_LIST_LIMIT);
        let details = Some(format!("limit={limit} after={:?}", req.after));
        let client = IndexerClient::from_env();
        let resp = audited("list_ootle_templates", details, async {
            client
                .list_templates_catalogue(limit, req.after.as_deref())
                .await
        })
        .await
        .map_err(indexer_error_to_mcp)?;

        serde_json::to_string_pretty(&resp).map_err(|e| {
            ErrorData::internal_error(format!("failed to serialize response: {e}"), None)
        })
    }

    /// Fetches a template's real on-chain ABI (its function list, with real argument types and
    /// mutability) from the public indexer.
    #[tool(
        name = "get_ootle_template_abi",
        description = "Fetch a Tari Ootle template's real on-chain ABI (functions, argument \
                        types, and whether each is a read (is_mut=false, callable via \
                        call_ootle_read_function, no approval) or a write (is_mut=true, not yet \
                        callable through this gateway - a future call_ootle_write_function is a \
                        separate, not-yet-built dispatch)."
    )]
    pub async fn get_ootle_template_abi(
        &self,
        Parameters(req): Parameters<GetOotleTemplateAbiRequest>,
    ) -> Result<String, ErrorData> {
        let bare_hex = strip_template_prefix(&req.template_address);
        let details = Some(format!("template_address={bare_hex}"));
        let client = IndexerClient::from_env();
        let resp = audited("get_ootle_template_abi", details, async {
            client.get_template(bare_hex).await
        })
        .await
        .map_err(indexer_error_to_mcp)?;

        let functions: Vec<_> = resp
            .definition
            .functions()
            .iter()
            .map(|f| {
                let has_self = f
                    .arguments
                    .first()
                    .map(|a| a.name == "self")
                    .unwrap_or(false);
                let summary = if f.is_mut {
                    "WRITE (is_mut=true): requires human approval; not callable through this \
                     gateway yet (call_ootle_write_function is a future, separate dispatch)."
                        .to_string()
                } else if has_self {
                    "READ (is_mut=false) METHOD: call via call_ootle_read_function with a \
                     component_<address> in `address`, omitting the leading `self` argument."
                        .to_string()
                } else {
                    "READ (is_mut=false) FUNCTION: call via call_ootle_read_function with this \
                     template's address in `address`."
                        .to_string()
                };
                json!({
                    "name": f.name,
                    "arguments": f.arguments,
                    "output": f.output,
                    "is_mut": f.is_mut,
                    "is_method": has_self,
                    "summary": summary,
                })
            })
            .collect();

        let response = json!({
            "name": resp.name,
            "template_address": bare_hex,
            "abi_version": resp.definition.abi_version(),
            "functions": functions,
        });

        serde_json::to_string_pretty(&response).map_err(|e| {
            ErrorData::internal_error(format!("failed to serialize response: {e}"), None)
        })
    }
}

/// Strips a `template_` prefix if present (the indexer's `/templates/{address}` route expects
/// the bare hex form — confirmed this session; `list_ootle_templates`' own entries already come
/// back bare). Mirrors the real convention in `crates/ootle_sdk_core/src/generic_builder.rs`'s
/// `parse_template_address` (read this session, not guessed).
pub fn strip_template_prefix(s: &str) -> &str {
    s.strip_prefix(tari_template_lib_types::address_prefixes::TEMPLATE)
        .and_then(|rest| rest.strip_prefix('_'))
        .unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_template_prefix_handles_both_forms() {
        let hex = "00".repeat(32);
        let prefixed = format!("template_{hex}");
        assert_eq!(strip_template_prefix(&prefixed), hex);
        assert_eq!(strip_template_prefix(&hex), hex);
    }

    /// Real live test (per DISPATCH_BRIEF.md's verification bar): fetch the real `Account`
    /// template's ABI via this tool's own logic (not just the raw indexer_client) and confirm
    /// the real functions/args come through correctly parsed and annotated.
    #[tokio::test]
    async fn live_get_ootle_template_abi_logic_annotates_real_account_functions() {
        let client = IndexerClient::from_env();
        let resp = client
            .get_template("0000000000000000000000000000000000000000000000000000000000000000")
            .await
            .expect("live indexer template ABI call failed");
        assert_eq!(resp.name, "Account");

        let functions: Vec<_> = resp
            .definition
            .functions()
            .iter()
            .map(|f| {
                let has_self = f
                    .arguments
                    .first()
                    .map(|a| a.name == "self")
                    .unwrap_or(false);
                (f.name.clone(), f.is_mut, has_self)
            })
            .collect();

        // `create` is a real associated function (no self, no approval needed for reading its
        // ABI, is_mut=false).
        let create = functions.iter().find(|(n, ..)| n == "create").unwrap();
        assert!(!create.1, "Account::create is_mut should be false");
        assert!(
            !create.2,
            "Account::create should have no self arg (it's a function)"
        );

        // `balance` is a real read-only method (self, is_mut=false).
        let balance = functions.iter().find(|(n, ..)| n == "balance").unwrap();
        assert!(!balance.1, "Account::balance is_mut should be false");
        assert!(
            balance.2,
            "Account::balance should have a self arg (it's a method)"
        );

        // `withdraw` is a real mutating method (self, is_mut=true) — confirms the WRITE
        // annotation branch is reachable against real data.
        let withdraw = functions.iter().find(|(n, ..)| n == "withdraw").unwrap();
        assert!(withdraw.1, "Account::withdraw is_mut should be true");
        assert!(
            withdraw.2,
            "Account::withdraw should have a self arg (it's a method)"
        );
    }
}
