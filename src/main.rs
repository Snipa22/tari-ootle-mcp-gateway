//! `tari-ootle-mcp-gateway` — v1 build order steps 1-2 scaffold (see AGENTS.md).
//!
//! This dispatch only wires up the audit log, rate limiter, and walletd client wrapper.
//! The axum-based `mcp::server` bootstrap and the `#[tool]`-decorated MCP tools
//! (`ootle_discovery` / `ootle_read` / `ootle_transact`) are explicitly out of scope here —
//! see AGENTS.md's "v1 build order" for the full plan. `main` therefore does not start any
//! long-running server yet; it just proves out the wiring with a real (if walletd is
//! reachable) or honestly-reported-unreachable connectivity check.

use tari_ootle_mcp_gateway::{
    audit::{AuditEntry, AuditLog, AuditStatus},
    rate_limiter::TransactionRateLimiter,
    walletd_client::{self, WalletdClientWrapper, WalletdConfig},
};

const LOG_TARGET: &str = "tari_ootle_mcp_gateway::main";

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    log::info!(
        target: LOG_TARGET,
        "tari-ootle-mcp-gateway v1 scaffold (audit + rate_limiter + walletd_client only; \
         mcp::server and MCP tools land in a later dispatch)"
    );

    // Rate limiter is wired but has no caller yet in this dispatch (that's ootle_transact,
    // step 6). Constructing it here just proves the module is usable end to end.
    let mut rate_limiter = TransactionRateLimiter::new(10);
    debug_assert!(rate_limiter.check_transaction_allowed());

    match WalletdConfig::from_env() {
        Ok(config) => {
            log::info!(target: LOG_TARGET, "Connecting to walletd at {}", config.endpoint);
            AuditLog::record(AuditEntry {
                timestamp: std::time::SystemTime::now(),
                tool_name: "startup_connectivity_check".to_string(),
                tier: "read".to_string(),
                status: AuditStatus::Started,
                duration_ms: None,
                client_info: None,
                details: Some(format!("endpoint={}", config.endpoint)),
            })
            .await;

            match WalletdClientWrapper::connect(&config) {
                Ok(mut client) => {
                    let started = std::time::Instant::now();
                    match client.get_accounts_list(0, 1).await {
                        Ok(resp) => {
                            log::info!(
                                target: LOG_TARGET,
                                "walletd reachable: {} account(s) total",
                                resp.total
                            );
                            AuditLog::record(AuditEntry {
                                timestamp: std::time::SystemTime::now(),
                                tool_name: "startup_connectivity_check".to_string(),
                                tier: "read".to_string(),
                                status: AuditStatus::Success,
                                duration_ms: Some(started.elapsed().as_millis() as u64),
                                client_info: None,
                                details: Some(format!("total_accounts={}", resp.total)),
                            })
                            .await;
                        }
                        Err(e) => {
                            log::warn!(target: LOG_TARGET, "walletd not reachable: {e}");
                            AuditLog::record(AuditEntry {
                                timestamp: std::time::SystemTime::now(),
                                tool_name: "startup_connectivity_check".to_string(),
                                tier: "read".to_string(),
                                status: AuditStatus::Error,
                                duration_ms: Some(started.elapsed().as_millis() as u64),
                                client_info: None,
                                details: Some(e.to_string()),
                            })
                            .await;
                        }
                    }
                }
                Err(e) => {
                    log::warn!(target: LOG_TARGET, "Failed to construct walletd client: {e}");
                }
            }
        }
        Err(e) => {
            log::warn!(
                target: LOG_TARGET,
                "walletd not configured ({e}); skipping connectivity check. Set {} and {} to enable it.",
                walletd_client::ENV_WALLETD_URL,
                walletd_client::ENV_WALLETD_API_KEY
            );
        }
    }
}
