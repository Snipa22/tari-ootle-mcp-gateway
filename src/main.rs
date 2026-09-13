//! `tari-ootle-mcp-gateway` — binary entrypoint.
//!
//! This dispatch (AGENTS.md's v1 build order step 3) wires up: env/CLI config loading, the
//! walletd connectivity check carried over from steps 1-2, the axum/rmcp MCP server
//! bootstrap (`server::McpServerManager`) with an empty tool router (`tools`), and
//! graceful shutdown on Ctrl+C / SIGTERM — same pattern as Universe's
//! `with_graceful_shutdown`. Real `#[tool]`-decorated functions
//! (`ootle_discovery`/`ootle_read`/`ootle_transact`) are explicitly out of scope here — see
//! AGENTS.md's "v1 build order" for the full plan.

use std::sync::Arc;

use clap::Parser;
use tari_ootle_mcp_gateway::{
    audit::{AuditEntry, AuditLog, AuditStatus},
    rate_limiter::TransactionRateLimiter,
    server::{McpServerManager, ServerConfig},
    walletd_client::{self, WalletdClientWrapper, WalletdConfig},
};

const LOG_TARGET: &str = "tari_ootle_mcp_gateway::main";

/// CLI args for `tari-ootle-mcp-gateway`. Server/walletd endpoint config is env-var-driven
/// (see `server::ServerConfig::from_env` / `walletd_client::WalletdConfig::from_env`) per
/// this ecosystem's flag-over-env-over-default convention; `--unsafe-auto-approve` is the
/// one setting AGENTS.md explicitly requires to be a real CLI flag, never a config-file- or
/// env-var-only toggle a future reader could miss.
#[derive(Parser, Debug)]
#[command(
    name = "tari-ootle-mcp-gateway",
    about = "Dynamic MCP gateway for Tari Ootle templates + wallet"
)]
struct CliArgs {
    /// DANGEROUS: execute mutating (is_mut=true) transactions immediately with NO human
    /// approval step. Still respects the rate limiter and any configured
    /// max-transaction-amount cap. Every transaction executed under this mode is
    /// audit-logged with the distinct `AutoApproved` status, never folded into `Success`.
    /// Intended for an agent running its own wallet fully unattended. See AGENTS.md.
    #[arg(long)]
    unsafe_auto_approve: bool,
}

/// Prints a loud, unmissable warning banner when `--unsafe-auto-approve` is set, in the
/// same spirit as `tari_ootle_walletd`'s own `--authentication None` startup warning
/// (`applications/tari_walletd/src/lib.rs`, confirmed real this session): stating plainly
/// what is disabled and why that's dangerous, not a generic one-liner.
fn print_unsafe_auto_approve_banner() {
    log::warn!(
        target: LOG_TARGET,
        "=================================================================================="
    );
    log::warn!(
        target: LOG_TARGET,
        "⚠️  --unsafe-auto-approve is ENABLED"
    );
    log::warn!(
        target: LOG_TARGET,
        "⚠️  Mutating (is_mut=true) transactions will execute immediately with NO human \
         approval step. Any MCP client that can reach this server's bearer token can spend \
         funds from the configured wallet account without further confirmation. The rate \
         limiter and any configured max-transaction-amount cap still apply, but the human \
         approval gate does not. If this is not a fully-unattended-automation deployment you \
         explicitly intend, stop this process now and restart without --unsafe-auto-approve."
    );
    log::warn!(
        target: LOG_TARGET,
        "⚠️  Every transaction executed under this mode will be audit-logged with the \
         distinct 'AutoApproved' status (never folded into 'Success') so a later audit \
         review can immediately tell which transactions had no human review."
    );
    log::warn!(
        target: LOG_TARGET,
        "=================================================================================="
    );
}

/// Waits for either Ctrl+C or (on Unix) SIGTERM — same graceful-shutdown trigger set as
/// Universe's Tauri app lifecycle, adapted for a plain binary with no windowing system to
/// hook into.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            log::info!(target: LOG_TARGET, "Received Ctrl+C, shutting down");
        },
        _ = terminate => {
            log::info!(target: LOG_TARGET, "Received SIGTERM, shutting down");
        },
    }
}

/// Carried over from the steps 1-2 scaffold: a real (if walletd is reachable) or
/// honestly-reported-unreachable connectivity check, now run once at startup before the
/// MCP server binds. Not required for the MCP server itself to start — a misconfigured or
/// unreachable walletd is logged and audited, but does not prevent this dispatch's
/// tool-less server from serving `get_info()`.
async fn walletd_startup_connectivity_check() {
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

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = CliArgs::parse();

    log::info!(
        target: LOG_TARGET,
        "tari-ootle-mcp-gateway v1 starting (server bootstrap + auth; MCP tools land in a \
         later dispatch)"
    );

    if cli.unsafe_auto_approve {
        print_unsafe_auto_approve_banner();
    }

    // Rate limiter is wired but has no caller yet in this dispatch (that's ootle_transact,
    // step 6). Constructing it here just proves the module is usable end to end.
    let mut rate_limiter = TransactionRateLimiter::new(10);
    debug_assert!(rate_limiter.check_transaction_allowed());

    walletd_startup_connectivity_check().await;

    let server_config = match ServerConfig::from_env(cli.unsafe_auto_approve) {
        Ok(config) => Arc::new(config),
        Err(e) => {
            log::error!(target: LOG_TARGET, "Refusing to start MCP server: {e}");
            std::process::exit(1);
        }
    };

    match McpServerManager::start(server_config).await {
        Ok(port) => {
            log::info!(target: LOG_TARGET, "MCP server listening on 127.0.0.1:{port} (path /mcp)");
        }
        Err(e) => {
            log::error!(target: LOG_TARGET, "Failed to start MCP server: {e}");
            std::process::exit(1);
        }
    }

    shutdown_signal().await;
    McpServerManager::stop().await;
    log::info!(target: LOG_TARGET, "tari-ootle-mcp-gateway shut down cleanly");
}
