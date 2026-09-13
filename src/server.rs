//! axum + rmcp HTTP server bootstrap for `tari-ootle-mcp-gateway`.
//!
//! Ported from `tari-project/universe`'s `src-tauri/src/mcp/server.rs` (read fresh from a
//! clone of that repo this session, not guessed) and adapted for a standalone (non-Tauri)
//! binary:
//! - Universe's `McpServerManager` reads its bearer token / port from a Tauri-app-wide
//!   `ConfigMcp` singleton and a `WalletManager`/node-status-receiver pair used to build its
//!   `TariMcpHandler`. This repo has none of those — config comes from [`ServerConfig`],
//!   sourced from env vars / CLI flags (see [`ServerConfig::from_env`]), and the handler
//!   (this dispatch: [`crate::tools::TariOotleMcpHandler`]) is currently a tool-less
//!   skeleton (real `ootle_discovery`/`ootle_read`/`ootle_transact` tools land in later
//!   dispatches per AGENTS.md's v1 build order).
//! - Universe's `auth_middleware` also does sliding-expiry token refresh against
//!   `ConfigMcp` on every successful request. This repo has no such expiry concept (no UI
//!   to configure `token_expiry_days`) — the bearer check here is a straight constant-time
//!   comparison with no expiry.
//! - Kept the SAME `McpServerManager` start/stop/restart lifecycle shape as Universe (a
//!   manager with explicit start/stop, not just an inline `main()` that blocks forever)
//!   specifically because AGENTS.md says this is meant to be lifted into Universe's actual
//!   manager pattern later, even though this standalone binary only ever starts one server
//!   for its whole process lifetime.
//! - Bind failure handling mirrors Universe's own "Refusing to fall back to a random port
//!   for security reasons" comment verbatim in spirit: this server refuses to fall back to
//!   an unconfigured port or an empty bearer token, for the same reason (another process on
//!   an unexpected port, or a missing/blank token, could intercept or bypass auth).

use std::{
    net::SocketAddr,
    sync::{Arc, LazyLock},
};

use log::{error, info, warn};
use rmcp::transport::{
    StreamableHttpServerConfig, streamable_http_server::session::local::LocalSessionManager,
    streamable_http_server::tower::StreamableHttpService,
};
use sha2::{Digest, Sha256};
use tokio::{sync::RwLock, task::JoinHandle};

use crate::tools::TariOotleMcpHandler;

const LOG_TARGET: &str = "tari_ootle_mcp_gateway::server";

/// How long [`McpServerManager::stop`] waits for the server task to finish shutting down
/// gracefully before giving up and reporting a timeout. Same value Universe uses.
const SHUTDOWN_TIMEOUT_SECS: u64 = 5;

/// Env var for the address the MCP HTTP server binds to. Falls back to
/// [`DEFAULT_LISTEN_ADDR`] if unset — a documented local-dev fallback only, per AGENTS.md's
/// "no hardcoded infra" rule.
pub const ENV_LISTEN_ADDR: &str = "TARI_OOTLE_MCP_LISTEN_ADDR";
/// Local-dev fallback listen address. Port 8199 chosen per AGENTS.md's dispatch brief as
/// free against this ecosystem's known port map (8080 explorer, 12009 walletd, 18200
/// validator JSON-RPC are all taken).
pub const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:8199";
/// Env var for the bearer token required on every MCP request. No default — same "refuse
/// to fall back insecurely" philosophy as Universe's own listener-bind comment: this server
/// refuses to start at all if this is unset, rather than picking an insecure default.
pub const ENV_BEARER_TOKEN: &str = "TARI_OOTLE_MCP_BEARER_TOKEN";

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error(
        "Missing required environment variable {0}: the MCP bearer token must be explicitly \
         configured. Refusing to start with no auth token — same \"refuse to fall back \
         insecurely\" philosophy as this server's own bind-failure handling (see AGENTS.md)."
    )]
    MissingBearerToken(&'static str),
    #[error(
        "{0} is set but empty: an empty bearer token would let any request through unauthenticated. \
         Refusing to start."
    )]
    EmptyBearerToken(&'static str),
    #[error("Invalid listen address '{addr}' (from {env_var}): {source}")]
    InvalidListenAddr {
        addr: String,
        env_var: &'static str,
        #[source]
        source: std::net::AddrParseError,
    },
    #[error(
        "MCP server failed to bind to {addr}: {source}. Refusing to fall back to a random \
         port for security reasons — another process on the configured port could intercept \
         bearer tokens."
    )]
    BindFailed {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("MCP server is already running on port {0}")]
    AlreadyRunning(u16),
}

/// Config-driven server settings, resolved once at startup and shared (via `Arc`) with the
/// handler so later dispatches (AGENTS.md's `ootle_transact` tool, v1 build order step 6)
/// can read [`Self::unsafe_auto_approve`] without any retrofitting of this plumbing.
#[derive(Debug)]
pub struct ServerConfig {
    pub listen_addr: SocketAddr,
    pub bearer_token: String,
    /// Whether `--unsafe-auto-approve` was passed on the command line. Not read by any tool
    /// in this dispatch (no tools exist yet) — wired through now per the dispatch brief so
    /// step 4+ doesn't have to retrofit it.
    pub unsafe_auto_approve: bool,
}

impl ServerConfig {
    /// Reads [`ENV_LISTEN_ADDR`] (defaulting to [`DEFAULT_LISTEN_ADDR`]) and
    /// [`ENV_BEARER_TOKEN`] (required, no default, must be non-empty) from the process
    /// environment. `unsafe_auto_approve` comes from the CLI flag, not an env var, per
    /// AGENTS.md's requirement that it never be a config-file-only/env-only toggle a future
    /// reader could miss.
    pub fn from_env(unsafe_auto_approve: bool) -> Result<Self, ServerError> {
        let addr_str =
            std::env::var(ENV_LISTEN_ADDR).unwrap_or_else(|_| DEFAULT_LISTEN_ADDR.to_string());
        let listen_addr =
            addr_str
                .parse::<SocketAddr>()
                .map_err(|source| ServerError::InvalidListenAddr {
                    addr: addr_str,
                    env_var: ENV_LISTEN_ADDR,
                    source,
                })?;

        let bearer_token = std::env::var(ENV_BEARER_TOKEN)
            .map_err(|_| ServerError::MissingBearerToken(ENV_BEARER_TOKEN))?;
        if bearer_token.is_empty() {
            return Err(ServerError::EmptyBearerToken(ENV_BEARER_TOKEN));
        }

        Ok(Self {
            listen_addr,
            bearer_token,
            unsafe_auto_approve,
        })
    }
}

static INSTANCE: LazyLock<RwLock<McpServerManager>> =
    LazyLock::new(|| RwLock::new(McpServerManager::new()));

/// Mirrors Universe's `McpServerManager` shape (start/stop/restart, bound-port tracking) so
/// this can be lifted into Universe's real singleton-manager pattern later with minimal
/// rework, per AGENTS.md. This standalone binary only ever constructs one server for its
/// whole process lifetime, but the explicit start/stop lifecycle is kept anyway.
pub struct McpServerManager {
    server_handle: Option<JoinHandle<()>>,
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
    bound_port: Option<u16>,
}

impl McpServerManager {
    fn new() -> Self {
        Self {
            server_handle: None,
            shutdown_tx: None,
            bound_port: None,
        }
    }

    pub fn current() -> &'static RwLock<Self> {
        &INSTANCE
    }

    pub fn port(&self) -> Option<u16> {
        self.bound_port
    }

    pub fn is_running(&self) -> bool {
        self.server_handle.is_some()
    }

    /// Starts the MCP HTTP server bound to `config.listen_addr`, protected by bearer auth.
    /// Returns the bound port. If a server is already running, returns its existing port
    /// without starting a second one (mirrors Universe's `start()` idempotency check).
    pub async fn start(config: Arc<ServerConfig>) -> Result<u16, ServerError> {
        {
            let manager = Self::current().read().await;
            if manager.is_running()
                && let Some(port) = manager.port()
            {
                info!(target: LOG_TARGET, "MCP server already running on port {port}");
                return Ok(port);
            }
        }

        let listener = tokio::net::TcpListener::bind(config.listen_addr)
            .await
            .map_err(|source| ServerError::BindFailed {
                addr: config.listen_addr,
                source,
            })?;
        let bound_port = listener
            .local_addr()
            .map_err(|source| ServerError::BindFailed {
                addr: config.listen_addr,
                source,
            })?
            .port();
        info!(target: LOG_TARGET, "MCP server listening on {}", config.listen_addr);

        let bearer_token = config.bearer_token.clone();
        let handler_config = config.clone();

        // Build the rmcp StreamableHttpService — a fresh `TariOotleMcpHandler` per session,
        // same pattern as Universe's `StreamableHttpService::new`.
        let mcp_service: StreamableHttpService<TariOotleMcpHandler, LocalSessionManager> =
            StreamableHttpService::new(
                move || Ok(TariOotleMcpHandler::new(handler_config.clone())),
                LocalSessionManager::default().into(),
                StreamableHttpServerConfig::default(),
            );

        // axum 0.8 router with bearer auth middleware wrapping the /mcp endpoint.
        let protected_router =
            axum::Router::new()
                .nest_service("/mcp", mcp_service)
                .layer(axum::middleware::from_fn(move |req, next| {
                    let token = bearer_token.clone();
                    auth_middleware(token, req, next)
                }));

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

        let handle = tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, protected_router)
                .with_graceful_shutdown(async move {
                    let _unused = shutdown_rx.wait_for(|v| *v).await;
                })
                .await
            {
                error!(target: LOG_TARGET, "MCP server exited with error: {e:?}");
            }
            info!(target: LOG_TARGET, "MCP server stopped");
        });

        {
            let mut manager = Self::current().write().await;
            manager.server_handle = Some(handle);
            manager.shutdown_tx = Some(shutdown_tx);
            manager.bound_port = Some(bound_port);
        }

        Ok(bound_port)
    }

    /// Signals the running server to shut down gracefully and waits (up to
    /// [`SHUTDOWN_TIMEOUT_SECS`]) for it to actually stop. Safe to call even if no server is
    /// running.
    pub async fn stop() {
        let (handle, shutdown_tx) = {
            let mut manager = Self::current().write().await;
            let handle = manager.server_handle.take();
            let tx = manager.shutdown_tx.take();
            manager.bound_port = None;
            (handle, tx)
        };

        if let Some(tx) = shutdown_tx {
            let _unused = tx.send(true);
        }

        if let Some(handle) = handle {
            let timeout = tokio::time::timeout(
                std::time::Duration::from_secs(SHUTDOWN_TIMEOUT_SECS),
                handle,
            );
            match timeout.await {
                Ok(Ok(())) => {
                    info!(target: LOG_TARGET, "MCP server shut down cleanly");
                }
                Ok(Err(e)) => {
                    error!(target: LOG_TARGET, "MCP server task panicked: {e:?}");
                }
                Err(_) => {
                    warn!(target: LOG_TARGET, "MCP server shutdown timed out after {SHUTDOWN_TIMEOUT_SECS}s");
                }
            }
        }
    }

    pub async fn restart(config: Arc<ServerConfig>) -> Result<u16, ServerError> {
        Self::stop().await;
        Self::start(config).await
    }
}

/// Bearer-token auth middleware. Ported from Universe's `auth_middleware`: constant-time
/// comparison via SHA-256 hashing (not a naive `==` on the raw token, to avoid a timing
/// side-channel that could let an attacker learn the token byte-by-byte). Unlike Universe's
/// version, there is no sliding-expiry token refresh here — this repo has no `ConfigMcp`
/// equivalent tracking `token_expiry_days`, so a valid token is valid indefinitely (or until
/// the process is restarted with a different `TARI_OOTLE_MCP_BEARER_TOKEN`).
async fn auth_middleware(
    expected_token: String,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, axum::http::StatusCode> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|v: &axum::http::HeaderValue| v.to_str().ok());

    match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            let provided = &header[7..];
            let provided_hash = Sha256::digest(provided.as_bytes());
            let expected_hash = Sha256::digest(expected_token.as_bytes());
            if provided_hash == expected_hash {
                Ok(next.run(req).await)
            } else {
                Err(axum::http::StatusCode::UNAUTHORIZED)
            }
        }
        _ => Err(axum::http::StatusCode::UNAUTHORIZED),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serial_test::serial;

    use super::*;

    fn unique_port() -> u16 {
        // Bind to port 0 to let the OS assign a free ephemeral port, then immediately
        // release it. Small TOCTOU race in theory, negligible in practice for a test suite
        // that doesn't run this at massive parallelism against the same port.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind failed");
        listener.local_addr().expect("local_addr failed").port()
    }

    #[test]
    #[serial]
    fn config_from_env_requires_bearer_token() {
        // SAFETY: test-only; no other test in this process depends on this var being unset
        // concurrently within the same process run in a way that would race meaningfully.
        unsafe {
            std::env::remove_var(ENV_BEARER_TOKEN);
            std::env::remove_var(ENV_LISTEN_ADDR);
        }
        let err = ServerConfig::from_env(false).unwrap_err();
        assert!(matches!(
            err,
            ServerError::MissingBearerToken(ENV_BEARER_TOKEN)
        ));
    }

    #[test]
    #[serial]
    fn config_from_env_rejects_empty_bearer_token() {
        unsafe {
            std::env::set_var(ENV_BEARER_TOKEN, "");
        }
        let err = ServerConfig::from_env(false).unwrap_err();
        assert!(matches!(
            err,
            ServerError::EmptyBearerToken(ENV_BEARER_TOKEN)
        ));
        unsafe {
            std::env::remove_var(ENV_BEARER_TOKEN);
        }
    }

    #[test]
    #[serial]
    fn config_from_env_defaults_listen_addr_when_unset() {
        unsafe {
            std::env::set_var(ENV_BEARER_TOKEN, "test_token");
            std::env::remove_var(ENV_LISTEN_ADDR);
        }
        let config = ServerConfig::from_env(false).unwrap();
        assert_eq!(config.listen_addr, DEFAULT_LISTEN_ADDR.parse().unwrap());
        unsafe {
            std::env::remove_var(ENV_BEARER_TOKEN);
        }
    }

    #[test]
    #[serial]
    fn config_from_env_rejects_invalid_listen_addr() {
        unsafe {
            std::env::set_var(ENV_BEARER_TOKEN, "test_token");
            std::env::set_var(ENV_LISTEN_ADDR, "not-a-valid-addr");
        }
        let err = ServerConfig::from_env(false).unwrap_err();
        assert!(matches!(err, ServerError::InvalidListenAddr { .. }));
        unsafe {
            std::env::remove_var(ENV_BEARER_TOKEN);
            std::env::remove_var(ENV_LISTEN_ADDR);
        }
    }

    #[test]
    #[serial]
    fn config_from_env_threads_unsafe_auto_approve_flag() {
        unsafe {
            std::env::set_var(ENV_BEARER_TOKEN, "test_token");
        }
        let config = ServerConfig::from_env(true).unwrap();
        assert!(config.unsafe_auto_approve);
        unsafe {
            std::env::remove_var(ENV_BEARER_TOKEN);
        }
    }

    /// Real end-to-end smoke test of the full auth flow: start a real server on a real
    /// ephemeral port, make a real HTTP request over a real TCP socket without a bearer
    /// token (expect 401) and with the correct one (expect a non-401 real MCP response),
    /// then stop it and confirm the port is released.
    #[tokio::test]
    #[serial]
    async fn server_rejects_missing_or_wrong_bearer_and_accepts_correct_one() {
        let port = unique_port();
        let config = Arc::new(ServerConfig {
            listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            bearer_token: "integration_test_token".to_string(),
            unsafe_auto_approve: false,
        });

        let bound_port = McpServerManager::start(config.clone())
            .await
            .expect("server failed to start");
        assert_eq!(bound_port, port);

        let base = format!("http://127.0.0.1:{bound_port}/mcp");
        let client = reqwest::Client::new();

        // No Authorization header at all.
        let resp = client.get(&base).send().await.expect("request failed");
        assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

        // Wrong token.
        let resp = client
            .get(&base)
            .header("Authorization", "Bearer wrong_token")
            .send()
            .await
            .expect("request failed");
        assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

        // Correct token: rmcp's streamable HTTP transport rejects a bare GET with no
        // session/protocol headers, but that rejection happens *after* auth, so any
        // non-401 response proves the bearer check passed and the request reached the
        // real rmcp service.
        let resp = client
            .get(&base)
            .header("Authorization", "Bearer integration_test_token")
            .send()
            .await
            .expect("request failed");
        assert_ne!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

        McpServerManager::stop().await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Port should be released now that the server has stopped.
        let rebind = tokio::net::TcpListener::bind(config.listen_addr).await;
        assert!(
            rebind.is_ok(),
            "port {bound_port} was not released after stop()"
        );
    }

    #[tokio::test]
    #[serial]
    async fn stop_is_safe_to_call_when_nothing_is_running() {
        McpServerManager::stop().await;
        McpServerManager::stop().await;
        let manager = McpServerManager::current().read().await;
        assert!(!manager.is_running());
    }
}
