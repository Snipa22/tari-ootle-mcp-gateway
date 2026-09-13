//! Audit log for MCP tool calls.
//!
//! Ported from `tari-project/universe`'s `src-tauri/src/mcp/audit.rs` (read fresh from a
//! clone of that repo this session, not guessed), adapted for a standalone (non-Tauri)
//! binary:
//! - Dropped the Tauri-event-emitter integration (there is no frontend to notify here).
//! - Log directory is config-driven (env var, see [`ENV_AUDIT_LOG_PATH`]) instead of
//!   Tauri's `APPLICATION_FOLDER_ID` + per-network config dir convention, since this repo
//!   has no `tari_common::configuration::Network` concept of its own.
//! - Added one new `AuditStatus` variant Universe's doesn't need: [`AuditStatus::AutoApproved`].
//!   Per AGENTS.md's `--unsafe-auto-approve` design, a transaction executed with no human
//!   approval must be distinctly audit-tagged so a later audit-log review can immediately
//!   tell which transactions had no human review — it must never be folded into the normal
//!   `Success` path.
//!
//! Core `AuditEntry`/`AuditLog`/`AuditStatus` shapes and the ring-buffer + append-only
//! JSONL-with-rotation persistence pattern are kept as close to the original as possible,
//! since this module is intended to be lifted into
//! `src-tauri/src/mcp/tools/ootle.rs`-adjacent code in Tari Universe with minimal rework
//! once this gateway is ready for that integration (see AGENTS.md).

use std::{
    collections::VecDeque,
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
    sync::LazyLock,
    time::SystemTime,
};

use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncWriteExt, sync::RwLock};

const LOG_TARGET: &str = "tari_ootle_mcp_gateway::audit";

/// Ring buffer capacity kept in memory for [`AuditLog::get_recent`].
const MAX_BUFFER_SIZE: usize = 500;
/// Number of JSONL lines written to the on-disk log before it is rotated.
const MAX_LOG_LINES: usize = 10_000;
/// How many rotated log files are kept around before the oldest are deleted.
const MAX_ROTATED_LOGS: usize = 5;

/// Env var that, if set, overrides the full path to the audit log file. Falls back to
/// `<dirs::config_dir()>/tari-ootle-mcp-gateway/mcp_audit.jsonl` (or the system temp dir if
/// no config dir can be determined) when unset. Same flag-over-env-over-default resolution
/// discipline as every other piece of config in this repo (see AGENTS.md), though here there
/// is no CLI-flag layer above the env var since the audit log path is not expected to change
/// between runs of the same deployment.
pub const ENV_AUDIT_LOG_PATH: &str = "TARI_OOTLE_MCP_AUDIT_LOG_PATH";

static INSTANCE: LazyLock<RwLock<AuditLog>> = LazyLock::new(|| RwLock::new(AuditLog::new()));

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: SystemTime,
    pub tool_name: String,
    pub tier: String,
    pub status: AuditStatus,
    pub duration_ms: Option<u64>,
    pub client_info: Option<String>,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditStatus {
    Started,
    Success,
    Error,
    Denied,
    RateLimited,
    /// A transaction executed under `--unsafe-auto-approve` with no human approval step.
    /// Distinct from `Success` so an audit-log review can immediately identify every
    /// transaction that had no human review, per AGENTS.md's non-negotiable requirement
    /// for that flag.
    AutoApproved,
}

pub struct AuditLog {
    buffer: VecDeque<AuditEntry>,
    log_path: PathBuf,
    line_count: usize,
}

impl AuditLog {
    fn new() -> Self {
        let log_path = Self::_get_log_path();
        let line_count = Self::_count_lines(&log_path);
        Self {
            buffer: VecDeque::with_capacity(MAX_BUFFER_SIZE),
            log_path,
            line_count,
        }
    }

    pub fn current() -> &'static RwLock<Self> {
        &INSTANCE
    }

    fn _get_log_path() -> PathBuf {
        if let Ok(path) = std::env::var(ENV_AUDIT_LOG_PATH) {
            return PathBuf::from(path);
        }
        let config_dir = dirs::config_dir().unwrap_or_else(std::env::temp_dir);
        config_dir
            .join("tari-ootle-mcp-gateway")
            .join("mcp_audit.jsonl")
    }

    fn _count_lines(path: &PathBuf) -> usize {
        match File::open(path) {
            Ok(file) => BufReader::new(file).lines().count(),
            Err(_) => 0,
        }
    }

    pub async fn record(entry: AuditEntry) {
        let cloned = entry.clone();
        let mut log = Self::current().write().await;

        // Add to ring buffer
        if log.buffer.len() >= MAX_BUFFER_SIZE {
            log.buffer.pop_front();
        }
        log.buffer.push_back(entry);

        // Check if rotation needed
        if log.line_count >= MAX_LOG_LINES {
            log._rotate().await;
        }

        let log_path = log.log_path.clone();
        let current_count = &mut log.line_count;

        // Write to file (outside of heavy processing but still within lock for line_count accuracy)
        if let Ok(serialized) = serde_json::to_string(&cloned) {
            if let Some(parent) = log_path.parent() {
                let _unused = tokio::fs::create_dir_all(parent).await;
            }
            match tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .await
            {
                Ok(mut file) => {
                    let line = format!("{serialized}\n");
                    if file.write_all(line.as_bytes()).await.is_ok() {
                        *current_count += 1;
                    }
                }
                Err(e) => {
                    error!(target: LOG_TARGET, "Failed to open MCP audit log: {e:?}");
                }
            }
        }
    }

    async fn _rotate(&mut self) {
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let rotated_path = self.log_path.with_extension(format!("{timestamp}.jsonl"));
        if let Err(e) = tokio::fs::rename(&self.log_path, &rotated_path).await {
            warn!(target: LOG_TARGET, "Failed to rotate MCP audit log: {e:?}");
        } else {
            info!(target: LOG_TARGET, "Rotated MCP audit log to {rotated_path:?}");
        }
        self.line_count = 0;
        self._cleanup_old_rotated_logs().await;
    }

    async fn _cleanup_old_rotated_logs(&self) {
        if let Some(parent) = self.log_path.parent() {
            let mut rotated: Vec<PathBuf> = Vec::new();
            if let Ok(mut entries) = tokio::fs::read_dir(parent).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();
                    let is_rotated = path
                        .to_str()
                        .map(|s| {
                            s.contains("mcp_audit.")
                                && s.ends_with(".jsonl")
                                && path != self.log_path
                        })
                        .unwrap_or(false);
                    if is_rotated {
                        rotated.push(path);
                    }
                }
            }
            rotated.sort();
            if rotated.len() > MAX_ROTATED_LOGS {
                for old in &rotated[..rotated.len() - MAX_ROTATED_LOGS] {
                    if let Err(e) = tokio::fs::remove_file(old).await {
                        warn!(target: LOG_TARGET, "Failed to remove old MCP audit log {old:?}: {e:?}");
                    } else {
                        info!(target: LOG_TARGET, "Removed old MCP audit log: {old:?}");
                    }
                }
            }
        }
    }

    pub async fn get_recent(count: usize) -> Vec<AuditEntry> {
        let log = Self::current().read().await;
        log.buffer.iter().rev().take(count).cloned().collect()
    }

    pub async fn export() -> Result<String, std::io::Error> {
        let log = Self::current().read().await;
        let path = &log.log_path;
        if path.exists() {
            tokio::fs::read_to_string(path).await
        } else {
            Ok(String::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_log_path(test_name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tari_ootle_mcp_gateway_audit_test_{test_name}_{}.jsonl",
            std::process::id()
        ))
    }

    #[tokio::test]
    async fn record_and_get_recent_round_trips() {
        let path = unique_log_path("record_and_get_recent");
        // SAFETY: test-only, single-threaded-per-test env var scoping is best-effort; this
        // crate's test suite does not run these audit tests concurrently against the same
        // path.
        unsafe { std::env::set_var(ENV_AUDIT_LOG_PATH, &path) };

        let entry = AuditEntry {
            timestamp: SystemTime::now(),
            tool_name: "test_tool".to_string(),
            tier: "read".to_string(),
            status: AuditStatus::Success,
            duration_ms: Some(42),
            client_info: None,
            details: Some("ok".to_string()),
        };
        AuditLog::record(entry.clone()).await;

        let recent = AuditLog::get_recent(10).await;
        assert!(recent.iter().any(|e| e.tool_name == "test_tool"));

        let _ = tokio::fs::remove_file(&path).await;
    }

    #[test]
    fn auto_approved_status_serializes_distinctly_from_success() {
        let success = serde_json::to_string(&AuditStatus::Success).unwrap();
        let auto_approved = serde_json::to_string(&AuditStatus::AutoApproved).unwrap();
        assert_ne!(
            success, auto_approved,
            "AutoApproved must never be folded into the normal Success path"
        );
        assert_eq!(auto_approved, "\"AutoApproved\"");
    }

    #[test]
    fn log_path_defaults_when_env_unset() {
        // Just exercises the default-path branch without actually touching disk; the fallback
        // must always produce *some* path.
        unsafe { std::env::remove_var(ENV_AUDIT_LOG_PATH) };
        let path = AuditLog::_get_log_path();
        assert!(path.ends_with("mcp_audit.jsonl"));
    }
}
