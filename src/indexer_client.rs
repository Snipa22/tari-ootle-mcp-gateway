//! HTTP client for the public Tari Ootle indexer's template + substate routes.
//!
//! Real, live, confirmed API surface (verified this session against
//! `https://ootle-indexer-a.tari.com`, a public, stable, reachable-from-anywhere service per
//! DISPATCH_BRIEF.md — no env-gated-skip needed here, unlike `walletd_client.rs`'s tests):
//!
//! - `GET /templates/catalogue?limit=N&after=<template_address>` — paginated list, cursor-based
//!   via `after` (the last entry's `template_address`), NOT offset-based. Real response shape
//!   confirmed live: `{"entries":[{"template_address":"...","template_name":"...",
//!   "author_public_key":"...","binary_hash":"...","at_epoch":0}, ...]}`.
//! - `GET /templates/{address}` — the real on-chain ABI. Real response shape confirmed live:
//!   `{"name":"Account","definition":{"V1":{"template_name":"Account","abi_version":0,
//!   "functions":[...]}}}`. `definition` deserializes directly into the REAL
//!   `tari_template_abi::TemplateDef` (pinned to this repo's `tari_ootle_walletd_client` git
//!   rev, so it is guaranteed to be the exact same wire shape the indexer/engine use — not a
//!   hand-rolled mirror struct) — confirmed byte-for-byte against a live fetch of the `Account`
//!   template this session: bare-string unit variants (`"U32"`), `{"Other":{"name":"..."}}`,
//!   `{"Option": <Type>}`, `{"Vec": <Type>}` all round-trip through `TemplateDef`'s derived
//!   `serde::Deserialize` exactly as seen on the wire.
//! - `GET /substates/{substate_id}` — used by `read.rs` to resolve a component address to its
//!   owning template (per DISPATCH_BRIEF.md step 3: "resolving component->template if a
//!   component address was given"). Real response shape confirmed live against
//!   `component_86d532...` (the funded `mcp-gateway-account` test account from AGENTS.md):
//!   `{"version":0,"substate":{"Component":{"header":{"template_address":"...", ...},
//!   "body":{...}}},"verified":true}`. Only `substate.Component.header.template_address` is
//!   read; the rest of the substate body (a CBOR-value-tree JSON encoding) is treated as opaque
//!   `serde_json::Value` — decoding it fully is out of scope for template/component
//!   resolution and belongs to a real substate-diff-aware module if ever needed.
//! - Non-2xx real responses observed this session: a malformed address to `/templates/{addr}`
//!   returns HTTP 400 with `{"error":"Invalid URL: ..."}`-shaped plain text; a well-formed but
//!   unknown substate id to `/substates/{id}` returns HTTP 404 with
//!   `{"error":"<id> not found"}`. Both are surfaced as [`IndexerError::HttpStatus`] with the
//!   raw body attached, so a caller (or an MCP tool wrapping this client) can see the real
//!   indexer-reported reason rather than a generic "request failed".

use serde::{Deserialize, Serialize};
use tari_template_abi::TemplateDef;

/// Env var for the indexer base URL. Falls back to [`DEFAULT_INDEXER_URL`] — per
/// DISPATCH_BRIEF.md this one CAN have a real default since it's a public, stable service,
/// unlike the walletd endpoint/key (which must never have a real default per AGENTS.md).
pub const ENV_INDEXER_URL: &str = "TARI_OOTLE_MCP_INDEXER_URL";
/// The real, live, public Tari Ootle indexer this repo's dispatch brief and AGENTS.md both
/// name explicitly.
pub const DEFAULT_INDEXER_URL: &str = "https://ootle-indexer-a.tari.com";

#[derive(Debug, Clone)]
pub struct IndexerConfig {
    pub base_url: String,
}

impl IndexerConfig {
    /// Reads [`ENV_INDEXER_URL`], defaulting to [`DEFAULT_INDEXER_URL`] when unset. Unlike
    /// `WalletdConfig::from_env` / `ServerConfig::from_env`, this cannot fail: the public
    /// indexer's default is a real, safe fallback (no secret, no local-only assumption).
    pub fn from_env() -> Self {
        let base_url =
            std::env::var(ENV_INDEXER_URL).unwrap_or_else(|_| DEFAULT_INDEXER_URL.to_string());
        Self { base_url }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IndexerError {
    #[error("request to {url} failed: {source}")]
    Request {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("{url} returned HTTP {status}: {body}")]
    HttpStatus {
        url: String,
        status: u16,
        body: String,
    },
    #[error("failed to decode response body from {url}: {source}")]
    Decode {
        url: String,
        #[source]
        source: reqwest::Error,
    },
}

/// A single entry of `GET /templates/catalogue`. Field names match the real live response
/// verbatim (confirmed this session) — no renaming.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateCatalogueEntry {
    pub template_address: String,
    pub template_name: String,
    pub author_public_key: String,
    pub binary_hash: String,
    pub at_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateCatalogueResponse {
    pub entries: Vec<TemplateCatalogueEntry>,
}

/// `GET /templates/{address}`'s real response shape. `definition` is the genuine
/// `tari_template_abi::TemplateDef` — see module docs.
#[derive(Debug, Clone, Deserialize)]
pub struct GetTemplateResponse {
    pub name: String,
    pub definition: TemplateDef,
}

/// Thin async HTTP client over the two real indexer routes documented above. Holds no
/// connection state beyond a plain `reqwest::Client` (cheap to construct; no pooling
/// requirements strict enough to justify a shared/cached instance for this v1's call volume).
pub struct IndexerClient {
    config: IndexerConfig,
    http: reqwest::Client,
}

impl IndexerClient {
    pub fn from_env() -> Self {
        Self::with_config(IndexerConfig::from_env())
    }

    pub fn with_config(config: IndexerConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
        }
    }

    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<T, IndexerError> {
        let url = format!("{}{}", self.config.base_url, path);
        let resp = self
            .http
            .get(&url)
            .query(query)
            .send()
            .await
            .map_err(|source| IndexerError::Request {
                url: url.clone(),
                source,
            })?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(IndexerError::HttpStatus {
                url,
                status: status.as_u16(),
                body,
            });
        }
        resp.json::<T>()
            .await
            .map_err(|source| IndexerError::Decode { url, source })
    }

    /// `GET /templates/catalogue?limit=N[&after=<template_address>]`. Cursor-based pagination:
    /// pass the previous page's last entry's `template_address` as `after` to get the next
    /// page, not an offset (confirmed real this session, matching `go-tari-ootle-explorer`'s
    /// `internal/indexerclient` pagination shape).
    pub async fn list_templates_catalogue(
        &self,
        limit: u32,
        after: Option<&str>,
    ) -> Result<TemplateCatalogueResponse, IndexerError> {
        let mut query = vec![("limit", limit.to_string())];
        if let Some(after) = after {
            query.push(("after", after.to_string()));
        }
        self.get_json("/templates/catalogue", &query).await
    }

    /// `GET /templates/{template_address}`. `template_address` must be the bare hex form (no
    /// `template_` prefix) — confirmed this is what the live indexer expects and returns in
    /// `list_templates_catalogue`'s entries.
    pub async fn get_template(
        &self,
        template_address: &str,
    ) -> Result<GetTemplateResponse, IndexerError> {
        self.get_json(&format!("/templates/{template_address}"), &[])
            .await
    }

    /// `GET /substates/{substate_id}`. `substate_id` is the canonical prefixed form (e.g.
    /// `component_<hex>`). Returns the raw JSON body — see module docs on why this is not
    /// further typed for this dispatch's narrow use (component→template resolution only).
    pub async fn get_substate(&self, substate_id: &str) -> Result<serde_json::Value, IndexerError> {
        self.get_json(&format!("/substates/{substate_id}"), &[])
            .await
    }
}

/// Extracts a `Component` substate's owning `template_address` (bare hex, as the indexer's own
/// `/templates/{address}` route expects) from the raw JSON `GET /substates/{id}` returns. `None`
/// if the substate is not a `Component` (e.g. it's a `Resource`/`Vault`/... substate) or the
/// expected shape is not present.
pub fn extract_component_template_address(substate_json: &serde_json::Value) -> Option<String> {
    substate_json
        .get("substate")?
        .get("Component")?
        .get("header")?
        .get("template_address")?
        .as_str()
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_env_defaults_to_the_real_public_indexer() {
        unsafe {
            std::env::remove_var(ENV_INDEXER_URL);
        }
        let config = IndexerConfig::from_env();
        assert_eq!(config.base_url, DEFAULT_INDEXER_URL);
    }

    #[test]
    fn extract_component_template_address_reads_real_live_shape() {
        // Real live shape captured this session (AGENTS.md's `mcp-gateway-account` test
        // account), trimmed to the fields this function reads.
        let json = serde_json::json!({
            "version": 0,
            "substate": {
                "Component": {
                    "header": {
                        "template_address": "0000000000000000000000000000000000000000000000000000000000000000",
                        "owner_rule": {"ByPublicKey": "483f..."},
                    },
                    "body": {}
                }
            },
            "verified": true
        });
        assert_eq!(
            extract_component_template_address(&json),
            Some("0000000000000000000000000000000000000000000000000000000000000000".to_string())
        );
    }

    #[test]
    fn extract_component_template_address_returns_none_for_non_component_substate() {
        let json = serde_json::json!({
            "version": 0,
            "substate": {"Resource": {"header": {}}},
            "verified": true
        });
        assert_eq!(extract_component_template_address(&json), None);
    }

    /// Real integration test against the live public indexer's catalogue route. Not
    /// env-gated-skip (per DISPATCH_BRIEF.md: this service is public and reachable from
    /// anywhere, confirmed this session), so this genuinely exercises the network.
    #[tokio::test]
    async fn live_catalogue_returns_real_entries() {
        let client = IndexerClient::from_env();
        let resp = client
            .list_templates_catalogue(3, None)
            .await
            .expect("live indexer catalogue call failed");
        assert!(
            !resp.entries.is_empty(),
            "expected at least one real catalogue entry"
        );
        // The `Account` template at the all-zero address is a real, permanent built-in entry.
        assert!(
            resp.entries.iter().any(|e| e.template_name == "Account"),
            "expected the real built-in Account template in the live catalogue"
        );
    }

    /// Real integration test against the live public indexer's per-template ABI route, for the
    /// real built-in `Account` template at the all-zero address (per AGENTS.md/DISPATCH_BRIEF.md).
    #[tokio::test]
    async fn live_account_template_abi_parses_into_real_template_def() {
        let client = IndexerClient::from_env();
        let resp = client
            .get_template("0000000000000000000000000000000000000000000000000000000000000000")
            .await
            .expect("live indexer template ABI call failed");
        assert_eq!(resp.name, "Account");
        let functions = resp.definition.functions();
        assert!(
            !functions.is_empty(),
            "expected real functions in the live Account ABI"
        );
        let balance = functions
            .iter()
            .find(|f| f.name == "balance")
            .expect("real Account ABI must have a 'balance' function");
        assert!(
            !balance.is_mut,
            "Account.balance is a real read-only (is_mut=false) function"
        );
        assert_eq!(balance.arguments[0].name, "self");
    }

    /// Real integration test confirming the live indexer's real non-2xx error shape for a
    /// well-formed but nonexistent substate id (confirmed this session: HTTP 404 with a real
    /// `{"error": "... not found"}` body).
    #[tokio::test]
    async fn live_get_substate_not_found_surfaces_real_404() {
        let client = IndexerClient::from_env();
        let err = client
            .get_substate(
                "component_0000000000000000000000000000000000000000000000000000000000000099",
            )
            .await
            .expect_err("expected a real 404 for a well-formed but nonexistent substate id");
        match err {
            IndexerError::HttpStatus { status, body, .. } => {
                assert_eq!(status, 404);
                assert!(body.contains("not found"), "real body: {body}");
            }
            other => panic!("expected HttpStatus, got {other:?}"),
        }
    }
}
