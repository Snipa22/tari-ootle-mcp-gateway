//! `call_ootle_create_function` MCP tool: real, executed (never dry-run) constructor calls
//! against any published Ootle template.
//!
//! DISPATCH_BRIEF.md v2 step 1, finding 2 ("v1 has no tool that can actually create a new
//! component for real"). v1's binary `is_mut` split doesn't cover Ootle's real three-way
//! shape:
//!
//! - pure reads (`is_mut=false`, no `self`, output is NOT `Component<...>`) — `read.rs`.
//! - mutations on an EXISTING component (`is_mut=true`, needs a `component_address`) —
//!   `write.rs`.
//! - constructors (`is_mut=false` per the ABI — there's nothing existing to mutate yet — but
//!   genuinely creates new on-chain state and needs a REAL submit, not a dry run) — THIS
//!   module.
//!
//! ## Confirming the constructor discriminator against real, live ABI data
//!
//! `is_mut=false` alone doesn't distinguish a constructor from an ordinary bare read
//! function (e.g. a hypothetical pure getter with no `self`). Per the dispatch brief, this
//! was confirmed live against the public indexer (`https://ootle-indexer-a.tari.com`,
//! 2026-09-13) for all four real templates named in the brief, not guessed:
//!
//! | Template          | `create` args (excl. self)         | `is_mut` | has `self` | `output` |
//! |--------------------|-------------------------------------|----------|------------|----------|
//! | `Account`           | `NonFungibleAddress`, 3×`Option<_>` | `false`  | no         | `Other{name:"Component<Account>"}` |
//! | `RandomnessBeacon`  | `Vec<RistrettoPublicKeyBytes>`, `U32` | `false`  | no       | `Other{name:"Component<RandomnessBeacon>"}` |
//! | `CoinFlip`          | `ComponentAddress`, `Bucket`        | `false`  | no         | `Other{name:"Component<CoinFlip>"}` |
//! | `Oracle`            | `Vec<RistrettoPublicKeyBytes>`, `U32` | `false`  | no       | `Other{name:"Component<Oracle>"}` |
//!
//! All four real constructors share the exact same real signal: `is_mut=false`, no `self`
//! receiver (a bare function, per `instruction::has_self_receiver`), AND an `output` whose
//! `Type::Other{name}` starts with the literal `"Component<"` prefix. This holds
//! universally across all four templates the brief asked to check, so
//! [`ensure_target_is_constructor`] uses it as the real discriminator, refusing any
//! `is_mut=false` bare function whose output isn't shaped this way (an ordinary read-only
//! associated function, if one exists, would have some other output type and correctly be
//! refused here — it should go through `call_ootle_read_function`'s dry run instead, not a
//! real submit).
//!
//! ## Why no approval gate, but still a real rate limiter
//!
//! Per the dispatch brief's explicit framing: a constructor genuinely doesn't need
//! `write.rs`'s human-approval safety pattern in the same way a mutation on an EXISTING,
//! funded component does — there is no existing balance/state a constructor call can put at
//! risk, only the fee-payer's fee (bounded by `max_fee`, same as `write.rs`). So this tool
//! skips `write.rs`'s single-inflight gate and `approve_ootle_write`-style approval wait
//! entirely.
//!
//! It deliberately does NOT skip rate limiting, though: AGENTS.md's `--unsafe-auto-approve`
//! section establishes the general principle that removing ONE safety control (there: the
//! human gate) must not silently remove every other one ("auto-approve removes the HUMAN
//! gate, not every other safety control") — the same principle is applied here to justify
//! keeping a real rate limiter even though the human-approval gate itself is intentionally
//! absent for the different (documented) reason above. A misbehaving or compromised agent
//! could otherwise spam real fee-spending constructor calls with zero throttling. This uses
//! its own separate [`TransactionRateLimiter`] instance/limit (`create`'s own tier), not
//! `write.rs`'s shared `WRITE_RATE_LIMITER` static, since the two tools' real risk profiles
//! differ and shouldn't silently share one quota.
//!
//! **This reasoning is flagged here explicitly per the dispatch brief's request, for
//! confirmation as the right safety-tier call rather than a silent assumption.**
//!
//! ## PIN-equivalent check
//!
//! Same as `write.rs`: `ensure_wallet_ready` makes a cheap real `accounts.list` call before
//! proceeding, re-checked on every call rather than cached at startup, for the identical
//! reason documented in `write.rs`'s module docs.
//!
//! ## Extracting the real new component address
//!
//! `submit_instruction`'s own response (confirmed reading
//! `clients/wallet_daemon_client/src/types.rs`'s real `TransactionSubmitResponse` this
//! session) is JUST a bare `transaction_id` — no execution result at all. So this tool
//! submits, then calls the real `transactions.wait_result` (`WalletdClientWrapper::
//! wait_transaction_result`, added this dispatch) to block for the real `FinalizeResult`.
//! The real, engine-native path to the new component address (confirmed reading
//! `crates/engine_types/src/{instruction_result,indexed_value}.rs` this session — NOT
//! guessed from the brief's paraphrase) is:
//!
//! `finalize.execution_results[0].indexed.component_addresses()` — `execution_results` is a
//! `Vec<InstructionResult>` (one per instruction in the submitted transaction; this tool
//! only ever submits exactly one `CallFunction` instruction, so index `0` is always our
//! constructor call's own result, not some other instruction's), `InstructionResult.indexed`
//! is a real `IndexedValue` whose public `component_addresses()` method returns every
//! `ComponentAddress` the engine indexed out of that instruction's return value — for a real
//! constructor, that is the newly-created component. On the wire (JSON), this is the exact
//! same data the brief's live-observed
//! `execution_results[0].indexed.indexed.component_addresses` path describes (the engine
//! type's own field is also named `indexed`); this module reads it through the typed Rust
//! API instead of walking raw JSON.

use std::str::FromStr;

use rmcp::{ErrorData, handler::server::wrapper::Parameters, tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use std::sync::LazyLock;
use tari_ootle_walletd_client::{
    ComponentAddressOrName,
    types::{CallInstructionRequest, TransactionWaitResultRequest},
};
use tari_template_abi::FunctionDef;
use tari_template_lib_types::{ComponentAddress, TemplateAddress};
use tokio::sync::Mutex as TokioMutex;

use crate::{
    audit::{AuditEntry, AuditLog, AuditStatus},
    indexer_client::IndexerClient,
    rate_limiter::TransactionRateLimiter,
    tools::{TariOotleMcpHandler, instruction},
    walletd_client::{WalletdClientWrapper, WalletdConfig},
};

const LOG_TARGET: &str = "tari_ootle_mcp_gateway::tools::create";

/// Real discriminating prefix confirmed live against all four templates named in
/// DISPATCH_BRIEF.md's v2 step 1 (`Account`, `RandomnessBeacon`, `CoinFlip`, `Oracle`) — see
/// module docs' table. A constructor's real ABI `output` is always `Other{name:
/// "Component<TemplateName>"}`.
const CONSTRUCTOR_OUTPUT_PREFIX: &str = "Component<";

/// This tool's own rate limit, separate from `write.rs`'s `WRITE_RATE_LIMITER` — see module
/// docs for why the two tools shouldn't silently share one quota. Same numeric value as
/// `write.rs`'s `RATE_LIMIT_PER_MINUTE` purely for consistency (no basis to pick a different
/// number yet); if real usage shows constructors need a different throttle than mutations,
/// change this constant, not `write.rs`'s.
const CREATE_RATE_LIMIT_PER_MINUTE: u32 = 10;

/// Bounds real fees spent if the caller doesn't specify `max_fee`. Same value as
/// `write.rs`'s `DEFAULT_MAX_FEE` (both are real, engine-charges-the-actual-lower-amount
/// submissions, not dry runs) — see that module's doc comment for the rationale.
const DEFAULT_MAX_FEE: u64 = 50_000;

/// How long this tool waits (server-side, via `transactions.wait_result`) for a submitted
/// constructor call to finalize before giving up and reporting "submitted but result
/// unknown" rather than silently hanging forever. Generous relative to AGENTS.md's own
/// observed real fee-paying transaction latency on esmeralda, but bounded so a stalled
/// network doesn't wedge this tool's caller indefinitely.
const WAIT_RESULT_TIMEOUT_SECS: u64 = 60;

static CREATE_RATE_LIMITER: LazyLock<TokioMutex<TransactionRateLimiter>> =
    LazyLock::new(|| TokioMutex::new(TransactionRateLimiter::new(CREATE_RATE_LIMIT_PER_MINUTE)));

#[derive(Debug, thiserror::Error)]
enum CreateToolError {
    #[error("invalid template address '{address}': {reason}")]
    InvalidAddress { address: String, reason: String },
    #[error(
        "call_ootle_create_function only accepts a template address, not a component \
         address ('{address}') - constructors are always bare-template function calls with \
         no existing component to target. Use call_ootle_write_function or \
         call_ootle_read_function if you meant to call a method on an existing component."
    )]
    RefusedComponentAddress { address: String },
    #[error("indexer request failed: {0}")]
    Indexer(#[from] crate::indexer_client::IndexerError),
    #[error("template '{template_address}' has no function named '{function}'")]
    UnknownFunction {
        template_address: String,
        function: String,
    },
    #[error(
        "'{function}' is not recognized as a real constructor: {reason}. \
         call_ootle_create_function only executes functions whose real on-chain ABI is \
         is_mut=false, has no 'self' receiver, and whose output type is \
         'Component<TemplateName>' (confirmed live against Account::create, \
         RandomnessBeacon::create, CoinFlip::create, and Oracle::create - see create.rs's \
         module docs)."
    )]
    NotAConstructor { function: String, reason: String },
    #[error(transparent)]
    ArgEncoding(#[from] instruction::ArgEncodingError),
    #[error(transparent)]
    InstructionShape(#[from] instruction::InstructionShapeError),
    #[error("invalid {0} '{1}': {2}")]
    Config(&'static str, String, String),
    #[error("walletd request failed: {0}")]
    Walletd(#[from] tari_ootle_walletd_client::error::WalletDaemonClientError),
    #[error(
        "walletd is not ready: the configured API key did not authenticate a real call ({0}). \
         Refusing to submit a real constructor call against a wallet that isn't demonstrably \
         unlocked and reachable (this gateway's PIN-equivalent check - see write.rs module \
         docs, reused here)."
    )]
    WalletNotReady(tari_ootle_walletd_client::error::WalletDaemonClientError),
    #[error(
        "constructor call rate limit exceeded ({CREATE_RATE_LIMIT_PER_MINUTE}/min); try \
         again shortly"
    )]
    RateLimited,
    #[error(
        "constructor call submitted as transaction {transaction_id} but was REJECTED by the \
         engine: {reason}. No new component was created; the fee-payer may still have been \
         charged a partial fee (see the real fee_receipt in walletd's own \
         transactions.get_result for that transaction_id)."
    )]
    TransactionRejected {
        transaction_id: String,
        reason: String,
    },
    #[error(
        "constructor call submitted as transaction {0} but did not finalize within \
         {WAIT_RESULT_TIMEOUT_SECS}s - its outcome is UNKNOWN from this call (it may still \
         commit or reject later). Use walletd's own transactions.get_result with this \
         transaction_id to check later; do not assume it failed."
    )]
    WaitResultTimedOut(String),
    #[error(
        "constructor call submitted and accepted as transaction {0}, but the engine's real \
         execution result contained no new component address (see create.rs's module docs \
         for the exact real field this is extracted from) - this should not happen for a \
         function recognized as a real constructor; please report this as a bug"
    )]
    NoComponentAddressInResult(String),
}

impl From<CreateToolError> for ErrorData {
    fn from(err: CreateToolError) -> Self {
        ErrorData::internal_error(err.to_string(), None)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct CallOotleCreateFunctionRequest {
    /// The target template's on-chain address, bare hex or `template_`-prefixed. NEVER a
    /// `component_`-prefixed address - constructors have no existing component to target
    /// (that's the whole point of calling one). See `get_ootle_template_abi`'s per-function
    /// `output` field: a real constructor's output is always `Component<TemplateName>`.
    pub template_address: String,
    /// The constructor function's name exactly as it appears in `get_ootle_template_abi`'s
    /// output (e.g. `"create"` - the real, universal convention observed across every
    /// template checked this session, though this tool does not hardcode that name; it is
    /// verified against the real ABI's shape, not the function's name).
    pub function: String,
    /// Positional arguments in the constructor's real ABI order (constructors never have a
    /// `self` receiver, so every argument is positional - see
    /// `call_ootle_read_function`'s docs for the full `ArgValue`-tagged-JSON tag list this
    /// shares).
    #[serde(default)]
    pub args: Vec<JsonValue>,
    /// The component address or wallet-daemon-known account name that pays this REAL
    /// transaction's fee. REQUIRED - same reasoning as `call_ootle_write_function`'s
    /// `fee_account` (no "use my default account" sentinel exists at the JSON-RPC layer for
    /// a real submit).
    pub fee_account: String,
    /// Maximum fee (µtTARI) this transaction may spend. Defaults to a generous cap if
    /// omitted (see `DEFAULT_MAX_FEE`).
    #[serde(default)]
    pub max_fee: Option<u64>,
}

#[derive(Debug)]
struct CreateOutcome {
    json: String,
}

/// The real constructor discriminator (see module docs' table): `is_mut=false`, no `self`
/// receiver, AND an `Other{name}` output whose name starts with `"Component<"`. Deliberately
/// does NOT just check `is_mut=false` alone - that would also admit an ordinary read-only
/// bare function (a hypothetical pure getter with no `self`), which is NOT a constructor and
/// should go through `call_ootle_read_function`'s dry run, not a real submit.
fn ensure_target_is_constructor(
    function: &str,
    function_def: &FunctionDef,
) -> Result<(), CreateToolError> {
    if function_def.is_mut {
        return Err(CreateToolError::NotAConstructor {
            function: function.to_string(),
            reason: "is_mut=true (a real mutating method) - every real constructor observed \
                      this session is is_mut=false (there's nothing existing to mutate yet)"
                .to_string(),
        });
    }
    if instruction::has_self_receiver(function_def) {
        return Err(CreateToolError::NotAConstructor {
            function: function.to_string(),
            reason: "has a 'self' receiver, i.e. it's a METHOD on an existing component, not \
                      a bare constructor function"
                .to_string(),
        });
    }
    let is_component_output = function_def
        .output
        .other()
        .map(|name| name.starts_with(CONSTRUCTOR_OUTPUT_PREFIX))
        .unwrap_or(false);
    if !is_component_output {
        return Err(CreateToolError::NotAConstructor {
            function: function.to_string(),
            reason: format!(
                "its real ABI output is '{}', not a 'Component<...>' type",
                function_def.output
            ),
        });
    }
    Ok(())
}

/// PIN-equivalent check. See `write.rs`'s `ensure_wallet_ready` doc comment for the full
/// rationale (re-checked on every call rather than cached at startup) — duplicated here
/// (not shared via `instruction.rs`) since that module is deliberately policy-agnostic
/// address/arg/instruction plumbing, not a place for wallet-connectivity checks.
async fn ensure_wallet_ready(client: &mut WalletdClientWrapper) -> Result<(), CreateToolError> {
    client
        .get_accounts_list(0, 1)
        .await
        .map(|_| ())
        .map_err(CreateToolError::WalletNotReady)
}

/// Extracts the real new component address from a finalized constructor call's
/// `FinalizeResult`. See module docs for the exact real field path this reads
/// (`execution_results[0].indexed.component_addresses()`), confirmed against the real
/// engine types, not guessed.
fn extract_new_component_address(
    transaction_id: &str,
    finalize: &tari_engine_types::commit_result::FinalizeResult,
) -> Result<ComponentAddress, CreateToolError> {
    if let Some(reject) = finalize.any_reject() {
        return Err(CreateToolError::TransactionRejected {
            transaction_id: transaction_id.to_string(),
            reason: reject.to_string(),
        });
    }

    let addresses = finalize
        .execution_results
        .first()
        .map(|result| result.indexed.component_addresses())
        .unwrap_or_default();

    addresses
        .first()
        .copied()
        .ok_or_else(|| CreateToolError::NoComponentAddressInResult(transaction_id.to_string()))
}

#[tool_router(router = tool_router_create, vis = "pub")]
impl TariOotleMcpHandler {
    /// Executes a real, on-chain constructor call (`is_mut=false` but output-shaped as
    /// `Component<TemplateName>` - see module docs for the real discriminator), creating a
    /// genuinely new component. Unlike `call_ootle_read_function`, this NEVER dry-runs: a
    /// constructor's whole point is to create real new state.
    #[tool(
        name = "call_ootle_create_function",
        description = "Call a real constructor function on any published Tari Ootle \
                        template (e.g. Account::create, RandomnessBeacon::create), verified \
                        against the real on-chain ABI first: must be is_mut=false, have no \
                        'self' receiver, and have an output type of Component<TemplateName> \
                        (the real signal that distinguishes a genuine constructor from an \
                        ordinary read-only function). Executes as a REAL on-chain \
                        transaction (spends real fees from fee_account, creates real new \
                        state) - never a dry run, unlike call_ootle_read_function. No human \
                        approval gate (a constructor puts no EXISTING balance/state at risk, \
                        only fee_account's fee - see create.rs's module docs for the full \
                        reasoning), but is still rate-limited and audited. Returns the real \
                        new component's address. Use get_ootle_template_abi first to confirm \
                        a function's real signature and output type."
    )]
    pub async fn call_ootle_create_function(
        &self,
        Parameters(req): Parameters<CallOotleCreateFunctionRequest>,
    ) -> Result<String, ErrorData> {
        let details = Some(format!(
            "template_address={} function={} n_args={} fee_account={}",
            req.template_address,
            req.function,
            req.args.len(),
            req.fee_account
        ));
        AuditLog::record(AuditEntry {
            timestamp: std::time::SystemTime::now(),
            tool_name: "call_ootle_create_function".to_string(),
            tier: "create".to_string(),
            status: AuditStatus::Started,
            duration_ms: None,
            client_info: None,
            details: details.clone(),
        })
        .await;

        let started = std::time::Instant::now();
        let result = execute_create_call(req).await;

        let status = match &result {
            Ok(_) => AuditStatus::Success,
            Err(CreateToolError::RateLimited) => AuditStatus::RateLimited,
            Err(_) => AuditStatus::Error,
        };
        if let Err(e) = &result {
            log::warn!(target: LOG_TARGET, "call_ootle_create_function failed: {e}");
        }
        AuditLog::record(AuditEntry {
            timestamp: std::time::SystemTime::now(),
            tool_name: "call_ootle_create_function".to_string(),
            tier: "create".to_string(),
            status,
            duration_ms: Some(started.elapsed().as_millis() as u64),
            client_info: None,
            details: match &result {
                Ok(_) => details,
                Err(e) => Some(e.to_string()),
            },
        })
        .await;

        result.map(|outcome| outcome.json).map_err(ErrorData::from)
    }
}

async fn execute_create_call(
    req: CallOotleCreateFunctionRequest,
) -> Result<CreateOutcome, CreateToolError> {
    if instruction::is_component_address(&req.template_address) {
        return Err(CreateToolError::RefusedComponentAddress {
            address: req.template_address,
        });
    }
    let template_address_hex =
        instruction::strip_template_prefix(&req.template_address).to_string();

    let indexer = IndexerClient::from_env();
    let abi = indexer.get_template(&template_address_hex).await?;
    let function_def = abi.definition.get_function(&req.function).ok_or_else(|| {
        CreateToolError::UnknownFunction {
            template_address: template_address_hex.clone(),
            function: req.function.clone(),
        }
    })?;

    ensure_target_is_constructor(&req.function, function_def)?;

    let instruction_args =
        instruction::encode_instruction_args(&req.function, function_def, &req.args)?;

    let template_address = TemplateAddress::from_hex(&template_address_hex).map_err(|e| {
        CreateToolError::InvalidAddress {
            address: template_address_hex.clone(),
            reason: format!("{e:?}"),
        }
    })?;

    // Constructors are always bare-template function calls: no component address.
    let call_instruction = instruction::build_call_instruction(
        &req.function,
        function_def,
        template_address,
        None,
        instruction_args,
    )?;

    let fee_account = ComponentAddressOrName::from_str(&req.fee_account)
        .unwrap_or_else(|infallible| match infallible {});
    let max_fee = req.max_fee.unwrap_or(DEFAULT_MAX_FEE);

    let walletd_config = WalletdConfig::from_env()
        .map_err(|e| CreateToolError::Config("walletd config", String::new(), e.to_string()))?;
    let mut client = WalletdClientWrapper::connect(&walletd_config)?;

    // PIN-equivalent check BEFORE burning rate-limit quota on a call that can't possibly be
    // submitted anyway.
    ensure_wallet_ready(&mut client).await?;

    // Rate limit check - see module docs for why this is a SEPARATE limiter/quota from
    // write.rs's WRITE_RATE_LIMITER, not a shared one.
    if !CREATE_RATE_LIMITER.lock().await.check_transaction_allowed() {
        return Err(CreateToolError::RateLimited);
    }

    let submit_request = CallInstructionRequest {
        instructions: vec![call_instruction],
        fee_account,
        max_fee,
        inputs: vec![],
        override_inputs: None,
        new_outputs: None,
        proof_ids: vec![],
        min_epoch: None,
        max_epoch: None,
    };

    let submit_resp = client.submit_instruction(submit_request).await?;
    let transaction_id = submit_resp.transaction_id.to_string();

    // submit_instruction's own response is just a bare transaction_id (see module docs) -
    // wait for the real finalized result to extract the new component address.
    let wait_resp = client
        .wait_transaction_result(TransactionWaitResultRequest {
            transaction_id: submit_resp.transaction_id,
            timeout_secs: Some(WAIT_RESULT_TIMEOUT_SECS),
        })
        .await?;

    if wait_resp.timed_out {
        return Err(CreateToolError::WaitResultTimedOut(transaction_id));
    }
    let finalize = wait_resp
        .result
        .ok_or_else(|| CreateToolError::WaitResultTimedOut(transaction_id.clone()))?;

    let new_component_address = extract_new_component_address(&transaction_id, &finalize)?;

    let response = json!({
        "transaction_id": transaction_id,
        "new_component_address": new_component_address.to_string(),
        "final_fee": wait_resp.final_fee,
    });
    let json_body = serde_json::to_string_pretty(&response).map_err(|e| {
        CreateToolError::Config("response serialization", String::new(), e.to_string())
    })?;

    Ok(CreateOutcome { json: json_body })
}

#[cfg(test)]
mod tests {
    use serde_json::json as jsonify;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_partial_json, method, path},
    };

    use super::*;

    fn constructor_function_def(output_name: &str) -> FunctionDef {
        FunctionDef {
            name: "create".to_string(),
            arguments: vec![tari_template_abi::ArgDef {
                name: "threshold".to_string(),
                arg_type: tari_template_abi::Type::U32,
            }],
            output: tari_template_abi::Type::Other {
                name: output_name.to_string(),
            },
            is_mut: false,
            is_migration: false,
        }
    }

    fn mutating_method_def() -> FunctionDef {
        FunctionDef {
            name: "commit".to_string(),
            arguments: vec![tari_template_abi::ArgDef {
                name: "self".to_string(),
                arg_type: tari_template_abi::Type::Other {
                    name: "&mut self".to_string(),
                },
            }],
            output: tari_template_abi::Type::Unit,
            is_mut: true,
            is_migration: false,
        }
    }

    fn read_only_method_def() -> FunctionDef {
        let mut def = mutating_method_def();
        def.is_mut = false;
        def.name = "balance".to_string();
        def
    }

    fn read_only_plain_function_non_component_output() -> FunctionDef {
        FunctionDef {
            name: "current_epoch".to_string(),
            arguments: vec![],
            output: tari_template_abi::Type::U64,
            is_mut: false,
            is_migration: false,
        }
    }

    // =========================================================================
    // The real discriminator, confirmed live against all four templates named in
    // DISPATCH_BRIEF.md's v2 step 1 (see module docs' table): is_mut=false AND no self AND
    // output is Component<...>.
    // =========================================================================

    #[test]
    fn recognizes_real_constructor_shapes_confirmed_live() {
        for template_name in ["Account", "RandomnessBeacon", "CoinFlip", "Oracle"] {
            let output_name = format!("Component<{template_name}>");
            ensure_target_is_constructor("create", &constructor_function_def(&output_name))
                .unwrap_or_else(|e| {
                    panic!("{output_name} must be recognized as a real constructor: {e}")
                });
        }
    }

    #[test]
    fn refuses_mutating_function_even_with_component_output_shape() {
        let mut def = mutating_method_def();
        def.output = tari_template_abi::Type::Other {
            name: "Component<Foo>".to_string(),
        };
        let err = ensure_target_is_constructor("commit", &def).unwrap_err();
        assert!(matches!(err, CreateToolError::NotAConstructor { .. }));
    }

    #[test]
    fn refuses_method_with_self_receiver_even_if_is_mut_false() {
        let mut def = read_only_method_def();
        def.output = tari_template_abi::Type::Other {
            name: "Component<Foo>".to_string(),
        };
        let err = ensure_target_is_constructor("balance", &def).unwrap_err();
        assert!(matches!(err, CreateToolError::NotAConstructor { .. }));
    }

    #[test]
    fn refuses_ordinary_read_only_bare_function_with_non_component_output() {
        // is_mut=false AND no self, but NOT a constructor - a hypothetical pure getter
        // bare-function. Must be refused: only the real Component<...> output signal makes
        // something a constructor.
        let err = ensure_target_is_constructor(
            "current_epoch",
            &read_only_plain_function_non_component_output(),
        )
        .unwrap_err();
        assert!(matches!(err, CreateToolError::NotAConstructor { .. }));
    }

    #[test]
    fn accepts_real_randomness_beacon_create_shape() {
        // Real live shape confirmed this session (see module docs table).
        ensure_target_is_constructor(
            "create",
            &constructor_function_def("Component<RandomnessBeacon>"),
        )
        .expect("RandomnessBeacon::create's real shape must be recognized");
    }

    // =========================================================================
    // Address-kind refusal: this tool only accepts template addresses.
    // =========================================================================

    #[tokio::test]
    async fn refuses_component_prefixed_address() {
        let req = CallOotleCreateFunctionRequest {
            template_address:
                "component_86d532912d9c22b7f4a191d5a00d532c5bc5af3672c651e64094578bef90faf5"
                    .to_string(),
            function: "create".to_string(),
            args: vec![],
            fee_account: "some_account".to_string(),
            max_fee: None,
        };
        let err = execute_create_call(req).await.unwrap_err();
        assert!(matches!(
            err,
            CreateToolError::RefusedComponentAddress { .. }
        ));
    }

    // =========================================================================
    // Rate limiting: same real logic as write.rs's test, exercised against a fresh LOCAL
    // limiter (not the shared CREATE_RATE_LIMITER static) for the same reason write.rs's
    // equivalent test documents.
    // =========================================================================

    #[test]
    fn rate_limit_exceeded_is_refused() {
        let mut limiter = TransactionRateLimiter::new(CREATE_RATE_LIMIT_PER_MINUTE);
        for _ in 0..CREATE_RATE_LIMIT_PER_MINUTE {
            assert!(limiter.check_transaction_allowed());
        }
        assert!(
            !limiter.check_transaction_allowed(),
            "the request beyond the configured per-minute limit must be refused"
        );
    }

    // =========================================================================
    // Real end-to-end (mocked walletd) test: submits via submit_instruction, waits via
    // wait_transaction_result, extracts the real new component address from a real
    // FinalizeResult shape (built via the genuine tari_engine_types constructors, not a
    // hand-rolled JSON mirror).
    // =========================================================================

    fn real_finalize_result_with_new_component(
        new_component: ComponentAddress,
    ) -> tari_engine_types::commit_result::FinalizeResult {
        use tari_engine_types::{
            commit_result::{FinalizeResult, TransactionResult},
            fees::FeeReceipt,
            indexed_value::IndexedValue,
            instruction_result::InstructionResult,
            substate::SubstateDiff,
        };

        // Real encode-then-index round trip (not a hand-rolled mirror): encodes the real
        // `ComponentAddress` the same way the engine's own return value would be CBOR-tagged,
        // then indexes it via the real `IndexedValue::from_type`, exactly like the engine
        // does for a real instruction's return value. This is how a real constructor's
        // returned `Component<T>` handle ends up discoverable via
        // `component_addresses()` on the wire.
        let indexed =
            IndexedValue::from_type(&new_component).expect("encoding a real ComponentAddress");
        assert_eq!(
            indexed.component_addresses(),
            &[new_component],
            "sanity: the real IndexedValue encoding must round-trip the component address"
        );

        let instruction_result = InstructionResult {
            indexed,
            return_type: tari_template_abi::Type::Other {
                name: "Component<RandomnessBeacon>".to_string(),
            },
        };

        let mut finalize = FinalizeResult::new(
            tari_template_lib_types::Hash32::zero(),
            vec![],
            vec![],
            TransactionResult::Accept(SubstateDiff::default()),
            FeeReceipt::builder().build(),
        );
        finalize.execution_results = vec![instruction_result];
        finalize
    }

    #[tokio::test]
    async fn end_to_end_create_call_against_mocked_walletd_extracts_new_component_address() {
        let server = MockServer::start().await;
        let new_component = ComponentAddress::from_hex(&"33".repeat(32)).unwrap();
        let transaction_id_hex = "44".repeat(32);

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(jsonify!({"method": "accounts.list"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(jsonify!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"accounts": [], "total": 0}
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(
                jsonify!({"method": "transactions.submit_instruction"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(jsonify!({
                "jsonrpc": "2.0",
                "id": 2,
                "result": {"transaction_id": transaction_id_hex}
            })))
            .mount(&server)
            .await;

        let finalize = real_finalize_result_with_new_component(new_component);
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(
                jsonify!({"method": "transactions.wait_result"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(jsonify!({
                "jsonrpc": "2.0",
                "id": 3,
                "result": {
                    "transaction_id": transaction_id_hex,
                    "result": finalize,
                    "status": "Accepted",
                    "final_fee": 2308,
                    "timed_out": false,
                }
            })))
            .mount(&server)
            .await;

        unsafe {
            std::env::set_var(crate::walletd_client::ENV_WALLETD_URL, server.uri());
            std::env::set_var(crate::walletd_client::ENV_WALLETD_API_KEY, "tw_test_key");
        }

        let req = CallOotleCreateFunctionRequest {
            template_address: "80e76c2a2fd86de97ec3849e3495cbf8419a900c81389a1459e5368b7a12b1c4"
                .to_string(),
            function: "create".to_string(),
            args: vec![jsonify!({"List": []}), jsonify!({"U64": 1})],
            fee_account:
                "component_86d532912d9c22b7f4a191d5a00d532c5bc5af3672c651e64094578bef90faf5"
                    .to_string(),
            max_fee: Some(50_000),
        };

        // This still resolves the constructor's real ABI via a genuine live indexer call
        // (RandomnessBeacon at the real address named in AGENTS.md/DISPATCH_BRIEF.md) - only
        // walletd itself is mocked (the real one is unreachable from this sandbox, per
        // walletd_client.rs's own confirmed-unreachable finding). This proves the real
        // submit -> wait -> extract chain end to end against a mocked walletd, the same
        // "real ABI + mocked walletd" pattern write.rs's own end-to-end test uses.
        let outcome = execute_create_call(req)
            .await
            .expect("create call should succeed end to end against the mocked walletd");

        assert!(outcome.json.contains("new_component_address"));
        assert!(outcome.json.contains(&new_component.to_string()));

        unsafe {
            std::env::remove_var(crate::walletd_client::ENV_WALLETD_URL);
            std::env::remove_var(crate::walletd_client::ENV_WALLETD_API_KEY);
        }
    }
}
