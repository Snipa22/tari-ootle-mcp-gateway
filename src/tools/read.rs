//! `call_ootle_read_function` MCP tool: dynamic, ABI-verified READ-ONLY calls against any
//! published Ootle template, executed as a real (fee-free) dry run.
//!
//! AGENTS.md's v1 build order step 5. Per DISPATCH_BRIEF.md:
//!
//! - Looks up the real ABI first (via `indexer_client`, resolving component→template through
//!   the indexer's `/substates/{id}` route if a component address was given) to CONFIRM the
//!   target function is genuinely `is_mut=false` before proceeding — refuses with a clear error
//!   if an agent tries to call a mutating function through this read-only tool.
//! - Executes via `walletd_client::submit_transaction_dry_run` (no real fee spent, no state
//!   change).
//! - No approval, no rate limit needed for a genuine dry-run/read call — but still
//!   audit-logged (tier `"read"`), same wrap pattern as every tool.
//!
//! ## Argument encoding: reusing the real `ootle_sdk_core` typed-argument DSL
//!
//! Rather than reinventing a JSON→CBOR-literal mapping (and risking a subtly wrong encoding
//! that silently produces bytes the engine rejects or misinterprets), this tool's `args` field
//! accepts JSON in the exact wire shape of `ootle_sdk_core::types::generic_intent::ArgValue`
//! (confirmed real, already-tested, pinned to the same git rev as every other dependency here —
//! see `crates/ootle_sdk_core/src/types/generic_intent.rs`), and lowers each element via the
//! real `encode_arg` function. This is a genuine reuse of upstream SDK code, not a
//! reimplementation — flagged here (not just in discovery.rs) since it's the second half of the
//! same "don't reinvent the ABI-to-wire mapping" design decision.
//!
//! ## Why a `self` receiver is never in `args`
//!
//! The real live `Account` ABI (confirmed this session) explicitly lists a `self`/`&self`/
//! `&mut self` receiver as `arguments[0]` for every method. This tool strips that entry when
//! validating the caller's `args` length: the receiver is supplied structurally via `address`
//! (a `component_`-prefixed address), never as a positional arg value.
//!
//! ## Shared plumbing (AGENTS.md step 6 refactor)
//!
//! Address resolution (`resolve_target`), arg encoding, and instruction building are shared
//! with `write.rs` via `tools::instruction` (extracted from this module when `write.rs` was
//! built — see that module's docs for why the `is_mut` check itself is deliberately NOT
//! shared).

use ootle_sdk_core::finalized_from_execute_result;
use rmcp::{ErrorData, handler::server::wrapper::Parameters, tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use tari_ootle_transaction::{Epoch, Instruction, Network, TransactionBuilder};
use tari_ootle_walletd_client::{ComponentAddressOrName, types::TransactionSubmitDryRunRequest};
use tari_template_lib_types::{Amount, TemplateAddress};

use crate::{
    audit::{AuditEntry, AuditLog, AuditStatus},
    indexer_client::IndexerClient,
    tools::{
        TariOotleMcpHandler,
        instruction::{self, ArgEncodingError, InstructionShapeError, TargetResolutionError},
    },
    walletd_client::{WalletdClientWrapper, WalletdConfig},
};
use std::str::FromStr;

const LOG_TARGET: &str = "tari_ootle_mcp_gateway::tools::read";

/// Env var for the Ootle network byte a built transaction is stamped with. Falls back to
/// `"esmeralda"` — matches the real, live `tari_ootle_walletd` instance's own configured
/// network per AGENTS.md ("network esmeralda"). Parsed via the real `ootle_network::Network`
/// (re-exported as `tari_ootle_transaction::Network`), not guessed.
pub const ENV_NETWORK: &str = "TARI_OOTLE_MCP_NETWORK";
const DEFAULT_NETWORK: &str = "esmeralda";

/// The `max_fee` locked by this dry run's `pay_fee_from_component` instruction. A dry run spends
/// no real fee and changes no state (confirmed via `tari_ootle_walletd_client`'s own doc
/// comments, read this session — see `walletd_client.rs`'s module docs) — this value only sizes
/// the (unused) lock so the instruction has something to encode; it is never actually charged.
const DRY_RUN_MAX_FEE: u64 = 50_000;

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct CallOotleReadFunctionRequest {
    /// EITHER a `component_`-prefixed component address (for a METHOD call — the owning
    /// template is resolved automatically via the indexer's substate lookup) OR a template
    /// address, bare hex or `template_`-prefixed (for a FUNCTION call with no `self` receiver,
    /// e.g. a constructor like `Account::create`). See `get_ootle_template_abi`'s per-function
    /// `is_method` field to know which form a given `function` expects.
    pub address: String,
    /// The function or method name exactly as it appears in `get_ootle_template_abi`'s output.
    pub function: String,
    /// Positional arguments, EXCLUDING any `self`/`&self`/`&mut self` receiver (the gateway
    /// supplies that from `address` automatically — see module docs). Each element must be a
    /// tagged `ArgValue`-shaped object: `{"Amount": 1000}`, `{"Address": "resource_..."}`,
    /// `{"String": "foo"}`, `{"U64": 5}`, `{"I64": -3}`, `{"Bool": true}`,
    /// `{"NonFungibleId": "uuid_..."}`, `{"Bytes": "<lowercase hex>"}`,
    /// `{"Metadata": {"key": "value"}}`, `{"List": [...]}`, `{"Optional": null}` /
    /// `{"Optional": {...}}`. Use `get_ootle_template_abi`'s per-argument `arg_type` to pick the
    /// right tag: template-specific `Other{name: "ResourceAddress"|"ComponentAddress"|...}`
    /// types use `Address`; `Other{name: "Amount"}` uses `Amount`; primitives map to their
    /// same-named tag (`U32`/`I8`/etc. all encode fine via the `U64`/`I64` tags — the engine
    /// decodes by CBOR minimal-encoding, not by tag width).
    ///
    /// ## Composite/multi-field struct arguments (e.g. `SchnorrSignatureBytes`)
    ///
    /// A template-specific `Other{name}` type that is a genuine multi-field struct (NOT a
    /// single-field/transparent byte-array newtype like `RistrettoPublicKeyBytes` or
    /// `ResourceAddress`, which use `Address`/`Bytes` directly) has no dedicated `ArgValue`
    /// tag of its own — encode it as `{"List": [<field 0>, <field 1>, ...]}`, one element per
    /// struct field IN DECLARATION ORDER. This works because every such struct's real
    /// `minicbor::Encode` derive uses the (default, unmarked) array encoding: it serializes to
    /// a definite-length CBOR array of its fields in order, which is byte-identical to what
    /// `ArgValue::List` already produces for its (also CBOR-array-encoded) elements — no
    /// dedicated "struct" `ArgValue` variant is needed, this is not a special case of `List`,
    /// it's the same encoding.
    ///
    /// Worked example: `SchnorrSignatureBytes { public_nonce: RistrettoPublicKeyBytes,
    /// signature: Scalar32Bytes }` (both fields are 32-byte transparent byte-array newtypes,
    /// so each lowers to a CBOR byte string via `Bytes`) is
    /// `{"List": [{"Bytes": "<32-byte-hex public_nonce>"}, {"Bytes": "<32-byte-hex
    /// signature>"}]}` — a 2-element array of byte strings, NOT a flat 64-byte string and NOT
    /// a 64-element array of individual byte scalars. This generalizes to any composite
    /// struct argument: nest each field's own `ArgValue` encoding (which may itself be a
    /// `List` for a nested composite field) inside the outer `List`, in the struct's real
    /// field declaration order. See `tools::instruction`'s
    /// `schnorr_signature_bytes_list_encodes_byte_identically_to_the_real_minicbor_struct`
    /// test for a byte-identical-CBOR proof against the real, pinned-commit
    /// `tari_template_lib_types::crypto::SchnorrSignatureBytes` type.
    #[serde(default)]
    pub args: Vec<JsonValue>,
    /// Component address or account name whose `pay_fee` method funds this dry run's (unused)
    /// fee lock. Defaults to walletd's configured default account.
    #[serde(default)]
    pub fee_account: Option<String>,
}

#[derive(Debug, thiserror::Error)]
enum ReadToolError {
    #[error("invalid address '{address}': {reason}")]
    InvalidAddress { address: String, reason: String },
    #[error(transparent)]
    TargetResolution(#[from] TargetResolutionError),
    #[error("indexer request failed: {0}")]
    Indexer(#[from] crate::indexer_client::IndexerError),
    #[error("template '{template_address}' has no function named '{function}'")]
    UnknownFunction {
        template_address: String,
        function: String,
    },
    #[error(
        "refusing to call '{function}': is_mut=true (a real mutating write). \
         call_ootle_read_function only executes is_mut=false reads; use \
         call_ootle_write_function (AGENTS.md step 6) for writes."
    )]
    RefusedMutatingFunction { function: String },
    #[error(transparent)]
    ArgEncoding(#[from] ArgEncodingError),
    #[error(transparent)]
    InstructionShape(#[from] InstructionShapeError),
    #[error("invalid {0} '{1}': {2}")]
    Config(&'static str, String, String),
    #[error("walletd request failed: {0}")]
    Walletd(#[from] tari_ootle_walletd_client::error::WalletDaemonClientError),
    #[error("resolved fee account '{0}' has no owner key on record")]
    NoOwnerKey(String),
}

impl From<ReadToolError> for ErrorData {
    fn from(err: ReadToolError) -> Self {
        ErrorData::internal_error(err.to_string(), None)
    }
}

fn resolve_network() -> Result<Network, ReadToolError> {
    let raw = std::env::var(ENV_NETWORK).unwrap_or_else(|_| DEFAULT_NETWORK.to_string());
    Network::from_str(&raw).map_err(|e| ReadToolError::Config(ENV_NETWORK, raw, e.to_string()))
}

/// Validates `function_def` is a genuine `is_mut=false` read, then delegates to the shared
/// `instruction::build_call_instruction` (see `tools::instruction` module docs for why the
/// `is_mut` check itself is NOT part of the shared helper).
fn build_instruction(
    function: &str,
    function_def: &tari_template_abi::FunctionDef,
    template_address: TemplateAddress,
    component_address: Option<tari_template_lib_types::ComponentAddress>,
    instruction_args: Vec<tari_ootle_transaction::args::InstructionArg>,
) -> Result<Instruction, ReadToolError> {
    if function_def.is_mut {
        return Err(ReadToolError::RefusedMutatingFunction {
            function: function.to_string(),
        });
    }
    Ok(instruction::build_call_instruction(
        function,
        function_def,
        template_address,
        component_address,
        instruction_args,
    )?)
}

#[tool_router(router = tool_router_read, vis = "pub")]
impl TariOotleMcpHandler {
    /// Executes a real (fee-free) dry run of a `is_mut=false` template function/method,
    /// refusing anything the ABI reports as mutating.
    #[tool(
        name = "call_ootle_read_function",
        description = "Call a read-only (is_mut=false) function/method on any published Tari \
                        Ootle template, verified against the real on-chain ABI first (refuses \
                        is_mut=true functions). Executes as a real fee-free dry run via the \
                        configured tari_ootle_walletd instance - no state change, no approval \
                        needed. Use get_ootle_template_abi first to see available functions, \
                        their argument types, and whether each is a method (needs a \
                        component_<address>) or a bare-template function."
    )]
    pub async fn call_ootle_read_function(
        &self,
        Parameters(req): Parameters<CallOotleReadFunctionRequest>,
    ) -> Result<String, ErrorData> {
        let details = Some(format!(
            "address={} function={} n_args={}",
            req.address,
            req.function,
            req.args.len()
        ));
        AuditLog::record(AuditEntry {
            timestamp: std::time::SystemTime::now(),
            tool_name: "call_ootle_read_function".to_string(),
            tier: "read".to_string(),
            status: AuditStatus::Started,
            duration_ms: None,
            client_info: None,
            details: details.clone(),
        })
        .await;

        let started = std::time::Instant::now();
        let result = execute_read_call(req).await;

        match &result {
            Ok(_) => {
                AuditLog::record(AuditEntry {
                    timestamp: std::time::SystemTime::now(),
                    tool_name: "call_ootle_read_function".to_string(),
                    tier: "read".to_string(),
                    status: AuditStatus::Success,
                    duration_ms: Some(started.elapsed().as_millis() as u64),
                    client_info: None,
                    details,
                })
                .await;
            }
            Err(e) => {
                log::warn!(target: LOG_TARGET, "call_ootle_read_function failed: {e}");
                AuditLog::record(AuditEntry {
                    timestamp: std::time::SystemTime::now(),
                    tool_name: "call_ootle_read_function".to_string(),
                    tier: "read".to_string(),
                    status: AuditStatus::Error,
                    duration_ms: Some(started.elapsed().as_millis() as u64),
                    client_info: None,
                    details: Some(e.to_string()),
                })
                .await;
            }
        }

        result.map_err(ErrorData::from)
    }
}

async fn execute_read_call(req: CallOotleReadFunctionRequest) -> Result<String, ReadToolError> {
    let indexer = IndexerClient::from_env();
    let (template_address_hex, component_address) =
        instruction::resolve_target(&indexer, &req.address).await?;

    let abi = indexer.get_template(&template_address_hex).await?;
    let function_def = abi.definition.get_function(&req.function).ok_or_else(|| {
        ReadToolError::UnknownFunction {
            template_address: template_address_hex.clone(),
            function: req.function.clone(),
        }
    })?;

    let instruction_args =
        instruction::encode_instruction_args(&req.function, function_def, &req.args)?;

    let template_address = TemplateAddress::from_hex(&template_address_hex).map_err(|e| {
        ReadToolError::InvalidAddress {
            address: template_address_hex.clone(),
            reason: format!("{e:?}"),
        }
    })?;

    let instruction = build_instruction(
        &req.function,
        function_def,
        template_address,
        component_address,
        instruction_args,
    )?;

    let network = resolve_network()?;

    let walletd_config = WalletdConfig::from_env()
        .map_err(|e| ReadToolError::Config("walletd config", String::new(), e.to_string()))?;
    let mut client = WalletdClientWrapper::connect(&walletd_config)?;

    let account = match &req.fee_account {
        Some(s) => {
            let name_or_address = ComponentAddressOrName::from_str(s)
                .unwrap_or_else(|infallible| match infallible {});
            client.get_account(name_or_address).await?
        }
        None => client.get_default_account().await?,
    };
    let fee_component_address = *account.account.component_address();
    let seal_signer = account
        .account
        .owner_key_id()
        .ok_or_else(|| ReadToolError::NoOwnerKey(fee_component_address.to_string()))?;

    let unsigned = TransactionBuilder::new(network.as_byte(), Epoch::max())
        .with_auto_fill_inputs()
        .pay_fee_from_component(fee_component_address, Amount::from(DRY_RUN_MAX_FEE))
        .add_instruction(instruction)
        .build_unsigned();

    let dry_run_request = TransactionSubmitDryRunRequest {
        transaction: unsigned,
        seal_signer,
        other_signers: vec![],
        signatures: vec![],
        detect_inputs: true,
        detect_inputs_use_unversioned: true,
        lock_ids: vec![],
    };

    let resp = client.submit_transaction_dry_run(dry_run_request).await?;

    let mut outcome = finalized_from_execute_result(&resp.result);
    outcome.estimated_fee = Some(resp.required_fees);

    let response = json!({
        "transaction_id": resp.transaction_id,
        "required_fees": resp.required_fees,
        "outcome": outcome,
        "execution_results": resp.result.finalize.execution_results,
    });

    serde_json::to_string_pretty(&response)
        .map_err(|e| ReadToolError::Config("response serialization", String::new(), e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_resolves_to_real_esmeralda_byte_by_default() {
        unsafe {
            std::env::remove_var(ENV_NETWORK);
        }
        let network = resolve_network().unwrap();
        assert_eq!(network.as_byte(), 0x26, "esmeralda's real wire byte");
    }

    /// `build_instruction` (this module's thin `is_mut`-checking wrapper around the shared
    /// `instruction::build_call_instruction`) must refuse a mutating function — the shape
    /// checks themselves (`ExpectedComponentAddress`/`ExpectedTemplateAddress`) are covered by
    /// `tools::instruction`'s own tests now that this logic is shared with `write.rs`.
    #[test]
    fn build_instruction_refuses_mutating_function() {
        let function_def = tari_template_abi::FunctionDef {
            name: "withdraw".to_string(),
            arguments: vec![],
            output: tari_template_abi::Type::Unit,
            is_mut: true,
            is_migration: false,
        };
        let err = build_instruction(
            "withdraw",
            &function_def,
            TemplateAddress::from_hex(&"00".repeat(32)).unwrap(),
            None,
            vec![],
        )
        .unwrap_err();
        assert!(matches!(err, ReadToolError::RefusedMutatingFunction { .. }));
    }

    /// End-to-end (still offline) proof that `build_instruction` composes the `is_mut=false`
    /// check with the shared `instruction::build_call_instruction` correctly for a real
    /// read-only method shape.
    #[test]
    fn build_instruction_builds_real_call_method_for_a_read_only_method() {
        let function_def = tari_template_abi::FunctionDef {
            name: "balance".to_string(),
            arguments: vec![
                tari_template_abi::ArgDef {
                    name: "self".to_string(),
                    arg_type: tari_template_abi::Type::Other {
                        name: "&self".to_string(),
                    },
                },
                tari_template_abi::ArgDef {
                    name: "resource".to_string(),
                    arg_type: tari_template_abi::Type::Other {
                        name: "ResourceAddress".to_string(),
                    },
                },
            ],
            output: tari_template_abi::Type::Other {
                name: "Amount".to_string(),
            },
            is_mut: false,
            is_migration: false,
        };
        let component =
            tari_template_lib_types::ComponentAddress::from_hex(&"11".repeat(32)).unwrap();
        let arg = ootle_sdk_core::encode_arg(&ootle_sdk_core::ArgValue::Address(format!(
            "resource_{}",
            "22".repeat(32)
        )))
        .unwrap();
        let instr = build_instruction(
            "balance",
            &function_def,
            TemplateAddress::from_hex(&"00".repeat(32)).unwrap(),
            Some(component),
            vec![arg],
        )
        .unwrap();
        match instr {
            Instruction::CallMethod { call, method, args } => {
                assert_eq!(
                    call,
                    tari_ootle_transaction::ComponentReference::Address(component)
                );
                assert_eq!(method.to_string(), "balance");
                assert_eq!(args.len(), 1);
            }
            other => panic!("expected CallMethod, got {other:?}"),
        }
    }
}
