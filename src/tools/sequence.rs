//! `call_ootle_write_sequence` MCP tool: real, multi-INSTRUCTION (not multi-transaction)
//! on-chain transactions, so an agent can express workspace-chained calls like
//! "withdraw a bucket from an account, then hand that bucket to another component's
//! mutating call" as ONE tool call / ONE real transaction.
//!
//! DISPATCH_BRIEF.md v2 step 3. Real gap this closes (confirmed live this session against the
//! public indexer, 2026-09-13): every existing write-shaped tool in this gateway
//! (`call_ootle_read_function`, `call_ootle_write_function`, `call_ootle_create_function`)
//! builds and submits EXACTLY ONE `CallMethod`/`CallFunction` instruction. A real `Bucket`
//! argument (e.g. `CoinFlip::create`'s `house_bucket`, `CoinFlip::fund_house`'s `bucket`,
//! `CoinFlip::place_bet`'s `stake`) cannot be supplied any other way in Ootle's real
//! transaction model: the only way to produce a `Bucket` value is a prior instruction's return
//! value (typically `Account::withdraw(resource, amount) -> Bucket`, confirmed live against
//! the real `Account` template ABI at `template_0000...0000`), placed on the runtime's
//! workspace via `Instruction::PutLastInstructionOutputOnWorkspace`, then referenced by a
//! later instruction's argument via `InstructionArg::Workspace`.
//!
//! ## The real JSON shape landed on
//!
//! ```json
//! {
//!   "steps": [
//!     {
//!       "kind": "withdraw_to_workspace",
//!       "account": "component_86d532...",
//!       "resource_address": "resource_0000...0000",
//!       "amount": 1000000,
//!       "workspace_key": "house_bucket"
//!     },
//!     {
//!       "kind": "call",
//!       "address": "80e76c2a...template hex...",
//!       "function": "create",
//!       "args": [
//!         {"Address": "component_bb6a8634...beacon..."},
//!         {"Workspace": "house_bucket"}
//!       ]
//!     }
//!   ],
//!   "fee_account": "component_86d532...",
//!   "max_fee": 50000
//! }
//! ```
//!
//! An internally-tagged enum (`kind` discriminant) was chosen over the dispatch brief's
//! sketch (a single struct with a pile of `Option<_>` fields, one discriminant field) because
//! it makes each step's real required fields non-optional in the generated JSON Schema — an
//! MCP client sees "a `withdraw_to_workspace` step MUST have `account`/`resource_address`/
//! `amount`/`workspace_key`" rather than "every field is optional, go read the docs to learn
//! which combination is legal for which `kind`". `schemars`' `oneOf` rendering of a
//! `#[serde(tag = "kind")]` enum expresses that directly.
//!
//! `WithdrawToWorkspace::account` is a REQUIRED, explicit field — NOT defaulted to
//! `fee_account` — per the dispatch brief's explicit instruction to confirm this rather than
//! assume it: nothing in the real `Account`/`CoinFlip` ABIs surveyed this session requires the
//! withdrawn-from account to be the fee-payer (they are logically separate real-world roles —
//! "who withdraws the stake" vs. "who pays the transaction fee" — even though today's own live
//! test happens to use the same funded `mcp-gateway-account` for both), so silently defaulting
//! one to the other would be a real, undocumented behavioural assumption baked into the tool.
//!
//! `Call::args` reuses the exact same `ArgValue`-tagged-JSON shape every other tool in this
//! gateway uses (see `read.rs`'s docs for the full tag list), with ONE addition already
//! present in the real, upstream `ArgValue` enum: `{"Workspace": "<key>"}`, which this tool
//! resolves to the real numeric `InstructionArg::Workspace(WorkspaceOffsetId)` produced by an
//! EARLIER `withdraw_to_workspace` step in the same sequence — see [`encode_call_args`] and the
//! "ordering" section below. `instruction::encode_instruction_args`/`ootle_sdk_core::encode_arg`
//! are deliberately NOT reused unmodified for this: `encode_arg` itself refuses to encode
//! `ArgValue::Workspace` standalone (confirmed reading
//! `crates/ootle_sdk_core/src/types/generic_intent.rs`'s own doc comment: "its numeric id is
//! assigned during builder composition ... not here") — exactly the resolution this module
//! performs. Every OTHER `ArgValue` tag still goes through the real `encode_arg` unmodified.
//!
//! ## Workspace-key ordering: a real, checkable constraint enforced by construction
//!
//! A `{"Workspace": "<key>"}` arg reference must resolve to a `workspace_key` bound by a
//! STRICTLY EARLIER `withdraw_to_workspace` step in the same sequence — never the same step,
//! a later one, or an undefined one. This module enforces that by construction rather than a
//! separate validation pass: `execute_write_sequence` walks `steps` in order, maintaining a
//! `workspace_ids: HashMap<String, WorkspaceId>` that only gains an entry AFTER a
//! `withdraw_to_workspace` step has been fully processed. A `call` step's arg resolution looks
//! up its `Workspace` references in THAT map at the time it is processed — a forward or
//! self-reference is therefore, structurally, always a lookup miss (the key genuinely is not
//! in the map yet), surfaced as [`SequenceToolError::UnknownWorkspaceKey`] with a clear
//! "defined by an earlier step, or not at all" message rather than a cryptic engine-side
//! failure at submit time. A duplicate `workspace_key` across two `withdraw_to_workspace`
//! steps is rejected explicitly too ([`SequenceToolError::DuplicateWorkspaceKey`]) rather than
//! silently letting the second shadow the first in the map.
//!
//! ## Safety tier: reuses `write.rs`'s EXACT gate, limiter, and `approve_ootle_write` — no
//! second parallel safety state machine
//!
//! Per the dispatch brief: "route it through the SAME full safety state machine as
//! `call_ootle_write_function` ... consider whether `approve_ootle_write` should be
//! renamed/generalized ... or whether a sequence needs its own distinct approval tool".
//!
//! **Decision: reuse `approve_ootle_write` completely unchanged, with no rename.** This
//! module calls `write::WRITE_DIALOG_GATE`, `write::WRITE_RATE_LIMITER`, `write::await_approval`,
//! and `write::ensure_wallet_ready` DIRECTLY — the exact same statics/functions
//! `call_ootle_write_function` uses, not copies. The approval mechanism (a single opaque
//! `request_id`, a single in-flight oneshot channel, resolved by `approve_ootle_write`) has no
//! knowledge of, or interest in, what KIND of write is pending — a single-instruction write or
//! a multi-instruction sequence look identical to it: "some real on-chain mutation is waiting
//! for a human". Giving each write-shaped tool its OWN single-inflight gate would defeat the
//! entire point of a single-inflight semaphore (AGENTS.md's "only one write may be pending
//! approval at a time" guarantee) — a human operator could then be asked to approve a regular
//! write AND a sequence simultaneously, exactly the concurrent-approval-request problem the
//! single-inflight design exists to prevent. So: one shared gate, one shared rate-limiter
//! quota, one shared approval tool, for every write-tier tool in this gateway — a sequence is
//! not a lesser (or greater) risk category than a single write, it draws from the identical
//! pool. `--unsafe-auto-approve` is honoured identically (skips the approval wait, still rate
//! limited, distinctly audited as `AuditStatus::AutoApproved`) for the same reason.
//!
//! This module does NOT itself decide whether any given sequence is "risky enough" to warrant
//! the gate based on each step's own `is_mut` — every sequence unconditionally goes through
//! the full gate regardless of whether any individual `call` step's ABI happens to be
//! `is_mut=true`. A sequence whose only `call` step is a real (fee-spending, state-creating)
//! constructor like `CoinFlip::create` is `is_mut=false` per its own ABI, but is obviously not
//! risk-free (real fees, real new on-chain state, and it typically CONSUMES a bucket produced
//! by a real mutating `withdraw`) — trying to compute "is this sequence risky" from the union
//! of its steps' individual `is_mut` flags would be exactly the kind of fragile, easy-to-get-
//! wrong heuristic AGENTS.md's "don't weaken the safety pattern for the default mode" warns
//! against. Being unconditionally conservative is simpler and strictly safer.
//!
//! ## Result extraction: mirrors `create.rs`'s `wait_transaction_result` pattern
//!
//! `submit_instruction`'s own response is just a bare `transaction_id` (see `write.rs`/
//! `create.rs`'s module docs). Since a sequence's whole point is very often to create a new
//! component (the CoinFlip live-test scenario below), this tool waits for the real finalized
//! result via `transactions.wait_result` (same `WAIT_RESULT_TIMEOUT_SECS` value and the same
//! reasoning as `create.rs`) and reports every new component address found across ALL of the
//! sequence's instructions' `execution_results` (a sequence can, in principle, create more
//! than one component; `create.rs`'s single-instruction tool only ever needs the first result's
//! addresses, but this tool's whole reason to exist is multi-instruction transactions, so it
//! does not assume there is only one).

use std::{collections::HashMap, str::FromStr, sync::Arc, time::Duration};

use rmcp::{ErrorData, handler::server::wrapper::Parameters, tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use tari_ootle_transaction::{
    Instruction,
    args::{InstructionArg, WorkspaceId, WorkspaceOffsetId},
};
use tari_ootle_walletd_client::{
    ComponentAddressOrName,
    types::{CallInstructionRequest, TransactionWaitResultRequest},
};
use tari_template_lib_types::TemplateAddress;
use uuid::Uuid;

use crate::{
    audit::{AuditEntry, AuditLog, AuditStatus},
    indexer_client::IndexerClient,
    server::ServerConfig,
    tools::{
        TariOotleMcpHandler,
        instruction::{self, ArgEncodingError, InstructionShapeError, TargetResolutionError},
        write::{self, WriteToolError},
    },
    walletd_client::{WalletdClientWrapper, WalletdConfig},
};

const LOG_TARGET: &str = "tari_ootle_mcp_gateway::tools::sequence";

/// Same reasoning/value as `create.rs`'s `WAIT_RESULT_TIMEOUT_SECS` — see that module's docs.
const WAIT_RESULT_TIMEOUT_SECS: u64 = 60;

/// Same reasoning/value as `write.rs`'s `DEFAULT_MAX_FEE` — a real, engine-charges-the-actual-
/// lower-amount submission, not a dry run.
const DEFAULT_MAX_FEE: u64 = 50_000;

/// A single step in a `call_ootle_write_sequence` call. See module docs for the real JSON
/// shape and why an internally-tagged enum (rather than the dispatch brief's flat
/// all-fields-optional sketch) was chosen.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SequenceStep {
    /// Withdraw `amount` of `resource_address` from `account` into a new bucket, then place
    /// that bucket on the transaction's runtime workspace under `workspace_key` so a LATER
    /// step's `call.args` can reference it via `{"Workspace": "<workspace_key>"}`. Maps to a
    /// real `CallMethod(account, "withdraw", [resource_address, amount])` instruction
    /// immediately followed by a real `PutLastInstructionOutputOnWorkspace` instruction.
    ///
    /// Verified against `account`'s real on-chain ABI first, same discipline as every other
    /// tool in this gateway: `account` must expose a method literally named `withdraw` taking
    /// exactly two non-`self` arguments (a resource address, then an amount) — the real,
    /// confirmed-live `Account::withdraw` shape, though this is not hardcoded to the `Account`
    /// template specifically (any component exposing that same real method shape works).
    WithdrawToWorkspace {
        /// The component to withdraw FROM. REQUIRED and explicit — deliberately NOT defaulted
        /// to `fee_account` (see module docs for why: they are separate real-world roles, not
        /// guaranteed to be the same account for every real template).
        account: String,
        /// The resource to withdraw, as it appears in `get_ootle_template_abi`'s `Address`-
        /// tagged argument convention (e.g. `resource_0000...0000` for the network's native
        /// token).
        resource_address: String,
        /// The amount to withdraw, in the resource's base unit (µtTARI for the native token).
        amount: u64,
        /// The label this bucket is stored under on the transaction's runtime workspace,
        /// referenced by a LATER step's `call.args` as `{"Workspace": "<this value>"}`. Must
        /// be unique across every `withdraw_to_workspace` step in the same sequence.
        workspace_key: String,
    },
    /// Call a function or method — the same `address`/`function`/`args` shape as
    /// `call_ootle_write_function`, except any element of `args` may ALSO be
    /// `{"Workspace": "<key>"}`, referencing an EARLIER `withdraw_to_workspace` step's
    /// `workspace_key` instead of a literal value. Verified against the real on-chain ABI
    /// first, same as every other tool.
    Call {
        /// EITHER a `component_`-prefixed component address (METHOD call) OR a template
        /// address, bare hex or `template_`-prefixed (FUNCTION call, e.g. a real constructor
        /// like `CoinFlip::create`). Same shape as `call_ootle_write_function`'s `address`.
        address: String,
        /// The function or method name exactly as it appears in `get_ootle_template_abi`.
        function: String,
        /// Positional arguments, EXCLUDING any `self` receiver. Each element is either a
        /// normal `ArgValue`-tagged JSON value (same tags as `call_ootle_read_function`'s
        /// `args`) or `{"Workspace": "<key>"}` referencing an earlier `withdraw_to_workspace`
        /// step's `workspace_key`.
        #[serde(default)]
        args: Vec<JsonValue>,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct CallOotleWriteSequenceRequest {
    /// The ordered list of steps. Executed as instructions in EXACTLY this order within ONE
    /// real transaction (never multiple transactions) — a `withdraw_to_workspace` step's
    /// `workspace_key` only becomes referenceable by `call` steps that appear AFTER it in
    /// this list.
    pub steps: Vec<SequenceStep>,
    /// The component address or wallet-daemon-known account name that pays this REAL
    /// transaction's fee. REQUIRED — same reasoning as `call_ootle_write_function`'s
    /// `fee_account`.
    pub fee_account: String,
    /// Maximum fee (µtTARI) this transaction may spend. Defaults to a generous cap if
    /// omitted (see `DEFAULT_MAX_FEE`).
    #[serde(default)]
    pub max_fee: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
enum SequenceToolError {
    #[error("call_ootle_write_sequence requires at least one step")]
    EmptySequence,
    #[error(
        "call_ootle_write_sequence requires at least one 'call' step - a sequence of only \
         withdraw_to_workspace steps would leave a real bucket undeposited, which the engine \
         rejects"
    )]
    NoCallStep,
    #[error(
        "step {step_index} (withdraw_to_workspace): duplicate workspace_key '{key}' - every \
         workspace_key in a single sequence must be unique"
    )]
    DuplicateWorkspaceKey { step_index: usize, key: String },
    #[error(
        "step {step_index} (withdraw_to_workspace): account '{account}' must be a \
         component_-prefixed address, not a bare template address"
    )]
    WithdrawAccountMustBeComponent { step_index: usize, account: String },
    #[error("step {step_index} ({kind}): invalid address '{address}': {reason}")]
    InvalidAddress {
        step_index: usize,
        kind: &'static str,
        address: String,
        reason: String,
    },
    #[error("step {step_index} ({kind}): {source}")]
    TargetResolution {
        step_index: usize,
        kind: &'static str,
        #[source]
        source: TargetResolutionError,
    },
    #[error("step {step_index} ({kind}): indexer request failed: {source}")]
    Indexer {
        step_index: usize,
        kind: &'static str,
        #[source]
        source: crate::indexer_client::IndexerError,
    },
    #[error(
        "step {step_index} ({kind}): template '{template_address}' has no function named \
         '{function}'"
    )]
    UnknownFunction {
        step_index: usize,
        kind: &'static str,
        template_address: String,
        function: String,
    },
    #[error(
        "step {step_index} (withdraw_to_workspace): account '{account}' has no real 'withdraw' \
         function on its ABI, or that function's real shape isn't (self, resource_address, \
         amount) -> Bucket: {reason}"
    )]
    NotAWithdrawFunction {
        step_index: usize,
        account: String,
        reason: String,
    },
    #[error(
        "step {step_index} (call): arg {arg_index} references workspace key '{key}', but no \
         earlier withdraw_to_workspace step in this sequence defined it - workspace keys can \
         only be referenced by steps that come strictly AFTER the withdraw_to_workspace step \
         that defines them, never the same step, an earlier one, or an undefined one"
    )]
    UnknownWorkspaceKey {
        step_index: usize,
        arg_index: usize,
        key: String,
    },
    #[error("step {step_index} ({kind}): arg {arg_index}: invalid ArgValue: {source}")]
    InvalidArgValue {
        step_index: usize,
        kind: &'static str,
        arg_index: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error(transparent)]
    ArgEncoding(#[from] ArgEncodingError),
    #[error("step {step_index} ({kind}): {source}")]
    InstructionShape {
        step_index: usize,
        kind: &'static str,
        #[source]
        source: InstructionShapeError,
    },
    #[error("invalid {0} '{1}': {2}")]
    Config(&'static str, String, String),
    #[error("walletd request failed: {0}")]
    Walletd(#[from] tari_ootle_walletd_client::error::WalletDaemonClientError),
    #[error(
        "sequence submitted as transaction {transaction_id} but was REJECTED by the engine: \
         {reason}. No new state was created; the fee-payer may still have been charged a \
         partial fee."
    )]
    TransactionRejected {
        transaction_id: String,
        reason: String,
    },
    #[error(
        "sequence submitted as transaction {0} but did not finalize within \
         {WAIT_RESULT_TIMEOUT_SECS}s - its outcome is UNKNOWN from this call. Use walletd's own \
         transactions.get_result with this transaction_id to check later; do not assume it \
         failed."
    )]
    WaitResultTimedOut(String),
    // Variants below are reused DIRECTLY from write.rs - see module docs for why this tool
    // shares the exact same gate/limiter/approval mechanism rather than duplicating it.
    #[error(transparent)]
    Write(#[from] WriteToolError),
}

impl From<SequenceToolError> for ErrorData {
    fn from(err: SequenceToolError) -> Self {
        ErrorData::internal_error(err.to_string(), None)
    }
}

#[derive(Debug)]
struct SequenceOutcome {
    auto_approved: bool,
    json: String,
}

/// The real discriminator for a genuine `withdraw`-shaped function: has a `self` receiver
/// (it's a method, not a bare function), and exactly 2 non-`self` arguments (resource, then
/// amount) - the real, confirmed-live `Account::withdraw(self, resource: ResourceAddress,
/// amount: Amount) -> Bucket` shape. Deliberately does not check `is_mut` - a real withdraw is
/// always `is_mut=true` (confirmed live), but this discriminator is about SHAPE (can this
/// function plausibly be called as `withdraw(resource, amount)`), not policy; a withdraw
/// function that happened to be `is_mut=false` would still be shape-compatible and there is no
/// safety reason to refuse it here (the overall sequence is gated regardless - see module
/// docs).
fn ensure_is_withdraw_shaped(function_def: &tari_template_abi::FunctionDef) -> Result<(), String> {
    if !instruction::has_self_receiver(function_def) {
        return Err("has no 'self' receiver - not a method".to_string());
    }
    let expected = instruction::expected_arg_count(function_def);
    if expected != 2 {
        return Err(format!(
            "expects {expected} non-self argument(s), not the real withdraw(resource, amount) \
             shape's 2"
        ));
    }
    Ok(())
}

/// Encodes a `call` step's `args`, resolving any `{"Workspace": "<key>"}` element against
/// `workspace_ids` (populated ONLY by `withdraw_to_workspace` steps processed strictly earlier
/// in the same sequence - see module docs' "ordering" section for why this is enough to
/// enforce the real ordering constraint by construction). Every other `ArgValue` tag is
/// encoded via the real, shared `ootle_sdk_core::encode_arg`, identically to
/// `instruction::encode_instruction_args`.
fn encode_call_args(
    step_index: usize,
    function_def: &tari_template_abi::FunctionDef,
    args: &[JsonValue],
    workspace_ids: &HashMap<String, WorkspaceId>,
) -> Result<Vec<InstructionArg>, SequenceToolError> {
    let expected = instruction::expected_arg_count(function_def);
    if args.len() != expected {
        return Err(SequenceToolError::ArgEncoding(
            ArgEncodingError::ArgCountMismatch {
                function: format!("step {step_index}"),
                expected,
                got: args.len(),
            },
        ));
    }

    args.iter()
        .enumerate()
        .map(|(arg_index, v)| {
            let arg_value: ootle_sdk_core::ArgValue =
                serde_json::from_value(v.clone()).map_err(|source| {
                    SequenceToolError::InvalidArgValue {
                        step_index,
                        kind: "call",
                        arg_index,
                        source,
                    }
                })?;
            match arg_value {
                ootle_sdk_core::ArgValue::Workspace(key) => {
                    let id = workspace_ids.get(&key).copied().ok_or_else(|| {
                        SequenceToolError::UnknownWorkspaceKey {
                            step_index,
                            arg_index,
                            key: key.clone(),
                        }
                    })?;
                    Ok(InstructionArg::Workspace(WorkspaceOffsetId::new(id)))
                }
                other => ootle_sdk_core::encode_arg(&other).map_err(|source| {
                    SequenceToolError::ArgEncoding(ArgEncodingError::ArgEncoding {
                        index: arg_index,
                        source,
                    })
                }),
            }
        })
        .collect()
}

/// Builds the real `Vec<Instruction>` for the whole sequence, ABI-verifying every step against
/// the live indexer first. See module docs for the real ordering-enforcement mechanism.
async fn build_sequence_instructions(
    indexer: &IndexerClient,
    steps: &[SequenceStep],
) -> Result<Vec<Instruction>, SequenceToolError> {
    let mut instructions = Vec::new();
    let mut workspace_ids: HashMap<String, WorkspaceId> = HashMap::new();
    let mut next_workspace_id: WorkspaceId = 0;

    for (step_index, step) in steps.iter().enumerate() {
        match step {
            SequenceStep::WithdrawToWorkspace {
                account,
                resource_address,
                amount,
                workspace_key,
            } => {
                if workspace_ids.contains_key(workspace_key) {
                    return Err(SequenceToolError::DuplicateWorkspaceKey {
                        step_index,
                        key: workspace_key.clone(),
                    });
                }
                if !instruction::is_component_address(account) {
                    return Err(SequenceToolError::WithdrawAccountMustBeComponent {
                        step_index,
                        account: account.clone(),
                    });
                }

                let (template_address_hex, component_address) =
                    instruction::resolve_target(indexer, account)
                        .await
                        .map_err(|source| SequenceToolError::TargetResolution {
                            step_index,
                            kind: "withdraw_to_workspace",
                            source,
                        })?;
                let abi = indexer
                    .get_template(&template_address_hex)
                    .await
                    .map_err(|source| SequenceToolError::Indexer {
                        step_index,
                        kind: "withdraw_to_workspace",
                        source,
                    })?;
                let function_def = abi.definition.get_function("withdraw").ok_or_else(|| {
                    SequenceToolError::UnknownFunction {
                        step_index,
                        kind: "withdraw_to_workspace",
                        template_address: template_address_hex.clone(),
                        function: "withdraw".to_string(),
                    }
                })?;
                ensure_is_withdraw_shaped(function_def).map_err(|reason| {
                    SequenceToolError::NotAWithdrawFunction {
                        step_index,
                        account: account.clone(),
                        reason,
                    }
                })?;

                let resource_arg = ootle_sdk_core::encode_arg(&ootle_sdk_core::ArgValue::Address(
                    resource_address.clone(),
                ))
                .map_err(|source| {
                    SequenceToolError::ArgEncoding(ArgEncodingError::ArgEncoding {
                        index: 0,
                        source,
                    })
                })?;
                let amount_arg =
                    ootle_sdk_core::encode_arg(&ootle_sdk_core::ArgValue::Amount(*amount))
                        .map_err(|source| {
                            SequenceToolError::ArgEncoding(ArgEncodingError::ArgEncoding {
                                index: 1,
                                source,
                            })
                        })?;

                let template_address =
                    TemplateAddress::from_hex(&template_address_hex).map_err(|e| {
                        SequenceToolError::InvalidAddress {
                            step_index,
                            kind: "withdraw_to_workspace",
                            address: template_address_hex.clone(),
                            reason: format!("{e:?}"),
                        }
                    })?;

                let withdraw_instruction = instruction::build_call_instruction(
                    "withdraw",
                    function_def,
                    template_address,
                    component_address,
                    vec![resource_arg, amount_arg],
                )
                .map_err(|source| SequenceToolError::InstructionShape {
                    step_index,
                    kind: "withdraw_to_workspace",
                    source,
                })?;
                instructions.push(withdraw_instruction);

                let workspace_id = next_workspace_id;
                next_workspace_id = next_workspace_id
                    .checked_add(1)
                    .expect("WorkspaceId overflow: an unreasonably large number of steps");
                instructions
                    .push(Instruction::PutLastInstructionOutputOnWorkspace { key: workspace_id });
                workspace_ids.insert(workspace_key.clone(), workspace_id);
            }
            SequenceStep::Call {
                address,
                function,
                args,
            } => {
                let (template_address_hex, component_address) =
                    instruction::resolve_target(indexer, address)
                        .await
                        .map_err(|source| SequenceToolError::TargetResolution {
                            step_index,
                            kind: "call",
                            source,
                        })?;
                let abi = indexer
                    .get_template(&template_address_hex)
                    .await
                    .map_err(|source| SequenceToolError::Indexer {
                        step_index,
                        kind: "call",
                        source,
                    })?;
                let function_def = abi.definition.get_function(function).ok_or_else(|| {
                    SequenceToolError::UnknownFunction {
                        step_index,
                        kind: "call",
                        template_address: template_address_hex.clone(),
                        function: function.clone(),
                    }
                })?;

                let instruction_args =
                    encode_call_args(step_index, function_def, args, &workspace_ids)?;

                let template_address =
                    TemplateAddress::from_hex(&template_address_hex).map_err(|e| {
                        SequenceToolError::InvalidAddress {
                            step_index,
                            kind: "call",
                            address: template_address_hex.clone(),
                            reason: format!("{e:?}"),
                        }
                    })?;

                let call_instruction = instruction::build_call_instruction(
                    function,
                    function_def,
                    template_address,
                    component_address,
                    instruction_args,
                )
                .map_err(|source| SequenceToolError::InstructionShape {
                    step_index,
                    kind: "call",
                    source,
                })?;
                instructions.push(call_instruction);
            }
        }
    }

    Ok(instructions)
}

#[tool_router(router = tool_router_sequence, vis = "pub")]
impl TariOotleMcpHandler {
    /// Executes a real, multi-instruction on-chain transaction from an ordered list of steps,
    /// ABI-verified first. See `sequence.rs`'s module docs for the real JSON shape, the
    /// workspace-key ordering rule, and why this reuses `call_ootle_write_function`'s EXACT
    /// safety gate/rate-limiter/approval mechanism rather than a separate one.
    #[tool(
        name = "call_ootle_write_sequence",
        description = "Execute a real, multi-instruction on-chain transaction built from an \
                        ordered list of steps: withdraw_to_workspace (withdraw a resource \
                        amount from an account into a bucket placed on the transaction's \
                        runtime workspace under a label) and call (call a function/method, \
                        whose args may reference an earlier withdraw_to_workspace step's \
                        bucket via {\"Workspace\": \"<label>\"}). This is the ONLY way to \
                        supply a real Bucket-typed argument to a template function in this \
                        gateway (e.g. CoinFlip::create's house_bucket) - single-instruction \
                        tools (call_ootle_write_function, call_ootle_create_function) cannot \
                        produce a Bucket at all. Every step is verified against the real \
                        on-chain ABI first. Shares the EXACT same single-inflight approval \
                        gate, rate limiter, and approve_ootle_write tool as \
                        call_ootle_write_function (unless this server was started with \
                        --unsafe-auto-approve) - there is one write-tier approval queue for \
                        this whole gateway, not one per tool. Use get_ootle_template_abi first \
                        to see each target function's real argument types."
    )]
    pub async fn call_ootle_write_sequence(
        &self,
        Parameters(req): Parameters<CallOotleWriteSequenceRequest>,
    ) -> Result<String, ErrorData> {
        let details = Some(format!(
            "n_steps={} fee_account={}",
            req.steps.len(),
            req.fee_account
        ));
        AuditLog::record(AuditEntry {
            timestamp: std::time::SystemTime::now(),
            tool_name: "call_ootle_write_sequence".to_string(),
            tier: "write_sequence".to_string(),
            status: AuditStatus::Started,
            duration_ms: None,
            client_info: None,
            details: details.clone(),
        })
        .await;

        let started = std::time::Instant::now();
        let result = execute_write_sequence(req, self.config.clone()).await;

        let status = match &result {
            Ok(outcome) if outcome.auto_approved => AuditStatus::AutoApproved,
            Ok(_) => AuditStatus::Success,
            Err(SequenceToolError::Write(WriteToolError::Denied(_))) => AuditStatus::Denied,
            Err(SequenceToolError::Write(WriteToolError::RateLimited)) => AuditStatus::RateLimited,
            Err(SequenceToolError::Write(WriteToolError::Timeout(_))) => AuditStatus::Timeout,
            Err(_) => AuditStatus::Error,
        };
        if let Err(e) = &result {
            log::warn!(target: LOG_TARGET, "call_ootle_write_sequence failed: {e}");
        }
        AuditLog::record(AuditEntry {
            timestamp: std::time::SystemTime::now(),
            tool_name: "call_ootle_write_sequence".to_string(),
            tier: "write_sequence".to_string(),
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

async fn execute_write_sequence(
    req: CallOotleWriteSequenceRequest,
    config: Arc<ServerConfig>,
) -> Result<SequenceOutcome, SequenceToolError> {
    if req.steps.is_empty() {
        return Err(SequenceToolError::EmptySequence);
    }
    if !req
        .steps
        .iter()
        .any(|s| matches!(s, SequenceStep::Call { .. }))
    {
        return Err(SequenceToolError::NoCallStep);
    }

    let indexer = IndexerClient::from_env();
    let instructions = build_sequence_instructions(&indexer, &req.steps).await?;

    let fee_account = ComponentAddressOrName::from_str(&req.fee_account)
        .unwrap_or_else(|infallible| match infallible {});
    let max_fee = req.max_fee.unwrap_or(DEFAULT_MAX_FEE);

    let walletd_config = WalletdConfig::from_env()
        .map_err(|e| SequenceToolError::Config("walletd config", String::new(), e.to_string()))?;
    let mut client = WalletdClientWrapper::connect(&walletd_config)?;

    // PIN-equivalent check BEFORE taking the shared single-inflight gate / burning shared
    // rate-limit quota / prompting an operator for a sequence that can't possibly be
    // submitted anyway. Reused DIRECTLY from write.rs - see module docs.
    write::ensure_wallet_ready(&mut client).await?;

    // 1. Acquire the SAME single-inflight gate call_ootle_write_function uses - see module
    // docs for why this gateway has exactly one write-tier approval queue, not one per tool.
    let _permit = write::WRITE_DIALOG_GATE
        .acquire()
        .await
        .map_err(|_| WriteToolError::InternalError("write gate closed".to_string()))?;

    // 2. Rate limit check AFTER acquiring the gate - same ordering write.rs uses, and the
    // SAME shared quota (not a second, sequence-specific limiter).
    if !write::WRITE_RATE_LIMITER
        .lock()
        .await
        .check_transaction_allowed()
    {
        return Err(SequenceToolError::Write(WriteToolError::RateLimited));
    }

    let auto_approved = config.unsafe_auto_approve;
    if auto_approved {
        log::warn!(
            target: LOG_TARGET,
            "call_ootle_write_sequence executing under --unsafe-auto-approve (NO human \
             approval): n_instructions={}",
            instructions.len()
        );
    } else {
        let request_id = format!("mcp_write_seq_{}", Uuid::new_v4());
        log::info!(
            target: LOG_TARGET,
            "call_ootle_write_sequence awaiting approval (request_id={request_id}); call \
             approve_ootle_write with this request_id to unblock it (120s timeout) - the SAME \
             tool used to approve a regular call_ootle_write_function request"
        );
        write::await_approval(request_id, Duration::from_secs(write::DIALOG_TIMEOUT_SECS)).await?;
    }

    let submit_request = CallInstructionRequest {
        instructions,
        fee_account,
        max_fee,
        inputs: vec![],
        // MUST be `Some(true)` - see write.rs/create.rs's identical, already-regression-
        // tested rationale (`detect_inputs: req.override_inputs.unwrap_or_default()` in the
        // real handler): without this, the fee account's own substate is never resolved as a
        // transaction input and the real engine rejects with "Substates not found".
        override_inputs: Some(true),
        new_outputs: None,
        proof_ids: vec![],
        min_epoch: None,
        max_epoch: None,
    };

    let submit_resp = client.submit_instruction(submit_request).await?;
    let transaction_id = submit_resp.transaction_id.to_string();

    let wait_resp = client
        .wait_transaction_result(TransactionWaitResultRequest {
            transaction_id: submit_resp.transaction_id,
            timeout_secs: Some(WAIT_RESULT_TIMEOUT_SECS),
        })
        .await?;

    if wait_resp.timed_out {
        return Err(SequenceToolError::WaitResultTimedOut(transaction_id));
    }
    let finalize = wait_resp
        .result
        .ok_or_else(|| SequenceToolError::WaitResultTimedOut(transaction_id.clone()))?;

    if let Some(reject) = finalize.any_reject() {
        return Err(SequenceToolError::TransactionRejected {
            transaction_id,
            reason: reject.to_string(),
        });
    }

    let new_component_addresses: Vec<String> = finalize
        .execution_results
        .iter()
        .flat_map(|result| result.indexed.component_addresses().iter())
        .map(|addr| addr.to_string())
        .collect();

    let response = json!({
        "transaction_id": transaction_id,
        "auto_approved": auto_approved,
        "final_fee": wait_resp.final_fee,
        "new_component_addresses": new_component_addresses,
    });
    let json_body = serde_json::to_string_pretty(&response).map_err(|e| {
        SequenceToolError::Config("response serialization", String::new(), e.to_string())
    })?;

    Ok(SequenceOutcome {
        auto_approved,
        json: json_body,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json as jsonify;
    use serial_test::serial;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_partial_json, method, path},
    };

    use super::*;

    fn test_config(unsafe_auto_approve: bool) -> Arc<ServerConfig> {
        Arc::new(ServerConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            bearer_token: "test_token".to_string(),
            unsafe_auto_approve,
        })
    }

    fn account_withdraw_function_def() -> tari_template_abi::FunctionDef {
        tari_template_abi::FunctionDef {
            name: "withdraw".to_string(),
            arguments: vec![
                tari_template_abi::ArgDef {
                    name: "self".to_string(),
                    arg_type: tari_template_abi::Type::Other {
                        name: "&mut self".to_string(),
                    },
                },
                tari_template_abi::ArgDef {
                    name: "resource".to_string(),
                    arg_type: tari_template_abi::Type::Other {
                        name: "ResourceAddress".to_string(),
                    },
                },
                tari_template_abi::ArgDef {
                    name: "amount".to_string(),
                    arg_type: tari_template_abi::Type::Other {
                        name: "Amount".to_string(),
                    },
                },
            ],
            output: tari_template_abi::Type::Other {
                name: "Bucket".to_string(),
            },
            is_mut: true,
            is_migration: false,
        }
    }

    // =========================================================================
    // Shape discriminator for withdraw_to_workspace's ABI check.
    // =========================================================================

    #[test]
    fn recognizes_real_account_withdraw_shape() {
        ensure_is_withdraw_shaped(&account_withdraw_function_def())
            .expect("real Account::withdraw(self, resource, amount) shape must be recognized");
    }

    #[test]
    fn refuses_bare_function_with_no_self_receiver() {
        let mut def = account_withdraw_function_def();
        def.arguments.remove(0); // drop the self receiver
        let err = ensure_is_withdraw_shaped(&def).unwrap_err();
        assert!(err.contains("no 'self' receiver"));
    }

    #[test]
    fn refuses_wrong_arg_count() {
        let mut def = account_withdraw_function_def();
        def.arguments.pop(); // drop `amount`, leaving only (self, resource)
        let err = ensure_is_withdraw_shaped(&def).unwrap_err();
        assert!(err.contains("non-self argument"));
    }

    // =========================================================================
    // Workspace-key ordering: the real, checkable constraint. Exercised directly against
    // build_sequence_instructions with a real live indexer lookup for the withdraw step's ABI
    // (Account::withdraw, real live template) - no walletd involved yet at this layer.
    // =========================================================================

    #[tokio::test]
    async fn forward_reference_to_a_later_steps_workspace_key_is_rejected() {
        let indexer = IndexerClient::from_env();
        let steps = vec![
            // References "bucket", which is only defined by the SECOND step - a real,
            // checkable forward reference that must be rejected.
            SequenceStep::Call {
                address: "80e76c2a2fd86de97ec3849e3495cbf8419a900c81389a1459e5368b7a12b1c4"
                    .to_string(),
                function: "create".to_string(),
                args: vec![
                    jsonify!({"Address": format!("component_{}", "bb".repeat(32))}),
                    jsonify!({"Workspace": "bucket"}),
                ],
            },
            SequenceStep::WithdrawToWorkspace {
                account:
                    "component_86d532912d9c22b7f4a191d5a00d532c5bc5af3672c651e64094578bef90faf5"
                        .to_string(),
                resource_address: format!("resource_{}", "00".repeat(32)),
                amount: 1000,
                workspace_key: "bucket".to_string(),
            },
        ];
        let err = build_sequence_instructions(&indexer, &steps)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                SequenceToolError::UnknownWorkspaceKey {
                    step_index: 0,
                    arg_index: 1,
                    ..
                }
            ),
            "expected UnknownWorkspaceKey for the forward reference, got {err:?}"
        );
    }

    #[tokio::test]
    async fn undefined_workspace_key_is_rejected() {
        let indexer = IndexerClient::from_env();
        let steps = vec![SequenceStep::Call {
            address: "80e76c2a2fd86de97ec3849e3495cbf8419a900c81389a1459e5368b7a12b1c4".to_string(),
            function: "create".to_string(),
            args: vec![
                jsonify!({"Address": format!("component_{}", "bb".repeat(32))}),
                jsonify!({"Workspace": "never_defined"}),
            ],
        }];
        let err = build_sequence_instructions(&indexer, &steps)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SequenceToolError::UnknownWorkspaceKey { key, .. } if key == "never_defined"
        ));
    }

    #[tokio::test]
    async fn duplicate_workspace_key_across_two_withdraw_steps_is_rejected() {
        let indexer = IndexerClient::from_env();
        let account = "component_86d532912d9c22b7f4a191d5a00d532c5bc5af3672c651e64094578bef90faf5"
            .to_string();
        let steps = vec![
            SequenceStep::WithdrawToWorkspace {
                account: account.clone(),
                resource_address: format!("resource_{}", "00".repeat(32)),
                amount: 1000,
                workspace_key: "dup".to_string(),
            },
            SequenceStep::WithdrawToWorkspace {
                account,
                resource_address: format!("resource_{}", "00".repeat(32)),
                amount: 2000,
                workspace_key: "dup".to_string(),
            },
        ];
        let err = build_sequence_instructions(&indexer, &steps)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SequenceToolError::DuplicateWorkspaceKey { step_index: 1, key } if key == "dup"
        ));
    }

    #[tokio::test]
    async fn backward_reference_to_an_earlier_steps_workspace_key_is_accepted() {
        // The real, correct ordering: withdraw first, reference it in a LATER call step.
        // Proves build_sequence_instructions produces a real
        // CallMethod/PutLastInstructionOutputOnWorkspace/CallFunction instruction triple with
        // the Workspace arg correctly resolved to workspace id 0.
        let indexer = IndexerClient::from_env();
        let account = "component_86d532912d9c22b7f4a191d5a00d532c5bc5af3672c651e64094578bef90faf5"
            .to_string();
        let steps = vec![
            SequenceStep::WithdrawToWorkspace {
                account,
                resource_address: format!("resource_{}", "00".repeat(32)),
                amount: 1000,
                workspace_key: "house_bucket".to_string(),
            },
            SequenceStep::Call {
                address: "80e76c2a2fd86de97ec3849e3495cbf8419a900c81389a1459e5368b7a12b1c4"
                    .to_string(),
                function: "create".to_string(),
                args: vec![
                    jsonify!({"Address": format!("component_{}", "bb".repeat(32))}),
                    jsonify!({"Workspace": "house_bucket"}),
                ],
            },
        ];
        let instructions = build_sequence_instructions(&indexer, &steps)
            .await
            .expect("a correctly-ordered real sequence must build successfully");

        assert_eq!(
            instructions.len(),
            3,
            "withdraw + PutLastInstructionOutputOnWorkspace + create = 3 real instructions"
        );
        assert!(matches!(instructions[0], Instruction::CallMethod { .. }));
        match &instructions[1] {
            Instruction::PutLastInstructionOutputOnWorkspace { key } => assert_eq!(*key, 0),
            other => panic!("expected PutLastInstructionOutputOnWorkspace, got {other:?}"),
        }
        match &instructions[2] {
            Instruction::CallFunction { args, .. } => {
                assert_eq!(args.len(), 2);
                assert!(matches!(args[1], InstructionArg::Workspace(_)));
            }
            other => panic!("expected CallFunction, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn withdraw_account_must_be_a_component_address() {
        let indexer = IndexerClient::from_env();
        let steps = vec![
            SequenceStep::WithdrawToWorkspace {
                account: "80e76c2a2fd86de97ec3849e3495cbf8419a900c81389a1459e5368b7a12b1c4"
                    .to_string(),
                resource_address: format!("resource_{}", "00".repeat(32)),
                amount: 1000,
                workspace_key: "bucket".to_string(),
            },
            SequenceStep::Call {
                address: "80e76c2a2fd86de97ec3849e3495cbf8419a900c81389a1459e5368b7a12b1c4"
                    .to_string(),
                function: "create".to_string(),
                args: vec![
                    jsonify!({"Address": format!("component_{}", "bb".repeat(32))}),
                    jsonify!({"Workspace": "bucket"}),
                ],
            },
        ];
        let err = build_sequence_instructions(&indexer, &steps)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SequenceToolError::WithdrawAccountMustBeComponent { step_index: 0, .. }
        ));
    }

    // =========================================================================
    // Top-level request validation.
    // =========================================================================

    #[tokio::test]
    #[serial(write_state)]
    async fn empty_sequence_is_rejected() {
        let req = CallOotleWriteSequenceRequest {
            steps: vec![],
            fee_account:
                "component_86d532912d9c22b7f4a191d5a00d532c5bc5af3672c651e64094578bef90faf5"
                    .to_string(),
            max_fee: None,
        };
        let err = execute_write_sequence(req, test_config(true))
            .await
            .unwrap_err();
        assert!(matches!(err, SequenceToolError::EmptySequence));
    }

    #[tokio::test]
    #[serial(write_state)]
    async fn sequence_with_no_call_step_is_rejected() {
        let req = CallOotleWriteSequenceRequest {
            steps: vec![SequenceStep::WithdrawToWorkspace {
                account:
                    "component_86d532912d9c22b7f4a191d5a00d532c5bc5af3672c651e64094578bef90faf5"
                        .to_string(),
                resource_address: format!("resource_{}", "00".repeat(32)),
                amount: 1000,
                workspace_key: "bucket".to_string(),
            }],
            fee_account:
                "component_86d532912d9c22b7f4a191d5a00d532c5bc5af3672c651e64094578bef90faf5"
                    .to_string(),
            max_fee: None,
        };
        let err = execute_write_sequence(req, test_config(true))
            .await
            .unwrap_err();
        assert!(matches!(err, SequenceToolError::NoCallStep));
    }

    // =========================================================================
    // Real end-to-end (mocked walletd, real live indexer ABI lookups) test: withdraw + create,
    // exactly the CoinFlip-instantiation shape the dispatch brief's live test targets. Proves
    // the whole chain: ABI verification -> instruction building -> shared gate/rate-limiter ->
    // --unsafe-auto-approve -> submit_instruction (asserting >1 real instruction in the body) ->
    // wait_transaction_result -> new_component_addresses extraction.
    // =========================================================================

    fn real_finalize_result_with_new_component(
        new_component: tari_template_lib_types::ComponentAddress,
    ) -> tari_engine_types::commit_result::FinalizeResult {
        use tari_engine_types::{
            commit_result::{FinalizeResult, TransactionResult},
            fees::FeeReceipt,
            indexed_value::IndexedValue,
            instruction_result::InstructionResult,
            substate::SubstateDiff,
        };

        let indexed =
            IndexedValue::from_type(&new_component).expect("encoding a real ComponentAddress");
        let withdraw_result = InstructionResult {
            indexed: IndexedValue::default(),
            return_type: tari_template_abi::Type::Other {
                name: "Bucket".to_string(),
            },
        };
        let put_on_workspace_result = InstructionResult {
            indexed: IndexedValue::default(),
            return_type: tari_template_abi::Type::Unit,
        };
        let create_result = InstructionResult {
            indexed,
            return_type: tari_template_abi::Type::Other {
                name: "Component<CoinFlip>".to_string(),
            },
        };

        let mut finalize = FinalizeResult::new(
            tari_template_lib_types::Hash32::zero(),
            vec![],
            vec![],
            TransactionResult::Accept(SubstateDiff::default()),
            FeeReceipt::builder().build(),
        );
        finalize.execution_results = vec![withdraw_result, put_on_workspace_result, create_result];
        finalize
    }

    #[tokio::test]
    #[serial(write_state)]
    async fn unsafe_auto_approve_end_to_end_withdraw_and_create_against_mocked_walletd() {
        write::clear_inflight_for_tests().await;
        let server = MockServer::start().await;
        let new_component =
            tari_template_lib_types::ComponentAddress::from_hex(&"77".repeat(32)).unwrap();
        let transaction_id_hex = "88".repeat(32);

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

        // The critical assertion: this mock only matches a submit_instruction request whose
        // real `params.instructions` has 3 entries (withdraw, PutLastInstructionOutputOnWorkspace,
        // create) - proving this is genuinely a multi-instruction submission, not 3 separate
        // single-instruction calls.
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(jsonify!({
                "method": "transactions.submit_instruction",
            })))
            .and(wiremock::matchers::body_string_contains(
                "PutLastInstructionOutputOnWorkspace",
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
                    "final_fee": 2500,
                    "timed_out": false,
                }
            })))
            .mount(&server)
            .await;

        unsafe {
            std::env::set_var(crate::walletd_client::ENV_WALLETD_URL, server.uri());
            std::env::set_var(crate::walletd_client::ENV_WALLETD_API_KEY, "tw_test_key");
        }

        let req = CallOotleWriteSequenceRequest {
            steps: vec![
                SequenceStep::WithdrawToWorkspace {
                    account:
                        "component_86d532912d9c22b7f4a191d5a00d532c5bc5af3672c651e64094578bef90faf5"
                            .to_string(),
                    resource_address: format!("resource_{}", "00".repeat(32)),
                    amount: 1_000_000,
                    workspace_key: "house_bucket".to_string(),
                },
                SequenceStep::Call {
                    address: "80e76c2a2fd86de97ec3849e3495cbf8419a900c81389a1459e5368b7a12b1c4"
                        .to_string(),
                    function: "create".to_string(),
                    args: vec![
                        jsonify!({"Address": "component_bb6a86349dfd27389bb12af0ad13540c8bbb10b406821491c450350339e98ce9"}),
                        jsonify!({"Workspace": "house_bucket"}),
                    ],
                },
            ],
            fee_account:
                "component_86d532912d9c22b7f4a191d5a00d532c5bc5af3672c651e64094578bef90faf5"
                    .to_string(),
            max_fee: Some(50_000),
        };

        let outcome = execute_write_sequence(req, test_config(true))
            .await
            .expect("end-to-end withdraw+create sequence should succeed against mocked walletd");

        assert!(outcome.auto_approved);
        assert!(outcome.json.contains(&new_component.to_string()));

        unsafe {
            std::env::remove_var(crate::walletd_client::ENV_WALLETD_URL);
            std::env::remove_var(crate::walletd_client::ENV_WALLETD_API_KEY);
        }
    }

    // =========================================================================
    // Proves the approval mechanism is genuinely SHARED with write.rs: a
    // call_ootle_write_sequence request awaiting approval is unblocked by the exact same
    // respond_to_write/approve_ootle_write path write.rs's own tests exercise directly (no
    // sequence-specific approval function exists to call instead).
    // =========================================================================

    #[tokio::test]
    #[serial(write_state)]
    async fn pending_sequence_is_unblocked_by_writes_shared_approval_mechanism() {
        write::clear_inflight_for_tests().await;
        let server = MockServer::start().await;
        let new_component =
            tari_template_lib_types::ComponentAddress::from_hex(&"99".repeat(32)).unwrap();
        let transaction_id_hex = "aa".repeat(32);

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
                    "final_fee": 2500,
                    "timed_out": false,
                }
            })))
            .mount(&server)
            .await;

        unsafe {
            std::env::set_var(crate::walletd_client::ENV_WALLETD_URL, server.uri());
            std::env::set_var(crate::walletd_client::ENV_WALLETD_API_KEY, "tw_test_key");
        }

        let req = CallOotleWriteSequenceRequest {
            steps: vec![
                SequenceStep::WithdrawToWorkspace {
                    account:
                        "component_86d532912d9c22b7f4a191d5a00d532c5bc5af3672c651e64094578bef90faf5"
                            .to_string(),
                    resource_address: format!("resource_{}", "00".repeat(32)),
                    amount: 1_000_000,
                    workspace_key: "house_bucket".to_string(),
                },
                SequenceStep::Call {
                    address: "80e76c2a2fd86de97ec3849e3495cbf8419a900c81389a1459e5368b7a12b1c4"
                        .to_string(),
                    function: "create".to_string(),
                    args: vec![
                        jsonify!({"Address": "component_bb6a86349dfd27389bb12af0ad13540c8bbb10b406821491c450350339e98ce9"}),
                        jsonify!({"Workspace": "house_bucket"}),
                    ],
                },
            ],
            fee_account:
                "component_86d532912d9c22b7f4a191d5a00d532c5bc5af3672c651e64094578bef90faf5"
                    .to_string(),
            max_fee: Some(50_000),
        };

        let call = tokio::spawn(execute_write_sequence(req, test_config(false)));

        tokio::time::sleep(Duration::from_millis(800)).await;
        let mut attempts = 0;
        loop {
            if let Some(request_id) = write::inflight_request_id_for_tests().await {
                assert!(
                    request_id.starts_with("mcp_write_seq_"),
                    "sequence request_ids should be visibly distinguishable in logs/approval \
                     calls, got {request_id}"
                );
                write::respond_to_write_for_tests(request_id, true)
                    .await
                    .expect("approving the real pending sequence request should succeed");
                break;
            }
            attempts += 1;
            assert!(
                attempts < 50,
                "sequence call never reached the approval-wait step in time"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let outcome = call.await.unwrap().expect(
            "execute_write_sequence should succeed once approved via write.rs's shared mechanism",
        );
        assert!(!outcome.auto_approved);
        assert!(outcome.json.contains(&new_component.to_string()));

        unsafe {
            std::env::remove_var(crate::walletd_client::ENV_WALLETD_URL);
            std::env::remove_var(crate::walletd_client::ENV_WALLETD_API_KEY);
        }
    }
}
