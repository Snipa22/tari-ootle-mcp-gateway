//! Shared address-resolution / ABI-argument-encoding / instruction-building helpers used by
//! BOTH `read.rs` (`is_mut=false` dry-run calls, AGENTS.md step 5) and `write.rs`
//! (`is_mut=true` real calls, AGENTS.md step 6).
//!
//! Extracted out of `read.rs` per DISPATCH_BRIEF.md step 6's explicit instruction to REUSE,
//! not duplicate, the address-resolution/arity-checking logic between the two tools. Three
//! pieces are shared here:
//!
//! 1. [`resolve_target`] — resolves `address` (a `component_`-prefixed component address OR a
//!    bare/`template_`-prefixed template address) to a bare-hex template address plus an
//!    optional resolved [`ComponentAddress`] for method calls, fetching the real owning
//!    template via the indexer's substate lookup when a component address was given.
//! 2. [`encode_instruction_args`] — validates the caller's positional `args` count against the
//!    ABI (excluding any `self` receiver) and lowers each JSON element through the real
//!    `ootle_sdk_core::encode_arg` typed-argument DSL.
//! 3. [`build_call_instruction`] — builds the real engine `Instruction` (`CallMethod` if a
//!    component address was resolved, `CallFunction` otherwise), verifying the address kind
//!    (component vs template) matches whether the ABI's function has a `self` receiver.
//!
//! ## What is deliberately NOT shared: the `is_mut` check
//!
//! `read.rs` refuses `is_mut=true` functions; `write.rs` refuses `is_mut=false` functions —
//! the two tools need the INVERSE check, so [`build_call_instruction`] does not look at
//! `is_mut` at all. Each tool performs its own mutability check (with its own tool-specific
//! error message) BEFORE calling into this module's helpers. Don't be tempted to add an
//! `expected_is_mut` parameter here "to be thorough" — that would smear a tool-specific policy
//! decision into a module whose whole point is being policy-agnostic address/arg/instruction
//! plumbing.

use std::str::FromStr;

use ootle_sdk_core::{ArgValue, encode_arg};
use serde_json::Value as JsonValue;
use tari_ootle_transaction::{ComponentReference, Instruction, args::InstructionArg};
use tari_template_abi::FunctionDef;
use tari_template_lib_types::{ComponentAddress, FunctionName, TemplateAddress, address_prefixes};

use crate::indexer_client::{IndexerClient, IndexerError, extract_component_template_address};

#[derive(Debug, thiserror::Error)]
pub enum TargetResolutionError {
    #[error("invalid address '{address}': {reason}")]
    InvalidAddress { address: String, reason: String },
    #[error("indexer request failed: {0}")]
    Indexer(#[from] IndexerError),
    #[error(
        "component '{address}' substate is not a Component (cannot resolve its owning template)"
    )]
    NotAComponent { address: String },
}

#[derive(Debug, thiserror::Error)]
pub enum ArgEncodingError {
    #[error("expected {expected} arg(s) for '{function}', got {got}")]
    ArgCountMismatch {
        function: String,
        expected: usize,
        got: usize,
    },
    #[error("arg {index}: invalid ArgValue: {source}")]
    InvalidArgValue {
        index: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error("arg {index}: failed to encode: {source}")]
    ArgEncoding {
        index: usize,
        #[source]
        source: ootle_sdk_core::types::error::OotleSdkError,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum InstructionShapeError {
    #[error("invalid function/method name '{0}': exceeds the engine's length limit")]
    InvalidFunctionName(String),
    #[error(
        "'{function}' is a METHOD (its ABI's first argument is 'self') — call it with a \
         component_<address> in `address`, not a bare template address"
    )]
    ExpectedComponentAddress { function: String },
    #[error(
        "'{function}' is a FUNCTION (no 'self' receiver in its ABI) — call it with the \
         template's address in `address`, not a component_<address>"
    )]
    ExpectedTemplateAddress { function: String },
}

/// Strips a `template_` prefix if present.
pub fn strip_template_prefix(s: &str) -> &str {
    s.strip_prefix(address_prefixes::TEMPLATE)
        .and_then(|rest| rest.strip_prefix('_'))
        .unwrap_or(s)
}

pub fn is_component_address(s: &str) -> bool {
    s.starts_with(address_prefixes::COMPONENT)
        && s[address_prefixes::COMPONENT.len()..].starts_with('_')
}

/// Whether `function_def`'s first argument is a `self`/`&self`/`&mut self` receiver, i.e.
/// whether it is a METHOD (needs a `component_<address>`) rather than a bare FUNCTION.
pub fn has_self_receiver(function_def: &FunctionDef) -> bool {
    function_def
        .arguments
        .first()
        .map(|a| a.name == "self")
        .unwrap_or(false)
}

/// The number of positional `args` a caller must supply, i.e. `function_def.arguments.len()`
/// minus one if the first argument is a `self` receiver (the gateway supplies that
/// structurally via `address`, never as a positional arg value).
pub fn expected_arg_count(function_def: &FunctionDef) -> usize {
    function_def.arguments.len() - usize::from(has_self_receiver(function_def))
}

/// Resolves `address` to (bare-hex template address, optional component address for a method
/// call), fetching the real ABI's owning template via the indexer if a component address was
/// given.
pub async fn resolve_target(
    indexer: &IndexerClient,
    address: &str,
) -> Result<(String, Option<ComponentAddress>), TargetResolutionError> {
    if is_component_address(address) {
        let component_address = ComponentAddress::from_str(address).map_err(|e| {
            TargetResolutionError::InvalidAddress {
                address: address.to_string(),
                reason: format!("{e:?}"),
            }
        })?;
        let substate = indexer.get_substate(address).await?;
        let template_address_hex =
            extract_component_template_address(&substate).ok_or_else(|| {
                TargetResolutionError::NotAComponent {
                    address: address.to_string(),
                }
            })?;
        Ok((template_address_hex, Some(component_address)))
    } else {
        let bare_hex = strip_template_prefix(address).to_string();
        Ok((bare_hex, None))
    }
}

/// Validates the caller's `args` length against the ABI (excluding any `self` receiver) and
/// lowers each JSON element to a real `InstructionArg` via `ootle_sdk_core`'s typed-argument
/// DSL. Shared verbatim between `read.rs` and `write.rs` — this has nothing to do with
/// mutability, only with "does this JSON match this function's real argument shape".
pub fn encode_instruction_args(
    function: &str,
    function_def: &FunctionDef,
    args: &[JsonValue],
) -> Result<Vec<InstructionArg>, ArgEncodingError> {
    let expected = expected_arg_count(function_def);
    if args.len() != expected {
        return Err(ArgEncodingError::ArgCountMismatch {
            function: function.to_string(),
            expected,
            got: args.len(),
        });
    }

    let arg_values: Vec<ArgValue> = args
        .iter()
        .enumerate()
        .map(|(index, v)| {
            serde_json::from_value::<ArgValue>(v.clone())
                .map_err(|source| ArgEncodingError::InvalidArgValue { index, source })
        })
        .collect::<Result<_, _>>()?;

    arg_values
        .iter()
        .enumerate()
        .map(|(index, v)| {
            encode_arg(v).map_err(|source| ArgEncodingError::ArgEncoding { index, source })
        })
        .collect()
}

/// Builds the real engine `Instruction` (`CallMethod` if a component address was resolved,
/// `CallFunction` otherwise), verifying the address kind matches whether `function_def` is a
/// method (has a `self` receiver) or a plain function. Deliberately does NOT check `is_mut` —
/// see module docs: that check is tool-specific (read.rs and write.rs need the inverse of each
/// other) and must be performed by the caller before this is invoked.
pub fn build_call_instruction(
    function: &str,
    function_def: &FunctionDef,
    template_address: TemplateAddress,
    component_address: Option<ComponentAddress>,
    instruction_args: Vec<InstructionArg>,
) -> Result<Instruction, InstructionShapeError> {
    let has_self = has_self_receiver(function_def);
    let function_name = FunctionName::try_from(function.to_string())
        .map_err(|_| InstructionShapeError::InvalidFunctionName(function.to_string()))?;

    match (has_self, component_address) {
        (true, Some(component_address)) => Ok(Instruction::CallMethod {
            call: ComponentReference::Address(component_address),
            method: function_name,
            args: instruction_args,
        }),
        (true, None) => Err(InstructionShapeError::ExpectedComponentAddress {
            function: function.to_string(),
        }),
        (false, None) => Ok(Instruction::CallFunction {
            address: template_address,
            function: function_name,
            args: instruction_args,
        }),
        (false, Some(_)) => Err(InstructionShapeError::ExpectedTemplateAddress {
            function: function.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_component_address_detects_prefix() {
        assert!(is_component_address("component_aabb"));
        assert!(!is_component_address("template_aabb"));
        assert!(!is_component_address("aabb"));
        assert!(!is_component_address("componentaabb"));
    }

    #[test]
    fn strip_template_prefix_handles_both_forms() {
        let hex = "00".repeat(32);
        let prefixed = format!("template_{hex}");
        assert_eq!(strip_template_prefix(&prefixed), hex);
        assert_eq!(strip_template_prefix(&hex), hex);
    }

    fn method_function_def(is_mut: bool) -> FunctionDef {
        FunctionDef {
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
            is_mut,
            is_migration: false,
        }
    }

    fn plain_function_def(is_mut: bool) -> FunctionDef {
        FunctionDef {
            name: "create".to_string(),
            arguments: vec![],
            output: tari_template_abi::Type::Unit,
            is_mut,
            is_migration: false,
        }
    }

    #[test]
    fn has_self_receiver_detects_method_vs_function() {
        assert!(has_self_receiver(&method_function_def(false)));
        assert!(!has_self_receiver(&plain_function_def(false)));
    }

    #[test]
    fn expected_arg_count_excludes_self_receiver() {
        assert_eq!(expected_arg_count(&method_function_def(false)), 1);
        assert_eq!(expected_arg_count(&plain_function_def(false)), 0);
    }

    #[test]
    fn build_call_instruction_requires_component_address_for_methods() {
        let function_def = method_function_def(false);
        let err = build_call_instruction(
            "balance",
            &function_def,
            TemplateAddress::from_hex(&"00".repeat(32)).unwrap(),
            None,
            vec![],
        )
        .unwrap_err();
        assert!(matches!(
            err,
            InstructionShapeError::ExpectedComponentAddress { .. }
        ));
    }

    #[test]
    fn build_call_instruction_rejects_component_address_for_plain_functions() {
        let function_def = plain_function_def(false);
        let component = ComponentAddress::from_hex(&"11".repeat(32)).unwrap();
        let err = build_call_instruction(
            "create",
            &function_def,
            TemplateAddress::from_hex(&"00".repeat(32)).unwrap(),
            Some(component),
            vec![],
        )
        .unwrap_err();
        assert!(matches!(
            err,
            InstructionShapeError::ExpectedTemplateAddress { .. }
        ));
    }

    #[test]
    fn build_call_instruction_builds_real_call_method() {
        let function_def = method_function_def(false);
        let component = ComponentAddress::from_hex(&"11".repeat(32)).unwrap();
        let arg = encode_arg(&ArgValue::Address(format!("resource_{}", "22".repeat(32)))).unwrap();
        let instruction = build_call_instruction(
            "balance",
            &function_def,
            TemplateAddress::from_hex(&"00".repeat(32)).unwrap(),
            Some(component),
            vec![arg],
        )
        .unwrap();
        match instruction {
            Instruction::CallMethod { call, method, args } => {
                assert_eq!(call, ComponentReference::Address(component));
                assert_eq!(method.to_string(), "balance");
                assert_eq!(args.len(), 1);
            }
            other => panic!("expected CallMethod, got {other:?}"),
        }
    }

    /// `build_call_instruction` doesn't care about `is_mut` at all — it should build the exact
    /// same instruction shape whether the function is a read or a write. This is a real
    /// assertion of module docs' "deliberately not shared" design decision: the SAME
    /// `is_mut=true` function def must succeed here (the mutability refusal is each tool's own
    /// job, not this module's).
    #[test]
    fn build_call_instruction_is_indifferent_to_is_mut() {
        let read_def = method_function_def(false);
        let write_def = method_function_def(true);
        let component = ComponentAddress::from_hex(&"11".repeat(32)).unwrap();
        let arg = encode_arg(&ArgValue::Address(format!("resource_{}", "22".repeat(32)))).unwrap();
        let read_instruction = build_call_instruction(
            "balance",
            &read_def,
            TemplateAddress::from_hex(&"00".repeat(32)).unwrap(),
            Some(component),
            vec![arg.clone()],
        )
        .unwrap();
        let write_instruction = build_call_instruction(
            "balance",
            &write_def,
            TemplateAddress::from_hex(&"00".repeat(32)).unwrap(),
            Some(component),
            vec![arg],
        )
        .unwrap();
        assert_eq!(
            format!("{read_instruction:?}"),
            format!("{write_instruction:?}")
        );
    }

    #[test]
    fn encode_instruction_args_rejects_wrong_arg_count() {
        let function_def = method_function_def(false);
        let err = encode_instruction_args("balance", &function_def, &[]).unwrap_err();
        assert!(matches!(
            err,
            ArgEncodingError::ArgCountMismatch {
                expected: 1,
                got: 0,
                ..
            }
        ));
    }

    #[test]
    fn encode_instruction_args_encodes_real_arg_value() {
        let function_def = method_function_def(false);
        let args = vec![serde_json::json!({"Address": format!("resource_{}", "22".repeat(32))})];
        let encoded = encode_instruction_args("balance", &function_def, &args).unwrap();
        assert_eq!(encoded.len(), 1);
    }

    /// DISPATCH_BRIEF.md v2 step 4: proves `ArgValue::List` of `ArgValue::Bytes` elements
    /// already encodes a composite/multi-field struct argument byte-identically to the real
    /// `minicbor`-derived `Encode` impl a genuine template parameter of that type actually
    /// uses — no new `ArgValue` variant is needed.
    ///
    /// `SchnorrSignatureBytes { public_nonce: RistrettoPublicKeyBytes, signature: Scalar32Bytes }`
    /// (`tari_template_lib_types::crypto::schnorr`, pinned commit `d89dc92`) derives
    /// `#[derive(Encode, Decode, CborLen)]` with NO `#[cbor(map)]`/`#[cbor(transparent)]`
    /// attribute, so `minicbor-derive` (confirmed reading `minicbor-derive` 0.19.5's own
    /// `Encoding::default() == Encoding::Array` and `encode_fields`'s `Encoding::Array` arm
    /// this session) encodes it as a definite-length CBOR array of its two fields in
    /// declaration order (`public_nonce` then `signature`), each field lowered via its own
    /// `Encode` impl. Both `RistrettoPublicKeyBytes` and `Scalar32Bytes` are `#[cbor(with =
    /// "minicbor::bytes")]` single-field newtypes, so each lowers to a definite-length CBOR
    /// byte string — exactly what `ArgValue::Bytes` produces (see `generic_intent.rs`'s
    /// `ArgValue::Bytes` arm: `InstructionArg::literal(tari_bor::Value::Bytes(...))`).
    ///
    /// This test builds a REAL `SchnorrSignatureBytes` value, encodes it via the exact same
    /// `tari_bor::encode` (= `minicbor`-backed) encoder the engine's own decoder is the
    /// counterpart of, and asserts the gateway's `{"List": [{"Bytes": ...}, {"Bytes":
    /// ...}]}`-shaped `ArgValue` produces byte-IDENTICAL literal bytes — the strongest
    /// available proof short of live network access to a real `tari_ootle_walletd`/validator
    /// (see module's sibling live test below and this dispatch's report for why that's
    /// unreachable from this sandbox).
    #[test]
    fn schnorr_signature_bytes_list_encodes_byte_identically_to_the_real_minicbor_struct() {
        use tari_template_lib_types::crypto::{
            RistrettoPublicKeyBytes, Scalar32Bytes, SchnorrSignatureBytes,
        };

        let public_nonce_bytes: [u8; 32] = std::array::from_fn(|i| i as u8);
        let signature_bytes: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_add(0x80));

        // The real, genuine minicbor-derived struct value a `signer: SchnorrSignatureBytes`
        // template parameter actually decodes from on-chain.
        let real_signature = SchnorrSignatureBytes::new(
            RistrettoPublicKeyBytes::from(public_nonce_bytes),
            Scalar32Bytes::from(signature_bytes),
        );
        // Encoded via `tari_bor::encode`, the exact encoder `InstructionArg::from_type` (used
        // by every scalar `encode_arg` arm) itself wraps — i.e. the real wire bytes a genuine
        // minicbor `Encode::encode` call for this struct produces, not a hand-rolled guess.
        let real_cbor = tari_bor::encode(&real_signature).expect("real struct must encode");

        // This gateway's composite-struct encoding pattern: a List of two Bytes elements,
        // one per field, in declaration order.
        let dsl_arg = encode_arg(&ArgValue::List(vec![
            ArgValue::Bytes(public_nonce_bytes.to_vec()),
            ArgValue::Bytes(signature_bytes.to_vec()),
        ]))
        .expect("List-of-Bytes composite arg must encode");
        let dsl_cbor = dsl_arg
            .as_literal_bytes()
            .expect("List/Optional arms always produce a Literal carrier")
            .to_vec();

        assert_eq!(
            dsl_cbor, real_cbor,
            "the gateway's {{\"List\": [{{\"Bytes\": ..}}, {{\"Bytes\": ..}}]}} composite-arg \
             encoding must produce byte-identical CBOR to the real minicbor-derived \
             SchnorrSignatureBytes::encode"
        );

        // Round-trip: the real struct's own `Decode` impl must accept the DSL-encoded bytes,
        // proving this isn't just accidentally-equal bytes but a genuinely valid encoding of
        // the real type.
        let decoded: SchnorrSignatureBytes = tari_bor::decode(&dsl_cbor)
            .expect("real SchnorrSignatureBytes::decode must accept the DSL encoding");
        assert_eq!(decoded, real_signature);
    }

    /// Real live test: resolve the funded `mcp-gateway-account` test account (AGENTS.md) from
    /// the live indexer's real substate route, confirming component→template resolution
    /// against real data. Moved here verbatim from `read.rs` when this module was extracted
    /// (AGENTS.md step 6) — both `read.rs` and `write.rs` depend on this exact behaviour.
    #[tokio::test]
    async fn live_resolve_target_resolves_real_account_component_to_account_template() {
        let indexer = IndexerClient::from_env();
        let address = "component_86d532912d9c22b7f4a191d5a00d532c5bc5af3672c651e64094578bef90faf5";
        let (template_address_hex, component_address) = resolve_target(&indexer, address)
            .await
            .expect("live substate resolution failed");
        assert_eq!(
            template_address_hex,
            "0000000000000000000000000000000000000000000000000000000000000000",
            "the real mcp-gateway-account is a real Account template instance"
        );
        assert!(component_address.is_some());
    }
}
