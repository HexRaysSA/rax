//! Static all-phase object factory. No process-bound executable lease is issued.

use crate::{
    Error, Limits, ParsedObject, abi,
    context::ObjectContext,
    decode_object,
    execution::{self, ProgramFacts, TypeFacts},
    limits::Budget,
    metadata,
};

const CONTRACT_ROOTS: [(u16, &str, &str); 7] = [
    (2, "runtime-contract", "runtime_symbols"),
    (4, "runtime-contract", "runtime_data"),
    (5, "runtime-contract", "runtime_relocations"),
    (6, "runtime-contract", "runtime_imports"),
    (7, "runtime-contract", "runtime_tls"),
    (9, "runtime-contract", "runtime_capabilities"),
    (10, "abi-contract", "abi_contract"),
];

/// Immutable static proof. Providers, grants, native evidence and runtime
/// lifetimes remain requirements; this object cannot enter a guest engine.
///
/// Decoding alone cannot manufacture this proof:
/// ```compile_fail
/// use rax_smir_portable::{VerifiedObject, Limits, decode_object};
/// let _: VerifiedObject = decode_object(&[], Limits::default()).unwrap();
/// ```
/// Inspection JSON cannot be deserialized into a proof:
/// ```compile_fail
/// let _: rax_smir_portable::VerifiedObject = serde_json::from_str("{}").unwrap();
/// ```
/// Checked static plans can be shared without mutable verification caches:
/// ```
/// fn assert_send_sync<T: Send + Sync>() {}
/// assert_send_sync::<rax_smir_portable::VerifiedObject>();
/// ```
pub struct VerifiedObject {
    requirements: AdmissionRequirements,
}

impl VerifiedObject {
    pub fn identity(&self) -> [u8; 32] {
        self.requirements.context.identity()
    }
    pub fn requirements(&self) -> &AdmissionRequirements {
        &self.requirements
    }
}

/// Owns the ten immutable source roots and every checked, branded phase output.
/// None of its condition vectors is replaced by the inspection projection.
pub struct AdmissionRequirements {
    context: ObjectContext,
    types: TypeFacts,
    abi: abi::AbiFacts,
    metadata: metadata::MetadataFacts,
    program: ProgramFacts,
}

/// Lossless source-contract inspection, not an executable requirement token.
pub struct RequirementView<'a> {
    object: &'a ParsedObject,
    section: u16,
    kind: &'static str,
    record_type: &'static str,
}

impl RequirementView<'_> {
    pub fn section(&self) -> u16 {
        self.section
    }
    pub fn kind(&self) -> &'static str {
        self.kind
    }
    pub fn record_type(&self) -> &'static str {
        self.record_type
    }
    pub fn encoded_length(&self) -> Result<usize, Error> {
        self.object.payload_len(self.section)
    }
    /// All inspection entries name complete owner roots; their JSON path is [].
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.object.payload(self.section)
    }
}

impl AdmissionRequirements {
    /// The decoded roots that every phase above checked.
    pub(crate) fn parsed(&self) -> &ParsedObject {
        self.context.parsed()
    }

    pub fn iter(&self) -> impl Iterator<Item = RequirementView<'_>> {
        CONTRACT_ROOTS
            .into_iter()
            .map(|(section, kind, record_type)| RequirementView {
                object: self.context.parsed(),
                section,
                kind,
                record_type,
            })
    }
}

/// Run actual type, ABI, metadata, program and final cross-root phases with one
/// cumulative budget. Any incomplete owner phase rejects; no partial success can
/// construct VerifiedObject. Numerical execution and live admission are separate.
pub fn verify_object(bytes: &[u8], limits: Limits) -> Result<VerifiedObject, Error> {
    let parsed = decode_object(bytes, limits)?;
    let mut budget = Budget::new(&limits);
    let context = ObjectContext::new(parsed, &mut budget)?;
    let types = execution::verify_types(&context, &mut budget)?;
    let abi = abi::verify(&context, &types, &mut budget)?;
    let metadata = metadata::verify(&context, &types, &abi, &mut budget)?;
    let program = execution::verify_program(&context, &types, &abi, &metadata, &mut budget)?;
    metadata::verify_program_joins(&context, &types, &abi, &metadata, &program, &mut budget)?;
    for (identity, brand) in [
        (types.identity(), types.context_id()),
        (abi.identity(), abi.context_id()),
        (metadata.identity(), metadata.context_id()),
        (program.identity(), program.context_id()),
    ] {
        if identity != context.identity() || brand != context.context_id() {
            return Err(Error::semantic("P2_PROOF_CONTEXT", "mixed phase proof"));
        }
    }
    Ok(VerifiedObject {
        requirements: AdmissionRequirements {
            context,
            types,
            abi,
            metadata,
            program,
        },
    })
}
