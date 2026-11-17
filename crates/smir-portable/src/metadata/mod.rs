//! Runtime declarations and static loader contracts.
//!
//! These routines never allocate guest storage, run initializers, resolve host
//! imports, select providers, or issue executable/runtime authority.

mod audit_profile;
pub(crate) mod imports;
pub(crate) mod linking;
pub(crate) mod program;
pub(crate) mod records;
pub(crate) mod relocations;
pub(crate) mod requirements;
pub(crate) mod source_roles;
pub(crate) mod storage;
pub(crate) mod symbols;

use crate::Error;
use crate::context::{ContextId, ObjectContext};
use crate::{
    abi::AbiFacts,
    execution::{ProgramFacts, TypeFacts},
    limits::Budget,
};
use std::collections::BTreeMap;

/// Sealed complete metadata-phase proof. No public/serde/test success constructor.
/// Only explicitly audited profiles can pass the private semantic factory.
pub(crate) struct MetadataFacts {
    identity: [u8; 32],
    context: ContextId,
    symbols: symbols::SymbolFacts,
    requirements: requirements::RequirementFacts,
    imports: BTreeMap<u32, imports::ImportFact>,
    storage: BTreeMap<(records::StorageKind, u32), storage::StorageFact>,
    initializers: Vec<relocations::ConstantInitializerFact>,
}

impl MetadataFacts {
    pub(crate) fn identity(&self) -> [u8; 32] {
        self.identity
    }
    pub(crate) fn context_id(&self) -> ContextId {
        self.context
    }
    pub(crate) fn assert_context(&self, ctx: &ObjectContext) -> Result<(), Error> {
        records::require(
            self.identity == ctx.identity() && self.context == ctx.context_id(),
            "RT_CONTEXT_MISMATCH",
        )
    }
    pub(crate) fn symbol(&self, id: u32) -> Result<&symbols::SymbolFact, Error> {
        self.symbols.symbol(id)
    }
    pub(crate) fn requirements(&self) -> &requirements::RequirementFacts {
        &self.requirements
    }
    pub(crate) fn import(&self, id: u32) -> Result<&imports::ImportFact, Error> {
        self.imports
            .get(&id)
            .ok_or_else(|| Error::semantic("RT_IMPORT_REFERENCE", id.to_string()))
    }
    pub(crate) fn storage(
        &self,
        kind: records::StorageKind,
        id: u32,
    ) -> Result<&storage::StorageFact, Error> {
        self.storage
            .get(&(kind, id))
            .ok_or_else(|| Error::semantic("RT_STORAGE_REFERENCE", id.to_string()))
    }
    pub(crate) fn tls(&self, id: u32) -> Result<&storage::StorageFact, Error> {
        self.storage(records::StorageKind::Tls, id)
    }
    pub(crate) fn initializers(&self) -> &[relocations::ConstantInitializerFact] {
        &self.initializers
    }
}

/// Complete runtime-root static phase. No executable or process token is issued.
pub(crate) fn verify(
    ctx: &ObjectContext,
    types: &TypeFacts,
    abi: &AbiFacts,
    budget: &mut Budget,
) -> Result<MetadataFacts, Error> {
    types.assert_context(ctx)?;
    abi.assert_context(ctx)?;
    symbols::verify_manifest(ctx, types, budget)?;
    let symbols = symbols::verify_local(ctx, budget)?;
    linking::verify_storage(ctx, types, abi, budget)?;
    linking::verify_symbols(ctx, types, abi, &symbols, budget)?;
    linking::verify_exports(ctx, types, abi, budget)?;
    let mut requirements = requirements::verify(ctx.root(9)?, budget)?;
    let imports = imports::verify(ctx, types, abi, &requirements, budget)?;
    let initializers = relocations::verify(ctx, types, &symbols, budget)?;
    program::verify_headers(ctx, types, abi, budget)?;
    // R-PROD004: all applicable predicates above run even for unused records.
    // A conservative per-input coverage check leaves every unaudited form
    // explicitly unknown; it never waives a validator or trusts a file claim.
    audit_profile::verify(ctx, types, abi, &symbols, budget)?;
    // Capture immutable outputs only for a covered input. All semantic checks
    // above still run; an unaudited large data prefix is not copied pointlessly.
    let storage = storage::capture_facts(ctx, types, budget)?;
    requirements::collect(ctx, &symbols, &imports, &mut requirements, budget)?;
    Ok(MetadataFacts {
        identity: ctx.identity(),
        context: ctx.context_id(),
        symbols,
        requirements,
        imports,
        storage,
        initializers,
    })
}

/// Program-dependent constraints are mandatory before root's all-phase seal.
pub(crate) fn verify_program_joins(
    ctx: &ObjectContext,
    types: &TypeFacts,
    abi: &AbiFacts,
    metadata: &MetadataFacts,
    program: &ProgramFacts,
    budget: &mut Budget,
) -> Result<(), Error> {
    metadata.assert_context(ctx)?;
    program::verify_joins(
        ctx,
        types,
        abi,
        &metadata.symbols,
        &metadata.initializers,
        program,
        budget,
    )
}
