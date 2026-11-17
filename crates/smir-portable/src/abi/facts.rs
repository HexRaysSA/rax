//! Immutable ABI phase proofs. Construction is restricted to the ABI verifier.

use super::{
    call,
    nominal::{Graph, table},
    value::*,
};
use crate::{
    Error,
    context::{ContextId, EntityKey, Namespace, ObjectContext},
    execution::{LayoutHandle, TypeFacts, TypeHandle},
    limits::Budget,
    wire::RecordValue,
};
use std::{collections::BTreeMap, sync::Arc};

pub(super) type Table = BTreeMap<u32, Arc<RecordValue>>;

pub(super) struct Tables {
    pub signatures: Table,
    pub storage: Table,
    pub recipes: Table,
    pub journals: Table,
    pub personalities: Table,
    pub unwind: Table,
    pub catches: Table,
    pub bridges: Table,
}

impl Tables {
    pub(super) fn build(root: &RecordValue, budget: &mut Budget) -> Result<Self, Error> {
        Ok(Self {
            signatures: table(root, "signatures", budget)?,
            storage: table(root, "storage_bindings", budget)?,
            recipes: table(root, "recipes", budget)?,
            journals: table(root, "journals", budget)?,
            personalities: table(root, "personalities", budget)?,
            unwind: table(root, "unwind", budget)?,
            catches: table(root, "catches", budget)?,
            bridges: table(root, "bridges", budget)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AbiRequirementKind {
    ExternalNominal,
    ExternalSourcePlan,
    ExternalRecipe,
    NativeDomain,
    NativeType,
    NativeLayout,
    NativeSymbol,
    NativePersonality,
    NativeUnwind,
    NativeMetadataBytes,
    ForeignBridge,
}

/// A predicate on the exact immutable source record, not a certificate/grant.
/// Source and field_path retain its full expected bytes through the owner facts
/// and the root's original ten records; they never name a provider-private ID.
pub(crate) struct AbiRequirement {
    pub(crate) kind: AbiRequirementKind,
    pub(crate) source: EntityKey,
    pub(crate) field_path: String,
    pub(crate) dependency: Option<(u32, u32)>,
    pub(crate) expected_native_cc: Option<&'static str>,
    pub(crate) expected_packet_cc: Option<&'static str>,
}

pub(crate) struct SourceLayoutFact {
    pub(crate) size_bytes: u64,
    pub(crate) alignment_bytes: u32,
    pub(crate) data_size_bytes: u64,
    pub(crate) nonvirtual_size_bytes: u64,
    pub(crate) nonvirtual_alignment_bytes: u32,
    record: Arc<RecordValue>,
}
impl SourceLayoutFact {
    pub(crate) fn record(&self) -> &RecordValue {
        &self.record
    }
}

pub(crate) struct NominalFact {
    record: Arc<RecordValue>,
    execution: Option<TypeHandle>,
    layout: Option<SourceLayoutFact>,
}
impl NominalFact {
    pub(crate) fn record(&self) -> &RecordValue {
        &self.record
    }
    pub(crate) fn kind(&self) -> Result<&str, Error> {
        text(field(&self.record, "kind")?)
    }
    pub(crate) fn execution_type(&self) -> Option<TypeHandle> {
        self.execution
    }
    pub(crate) fn layout(&self) -> Option<&SourceLayoutFact> {
        self.layout.as_ref()
    }
}

pub(crate) struct SignatureFact {
    record: Arc<RecordValue>,
    function_type: EntityKey,
    execution: TypeHandle,
}
impl SignatureFact {
    pub(crate) fn record(&self) -> &RecordValue {
        &self.record
    }
    pub(crate) fn function_type(&self) -> EntityKey {
        self.function_type
    }
    pub(crate) fn execution_signature(&self) -> TypeHandle {
        self.execution
    }
}

pub(crate) struct StorageBindingFact {
    record: Arc<RecordValue>,
    nominal: EntityKey,
    execution_layout: LayoutHandle,
    comparison: Option<super::mask::ComparisonMask>,
}
impl StorageBindingFact {
    pub(crate) fn record(&self) -> &RecordValue {
        &self.record
    }
    pub(crate) fn nominal(&self) -> EntityKey {
        self.nominal
    }
    pub(crate) fn execution_layout(&self) -> LayoutHandle {
        self.execution_layout
    }
    pub(crate) fn has_comparison_mask(&self) -> bool {
        self.comparison.is_some()
    }
    pub(crate) fn comparison_mask_matches(
        &self,
        mask: &[u8],
        budget: &mut Budget,
    ) -> Result<bool, Error> {
        self.comparison
            .as_ref()
            .ok_or_else(|| {
                Error::semantic(
                    "ABI_CC_NO_COMPARISON_MASK",
                    "allocation is not a logical value view",
                )
            })?
            .matches(mask, budget)
    }
}

macro_rules! checked_record {
    ($name:ident) => {
        pub(crate) struct $name {
            record: Arc<RecordValue>,
        }
        impl $name {
            pub(crate) fn record(&self) -> &RecordValue {
                &self.record
            }
        }
    };
}
checked_record!(RecipeFact);
checked_record!(JournalFact);
checked_record!(BridgeFact);

pub(crate) struct AbiFacts {
    identity: [u8; 32],
    context: ContextId,
    site: [u8; 32],
    graph: Graph,
    nominals: BTreeMap<u32, NominalFact>,
    signatures: BTreeMap<u32, SignatureFact>,
    storage: BTreeMap<u32, StorageBindingFact>,
    recipes: BTreeMap<u32, RecipeFact>,
    journals: BTreeMap<u32, JournalFact>,
    bridges: BTreeMap<u32, BridgeFact>,
    requirements: Vec<AbiRequirement>,
}

impl AbiFacts {
    /// Called only after every ABI predicate has succeeded, never by a decoder.
    pub(super) fn from_checked(
        ctx: &ObjectContext,
        types: &TypeFacts,
        site: [u8; 32],
        graph: Graph,
        tables: Tables,
        requirements: Vec<AbiRequirement>,
        mut masks: BTreeMap<u32, Option<super::mask::ComparisonMask>>,
        budget: &mut Budget,
    ) -> Result<Self, Error> {
        let mut nominals = BTreeMap::new();
        for (identifier, record) in &graph.types {
            budget.work(1)?;
            budget.reserve_bytes(512)?;
            let execution = optional(field(record, "execution")?)?
                .map(|value| types.type_reference(value))
                .transpose()?;
            let layout = if let Some(layout_id) = optional(field(record, "layout")?)? {
                let layout = graph
                    .layouts
                    .get(&id(layout_id)?)
                    .ok_or_else(|| Error::semantic("ABI_CC_LAYOUT_REFERENCE", "checked nominal"))?;
                Some(SourceLayoutFact {
                    size_bytes: uint(field(layout, "size")?)?,
                    alignment_bytes: id(field(layout, "align")?)?,
                    data_size_bytes: uint(field(layout, "data_size")?)?,
                    nonvirtual_size_bytes: uint(field(layout, "nonvirtual_size")?)?,
                    nonvirtual_alignment_bytes: id(field(layout, "nonvirtual_align")?)?,
                    record: Arc::clone(layout),
                })
            } else {
                None
            };
            nominals.insert(
                *identifier,
                NominalFact {
                    record: Arc::clone(record),
                    execution,
                    layout,
                },
            );
        }
        let mut signatures = BTreeMap::new();
        for (identifier, record) in &tables.signatures {
            budget.work(1)?;
            budget.reserve_bytes(256)?;
            let target = graph.resolve(field(record, "function_type")?)?;
            let function_type = ctx.local(Namespace::Nominal, target)?;
            let execution = types.type_reference(field(record, "execution")?)?;
            signatures.insert(
                *identifier,
                SignatureFact {
                    record: Arc::clone(record),
                    function_type,
                    execution,
                },
            );
        }
        let mut storage = BTreeMap::new();
        for (identifier, record) in &tables.storage {
            budget.work(1)?;
            budget.reserve_bytes(256)?;
            let nominal = ctx.local(
                Namespace::Nominal,
                graph.resolve(field(record, "nominal")?)?,
            )?;
            let execution_layout = types
                .layout_handle(super::nominal::self_id(field(record, "execution_layout")?)?)?;
            let comparison = masks.remove(identifier).ok_or_else(|| {
                Error::semantic("ABI_CC_STORAGE_PROOF", "missing source mask proof")
            })?;
            storage.insert(
                *identifier,
                StorageBindingFact {
                    record: Arc::clone(record),
                    nominal,
                    execution_layout,
                    comparison,
                },
            );
        }
        macro_rules! views {
            ($table:expr,$name:ident) => {{
                let mut result = BTreeMap::new();
                for (identifier, record) in $table {
                    budget.work(1)?;
                    budget.reserve_bytes(128)?;
                    result.insert(identifier, $name { record });
                }
                result
            }};
        }
        Ok(Self {
            identity: ctx.identity(),
            context: ctx.context_id(),
            site,
            graph,
            nominals,
            signatures,
            storage,
            recipes: views!(tables.recipes, RecipeFact),
            journals: views!(tables.journals, JournalFact),
            bridges: views!(tables.bridges, BridgeFact),
            requirements,
        })
    }
    pub(crate) fn identity(&self) -> [u8; 32] {
        self.identity
    }
    pub(crate) fn context_id(&self) -> ContextId {
        self.context
    }
    pub(crate) fn site_identity(&self) -> [u8; 32] {
        self.site
    }
    pub(crate) fn assert_context(&self, ctx: &ObjectContext) -> Result<(), Error> {
        require(
            ctx.identity() == self.identity && ctx.context_id() == self.context,
            "ABI_CC_CONTEXT",
        )
    }
    fn key(&self, key: EntityKey, namespace: Namespace) -> Result<u32, Error> {
        require(
            key.context_id() == self.context && key.namespace() == namespace,
            "ABI_CC_ENTITY_NAMESPACE",
        )?;
        Ok(key.id())
    }
    pub(crate) fn nominal(&self, key: EntityKey) -> Result<&NominalFact, Error> {
        self.nominals
            .get(&self.key(key, Namespace::Nominal)?)
            .ok_or_else(|| Error::semantic("ABI_CC_TYPE_REFERENCE", "nominal fact"))
    }
    pub(crate) fn signature(&self, key: EntityKey) -> Result<&SignatureFact, Error> {
        self.signatures
            .get(&self.key(key, Namespace::CallSignature)?)
            .ok_or_else(|| Error::semantic("ABI_CC_ENTITY_REFERENCE", "signature fact"))
    }
    pub(crate) fn storage_binding(&self, key: EntityKey) -> Result<&StorageBindingFact, Error> {
        self.storage
            .get(&self.key(key, Namespace::StorageBinding)?)
            .ok_or_else(|| Error::semantic("ABI_CC_ENTITY_REFERENCE", "storage fact"))
    }
    pub(crate) fn recipe(&self, key: EntityKey) -> Result<&RecipeFact, Error> {
        self.recipes
            .get(&self.key(key, Namespace::Recipe)?)
            .ok_or_else(|| Error::semantic("ABI_CC_ENTITY_REFERENCE", "recipe fact"))
    }
    pub(crate) fn journal(&self, key: EntityKey) -> Result<&JournalFact, Error> {
        self.journals
            .get(&self.key(key, Namespace::Journal)?)
            .ok_or_else(|| Error::semantic("ABI_CC_ENTITY_REFERENCE", "journal fact"))
    }
    pub(crate) fn bridge(&self, key: EntityKey) -> Result<&BridgeFact, Error> {
        self.bridges
            .get(&self.key(key, Namespace::Bridge)?)
            .ok_or_else(|| Error::semantic("ABI_CC_ENTITY_REFERENCE", "bridge fact"))
    }
    pub(crate) fn nominal_compatible(
        &self,
        a: EntityKey,
        b: EntityKey,
        budget: &mut Budget,
    ) -> Result<bool, Error> {
        self.graph.compatible(
            self.key(a, Namespace::Nominal)?,
            self.key(b, Namespace::Nominal)?,
            false,
            budget,
        )
    }
    /// Exact source compatibility ignoring only root cv, without C projection
    /// or caught-type normalization. Keys are admitted local expectations.
    pub(crate) fn source_compatible(
        &self,
        a: EntityKey,
        b: EntityKey,
        budget: &mut Budget,
    ) -> Result<bool, Error> {
        self.graph.compatible(
            self.key(a, Namespace::Nominal)?,
            self.key(b, Namespace::Nominal)?,
            true,
            budget,
        )
    }
    pub(crate) fn c_data_compatible(
        &self,
        a: EntityKey,
        b: EntityKey,
        budget: &mut Budget,
    ) -> Result<bool, Error> {
        self.graph.c_boundary(
            self.key(a, Namespace::Nominal)?,
            self.key(b, Namespace::Nominal)?,
            true,
            budget,
        )
    }
    pub(crate) fn catch_compatible(
        &self,
        a: EntityKey,
        b: EntityKey,
        budget: &mut Budget,
    ) -> Result<bool, Error> {
        let a = self.key(a, Namespace::Nominal)?;
        let b = self.key(b, Namespace::Nominal)?;
        for identifier in [a, b] {
            require(
                !matches!(
                    text(field(self.graph.typ_id(identifier)?, "kind")?)?,
                    "reference" | "array" | "function" | "void"
                ),
                "ABI_CC_CATCH_NORMALIZATION",
            )?;
        }
        self.graph.compatible(a, b, true, budget)
    }
    pub(crate) fn source_call_compatible(
        &self,
        a: EntityKey,
        b: EntityKey,
        budget: &mut Budget,
    ) -> Result<bool, Error> {
        let a = self.signature(a)?.record();
        let b = self.signature(b)?.record();
        budget.reserve_bytes(
            self.recipes
                .len()
                .checked_mul(128)
                .ok_or_else(|| Error::resource("ABI_CC_CALL_LIMIT", "recipe interface index"))?,
        )?;
        let recipes = self
            .recipes
            .iter()
            .map(|(id, record)| (*id, Arc::clone(&record.record)))
            .collect();
        call::compatible(&self.graph, a, b, &recipes, budget)
    }

    /// Actual-first API6 relation. Both ABI/type pairs and keys retain their
    /// original brands. A compatibility bool grants no entry, bridge or lease.
    pub(crate) fn ordinary_address_call_compatible(
        actual_abi: &AbiFacts,
        actual_types: &TypeFacts,
        actual: EntityKey,
        expected_abi: &AbiFacts,
        expected_types: &TypeFacts,
        expected: EntityKey,
        budget: &mut Budget,
    ) -> Result<bool, Error> {
        budget.work(1)?;
        require(
            actual_abi.context == actual_types.context_id()
                && actual_abi.identity == actual_types.identity()
                && expected_abi.context == expected_types.context_id()
                && expected_abi.identity == expected_types.identity(),
            "ABI_CC_CONTEXT",
        )?;
        let a = actual_abi.signature(actual)?;
        let b = expected_abi.signature(expected)?;
        if actual_abi.site != expected_abi.site {
            return Ok(false);
        }
        budget.reserve_bytes(
            (actual_abi.recipes.len() + expected_abi.recipes.len())
                .checked_mul(128)
                .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "recipe views"))?,
        )?;
        let ar = actual_abi
            .recipes
            .iter()
            .map(|(id, value)| (*id, Arc::clone(&value.record)))
            .collect();
        let br = expected_abi
            .recipes
            .iter()
            .map(|(id, value)| (*id, Arc::clone(&value.record)))
            .collect();
        call::ordinary_compatible(
            &actual_abi.graph,
            a.record(),
            actual_types,
            &expected_abi.graph,
            b.record(),
            expected_types,
            &ar,
            &br,
            budget,
        )
    }
    pub(crate) fn c_call_compatible(
        &self,
        a: EntityKey,
        b: EntityKey,
        budget: &mut Budget,
    ) -> Result<bool, Error> {
        for key in [a, b] {
            let record = self.signature(key)?.record();
            if !flags(
                self.graph.typ(field(record, "function_type")?)?,
                "flags",
                "c_linkage",
            )? {
                return Ok(false);
            }
        }
        self.source_call_compatible(a, b, budget)
    }
    pub(crate) fn requirements(&self) -> &[AbiRequirement] {
        &self.requirements
    }
}
