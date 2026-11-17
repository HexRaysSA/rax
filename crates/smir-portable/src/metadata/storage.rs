//! Phase-independent raw source bytes, as accepted in INT-023.
//! Declared hashes never certify a loaded native image or post-relocation bytes.

use super::records::{
    PatchInterval, StaticBytes, StorageKind, StorageView, add, number, optional_number, require,
    token, u32_field,
};
use crate::context::{
    ContextId, DeclaredEntity, EntityKey, EntityRef, Namespace, ObjectContext, entity_ref, field,
    list, optional,
};
use crate::execution::{LayoutHandle, TypeFacts};
use crate::{Error, limits::Budget, wire::RecordValue};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};

pub(crate) struct StorageFact {
    pub(crate) key: EntityKey,
    pub(crate) kind: StorageKind,
    pub(crate) extent: u64,
    pub(crate) alignment: u64,
    pub(crate) mutable: bool,
    pub(crate) layout: Option<LayoutHandle>,
    pub(crate) nominal: Option<EntityRef>,
    pub(crate) abi_binding: Option<EntityRef>,
    initial: Arc<[u8]>,
    poison: Arc<[u8]>,
    undef: Arc<[u8]>,
    zero_fill: u64,
    pub(crate) zero_shadow: super::records::ZeroShadow,
}

impl StorageFact {
    pub(crate) fn bytes(&self, offset: u64, length: u64) -> Result<StaticBytes<'_>, Error> {
        StorageView {
            id: self.key.id(),
            extent: self.extent,
            alignment: self.alignment,
            mutable: self.mutable,
            initial: &self.initial,
            poison: &self.poison,
            undef: &self.undef,
            zero_fill: self.zero_fill,
            zero_shadow: self.zero_shadow,
        }
        .range(offset, length)
    }
}

/// Called by metadata's private factory only after complete storage/source joins.
pub(super) fn capture_facts(
    ctx: &ObjectContext,
    types: &TypeFacts,
    budget: &mut Budget,
) -> Result<BTreeMap<(StorageKind, u32), StorageFact>, Error> {
    types.assert_context(ctx)?;
    let mut result = BTreeMap::new();
    for (section, kind, namespace) in [
        (4, StorageKind::Data, Namespace::Data),
        (7, StorageKind::Tls, Namespace::Tls),
    ] {
        for value in list(field(ctx.root(section)?, "segments")?)? {
            let value = if kind == StorageKind::Tls {
                field(value, "storage")?
            } else {
                value
            };
            let storage = StorageView::parse(value, budget)?;
            let copies = storage
                .initial
                .len()
                .checked_mul(3)
                .and_then(|v| v.checked_add(512))
                .ok_or_else(|| Error::resource("RT_STORAGE_RESOURCE", String::new()))?;
            budget.reserve_bytes(copies)?;
            budget.work(storage.initial.len() as u64)?;
            let layout = super::symbols::optional_ref(value, "layout")?
                .map(|r| types.layout_handle(super::symbols::self_id(r, "RT_SEGMENT_LAYOUT")?))
                .transpose()?;
            let fact = StorageFact {
                key: ctx.local(namespace, storage.id)?,
                kind,
                extent: storage.extent,
                alignment: storage.alignment,
                mutable: storage.mutable,
                layout,
                nominal: super::symbols::optional_ref(value, "nominal")?,
                abi_binding: super::symbols::optional_ref(value, "abi_binding")?,
                initial: Arc::from(storage.initial),
                poison: Arc::from(storage.poison),
                undef: Arc::from(storage.undef),
                zero_fill: storage.zero_fill,
                zero_shadow: storage.zero_shadow,
            };
            require(
                result.insert((kind, storage.id), fact).is_none(),
                "RT_STORAGE_DUPLICATE",
            )?;
        }
    }
    Ok(result)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PatchKind {
    Leaf,
    ConstantInitializer,
}

pub(crate) struct DeclaredPatch<'a> {
    pub(crate) kind: PatchKind,
    pub(crate) interval: PatchInterval,
    pub(crate) record: &'a RecordValue,
}

pub(crate) struct RawDeclaredBytes<'a> {
    identity: [u8; 32],
    context_id: ContextId,
    storage: EntityKey,
    source: Option<EntityRef>,
    offset: u64,
    length: u64,
    bytes: StaticBytes<'a>,
    mutable: bool,
    patches: Vec<DeclaredPatch<'a>>,
}

impl<'a> RawDeclaredBytes<'a> {
    pub(crate) fn identity(&self) -> [u8; 32] {
        self.identity
    }
    pub(crate) fn context_id(&self) -> ContextId {
        self.context_id
    }
    pub(crate) fn storage(&self) -> EntityKey {
        self.storage
    }
    pub(crate) fn source(&self) -> Option<EntityRef> {
        self.source
    }
    pub(crate) fn offset(&self) -> u64 {
        self.offset
    }
    pub(crate) fn length(&self) -> u64 {
        self.length
    }
    pub(crate) fn bytes(&self) -> &StaticBytes<'a> {
        &self.bytes
    }
    pub(crate) fn mutable(&self) -> bool {
        self.mutable
    }
    pub(crate) fn patches(&self) -> &[DeclaredPatch<'a>] {
        &self.patches
    }

    /// SHA256 of RAW declared bytes, with a precharged symbolic zero tail.
    pub(crate) fn sha256(&self, budget: &mut Budget) -> Result<[u8; 32], Error> {
        budget.work(self.length)?;
        let mut hash = Sha256::new();
        hash.update(self.bytes.initial);
        static ZERO: [u8; 4096] = [0; 4096];
        let mut remaining = self.bytes.zero_tail_bytes;
        while remaining > 0 {
            let length = remaining.min(ZERO.len() as u64) as usize;
            hash.update(&ZERO[..length]);
            remaining -= length as u64;
        }
        Ok(hash.finalize().into())
    }
}

pub(crate) enum DeclaredMetadataRange<'a> {
    Local(RawDeclaredBytes<'a>),
    Dependency {
        slot: u32,
        declaration: u32,
        offset: u64,
        length: u64,
        expected: &'a RecordValue,
    },
}

pub(crate) fn static_raw_range<'a>(
    ctx: &'a ObjectContext,
    storage: EntityKey,
    offset: u64,
    length: u64,
    budget: &mut Budget,
) -> Result<RawDeclaredBytes<'a>, Error> {
    let kind = match storage.namespace() {
        Namespace::Data => StorageKind::Data,
        Namespace::Tls => StorageKind::Tls,
        _ => return Err(Error::semantic("RT_METADATA_STORAGE_KIND", String::new())),
    };
    let value = ctx.entity(storage)?; // Also rejects an actual key from another decode.
    let value = if kind == StorageKind::Tls {
        field(value, "storage")?
    } else {
        value
    };
    let view = StorageView::parse(value, budget)?;
    let bytes = view.range(offset, length)?;
    let end = add(offset, length, "RT_METADATA_EXTENT")?;
    let root = ctx.root(5)?;
    let leaves = list(field(root, "relocations")?)?;
    let constants = list(field(root, "constant_initializers")?)?;
    let count = leaves
        .len()
        .checked_add(constants.len())
        .ok_or_else(|| Error::resource("RT_METADATA_RESOURCE", String::new()))?;
    budget.work(count as u64)?;
    budget.edges(count)?;
    budget.reserve_bytes(
        count
            .checked_mul(std::mem::size_of::<DeclaredPatch<'_>>())
            .ok_or_else(|| Error::resource("RT_METADATA_RESOURCE", String::new()))?,
    )?;
    let mut patches = Vec::with_capacity(count);
    for (records, patch_kind) in [
        (leaves, PatchKind::Leaf),
        (constants, PatchKind::ConstantInitializer),
    ] {
        for patch in records {
            let source_kind = StorageKind::parse(token(patch, "source_kind")?)?;
            let source = u32_field(patch, "source")?;
            if source_kind != kind || source != view.id {
                continue;
            }
            let width = if patch_kind == PatchKind::Leaf {
                number(patch, "width")?
            } else {
                let reference = entity_ref(field(patch, "layout")?)?;
                let key = match ctx.resolve_declaration(Namespace::MemoryLayout, &reference)? {
                    DeclaredEntity::Local(key) => key,
                    DeclaredEntity::Dependency { .. } => {
                        return Err(Error::semantic("RT_INITIALIZER_SELF", String::new()));
                    }
                };
                number(ctx.entity(key)?, "access_bytes")?
            };
            let interval =
                PatchInterval::new(kind, source, number(patch, "offset")?, width, view.extent)?;
            if interval.intersects(kind, source, offset, end) {
                patches.push(DeclaredPatch {
                    kind: patch_kind,
                    interval,
                    record: patch,
                });
            }
        }
    }
    Ok(RawDeclaredBytes {
        identity: ctx.identity(),
        context_id: ctx.context_id(),
        storage,
        source: None,
        offset,
        length,
        bytes,
        mutable: view.mutable,
        patches,
    })
}

pub(crate) fn declared_metadata_range<'a>(
    ctx: &'a ObjectContext,
    symbol: &RecordValue,
    offset: u64,
    length: u64,
    budget: &mut Budget,
) -> Result<DeclaredMetadataRange<'a>, Error> {
    budget.work(16)?;
    require(length > 0, "ABI_CC_METADATA_EXTENT")?;
    add(offset, length, "ABI_CC_METADATA_EXTENT")?;
    let reference = entity_ref(symbol)?;
    match ctx.resolve_declaration(Namespace::Symbol, &reference)? {
        DeclaredEntity::Dependency { slot, declaration } => {
            require(
                token(declaration, "symbol_kind")? == "data",
                "RT_METADATA_DEFINITION",
            )?;
            Ok(DeclaredMetadataRange::Dependency {
                slot,
                declaration: reference.id,
                offset,
                length,
                expected: declaration,
            })
        }
        DeclaredEntity::Local(key) => {
            let declared = ctx.entity(key)?;
            require(token(declared, "kind")? == "data", "RT_METADATA_DEFINITION")?;
            let definition = optional(field(declared, "definition")?)?
                .ok_or_else(|| Error::semantic("RT_METADATA_DEFINITION", String::new()))?;
            require(
                token(definition, "kind")? == "data",
                "RT_METADATA_DEFINITION",
            )?;
            let storage = ctx.local(Namespace::Data, u32_field(definition, "segment")?)?;
            let view = StorageView::parse(ctx.entity(storage)?, budget)?;
            require(
                optional_number(declared, "size")? == Some(view.extent),
                "RT_METADATA_SYMBOL_EXTENT",
            )?;
            require(
                view.fully_defined_readonly(budget)?,
                "RT_METADATA_INITIALIZED_READONLY",
            )?;
            let mut bytes = static_raw_range(ctx, storage, offset, length, budget)?;
            bytes.source = Some(reference);
            Ok(DeclaredMetadataRange::Local(bytes))
        }
    }
}
