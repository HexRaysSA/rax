//! Static relocation programs. Address-dependent evaluation belongs to admission.

use super::records::{flag, number, require, token};
use super::{
    records::{
        PatchInterval, StorageKind, StorageView, reject_overlaps, reject_overlaps_code, u32_field,
    },
    symbols::{Definition, SymbolFacts, SymbolKind, optional_ref, self_id},
};
use crate::context::{DeclaredEntity, Namespace, ObjectContext, entity_ref};
use crate::context::{field, list, optional, signed, text};
use crate::execution::{EscapeKind, LayoutHandle, TypeFacts};
use crate::{Error, limits::Budget, wire::RecordValue};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelocationKind {
    DataAddress,
    DataInteger,
    TlsOffset,
    FunctionToken,
    ImportToken,
    FunctionInteger,
    ImportInteger,
    CodeAddress,
}

impl RelocationKind {
    pub(crate) fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "data_address" => Ok(Self::DataAddress),
            "data_integer" => Ok(Self::DataInteger),
            "tls_offset" => Ok(Self::TlsOffset),
            "function_token" => Ok(Self::FunctionToken),
            "import_token" => Ok(Self::ImportToken),
            "function_integer" => Ok(Self::FunctionInteger),
            "import_integer" => Ok(Self::ImportInteger),
            "code_address" => Ok(Self::CodeAddress),
            _ => Err(Error::semantic("RT_RELOCATION_DOMAIN", value.to_owned())),
        }
    }
    pub(crate) fn integer(self) -> bool {
        matches!(
            self,
            Self::DataInteger | Self::FunctionInteger | Self::ImportInteger
        )
    }
    pub(crate) fn data(self) -> bool {
        matches!(self, Self::DataAddress | Self::DataInteger)
    }
    pub(crate) fn code(self) -> bool {
        matches!(
            self,
            Self::FunctionToken | Self::ImportToken | Self::FunctionInteger | Self::ImportInteger
        )
    }
    pub(crate) fn target_kind(self) -> &'static str {
        match self {
            Self::DataAddress | Self::DataInteger => "data",
            Self::TlsOffset => "tls",
            Self::FunctionToken | Self::FunctionInteger => "function",
            Self::ImportToken | Self::ImportInteger => "import",
            Self::CodeAddress => "function_address",
        }
    }
}

pub(crate) fn validate_step(
    step: &RecordValue,
    offset_name: &str,
    budget: &mut Budget,
) -> Result<(), Error> {
    budget.work(5)?;
    signed(field(step, offset_name)?)?;
    let flags = list(field(step, "flags")?)?;
    budget.work(flags.len() as u64)?;
    let mut previous = None;
    let mut inbounds = false;
    for value in flags {
        let value = text(value)?;
        require(
            ["inbounds", "nuw", "nusw"].contains(&value)
                && previous.is_none_or(|prior| prior < value),
            "RT_PATCH_FLAGS",
        )?;
        inbounds |= value == "inbounds";
        previous = Some(value);
    }
    require(
        !flag(step, "check_base")? || inbounds,
        "RT_PATCH_CHECK_BASE",
    )?;
    if let Some(range) = optional(field(step, "inrange")?)? {
        require(
            signed(field(range, "lower")?)? <= signed(field(range, "upper")?)?,
            "RT_PATCH_INRANGE_BOUNDS",
        )?;
    }
    Ok(())
}

/// Validates only independently decidable structure. It does not calculate a pointer.
pub(crate) fn verify_shape(
    record: &RecordValue,
    budget: &mut Budget,
) -> Result<RelocationKind, Error> {
    budget.work(12)?;
    let kind = RelocationKind::parse(token(record, "kind")?)?;
    let width = number(record, "width")?;
    let bits = number(record, "integer_bits")?;
    require(
        width > 0 && width <= u64::from(u32::MAX) && bits <= u64::from(u32::MAX),
        "RT_RELOCATION_INTEGER_WIDTH",
    )?;
    if kind.integer() {
        require(
            bits > 0 && width == bits.div_ceil(8),
            "RT_RELOCATION_INTEGER_WIDTH",
        )?;
    } else {
        require(
            bits == 0 && [4, 8].contains(&width),
            "RT_RELOCATION_INTEGER_WIDTH",
        )?;
    }
    let derivation = list(field(record, "derivation")?)?;
    require(derivation.len() <= 4096, "RT_PATCH_RESOURCE")?;
    for step in derivation {
        validate_step(step, "offset", budget)?;
    }
    validate_step(record, "addend", budget)?;
    let flags = list(field(record, "flags")?)?;
    if !kind.data() {
        require(
            derivation.is_empty()
                && !flag(record, "check_base")?
                && flags.is_empty()
                && optional(field(record, "inrange")?)?.is_none(),
            "RT_PATCH_UNUSED_POINTER_OPTIONS",
        )?;
    }
    if kind.code() || kind == RelocationKind::CodeAddress {
        require(
            kind.integer() || width == 8 && signed(field(record, "addend")?)? == 0,
            "RT_CODE_RELOCATION",
        )?;
    } else if kind.data() {
        require(kind.integer() || width == 8, "RT_POINTER_WIDTH")?;
    }
    Ok(kind)
}

pub(crate) struct ConstantInitializerFact {
    pub(crate) id: u32,
    pub(crate) kind: StorageKind,
    pub(crate) source: u32,
    pub(crate) offset: u64,
    pub(crate) access_bytes: u64,
    pub(crate) layout: LayoutHandle,
    pub(crate) function: u32,
    pub(crate) association: Option<u32>,
}

fn storage<'a>(
    ctx: &'a ObjectContext,
    kind: StorageKind,
    id: u32,
    budget: &mut Budget,
) -> Result<StorageView<'a>, Error> {
    let namespace = match kind {
        StorageKind::Data => Namespace::Data,
        StorageKind::Tls => Namespace::Tls,
    };
    let value = ctx.entity(ctx.local(namespace, id)?)?;
    StorageView::parse(
        if kind == StorageKind::Tls {
            field(value, "storage")?
        } else {
            value
        },
        budget,
    )
}

pub(crate) fn verify(
    ctx: &ObjectContext,
    types: &TypeFacts,
    symbols: &SymbolFacts,
    budget: &mut Budget,
) -> Result<Vec<ConstantInitializerFact>, Error> {
    types.assert_context(ctx)?;
    require(
        symbols.identity() == ctx.identity() && symbols.context_id() == ctx.context_id(),
        "RT_CONTEXT_MISMATCH",
    )?;
    let root = ctx.root(5)?;
    require(
        number(root, "payload_revision")? == 2,
        "RT_PAYLOAD_REVISION",
    )?;
    let leaves = list(field(root, "relocations")?)?;
    let constants = list(field(root, "constant_initializers")?)?;
    let count = leaves
        .len()
        .checked_add(constants.len())
        .ok_or_else(|| Error::resource("RT_PATCH_RESOURCE", String::new()))?;
    budget.reserve_bytes(
        count
            .checked_mul(std::mem::size_of::<PatchInterval>())
            .ok_or_else(|| Error::resource("RT_PATCH_RESOURCE", String::new()))?,
    )?;
    budget.edges(count)?;
    let mut patches = Vec::with_capacity(count);
    for leaf in leaves {
        let relocation = verify_shape(leaf, budget)?;
        let kind = StorageKind::parse(token(leaf, "source_kind")?)?;
        let id = u32_field(leaf, "source")?;
        let source = storage(ctx, kind, id, budget)?;
        patches.push(PatchInterval::new(
            kind,
            id,
            number(leaf, "offset")?,
            number(leaf, "width")?,
            source.extent,
        )?);
        let reference = entity_ref(field(leaf, "target")?)?;
        match ctx.resolve_declaration(Namespace::Symbol, &reference)? {
            DeclaredEntity::Local(key) => {
                let target = symbols.symbol(key.id())?;
                require(
                    if relocation == RelocationKind::CodeAddress {
                        matches!(target.kind, SymbolKind::Function | SymbolKind::Import | SymbolKind::FunctionAddress)
                    } else { target.kind.as_str() == relocation.target_kind() },
                    "RT_RELOCATION_DOMAIN",
                )?;
                require(
                    !relocation.code()
                        || !matches!(target.definition, Some(Definition::Native { .. })),
                    "RT_NATIVE_PORTABLE_TOKEN",
                )?;
            }
            DeclaredEntity::Dependency { declaration, .. } => {
                require(
                    if relocation == RelocationKind::CodeAddress {
                        ["function", "import", "function_address"].contains(&token(declaration, "symbol_kind")?)
                    } else { token(declaration, "symbol_kind")? == relocation.target_kind() },
                    "RT_RELOCATION_DOMAIN",
                )?;
            }
        }
    }
    reject_overlaps_code(&mut patches, "RT_RELOCATION_OVERLAP", budget)?;
    // Aliases of the same physical segment cannot belong to different selection groups.
    budget.reserve_bytes(
        symbols
            .all()
            .len()
            .checked_mul(160)
            .ok_or_else(|| Error::resource("RT_INITIALIZER_RESOURCE", String::new()))?,
    )?;
    let mut owners: BTreeMap<(StorageKind, u32), Vec<u32>> = BTreeMap::new();
    for symbol in symbols.all().values() {
        budget.work(1)?;
        if let Some((kind, id)) = symbols.physical(symbol.id) {
            let kind = if kind == SymbolKind::Data {
                StorageKind::Data
            } else {
                StorageKind::Tls
            };
            let members = owners.entry((kind, id)).or_default();
            if let Some(prior) = members.first() {
                require(
                    symbols.symbol(*prior)?.comdat == symbol.comdat,
                    "RT_INITIALIZER_SHARED_SELECTION",
                )?;
            }
            members.push(symbol.id);
        }
    }
    budget.reserve_bytes(
        constants
            .len()
            .checked_mul(std::mem::size_of::<ConstantInitializerFact>())
            .ok_or_else(|| Error::resource("RT_INITIALIZER_RESOURCE", String::new()))?,
    )?;
    let mut result = Vec::with_capacity(constants.len());
    let mut previous = None;
    for record in constants {
        budget.work(24)?;
        let id = u32_field(record, "id")?;
        require(
            previous.is_none_or(|prior| prior < id),
            "RT_INITIALIZER_ORDER",
        )?;
        previous = Some(id);
        let kind = StorageKind::parse(token(record, "source_kind")?)?;
        let source = u32_field(record, "source")?;
        let storage = storage(ctx, kind, source, budget)?;
        let layout = types.layout_handle(self_id(
            entity_ref(field(record, "layout")?)?,
            "RT_INITIALIZER_SELF",
        )?)?;
        let physical = types.layout(layout)?;
        let offset = number(record, "offset")?;
        patches.push(PatchInterval::new(
            kind,
            source,
            offset,
            physical.access_bytes,
            storage.extent,
        )?);
        let function = self_id(
            entity_ref(field(record, "function")?)?,
            "RT_INITIALIZER_SELF",
        )?;
        let body = types.function_decl(function)?;
        let signature = types.type_record(body.signature)?;
        require(
            body.abi_signature.is_none()
                && body.escape == EscapeKind::Propagate
                && !body.no_return
                && token(signature, "kind")? == "function"
                && token(signature, "cc")? == "portable"
                && !super::records::flag(signature, "variadic")?
                && list(field(signature, "params")?)?.is_empty()
                && list(field(signature, "param_noundef")?)?.is_empty(),
            "RT_INITIALIZER_SIGNATURE",
        )?;
        let returns = list(field(signature, "results")?)?;
        let promises = list(field(signature, "result_noundef")?)?;
        require(
            returns.len() == 1 && promises.len() == 1 && !crate::context::boolean(&promises[0])?,
            "RT_INITIALIZER_SIGNATURE",
        )?;
        require(
            types.type_equivalent(
                types.type_reference(&returns[0])?,
                physical.execution_type,
                budget,
            )?,
            "RT_INITIALIZER_SIGNATURE",
        )?;
        let association = optional_ref(record, "association")?
            .map(|r| self_id(r, "RT_INITIALIZER_OWNER"))
            .transpose()?;
        let members = owners
            .get(&(kind, source))
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if let Some(owner) = association {
            let owner = symbols.symbol(owner)?;
            require(
                members.contains(&owner.id)
                    && match owner.definition {
                        Some(Definition::Data(id)) => kind == StorageKind::Data && id == source,
                        Some(Definition::Tls(id)) => kind == StorageKind::Tls && id == source,
                        _ => false,
                    },
                "RT_INITIALIZER_SHARED_SELECTION",
            )?;
        } else {
            for owner in members {
                let owner = symbols.symbol(*owner)?;
                require(
                    owner.comdat.is_none()
                        && !["weak", "external_weak", "common"].contains(&owner.binding.as_str()),
                    "RT_INITIALIZER_OWNER_REQUIRED",
                )?;
            }
        }
        result.push(ConstantInitializerFact {
            id,
            kind,
            source,
            offset,
            access_bytes: physical.access_bytes,
            layout,
            function,
            association,
        });
    }
    reject_overlaps(&mut patches, budget)?;
    Ok(result)
}
