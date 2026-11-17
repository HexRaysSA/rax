//! Actual local symbol ownership and consumer declaration structure.
//! No provider selection or source-ABI equality is inferred by this phase.

use super::records::{
    alignment, identifier, number, optional_number, ordered, require, token, u32_field,
};
use crate::context::{
    ContextId, EntityRef, ModuleRef, Namespace, ObjectContext, bytes, entity_ref, field, list,
    optional, unsigned,
};
use crate::{Error, limits::Budget};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SymbolKind {
    Function,
    Data,
    Tls,
    Import,
    FunctionAddress,
}
impl SymbolKind {
    pub(crate) fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "function" => Ok(Self::Function),
            "data" => Ok(Self::Data),
            "tls" => Ok(Self::Tls),
            "import" => Ok(Self::Import),
            "function_address" => Ok(Self::FunctionAddress),
            _ => Err(Error::semantic("RT_SYMBOL_KIND", value.to_owned())),
        }
    }
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::Data => "data",
            Self::Tls => "tls",
            Self::Import => "import",
            Self::FunctionAddress => "function_address",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourceLinkage {
    None,
    C,
    Cpp,
}
impl SourceLinkage {
    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "none" => Ok(Self::None),
            "c" => Ok(Self::C),
            "cpp" => Ok(Self::Cpp),
            _ => Err(Error::semantic("RT_SOURCE_LINKAGE", value.to_owned())),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Definition {
    Function(u32),
    Data(u32),
    Tls(u32),
    Import(u32),
    Alias(u32),
    Common {
        size: u64,
        alignment: u64,
    },
    Native {
        image: [u8; 32],
        domain: u32,
        offset: u64,
        size: u64,
    },
}

#[derive(Debug)]
pub(crate) struct SymbolFact {
    pub(crate) id: u32,
    pub(crate) kind: SymbolKind,
    pub(crate) source_linkage: SourceLinkage,
    pub(crate) binding: String,
    pub(crate) visibility: String,
    pub(crate) execution: EntityRef,
    pub(crate) nominal: Option<EntityRef>,
    pub(crate) abi_signature: Option<EntityRef>,
    pub(crate) definition: Option<Definition>,
    pub(crate) size: Option<u64>,
    pub(crate) alignment: u64,
    pub(crate) comdat: Option<u32>,
    pub(crate) fallback: Option<EntityRef>,
}

pub(crate) struct SymbolFacts {
    identity: [u8; 32],
    context_id: ContextId,
    symbols: BTreeMap<u32, SymbolFact>,
    physical: BTreeMap<u32, (SymbolKind, u32)>,
}
impl SymbolFacts {
    pub(crate) fn identity(&self) -> [u8; 32] {
        self.identity
    }
    pub(crate) fn context_id(&self) -> ContextId {
        self.context_id
    }
    pub(crate) fn symbol(&self, id: u32) -> Result<&SymbolFact, Error> {
        self.symbols
            .get(&id)
            .ok_or_else(|| Error::semantic("RT_SYMBOL_REFERENCE", id.to_string()))
    }
    pub(crate) fn all(&self) -> &BTreeMap<u32, SymbolFact> {
        &self.symbols
    }
    pub(crate) fn physical(&self, id: u32) -> Option<(SymbolKind, u32)> {
        self.physical.get(&id).copied()
    }
}

pub(crate) fn optional_ref(
    value: &crate::wire::RecordValue,
    name: &str,
) -> Result<Option<EntityRef>, Error> {
    optional(field(value, name)?)?.map(entity_ref).transpose()
}

pub(crate) fn self_id(reference: EntityRef, code: &'static str) -> Result<u32, Error> {
    require(reference.module == ModuleRef::SelfModule, code)?;
    Ok(reference.id)
}

pub(crate) fn verify_local(ctx: &ObjectContext, budget: &mut Budget) -> Result<SymbolFacts, Error> {
    let root = ctx.root(2)?;
    require(
        number(root, "payload_revision")? == 2,
        "RT_PAYLOAD_REVISION",
    )?;
    let records = ordered(field(root, "symbols")?, "id", budget)?;
    budget.reserve_bytes(
        records
            .len()
            .checked_mul(512)
            .ok_or_else(|| Error::resource("RT_SYMBOL_RESOURCE", String::new()))?,
    )?;
    let mut symbols = BTreeMap::new();
    let mut names = BTreeSet::new();
    for (id, value) in records {
        budget.work(32)?;
        let namespace = token(value, "namespace")?;
        let name = token(value, "name")?;
        identifier(namespace)?;
        identifier(name)?;
        budget.reserve_bytes(
            namespace
                .len()
                .checked_add(name.len())
                .ok_or_else(|| Error::resource("RT_SYMBOL_RESOURCE", String::new()))?,
        )?;
        require(names.insert((namespace, name)), "RT_SYMBOL_DUPLICATE")?;
        let kind = SymbolKind::parse(token(value, "kind")?)?;
        let source_linkage = SourceLinkage::parse(token(value, "source_linkage")?)?;
        let binding = token(value, "binding")?;
        let visibility = token(value, "visibility")?;
        require(
            ["local", "strong", "weak", "external_weak", "common"].contains(&binding),
            "RT_SYMBOL_KIND",
        )?;
        require(
            ["default", "hidden", "protected"].contains(&visibility),
            "RT_SYMBOL_VISIBILITY",
        )?;
        let align = number(value, "alignment")?;
        require(alignment(align), "RT_SYMBOL_VISIBILITY")?;
        let abi_signature = optional_ref(value, "abi_signature")?;
        if let Some(reference) = abi_signature {
            ctx.local(
                Namespace::CallSignature,
                self_id(reference, "RT_SOURCE_PLAN_SELF")?,
            )?;
        }
        let execution = entity_ref(field(value, "execution")?)?;
        ctx.resolve_declaration(Namespace::ExecutionType, &execution)?;
        let nominal = optional_ref(value, "nominal")?;
        if let Some(reference) = nominal {
            ctx.resolve_declaration(Namespace::Nominal, &reference)?;
        }
        require(
            nominal.is_some() || source_linkage == SourceLinkage::None,
            "RT_SOURCE_LINKAGE_WITHOUT_NOMINAL",
        )?;
        if kind == SymbolKind::FunctionAddress {
            require(
                nominal.is_some()
                    && source_linkage != SourceLinkage::None
                    && abi_signature.is_none()
                    && optional_number(value, "size")?.is_none()
                    && align == 1
                    && optional_number(value, "comdat")?.is_none()
                    && optional_ref(value, "fallback")?.is_none()
                    && ["strong", "weak", "external_weak"].contains(&binding),
                "RT_FUNCTION_ADDRESS_SHAPE",
            )?;
            if let Some(definition) = optional(field(value, "definition")?)? {
                require(token(definition, "kind")? == "native", "RT_FUNCTION_ADDRESS_DEFINITION")?;
                require(["strong", "weak"].contains(&binding), "RT_FUNCTION_ADDRESS_BINDING")?;
            }
        }
        let definition = match optional(field(value, "definition")?)? {
            None => None,
            Some(record) => Some(match token(record, "kind")? {
                "function" | "alias" => {
                    let reference = entity_ref(field(record, "target")?)?;
                    let target = self_id(reference, "RT_DEFINITION_SELF")?;
                    if token(record, "kind")? == "function" {
                        require(kind == SymbolKind::Function, "RT_DEFINITION_DOMAIN")?;
                        ctx.local(Namespace::Function, target)?;
                        Definition::Function(target)
                    } else {
                        ctx.local(Namespace::Symbol, target)?;
                        Definition::Alias(target)
                    }
                }
                "data" | "tls" | "import" => {
                    let actual = token(record, "kind")?;
                    require(actual == kind.as_str(), "RT_DEFINITION_DOMAIN")?;
                    let target = u32_field(
                        record,
                        if actual == "import" {
                            "import"
                        } else {
                            "segment"
                        },
                    )?;
                    match kind {
                        SymbolKind::Data => {
                            ctx.local(Namespace::Data, target)?;
                            Definition::Data(target)
                        }
                        SymbolKind::Tls => {
                            ctx.local(Namespace::Tls, target)?;
                            Definition::Tls(target)
                        }
                        SymbolKind::Import => {
                            ctx.local(Namespace::Import, target)?;
                            Definition::Import(target)
                        }
                        _ => return Err(Error::semantic("RT_DEFINITION_DOMAIN", String::new())),
                    }
                }
                "common" => {
                    let align = number(record, "alignment")?;
                    require(
                        binding == "common" && kind == SymbolKind::Data && alignment(align),
                        "RT_COMMON_DEFINITION",
                    )?;
                    Definition::Common {
                        size: number(record, "size")?,
                        alignment: align,
                    }
                }
                "native" => {
                    require(
                        matches!(kind, SymbolKind::Function | SymbolKind::FunctionAddress)
                            && nominal.is_some(),
                        "RT_NATIVE_DEFINITION",
                    )?;
                    let image: [u8; 32] = bytes(field(record, "image")?)?
                        .try_into()
                        .map_err(|_| Error::semantic("RT_NATIVE_DEFINITION", String::new()))?;
                    let size = number(record, "size")?;
                    require(size > 0, "RT_NATIVE_DEFINITION")?;
                    require(number(record, "offset")?.checked_add(size).is_some(), "RT_NATIVE_DEFINITION")?;
                    let domain = u32_field(record, "domain")?;
                    ctx.local(Namespace::Domain, domain)?;
                    Definition::Native {
                        image,
                        domain,
                        offset: number(record, "offset")?,
                        size,
                    }
                }
                _ => return Err(Error::semantic("RT_DEFINITION_DOMAIN", String::new())),
            }),
        };
        require(
            binding != "local" || definition.is_some(),
            "RT_LOCAL_UNDEFINED",
        )?;
        let fallback = optional_ref(value, "fallback")?;
        if let Some(reference) = fallback {
            require(
                definition.is_none() && ["weak", "external_weak"].contains(&binding),
                "RT_FALLBACK_POLICY",
            )?;
            ctx.resolve_declaration(Namespace::Symbol, &reference)?;
        }
        let comdat = optional_number(value, "comdat")?
            .map(|v| u32::try_from(v).map_err(|_| Error::semantic("RT_COMDAT", String::new())))
            .transpose()?;
        budget.reserve_bytes(binding.len() + visibility.len())?;
        symbols.insert(
            id,
            SymbolFact {
                id,
                kind,
                source_linkage,
                binding: binding.into(),
                visibility: visibility.into(),
                execution,
                nominal,
                abi_signature,
                definition,
                size: optional_number(value, "size")?,
                alignment: align,
                comdat,
                fallback,
            },
        );
    }
    // Iterative tri-color DFS over BOTH alias and local fallback edges.
    budget.reserve_bytes(
        symbols
            .len()
            .checked_mul(256)
            .ok_or_else(|| Error::resource("RT_SYMBOL_RESOURCE", String::new()))?,
    )?;
    let mut colors = BTreeMap::new();
    let mut physical = BTreeMap::new();
    for &start in symbols.keys() {
        if colors.get(&start) == Some(&2) {
            continue;
        }
        let mut stack = vec![(start, false)];
        while let Some((id, leaving)) = stack.pop() {
            budget.work(1)?;
            let symbol = &symbols[&id];
            if leaving {
                colors.insert(id, 2);
                let owner = match symbol.definition {
                    Some(Definition::Data(segment)) => Some((SymbolKind::Data, segment)),
                    Some(Definition::Tls(segment)) => Some((SymbolKind::Tls, segment)),
                    Some(Definition::Alias(target)) => physical.get(&target).copied(),
                    _ => None,
                };
                if let Some(owner) = owner {
                    physical.insert(id, owner);
                }
                continue;
            }
            match colors.get(&id) {
                Some(2) => continue,
                Some(1) => return Err(Error::semantic("RT_ALIAS_CYCLE", String::new())),
                _ => {}
            }
            colors.insert(id, 1);
            stack.push((id, true));
            if let Some(reference) = symbol.fallback {
                if reference.module == ModuleRef::SelfModule {
                    stack.push((reference.id, false));
                }
            }
            if let Some(Definition::Alias(target)) = symbol.definition {
                require(symbols[&target].kind == symbol.kind, "RT_ALIAS_KIND")?;
                stack.push((target, false));
            }
        }
    }
    let groups = ordered(field(root, "comdats")?, "id", budget)?;
    let mut members = BTreeSet::new();
    budget.reserve_bytes(
        symbols
            .len()
            .checked_mul(96)
            .ok_or_else(|| Error::resource("RT_SYMBOL_RESOURCE", String::new()))?,
    )?;
    for (id, group) in groups {
        let selection = token(group, "selection")?;
        require(
            [
                "any",
                "exactmatch",
                "largest",
                "samesize",
                "noduplicates",
                "nodeduplicate",
            ]
            .contains(&selection),
            "RT_COMDAT",
        )?;
        let values = list(field(group, "members")?)?;
        budget.work(values.len() as u64)?;
        budget.edges(values.len())?;
        require(!values.is_empty(), "RT_COMDAT")?;
        let key = u32_field(group, "key_symbol")?;
        let mut found_key = false;
        for member in values {
            let member = u32::try_from(unsigned(member)?)
                .map_err(|_| Error::semantic("RT_COMDAT_MEMBERSHIP", String::new()))?;
            require(
                symbols.get(&member).is_some_and(|s| s.comdat == Some(id))
                    && members.insert(member),
                "RT_COMDAT_MEMBERSHIP",
            )?;
            found_key |= member == key;
        }
        require(found_key, "RT_COMDAT")?;
    }
    for symbol in symbols.values() {
        require(
            symbol.comdat.is_some() == members.contains(&symbol.id),
            "RT_COMDAT_MEMBERSHIP",
        )?;
    }
    Ok(SymbolFacts {
        identity: ctx.identity(),
        context_id: ctx.context_id(),
        symbols,
        physical,
    })
}

/// All locally decidable manifest/declaration fields, without provider fabrication.
pub(crate) fn verify_manifest(
    ctx: &ObjectContext,
    types: &crate::execution::TypeFacts,
    budget: &mut Budget,
) -> Result<(), Error> {
    use crate::context::{DeclaredEntity, boolean};
    types.assert_context(ctx)?;
    let root = ctx.root(2)?;
    let manifest = field(root, "manifest")?;
    let key = field(manifest, "key")?;
    identifier(token(key, "namespace")?)?;
    identifier(token(key, "name")?)?;
    require(
        bytes(field(manifest, "identity")?)? == ctx.identity(),
        "RT_CONTENT_IDENTITY",
    )?;
    require(
        bytes(field(manifest, "site")?)? == bytes(field(ctx.root(10)?, "identity")?)?,
        "RT_SITE_IDENTITY",
    )?;
    let kind = token(manifest, "kind")?;
    require(["object", "image"].contains(&kind), "RT_MODULE_KIND")?;
    require((kind == "image") == ctx.parsed().image(), "RT_MODULE_KIND")?;
    let entry = optional_ref(manifest, "entry")?;
    require((kind == "image") == entry.is_some(), "RT_IMAGE_ENTRY")?;
    if let Some(reference) = entry {
        ctx.local(Namespace::Function, self_id(reference, "RT_ENTRY")?)?;
    }
    require(
        ["linux", "darwin", "windows"].contains(&token(manifest, "personality")?),
        "RT_PERSONALITY",
    )?;
    require(
        ["none", "x86_64", "aarch64"].contains(&token(manifest, "foreign_isa")?),
        "RT_FOREIGN_ISA",
    )?;
    for dependency in ordered(field(manifest, "dependencies")?, "slot", budget)?.values() {
        budget.work(12)?;
        let key = field(dependency, "key")?;
        identifier(token(key, "namespace")?)?;
        identifier(token(key, "name")?)?;
        let low = number(dependency, "minimum_minor")?;
        let high = optional_number(dependency, "maximum_minor")?;
        let baseline = number(key, "abi_minor")?;
        require(
            low <= baseline && high.is_none_or(|high| baseline <= high),
            "RT_VERSION_BASELINE",
        )?;
        require(high.is_none_or(|high| low <= high), "RT_VERSION_RANGE")?;
        let declarations = list(field(dependency, "declarations")?)?;
        budget.reserve_bytes(
            declarations
                .len()
                .checked_mul(256)
                .ok_or_else(|| Error::resource("RT_DECLARATION_RESOURCE", String::new()))?,
        )?;
        let mut names = BTreeSet::new();
        for declaration in declarations {
            budget.work(16)?;
            let kind = token(declaration, "kind")?;
            let namespace = token(declaration, "namespace")?;
            let name = token(declaration, "name")?;
            require(
                ["type", "function", "symbol", "nominal", "recipe"].contains(&kind)
                    && names.insert((kind, namespace, name)),
                "RT_DECLARATION_IDENTITY",
            )?;
            identifier(namespace)?;
            identifier(name)?;
            let symbol_kind = token(declaration, "symbol_kind")?;
            if kind == "symbol" {
                SymbolKind::parse(symbol_kind)?;
            } else {
                require(symbol_kind == "none", "RT_DECLARATION_SYMBOL_KIND")?;
            }
            let linkage = SourceLinkage::parse(token(declaration, "source_linkage")?)?;
            require(
                ["function", "symbol"].contains(&kind) || linkage == SourceLinkage::None,
                "RT_SOURCE_LINKAGE",
            )?;
            for (field_name, namespace) in [
                ("execution", Namespace::ExecutionType),
                ("nominal", Namespace::Nominal),
                ("abi_signature", Namespace::CallSignature),
            ] {
                if let Some(reference) = optional_ref(declaration, field_name)? {
                    ctx.local(namespace, self_id(reference, "RT_DECLARATION_SELF")?)?;
                }
            }
            require(
                !boolean(field(declaration, "weak")?)? || ["function", "symbol"].contains(&kind),
                "RT_WEAK_DECLARATION_KIND",
            )?;
            if kind == "function" {
                let reference = optional(field(declaration, "execution")?)?
                    .ok_or_else(|| Error::semantic("RT_DECLARATION_FUNCTION_TYPE", "missing execution"))?;
                let expected = types.type_reference(reference)?;
                require(
                    token(types.type_record(expected)?, "kind")? == "function",
                    "RT_DECLARATION_FUNCTION_TYPE",
                )?;
            }
            if kind == "symbol" {
                let execution = optional(field(declaration, "execution")?)?;
                let callable = ["function", "import"].contains(&symbol_kind);
                require(execution.is_some() || !(callable || symbol_kind == "function_address"), "RT_DECLARATION_EXECUTION")?;
                if let Some(reference) = execution {
                    let ty = types.type_reference(reference)?;
                    let is_function = token(types.type_record(ty)?, "kind")? == "function";
                    require(callable == is_function, "RT_DECLARATION_SYMBOL_TYPE")?;
                    if symbol_kind == "function_address" {
                        require(token(types.type_record(ty)?, "kind")? == "code_address",
                                "RT_DECLARATION_SYMBOL_TYPE")?;
                    }
                }
            }
        }
    }
    let exports = ordered(field(manifest, "exports")?, "id", budget)?;
    budget.reserve_bytes(
        exports
            .len()
            .checked_mul(256)
            .ok_or_else(|| Error::resource("RT_EXPORT_RESOURCE", String::new()))?,
    )?;
    let mut names = BTreeSet::new();
    for exported in exports.values() {
        budget.work(16)?;
        let kind = token(exported, "kind")?;
        let namespace = token(exported, "namespace")?;
        let name = token(exported, "name")?;
        require(names.insert((kind, namespace, name)), "RT_EXPORT_IDENTITY")?;
        identifier(namespace)?;
        identifier(name)?;
        let expected = match kind {
            "function" => Namespace::Function,
            "symbol" => Namespace::Symbol,
            "type" => Namespace::ExecutionType,
            "nominal" => Namespace::Nominal,
            "recipe" => Namespace::Recipe,
            _ => return Err(Error::semantic("RT_EXPORT_IDENTITY", String::new())),
        };
        let linkage = SourceLinkage::parse(token(exported, "source_linkage")?)?;
        require(
            ["function", "symbol"].contains(&kind) || linkage == SourceLinkage::None,
            "RT_SOURCE_LINKAGE",
        )?;
        let target = entity_ref(field(exported, "target")?)?;
        ctx.local(expected, self_id(target, "RT_EXPORT_SELF")?)?;
        for (field_name, namespace) in [
            ("execution", Namespace::ExecutionType),
            ("nominal", Namespace::Nominal),
            ("abi_signature", Namespace::CallSignature),
        ] {
            if let Some(reference) = optional_ref(exported, field_name)? {
                ctx.local(namespace, self_id(reference, "RT_EXPORT_SELF")?)?;
            }
        }
    }
    for name in ["initializers", "finalizers"] {
        let records = list(field(root, name)?)?;
        budget.reserve_bytes(
            records
                .len()
                .checked_mul(96)
                .ok_or_else(|| Error::resource("RT_INITIALIZER_RESOURCE", String::new()))?,
        )?;
        let mut ordinals = BTreeSet::new();
        for record in records {
            budget.work(8)?;
            require(
                ordinals.insert(u32_field(record, "ordinal")?),
                "RT_INIT_ORDINAL",
            )?;
            let reference = entity_ref(field(record, "function")?)?;
            let signature = match ctx.resolve_declaration(Namespace::Function, &reference)? {
                DeclaredEntity::Local(key) => types.function_decl(key.id())?.signature,
                DeclaredEntity::Dependency { declaration, .. } => {
                    let reference = optional(field(declaration, "execution")?)?
                        .ok_or_else(|| Error::semantic("RT_INIT_SIGNATURE", String::new()))?;
                    types.type_reference(reference)?
                }
            };
            let signature = types.type_record(signature)?;
            require(
                token(signature, "kind")? == "function"
                    && list(field(signature, "params")?)?.is_empty()
                    && list(field(signature, "results")?)?.is_empty(),
                "RT_INIT_SIGNATURE",
            )?;
            if let Some(reference) = optional_ref(record, "association")? {
                ctx.resolve_declaration(Namespace::Symbol, &reference)?;
            }
        }
    }
    Ok(())
}
