//! Declared requirements are retained requests, never a registry or grant.

use super::records::{identifier, number, require, token};
use crate::context::{field, list, text};
use crate::error::Error;
use crate::limits::Budget;
use crate::wire::RecordValue;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const CAPABILITIES: &[&str] = &[
    "memory",
    "file",
    "clock",
    "entropy",
    "thread",
    "sync",
    "process",
    "module",
    "foreign",
    "environment",
    "network",
    "locale",
    "host_value",
];
pub(crate) const LIMITS: &[&str] = &[
    "memory_bytes",
    "atomic_bytes",
    "stack_bytes",
    "threads",
    "modules",
    "code_bytes",
    "helper_chunk_bytes",
    "poll_operations",
    "handles",
];
const KINDS: &[&str] = &[
    "runtime",
    "feature",
    "catalog",
    "library",
    "native_image",
    "personality",
    "host",
];

#[derive(Debug)]
pub(crate) struct DeclaredSupport {
    pub(crate) kind: String,
    pub(crate) name: String,
    pub(crate) version: u32,
}

#[derive(Debug)]
pub(crate) struct RequirementFacts {
    capabilities: BTreeSet<String>,
    support: Vec<DeclaredSupport>,
    limits: BTreeMap<String, u64>,
    obligations: Vec<RuntimeRequirement>,
}

/// Exact source associations, all scoped to the enclosing sealed object context.
/// These are predicates a later admission must discharge, never proof of support.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RuntimeRequirement {
    ProcessProfile,
    Dependency {
        slot: u32,
    },
    Capability {
        index: u32,
    },
    RegisteredSupport {
        index: u32,
    },
    ResourceLimit {
        index: u32,
    },
    SymbolBinding {
        symbol: u32,
    },
    ComdatSelection {
        group: u32,
    },
    NativeSymbol {
        symbol: u32,
        domain: u32,
        image: [u8; 32],
        offset: u64,
        size: u64,
    },
    DataSegment {
        segment: u32,
    },
    TlsSegment {
        segment: u32,
    },
    LeafRelocation {
        index: u32,
    },
    ConstantInitializer {
        id: u32,
    },
    InternalHelper {
        import: u32,
    },
    PortableService {
        import: u32,
    },
    RegisteredHost {
        import: u32,
    },
    ForeignImport {
        import: u32,
    },
    GlobalInitializer {
        index: u32,
    },
    GlobalFinalizer {
        index: u32,
    },
    TlsInitializer {
        segment: u32,
        index: u32,
    },
    TlsDestructor {
        segment: u32,
        index: u32,
    },
    EntryPoint {
        function: u32,
    },
}

impl RequirementFacts {
    pub(crate) fn requests(&self, capability: &str) -> bool {
        self.capabilities.contains(capability)
    }
    pub(crate) fn support(&self) -> &[DeclaredSupport] {
        &self.support
    }
    pub(crate) fn limits(&self) -> &BTreeMap<String, u64> {
        &self.limits
    }
    pub(crate) fn obligations(&self) -> &[RuntimeRequirement] {
        &self.obligations
    }
}

pub(crate) fn verify(value: &RecordValue, budget: &mut Budget) -> Result<RequirementFacts, Error> {
    require(
        number(value, "payload_revision")? == 1,
        "RT_PAYLOAD_REVISION",
    )?;
    let caps = list(field(value, "capabilities")?)?;
    let records = list(field(value, "requirements")?)?;
    let limits = list(field(value, "limits")?)?;
    let count = caps
        .len()
        .checked_add(records.len())
        .and_then(|v| v.checked_add(limits.len()))
        .ok_or_else(|| Error::resource("RT_REQUIREMENT_RESOURCE", String::new()))?;
    budget.work(count as u64)?;
    budget.edges(count)?;
    budget.reserve_bytes(
        count
            .checked_mul(160)
            .ok_or_else(|| Error::resource("RT_REQUIREMENT_RESOURCE", String::new()))?,
    )?;
    let mut capabilities = BTreeSet::new();
    let mut previous = None;
    for item in caps {
        let cap = text(item)?;
        require(
            CAPABILITIES.contains(&cap) && previous.is_none_or(|prior| prior < cap),
            "RT_CAPABILITIES",
        )?;
        budget.reserve_bytes(cap.len())?;
        capabilities.insert(cap.to_owned());
        previous = Some(cap);
    }
    let mut support = Vec::with_capacity(records.len());
    let mut previous = None;
    for item in records {
        let kind = token(item, "kind")?;
        let name = token(item, "name")?;
        let version = number(item, "version")?;
        require(KINDS.contains(&kind), "RT_REQUIREMENT_KIND")?;
        identifier(name)?;
        require(
            version > 0 && version <= u64::from(u32::MAX),
            "RT_REQUIREMENT_VALUE",
        )?;
        if kind == "native_image" {
            require(
                name.len() == 64
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "RT_REQUIREMENT_IMAGE",
            )?;
        }
        let key = (kind, name);
        require(
            previous.is_none_or(|prior| prior < key),
            "RT_REQUIREMENT_ORDER",
        )?;
        budget.reserve_bytes(
            kind.len()
                .checked_add(name.len())
                .ok_or_else(|| Error::resource("RT_REQUIREMENT_RESOURCE", String::new()))?,
        )?;
        support.push(DeclaredSupport {
            kind: kind.to_owned(),
            name: name.to_owned(),
            version: version as u32,
        });
        previous = Some(key);
    }
    let mut declared_limits = BTreeMap::new();
    let mut previous = None;
    for item in limits {
        let name = token(item, "name")?;
        let value = number(item, "value")?;
        require(LIMITS.contains(&name) && value > 0, "RT_LIMIT")?;
        require(previous.is_none_or(|prior| prior < name), "RT_LINK_ORDER")?;
        budget.reserve_bytes(name.len())?;
        declared_limits.insert(name.to_owned(), value);
        previous = Some(name);
    }
    Ok(RequirementFacts {
        capabilities,
        support,
        limits: declared_limits,
        obligations: Vec::new(),
    })
}

pub(crate) fn collect(
    ctx: &crate::context::ObjectContext,
    symbols: &super::symbols::SymbolFacts,
    imports: &BTreeMap<u32, super::imports::ImportFact>,
    facts: &mut RequirementFacts,
    budget: &mut Budget,
) -> Result<(), Error> {
    use super::{
        imports::ImportKind,
        records::u32_field,
        symbols::{Definition, optional_ref, self_id},
    };
    require(
        symbols.identity() == ctx.identity() && symbols.context_id() == ctx.context_id(),
        "RT_CONTEXT_MISMATCH",
    )?;
    require(
        facts.obligations.is_empty(),
        "RT_REQUIREMENT_COLLECTION_STATE",
    )?;
    let root = ctx.root(2)?;
    let manifest = field(root, "manifest")?;
    let mut count = 1_usize;
    // Conservative reserve: every actual runtime record/item may add at most two obligations.
    for (section, fields) in [
        (2, &["symbols", "comdats", "initializers", "finalizers"][..]),
        (4, &["segments"][..]),
        (5, &["relocations", "constant_initializers"][..]),
        (6, &["imports"][..]),
        (7, &["segments"][..]),
        (9, &["capabilities", "requirements", "limits"][..]),
    ] {
        for name in fields {
            count = count
                .checked_add(list(field(ctx.root(section)?, name)?)?.len())
                .ok_or_else(|| Error::resource("RT_REQUIREMENT_RESOURCE", String::new()))?;
        }
    }
    count = count
        .checked_add(list(field(manifest, "dependencies")?)?.len() + 1)
        .ok_or_else(|| Error::resource("RT_REQUIREMENT_RESOURCE", String::new()))?;
    for segment in list(field(ctx.root(7)?, "segments")?)? {
        for name in ["initializers", "destructors"] {
            count = count
                .checked_add(list(field(segment, name)?)?.len())
                .ok_or_else(|| Error::resource("RT_REQUIREMENT_RESOURCE", String::new()))?;
        }
    }
    let capacity = count
        .checked_mul(2)
        .ok_or_else(|| Error::resource("RT_REQUIREMENT_RESOURCE", String::new()))?;
    budget.reserve_bytes(
        capacity
            .checked_mul(std::mem::size_of::<RuntimeRequirement>())
            .ok_or_else(|| Error::resource("RT_REQUIREMENT_RESOURCE", String::new()))?,
    )?;
    budget.work(capacity as u64)?;
    budget.edges(capacity)?;
    let mut obligations = Vec::with_capacity(capacity);
    obligations.push(RuntimeRequirement::ProcessProfile);
    for dependency in list(field(manifest, "dependencies")?)? {
        obligations.push(RuntimeRequirement::Dependency {
            slot: u32_field(dependency, "slot")?,
        });
    }
    for symbol in symbols.all().values() {
        obligations.push(RuntimeRequirement::SymbolBinding { symbol: symbol.id });
        if let Some(Definition::Native {
            image,
            domain,
            offset,
            size,
        }) = symbol.definition
        {
            obligations.push(RuntimeRequirement::NativeSymbol {
                symbol: symbol.id,
                domain,
                image,
                offset,
                size,
            });
        }
    }
    for group in list(field(root, "comdats")?)? {
        obligations.push(RuntimeRequirement::ComdatSelection {
            group: u32_field(group, "id")?,
        });
    }
    for (name, kind) in [("initializers", true), ("finalizers", false)] {
        for index in 0..list(field(root, name)?)?.len() {
            let index = u32::try_from(index)
                .map_err(|_| Error::resource("RT_REQUIREMENT_RESOURCE", String::new()))?;
            obligations.push(if kind {
                RuntimeRequirement::GlobalInitializer { index }
            } else {
                RuntimeRequirement::GlobalFinalizer { index }
            });
        }
    }
    if let Some(entry) = optional_ref(manifest, "entry")? {
        obligations.push(RuntimeRequirement::EntryPoint {
            function: self_id(entry, "RT_ENTRY")?,
        });
    }
    for segment in list(field(ctx.root(4)?, "segments")?)? {
        obligations.push(RuntimeRequirement::DataSegment {
            segment: u32_field(segment, "id")?,
        });
    }
    for segment in list(field(ctx.root(7)?, "segments")?)? {
        let id = u32_field(field(segment, "storage")?, "id")?;
        obligations.push(RuntimeRequirement::TlsSegment { segment: id });
        for (name, kind) in [("initializers", true), ("destructors", false)] {
            for index in 0..list(field(segment, name)?)?.len() {
                let index = u32::try_from(index)
                    .map_err(|_| Error::resource("RT_REQUIREMENT_RESOURCE", String::new()))?;
                obligations.push(if kind {
                    RuntimeRequirement::TlsInitializer { segment: id, index }
                } else {
                    RuntimeRequirement::TlsDestructor { segment: id, index }
                });
            }
        }
    }
    for index in 0..list(field(ctx.root(5)?, "relocations")?)?.len() {
        obligations.push(RuntimeRequirement::LeafRelocation {
            index: u32::try_from(index)
                .map_err(|_| Error::resource("RT_REQUIREMENT_RESOURCE", String::new()))?,
        });
    }
    for record in list(field(ctx.root(5)?, "constant_initializers")?)? {
        obligations.push(RuntimeRequirement::ConstantInitializer {
            id: u32_field(record, "id")?,
        });
    }
    for import in imports.values() {
        obligations.push(match import.kind {
            ImportKind::Internal => RuntimeRequirement::InternalHelper { import: import.id },
            ImportKind::Service => RuntimeRequirement::PortableService { import: import.id },
            ImportKind::Host => RuntimeRequirement::RegisteredHost { import: import.id },
            ImportKind::Foreign => RuntimeRequirement::ForeignImport { import: import.id },
        });
    }
    for (name, kind) in [("capabilities", 0), ("requirements", 1), ("limits", 2)] {
        for index in 0..list(field(ctx.root(9)?, name)?)?.len() {
            let index = u32::try_from(index)
                .map_err(|_| Error::resource("RT_REQUIREMENT_RESOURCE", String::new()))?;
            obligations.push(match kind {
                0 => RuntimeRequirement::Capability { index },
                1 => RuntimeRequirement::RegisteredSupport { index },
                _ => RuntimeRequirement::ResourceLimit { index },
            });
        }
    }
    facts.obligations = obligations;
    Ok(())
}
