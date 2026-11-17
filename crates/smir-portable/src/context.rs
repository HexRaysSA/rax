//! Immutable, namespace-separated syntax context; lookups are not semantic proof.

use crate::{
    Error,
    limits::Budget,
    wire::{ParsedObject, RecordValue},
};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) fn record(value: &RecordValue) -> Result<&BTreeMap<String, RecordValue>, Error> {
    match value {
        RecordValue::Record(value) => Ok(value),
        _ => Err(Error::semantic("P2_RECORD", "expected record")),
    }
}
pub(crate) fn field<'a>(value: &'a RecordValue, name: &str) -> Result<&'a RecordValue, Error> {
    record(value)?
        .get(name)
        .ok_or_else(|| Error::semantic("P2_FIELD", name))
}
pub(crate) fn list(value: &RecordValue) -> Result<&[RecordValue], Error> {
    match value {
        RecordValue::Vector(value) => Ok(value),
        _ => Err(Error::semantic("P2_LIST", "expected list")),
    }
}
pub(crate) fn text(value: &RecordValue) -> Result<&str, Error> {
    match value {
        RecordValue::Text(value) => Ok(value),
        _ => Err(Error::semantic("P2_TEXT", "expected text")),
    }
}
pub(crate) fn unsigned(value: &RecordValue) -> Result<u64, Error> {
    match value {
        RecordValue::Unsigned(value) => Ok(*value),
        _ => Err(Error::semantic("P2_UNSIGNED", "expected unsigned integer")),
    }
}
pub(crate) fn signed(value: &RecordValue) -> Result<i64, Error> {
    match value {
        RecordValue::Signed(value) => Ok(*value),
        _ => Err(Error::semantic("P2_SIGNED", "expected signed integer")),
    }
}
pub(crate) fn boolean(value: &RecordValue) -> Result<bool, Error> {
    match value {
        RecordValue::Boolean(value) => Ok(*value),
        _ => Err(Error::semantic("P2_BOOLEAN", "expected boolean")),
    }
}
pub(crate) fn bytes(value: &RecordValue) -> Result<&[u8], Error> {
    match value {
        RecordValue::Bytes(value) => Ok(value),
        _ => Err(Error::semantic("P2_BYTES", "expected bytes")),
    }
}
pub(crate) fn optional(value: &RecordValue) -> Result<Option<&RecordValue>, Error> {
    match value {
        RecordValue::Option(value) => Ok(value.as_deref()),
        _ => Err(Error::semantic("P2_OPTION", "expected option")),
    }
}
fn id(value: &RecordValue) -> Result<u32, Error> {
    u32::try_from(unsigned(value)?).map_err(|_| Error::semantic("P2_ID", "ID exceeds u32"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ContextId(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ModuleRef {
    SelfModule,
    Dependency { slot: u32 },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct EntityRef {
    pub module: ModuleRef,
    pub id: u32,
}

pub(crate) fn entity_ref(value: &RecordValue) -> Result<EntityRef, Error> {
    let members = record(value)?;
    if members.len() != 2 {
        return Err(Error::semantic("P2_REFERENCE", "entity reference fields"));
    }
    let module = field(value, "module")?;
    let module = match text(field(module, "kind")?)? {
        "self" if record(module)?.len() == 1 => ModuleRef::SelfModule,
        "dependency" if record(module)?.len() == 2 => ModuleRef::Dependency {
            slot: id(field(module, "slot")?)?,
        },
        _ => return Err(Error::semantic("P2_REFERENCE", "module reference kind")),
    };
    Ok(EntityRef {
        module,
        id: id(field(value, "id")?)?,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Namespace {
    ExecutionType,
    MemoryLayout,
    Function,
    Exception,
    Symbol,
    Data,
    Import,
    Tls,
    Nominal,
    ObjectLayout,
    StorageBinding,
    CallSignature,
    Domain,
    Recipe,
    Personality,
    Unwind,
    Catch,
    Bridge,
    Journal,
}

const TABLES: [(Namespace, u16, &str); 19] = [
    (Namespace::ExecutionType, 1, "types"),
    (Namespace::MemoryLayout, 1, "memory_layouts"),
    (Namespace::Function, 3, "functions"),
    (Namespace::Exception, 8, "functions"),
    (Namespace::Symbol, 2, "symbols"),
    (Namespace::Data, 4, "segments"),
    (Namespace::Import, 6, "imports"),
    (Namespace::Tls, 7, "segments"),
    (Namespace::Nominal, 10, "types"),
    (Namespace::ObjectLayout, 10, "layouts"),
    (Namespace::StorageBinding, 10, "storage_bindings"),
    (Namespace::CallSignature, 10, "signatures"),
    (Namespace::Domain, 10, "domains"),
    (Namespace::Recipe, 10, "recipes"),
    (Namespace::Personality, 10, "personalities"),
    (Namespace::Unwind, 10, "unwind"),
    (Namespace::Catch, 10, "catches"),
    (Namespace::Bridge, 10, "bridges"),
    (Namespace::Journal, 10, "journals"),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct EntityKey {
    context: ContextId,
    namespace: Namespace,
    id: u32,
}
impl EntityKey {
    pub(crate) fn id(&self) -> u32 {
        self.id
    }
    pub(crate) fn namespace(&self) -> Namespace {
        self.namespace
    }
    pub(crate) fn context_id(&self) -> ContextId {
        self.context
    }
}

pub(crate) enum DeclaredEntity<'a> {
    Local(EntityKey),
    Dependency {
        slot: u32,
        declaration: &'a RecordValue,
    },
}

/// O(N log N) construction, O(N) index space; all derived indexes are precharged.
pub(crate) struct ObjectContext {
    object: ParsedObject,
    brand: ContextId,
    indexes: BTreeMap<Namespace, BTreeMap<u32, usize>>,
    dependencies: BTreeMap<u32, usize>,
    declarations: BTreeMap<(u32, u32), usize>,
}

fn charge_index(budget: &mut Budget, count: usize) -> Result<(), Error> {
    budget
        .work(u64::try_from(count).map_err(|_| Error::resource("P2_INDEX_LIMIT", "index size"))?)?;
    budget.edges(count)?;
    // Conservative per-entry B-tree storage bound, including sparse nodes.
    budget.reserve_bytes(
        count
            .checked_mul(512)
            .ok_or_else(|| Error::resource("P2_INDEX_LIMIT", "index allocation overflow"))?,
    )
}

impl ObjectContext {
    pub(crate) fn new(object: ParsedObject, budget: &mut Budget) -> Result<Self, Error> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let mut current = NEXT.load(Ordering::Relaxed);
        let brand = loop {
            budget.work(1)?;
            let next = current
                .checked_add(1)
                .ok_or_else(|| Error::resource("P2_CONTEXT_LIMIT", "context nonce exhausted"))?;
            match NEXT.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break ContextId(current),
                Err(observed) => current = observed,
            }
        };
        budget.reserve_bytes(TABLES.len() * 512)?;
        let mut indexes = BTreeMap::new();
        for (namespace, section, collection) in TABLES {
            let values = list(field(object.root(section)?, collection)?)?;
            charge_index(budget, values.len())?;
            let mut index = BTreeMap::new();
            for (position, value) in values.iter().enumerate() {
                let identifier = match namespace {
                    Namespace::Exception => id(field(value, "function")?)?,
                    Namespace::Tls => id(field(field(value, "storage")?, "id")?)?,
                    _ => id(field(value, "id")?)?,
                };
                if index.insert(identifier, position).is_some() {
                    return Err(Error::semantic(
                        "P2_DUPLICATE_ID",
                        format!("{namespace:?}:{identifier}"),
                    ));
                }
            }
            indexes.insert(namespace, index);
        }
        let dependency_records = list(field(field(object.root(2)?, "manifest")?, "dependencies")?)?;
        charge_index(budget, dependency_records.len())?;
        let mut dependencies = BTreeMap::new();
        let mut declarations = BTreeMap::new();
        for (position, dependency) in dependency_records.iter().enumerate() {
            let slot = id(field(dependency, "slot")?)?;
            if dependencies.insert(slot, position).is_some() {
                return Err(Error::semantic("P2_DUPLICATE_SLOT", "dependency slot"));
            }
            let entries = list(field(dependency, "declarations")?)?;
            charge_index(budget, entries.len())?;
            for (position, declaration) in entries.iter().enumerate() {
                let identifier = id(field(declaration, "id")?)?;
                if declarations.insert((slot, identifier), position).is_some() {
                    return Err(Error::semantic(
                        "P2_DUPLICATE_DECLARATION",
                        "consumer declaration",
                    ));
                }
            }
        }
        Ok(Self {
            object,
            brand,
            indexes,
            dependencies,
            declarations,
        })
    }

    pub(crate) fn root(&self, section: u16) -> Result<&RecordValue, Error> {
        self.object.root(section)
    }
    pub(crate) fn identity(&self) -> [u8; 32] {
        self.object.identity()
    }
    pub(crate) fn context_id(&self) -> ContextId {
        self.brand
    }
    pub(crate) fn parsed(&self) -> &ParsedObject {
        &self.object
    }

    pub(crate) fn local(&self, namespace: Namespace, id: u32) -> Result<EntityKey, Error> {
        if !self
            .indexes
            .get(&namespace)
            .is_some_and(|table| table.contains_key(&id))
        {
            return Err(Error::semantic(
                "P2_LOCAL_REFERENCE",
                format!("{namespace:?}:{id}"),
            ));
        }
        Ok(EntityKey {
            context: self.brand,
            namespace,
            id,
        })
    }

    pub(crate) fn entity(&self, key: EntityKey) -> Result<&RecordValue, Error> {
        if key.context != self.brand {
            return Err(Error::semantic(
                "P2_CONTEXT_MISMATCH",
                "foreign context key",
            ));
        }
        let index = self
            .indexes
            .get(&key.namespace)
            .and_then(|table| table.get(&key.id))
            .ok_or_else(|| Error::semantic("P2_LOCAL_REFERENCE", "missing indexed key"))?;
        let (_, section, collection) = TABLES
            .iter()
            .find(|(namespace, _, _)| *namespace == key.namespace)
            .ok_or_else(|| Error::semantic("P2_NAMESPACE", "unknown table"))?;
        list(field(self.root(*section)?, collection)?)?
            .get(*index)
            .ok_or_else(|| Error::semantic("P2_LOCAL_REFERENCE", "index out of bounds"))
    }

    pub(crate) fn dependency(&self, slot: u32) -> Result<&RecordValue, Error> {
        let index = self
            .dependencies
            .get(&slot)
            .ok_or_else(|| Error::semantic("P2_DEPENDENCY", "undeclared slot"))?;
        list(field(field(self.root(2)?, "manifest")?, "dependencies")?)?
            .get(*index)
            .ok_or_else(|| Error::semantic("P2_DEPENDENCY", "dependency index"))
    }

    pub(crate) fn declaration(&self, slot: u32, id: u32) -> Result<&RecordValue, Error> {
        let index = self
            .declarations
            .get(&(slot, id))
            .ok_or_else(|| Error::semantic("P2_DECLARATION", "undeclared consumer ID"))?;
        list(field(self.dependency(slot)?, "declarations")?)?
            .get(*index)
            .ok_or_else(|| Error::semantic("P2_DECLARATION", "declaration index"))
    }

    pub(crate) fn resolve_declaration(
        &self,
        expected: Namespace,
        reference: &EntityRef,
    ) -> Result<DeclaredEntity<'_>, Error> {
        let slot = match reference.module {
            ModuleRef::SelfModule => {
                return Ok(DeclaredEntity::Local(self.local(expected, reference.id)?));
            }
            ModuleRef::Dependency { slot } => slot,
        };
        if expected == Namespace::CallSignature {
            // DEP IDs name the original consumer declaration. Its explicit
            // abi_signature expectation is resolved by the ABI/program join;
            // this lookup neither chooses a provider nor creates a local key.
            let declaration = self.declaration(slot, reference.id)?;
            let callable = match text(field(declaration, "kind")?)? {
                "function" => true,
                "symbol" => matches!(
                    text(field(declaration, "symbol_kind")?)?,
                    "function" | "import"
                ),
                _ => false,
            };
            if !callable {
                return Err(Error::semantic(
                    "P2_DEPENDENCY_NAMESPACE",
                    "declaration has no callable signature namespace",
                ));
            }
            return Ok(DeclaredEntity::Dependency { slot, declaration });
        }
        let required = match expected {
            Namespace::ExecutionType => "type",
            Namespace::Function => "function",
            Namespace::Symbol => "symbol",
            Namespace::Nominal => "nominal",
            Namespace::Recipe => "recipe",
            _ => {
                return Err(Error::semantic(
                    "P2_DEPENDENCY_NAMESPACE",
                    "namespace is not externally declarable",
                ));
            }
        };
        let declaration = self.declaration(slot, reference.id)?;
        if text(field(declaration, "kind")?)? != required {
            return Err(Error::semantic(
                "P2_DECLARATION_KIND",
                "consumer declaration namespace mismatch",
            ));
        }
        Ok(DeclaredEntity::Dependency { slot, declaration })
    }
}
