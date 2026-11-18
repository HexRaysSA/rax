//! Linking: one program of several modules.
//!
//! A module that calls functions of another names the other as a dependency
//! and declares the functions it calls of it; until it is linked, each such
//! function is a place among its functions with a type and no body. Linking
//! lays the modules out as one: their types, functions, data and
//! thread-local storage one module after another, and every reference
//! moved to where its target went. A call of a declared function becomes a
//! call of the function that the dependency defines under that name.
//!
//! Nothing but those calls joins the modules. A module's data and its other
//! functions keep to it, and two modules that were each built with a copy
//! of the same library each have their copy.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::Error;

use super::lower::structurally_equal;
use super::{
    Callee, FuncIdx, Function, HostImport, Linkage, Module, Op, Relocation, RelocationKind, SegIdx,
    Signature, Type, TypeId,
};

fn refused(code: &'static str, what: impl Into<String>) -> Error {
    Error::semantic(code, what)
}

/// Where a module's parts are in the linked program.
#[derive(Default)]
struct Place {
    /// What is added to its type, segment and thread-local segment indices,
    /// and to the places of its host imports.
    types: u32,
    segments: u32,
    thread_local: u32,
    hosts: u32,
    /// Where each of its functions went; for one a dependency supplies,
    /// where that module's function went.
    functions: Vec<Option<FuncIdx>>,
}

impl Place {
    fn ty(&self, id: TypeId) -> TypeId {
        TypeId(id.0 + self.types)
    }

    fn function(&self, index: FuncIdx) -> Result<FuncIdx, Error> {
        self.functions
            .get(index.index())
            .copied()
            .flatten()
            .ok_or_else(|| refused("LINK_INTERNAL", "a function was not placed"))
    }

    fn signature(&self, signature: &Signature) -> Signature {
        Signature {
            params: signature.params.iter().map(|ty| self.ty(*ty)).collect(),
            results: signature.results.iter().map(|ty| self.ty(*ty)).collect(),
            ..signature.clone()
        }
    }

    fn relocation(&self, relocation: &Relocation) -> Result<Relocation, Error> {
        let segment = |index: SegIdx| SegIdx(index.0 + self.segments);
        Ok(Relocation {
            segment: segment(relocation.segment),
            offset: relocation.offset,
            kind: match relocation.kind {
                RelocationKind::DataAddress { target, addend } => RelocationKind::DataAddress {
                    target: segment(target),
                    addend,
                },
                RelocationKind::DataInteger {
                    target,
                    addend,
                    bytes,
                } => RelocationKind::DataInteger {
                    target: segment(target),
                    addend,
                    bytes,
                },
                RelocationKind::FunctionToken { function } => RelocationKind::FunctionToken {
                    function: self.function(function)?,
                },
                RelocationKind::FunctionInteger {
                    function,
                    addend,
                    bits,
                } => RelocationKind::FunctionInteger {
                    function: self.function(function)?,
                    addend,
                    bits,
                },
            },
        })
    }

    /// A function of the module as it is in the linked program.
    fn moved(&self, function: &Function) -> Result<Function, Error> {
        let mut moved = function.clone();
        moved.signature_type = self.ty(function.signature_type);
        moved.signature = self.signature(&function.signature);
        for block in &mut moved.blocks {
            for op in &mut block.ops {
                match op {
                    Op::Call { callee, .. } => match callee {
                        Callee::Direct(target) => *target = self.function(*target)?,
                        Callee::Indirect { signature, .. } => *signature = self.ty(*signature),
                    },
                    Op::AddressOf { function, .. } => *function = self.function(*function)?,
                    Op::AddressOfData { segment, .. } => segment.0 += self.segments,
                    Op::TlsAddress { segment, .. } => *segment += self.thread_local,
                    Op::Host { import, .. } => *import += self.hosts,
                    _ => {}
                }
            }
        }
        Ok(moved)
    }
}

/// Which module answers each dependency of each module, by slot.
fn answers(modules: &[Module]) -> Result<Vec<BTreeMap<u32, usize>>, Error> {
    let mut all = Vec::with_capacity(modules.len());
    for (asking, module) in modules.iter().enumerate() {
        let mut found = BTreeMap::new();
        for dependency in &module.linkage.dependencies {
            let mut candidates = modules.iter().enumerate().filter(|(index, candidate)| {
                let key = &candidate.linkage.key;
                *index != asking
                    && key.namespace == dependency.namespace
                    && key.name == dependency.name
                    && key.major == dependency.major
                    && key.minor >= dependency.minimum_minor
                    && dependency
                        .maximum_minor
                        .is_none_or(|maximum| key.minor <= maximum)
            });
            let named = || {
                format!(
                    "{}:{} version {}",
                    dependency.namespace, dependency.name, dependency.major
                )
            };
            let (Some((answer, _)), None) = (candidates.next(), candidates.next()) else {
                return Err(refused("LINK_DEPENDENCY", named()));
            };
            found.insert(dependency.slot, answer);
        }
        all.push(found);
    }
    Ok(all)
}

/// The modules in an order in which each comes after those it depends on,
/// from the first module on.
fn ordered(answers: &[BTreeMap<u32, usize>]) -> Result<Vec<usize>, Error> {
    #[derive(Clone, Copy, PartialEq)]
    enum Seen {
        No,
        Under,
        Done,
    }
    fn visit(
        module: usize,
        answers: &[BTreeMap<u32, usize>],
        seen: &mut [Seen],
        order: &mut Vec<usize>,
    ) -> Result<(), Error> {
        match seen[module] {
            Seen::Done => return Ok(()),
            Seen::Under => return Err(refused("LINK_CYCLE", String::new())),
            Seen::No => {}
        }
        seen[module] = Seen::Under;
        for dependency in answers[module].values() {
            visit(*dependency, answers, seen, order)?;
        }
        seen[module] = Seen::Done;
        order.push(module);
        Ok(())
    }
    let mut seen = vec![Seen::No; answers.len()];
    let mut order = Vec::with_capacity(answers.len());
    visit(0, answers, &mut seen, &mut order)?;
    if seen.contains(&Seen::No) {
        return Err(refused("LINK_UNUSED", String::new()));
    }
    Ok(order)
}

pub(super) fn link(modules: Vec<Module>) -> Result<Module, Error> {
    if modules.is_empty() {
        return Err(refused("LINK_DEPENDENCY", "no module"));
    }
    // A process has one personality and at most one foreign processor, and
    // every module of it has them.
    let program = &modules[0].linkage;
    if let Some(other) = modules.iter().map(|module| &module.linkage).find(|other| {
        (&other.personality, &other.foreign_isa) != (&program.personality, &program.foreign_isa)
    }) {
        return Err(refused(
            "LINK_PERSONALITY",
            format!(
                "{}:{} is for {}, the program for {}",
                other.key.namespace, other.key.name, other.personality, program.personality
            ),
        ));
    }
    let answers = answers(&modules)?;
    let order = ordered(&answers)?;
    let count = |length: usize| {
        u32::try_from(length).map_err(|_| refused("LINK_SIZE", "index space exhausted"))
    };

    // Where each module's parts go: the modules one after another, in the
    // order they are initialized in.
    let mut places: Vec<Place> = modules.iter().map(|_| Place::default()).collect();
    let (mut types, mut segments, mut thread_local, mut functions) = (0_u32, 0_u32, 0_u32, 0_u32);
    let mut hosts = 0_u32;
    for index in &order {
        let (module, place) = (&modules[*index], &mut places[*index]);
        place.types = types;
        place.segments = segments;
        place.thread_local = thread_local;
        for own in 0..module.functions.len() {
            let external = module.linkage.externals.contains_key(&FuncIdx(count(own)?));
            place.functions.push(if external {
                None
            } else {
                functions += 1;
                Some(FuncIdx(functions - 1))
            });
        }
        place.hosts = hosts;
        types += count(module.types.len())?;
        segments += count(module.segments.len())?;
        thread_local += count(module.thread_local.len())?;
        hosts += count(module.linkage.hosts.len())?;
    }

    let mut linked = Module {
        identity: {
            let mut digest = Sha256::new();
            digest.update(b"SMIR-LINKED\0");
            for module in &modules {
                digest.update(module.identity);
            }
            digest.finalize().into()
        },
        linkage: Linkage {
            key: modules[0].linkage.key.clone(),
            personality: modules[0].linkage.personality.clone(),
            foreign_isa: modules[0].linkage.foreign_isa.clone(),
            ..Linkage::default()
        },
        types: Vec::new(),
        type_ids: BTreeMap::new(),
        functions: Vec::new(),
        function_ids: BTreeMap::new(),
        segments: Vec::new(),
        relocations: Vec::new(),
        thread_local: Vec::new(),
        exports: BTreeMap::new(),
        capabilities: Default::default(),
        initializers: Vec::new(),
        finalizers: Vec::new(),
    };
    for index in &order {
        let (module, place) = (&modules[*index], &places[*index]);
        linked.types.extend(module.types.iter().map(|ty| match ty {
            Type::CodePtr { signature } => Type::CodePtr {
                signature: place.ty(*signature),
            },
            Type::Function(signature) => Type::Function(place.signature(signature)),
            other => other.clone(),
        }));
    }

    // Each function a dependency supplies: the function of that name there,
    // which must be of the type it was declared with here.
    for (asking, module) in modules.iter().enumerate() {
        for (index, external) in &module.linkage.externals {
            let supplier = *answers[asking]
                .get(&external.slot)
                .ok_or_else(|| refused("LINK_DEPENDENCY", "a declaration of no dependency"))?;
            let named = || format!("{}:{}", external.namespace, external.name);
            let name = (external.namespace.clone(), external.name.clone());
            let target = *modules[supplier]
                .linkage
                .symbols
                .get(&name)
                .ok_or_else(|| refused("LINK_UNDEFINED", named()))?;
            let declared = places[asking].ty(module.functions[index.index()].signature_type);
            let defined =
                places[supplier].ty(modules[supplier].functions[target.index()].signature_type);
            if !structurally_equal(&linked.types, declared, defined) {
                return Err(refused("LINK_TYPE", named()));
            }
            let placed = places[supplier].function(target)?;
            places[asking].functions[index.index()] = Some(placed);
        }
    }

    for index in &order {
        let (module, place) = (&modules[*index], &places[*index]);
        for (own, function) in module.functions.iter().enumerate() {
            if !module.linkage.externals.contains_key(&FuncIdx(count(own)?)) {
                linked.functions.push(place.moved(function)?);
            }
        }
        linked.segments.extend(module.segments.iter().cloned());
        linked
            .thread_local
            .extend(module.thread_local.iter().cloned());
        for relocation in &module.relocations {
            linked.relocations.push(place.relocation(relocation)?);
        }
        linked
            .capabilities
            .extend(module.capabilities.iter().cloned());
        // Each module's host functions, as that module imports them.
        for import in &module.linkage.hosts {
            linked.linkage.hosts.push(HostImport {
                signature: place.ty(import.signature),
                ..import.clone()
            });
        }
        // A module is initialized after what it depends on.
        for initializer in &module.initializers {
            linked.initializers.push(place.function(*initializer)?);
        }
    }
    // And finalized before it.
    for index in order.iter().rev() {
        for finalizer in &modules[*index].finalizers {
            linked.finalizers.push(places[*index].function(*finalizer)?);
        }
    }

    // The program is known by what its first module is known by.
    let (program, place) = (&modules[0], &places[0]);
    for (id, ty) in &program.type_ids {
        linked.type_ids.insert(*id, place.ty(*ty));
    }
    for (id, function) in &program.function_ids {
        linked.function_ids.insert(*id, place.function(*function)?);
    }
    for (name, function) in &program.exports {
        linked
            .exports
            .insert(name.clone(), place.function(*function)?);
    }
    for (name, function) in &program.linkage.symbols {
        linked
            .linkage
            .symbols
            .insert(name.clone(), place.function(*function)?);
    }
    Ok(linked)
}
