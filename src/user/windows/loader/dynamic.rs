//! Dynamic image ownership and callback-independent loader transactions.
//!
//! Module indices never move. Dependency reachability, rather than incoming
//! edge counts, permits an otherwise unreferenced import cycle to unload.

use super::*;
use crate::user::windows::process::{Thread, thread};
use std::collections::{BTreeMap, BTreeSet, HashSet};

pub(crate) struct LoadPlan {
    pub id: u64,
    pub root: usize,
    pub initialize: Vec<usize>,
}
pub(crate) struct LookupPlan {
    pub id: u64,
    pub address: Option<u64>,
    pub initialize: Vec<usize>,
}
pub(crate) struct UnloadPlan {
    pub id: u64,
    pub detach: Vec<usize>,
}

#[derive(Default)]
pub(crate) struct DynamicState {
    pub(super) unloaded: HashSet<usize>,
    pub(super) attaching: HashSet<usize>,
    pub(super) detaching: HashSet<usize>,
    pub(super) attached_order: Vec<usize>,
    pub(super) main_called: HashSet<usize>,
    pub(super) init_linked: HashSet<usize>,
    pub(super) pins: HashSet<usize>,
    pub(super) dependencies: HashMap<usize, BTreeSet<usize>>,
    pub(super) free_tls: BTreeSet<u32>,
    pub(crate) tls_blocks: HashMap<u32, HashMap<usize, u64>>,
    pub(super) ldr_allocations: HashMap<usize, Vec<u64>>,
    pub(super) ldr_links: HashMap<usize, [bool; 3]>,
    next_id: u64,
    journals: BTreeMap<u64, Journal>,
    active: Vec<u64>,
}

struct Journal {
    created: Vec<usize>,
    edges: Vec<(usize, usize)>,
    added_reference: Option<usize>,
    old_arrays: Vec<u64>,
    detach: Vec<usize>,
    remove: Vec<usize>,
    rollback: bool,
    unload: bool,
    error: Option<LoadError>,
}

fn journal(p: &mut Proc, unload: bool) -> Result<u64, LoadError> {
    let id = p
        .modules
        .dynamic
        .next_id
        .checked_add(1)
        .ok_or_else(|| LoadError::new(STATUS_NO_MEMORY, "loader transaction IDs exhausted"))?;
    p.modules.dynamic.next_id = id;
    p.modules.dynamic.journals.insert(
        id,
        Journal {
            created: Vec::new(),
            edges: Vec::new(),
            added_reference: None,
            old_arrays: Vec::new(),
            detach: Vec::new(),
            remove: Vec::new(),
            rollback: false,
            unload,
            error: None,
        },
    );
    Ok(id)
}

fn missing_transaction() -> LoadError {
    LoadError::new(STATUS_INVALID_PARAMETER, "invalid loader transaction")
}

/// Forced process shutdown discards only host receipts. No guest callbacks,
/// guest writes, image release, or TLS registry changes are permitted here;
/// live heap/image storage stays owned by the dying process until teardown.
pub(crate) fn discard_transactions(p: &mut Proc) {
    p.modules.dynamic.journals.clear();
    p.modules.dynamic.active.clear();
}

pub(super) fn dependency(p: &mut Proc, owner: usize, target: usize) {
    if p.modules
        .dynamic
        .dependencies
        .entry(owner)
        .or_default()
        .insert(target)
    {
        if let Some(id) = p.modules.dynamic.active.last().copied() {
            if let Some(journal) = p.modules.dynamic.journals.get_mut(&id) {
                journal.edges.push((owner, target));
            }
        }
    }
}

/// O(H + E) including the H-slot historical root scan and live dependency
/// edges E. Pins and explicit references are independent roots.
fn reachable(p: &Proc) -> HashSet<usize> {
    let roots = p.modules.list.iter().enumerate().filter_map(|(idx, m)| {
        (p.modules.is_live(idx)
            && (matches!(m.kind, ModuleKind::Exe | ModuleKind::Builtin(_))
                || m.load_count != 0
                || p.modules.dynamic.pins.contains(&idx)))
        .then_some(idx)
    });
    walk(p, roots)
}

fn walk(p: &Proc, roots: impl IntoIterator<Item = usize>) -> HashSet<usize> {
    let mut seen = HashSet::new();
    let mut pending: Vec<_> = roots.into_iter().collect();
    while let Some(idx) = pending.pop() {
        if !p.modules.is_live(idx) || !seen.insert(idx) {
            continue;
        }
        if let Some(edges) = p.modules.dynamic.dependencies.get(&idx) {
            pending.extend(edges.iter().copied());
        }
    }
    seen
}

fn initialization(p: &Proc, root: usize) -> Vec<usize> {
    let needed = walk(p, [root]);
    p.modules
        .init_order
        .iter()
        .copied()
        .filter(|&idx| {
            needed.contains(&idx)
                && !p.modules.list[idx].initialized
                && !p.modules.dynamic.attaching.contains(&idx)
        })
        .collect()
}

/// Increment an explicit reference, or permanently pin a live module.
pub(crate) fn reference_module(p: &mut Proc, idx: usize, pin: bool) -> Result<(), LoadError> {
    if !p.modules.is_live(idx) || p.modules.dynamic.detaching.contains(&idx) {
        return Err(LoadError::new(
            STATUS_INVALID_PARAMETER,
            "invalid or detaching module",
        ));
    }
    let old = p.modules.list[idx].load_count;
    let count = if pin || old == u32::MAX {
        u32::MAX
    } else {
        old.checked_add(1)
            .filter(|&count| count != u32::MAX)
            .ok_or_else(|| LoadError::new(STATUS_NO_MEMORY, "module references exhausted"))?
    };
    ldr::set_count(p, idx, count)?;
    p.modules.list[idx].load_count = count;
    if pin {
        p.modules.dynamic.pins.insert(idx);
    }
    Ok(())
}

#[cfg(test)]
#[path = "dynamic_tests.rs"]
mod tests;

fn prepare(p: &mut Proc, t: &mut Thread, id: u64, first: usize) -> Result<(), LoadError> {
    let created: Vec<_> = (first..p.modules.list.len())
        .filter(|&idx| !matches!(p.modules.list[idx].kind, ModuleKind::Builtin(_)))
        .collect();
    p.modules
        .dynamic
        .journals
        .get_mut(&id)
        .ok_or_else(missing_transaction)?
        .created = created.clone();
    let tls: Vec<_> = created
        .into_iter()
        .filter(|&idx| p.modules.is_live(idx) && p.modules.list[idx].tls.is_some())
        .collect();
    let arrays = thread::install_dynamic_tls(p, t, &tls)
        .map_err(|status| LoadError::new(status, "cannot install dynamic static TLS"))?;
    p.modules
        .dynamic
        .journals
        .get_mut(&id)
        .ok_or_else(missing_transaction)?
        .old_arrays = arrays;
    Ok(())
}

fn failed_begin(p: &mut Proc, t: &mut Thread, id: u64, error: LoadError) -> LoadError {
    if let Err(cleanup) =
        begin_rollback(p, id, error.clone(), None).and_then(|_| finish_rollback(p, t, id))
    {
        p.fail(format!(
            "loader rollback failed: {cleanup}; original: {error}"
        ));
    }
    error
}

pub(crate) fn begin_load(p: &mut Proc, t: &mut Thread, name: &str) -> Result<LoadPlan, LoadError> {
    let id = journal(p, false)?;
    let first = p.modules.list.len();
    p.modules.dynamic.active.push(id);
    let result = load_dll(p, name);
    p.modules.dynamic.active.pop();
    // Record partial images even when mapping/binding failed before TLS setup.
    p.modules.dynamic.journals.get_mut(&id).unwrap().created = (first..p.modules.list.len())
        .filter(|&idx| !matches!(p.modules.list[idx].kind, ModuleKind::Builtin(_)))
        .collect();
    let root = match result {
        Ok(idx) => idx,
        Err(error) => return Err(failed_begin(p, t, id, error)),
    };
    if let Err(error) = reference_module(p, root, false) {
        return Err(failed_begin(p, t, id, error));
    }
    if p.modules.list[root].load_count != u32::MAX {
        p.modules
            .dynamic
            .journals
            .get_mut(&id)
            .unwrap()
            .added_reference = Some(root);
    }
    if let Err(error) = prepare(p, t, id, first) {
        return Err(failed_begin(p, t, id, error));
    }
    Ok(LoadPlan {
        id,
        root,
        initialize: initialization(p, root),
    })
}

pub(crate) fn begin_lookup(
    p: &mut Proc,
    t: &mut Thread,
    idx: usize,
    sym: &SymRef,
) -> Result<LookupPlan, LoadError> {
    let id = journal(p, false)?;
    let first = p.modules.list.len();
    p.modules.dynamic.active.push(id);
    let result = lookup(p, idx, sym);
    p.modules.dynamic.active.pop();
    p.modules.dynamic.journals.get_mut(&id).unwrap().created = (first..p.modules.list.len())
        .filter(|&i| !matches!(p.modules.list[i].kind, ModuleKind::Builtin(_)))
        .collect();
    let address = match result {
        Ok(v) => v,
        Err(error) => return Err(failed_begin(p, t, id, error)),
    };
    if let Err(error) = prepare(p, t, id, first) {
        return Err(failed_begin(p, t, id, error));
    }
    Ok(LookupPlan {
        id,
        address,
        initialize: initialization(p, idx),
    })
}

/// Idempotent before TLS callbacks and again immediately before DllMain.
pub(crate) fn attach_started(
    p: &mut Proc,
    idx: usize,
    called_dll_main: bool,
) -> Result<(), LoadError> {
    if !p.modules.is_live(idx) {
        return Err(LoadError::new(
            STATUS_INVALID_PARAMETER,
            "invalid attaching module",
        ));
    }
    if matches!(p.modules.list[idx].kind, ModuleKind::Native)
        && !p.modules.dynamic.init_linked.contains(&idx)
    {
        ldr::link_init_order(p, idx)?;
        p.modules.dynamic.init_linked.insert(idx);
    }
    p.modules.dynamic.attaching.insert(idx);
    if called_dll_main {
        p.modules.dynamic.main_called.insert(idx);
    }
    Ok(())
}

pub(crate) fn attach_succeeded(p: &mut Proc, idx: usize) -> Result<(), LoadError> {
    if !p.modules.is_live(idx) {
        return Err(LoadError::new(
            STATUS_INVALID_PARAMETER,
            "invalid initialized module",
        ));
    }
    p.modules.list[idx].initialized = true;
    p.modules.dynamic.attaching.remove(&idx);
    if matches!(p.modules.list[idx].kind, ModuleKind::Native)
        && !p.modules.dynamic.attached_order.contains(&idx)
    {
        p.modules.dynamic.attached_order.push(idx);
    }
    Ok(())
}

pub(crate) fn detach_completed(p: &mut Proc, idx: usize) -> Result<(), LoadError> {
    if idx >= p.modules.list.len() {
        return Err(LoadError::new(
            STATUS_INVALID_PARAMETER,
            "invalid detached module",
        ));
    }
    p.modules.list[idx].initialized = false;
    p.modules.dynamic.attaching.remove(&idx);
    p.modules.dynamic.main_called.remove(&idx);
    p.modules.dynamic.attached_order.retain(|&i| i != idx);
    Ok(())
}

/// Normal process-exit notifications also prohibit recursively freeing or
/// referencing the same image while its entrypoint is being detached.
pub(crate) fn detach_started(p: &mut Proc, idx: usize) -> Result<(), LoadError> {
    if !p.modules.is_live(idx) {
        return Err(LoadError::new(
            STATUS_INVALID_PARAMETER,
            "invalid detaching module",
        ));
    }
    p.modules.dynamic.detaching.insert(idx);
    Ok(())
}

fn free_arrays(p: &mut Proc, arrays: Vec<u64>) -> Result<(), LoadError> {
    for array in arrays {
        // A nested transaction can retain the same old array in its journal.
        if p.heaps.owner(array).is_some() {
            p.heaps.free(p.process_heap, array).map_err(|_| {
                LoadError::new(STATUS_INVALID_IMAGE_FORMAT, "invalid owned TLS array")
            })?;
        }
    }
    Ok(())
}

pub(crate) fn commit_load(p: &mut Proc, id: u64) -> Result<(), LoadError> {
    let j = p
        .modules
        .dynamic
        .journals
        .get(&id)
        .ok_or_else(missing_transaction)?;
    if j.rollback || j.unload {
        return Err(missing_transaction());
    }
    let arrays = j.old_arrays.clone();
    free_arrays(p, arrays)?;
    p.modules.dynamic.journals.remove(&id);
    Ok(())
}

pub(crate) fn begin_rollback(
    p: &mut Proc,
    id: u64,
    error: LoadError,
    failing_entry: Option<usize>,
) -> Result<Vec<usize>, LoadError> {
    let (created, edges, reference, unload) = {
        let j = p
            .modules
            .dynamic
            .journals
            .get_mut(&id)
            .ok_or_else(missing_transaction)?;
        if j.unload {
            return Err(LoadError::new(
                STATUS_NOT_IMPLEMENTED,
                "abandoned unload notification cannot be rolled back",
            ));
        }
        if j.rollback {
            return Ok(j.detach.clone());
        }
        (
            j.created.clone(),
            j.edges.clone(),
            j.added_reference,
            j.unload,
        )
    };
    debug_assert!(!unload);
    if let Some(idx) = reference {
        if p.modules.list[idx].load_count != u32::MAX {
            let count = p.modules.list[idx]
                .load_count
                .checked_sub(1)
                .ok_or_else(missing_transaction)?;
            ldr::set_count(p, idx, count)?;
            p.modules.list[idx].load_count = count;
        }
    }
    let before = reachable(p);
    let retained: HashSet<_> = created
        .iter()
        .copied()
        .filter(|&idx| before.contains(&idx) && p.modules.list[idx].initialized)
        .collect();
    for (owner, target) in edges {
        if retained.contains(&owner) {
            continue;
        }
        if let Some(edges) = p.modules.dynamic.dependencies.get_mut(&owner) {
            edges.remove(&target);
        }
    }
    let reachable = reachable(p);
    let remove: Vec<_> = created
        .into_iter()
        .filter(|idx| !reachable.contains(idx) || !p.modules.list[*idx].initialized)
        .collect();
    let selected: HashSet<_> = remove.iter().copied().collect();
    let mut detach: Vec<_> = p
        .modules
        .dynamic
        .attached_order
        .iter()
        .rev()
        .copied()
        .filter(|idx| selected.contains(idx) && p.modules.list[*idx].initialized)
        .collect();
    if let Some(idx) = failing_entry {
        if selected.contains(&idx)
            && p.modules.dynamic.main_called.contains(&idx)
            && !detach.contains(&idx)
        {
            detach.insert(0, idx);
        }
    }
    let j = p
        .modules
        .dynamic
        .journals
        .get_mut(&id)
        .ok_or_else(missing_transaction)?;
    j.rollback = true;
    j.error = Some(error);
    j.added_reference = None;
    j.remove = remove;
    j.detach = detach.clone();
    p.modules.dynamic.detaching.extend(selected);
    Ok(detach)
}

pub(crate) fn begin_unload(p: &mut Proc, base: u64) -> Result<UnloadPlan, LoadError> {
    let idx = p
        .modules
        .by_base(base)
        .ok_or_else(|| LoadError::new(STATUS_INVALID_PARAMETER, "invalid module handle"))?;
    if p.modules.dynamic.attaching.contains(&idx) || p.modules.dynamic.detaching.contains(&idx) {
        return Err(LoadError::new(
            STATUS_DLL_INIT_FAILED,
            "module initialization or detachment is in progress",
        ));
    }
    if p.modules.list[idx].load_count == 0 {
        return Err(LoadError::new(
            STATUS_INVALID_PARAMETER,
            "no explicit module reference",
        ));
    }
    let id = journal(p, true)?;
    let count = p.modules.list[idx].load_count;
    if count != u32::MAX && !p.modules.dynamic.pins.contains(&idx) {
        let count = count.checked_sub(1).ok_or_else(|| {
            LoadError::new(STATUS_INVALID_PARAMETER, "no explicit module reference")
        })?;
        if let Err(e) = ldr::set_count(p, idx, count) {
            p.modules.dynamic.journals.remove(&id);
            return Err(e);
        }
        p.modules.list[idx].load_count = count;
    }
    let live = reachable(p);
    let remove: Vec<_> = p
        .modules
        .list
        .iter()
        .enumerate()
        .filter_map(|(i, m)| {
            (p.modules.is_live(i)
                && matches!(m.kind, ModuleKind::Native | ModuleKind::Data)
                && !live.contains(&i))
            .then_some(i)
        })
        .collect();
    let selected: HashSet<_> = remove.iter().copied().collect();
    let detach = p
        .modules
        .dynamic
        .attached_order
        .iter()
        .rev()
        .copied()
        .filter(|i| selected.contains(i) && p.modules.list[*i].initialized)
        .collect::<Vec<_>>();
    let j = p.modules.dynamic.journals.get_mut(&id).unwrap();
    j.remove = remove;
    j.detach = detach.clone();
    p.modules.dynamic.detaching.extend(selected);
    Ok(UnloadPlan { id, detach })
}

fn finish(p: &mut Proc, t: &mut Thread, id: u64) -> Result<(), LoadError> {
    let remove = p
        .modules
        .dynamic
        .journals
        .get(&id)
        .ok_or_else(missing_transaction)?
        .remove
        .clone();
    for idx in remove.into_iter().rev() {
        if p.modules.dynamic.unloaded.contains(&idx) {
            continue;
        }
        thread::remove_dynamic_tls(p, t, idx)
            .map_err(|s| LoadError::new(s, "cannot remove dynamic TLS"))?;
        ldr::remove_entry(p, idx)?;
        let base = p.modules.list[idx].base;
        p.vm.release(base)
            .map_err(|e| LoadError::new(e.status(), "cannot release DLL image"))?;
        if let Some(tls) = p.modules.list[idx].tls.take() {
            p.modules.dynamic.free_tls.insert(tls.index);
        }
        p.modules.dynamic.dependencies.remove(&idx);
        for edges in p.modules.dynamic.dependencies.values_mut() {
            edges.remove(&idx);
        }
        p.modules.dynamic.unloaded.insert(idx);
        p.modules.dynamic.attaching.remove(&idx);
        p.modules.dynamic.detaching.remove(&idx);
        p.modules.dynamic.attached_order.retain(|&i| i != idx);
        p.modules.dynamic.main_called.remove(&idx);
        p.modules.dynamic.init_linked.remove(&idx);
        p.modules.dynamic.pins.remove(&idx);
        let m = &mut p.modules.list[idx];
        m.entry = 0;
        m.size = 0;
        m.initialized = false;
        m.load_count = 0;
        m.exports = DataDirectory::default();
        m.pdata = DataDirectory::default();
        m.safe_seh = None;
        let name = normalize_name(&m.name).to_ascii_lowercase();
        let path = m.path.to_ascii_lowercase();
        p.modules.failures.remove(&name);
        p.modules.failures.remove(&path);
    }
    while p.modules.next_tls_index != 0
        && p.modules
            .dynamic
            .free_tls
            .remove(&(p.modules.next_tls_index - 1))
    {
        p.modules.next_tls_index -= 1;
    }
    p.modules
        .init_order
        .retain(|idx| !p.modules.dynamic.unloaded.contains(idx));
    let arrays = p
        .modules
        .dynamic
        .journals
        .get(&id)
        .ok_or_else(missing_transaction)?
        .old_arrays
        .clone();
    free_arrays(p, arrays)?;
    p.modules.dynamic.journals.remove(&id);
    Ok(())
}

pub(crate) fn finish_rollback(p: &mut Proc, t: &mut Thread, id: u64) -> Result<(), LoadError> {
    if !p
        .modules
        .dynamic
        .journals
        .get(&id)
        .is_some_and(|j| j.rollback && !j.unload)
    {
        return Err(missing_transaction());
    }
    finish(p, t, id)
}
pub(crate) fn finish_unload(p: &mut Proc, t: &mut Thread, id: u64) -> Result<(), LoadError> {
    if !p
        .modules
        .dynamic
        .journals
        .get(&id)
        .is_some_and(|j| j.unload)
    {
        return Err(missing_transaction());
    }
    finish(p, t, id)
}
