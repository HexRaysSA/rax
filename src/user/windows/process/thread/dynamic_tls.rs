//! Checked publication of static TLS for threads that already exist.
//!
//! New arrays and template blocks are staged for every thread before any TEB
//! pointer changes. Old arrays stay owned by the loader journal until commit
//! or rollback; nested callback loads may therefore expand them again safely.

use super::*;
use crate::error::MemoryAccessKind;
use crate::user::windows::heap::HeapError;
use std::collections::HashMap;

struct Prepared {
    tid: u32,
    teb: u64,
    old: u64,
    array: u64,
    blocks: HashMap<usize, u64>,
}

fn allocation(p: &mut Proc, bytes: u64) -> Result<u64, u32> {
    p.heaps
        .alloc_checked(&mut p.vm, p.process_heap, bytes, true)
        .map_err(|error| match error {
            HeapError::NoMemory => STATUS_NO_MEMORY,
            HeapError::MemoryFault(_) => STATUS_ACCESS_VIOLATION,
            HeapError::BadHeap | HeapError::BadBlock => STATUS_INVALID_IMAGE_FORMAT,
        })
}

fn release_staged(p: &mut Proc, staged: &[Prepared]) {
    for s in staged {
        for block in s.blocks.values() {
            let _ = p.heaps.free(p.process_heap, *block);
        }
        if s.array != 0 {
            let _ = p.heaps.free(p.process_heap, s.array);
        }
    }
}

fn target(p: &Proc, teb: u64) -> Result<u64, u32> {
    let at = teb
        .checked_add(offsets(p.arch).teb_tls_pointer)
        .ok_or(STATUS_ACCESS_VIOLATION)?;
    p.space
        .probe(at, p.arch.ptr_size() as usize, MemoryAccessKind::Write)
        .map_err(|_| STATUS_ACCESS_VIOLATION)?;
    Ok(at)
}

/// O(T × (N + B)) time and O(T × N + T × B) guest bytes for T existing
/// threads, N array bytes, and B new template/zero-fill bytes per thread.
/// The current scheduler thread is extracted from `Proc::threads` in normal
/// operation, so it is explicitly included and never counted twice.
pub(crate) fn install_dynamic_tls(
    p: &mut Proc,
    current: &mut Thread,
    modules: &[usize],
) -> Result<Vec<u64>, u32> {
    if modules.is_empty() {
        return Ok(Vec::new());
    }
    let ptr = p.arch.ptr_size();
    let bytes = u64::from(p.modules.next_tls_index)
        .checked_mul(ptr)
        .ok_or(STATUS_NO_MEMORY)?;
    let threads: Vec<_> = std::iter::once((current.tid, current.teb, current.tls_array))
        .chain(
            p.threads
                .values()
                .filter(|t| t.tid != current.tid)
                .map(|t| (t.tid, t.teb, t.tls_array)),
        )
        .collect();
    // Guest protection failures precede allocation or publication.
    for &(_, teb, _) in &threads {
        target(p, teb)?;
    }
    let mut staged = Vec::new();
    let result = (|| {
        for (tid, teb, old) in threads {
            let array = allocation(p, bytes)?;
            staged.push(Prepared {
                tid,
                teb,
                old,
                array,
                blocks: HashMap::new(),
            });
            let s = staged.last_mut().unwrap();
            if old != 0 {
                let old_bytes = p
                    .heaps
                    .size(p.process_heap, old)
                    .map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
                let mut buf = vec![0; bytes.min(old_bytes).min(0x10000) as usize];
                let mut at = 0;
                while at < bytes.min(old_bytes) {
                    let n = (bytes.min(old_bytes) - at).min(buf.len() as u64) as usize;
                    p.space
                        .read(old + at, &mut buf[..n])
                        .map_err(|_| STATUS_ACCESS_VIOLATION)?;
                    p.space
                        .write(array + at, &buf[..n])
                        .map_err(|_| STATUS_ACCESS_VIOLATION)?;
                    at += n as u64;
                }
            }
            for &idx in modules {
                if p.modules
                    .dynamic
                    .tls_blocks
                    .get(&tid)
                    .is_some_and(|blocks| blocks.contains_key(&idx))
                {
                    continue;
                }
                let tls = p
                    .modules
                    .list
                    .get(idx)
                    .and_then(|m| m.tls)
                    .ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
                if tls.index >= p.modules.next_tls_index {
                    return Err(STATUS_INVALID_IMAGE_FORMAT);
                }
                let size = tls
                    .raw_size
                    .checked_add(tls.zero_fill)
                    .ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
                let block = allocation(p, size.max(1))?;
                s.blocks.insert(idx, block);
                let mut buf = vec![0; tls.raw_size.min(0x10000) as usize];
                let mut at = 0;
                while at < tls.raw_size {
                    let n = (tls.raw_size - at).min(buf.len() as u64) as usize;
                    let source = tls
                        .template
                        .checked_add(at)
                        .ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
                    p.vm.peek(source, &mut buf[..n])
                        .map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
                    p.vm.poke(block + at, &buf[..n])
                        .map_err(|_| STATUS_ACCESS_VIOLATION)?;
                    at += n as u64;
                }
                p.space
                    .wptr(array + ptr * u64::from(tls.index), ptr, block)
                    .map_err(|_| STATUS_ACCESS_VIOLATION)?;
            }
        }
        Ok(())
    })();
    if let Err(status) = result {
        release_staged(p, &staged);
        return Err(status);
    }
    // Probes above and the single-threaded host dispatch make these writes
    // infallible unless an internal mapping invariant is violated.
    let mut old_arrays = Vec::new();
    for s in staged {
        p.space
            .wptr(target(p, s.teb)?, ptr, s.array)
            .map_err(|_| STATUS_ACCESS_VIOLATION)?;
        if s.old != 0 {
            old_arrays.push(s.old);
        }
        let t = if s.tid == current.tid {
            &mut *current
        } else {
            p.threads.get_mut(&s.tid).ok_or(STATUS_INVALID_PARAMETER)?
        };
        t.tls_array = s.array;
        t.tls_blocks.extend(s.blocks.values().copied());
        p.modules
            .dynamic
            .tls_blocks
            .entry(s.tid)
            .or_default()
            .extend(s.blocks);
    }
    Ok(old_arrays)
}

/// Clears only the host-recorded block for `idx`; guest-written array values
/// are never used as heap ownership evidence. Shared array capacity can stay
/// at the peak live index while another module retains static TLS.
pub(crate) fn remove_dynamic_tls(
    p: &mut Proc,
    current: &mut Thread,
    idx: usize,
) -> Result<(), u32> {
    let Some(tls) = p.modules.list.get(idx).and_then(|m| m.tls) else {
        return Ok(());
    };
    let ptr = p.arch.ptr_size();
    let others = p
        .modules
        .list
        .iter()
        .enumerate()
        .any(|(i, m)| i != idx && p.modules.is_live(i) && m.tls.is_some());
    let threads: Vec<_> = std::iter::once((current.tid, current.teb, current.tls_array))
        .chain(
            p.threads
                .values()
                .filter(|t| t.tid != current.tid)
                .map(|t| (t.tid, t.teb, t.tls_array)),
        )
        .collect();
    let mut owned = Vec::new();
    for (tid, teb, array) in threads {
        let Some(block) = p
            .modules
            .dynamic
            .tls_blocks
            .get(&tid)
            .and_then(|m| m.get(&idx))
            .copied()
        else {
            continue;
        };
        if p.heaps.owner(block) != Some(p.process_heap) {
            return Err(STATUS_INVALID_IMAGE_FORMAT);
        }
        let slot = array
            .checked_add(ptr * u64::from(tls.index))
            .ok_or(STATUS_ACCESS_VIOLATION)?;
        let capacity = p
            .heaps
            .size(p.process_heap, array)
            .map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
        if ptr * (u64::from(tls.index) + 1) > capacity {
            return Err(STATUS_INVALID_IMAGE_FORMAT);
        }
        p.space
            .probe(slot, ptr as usize, MemoryAccessKind::Write)
            .map_err(|_| STATUS_ACCESS_VIOLATION)?;
        if !others {
            target(p, teb)?;
        }
        owned.push((tid, teb, array, slot, block));
    }
    for (tid, teb, array, slot, block) in owned {
        p.space
            .wptr(slot, ptr, 0)
            .map_err(|_| STATUS_ACCESS_VIOLATION)?;
        if !others {
            p.space
                .wptr(target(p, teb)?, ptr, 0)
                .map_err(|_| STATUS_ACCESS_VIOLATION)?;
        }
        p.heaps
            .free(p.process_heap, block)
            .map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
        let t = if tid == current.tid {
            &mut *current
        } else {
            p.threads.get_mut(&tid).ok_or(STATUS_INVALID_PARAMETER)?
        };
        t.tls_blocks.retain(|b| *b != block);
        if !others {
            p.heaps
                .free(p.process_heap, array)
                .map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
            t.tls_array = 0;
        }
        p.modules
            .dynamic
            .tls_blocks
            .get_mut(&tid)
            .unwrap()
            .remove(&idx);
    }
    Ok(())
}
