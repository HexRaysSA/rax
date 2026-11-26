//! MSVCRT numbered locks and DLL-owned two-pointer exit tables.

use crate::error::MemoryAccessKind;
use crate::user::windows::{
    hle::{ApiErr, ApiResult, Arg::*, Conv::Cdecl, Ctx, Export, Flow, Value},
    memory::{Mem, MemFault},
    sync::Wait,
};

use super::{RuntimeKind, allocation, termination};

pub(crate) static MSVCRT_ONEXIT_EXPORTS: &[Export] = &[
    Export::func("_lock", Cdecl, &[I32], lock),
    Export::func("_unlock", Cdecl, &[I32], unlock),
    Export::func("__dllonexit", Cdecl, &[Ptr, Ptr, Ptr], dll_onexit),
];

const EXIT_LOCK: usize = 8;

fn wait_key(index: usize) -> u128 {
    (1u128 << 125) | index as u128
}

fn lock(c: &mut Ctx) -> ApiResult {
    lock_number(c, c.u32(0)? as usize)
}

fn lock_number(c: &mut Ctx, index: usize) -> ApiResult {
    if index == EXIT_LOCK {
        return termination::acquire_legacy(c);
    }
    if index >= 36 {
        return Err(ApiErr::Internal(format!(
            "MSVCRT lock number {index} is out of range"
        )));
    }
    let locks = &mut c.p.crt.runtimes[RuntimeKind::Msvcrt.index()].legacy_locks;
    let depth = match locks.get(&index).copied() {
        Some((owner, _)) if owner != c.t.tid => {
            return Flow::block(
                Wait::Address {
                    key: wait_key(index),
                    deadline: None,
                },
                move |c, _| lock_number(c, index),
            );
        }
        Some((_, depth)) => depth
            .checked_add(1)
            .ok_or_else(|| ApiErr::Internal("MSVCRT lock recursion exhausted".into()))?,
        None => 1,
    };
    locks.insert(index, (c.t.tid, depth));
    Flow::void()
}

fn unlock(c: &mut Ctx) -> ApiResult {
    let index = c.u32(0)? as usize;
    if index == EXIT_LOCK {
        return termination::release_legacy(c);
    }
    let locks = &mut c.p.crt.runtimes[RuntimeKind::Msvcrt.index()].legacy_locks;
    match locks.get(&index).copied() {
        Some((owner, 1)) if owner == c.t.tid => {
            locks.remove(&index);
            c.p.sync.wake(wait_key(index), usize::MAX);
        }
        Some((owner, depth)) if owner == c.t.tid => {
            locks.insert(index, (owner, depth - 1));
        }
        _ => {
            return Err(ApiErr::Internal(
                "MSVCRT unlock without a matching lock".into(),
            ));
        }
    }
    Flow::void()
}

fn dll_onexit(c: &mut Ctx) -> ApiResult {
    let (callback, begin, end) = (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?);
    termination::with_lock(
        c,
        RuntimeKind::Msvcrt,
        Box::new(move |c, _| append(c, callback, begin, end)),
    )
}

fn append(c: &mut Ctx, callback: u64, begin: u64, end: u64) -> ApiResult {
    let kind = RuntimeKind::Msvcrt;
    let width = c.psize();
    let first = c.read_ptr(begin)?;
    let last = c.read_ptr(end)?;
    let Some(used) = last.checked_sub(first).filter(|used| used % width == 0) else {
        return Flow::ret(0);
    };
    let Some(&size) = c.p.crt.runtimes[kind.index()].allocations.get(&first) else {
        return Flow::ret(0);
    };
    if used > size || begin == end {
        return Flow::ret(0);
    }
    for address in [begin, end] {
        probe(c, address, width)?;
    }
    let new_first = if size - used < width {
        let growth = size.clamp(32, 4096);
        let Some(new_size) = size.checked_add(growth) else {
            return Flow::ret(0);
        };
        match allocation::resize_block(c, kind, first, new_size, false)? {
            Flow::Ret(Value::Int(0)) if growth > 32 => {
                match allocation::resize_block(c, kind, first, size + 32, false)? {
                    Flow::Ret(Value::Int(0)) => return Flow::ret(0),
                    Flow::Ret(Value::Int(first)) => first,
                    flow => return Ok(flow),
                }
            }
            Flow::Ret(Value::Int(0)) => return Flow::ret(0),
            Flow::Ret(Value::Int(first)) => first,
            flow => return Ok(flow),
        }
    } else {
        first
    };
    let new_last = new_first + used;
    if new_first != first {
        c.write_ptr(begin, new_first)?;
        c.write_ptr(end, new_last)?;
    }
    c.write_ptr(new_last, callback)?;
    c.write_ptr(end, new_last + width)?;
    Flow::ret(callback)
}

fn probe(c: &Ctx, address: u64, width: u64) -> Result<(), MemFault> {
    c.mem()
        .probe(address, width as usize, MemoryAccessKind::Write)
        .map_err(|fault| MemFault {
            addr: fault.address,
            write: true,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::windows::dll::crt::tests::{area, int, invoke, run, void};

    #[test]
    fn appends_with_recursive_exit_lock_and_grows_the_crt_allocation() {
        run(|c| {
            let kind = RuntimeKind::Msvcrt;
            let width = c.psize();
            let begin = area(c);
            let end = begin + width;
            let first = int(invoke(c, kind, "malloc", &[width]));
            c.write_ptr(begin, first).unwrap();
            c.write_ptr(end, first).unwrap();
            void(invoke(c, kind, "_lock", &[EXIT_LOCK as u64]));
            for callback in [0x1234, 0x5678] {
                assert_eq!(
                    int(invoke(c, kind, "__dllonexit", &[callback, begin, end])),
                    callback
                );
            }
            void(invoke(c, kind, "_unlock", &[EXIT_LOCK as u64]));
            let table = c.read_ptr(begin).unwrap();
            assert_eq!(c.read_ptr(end).unwrap(), table + 2 * width);
            assert_eq!(c.read_ptr(table).unwrap(), 0x1234);
            assert_eq!(c.read_ptr(table + width).unwrap(), 0x5678);
            void(invoke(c, kind, "free", &[table]));
        });
    }
}
