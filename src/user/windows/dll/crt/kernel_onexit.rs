//! x64 system CRT exit registration. The caller owns a table with four inline
//! encoded callbacks and a count. A fifth callback spills to the process heap.

use crate::error::MemoryAccessKind;
use crate::user::windows::{
    hle::{ApiResult, Archs, Arg::Ptr, Conv::Cdecl, Ctx, Export, Flow},
    memory::{Mem, MemFault},
};

use super::super::pointer_encoding::{decode_value, encode_value};

pub(in crate::user::windows::dll) static KERNELBASE_ONEXIT_EXPORTS: &[Export] =
    &[Export::func("__dllonexit3", Cdecl, &[Ptr, Ptr], register).only(Archs::X64)];

const INLINE_COUNT: u32 = 4;
const INLINE_OFFSET: u64 = 0x10;
const COUNT_OFFSET: u64 = 0x30;

fn register(c: &mut Ctx) -> ApiResult {
    let (callback, table) = (c.ptr(0)?, c.ptr(1)?);
    c.mem()
        .probe(table, COUNT_OFFSET as usize + 4, MemoryAccessKind::Write)
        .map_err(|fault| MemFault {
            addr: fault.address,
            write: true,
        })?;
    let count = c.mem().u32(table + COUNT_OFFSET)?;
    let Some(next_count) = count.checked_add(1) else {
        return Flow::ret(0);
    };
    let heap = c.p.process_heap;
    let inline = table + INLINE_OFFSET;
    let used = u64::from(count) * 8;
    let base = if count < INLINE_COUNT {
        inline
    } else if count == INLINE_COUNT {
        let entries = c.mem().bytes(inline, used as usize)?;
        let Some(block) = c.p.heaps.alloc(&mut c.p.vm, heap, 64, true) else {
            return Flow::ret(0);
        };
        if let Err(error) = c.mem().wr(block, &entries) {
            let _ = c.p.heaps.free(heap, block);
            return Err(error.into());
        }
        block
    } else {
        let base = decode_value(c, c.mem().u64(table)?);
        let next = decode_value(c, c.mem().u64(table + 8)?);
        let Ok(size) = c.p.heaps.size(heap, base) else {
            return Flow::ret(0);
        };
        if base.checked_add(used) != Some(next) || used > size {
            return Flow::ret(0);
        }
        if size - used >= 8 {
            base
        } else {
            let growth = size.min(0x100);
            let expanded =
                c.p.heaps
                    .realloc(&mut c.p.vm, heap, base, size + growth, false, true);
            let Ok(block) = expanded.or_else(|_| {
                c.p.heaps
                    .realloc(&mut c.p.vm, heap, base, size + 32, false, true)
            }) else {
                return Flow::ret(0);
            };
            block
        }
    };
    let slot = base + used;
    c.mem().w64(slot, encode_value(c, callback))?;
    c.mem().w64(table, encode_value(c, base))?;
    c.mem().w64(table + 8, encode_value(c, slot + 8))?;
    c.mem().w32(table + COUNT_OFFSET, next_count)?;
    Flow::ret(callback)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::windows::WinArch;
    use crate::user::windows::dll::crt::tests::{area, int, run};
    use crate::user::windows::loader::{self, SymRef};
    use crate::user::windows::traps::Trap;

    #[test]
    fn core_crt_exit_table_keeps_encoded_callbacks_through_inline_and_heap_growth() {
        run(|c| {
            if c.arch() != WinArch::X64 {
                return;
            }
            let table = area(c);
            let kernel = loader::load_dll(c.p, "api-ms-win-core-crt-l2-1-0.dll").unwrap();
            let address =
                loader::lookup(c.p, kernel, &SymRef::Name(b"__dllonexit3".to_vec(), None))
                    .unwrap()
                    .unwrap();
            let Some(Trap::Entry(api)) = c.p.traps.lookup(address) else {
                panic!("system CRT exit registration did not bind");
            };
            c.t.cpu.set_gpr(2, table);
            let sp = c.entry_sp;
            let mut call = Ctx {
                p: c.p,
                t: c.t,
                api,
                entry_pc: address,
                entry_sp: sp,
                ret_addr: 0,
                cursor: sp,
            };
            for n in 1..=10 {
                call.t.cpu.set_gpr(1, 0x5000 + n);
                assert_eq!(int((api.imp)(&mut call)), 0x5000 + n);
                let base = decode_value(&call, call.mem().u64(table).unwrap());
                assert_eq!(base == table + INLINE_OFFSET, n <= 4);
                assert_eq!(
                    decode_value(&call, call.mem().u64(table + 8).unwrap()),
                    base + 8 * n
                );
                for i in 1..=n {
                    let encoded = call.mem().u64(base + (i - 1) * 8).unwrap();
                    assert_eq!(decode_value(&call, encoded), 0x5000 + i);
                }
                assert_eq!(call.mem().u32(table + COUNT_OFFSET).unwrap(), n as u32);
            }
        });
    }
}
