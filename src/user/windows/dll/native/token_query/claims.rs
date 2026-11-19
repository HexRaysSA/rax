//! Empty claim results with the installed WoW64 buffer clearing order.
use super::{Ctx, Flow, Mem, STATUS_BUFFER_TOO_SMALL, STATUS_SUCCESS};
use crate::user::mm::AddressSpace;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::ApiResult;
use crate::user::windows::memory::MemFault;
use crate::user::windows::security::token::claims::EMPTY_RECORD;

pub(super) fn publish_empty(c: &Ctx, output: u64, length: u32, returned: u64) -> ApiResult {
    let required = EMPTY_RECORD.len() as u32;
    c.mem().w32(returned, required)?;
    if length < required {
        return Flow::ret(STATUS_BUFFER_TOO_SMALL.into());
    }
    if c.arch() == WinArch::X86 {
        clear_wow64(c.mem(), output, u64::from(length))?;
        c.mem().w16(output, 1)?;
    } else {
        c.mem().wr(output, &EMPTY_RECORD)?;
    }
    Flow::ret(STATUS_SUCCESS.into())
}

// Windows 11 ARM64 build 29708 uses the installed 16-byte vector stores
// below. Splitting each pair preserves the reached half at a page boundary.
// The large, zero-filled path uses aligned 64-byte stores.
fn clear_wow64(memory: &AddressSpace, start: u64, length: u64) -> Result<(), MemFault> {
    const VECTOR: [u8; 16] = [0; 16];
    const LINE: [u8; 64] = [0; 64];
    let end = start + length;
    let store = |address| memory.wr(address, &VECTOR);
    store(start)?;
    match length {
        16..=63 => {
            store(end - 16)?;
            if length >= 32 {
                store(start + 16)?;
                store(end - 32)?;
            }
            return Ok(());
        }
        64..=96 => {
            for address in [start + 16, start + 32, start + 48, end - 32, end - 16] {
                store(address)?;
            }
            return Ok(());
        }
        97..=32767 => {
            let mut cursor = (start & !15) + 16;
            while cursor < end - 64 {
                for offset in [0, 16, 32, 48] {
                    store(cursor + offset)?;
                }
                cursor += 64;
            }
        }
        _ => {
            let aligned = start & !15;
            for offset in [16, 32, 48] {
                store(aligned + offset)?;
            }
            let mut cursor = (aligned & !63) + 64;
            while cursor < end - 64 {
                memory.wr(cursor, &LINE)?;
                cursor += 64;
            }
        }
    }
    for offset in [64, 48, 32, 16] {
        store(end - offset)?;
    }
    Ok(())
}
