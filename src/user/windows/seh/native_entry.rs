//! Kernel-to-NTDLL exception entry for selected installed libraries.
//!
//! Frame offsets come from the independent entry and unwind observations in
//! `docs/specifications/windows/native-exception-entry-profile/`. In particular,
//! an AMD64 dispatcher unwinds through a machine frame, not a callable return
//! address. The x64 view of an ARM64 kernel is a different ABI. Its wrapper
//! lacks the machine-frame unwind tail required below and is rejected before
//! any stack or CPU state is published.

use super::{ExceptionRecord, Outcome, Proc, RegContext, Thread, WinArch};
use crate::user::windows::context::x64;
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_BAD_STACK, STATUS_INVALID_IMAGE_FORMAT, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED,
    STATUS_STACK_OVERFLOW,
};
use crate::user::windows::process::{native_start, stack};

struct Frame {
    sp: u64,
    bytes: Vec<u8>,
}

impl Frame {
    fn new(record: &ExceptionRecord, context: &RegContext) -> Result<Self, u32> {
        let arch = context.arch();
        // The context model has no XSTATE image. Do not advertise a nonempty
        // extended-state area or let RTL read beyond the captured legacy state.
        if context.flags() & 0x40 != 0 {
            return Err(STATUS_NOT_SUPPORTED);
        }
        let (context_offset, record_offset, length, reserved, residue) = match arch {
            WinArch::X86 => (88usize, 8usize, 828usize, 0u64, 12u64),
            WinArch::X64 => (0, 1264, 1472, 0, 0),
            WinArch::Arm64 => (0, 944, 1104, 16, 0),
        };
        let top = context
            .sp()
            .checked_sub(reserved)
            .and_then(|top| top.checked_sub(length as u64))
            .and_then(|top| top.checked_sub(residue))
            .ok_or(STATUS_BAD_STACK)?;
        let sp = (top & !15) + residue;
        let mut bytes = vec![0; length];
        bytes[context_offset..context_offset + context.bytes().len()]
            .copy_from_slice(context.bytes());
        let encoded = record.encode(arch);
        bytes[record_offset..record_offset + encoded.len()].copy_from_slice(&encoded);

        let extension = context_offset + context.bytes().len();
        // CONTEXT_EX consists of All, Legacy and XState CONTEXT_CHUNK pairs.
        // Offsets are signed relative to CONTEXT_EX, lengths are byte counts.
        let legacy_offset = -(context.bytes().len() as i32);
        let xstate_offset = length - extension;
        let chunks = [
            legacy_offset as u32,
            (length - context_offset) as u32,
            legacy_offset as u32,
            context.bytes().len() as u32,
            xstate_offset as u32,
            0,
        ];
        for (index, value) in chunks.into_iter().enumerate() {
            let offset = extension + 4 * index;
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }

        match arch {
            WinArch::X86 => {
                // The dispatcher reads the pair directly from ESP/ESP+4;
                // there is no caller return-address slot at entry.
                bytes[..4].copy_from_slice(&((sp + record_offset as u64) as u32).to_le_bytes());
                bytes[4..8].copy_from_slice(&((sp + context_offset as u64) as u32).to_le_bytes());
            }
            WinArch::X64 => {
                let source = context.bytes();
                let selector = |offset| u16::from_le_bytes([source[offset], source[offset + 1]]);
                let machine = [
                    context.pc(),
                    u64::from(selector(x64::SEG_CS)),
                    u64::from(context.flags_register()),
                    context.sp(),
                    u64::from(selector(x64::SEG_SS)),
                ];
                for (index, value) in machine.into_iter().enumerate() {
                    let offset = 1424 + 8 * index;
                    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
                }
            }
            WinArch::Arm64 => {}
        }
        Ok(Self { sp, bytes })
    }
}

fn publish(p: &mut Proc, t: &mut Thread, frame: &Frame, entry: u64) -> Result<(), u32> {
    // All guest writes are preflighted, including pages grown through the
    // thread's owned guard. Mapping and execution share one scheduler thread.
    stack::prepare(p, t, frame.sp, frame.bytes.len() as u64).map_err(|_| STATUS_BAD_STACK)?;
    p.space
        .wr(frame.sp, &frame.bytes)
        .map_err(|_| STATUS_BAD_STACK)?;
    t.cpu.set_sp(frame.sp);
    t.cpu.set_pc(entry);
    Ok(())
}

fn verify_x64_frame(p: &Proc, entry: u64) -> Result<(), u32> {
    let function = super::unwind::lookup(p, entry)
        .map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?
        .ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
    let (_, module) = p
        .modules
        .by_address(entry)
        .ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
    let end = module
        .base
        .checked_add(module.size)
        .ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
    let info = function
        .image_base
        .checked_add(u64::from(function.unwind))
        .ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
    if function.image_base != module.base
        || module.base.checked_add(u64::from(function.begin)) != Some(entry)
        || info % 4 != 0
        || info < module.base
        || info
            .checked_add(4)
            .is_none_or(|header_end| header_end > end)
    {
        return Err(STATUS_INVALID_IMAGE_FORMAT);
    }
    let header = p
        .space
        .bytes(info, 4)
        .map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
    let count = u64::from(header[2]);
    let codes_end = info
        .checked_add(4 + count * 2)
        .ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
    if codes_end > end {
        return Err(STATUS_INVALID_IMAGE_FORMAT);
    }
    let codes = p
        .space
        .bytes(info + 4, count as usize * 2)
        .map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
    // UWOP_ALLOC_LARGE(0), 178 * 8 bytes, UWOP_PUSH_MACHFRAME(0).
    // This is the independently observed native AMD64 kernel frame, including
    // its saved RIP/CS/EFLAGS/RSP/SS. A callable wrapper is not interchangeable.
    if !x64_recipe(&header, &codes) {
        return Err(STATUS_INVALID_IMAGE_FORMAT);
    }
    Ok(())
}

fn x64_recipe(header: &[u8], codes: &[u8]) -> bool {
    if header.len() != 4
        || !matches!(header[0], 1 | 2)
        || header[1] != 0
        || header[3] != 0
        || codes.len() != usize::from(header[2]) * 2
    {
        return false;
    }
    let Some(mut saves) = codes.strip_suffix(&[0, 1, 178, 0, 0, 10]) else {
        return false;
    };
    // Both independent native AMD64 captures have these two version-2 epilog
    // slots. Qualify that measured descriptor, without guessing other v2 forms.
    if header[0] == 2 {
        if let Some(rest) = saves.strip_prefix(&[1, 22, 0, 6]) {
            saves = rest;
        }
    }
    // Before the sole stack allocation, restores may only read nonvolatile
    // registers at their matching offsets in the legacy CONTEXT. An additional
    // PUSH/ALLOC/SET_FPREG would invalidate the constructed machine frame.
    if !saves.len().is_multiple_of(4) {
        return false;
    }
    saves.chunks_exact(4).all(|save| {
        let register = usize::from(save[1] >> 4);
        let offset = usize::from(u16::from_le_bytes([save[2], save[3]]));
        save[0] == 0
            && match save[1] & 15 {
                4 if matches!(register, 3 | 5 | 6 | 7 | 12..=15) => {
                    offset * 8 == x64::RAX + register * 8
                }
                8 if (6..16).contains(&register) => offset * 16 == x64::XMM0 + register * 16,
                _ => false,
            }
    })
}

pub(super) fn raise(
    p: &mut Proc,
    t: &mut Thread,
    record: ExceptionRecord,
    context: RegContext,
) -> Outcome {
    if context.arch() != p.arch {
        return Outcome::Fail(format!(
            "native exception context: {STATUS_INVALID_PARAMETER:#010x}"
        ));
    }
    let frame = match Frame::new(&record, &context) {
        Ok(frame) => frame,
        Err(STATUS_BAD_STACK) => return stack_failure(record.code),
        Err(status) => return Outcome::Fail(format!("native exception context: {status:#010x}")),
    };
    let entry = match native_start::resolve_export(p, b"KiUserExceptionDispatcher") {
        Ok(entry) => entry,
        Err(status) => {
            return Outcome::Fail(format!("native exception dispatcher: {status:#010x}"));
        }
    };
    if p.arch == WinArch::X64 {
        if let Err(status) = verify_x64_frame(p, entry) {
            return Outcome::Fail(format!(
                "native AMD64 dispatcher frame is unqualified: {status:#010x}"
            ));
        }
    }
    match publish(p, t, &frame, entry) {
        Ok(()) => Outcome::Continue,
        Err(_) => stack_failure(record.code),
    }
}

fn stack_failure(code: u32) -> Outcome {
    Outcome::ProcessTerminate(if code == STATUS_STACK_OVERFLOW {
        STATUS_STACK_OVERFLOW
    } else {
        STATUS_BAD_STACK
    })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod qualification_tests;
