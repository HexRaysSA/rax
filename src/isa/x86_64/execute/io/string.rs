//! String I/O instructions: INSB, INSW, OUTSB, OUTSW.

use crate::error::Result;
use crate::vm::vcpu::VcpuExit;

use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};
use crate::isa::x86_64::flags;

/// INSB (0x6C) - Input byte from port DX into ES:[RDI]
pub fn insb(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    ins_common(vcpu, ctx, 1)
}

/// INSW/INSD (0x6D) - Input word/dword from port DX into ES:[RDI]
pub fn insw(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let size = if ctx.op_size == 2 { 2 } else { 4 };
    ins_common(vcpu, ctx, size)
}

fn ins_common(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext, size: u8) -> Result<Option<VcpuExit>> {
    let port = vcpu.regs.rdx as u16;
    let df = (vcpu.regs.rflags & flags::bits::DF) != 0;
    let rep = matches!(ctx.rep_prefix, Some(0xF3) | Some(0xF2));
    let addr_size = addr_size_bytes(vcpu, ctx);

    if rep && rep_count(vcpu, addr_size) == 0 {
        normalize_zero_rep_count(vcpu, addr_size);
        vcpu.regs.rip += ctx.cursor as u64;
        return Ok(None);
    }

    vcpu.check_io_permission(port, size)?;

    // `rep ins` is emulated one element per VM exit: each iteration performs the
    // port input into ES:[RDI], advances RDI by the operand size (honoring DF),
    // and decrements RCX. The instruction is only retired (RIP advanced) once
    // RCX reaches zero; until then RIP is left pointing at the same instruction
    // so it re-executes for the next element. This keeps each port read a
    // discrete `IoIn` exit, matching hardware semantics where every string
    // element is an individual port access (a batched fast path is invisible to
    // FIFO-style devices and to consumers that count discrete port reads).
    // ES:[RDI]: ES's base outside 64-bit mode (get_segment_base), wrapped.
    let addr = vcpu.segment_linear(vcpu.get_segment_base(Some(0x26)), di_addr(vcpu, addr_size));
    vcpu.set_io_pending_mem(size, addr);
    update_di(vcpu, addr_size, size, df);

    if rep {
        let remaining = dec_rep_count(vcpu, addr_size);
        if remaining == 0 {
            vcpu.regs.rip += ctx.cursor as u64;
        }
    } else {
        vcpu.regs.rip += ctx.cursor as u64;
    }

    Ok(Some(VcpuExit::IoIn { port, size }))
}

fn addr_size_bytes(vcpu: &X86_64Vcpu, ctx: &InsnContext) -> u8 {
    if vcpu.sregs.cs.l {
        if ctx.address_size_override { 4 } else { 8 }
    } else {
        let default_16bit = !vcpu.sregs.cs.db;
        let is_16bit = default_16bit ^ ctx.address_size_override;
        if is_16bit { 2 } else { 4 }
    }
}

fn di_addr(vcpu: &X86_64Vcpu, addr_size: u8) -> u64 {
    match addr_size {
        2 => vcpu.regs.rdi & 0xFFFF,
        4 => vcpu.regs.rdi & 0xFFFF_FFFF,
        _ => vcpu.regs.rdi,
    }
}

fn update_di(vcpu: &mut X86_64Vcpu, addr_size: u8, size: u8, df: bool) {
    match addr_size {
        2 => {
            let di = vcpu.regs.rdi as u16;
            let delta = size as u16;
            let di = if df {
                di.wrapping_sub(delta)
            } else {
                di.wrapping_add(delta)
            };
            vcpu.regs.rdi = (vcpu.regs.rdi & !0xFFFF) | di as u64;
        }
        4 => {
            let edi = vcpu.regs.rdi as u32;
            let delta = size as u32;
            let edi = if df {
                edi.wrapping_sub(delta)
            } else {
                edi.wrapping_add(delta)
            };
            vcpu.regs.rdi = edi as u64;
        }
        _ => {
            let delta = size as u64;
            if df {
                vcpu.regs.rdi = vcpu.regs.rdi.wrapping_sub(delta);
            } else {
                vcpu.regs.rdi = vcpu.regs.rdi.wrapping_add(delta);
            }
        }
    }
}

fn rep_count(vcpu: &X86_64Vcpu, addr_size: u8) -> u64 {
    match addr_size {
        2 => vcpu.regs.rcx & 0xFFFF,
        4 => vcpu.regs.rcx & 0xFFFF_FFFF,
        _ => vcpu.regs.rcx,
    }
}

fn dec_rep_count(vcpu: &mut X86_64Vcpu, addr_size: u8) -> u64 {
    match addr_size {
        2 => {
            let cx = (vcpu.regs.rcx as u16).wrapping_sub(1);
            vcpu.regs.rcx = (vcpu.regs.rcx & !0xFFFF) | cx as u64;
            cx as u64
        }
        4 => {
            let ecx = (vcpu.regs.rcx as u32).wrapping_sub(1);
            vcpu.regs.rcx = ecx as u64;
            ecx as u64
        }
        _ => {
            vcpu.regs.rcx = vcpu.regs.rcx.wrapping_sub(1);
            vcpu.regs.rcx
        }
    }
}

fn normalize_zero_rep_count(vcpu: &mut X86_64Vcpu, addr_size: u8) {
    if addr_size == 4 {
        vcpu.regs.rcx = (vcpu.regs.rcx as u32) as u64;
    }
}

/// OUTSB (0x6E) - Output byte from DS:[RSI] to port DX
pub fn outsb(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    outs_common(vcpu, ctx, 1)
}

fn outs_common(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext, size: u8) -> Result<Option<VcpuExit>> {
    let port = vcpu.regs.rdx as u16;
    let df = (vcpu.regs.rflags & flags::bits::DF) != 0;
    let rep = matches!(ctx.rep_prefix, Some(0xF3) | Some(0xF2));
    let addr_size = addr_size_bytes(vcpu, ctx);

    // Check REP count - if zero, skip the operation
    if rep && rep_count(vcpu, addr_size) == 0 {
        normalize_zero_rep_count(vcpu, addr_size);
        vcpu.regs.rip += ctx.cursor as u64;
        return Ok(None);
    }

    // I/O permission precedes the source-memory read architecturally.
    vcpu.check_io_permission(port, size)?;

    // Read data from DS:RSI; FS/GS segment overrides provide nonzero bases in
    // long mode, while other segment bases are handled for legacy modes.
    let addr = vcpu.segment_linear(
        vcpu.get_segment_base(ctx.segment_override),
        si_addr(vcpu, addr_size),
    );
    let val = vcpu.read_mem(addr, size)?;
    let mut data = Vec::with_capacity(size as usize);
    for i in 0..size {
        data.push((val >> (i * 8)) as u8);
    }

    // Update RSI
    update_si(vcpu, addr_size, size, df);

    // Handle REP prefix
    if rep {
        let remaining = dec_rep_count(vcpu, addr_size);
        if remaining == 0 {
            vcpu.regs.rip += ctx.cursor as u64;
        }
        // RIP stays the same if remaining > 0 (will re-execute)
    } else {
        vcpu.regs.rip += ctx.cursor as u64;
    }

    Ok(Some(VcpuExit::IoOut { port, data }))
}

fn si_addr(vcpu: &X86_64Vcpu, addr_size: u8) -> u64 {
    match addr_size {
        2 => vcpu.regs.rsi & 0xFFFF,
        4 => vcpu.regs.rsi & 0xFFFF_FFFF,
        _ => vcpu.regs.rsi,
    }
}

fn update_si(vcpu: &mut X86_64Vcpu, addr_size: u8, size: u8, df: bool) {
    match addr_size {
        2 => {
            let si = vcpu.regs.rsi as u16;
            let delta = size as u16;
            let si = if df {
                si.wrapping_sub(delta)
            } else {
                si.wrapping_add(delta)
            };
            vcpu.regs.rsi = (vcpu.regs.rsi & !0xFFFF) | si as u64;
        }
        4 => {
            let esi = vcpu.regs.rsi as u32;
            let delta = size as u32;
            let esi = if df {
                esi.wrapping_sub(delta)
            } else {
                esi.wrapping_add(delta)
            };
            vcpu.regs.rsi = esi as u64;
        }
        _ => {
            let delta = size as u64;
            if df {
                vcpu.regs.rsi = vcpu.regs.rsi.wrapping_sub(delta);
            } else {
                vcpu.regs.rsi = vcpu.regs.rsi.wrapping_add(delta);
            }
        }
    }
}

/// OUTSW/OUTSD (0x6F) - Output word/dword from DS:[RSI] to port DX
pub fn outsw(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let size = if ctx.op_size == 2 { 2 } else { 4 };
    outs_common(vcpu, ctx, size)
}
