//! XSAVE / XRSTOR / FXSAVE extended-state interpretation

use crate::smir::interpret::*;
use std::cmp::Ordering;
use std::collections::HashMap;

use crate::smir::ir::context::{ArchRegState, ExitReason, SmirContext, VecValue};
use crate::smir::ir::flags::{FlagSet, FlagUpdate, LazyFlagOp, LazyFlags};
use crate::smir::ir::memory::{MemoryError, SmirMemory};
use crate::smir::ir::ops::{
    HexFpOp, HexFpRecipKind, OpKind, RvVectorState, SmirOp, X86AdxKind, X86BlsKind,
    X86CacheControlKind, X86CountKind, X86OpHint, X86ThreeDNowKind, X86X87ArithmeticDestination,
    X86X87ArithmeticSource, X86X87CompareSource, X86X87Constant, X86X87ControlKind, X86X87DataKind,
    X86X87EnvWidth, X86X87FloatWidth, X86X87IntWidth, X86XSaveKind,
};
use crate::smir::ir::types::*;
use crate::smir::ir::{CallTarget, SmirBlock, SmirFunction, Terminator, TrapKind};

impl SmirInterpreter {
    /// Snapshot a legacy packed-SSE architectural destination before an
    /// operation whose generic vector implementation clears inactive words.
    pub(crate) fn legacy_xmm_snapshot(
        ctx: &SmirContext,
        dst: VReg,
        hint: Option<X86OpHint>,
    ) -> Option<VecValue> {
        if matches!(hint, Some(X86OpHint::SseOp { .. }))
            && matches!(dst, VReg::Arch(ArchReg::X86(X86Reg::Xmm(_))))
        {
            Some(Self::read_vec(ctx, dst))
        } else {
            None
        }
    }

    /// Legacy 128-bit SSE operations preserve the shared YMM/ZMM backing
    /// state above bit 127. Restore those words after the low XMM result has
    /// been computed by a width-bounded generic vector operation.
    pub(crate) fn restore_legacy_xmm_upper(
        ctx: &mut SmirContext,
        dst: VReg,
        old: Option<VecValue>,
    ) {
        if let Some(old) = old {
            let mut result = Self::read_vec(ctx, dst);
            result[2..].copy_from_slice(&old[2..]);
            Self::write_vec(ctx, dst, result);
        }
    }

    pub(crate) fn x86_fxsave_image(ctx: &SmirContext, rex_w: bool) -> [u8; 464] {
        let mut image = [0u8; 464];
        let ArchRegState::X86_64(x86) = &ctx.arch_regs else {
            return image;
        };
        image[0..2].copy_from_slice(&x86.x87.control_word.to_le_bytes());
        image[2..4].copy_from_slice(&x86.x87.status_word.to_le_bytes());
        image[4] = x86.x87.abridged_tag_word();
        image[6..8].copy_from_slice(&(x86.x87.last_opcode & 0x07FF).to_le_bytes());
        if rex_w {
            image[8..16].copy_from_slice(&x86.x87.instr_ptr.to_le_bytes());
            image[16..24].copy_from_slice(&x86.x87.data_ptr.to_le_bytes());
        } else {
            image[8..12].copy_from_slice(&(x86.x87.instr_ptr as u32).to_le_bytes());
            image[16..20].copy_from_slice(&(x86.x87.data_ptr as u32).to_le_bytes());
        }
        image[24..28].copy_from_slice(&x86.mxcsr.to_le_bytes());
        image[28..32].copy_from_slice(&0x0000_FFFFu32.to_le_bytes());

        // Register payload slots are in logical ST(0)..ST(7) order even though
        // abridged FTW bits above are in physical R0..R7 order.
        for logical in 0..8u8 {
            let physical = x86.x87.physical_index(logical);
            let offset = 32 + logical as usize * 16;
            image[offset..offset + 10].copy_from_slice(&x86.x87.regs[physical]);
        }
        for register in 0..16 {
            let offset = 160 + register * 16;
            image[offset..offset + 8].copy_from_slice(&x86.xmm[register][0].to_le_bytes());
            image[offset + 8..offset + 16].copy_from_slice(&x86.xmm[register][1].to_le_bytes());
        }
        image
    }

    pub(crate) fn restore_x86_fxsave_image(ctx: &mut SmirContext, image: &[u8; 512], rex_w: bool) {
        let ArchRegState::X86_64(x86) = &mut ctx.arch_regs else {
            return;
        };
        x86.x87.control_word = u16::from_le_bytes(image[0..2].try_into().unwrap());
        x86.x87.status_word = u16::from_le_bytes(image[2..4].try_into().unwrap());
        let abridged_tag = image[4];
        x86.x87.last_opcode = u16::from_le_bytes(image[6..8].try_into().unwrap()) & 0x07FF;
        if rex_w {
            x86.x87.instr_ptr = u64::from_le_bytes(image[8..16].try_into().unwrap());
            x86.x87.data_ptr = u64::from_le_bytes(image[16..24].try_into().unwrap());
        } else {
            x86.x87.instr_ptr = u32::from_le_bytes(image[8..12].try_into().unwrap()) as u64;
            x86.x87.data_ptr = u32::from_le_bytes(image[16..20].try_into().unwrap()) as u64;
        }
        for logical in 0..8u8 {
            let physical = x86.x87.physical_index(logical);
            let offset = 32 + logical as usize * 16;
            x86.x87.regs[physical].copy_from_slice(&image[offset..offset + 10]);
        }
        x86.x87.restore_abridged_tag_word(abridged_tag);
        x86.mxcsr = u32::from_le_bytes(image[24..28].try_into().unwrap());
        for register in 0..16 {
            let offset = 160 + register * 16;
            x86.xmm[register][0] =
                u64::from_le_bytes(image[offset..offset + 8].try_into().unwrap());
            x86.xmm[register][1] =
                u64::from_le_bytes(image[offset + 8..offset + 16].try_into().unwrap());
        }
    }

    const X86_XSAVE_SUPPORTED: u64 = 0x7 | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 9) | (1 << 19);

    pub(crate) fn x86_xstate_in_use(x86: &crate::smir::X86RegState) -> u64 {
        let mut result = 0;
        if x86.x87.control_word != 0x037F
            || x86.x87.status_word != 0
            || x86.x87.tag_word != 0xFFFF
            || x86.x87.data_ptr != 0
            || x86.x87.instr_ptr != 0
            || x86.x87.last_opcode != 0
        {
            result |= 1;
        }
        if x86.xmm[..16]
            .iter()
            .any(|register| register[..2].iter().any(|lane| *lane != 0))
        {
            result |= 1 << 1;
        }
        if x86.xmm[..16]
            .iter()
            .any(|register| register[2..4].iter().any(|lane| *lane != 0))
        {
            result |= 1 << 2;
        }
        if x86.k.iter().any(|register| *register != 0) {
            result |= 1 << 5;
        }
        if x86.xmm[..16]
            .iter()
            .any(|register| register[4..8].iter().any(|lane| *lane != 0))
        {
            result |= 1 << 6;
        }
        if x86.xmm[16..32]
            .iter()
            .any(|register| register[..8].iter().any(|lane| *lane != 0))
        {
            result |= 1 << 7;
        }
        if x86.pkru != 0 {
            result |= 1 << 9;
        }
        if x86.gpr[16..32].iter().any(|register| *register != 0) {
            result |= 1 << 19;
        }
        result
    }

    pub(crate) fn save_x86_xsave_standard(
        ctx: &SmirContext,
        memory: &mut dyn SmirMemory,
        addr: u64,
        rex_w: bool,
        requested: u64,
        kind: X86XSaveKind,
    ) -> Result<(), MemoryError> {
        let ArchRegState::X86_64(x86) = &ctx.arch_regs else {
            return Ok(());
        };
        let rfbm = requested & x86.xcr0 & Self::X86_XSAVE_SUPPORTED;
        let in_use = Self::x86_xstate_in_use(x86);
        let save_mask = if kind == X86XSaveKind::XSaveOpt {
            rfbm & in_use
        } else {
            rfbm
        };
        let legacy = Self::x86_fxsave_image(ctx, rex_w);
        // XSAVE and XSAVEOPT read OLD_BV before any component store.
        let mut old_xstate = [0u8; 8];
        memory.read(addr + 512, &mut old_xstate)?;
        let old_xstate = u64::from_le_bytes(old_xstate);

        if save_mask & 1 != 0 {
            memory.write(addr, &legacy[0..5])?;
            memory.write(addr + 6, &legacy[6..24])?;
            for register in 0..8 {
                let offset = 32 + register * 16;
                memory.write(addr + offset as u64, &legacy[offset..offset + 10])?;
            }
        }
        if rfbm & 0x6 != 0 {
            memory.write(addr + 24, &legacy[24..32])?;
        }
        if save_mask & (1 << 1) != 0 {
            memory.write(addr + 160, &legacy[160..416])?;
        }

        let mut write_lanes =
            |offset: u64, registers: std::ops::Range<usize>, lanes: std::ops::Range<usize>| {
                let mut image = Vec::with_capacity(registers.len() * lanes.len() * 8);
                for register in registers {
                    for lane in lanes.clone() {
                        image.extend_from_slice(&x86.xmm[register][lane].to_le_bytes());
                    }
                }
                memory.write(addr + offset, &image)
            };
        if save_mask & (1 << 2) != 0 {
            write_lanes(576, 0..16, 2..4)?;
        }
        if save_mask & (1 << 6) != 0 {
            write_lanes(1152, 0..16, 4..8)?;
        }
        if save_mask & (1 << 7) != 0 {
            write_lanes(1664, 16..32, 0..8)?;
        }
        if save_mask & (1 << 19) != 0 {
            let mut image = Vec::with_capacity(128);
            for register in &x86.gpr[16..32] {
                image.extend_from_slice(&register.to_le_bytes());
            }
            memory.write(addr + 960, &image)?;
        }
        if save_mask & (1 << 5) != 0 {
            let mut image = Vec::with_capacity(64);
            for register in &x86.k {
                image.extend_from_slice(&register.to_le_bytes());
            }
            memory.write(addr + 1088, &image)?;
        }
        if save_mask & (1 << 9) != 0 {
            memory.write(addr + 2688, &u64::from(x86.pkru).to_le_bytes())?;
        }

        let new_xstate = (old_xstate & !rfbm) | (in_use & rfbm);
        memory.write(addr + 512, &new_xstate.to_le_bytes())?;
        Ok(())
    }

    pub(crate) fn x86_xsave_component_size(component: u8) -> u64 {
        match component {
            2 => 256,
            5 => 64,
            6 => 512,
            7 => 1024,
            9 => 8,
            19 => 128,
            _ => unreachable!("unsupported XSAVE component {component}"),
        }
    }

    pub(crate) fn write_x86_xsave_extended_component(
        memory: &mut dyn SmirMemory,
        addr: u64,
        x86: &crate::smir::X86RegState,
        component: u8,
    ) -> Result<(), MemoryError> {
        let mut image = Vec::with_capacity(Self::x86_xsave_component_size(component) as usize);
        match component {
            2 => {
                for register in &x86.xmm[..16] {
                    for lane in &register[2..4] {
                        image.extend_from_slice(&lane.to_le_bytes());
                    }
                }
            }
            5 => {
                for register in &x86.k {
                    image.extend_from_slice(&register.to_le_bytes());
                }
            }
            6 => {
                for register in &x86.xmm[..16] {
                    for lane in &register[4..8] {
                        image.extend_from_slice(&lane.to_le_bytes());
                    }
                }
            }
            7 => {
                for register in &x86.xmm[16..32] {
                    for lane in &register[..8] {
                        image.extend_from_slice(&lane.to_le_bytes());
                    }
                }
            }
            9 => image.extend_from_slice(&u64::from(x86.pkru).to_le_bytes()),
            19 => {
                for register in &x86.gpr[16..32] {
                    image.extend_from_slice(&register.to_le_bytes());
                }
            }
            _ => unreachable!("unsupported XSAVE component {component}"),
        }
        debug_assert_eq!(
            image.len(),
            Self::x86_xsave_component_size(component) as usize
        );
        memory.write(addr, &image)
    }

    pub(crate) fn save_x86_xsave_compacted(
        ctx: &SmirContext,
        memory: &mut dyn SmirMemory,
        addr: u64,
        rex_w: bool,
        requested: u64,
    ) -> Result<(), MemoryError> {
        let ArchRegState::X86_64(x86) = &ctx.arch_regs else {
            return Ok(());
        };
        // The repository advertises no IA32_XSS-managed supervisor
        // components, so XSAVES currently has the same represented RFBM as
        // XSAVEC. Keeping the SMIR kinds distinct preserves that boundary.
        let rfbm = requested & x86.xcr0 & Self::X86_XSAVE_SUPPORTED;
        let mut save_mask = rfbm & Self::x86_xstate_in_use(x86);
        if rfbm & (1 << 1) != 0 && x86.mxcsr != 0x1F80 {
            save_mask |= 1 << 1;
        }
        let legacy = Self::x86_fxsave_image(ctx, rex_w);
        if save_mask & 1 != 0 {
            memory.write(addr, &legacy[0..5])?;
            memory.write(addr + 6, &legacy[6..24])?;
            for register in 0..8 {
                let offset = 32 + register * 16;
                memory.write(addr + offset as u64, &legacy[offset..offset + 10])?;
            }
        }
        if save_mask & (1 << 1) != 0 {
            memory.write(addr + 24, &legacy[24..32])?;
            memory.write(addr + 160, &legacy[160..416])?;
        }

        let mut next_offset = 576;
        for component in [2u8, 5, 6, 7, 9, 19] {
            let bit = 1u64 << component;
            if rfbm & bit != 0 {
                if save_mask & bit != 0 {
                    Self::write_x86_xsave_extended_component(
                        memory,
                        addr + next_offset,
                        x86,
                        component,
                    )?;
                }
                next_offset += Self::x86_xsave_component_size(component);
            }
        }
        memory.write(addr + 512, &save_mask.to_le_bytes())?;
        memory.write(addr + 520, &((1u64 << 63) | rfbm).to_le_bytes())?;
        Ok(())
    }

    pub(crate) fn restore_x86_xsave(
        ctx: &mut SmirContext,
        memory: &mut dyn SmirMemory,
        addr: u64,
        rex_w: bool,
        requested: u64,
        supervisor: bool,
    ) -> Result<bool, MemoryError> {
        let ArchRegState::X86_64(current) = &ctx.arch_regs else {
            return Ok(true);
        };
        let mut restored = current.clone();
        let rfbm = requested & restored.xcr0 & Self::X86_XSAVE_SUPPORTED;
        let mut header = [0u8; 64];
        memory.read(addr + 512, &mut header)?;
        let xstate_bv = u64::from_le_bytes(header[0..8].try_into().unwrap());
        let xcomp_bv = u64::from_le_bytes(header[8..16].try_into().unwrap());
        let compacted = xcomp_bv & (1 << 63) != 0;
        let format = xcomp_bv & !(1 << 63);
        let enabled = restored.xcr0 & Self::X86_XSAVE_SUPPORTED;
        let malformed = if compacted {
            format & !enabled != 0
                || xstate_bv & !xcomp_bv != 0
                || header[16..].iter().any(|byte| *byte != 0)
        } else {
            xstate_bv & !enabled != 0 || header[8..24].iter().any(|byte| *byte != 0)
        };
        if malformed || (supervisor && !compacted) {
            return Ok(false);
        }
        let to_restore = if compacted {
            rfbm & format & xstate_bv
        } else {
            rfbm & xstate_bv
        };
        let to_initialize = if compacted {
            (rfbm & !xstate_bv) | (rfbm & !format)
        } else {
            rfbm & !xstate_bv
        };

        if to_restore & 1 != 0 {
            let mut image = [0u8; 160];
            memory.read(addr, &mut image[0..24])?;
            for register in 0..8 {
                let offset = 32 + register * 16;
                memory.read(addr + offset as u64, &mut image[offset..offset + 10])?;
            }
            restored.x87.control_word = u16::from_le_bytes(image[0..2].try_into().unwrap());
            restored.x87.status_word = u16::from_le_bytes(image[2..4].try_into().unwrap());
            let abridged_tag = image[4];
            restored.x87.last_opcode = u16::from_le_bytes(image[6..8].try_into().unwrap()) & 0x07FF;
            if rex_w {
                restored.x87.instr_ptr = u64::from_le_bytes(image[8..16].try_into().unwrap());
                restored.x87.data_ptr = u64::from_le_bytes(image[16..24].try_into().unwrap());
            } else {
                restored.x87.instr_ptr =
                    u32::from_le_bytes(image[8..12].try_into().unwrap()) as u64;
                restored.x87.data_ptr =
                    u32::from_le_bytes(image[16..20].try_into().unwrap()) as u64;
            }
            for logical in 0..8u8 {
                let physical = restored.x87.physical_index(logical);
                let offset = 32 + logical as usize * 16;
                restored.x87.regs[physical].copy_from_slice(&image[offset..offset + 10]);
            }
            restored.x87.restore_abridged_tag_word(abridged_tag);
        } else if to_initialize & 1 != 0 {
            restored.x87.init();
        }

        if compacted {
            if to_restore & (1 << 1) != 0 {
                let mut mxcsr = [0u8; 4];
                memory.read(addr + 24, &mut mxcsr)?;
                let mxcsr = u32::from_le_bytes(mxcsr);
                if mxcsr & !0x0000_FFFF != 0 {
                    return Ok(false);
                }
                restored.mxcsr = mxcsr;
                let mut image = [0u8; 256];
                memory.read(addr + 160, &mut image)?;
                for register in 0..16 {
                    let offset = register * 16;
                    restored.xmm[register][0] =
                        u64::from_le_bytes(image[offset..offset + 8].try_into().unwrap());
                    restored.xmm[register][1] =
                        u64::from_le_bytes(image[offset + 8..offset + 16].try_into().unwrap());
                }
            } else if to_initialize & (1 << 1) != 0 {
                restored.mxcsr = 0x1F80;
                for register in &mut restored.xmm[..16] {
                    register[0..2].fill(0);
                }
            }
        } else {
            if rfbm & 0x6 != 0 {
                let mut mxcsr = [0u8; 4];
                memory.read(addr + 24, &mut mxcsr)?;
                let mxcsr = u32::from_le_bytes(mxcsr);
                if mxcsr & !0x0000_FFFF != 0 {
                    return Ok(false);
                }
                restored.mxcsr = mxcsr;
            }
            if to_restore & (1 << 1) != 0 {
                let mut image = [0u8; 256];
                memory.read(addr + 160, &mut image)?;
                for register in 0..16 {
                    let offset = register * 16;
                    restored.xmm[register][0] =
                        u64::from_le_bytes(image[offset..offset + 8].try_into().unwrap());
                    restored.xmm[register][1] =
                        u64::from_le_bytes(image[offset + 8..offset + 16].try_into().unwrap());
                }
            } else if to_initialize & (1 << 1) != 0 {
                for register in &mut restored.xmm[..16] {
                    register[0..2].fill(0);
                }
            }
        }

        let mut offsets = [None; 6];
        let components = [2u8, 5, 6, 7, 9, 19];
        if compacted {
            let mut next_offset = 576;
            for (index, component) in components.iter().copied().enumerate() {
                if format & (1u64 << component) != 0 {
                    offsets[index] = Some(next_offset);
                    next_offset += Self::x86_xsave_component_size(component);
                }
            }
        } else {
            offsets = [
                Some(576),
                Some(1088),
                Some(1152),
                Some(1664),
                Some(2688),
                Some(960),
            ];
        }
        for (index, component) in components.iter().copied().enumerate() {
            let bit = 1u64 << component;
            if to_restore & bit != 0 {
                Self::restore_x86_xsave_extended_component(
                    memory,
                    addr + offsets[index].expect("restored component must be present in format"),
                    &mut restored,
                    component,
                )?;
            } else if to_initialize & bit != 0 {
                match component {
                    2 => {
                        for register in &mut restored.xmm[..16] {
                            register[2..4].fill(0);
                        }
                    }
                    5 => restored.k.fill(0),
                    6 => {
                        for register in &mut restored.xmm[..16] {
                            register[4..8].fill(0);
                        }
                    }
                    7 => {
                        for register in &mut restored.xmm[16..32] {
                            register[0..8].fill(0);
                        }
                    }
                    9 => restored.pkru = 0,
                    19 => restored.gpr[16..32].fill(0),
                    _ => unreachable!(),
                }
            }
        }

        restored.xgetbv1 = Self::x86_xstate_in_use(&restored);
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            *x86 = restored;
        }
        Ok(true)
    }

    pub(crate) fn restore_x86_xsave_extended_component(
        memory: &mut dyn SmirMemory,
        addr: u64,
        x86: &mut crate::smir::X86RegState,
        component: u8,
    ) -> Result<(), MemoryError> {
        match component {
            2 => Self::restore_x86_xsave_lanes(memory, addr, &mut x86.xmm, 0..16, 2..4),
            5 => {
                let mut image = [0u8; 64];
                memory.read(addr, &mut image)?;
                for register in 0..8 {
                    let offset = register * 8;
                    x86.k[register] =
                        u64::from_le_bytes(image[offset..offset + 8].try_into().unwrap());
                }
                Ok(())
            }
            6 => Self::restore_x86_xsave_lanes(memory, addr, &mut x86.xmm, 0..16, 4..8),
            7 => Self::restore_x86_xsave_lanes(memory, addr, &mut x86.xmm, 16..32, 0..8),
            9 => {
                let mut image = [0u8; 8];
                memory.read(addr, &mut image)?;
                x86.pkru = u64::from_le_bytes(image) as u32;
                Ok(())
            }
            19 => {
                let mut image = [0u8; 128];
                memory.read(addr, &mut image)?;
                for register in 0..16 {
                    let offset = register * 8;
                    x86.gpr[16 + register] =
                        u64::from_le_bytes(image[offset..offset + 8].try_into().unwrap());
                }
                Ok(())
            }
            _ => unreachable!("unsupported XSAVE component {component}"),
        }
    }

    pub(crate) fn restore_x86_xsave_lanes(
        memory: &mut dyn SmirMemory,
        addr: u64,
        xmm: &mut [VecValue; 32],
        registers: std::ops::Range<usize>,
        lanes: std::ops::Range<usize>,
    ) -> Result<(), MemoryError> {
        let mut image = vec![0u8; registers.len() * lanes.len() * 8];
        memory.read(addr, &mut image)?;
        let mut cursor = 0;
        for register in registers {
            for lane in lanes.clone() {
                xmm[register][lane] =
                    u64::from_le_bytes(image[cursor..cursor + 8].try_into().unwrap());
                cursor += 8;
            }
        }
        Ok(())
    }
}
