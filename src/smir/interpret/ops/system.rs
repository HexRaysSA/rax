//! System/privileged op execution

use crate::isa::x86_64::execute::control::{
    X86FarJumpDescriptor, decode_x86_far_call_descriptor, decode_x86_far_call_gate_target,
    decode_x86_far_jump_call_gate_target, decode_x86_far_jump_descriptor,
    validate_x86_far_call_target_offset, x86_far_jump_is_ia32e_call_gate,
};
use crate::isa::x86_64::execute::system::{
    X86ControlWriteFault, X86ControlWriteState, X86FastSystemTransferFault,
    X86FastSystemTransferState, X86MsrFault, X86MsrState, X86PmcFault, X86PmcState,
    X86SystemDescriptorFault, decode_x86_ldt_descriptor, decode_x86_tss_descriptor,
    evaluate_x86_sysenter, evaluate_x86_sysexit, read_x86_msr, read_x86_pmc,
    validate_x86_control_write, validate_x86_msr_write,
};
use crate::smir::interpret::*;
use crate::smir::ir::context::{
    ArchRegState, ExitReason, SmirContext, VecValue, X86SystemSegmentCache,
};
use crate::smir::ir::flags::{FlagSet, FlagUpdate, LazyFlagOp, LazyFlags};
use crate::smir::ir::memory::{MemoryError, SmirMemory};
use crate::smir::ir::ops::{
    HexFpOp, HexFpRecipKind, OpKind, RvVectorState, SmirOp, X86AdxKind, X86BlsKind,
    X86CacheControlKind, X86ControlReg, X86CountKind, X86DebugReg, X86DescriptorTable,
    X86FarCallOp, X86FarJumpOp, X86FastSystemTransferKind, X86LmswSource, X86MonitorMwaitOp,
    X86OpHint, X86SmswTarget, X86SystemSelector, X86SystemSelectorSource, X86SystemSelectorTarget,
    X86ThreeDNowKind, X86WaitPkgOp, X86X87ArithmeticDestination, X86X87ArithmeticSource,
    X86X87CompareSource, X86X87Constant, X86X87ControlKind, X86X87DataKind, X86X87EnvWidth,
    X86X87FloatWidth, X86X87IntWidth, X86XSaveKind,
};
use crate::smir::ir::types::*;
use crate::smir::ir::{CallTarget, SmirBlock, SmirFunction, Terminator, TrapKind};

pub(super) fn x86_system_segment_cache(
    segment: &crate::vm::vcpu::Segment,
) -> X86SystemSegmentCache {
    X86SystemSegmentCache {
        base: segment.base,
        limit: segment.limit,
        type_: segment.type_,
        present: segment.present,
        dpl: segment.dpl,
        db: segment.db,
        s: segment.s,
        l: segment.l,
        g: segment.g,
        avl: segment.avl,
        unusable: segment.unusable,
    }
}

pub(super) fn request_x86_descriptor_fault(
    ctx: &mut SmirContext,
    guest_pc: u64,
    fault: X86SystemDescriptorFault,
) {
    match fault {
        X86SystemDescriptorFault::GeneralProtection { error_code } => {
            ctx.request_exit(ExitReason::GeneralProtection {
                addr: guest_pc,
                error_code,
            });
        }
        X86SystemDescriptorFault::SegmentNotPresent { error_code } => {
            ctx.request_exit(ExitReason::SegmentNotPresent {
                addr: guest_pc,
                error_code,
            });
        }
    }
}

pub(super) fn x86_far_jump_descriptor_address(
    x86: &crate::smir::ir::context::X86RegState,
    selector: u16,
    size: u64,
) -> Result<u64, X86SystemDescriptorFault> {
    let error_code = u32::from(selector & 0xFFFC);
    if selector & 0xFFFC == 0 {
        return Err(X86SystemDescriptorFault::GeneralProtection { error_code: 0 });
    }
    let ti = selector & 4 != 0;
    if ti && (x86.ldtr_selector & 0xFFFC == 0 || x86.ldtr_cache.unusable) {
        return Err(X86SystemDescriptorFault::GeneralProtection { error_code });
    }
    let (base, limit) = if ti {
        (x86.ldtr_cache.base, u64::from(x86.ldtr_cache.limit))
    } else {
        (x86.gdtr_base, u64::from(x86.gdtr_limit))
    };
    let offset = u64::from(selector >> 3) * 8;
    let Some(last_offset) = offset.checked_add(size - 1) else {
        return Err(X86SystemDescriptorFault::GeneralProtection { error_code });
    };
    if last_offset > limit {
        return Err(X86SystemDescriptorFault::GeneralProtection { error_code });
    }
    let Some(address) = base.checked_add(offset) else {
        return Err(X86SystemDescriptorFault::GeneralProtection { error_code });
    };
    let Some(last) = address.checked_add(size - 1) else {
        return Err(X86SystemDescriptorFault::GeneralProtection { error_code });
    };
    if !crate::isa::x86_64::execute::system::is_canonical_48(address)
        || !crate::isa::x86_64::execute::system::is_canonical_48(last)
    {
        return Err(X86SystemDescriptorFault::GeneralProtection { error_code });
    }
    Ok(address)
}

pub(super) fn read_smir_u64(memory: &mut dyn SmirMemory, address: u64) -> Result<u64, MemoryError> {
    let mut bytes = [0_u8; 8];
    memory.read(address, &mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

#[derive(Clone, Copy)]
struct SmirFarCallStackWrite {
    address: u64,
    width: u8,
    value: u64,
}

fn build_smir_far_call_frame(
    initial_rsp: u64,
    values: &[(u8, u64)],
) -> Result<(Vec<SmirFarCallStackWrite>, u64), ()> {
    let mut rsp = initial_rsp;
    let mut writes = Vec::with_capacity(values.len());
    for &(width, value) in values {
        rsp = rsp.wrapping_sub(u64::from(width));
        let canonical = rsp.checked_add(u64::from(width) - 1).is_some_and(|last| {
            crate::isa::x86_64::execute::system::is_canonical_48(rsp)
                && crate::isa::x86_64::execute::system::is_canonical_48(last)
        });
        if !canonical {
            return Err(());
        }
        writes.push(SmirFarCallStackWrite {
            address: rsp,
            width,
            value,
        });
    }
    Ok((writes, rsp))
}

fn smir_null_long_mode_ss(cpl: u8) -> X86SystemSegmentCache {
    X86SystemSegmentCache {
        base: 0,
        limit: 0xFFFF_FFFF,
        type_: 0x3,
        present: true,
        dpl: cpl,
        db: true,
        s: true,
        l: false,
        g: true,
        avl: false,
        unusable: false,
    }
}

use std::cmp::Ordering;
use std::collections::HashMap;

impl SmirInterpreter {
    pub(crate) fn execute_op_system(
        &self,
        ctx: &mut SmirContext,
        memory: &mut dyn SmirMemory,
        op: &SmirOp,
    ) -> Result<(), MemoryError> {
        let x86_hint = op.x86_hint;
        match &op.kind {
            // ==================================================================
            // SYSTEM / PRIVILEGED
            // ==================================================================
            OpKind::HexagonPacketBegin | OpKind::HexagonPacketCommit => {
                ctx.request_exit(ExitReason::Unsupported {
                    addr: op.guest_pc,
                    operation: "Hexagon packet boundary outside a Hexagon execution context",
                });
            }
            OpKind::EbpfInstruction { .. } => {}
            OpKind::Syscall { num, args } => {
                let num_val = ctx.read_vreg(*num);
                let arg_vals: Vec<u64> = args.iter().map(|a| ctx.read_vreg(*a)).collect();
                if ctx.source_arch == SourceArch::Ebpf {
                    ctx.pc = op.guest_pc.wrapping_add(8);
                    ctx.arch_regs.set_pc(ctx.pc);
                }
                ctx.request_exit(ExitReason::Syscall {
                    num: num_val,
                    args: arg_vals,
                });
            }

            OpKind::Swi { imm } => {
                ctx.request_exit(ExitReason::Syscall {
                    num: *imm as u64,
                    args: vec![],
                });
            }

            OpKind::ReadSysReg { dst, reg: _ } => {
                // Simplified: return 0
                ctx.write_vreg(*dst, 0);
            }

            OpKind::WriteSysReg { reg: _, src: _ } => {
                // Simplified: no-op
            }

            OpKind::X86CacheMaintenance { .. } => {
                let ArchRegState::X86_64(x86) = &ctx.arch_regs else {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                    return Ok(());
                };
                if x86.cr0 & 1 != 0 && x86.cpl != 0 {
                    ctx.request_exit(ExitReason::GeneralProtection {
                        addr: op.guest_pc,
                        error_code: 0,
                    });
                    return Ok(());
                }
                std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
            }

            OpKind::X86Clts => {
                let ArchRegState::X86_64(x86) = &mut ctx.arch_regs else {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                    return Ok(());
                };
                // Real-address mode permits CLTS regardless of stale CS.RPL.
                // X86RegState.cpl is the effective CPL, including VM86 as CPL3.
                if x86.cr0 & 1 != 0 && x86.cpl != 0 {
                    ctx.request_exit(ExitReason::GeneralProtection {
                        addr: op.guest_pc,
                        error_code: 0,
                    });
                    return Ok(());
                }
                x86.cr0 &= !(1 << 3);
            }

            OpKind::X86Msr(msr) => {
                let index = ctx.read_vreg(msr.ecx) as u32;
                let write_value = ((ctx.read_vreg(msr.edx) & u64::from(u32::MAX)) << 32)
                    | (ctx.read_vreg(msr.eax) & u64::from(u32::MAX));
                let tsc_base = ctx.cycle_count;
                let state = match &ctx.arch_regs {
                    ArchRegState::X86_64(x86) => {
                        if x86.cr0 & 1 != 0 && x86.cpl != 0 {
                            ctx.request_exit(ExitReason::GeneralProtection {
                                addr: op.guest_pc,
                                error_code: 0,
                            });
                            return Ok(());
                        }
                        X86MsrState {
                            apic_base: x86.apic.base,
                            cr0: x86.cr0,
                            tsc_adjust: x86.tsc_adjust,
                            tsc_aux: x86.tsc_aux,
                            efer: x86.efer,
                            star: x86.star,
                            lstar: x86.lstar,
                            cstar: x86.cstar,
                            fmask: x86.fmask,
                            sysenter_cs: x86.sysenter_cs,
                            sysenter_esp: x86.sysenter_esp,
                            sysenter_eip: x86.sysenter_eip,
                            misc_enable: x86.misc_enable,
                            pat: x86.pat,
                            umwait_control: x86.umwait_control,
                            fs_base: x86.fs_base,
                            gs_base: x86.gs_base,
                            kernel_gs_base: x86.kernel_gs_base,
                        }
                    }
                    _ => {
                        ctx.request_exit(ExitReason::Undefined {
                            addr: op.guest_pc,
                            opcode: 0,
                        });
                        return Ok(());
                    }
                };
                let tsc = tsc_base.wrapping_add(state.tsc_adjust);

                if msr.write {
                    let effect = match validate_x86_msr_write(index, write_value, state, tsc) {
                        Ok(effect) => effect,
                        Err(X86MsrFault::GeneralProtection) => {
                            ctx.request_exit(ExitReason::GeneralProtection {
                                addr: op.guest_pc,
                                error_code: 0,
                            });
                            return Ok(());
                        }
                    };
                    let ArchRegState::X86_64(x86) = &mut ctx.arch_regs else {
                        unreachable!("validated x86 MSR state changed")
                    };
                    x86.tsc_adjust = effect.state.tsc_adjust;
                    x86.apic.base = effect.state.apic_base;
                    x86.tsc_aux = effect.state.tsc_aux;
                    x86.efer = effect.state.efer;
                    x86.star = effect.state.star;
                    x86.lstar = effect.state.lstar;
                    x86.cstar = effect.state.cstar;
                    x86.fmask = effect.state.fmask;
                    x86.sysenter_cs = effect.state.sysenter_cs;
                    x86.sysenter_esp = effect.state.sysenter_esp;
                    x86.sysenter_eip = effect.state.sysenter_eip;
                    x86.misc_enable = effect.state.misc_enable;
                    x86.pat = effect.state.pat;
                    x86.umwait_control = effect.state.umwait_control;
                    x86.fs_base = effect.state.fs_base;
                    x86.gs_base = effect.state.gs_base;
                    x86.kernel_gs_base = effect.state.kernel_gs_base;
                } else {
                    let value = match read_x86_msr(index, state, tsc) {
                        Ok(value) => value,
                        Err(X86MsrFault::GeneralProtection) => {
                            ctx.request_exit(ExitReason::GeneralProtection {
                                addr: op.guest_pc,
                                error_code: 0,
                            });
                            return Ok(());
                        }
                    };
                    Self::write_x86_partial(
                        ctx,
                        msr.eax,
                        value & u64::from(u32::MAX),
                        OpWidth::W32,
                    );
                    Self::write_x86_partial(ctx, msr.edx, value >> 32, OpWidth::W32);
                }
            }

            OpKind::X86ReadControl { dst, control } => {
                let value = match &ctx.arch_regs {
                    ArchRegState::X86_64(x86) => {
                        // Real-address mode permits the read regardless of a
                        // stale CS.RPL. X86RegState.cpl already maps VM86 to
                        // effective CPL3.
                        if x86.cr0 & 1 != 0 && x86.cpl != 0 {
                            ctx.request_exit(ExitReason::GeneralProtection {
                                addr: op.guest_pc,
                                error_code: 0,
                            });
                            return Ok(());
                        }
                        match control {
                            X86ControlReg::Cr0 => x86.cr0,
                            X86ControlReg::Cr2 => x86.cr2,
                            X86ControlReg::Cr3 => x86.cr3,
                            X86ControlReg::Cr4 => x86.cr4,
                            X86ControlReg::Cr8 => x86.cr8,
                        }
                    }
                    _ => {
                        ctx.request_exit(ExitReason::Undefined {
                            addr: op.guest_pc,
                            opcode: 0,
                        });
                        return Ok(());
                    }
                };
                Self::write_x86_partial(ctx, *dst, value, OpWidth::W64);
            }

            OpKind::X86Smsw(smsw) => {
                let target_shape = match &smsw.target {
                    X86SmswTarget::Register { dst, width } => {
                        matches!(width, OpWidth::W16 | OpWidth::W32 | OpWidth::W64)
                            && matches!(
                                dst,
                                VReg::Arch(ArchReg::X86(reg))
                                    if reg.gpr_index().is_some_and(|index| {
                                        index < 16 || smsw.requires_apx
                                    })
                            )
                    }
                    X86SmswTarget::Memory { addr } => {
                        let uses_egpr = addr.regs().iter().any(
                            |reg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.is_egpr()),
                        );
                        addr.is_x86_state_backed_shape() && (!uses_egpr || smsw.requires_apx)
                    }
                };
                if !target_shape {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                    return Ok(());
                }

                let cr0 = match &ctx.arch_regs {
                    ArchRegState::X86_64(x86) => {
                        if smsw.requires_apx && !x86.apx_enabled {
                            ctx.request_exit(ExitReason::Undefined {
                                addr: op.guest_pc,
                                opcode: 0,
                            });
                            return Ok(());
                        }
                        // Real-address mode has effective CPL 0. In protected
                        // mode CR4.UMIP blocks SMSW above CPL 0 with #GP(0).
                        if x86.cr0 & 1 != 0 && x86.cr4 & (1 << 11) != 0 && x86.cpl != 0 {
                            ctx.request_exit(ExitReason::GeneralProtection {
                                addr: op.guest_pc,
                                error_code: 0,
                            });
                            return Ok(());
                        }
                        x86.cr0
                    }
                    _ => {
                        ctx.request_exit(ExitReason::Undefined {
                            addr: op.guest_pc,
                            opcode: 0,
                        });
                        return Ok(());
                    }
                };

                match &smsw.target {
                    X86SmswTarget::Register { dst, width } => {
                        Self::write_x86_partial(ctx, *dst, cr0, *width);
                    }
                    X86SmswTarget::Memory { addr } => {
                        let effective_addr = self.compute_address(ctx, addr);
                        self.store_memory(memory, effective_addr, cr0, MemWidth::B2)?;
                    }
                }
            }

            OpKind::X86SystemSelectorStore(store) => {
                let target_shape = match &store.target {
                    X86SystemSelectorTarget::Register { dst, width } => {
                        matches!(width, OpWidth::W16 | OpWidth::W32 | OpWidth::W64)
                            && matches!(
                                dst,
                                VReg::Arch(ArchReg::X86(reg))
                                    if reg.gpr_index().is_some_and(|index| {
                                        index < 16 || store.requires_apx
                                    })
                            )
                    }
                    X86SystemSelectorTarget::Memory { addr } => {
                        let uses_egpr = addr.regs().iter().any(
                            |reg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.is_egpr()),
                        );
                        addr.is_x86_state_backed_shape() && (!uses_egpr || store.requires_apx)
                    }
                    X86SystemSelectorTarget::Stack {
                        stack_pointer,
                        width,
                    } => {
                        matches!(stack_pointer, VReg::Arch(ArchReg::X86(X86Reg::Rsp)))
                            && matches!(width, MemWidth::B2 | MemWidth::B8)
                            && matches!(
                                store.selector,
                                X86SystemSelector::Fs | X86SystemSelector::Gs
                            )
                    }
                };
                if op.x86_hint.is_some() || !target_shape {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                    return Ok(());
                }

                let selector = match &ctx.arch_regs {
                    ArchRegState::X86_64(x86) => {
                        // REX2 availability is a decode-time fault and precedes
                        // mode, privilege, and destination validation.
                        if store.requires_apx && !x86.apx_enabled {
                            ctx.request_exit(ExitReason::Undefined {
                                addr: op.guest_pc,
                                opcode: 0,
                            });
                            return Ok(());
                        }
                        if matches!(
                            store.selector,
                            X86SystemSelector::Ldtr | X86SystemSelector::Tr
                        ) {
                            // SLDT/STR are recognized only in protected mode,
                            // are invalid in virtual-8086 mode, and are subject
                            // to UMIP. MOV r/m,Sreg has none of these guards.
                            if x86.cr0 & 1 == 0
                                || x86.rflags & crate::isa::x86_64::flags::bits::VM != 0
                            {
                                ctx.request_exit(ExitReason::Undefined {
                                    addr: op.guest_pc,
                                    opcode: 0,
                                });
                                return Ok(());
                            }
                            if x86.cr4 & (1 << 11) != 0 && x86.cpl != 0 {
                                ctx.request_exit(ExitReason::GeneralProtection {
                                    addr: op.guest_pc,
                                    error_code: 0,
                                });
                                return Ok(());
                            }
                        }
                        match store.selector {
                            X86SystemSelector::Ldtr => x86.ldtr_selector,
                            X86SystemSelector::Tr => x86.tr_selector,
                            X86SystemSelector::Es => x86.es_selector,
                            X86SystemSelector::Cs => x86.cs_selector,
                            X86SystemSelector::Ss => x86.ss_selector,
                            X86SystemSelector::Ds => x86.ds_selector,
                            X86SystemSelector::Fs => x86.fs_selector,
                            X86SystemSelector::Gs => x86.gs_selector,
                        }
                    }
                    _ => {
                        ctx.request_exit(ExitReason::Undefined {
                            addr: op.guest_pc,
                            opcode: 0,
                        });
                        return Ok(());
                    }
                };

                match &store.target {
                    X86SystemSelectorTarget::Register { dst, width } => {
                        Self::write_x86_partial(ctx, *dst, u64::from(selector), *width);
                    }
                    X86SystemSelectorTarget::Memory { addr } => {
                        let effective_addr = self.compute_address(ctx, addr);
                        self.store_memory(
                            memory,
                            effective_addr,
                            u64::from(selector),
                            MemWidth::B2,
                        )?;
                    }
                    X86SystemSelectorTarget::Stack { width, .. } => {
                        let initial_rsp = match &ctx.arch_regs {
                            ArchRegState::X86_64(x86) if x86.efer & (1 << 10) != 0 && x86.cs_l => {
                                x86.gpr[4]
                            }
                            _ => {
                                ctx.request_exit(ExitReason::Undefined {
                                    addr: op.guest_pc,
                                    opcode: 0,
                                });
                                return Ok(());
                            }
                        };
                        let width_bytes = width.bytes() as u64;
                        let new_rsp = initial_rsp.wrapping_sub(width_bytes);
                        let canonical = new_rsp.checked_add(width_bytes - 1).is_some_and(|last| {
                            crate::isa::x86_64::execute::system::is_canonical_48(new_rsp)
                                && crate::isa::x86_64::execute::system::is_canonical_48(last)
                        });
                        if !canonical {
                            ctx.request_exit(ExitReason::StackSegment {
                                addr: op.guest_pc,
                                error_code: 0,
                            });
                            return Ok(());
                        }

                        // Commit RSP only after the complete stack write. This
                        // is required for fault-class restart at the original
                        // instruction frontier.
                        self.store_memory(memory, new_rsp, u64::from(selector), *width)?;
                        let ArchRegState::X86_64(x86) = &mut ctx.arch_regs else {
                            unreachable!("validated x86 PUSH-segment state changed")
                        };
                        x86.gpr[4] = new_rsp;
                    }
                }
            }

            OpKind::X86SystemSelectorLoad(load) => {
                self.execute_x86_system_selector_load(ctx, memory, op, load)?;
            }

            OpKind::X86SelectorVerify(verify) => {
                self.execute_x86_selector_verify(ctx, memory, op, verify)?;
            }

            OpKind::X86SelectorQuery(query) => {
                self.execute_x86_selector_query(ctx, memory, op, query)?;
            }

            OpKind::X86FarJump(jump) => {
                let X86FarJumpOp {
                    addr,
                    target,
                    offset_width,
                    requires_apx,
                    stack_segment,
                    next_pc,
                } = jump;
                let uses_egpr = addr
                    .regs()
                    .iter()
                    .any(|reg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.is_egpr()));
                let valid_shape = op.x86_hint.is_none()
                    && matches!(next_pc.checked_sub(op.guest_pc), Some(2..=15))
                    && matches!(offset_width, OpWidth::W16 | OpWidth::W32 | OpWidth::W64)
                    && *target == VReg::Arch(ArchReg::X86(X86Reg::Rip))
                    && addr.is_x86_state_backed_shape()
                    && (!uses_egpr || *requires_apx);
                if !valid_shape {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                    return Ok(());
                }

                let (cpl, gdtr_base, gdtr_limit, ldtr_selector, ldtr_cache) = match &ctx.arch_regs {
                    ArchRegState::X86_64(x86)
                        if x86.cr0 & 1 != 0
                            && x86.rflags & crate::isa::x86_64::flags::bits::VM == 0
                            && x86.efer & (1 << 10) != 0
                            && x86.cs_l
                            && (!*requires_apx || x86.apx_enabled) =>
                    {
                        (
                            x86.cpl,
                            x86.gdtr_base,
                            x86.gdtr_limit,
                            x86.ldtr_selector,
                            x86.ldtr_cache.clone(),
                        )
                    }
                    _ => {
                        ctx.request_exit(ExitReason::Undefined {
                            addr: op.guest_pc,
                            opcode: 0,
                        });
                        return Ok(());
                    }
                };

                let pointer_address = self.compute_address(ctx, addr);
                let pointer_size = offset_width.bits() as u64 / 8 + 2;
                let canonical_range =
                    pointer_address
                        .checked_add(pointer_size - 1)
                        .is_some_and(|last| {
                            crate::isa::x86_64::execute::system::is_canonical_48(pointer_address)
                                && crate::isa::x86_64::execute::system::is_canonical_48(last)
                        });
                if !canonical_range {
                    ctx.request_exit(if *stack_segment {
                        ExitReason::StackSegment {
                            addr: op.guest_pc,
                            error_code: 0,
                        }
                    } else {
                        ExitReason::GeneralProtection {
                            addr: op.guest_pc,
                            error_code: 0,
                        }
                    });
                    return Ok(());
                }

                let mem_width = offset_width.to_mem_width();
                let pointer_offset =
                    self.load_memory(memory, pointer_address, mem_width, SignExtend::Zero)?;
                let selector = self.load_memory(
                    memory,
                    pointer_address.wrapping_add(u64::from(mem_width.bytes())),
                    MemWidth::B2,
                    SignExtend::Zero,
                )? as u16;

                // Reconstruct only the implicit descriptor state needed by the
                // table locator, keeping mutable memory access independent of
                // the live architectural-context borrow.
                let mut descriptor_state = crate::smir::ir::context::X86RegState::new();
                descriptor_state.gdtr_base = gdtr_base;
                descriptor_state.gdtr_limit = gdtr_limit;
                descriptor_state.ldtr_selector = ldtr_selector;
                descriptor_state.ldtr_cache = ldtr_cache;
                let descriptor_address =
                    match x86_far_jump_descriptor_address(&descriptor_state, selector, 8) {
                        Ok(address) => address,
                        Err(fault) => {
                            request_x86_descriptor_fault(ctx, op.guest_pc, fault);
                            return Ok(());
                        }
                    };
                let mut selected_address = descriptor_address;
                let mut selected_low = read_smir_u64(memory, descriptor_address)?;
                let selected_high = if x86_far_jump_is_ia32e_call_gate(selected_low, true) {
                    selected_address =
                        match x86_far_jump_descriptor_address(&descriptor_state, selector, 16) {
                            Ok(address) => address,
                            Err(fault) => {
                                request_x86_descriptor_fault(ctx, op.guest_pc, fault);
                                return Ok(());
                            }
                        };
                    Some(read_smir_u64(memory, selected_address.wrapping_add(8))?)
                } else {
                    None
                };
                let descriptor = match decode_x86_far_jump_descriptor(
                    selector,
                    selected_low,
                    selected_high,
                    pointer_offset,
                    *offset_width,
                    cpl,
                    true,
                ) {
                    Ok(descriptor) => descriptor,
                    Err(fault) => {
                        request_x86_descriptor_fault(ctx, op.guest_pc, fault);
                        return Ok(());
                    }
                };
                let target_state = match descriptor {
                    X86FarJumpDescriptor::Code(target) => target,
                    X86FarJumpDescriptor::CallGate(gate) => {
                        selected_address = match x86_far_jump_descriptor_address(
                            &descriptor_state,
                            gate.selector,
                            8,
                        ) {
                            Ok(address) => address,
                            Err(fault) => {
                                request_x86_descriptor_fault(ctx, op.guest_pc, fault);
                                return Ok(());
                            }
                        };
                        selected_low = read_smir_u64(memory, selected_address)?;
                        match decode_x86_far_jump_call_gate_target(
                            gate.selector,
                            selected_low,
                            gate.offset,
                            cpl,
                        ) {
                            Ok(target) => target,
                            Err(fault) => {
                                request_x86_descriptor_fault(ctx, op.guest_pc, fault);
                                return Ok(());
                            }
                        }
                    }
                };

                // The implicit accessed-bit write is the final faulting action.
                // Only then does the operation expose the new CS:RIP pair.
                if selected_low != target_state.accessed_low {
                    memory.write(selected_address, &target_state.accessed_low.to_le_bytes())?;
                }
                let target_offset = target_state.offset;
                let cache = x86_system_segment_cache(&target_state.segment);
                let ArchRegState::X86_64(x86) = &mut ctx.arch_regs else {
                    unreachable!("validated x86 far-JMP context changed")
                };
                x86.cs_selector = target_state.segment.selector;
                x86.cs_l = target_state.segment.l;
                x86.cs_cache = cache;
                ctx.write_vreg(*target, target_offset);
            }

            OpKind::X86FarCall(call) => {
                let X86FarCallOp {
                    addr,
                    target,
                    offset_width,
                    requires_apx,
                    stack_segment,
                    next_pc,
                } = call;
                let uses_egpr = addr
                    .regs()
                    .iter()
                    .any(|reg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.is_egpr()));
                let valid_shape = op.x86_hint.is_none()
                    && matches!(next_pc.checked_sub(op.guest_pc), Some(2..=15))
                    && matches!(offset_width, OpWidth::W16 | OpWidth::W32 | OpWidth::W64)
                    && *target == VReg::Arch(ArchReg::X86(X86Reg::Rip))
                    && addr.is_x86_state_backed_shape()
                    && (!uses_egpr || *requires_apx);
                if !valid_shape {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                    return Ok(());
                }

                let (
                    cpl,
                    gdtr_base,
                    gdtr_limit,
                    ldtr_selector,
                    ldtr_cache,
                    tr_selector,
                    tr_cache,
                    old_cs,
                    old_ss,
                    old_rsp,
                ) = match &ctx.arch_regs {
                    ArchRegState::X86_64(x86)
                        if x86.cr0 & 1 != 0
                            && x86.rflags & crate::isa::x86_64::flags::bits::VM == 0
                            && x86.efer & (1 << 10) != 0
                            && x86.cs_l
                            && (!*requires_apx || x86.apx_enabled) =>
                    {
                        (
                            x86.cpl,
                            x86.gdtr_base,
                            x86.gdtr_limit,
                            x86.ldtr_selector,
                            x86.ldtr_cache.clone(),
                            x86.tr_selector,
                            x86.tr_cache.clone(),
                            x86.cs_selector,
                            x86.ss_selector,
                            x86.gpr[4],
                        )
                    }
                    _ => {
                        ctx.request_exit(ExitReason::Undefined {
                            addr: op.guest_pc,
                            opcode: 0,
                        });
                        return Ok(());
                    }
                };

                let pointer_address = self.compute_address(ctx, addr);
                let pointer_size = offset_width.bits() as u64 / 8 + 2;
                let canonical_pointer =
                    pointer_address
                        .checked_add(pointer_size - 1)
                        .is_some_and(|last| {
                            crate::isa::x86_64::execute::system::is_canonical_48(pointer_address)
                                && crate::isa::x86_64::execute::system::is_canonical_48(last)
                        });
                if !canonical_pointer {
                    ctx.request_exit(if *stack_segment {
                        ExitReason::StackSegment {
                            addr: op.guest_pc,
                            error_code: 0,
                        }
                    } else {
                        ExitReason::GeneralProtection {
                            addr: op.guest_pc,
                            error_code: 0,
                        }
                    });
                    return Ok(());
                }

                let mem_width = offset_width.to_mem_width();
                let pointer_offset =
                    self.load_memory(memory, pointer_address, mem_width, SignExtend::Zero)?;
                let selector = self.load_memory(
                    memory,
                    pointer_address.wrapping_add(u64::from(mem_width.bytes())),
                    MemWidth::B2,
                    SignExtend::Zero,
                )? as u16;

                let mut descriptor_state = crate::smir::ir::context::X86RegState::new();
                descriptor_state.gdtr_base = gdtr_base;
                descriptor_state.gdtr_limit = gdtr_limit;
                descriptor_state.ldtr_selector = ldtr_selector;
                descriptor_state.ldtr_cache = ldtr_cache;
                let mut selected_address =
                    match x86_far_jump_descriptor_address(&descriptor_state, selector, 8) {
                        Ok(address) => address,
                        Err(fault) => {
                            request_x86_descriptor_fault(ctx, op.guest_pc, fault);
                            return Ok(());
                        }
                    };
                let mut selected_low = read_smir_u64(memory, selected_address)?;
                let selected_high = if x86_far_jump_is_ia32e_call_gate(selected_low, true) {
                    selected_address =
                        match x86_far_jump_descriptor_address(&descriptor_state, selector, 16) {
                            Ok(address) => address,
                            Err(fault) => {
                                request_x86_descriptor_fault(ctx, op.guest_pc, fault);
                                return Ok(());
                            }
                        };
                    Some(read_smir_u64(memory, selected_address.wrapping_add(8))?)
                } else {
                    None
                };
                let descriptor = match decode_x86_far_call_descriptor(
                    selector,
                    selected_low,
                    selected_high,
                    pointer_offset,
                    *offset_width,
                    cpl,
                    true,
                ) {
                    Ok(descriptor) => descriptor,
                    Err(fault) => {
                        request_x86_descriptor_fault(ctx, op.guest_pc, fault);
                        return Ok(());
                    }
                };

                let (target_state, stack_writes, final_rsp, new_ss) = match descriptor {
                    X86FarJumpDescriptor::Code(target_state) => {
                        let width = mem_width.bytes() as u8;
                        let Ok((writes, final_rsp)) = build_smir_far_call_frame(
                            old_rsp,
                            &[(width, u64::from(old_cs)), (width, *next_pc)],
                        ) else {
                            ctx.request_exit(ExitReason::StackSegment {
                                addr: op.guest_pc,
                                error_code: 0,
                            });
                            return Ok(());
                        };
                        (target_state, writes, final_rsp, None)
                    }
                    X86FarJumpDescriptor::CallGate(gate) => {
                        selected_address = match x86_far_jump_descriptor_address(
                            &descriptor_state,
                            gate.selector,
                            8,
                        ) {
                            Ok(address) => address,
                            Err(fault) => {
                                request_x86_descriptor_fault(ctx, op.guest_pc, fault);
                                return Ok(());
                            }
                        };
                        selected_low = read_smir_u64(memory, selected_address)?;
                        let target_state = match decode_x86_far_call_gate_target(
                            gate.selector,
                            selected_low,
                            gate.offset,
                            cpl,
                        ) {
                            Ok(target) => target,
                            Err(fault) => {
                                request_x86_descriptor_fault(ctx, op.guest_pc, fault);
                                return Ok(());
                            }
                        };
                        let target_cpl = (target_state.segment.selector & 3) as u8;
                        if target_cpl < cpl {
                            let tr_error = u32::from(tr_selector & 0xFFFC);
                            if tr_selector & 0xFFFC == 0
                                || tr_cache.unusable
                                || !tr_cache.present
                                || tr_cache.s
                                || !matches!(tr_cache.type_ & 0xF, 0x9 | 0xB)
                            {
                                ctx.request_exit(ExitReason::InvalidTss {
                                    addr: op.guest_pc,
                                    error_code: tr_error,
                                });
                                return Ok(());
                            }
                            let tss_offset = 4_u64 + u64::from(target_cpl) * 8;
                            let tss_address = tr_cache.base.checked_add(tss_offset);
                            let tss_valid = tss_offset + 7 <= u64::from(tr_cache.limit)
                                && tss_address.is_some_and(|address| {
                                    address.checked_add(7).is_some_and(|last| {
                                        crate::isa::x86_64::execute::system::is_canonical_48(
                                            address,
                                        ) && crate::isa::x86_64::execute::system::is_canonical_48(
                                            last,
                                        )
                                    })
                                });
                            if !tss_valid {
                                ctx.request_exit(ExitReason::InvalidTss {
                                    addr: op.guest_pc,
                                    error_code: tr_error,
                                });
                                return Ok(());
                            }
                            let new_rsp = read_smir_u64(memory, tss_address.unwrap())?;
                            let Ok((writes, final_rsp)) = build_smir_far_call_frame(
                                new_rsp,
                                &[
                                    (8, u64::from(old_ss)),
                                    (8, old_rsp),
                                    (8, u64::from(old_cs)),
                                    (8, *next_pc),
                                ],
                            ) else {
                                ctx.request_exit(ExitReason::StackSegment {
                                    addr: op.guest_pc,
                                    error_code: 0,
                                });
                                return Ok(());
                            };
                            (
                                target_state,
                                writes,
                                final_rsp,
                                Some((u16::from(target_cpl), smir_null_long_mode_ss(target_cpl))),
                            )
                        } else {
                            let Ok((writes, final_rsp)) = build_smir_far_call_frame(
                                old_rsp,
                                &[(8, u64::from(old_cs)), (8, *next_pc)],
                            ) else {
                                ctx.request_exit(ExitReason::StackSegment {
                                    addr: op.guest_pc,
                                    error_code: 0,
                                });
                                return Ok(());
                            };
                            (target_state, writes, final_rsp, None)
                        }
                    }
                };
                if let Err(fault) = validate_x86_far_call_target_offset(&target_state) {
                    request_x86_descriptor_fault(ctx, op.guest_pc, fault);
                    return Ok(());
                }

                // Probe every write before the first store. This preserves the
                // operation's all-state-or-fault contract across page edges.
                if selected_low != target_state.accessed_low {
                    memory.probe(selected_address, 8, true)?;
                }
                for write in &stack_writes {
                    memory.probe(write.address, usize::from(write.width), true)?;
                }
                if selected_low != target_state.accessed_low {
                    memory.write(selected_address, &target_state.accessed_low.to_le_bytes())?;
                }
                for write in &stack_writes {
                    let bytes = write.value.to_le_bytes();
                    memory.write(write.address, &bytes[..usize::from(write.width)])?;
                }

                let target_offset = target_state.offset;
                let target_selector = target_state.segment.selector;
                let target_l = target_state.segment.l;
                let target_cache = x86_system_segment_cache(&target_state.segment);
                let ArchRegState::X86_64(x86) = &mut ctx.arch_regs else {
                    unreachable!("validated x86 far-CALL context changed")
                };
                if let Some((selector, cache)) = new_ss {
                    x86.ss_selector = selector;
                    x86.ss_cache = cache;
                }
                x86.gpr[4] = final_rsp;
                x86.cs_selector = target_selector;
                x86.cs_l = target_l;
                x86.cs_cache = target_cache;
                x86.cpl = (target_selector & 3) as u8;
                x86.rip = target_offset;
            }

            OpKind::X86FarReturn(..) => {
                return self.execute_op_far_return(ctx, memory, op);
            }

            OpKind::X86FastSystemTransfer(transfer) => {
                let valid_shape = op.x86_hint.is_none()
                    && matches!(transfer.next_pc.checked_sub(op.guest_pc), Some(2..=15))
                    && transfer.target == VReg::Arch(ArchReg::X86(X86Reg::Rip))
                    && transfer.stack_pointer == VReg::Arch(ArchReg::X86(X86Reg::Rsp))
                    && transfer.return_target == VReg::Arch(ArchReg::X86(X86Reg::Rdx))
                    && transfer.return_stack_pointer == VReg::Arch(ArchReg::X86(X86Reg::Rcx))
                    && (transfer.kind == X86FastSystemTransferKind::Sysexit || !transfer.operand64);
                if !valid_shape {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                    return Ok(());
                }
                let state = match &ctx.arch_regs {
                    ArchRegState::X86_64(x86) => X86FastSystemTransferState {
                        cr0: x86.cr0,
                        efer: x86.efer,
                        cpl: x86.cpl,
                        rflags: x86.rflags,
                        sysenter_cs: x86.sysenter_cs,
                        sysenter_esp: x86.sysenter_esp,
                        sysenter_eip: x86.sysenter_eip,
                        rcx: x86.gpr[1],
                        rdx: x86.gpr[2],
                    },
                    _ => {
                        ctx.request_exit(ExitReason::Undefined {
                            addr: op.guest_pc,
                            opcode: 0,
                        });
                        return Ok(());
                    }
                };
                let effect = match transfer.kind {
                    X86FastSystemTransferKind::Sysenter => evaluate_x86_sysenter(state),
                    X86FastSystemTransferKind::Sysexit => {
                        evaluate_x86_sysexit(state, transfer.operand64)
                    }
                };
                let effect = match effect {
                    Ok(effect) => effect,
                    Err(X86FastSystemTransferFault::GeneralProtection) => {
                        ctx.request_exit(ExitReason::GeneralProtection {
                            addr: op.guest_pc,
                            error_code: 0,
                        });
                        return Ok(());
                    }
                };

                let code_cache = X86SystemSegmentCache {
                    base: 0,
                    limit: 0x000F_FFFF,
                    type_: 0x0B,
                    present: true,
                    dpl: effect.cpl,
                    db: effect.cs_default_big,
                    s: true,
                    l: effect.cs_long,
                    g: true,
                    avl: false,
                    unusable: false,
                };
                let stack_cache = X86SystemSegmentCache {
                    base: 0,
                    limit: 0x000F_FFFF,
                    type_: 0x03,
                    present: true,
                    dpl: effect.cpl,
                    db: true,
                    s: true,
                    l: false,
                    g: true,
                    avl: false,
                    unusable: false,
                };
                let ArchRegState::X86_64(x86) = &mut ctx.arch_regs else {
                    unreachable!("validated x86 fast-system-transfer context changed")
                };
                x86.rflags = effect.rflags;
                x86.cpl = effect.cpl;
                x86.cs_selector = effect.cs_selector;
                x86.cs_cache = code_cache;
                x86.cs_l = effect.cs_long;
                x86.ss_selector = effect.ss_selector;
                x86.ss_cache = stack_cache;
                ctx.write_vreg(transfer.stack_pointer, effect.rsp);
                ctx.write_vreg(transfer.target, effect.rip);
            }

            OpKind::X86Lmsw(lmsw) => {
                let instruction_len = lmsw.next_pc.checked_sub(op.guest_pc);
                let source_shape = match &lmsw.source {
                    X86LmswSource::Register { src } => matches!(
                        src,
                        VReg::Arch(ArchReg::X86(reg))
                            if reg.gpr_index().is_some_and(|index| {
                                index < 16 || lmsw.requires_apx
                            })
                    ),
                    X86LmswSource::Memory { addr } => {
                        let uses_egpr = addr.regs().iter().any(
                            |reg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.is_egpr()),
                        );
                        addr.is_x86_state_backed_shape() && (!uses_egpr || lmsw.requires_apx)
                    }
                };
                if !matches!(instruction_len, Some(3..=15))
                    || op.x86_hint.is_some()
                    || !source_shape
                {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                    return Ok(());
                }

                let old_cr0 = match &ctx.arch_regs {
                    ArchRegState::X86_64(x86) => {
                        if lmsw.requires_apx && !x86.apx_enabled {
                            ctx.request_exit(ExitReason::Undefined {
                                addr: op.guest_pc,
                                opcode: 0,
                            });
                            return Ok(());
                        }
                        if x86.cr0 & 1 != 0 && x86.cpl != 0 {
                            ctx.request_exit(ExitReason::GeneralProtection {
                                addr: op.guest_pc,
                                error_code: 0,
                            });
                            return Ok(());
                        }
                        x86.cr0
                    }
                    _ => {
                        ctx.request_exit(ExitReason::Undefined {
                            addr: op.guest_pc,
                            opcode: 0,
                        });
                        return Ok(());
                    }
                };

                let source = match &lmsw.source {
                    X86LmswSource::Register { src } => ctx.read_vreg(*src),
                    X86LmswSource::Memory { addr } => {
                        let effective_addr = self.compute_address(ctx, addr);
                        self.load_memory(memory, effective_addr, MemWidth::B2, SignExtend::Zero)?
                    }
                };
                let new_cr0 = (old_cr0 & !0xF) | (source & 0xF) | (old_cr0 & 1);
                let ArchRegState::X86_64(x86) = &mut ctx.arch_regs else {
                    unreachable!("validated x86 LMSW state changed")
                };
                x86.cr0 = new_cr0;
            }

            OpKind::X86DescriptorTableStore(store) => {
                let uses_egpr = store
                    .addr
                    .regs()
                    .iter()
                    .any(|reg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.is_egpr()));
                if op.x86_hint.is_some()
                    || !store.addr.is_x86_state_backed_shape()
                    || (uses_egpr && !store.requires_apx)
                {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                    return Ok(());
                }

                let (limit, base) = match &ctx.arch_regs {
                    ArchRegState::X86_64(x86) => {
                        if store.requires_apx && !x86.apx_enabled {
                            ctx.request_exit(ExitReason::Undefined {
                                addr: op.guest_pc,
                                opcode: 0,
                            });
                            return Ok(());
                        }
                        if x86.cr4 & (1 << 11) != 0 && x86.cpl != 0 {
                            ctx.request_exit(ExitReason::GeneralProtection {
                                addr: op.guest_pc,
                                error_code: 0,
                            });
                            return Ok(());
                        }
                        match store.table {
                            X86DescriptorTable::Gdt => (x86.gdtr_limit, x86.gdtr_base),
                            X86DescriptorTable::Idt => (x86.idtr_limit, x86.idtr_base),
                        }
                    }
                    _ => {
                        ctx.request_exit(ExitReason::Undefined {
                            addr: op.guest_pc,
                            opcode: 0,
                        });
                        return Ok(());
                    }
                };

                let effective_addr = self.compute_address(ctx, &store.addr);
                let mut payload = [0u8; 10];
                payload[..2].copy_from_slice(&limit.to_le_bytes());
                payload[2..].copy_from_slice(&base.to_le_bytes());
                memory.write(effective_addr, &payload)?;
            }

            OpKind::X86DescriptorTableLoad(load) => {
                let instruction_len = load.next_pc.checked_sub(op.guest_pc);
                let uses_egpr = load
                    .addr
                    .regs()
                    .iter()
                    .any(|reg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.is_egpr()));
                if !matches!(instruction_len, Some(3..=15))
                    || op.x86_hint.is_some()
                    || !load.addr.is_x86_state_backed_shape()
                    || (uses_egpr && !load.requires_apx)
                {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                    return Ok(());
                }

                match &ctx.arch_regs {
                    ArchRegState::X86_64(x86) => {
                        // REX2/APX validity is a decode-time fault and therefore
                        // precedes privilege and memory validation.
                        if load.requires_apx && !x86.apx_enabled {
                            ctx.request_exit(ExitReason::Undefined {
                                addr: op.guest_pc,
                                opcode: 0,
                            });
                            return Ok(());
                        }
                        if x86.cpl != 0 {
                            ctx.request_exit(ExitReason::GeneralProtection {
                                addr: op.guest_pc,
                                error_code: 0,
                            });
                            return Ok(());
                        }
                    }
                    _ => {
                        ctx.request_exit(ExitReason::Undefined {
                            addr: op.guest_pc,
                            opcode: 0,
                        });
                        return Ok(());
                    }
                }

                // Read the complete long-mode pseudo-descriptor before
                // committing either implicit field. The deterministic guest
                // profile identifies as GenuineIntel, whose 64-bit-mode LGDT/
                // LIDT definition retains all 64 source base bits.
                let effective_addr = self.compute_address(ctx, &load.addr);
                let mut payload = [0u8; 10];
                memory.read(effective_addr, &mut payload)?;
                let limit = u16::from_le_bytes(payload[..2].try_into().unwrap());
                let base = u64::from_le_bytes(payload[2..].try_into().unwrap());
                let ArchRegState::X86_64(x86) = &mut ctx.arch_regs else {
                    unreachable!("validated x86 descriptor-table state changed")
                };
                match load.table {
                    X86DescriptorTable::Gdt => {
                        x86.gdtr_limit = limit;
                        x86.gdtr_base = base;
                    }
                    X86DescriptorTable::Idt => {
                        x86.idtr_limit = limit;
                        x86.idtr_base = base;
                    }
                }
            }

            OpKind::X86Invlpg(invlpg) => {
                let instruction_len = invlpg.next_pc.checked_sub(op.guest_pc);
                let uses_egpr = invlpg
                    .addr
                    .regs()
                    .iter()
                    .any(|reg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.is_egpr()));
                let minimum_len = if invlpg.requires_apx { 4 } else { 3 };
                if !instruction_len.is_some_and(|len| (minimum_len..=15).contains(&len))
                    || op.x86_hint.is_some()
                    || !invlpg.addr.is_x86_state_backed_shape()
                    || (uses_egpr && !invlpg.requires_apx)
                {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                    return Ok(());
                }

                match &ctx.arch_regs {
                    ArchRegState::X86_64(x86) => {
                        if invlpg.requires_apx && !x86.apx_enabled {
                            ctx.request_exit(ExitReason::Undefined {
                                addr: op.guest_pc,
                                opcode: 0,
                            });
                            return Ok(());
                        }
                        // The strict x86-64 operation denotes 64-bit mode,
                        // where INVLPG requires effective CPL0.
                        if x86.cpl != 0 {
                            ctx.request_exit(ExitReason::GeneralProtection {
                                addr: op.guest_pc,
                                error_code: 0,
                            });
                            return Ok(());
                        }
                    }
                    _ => {
                        ctx.request_exit(ExitReason::Undefined {
                            addr: op.guest_pc,
                            opcode: 0,
                        });
                        return Ok(());
                    }
                }

                let effective_addr = self.compute_address(ctx, &invlpg.addr);
                if crate::isa::x86_64::execute::system::is_canonical_48(effective_addr) {
                    memory.invalidate_translation(effective_addr);
                }
            }

            OpKind::X86Invpcid(invpcid) => {
                self.execute_x86_invpcid(ctx, memory, op, invpcid)?;
            }

            OpKind::X86WriteControl {
                src,
                control,
                next_pc: _,
            } => {
                let value = ctx.read_vreg(*src);
                let ArchRegState::X86_64(x86) = &mut ctx.arch_regs else {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                    return Ok(());
                };

                // Real-address mode permits the write. Effective CPL already
                // maps virtual-8086 execution to CPL3. All validation precedes
                // every architectural state update.
                if x86.cr0 & 1 != 0 && x86.cpl != 0 {
                    ctx.request_exit(ExitReason::GeneralProtection {
                        addr: op.guest_pc,
                        error_code: 0,
                    });
                    return Ok(());
                }
                let selector = match control {
                    X86ControlReg::Cr0 => 0,
                    X86ControlReg::Cr2 => 2,
                    X86ControlReg::Cr3 => 3,
                    X86ControlReg::Cr4 => 4,
                    X86ControlReg::Cr8 => 8,
                };
                let effect = match validate_x86_control_write(
                    selector,
                    value,
                    X86ControlWriteState {
                        cr0: x86.cr0,
                        cr3: x86.cr3,
                        cr4: x86.cr4,
                        efer: x86.efer,
                        cs_l: x86.cs_l,
                        tr_type: x86.tr_type,
                    },
                ) {
                    Ok(effect) => effect,
                    Err(X86ControlWriteFault::GeneralProtection) => {
                        ctx.request_exit(ExitReason::GeneralProtection {
                            addr: op.guest_pc,
                            error_code: 0,
                        });
                        return Ok(());
                    }
                };

                match control {
                    X86ControlReg::Cr0 => x86.cr0 = effect.value,
                    X86ControlReg::Cr2 => x86.cr2 = effect.value,
                    X86ControlReg::Cr3 => x86.cr3 = effect.value,
                    X86ControlReg::Cr4 => x86.cr4 = effect.value,
                    X86ControlReg::Cr8 => x86.cr8 = effect.value,
                }
                x86.efer = effect.efer;
            }

            OpKind::X86ReadDebug { dst, debug } => {
                const CR4_DE: u64 = 1 << 3;
                const DR6_BD: u64 = 1 << 13;
                const DR7_GD: u64 = 1 << 13;

                let value = match &mut ctx.arch_regs {
                    ArchRegState::X86_64(x86) => {
                        // General detect is a fault before the MOV executes.
                        // Set BD before reporting it; GD is cleared only when
                        // the architectural #DB handler is actually entered.
                        if x86.dr7 & DR7_GD != 0 {
                            x86.dr6 |= DR6_BD;
                            ctx.request_exit(ExitReason::Debug { addr: op.guest_pc });
                            return Ok(());
                        }
                        if matches!(debug, X86DebugReg::Dr4 | X86DebugReg::Dr5)
                            && x86.cr4 & CR4_DE != 0
                        {
                            ctx.request_exit(ExitReason::Undefined {
                                addr: op.guest_pc,
                                opcode: 0,
                            });
                            return Ok(());
                        }
                        // Real-address mode permits the read. Effective CPL
                        // already maps virtual-8086 execution to CPL3.
                        if x86.cr0 & 1 != 0 && x86.cpl != 0 {
                            ctx.request_exit(ExitReason::GeneralProtection {
                                addr: op.guest_pc,
                                error_code: 0,
                            });
                            return Ok(());
                        }
                        match debug {
                            X86DebugReg::Dr0 => x86.dr0,
                            X86DebugReg::Dr1 => x86.dr1,
                            X86DebugReg::Dr2 => x86.dr2,
                            X86DebugReg::Dr3 => x86.dr3,
                            X86DebugReg::Dr4 | X86DebugReg::Dr6 => x86.dr6,
                            X86DebugReg::Dr5 | X86DebugReg::Dr7 => x86.dr7,
                        }
                    }
                    _ => {
                        ctx.request_exit(ExitReason::Undefined {
                            addr: op.guest_pc,
                            opcode: 0,
                        });
                        return Ok(());
                    }
                };
                Self::write_x86_partial(ctx, *dst, value, OpWidth::W64);
            }

            OpKind::X86WriteDebug { src, debug } => {
                const CR4_DE: u64 = 1 << 3;
                const DR6_BD: u64 = 1 << 13;
                const DR7_GD: u64 = 1 << 13;

                let value = ctx.read_vreg(*src);
                match &mut ctx.arch_regs {
                    ArchRegState::X86_64(x86) => {
                        // Match direct execution priority. The write is wholly
                        // non-committing on every fault path.
                        if x86.dr7 & DR7_GD != 0 {
                            x86.dr6 |= DR6_BD;
                            ctx.request_exit(ExitReason::Debug { addr: op.guest_pc });
                            return Ok(());
                        }
                        if matches!(debug, X86DebugReg::Dr4 | X86DebugReg::Dr5)
                            && x86.cr4 & CR4_DE != 0
                        {
                            ctx.request_exit(ExitReason::Undefined {
                                addr: op.guest_pc,
                                opcode: 0,
                            });
                            return Ok(());
                        }
                        if x86.cr0 & 1 != 0 && x86.cpl != 0 {
                            ctx.request_exit(ExitReason::GeneralProtection {
                                addr: op.guest_pc,
                                error_code: 0,
                            });
                            return Ok(());
                        }
                        if matches!(
                            debug,
                            X86DebugReg::Dr4
                                | X86DebugReg::Dr5
                                | X86DebugReg::Dr6
                                | X86DebugReg::Dr7
                        ) && value >> 32 != 0
                        {
                            ctx.request_exit(ExitReason::GeneralProtection {
                                addr: op.guest_pc,
                                error_code: 0,
                            });
                            return Ok(());
                        }
                        match debug {
                            X86DebugReg::Dr0 => x86.dr0 = value,
                            X86DebugReg::Dr1 => x86.dr1 = value,
                            X86DebugReg::Dr2 => x86.dr2 = value,
                            X86DebugReg::Dr3 => x86.dr3 = value,
                            X86DebugReg::Dr4 | X86DebugReg::Dr6 => x86.dr6 = value,
                            X86DebugReg::Dr5 | X86DebugReg::Dr7 => x86.dr7 = value,
                        }
                    }
                    _ => {
                        ctx.request_exit(ExitReason::Undefined {
                            addr: op.guest_pc,
                            opcode: 0,
                        });
                        return Ok(());
                    }
                }
            }

            OpKind::X86ReadTsc(read) => {
                let (cr0, cr4, cpl, tsc_aux) = match &ctx.arch_regs {
                    ArchRegState::X86_64(x86) => (x86.cr0, x86.cr4, x86.cpl, x86.tsc_aux),
                    _ => {
                        ctx.request_exit(ExitReason::Undefined {
                            addr: op.guest_pc,
                            opcode: 0,
                        });
                        return Ok(());
                    }
                };
                if cr0 & 1 != 0 && cr4 & (1 << 2) != 0 && cpl != 0 {
                    ctx.request_exit(ExitReason::GeneralProtection {
                        addr: op.guest_pc,
                        error_code: 0,
                    });
                    return Ok(());
                }
                let tsc = ctx.cycle_count;
                Self::write_x86_partial(ctx, read.dst_lo, tsc & u32::MAX as u64, OpWidth::W32);
                Self::write_x86_partial(ctx, read.dst_hi, tsc >> 32, OpWidth::W32);
                if let Some(dst_aux) = read.dst_aux {
                    Self::write_x86_partial(ctx, dst_aux, u64::from(tsc_aux), OpWidth::W32);
                }
            }

            OpKind::X86ReadPmc(read) => {
                let selector = ctx.read_vreg(read.selector) as u32;
                let state = match &ctx.arch_regs {
                    ArchRegState::X86_64(x86) => X86PmcState {
                        cr0: x86.cr0,
                        cr4: x86.cr4,
                        cpl: x86.cpl,
                    },
                    _ => {
                        ctx.request_exit(ExitReason::Undefined {
                            addr: op.guest_pc,
                            opcode: 0,
                        });
                        return Ok(());
                    }
                };
                let value = match read_x86_pmc(selector, state, ctx.cycle_count) {
                    Ok(value) => value,
                    Err(X86PmcFault::GeneralProtection) => {
                        ctx.request_exit(ExitReason::GeneralProtection {
                            addr: op.guest_pc,
                            error_code: 0,
                        });
                        return Ok(());
                    }
                };
                Self::write_x86_partial(
                    ctx,
                    read.dst_lo,
                    value & u64::from(u32::MAX),
                    OpWidth::W32,
                );
                Self::write_x86_partial(ctx, read.dst_hi, value >> 32, OpWidth::W32);
            }

            OpKind::X86Cpuid {
                dst_eax,
                dst_ebx,
                dst_ecx,
                dst_edx,
                leaf,
                subleaf,
            } => {
                let leaf = ctx.read_vreg(*leaf) as u32;
                let subleaf = ctx.read_vreg(*subleaf) as u32;
                let ArchRegState::X86_64(x86) = &ctx.arch_regs else {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                    return Ok(());
                };
                let (eax, ebx, ecx, edx) = crate::isa::x86_64::execute::system::evaluate_cpuid(
                    leaf,
                    subleaf,
                    crate::isa::x86_64::execute::system::X86CpuidState {
                        initial_apic_id: x86.apic.initial_id,
                        cr4: x86.cr4,
                        xcr0: x86.xcr0,
                        xeon_phi_avx512: x86.xeon_phi_avx512,
                        vp2intersect: x86.vp2intersect,
                        sse4a: x86.sse4a,
                        tbm: x86.tbm,
                        xop: x86.xop,
                        apx: x86.apx_enabled,
                    },
                );
                for (dst, value) in [
                    (*dst_eax, eax),
                    (*dst_ebx, ebx),
                    (*dst_ecx, ecx),
                    (*dst_edx, edx),
                ] {
                    Self::write_x86_partial(ctx, dst, u64::from(value), OpWidth::W32);
                }
            }

            OpKind::X86FsGsBase {
                operand,
                base,
                write,
                width,
                requires_apx,
            } => {
                let (cr4, apx_enabled) = match &ctx.arch_regs {
                    ArchRegState::X86_64(x86) => (x86.cr4, x86.apx_enabled),
                    _ => {
                        ctx.request_exit(ExitReason::Undefined {
                            addr: op.guest_pc,
                            opcode: 0,
                        });
                        return Ok(());
                    }
                };
                if cr4 & (1 << 16) == 0 || (*requires_apx && !apx_enabled) {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                    return Ok(());
                }
                if !matches!(width, OpWidth::W32 | OpWidth::W64) {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                    return Ok(());
                }
                if *write {
                    let value = ctx.read_vreg(*operand) & width.mask();
                    if *width == OpWidth::W64 && (((value as i64) << 16 >> 16) as u64 != value) {
                        ctx.request_exit(ExitReason::GeneralProtection {
                            addr: op.guest_pc,
                            error_code: 0,
                        });
                        return Ok(());
                    }
                    ctx.write_vreg(*base, value);
                } else {
                    let value = ctx.read_vreg(*base);
                    Self::write_x86_partial(ctx, *operand, value, *width);
                }
            }

            OpKind::X86SwapGs {
                gs_base,
                kernel_gs_base,
            } => {
                let cpl = match &ctx.arch_regs {
                    ArchRegState::X86_64(x86) => x86.cpl,
                    _ => {
                        ctx.request_exit(ExitReason::Undefined {
                            addr: op.guest_pc,
                            opcode: 0,
                        });
                        return Ok(());
                    }
                };
                if cpl != 0 {
                    ctx.request_exit(ExitReason::GeneralProtection {
                        addr: op.guest_pc,
                        error_code: 0,
                    });
                    return Ok(());
                }
                let old_gs_base = ctx.read_vreg(*gs_base);
                let old_kernel_gs_base = ctx.read_vreg(*kernel_gs_base);
                ctx.write_vreg(*gs_base, old_kernel_gs_base);
                ctx.write_vreg(*kernel_gs_base, old_gs_base);
            }

            OpKind::X86MonitorMwait(X86MonitorMwaitOp {
                rcx,
                hint,
                addr,
                stack_segment,
            }) => {
                let cpl = match &ctx.arch_regs {
                    ArchRegState::X86_64(x86) => x86.cpl,
                    _ => {
                        ctx.request_exit(ExitReason::Undefined {
                            addr: op.guest_pc,
                            opcode: 0,
                        });
                        return Ok(());
                    }
                };
                if cpl != 0 {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                    return Ok(());
                }
                if ctx.read_vreg(*rcx) != 0 {
                    ctx.request_exit(ExitReason::GeneralProtection {
                        addr: op.guest_pc,
                        error_code: 0,
                    });
                    return Ok(());
                }
                // EDX for MONITOR and EAX for MWAIT are architecturally read
                // hint inputs. Their values are implementation-dependent and
                // intentionally have no effect in the deterministic profile.
                let _ = ctx.read_vreg(*hint);
                if let Some(addr) = addr {
                    let effective_addr = self.compute_address(ctx, addr);
                    if (((effective_addr as i64) << 16 >> 16) as u64) != effective_addr {
                        ctx.request_exit(if *stack_segment {
                            ExitReason::StackSegment {
                                addr: op.guest_pc,
                                error_code: 0,
                            }
                        } else {
                            ExitReason::GeneralProtection {
                                addr: op.guest_pc,
                                error_code: 0,
                            }
                        });
                        return Ok(());
                    }
                    let _ =
                        self.load_memory(memory, effective_addr, MemWidth::B1, SignExtend::Zero)?;
                }
            }

            OpKind::X86WaitPkg(wait) => match wait {
                X86WaitPkgOp::Umonitor {
                    addr,
                    stack_segment,
                } => {
                    if !matches!(ctx.arch_regs, ArchRegState::X86_64(_)) {
                        ctx.request_exit(ExitReason::Undefined {
                            addr: op.guest_pc,
                            opcode: 0,
                        });
                        return Ok(());
                    }
                    let effective_addr = self.compute_address(ctx, addr);
                    if (((effective_addr as i64) << 16 >> 16) as u64) != effective_addr {
                        ctx.request_exit(if *stack_segment {
                            ExitReason::StackSegment {
                                addr: op.guest_pc,
                                error_code: 0,
                            }
                        } else {
                            ExitReason::GeneralProtection {
                                addr: op.guest_pc,
                                error_code: 0,
                            }
                        });
                        return Ok(());
                    }
                    let _ =
                        self.load_memory(memory, effective_addr, MemWidth::B1, SignExtend::Zero)?;
                }
                X86WaitPkgOp::Umwait {
                    control,
                    deadline_low,
                    deadline_high,
                }
                | X86WaitPkgOp::Tpause {
                    control,
                    deadline_low,
                    deadline_high,
                } => {
                    let (cr0, cr4, cpl) = match &ctx.arch_regs {
                        ArchRegState::X86_64(x86) => (x86.cr0, x86.cr4, x86.cpl),
                        _ => {
                            ctx.request_exit(ExitReason::Undefined {
                                addr: op.guest_pc,
                                opcode: 0,
                            });
                            return Ok(());
                        }
                    };
                    let control = ctx.read_vreg(*control) as u32;
                    if control & !1 != 0 || (cr0 & 1 != 0 && cr4 & (1 << 2) != 0 && cpl != 0) {
                        ctx.request_exit(ExitReason::GeneralProtection {
                            addr: op.guest_pc,
                            error_code: 0,
                        });
                        return Ok(());
                    }
                    // EDX:EAX is an architecturally read deadline. The
                    // deterministic profile takes an allowed immediate wake
                    // event, so the value has no further observable effect.
                    let _deadline = (ctx.read_vreg(*deadline_high) as u32 as u64) << 32
                        | ctx.read_vreg(*deadline_low) as u32 as u64;
                    ctx.flags.materialize_all();
                    ctx.flags.materialized.cf = false;
                    ctx.flags.materialized.pf = false;
                    ctx.flags.materialized.af = false;
                    ctx.flags.materialized.zf = false;
                    ctx.flags.materialized.sf = false;
                    ctx.flags.materialized.of = false;
                }
            },

            OpKind::X86Pkru {
                eax,
                ecx,
                edx,
                pkru,
                write,
            } => {
                let cr4 = match &ctx.arch_regs {
                    ArchRegState::X86_64(x86) => x86.cr4,
                    _ => {
                        ctx.request_exit(ExitReason::Undefined {
                            addr: op.guest_pc,
                            opcode: 0,
                        });
                        return Ok(());
                    }
                };
                if cr4 & (1 << 22) == 0 {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                    return Ok(());
                }

                let ecx_value = ctx.read_vreg(*ecx) as u32;
                if ecx_value != 0 || (*write && ctx.read_vreg(*edx) as u32 != 0) {
                    ctx.request_exit(ExitReason::GeneralProtection {
                        addr: op.guest_pc,
                        error_code: 0,
                    });
                    return Ok(());
                }

                if *write {
                    ctx.write_vreg(*pkru, ctx.read_vreg(*eax) as u32 as u64);
                } else {
                    let value = ctx.read_vreg(*pkru) as u32 as u64;
                    Self::write_x86_partial(ctx, *eax, value, OpWidth::W32);
                    Self::write_x86_partial(ctx, *edx, 0, OpWidth::W32);
                }
            }

            _ => return self.execute_op_opmask(ctx, memory, op),
        }

        Ok(())
    }
}
