//! Flag op execution

use crate::smir::interpret::*;
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
use std::cmp::Ordering;
use std::collections::HashMap;

impl SmirInterpreter {
    pub(crate) fn execute_op_flags(
        &self,
        ctx: &mut SmirContext,
        memory: &mut dyn SmirMemory,
        op: &SmirOp,
    ) -> Result<(), MemoryError> {
        let x86_hint = op.x86_hint;
        match &op.kind {
            // ==================================================================
            // FLAG OPERATIONS
            // ==================================================================
            OpKind::ReadFlags { dst } => {
                ctx.flags.materialize_all();
                let rflags = ctx.flags.materialized.to_rflags();
                ctx.write_vreg(*dst, rflags);
            }

            OpKind::WriteFlags { src } => {
                let rflags = ctx.read_vreg(*src);
                ctx.flags.materialized =
                    crate::smir::ir::flags::MaterializedFlags::from_rflags(rflags);
                ctx.flags.lazy = None;
            }

            OpKind::SetCF { value } => {
                ctx.flags.materialize_all();
                ctx.flags.materialized.cf = *value;
            }

            OpKind::SetDF { value } => {
                ctx.flags.materialize_all();
                ctx.flags.materialized.df = *value;
            }

            OpKind::SetAC { value } => {
                let allowed = match &ctx.arch_regs {
                    ArchRegState::X86_64(x86) => x86.cr0 & 1 == 0 || x86.cpl == 0,
                    _ => false,
                };
                if !allowed {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                    return Ok(());
                }
                ctx.flags.materialize_all();
                ctx.flags.materialized.ac = *value;
            }

            OpKind::X86RequireApx => {
                if !matches!(
                    &ctx.arch_regs,
                    ArchRegState::X86_64(x86) if x86.apx_enabled
                ) {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                }
            }

            OpKind::X86RequireSse4a => {
                const CR0_EM: u64 = 1 << 2;
                const CR0_TS: u64 = 1 << 3;
                const CR4_OSFXSR: u64 = 1 << 9;
                if !matches!(
                    &ctx.arch_regs,
                    ArchRegState::X86_64(x86)
                        if x86.sse4a
                            && x86.cr0 & (CR0_EM | CR0_TS) == 0
                            && x86.cr4 & CR4_OSFXSR != 0
                ) {
                    // The x86 integration replays this exact instruction on
                    // the direct path, which distinguishes #UD from #NM.
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                }
            }

            OpKind::X86RequireTbm => {
                if !matches!(
                    &ctx.arch_regs,
                    ArchRegState::X86_64(x86)
                        if x86.tbm
                            && x86.cr0 & 1 != 0
                            && x86.cs_l
                            && x86.rflags & crate::isa::x86_64::flags::bits::VM == 0
                ) {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                }
            }

            OpKind::X86RequireXop => {
                const CR0_TS: u64 = 1 << 3;
                const CR4_OSXSAVE: u64 = 1 << 18;
                if !matches!(
                    &ctx.arch_regs,
                    ArchRegState::X86_64(x86)
                        if x86.xop
                            && x86.cr0 & 1 != 0
                            && x86.cs_l
                            && x86.rflags & crate::isa::x86_64::flags::bits::VM == 0
                            && x86.cr4 & CR4_OSXSAVE != 0
                            && x86.xcr0 & 0b110 == 0b110
                            && x86.cr0 & CR0_TS == 0
                ) {
                    // Exact integration replays this instruction on the direct
                    // path, which distinguishes every #UD condition from #NM.
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                }
            }

            OpKind::X86Cli {
                requires_apx,
                next_pc: _,
            } => {
                use crate::isa::x86_64::execute::system::{
                    X86CliEffect, X86CliFault, X86CliState, evaluate_x86_cli,
                };
                use crate::isa::x86_64::flags;

                let ArchRegState::X86_64(x86) = &mut ctx.arch_regs else {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                    return Ok(());
                };
                if *requires_apx && !x86.apx_enabled {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                    return Ok(());
                }

                match evaluate_x86_cli(X86CliState {
                    cr0: x86.cr0,
                    cr4: x86.cr4,
                    rflags: x86.rflags,
                    cpl: x86.cpl,
                }) {
                    Ok(X86CliEffect::ClearIf) => x86.rflags &= !flags::bits::IF,
                    Ok(X86CliEffect::ClearVif) => x86.rflags &= !flags::bits::VIF,
                    Err(X86CliFault::GeneralProtection) => {
                        ctx.request_exit(ExitReason::GeneralProtection {
                            addr: op.guest_pc,
                            error_code: 0,
                        });
                    }
                }
            }

            OpKind::X86Sti {
                requires_apx,
                next_pc: _,
            } => {
                use crate::isa::x86_64::execute::system::{
                    X86StiEffect, X86StiFault, X86StiState, evaluate_x86_sti,
                };
                use crate::isa::x86_64::flags;

                let ArchRegState::X86_64(x86) = &mut ctx.arch_regs else {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                    return Ok(());
                };

                // Reaching this instruction consumes any prior STI shadow. A
                // successful IF 0->1 transition below may establish a fresh
                // one; VIF updates and fault delivery leave none.
                x86.interrupt_inhibit = false;
                if *requires_apx && !x86.apx_enabled {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                    return Ok(());
                }

                match evaluate_x86_sti(X86StiState {
                    cr0: x86.cr0,
                    cr4: x86.cr4,
                    rflags: x86.rflags,
                    cpl: x86.cpl,
                }) {
                    Ok(X86StiEffect::SetIf { inhibit_interrupts }) => {
                        x86.rflags |= flags::bits::IF;
                        x86.interrupt_inhibit = inhibit_interrupts;
                    }
                    Ok(X86StiEffect::SetVif) => x86.rflags |= flags::bits::VIF,
                    Err(X86StiFault::GeneralProtection) => {
                        ctx.request_exit(ExitReason::GeneralProtection {
                            addr: op.guest_pc,
                            error_code: 0,
                        });
                    }
                }
            }

            OpKind::CmcCF => {
                let cf = ctx.flags.get_cf();
                ctx.flags.materialize_all();
                ctx.flags.materialized.cf = !cf;
            }

            OpKind::MaterializeFlags => {
                ctx.flags.materialize_all();
            }

            OpKind::X86XTest => {
                ctx.flags.materialize_all();
                ctx.flags.materialized.cf = false;
                ctx.flags.materialized.pf = false;
                ctx.flags.materialized.af = false;
                ctx.flags.materialized.zf = true;
                ctx.flags.materialized.sf = false;
                ctx.flags.materialized.of = false;
                ctx.flags.lazy = None;
            }

            OpKind::X86LoadMxcsr {
                addr, requires_apx, ..
            } => {
                if *requires_apx
                    && !matches!(
                        &ctx.arch_regs,
                        ArchRegState::X86_64(x86) if x86.apx_enabled
                    )
                {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                    return Ok(());
                }
                if matches!(
                    &ctx.arch_regs,
                    ArchRegState::X86_64(x86) if x86.cr0 & (1 << 3) != 0
                ) {
                    // The x86 integration replays this exact instruction on
                    // the direct path, which delivers #NM before memory.
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                    return Ok(());
                }
                let effective_addr = self.compute_address(ctx, addr);
                let mut bytes = [0u8; 4];
                memory.read(effective_addr, &mut bytes)?;
                let value = u32::from_le_bytes(bytes);
                if !crate::isa::x86_64::mxcsr_value_is_valid(value) {
                    ctx.request_exit(ExitReason::GeneralProtection {
                        addr: op.guest_pc,
                        error_code: 0,
                    });
                } else if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
                    x86.mxcsr = value;
                }
            }

            OpKind::X86StoreMxcsr { addr, requires_apx } => {
                if *requires_apx
                    && !matches!(
                        &ctx.arch_regs,
                        ArchRegState::X86_64(x86) if x86.apx_enabled
                    )
                {
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                    return Ok(());
                }
                if matches!(
                    &ctx.arch_regs,
                    ArchRegState::X86_64(x86) if x86.cr0 & (1 << 3) != 0
                ) {
                    // The x86 integration replays this exact instruction on
                    // the direct path, which delivers #NM before memory.
                    ctx.request_exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                    return Ok(());
                }
                let effective_addr = self.compute_address(ctx, addr);
                let value = match &ctx.arch_regs {
                    ArchRegState::X86_64(x86) => x86.mxcsr,
                    _ => 0,
                };
                memory.write(effective_addr, &value.to_le_bytes())?;
            }

            OpKind::X86X87Control { kind, .. }
                if matches!(
                    kind,
                    X86X87ControlKind::Init
                        | X86X87ControlKind::ClearExceptions
                        | X86X87ControlKind::StoreStatusAx
                ) && matches!(
                    &ctx.arch_regs,
                    ArchRegState::X86_64(x86) if x86.cr0 & ((1 << 2) | (1 << 3)) != 0
                ) =>
            {
                // The x86 integration replays this exact instruction on
                // the direct path, which delivers #NM before any x87 state
                // or AX commit. REX2/APX and LOCK #UD checks have already
                // executed at an earlier SMIR frontier.
                ctx.request_exit(ExitReason::Undefined {
                    addr: op.guest_pc,
                    opcode: 0,
                });
                return Ok(());
            }
            OpKind::X86X87Control { kind, addr } => match kind {
                X86X87ControlKind::Init => {
                    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
                        x86.x87.init();
                    }
                }
                X86X87ControlKind::ClearExceptions => {
                    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
                        x86.x87.clear_exceptions();
                    }
                }
                X86X87ControlKind::EnterMmx => {
                    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
                        x86.x87.tag_word = 0;
                    }
                }
                X86X87ControlKind::EmptyMmx => {
                    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
                        x86.x87.tag_word = 0xFFFF;
                    }
                }
                X86X87ControlKind::StoreStatusAx => {
                    let status = match &ctx.arch_regs {
                        ArchRegState::X86_64(x86) => x86.x87.status_word,
                        _ => 0,
                    };
                    Self::write_x86_partial(
                        ctx,
                        VReg::Arch(ArchReg::X86(X86Reg::Rax)),
                        status as u64,
                        OpWidth::W16,
                    );
                }
                X86X87ControlKind::LoadControlWord => {
                    let effective_addr = self.compute_address(
                        ctx,
                        addr.as_ref().expect("x87 FLDCW requires an address"),
                    );
                    let mut bytes = [0u8; 2];
                    memory.read(effective_addr, &mut bytes)?;
                    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
                        x86.x87.control_word = u16::from_le_bytes(bytes);
                    }
                }
                X86X87ControlKind::LoadEnvironment(width) => {
                    let effective_addr = self.compute_address(
                        ctx,
                        addr.as_ref().expect("x87 FLDENV requires an address"),
                    );
                    let len = Self::x86_x87_environment_len(*width);
                    let mut image = [0u8; 28];
                    memory.read(effective_addr, &mut image[..len])?;
                    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
                        Self::restore_x86_x87_environment(&mut x86.x87, &image[..len], *width);
                    }
                }
                X86X87ControlKind::StoreEnvironment(width) => {
                    let effective_addr = self.compute_address(
                        ctx,
                        addr.as_ref().expect("x87 FNSTENV requires an address"),
                    );
                    let (image, len) = match &ctx.arch_regs {
                        ArchRegState::X86_64(x86) => {
                            Self::x86_x87_environment_image(&x86.x87, *width)
                        }
                        _ => ([0u8; 28], Self::x86_x87_environment_len(*width)),
                    };
                    memory.write(effective_addr, &image[..len])?;
                    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
                        // The saved FCW is the pre-instruction value; exception
                        // masks become set only after the complete store.
                        x86.x87.control_word |= 0x003F;
                    }
                }
                X86X87ControlKind::RestoreState(width) => {
                    let effective_addr = self.compute_address(
                        ctx,
                        addr.as_ref().expect("x87 FRSTOR requires an address"),
                    );
                    let len = Self::x86_x87_environment_len(*width) + 80;
                    let mut image = [0u8; 108];
                    memory.read(effective_addr, &mut image[..len])?;
                    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
                        Self::restore_x86_x87_state(&mut x86.x87, &image[..len], *width);
                    }
                }
                X86X87ControlKind::SaveState(width) => {
                    let effective_addr = self.compute_address(
                        ctx,
                        addr.as_ref().expect("x87 FNSAVE requires an address"),
                    );
                    let (image, len) = match &ctx.arch_regs {
                        ArchRegState::X86_64(x86) => Self::x86_x87_state_image(&x86.x87, *width),
                        _ => ([0u8; 108], Self::x86_x87_environment_len(*width) + 80),
                    };
                    memory.write(effective_addr, &image[..len])?;
                    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
                        x86.x87.init();
                    }
                }
                X86X87ControlKind::StoreControlWord | X86X87ControlKind::StoreStatusWord => {
                    let effective_addr = self.compute_address(
                        ctx,
                        addr.as_ref()
                            .expect("x87 status/control store requires an address"),
                    );
                    let value = match &ctx.arch_regs {
                        ArchRegState::X86_64(x86) => {
                            if *kind == X86X87ControlKind::StoreControlWord {
                                x86.x87.control_word
                            } else {
                                x86.x87.status_word
                            }
                        }
                        _ => 0,
                    };
                    memory.write(effective_addr, &value.to_le_bytes())?;
                }
            },

            OpKind::X86X87Data { kind, .. }
                if (kind.is_stack_metadata()
                    || matches!(
                        kind,
                        X86X87DataKind::ChangeSign
                            | X86X87DataKind::Absolute
                            | X86X87DataKind::StoreRegister
                            | X86X87DataKind::StorePopRegister
                    ))
                    && matches!(
                        &ctx.arch_regs,
                        ArchRegState::X86_64(x86)
                            if x86.cr0 & ((1 << 2) | (1 << 3)) != 0
                                || (x86.cr0 & (1 << 5) != 0
                                    && x86.x87.status_word & 0x0080 != 0)
                    ) =>
            {
                // These are waiting x87 operations. Replay the exact guest
                // instruction so the direct path delivers #NM before #MF and
                // neither fault commits payloads, TOP, tags, C1, FIP, or FOP.
                ctx.request_exit(ExitReason::Undefined {
                    addr: op.guest_pc,
                    opcode: 0,
                });
                return Ok(());
            }

            OpKind::X86X87Data {
                kind,
                addr,
                st,
                fop,
            } => {
                self.execute_x86_x87_data(
                    ctx,
                    memory,
                    op.guest_pc,
                    *kind,
                    addr.as_ref(),
                    *st,
                    *fop,
                )?;
            }

            OpKind::X86FxSave { addr, rex_w } => {
                let effective_addr = self.compute_address(ctx, addr);
                if effective_addr & 0xF != 0 {
                    return Err(MemoryError::Alignment {
                        addr: effective_addr,
                        required: 16,
                    });
                }
                let image = Self::x86_fxsave_image(ctx, *rex_w);
                // Bytes 464:511 are explicitly available to software and are
                // not modified by FXSAVE.
                memory.write(effective_addr, &image)?;
            }

            OpKind::X86FxRstor { addr, rex_w } => {
                let effective_addr = self.compute_address(ctx, addr);
                if effective_addr & 0xF != 0 {
                    ctx.request_exit(ExitReason::GeneralProtection {
                        addr: op.guest_pc,
                        error_code: 0,
                    });
                    return Ok(());
                }
                let mut image = [0u8; 512];
                memory.read(effective_addr, &mut image)?;
                let mxcsr = u32::from_le_bytes(image[24..28].try_into().unwrap());
                if mxcsr & !0x0000_FFFF != 0 {
                    ctx.request_exit(ExitReason::GeneralProtection {
                        addr: op.guest_pc,
                        error_code: 0,
                    });
                    return Ok(());
                }
                // Commit only after the complete image and MXCSR validation
                // succeed, preserving architectural state on a restore fault.
                Self::restore_x86_fxsave_image(ctx, &image, *rex_w);
            }

            OpKind::X86XSave {
                addr,
                rex_w,
                kind,
                src_low,
                src_high,
            } => {
                let effective_addr = self.compute_address(ctx, addr);
                if effective_addr & 0x3F != 0 {
                    ctx.request_exit(ExitReason::GeneralProtection {
                        addr: op.guest_pc,
                        error_code: 0,
                    });
                } else {
                    let requested = (ctx.read_vreg(*src_low) as u32 as u64)
                        | ((ctx.read_vreg(*src_high) as u32 as u64) << 32);
                    match kind {
                        X86XSaveKind::XSave | X86XSaveKind::XSaveOpt => {
                            Self::save_x86_xsave_standard(
                                ctx,
                                memory,
                                effective_addr,
                                *rex_w,
                                requested,
                                *kind,
                            )?;
                        }
                        X86XSaveKind::XSaveC | X86XSaveKind::XSaveS => {
                            Self::save_x86_xsave_compacted(
                                ctx,
                                memory,
                                effective_addr,
                                *rex_w,
                                requested,
                            )?;
                        }
                    }
                }
            }

            OpKind::X86XRstor {
                addr,
                rex_w,
                supervisor,
                src_low,
                src_high,
            } => {
                let effective_addr = self.compute_address(ctx, addr);
                if effective_addr & 0x3F != 0 {
                    ctx.request_exit(ExitReason::GeneralProtection {
                        addr: op.guest_pc,
                        error_code: 0,
                    });
                } else {
                    let requested = (ctx.read_vreg(*src_low) as u32 as u64)
                        | ((ctx.read_vreg(*src_high) as u32 as u64) << 32);
                    if !Self::restore_x86_xsave(
                        ctx,
                        memory,
                        effective_addr,
                        *rex_w,
                        requested,
                        *supervisor,
                    )? {
                        ctx.request_exit(ExitReason::GeneralProtection {
                            addr: op.guest_pc,
                            error_code: 0,
                        });
                    }
                }
            }

            OpKind::X86Cmpxchg8b16b {
                addr,
                wide,
                locked,
                compare_lo,
                compare_hi,
                new_lo,
                new_hi,
                dst_lo,
                dst_hi,
            } => {
                let effective_addr = self.compute_address(ctx, addr);
                if *wide && effective_addr & 0xF != 0 {
                    ctx.request_exit(ExitReason::GeneralProtection {
                        addr: op.guest_pc,
                        error_code: 0,
                    });
                } else {
                    let compare_lo_value = ctx.read_vreg(*compare_lo);
                    let compare_hi_value = ctx.read_vreg(*compare_hi);
                    let new_lo_value = ctx.read_vreg(*new_lo);
                    let new_hi_value = ctx.read_vreg(*new_hi);
                    let (old_lo, old_hi, success) = if *wide {
                        let (old, success) = memory.compare_and_swap_128(
                            effective_addr,
                            [compare_lo_value, compare_hi_value],
                            [new_lo_value, new_hi_value],
                            if *locked {
                                MemoryOrder::SeqCst
                            } else {
                                MemoryOrder::Relaxed
                            },
                            MemoryOrder::Relaxed,
                        )?;
                        (old[0], old[1], success)
                    } else {
                        let expected = (compare_lo_value as u32 as u64)
                            | ((compare_hi_value as u32 as u64) << 32);
                        let replacement =
                            (new_lo_value as u32 as u64) | ((new_hi_value as u32 as u64) << 32);
                        let (old, success) = memory.compare_and_swap_writeback(
                            effective_addr,
                            expected,
                            replacement,
                            MemWidth::B8,
                            if *locked {
                                MemoryOrder::SeqCst
                            } else {
                                MemoryOrder::Relaxed
                            },
                            MemoryOrder::Relaxed,
                        )?;
                        (old as u32 as u64, old >> 32, success)
                    };
                    if !success {
                        Self::write_x86_partial(
                            ctx,
                            *dst_lo,
                            old_lo,
                            if *wide { OpWidth::W64 } else { OpWidth::W32 },
                        );
                        Self::write_x86_partial(
                            ctx,
                            *dst_hi,
                            old_hi,
                            if *wide { OpWidth::W64 } else { OpWidth::W32 },
                        );
                    }
                    ctx.flags.materialize_all();
                    ctx.flags.materialized.zf = success;
                }
            }

            OpKind::X86Random { dst, width, seed } => {
                let (value, success) = Self::x86_hardware_random(*width, *seed);
                Self::write_x86_partial(ctx, *dst, if success { value } else { 0 }, *width);
                ctx.flags.materialize_all();
                ctx.flags.materialized.cf = success;
                ctx.flags.materialized.of = false;
                ctx.flags.materialized.sf = false;
                ctx.flags.materialized.zf = false;
                ctx.flags.materialized.af = false;
                ctx.flags.materialized.pf = false;
            }

            OpKind::X86ReadPid { dst } => {
                let value = match &ctx.arch_regs {
                    ArchRegState::X86_64(x86) => x86.tsc_aux as u64,
                    _ => 0,
                };
                // IA32_TSC_AUX is 32 bits. Both architectural RDPID
                // destination spellings therefore produce the same zero-
                // extended GPR value; operand-size prefixes are ignored.
                Self::write_x86_partial(ctx, *dst, value, OpWidth::W32);
            }

            OpKind::X86XGetBv {
                dst_low,
                dst_high,
                selector,
            } => {
                let selector = ctx.read_vreg(*selector) as u32;
                let value = match &ctx.arch_regs {
                    ArchRegState::X86_64(x86) => match selector {
                        0 => Some(x86.xcr0),
                        1 => Some(x86.xgetbv1 & x86.xcr0),
                        _ => None,
                    },
                    _ => None,
                };
                if let Some(value) = value {
                    ctx.write_vreg(*dst_low, value as u32 as u64);
                    ctx.write_vreg(*dst_high, (value >> 32) as u32 as u64);
                } else {
                    ctx.request_exit(ExitReason::GeneralProtection {
                        addr: op.guest_pc,
                        error_code: 0,
                    });
                }
            }

            OpKind::X86XSetBv {
                selector,
                src_low,
                src_high,
            } => {
                let selector = ctx.read_vreg(*selector) as u32;
                let value = (ctx.read_vreg(*src_low) as u32 as u64)
                    | ((ctx.read_vreg(*src_high) as u32 as u64) << 32);
                const AVX512_STATE: u64 = (1 << 5) | (1 << 6) | (1 << 7);
                const SUPPORTED: u64 = 0x7 | AVX512_STATE | (1 << 9) | (1 << 19);
                let avx512 = value & AVX512_STATE;
                let invalid = selector != 0
                    || value & 1 == 0
                    || value & !SUPPORTED != 0
                    || (value & (1 << 2) != 0 && value & (1 << 1) == 0)
                    || (avx512 != 0 && (avx512 != AVX512_STATE || value & 0x6 != 0x6));
                if invalid {
                    ctx.request_exit(ExitReason::GeneralProtection {
                        addr: op.guest_pc,
                        error_code: 0,
                    });
                } else if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
                    x86.xcr0 = value;
                }
            }

            OpKind::TestCondition { dst, cond } => {
                let result = if ctx.flags.eval_condition(*cond) {
                    1
                } else {
                    0
                };
                ctx.write_vreg(*dst, result);
            }

            OpKind::SetCC { dst, cond, width } => {
                let result = if ctx.flags.eval_condition(*cond) {
                    1u64
                } else {
                    0
                };
                Self::write_x86_partial(ctx, *dst, result & width.mask(), *width);
            }

            _ => return self.execute_op_system(ctx, memory, op),
        }

        Ok(())
    }
}
