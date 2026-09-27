//! Argument passing.
//!
//! | Architecture | Integer/pointer | Floating point | Stack |
//! |---|---|---|---|
//! | x86 | stack | stack | `[ESP+4]` upward in 4-byte slots; 64-bit values take two |
//! | x64 | RCX, RDX, R8, R9 by position | XMM0-XMM3 by position | `[RSP+8+8*i]` (32 bytes of home space for the first four) |
//! | ARM64 | X0-X7 in order | V0-V7 in order | `[SP]` upward in 8-byte slots |
//!
//! Microsoft Learn's "x64 calling convention", "Overview of ARM64 ABI
//! conventions" (Parameter passing, including its variadic addendum),
//! `__stdcall`, and `__cdecl` specify these layouts. On ARM64 variadic
//! functions use only integer registers and stack slots. A `va_list` is a
//! pointer to 4-byte (x86) or 8-byte (x64, ARM64) slots.
//!
//! This module handles the scalar classes in [`Arg`]; aggregate, vectorcall,
//! thiscall, fastcall, and ARM64EC signatures require separate descriptors.
//! Locating an argument takes O(index) time on x86/ARM64 and O(1) on x64,
//! with O(1) extra space. All guest-memory reads propagate faults.

use super::{Arg, Conv, Ctx};
use crate::user::windows::arch::{WinArch, WinCpu};
use crate::user::windows::memory::{Mem, MemFault};

/// Where one argument is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Loc {
    /// Integer register (x64: position 0-3 → RCX/RDX/R8/R9; ARM64: X0-X7).
    Reg(usize),
    /// Floating-point register (x64: XMM0-3; ARM64: V0-V7).
    FReg(usize),
    /// Stack, at this byte offset from the entry stack pointer.
    Stack(u64),
}

const X64_INT: [usize; 4] = [1, 2, 8, 9]; // RCX, RDX, R8, R9 in ModR/M order

/// Computes the scalar argument location; rejects an unrepresentable offset.
pub fn locate(arch: WinArch, args: &[Arg], conv: Conv, index: usize) -> Result<Loc, MemFault> {
    let overflow = || MemFault {
        addr: u64::MAX,
        write: false,
    };
    let slots = |n: usize, size: u64| {
        u64::try_from(n)
            .ok()
            .and_then(|n| n.checked_mul(size))
            .ok_or_else(overflow)
    };
    Ok(match arch {
        WinArch::X86 => {
            let mut off = 4u64;
            for a in args.iter().take(index) {
                off = off.checked_add(slot_bytes_x86(*a)).ok_or_else(overflow)?;
            }
            // Unlisted arguments belong to the variadic tail; default
            // promotions are chosen by the va reader, not this descriptor.
            off = off
                .checked_add(slots(index.saturating_sub(args.len()), 4)?)
                .ok_or_else(overflow)?;
            Loc::Stack(off)
        }
        WinArch::X64 => {
            let float = matches!(args.get(index), Some(Arg::F32 | Arg::F64));
            if index < 4 {
                if float {
                    Loc::FReg(index)
                } else {
                    Loc::Reg(index)
                }
            } else {
                Loc::Stack(slots(index, 8)?.checked_add(8).ok_or_else(overflow)?)
            }
        }
        WinArch::Arm64 => {
            let (mut ngrn, mut nsrn, mut nsaa) = (0usize, 0usize, 0u64);
            let variadic = conv == Conv::Variadic;
            for (i, a) in args.iter().enumerate() {
                let float = !variadic && matches!(a, Arg::F32 | Arg::F64);
                let loc = if float {
                    if nsrn < 8 {
                        nsrn += 1;
                        Loc::FReg(nsrn - 1)
                    } else {
                        nsaa = nsaa.checked_add(8).ok_or_else(overflow)?;
                        Loc::Stack(nsaa - 8)
                    }
                } else if ngrn < 8 {
                    ngrn += 1;
                    Loc::Reg(ngrn - 1)
                } else {
                    nsaa = nsaa.checked_add(8).ok_or_else(overflow)?;
                    Loc::Stack(nsaa - 8)
                };
                if i == index {
                    return Ok(loc);
                }
            }
            // Past the listed parameters (a variadic tail): integer slots.
            let extra = index.saturating_sub(args.len());
            let position = ngrn.checked_add(extra).ok_or_else(overflow)?;
            if position < 8 {
                Loc::Reg(position)
            } else {
                Loc::Stack(
                    nsaa.checked_add(slots(position - 8, 8)?)
                        .ok_or_else(overflow)?,
                )
            }
        }
    })
}

/// Bytes an x86 stack argument occupies.
pub fn slot_bytes_x86(a: Arg) -> u64 {
    match a {
        Arg::I64 | Arg::F64 => 8,
        _ => 4,
    }
}

/// Bytes a `__stdcall` callee removes on x86.
pub fn stdcall_bytes(args: &[Arg]) -> u64 {
    args.iter().map(|a| slot_bytes_x86(*a)).sum()
}

fn read_loc(
    cpu: &WinCpu,
    mem: &impl Mem,
    entry_sp: u64,
    loc: Loc,
    width: u64,
) -> Result<u64, MemFault> {
    let arch = cpu.arch();
    Ok(match loc {
        Loc::Reg(i) => match arch {
            WinArch::X64 => cpu.gpr(X64_INT[i]),
            _ => cpu.gpr(i),
        },
        Loc::FReg(i) => match cpu {
            WinCpu::X86(x, _) => x.vcpu().user_regs().xmm[i][0],
            WinCpu::Arm64(a) => a.core().get_simd(i as u8) as u64,
        },
        Loc::Stack(off) => {
            let at = stack_addr(arch, entry_sp, off, width)?;
            if width == 8 {
                mem.u64(at)?
            } else {
                u64::from(mem.u32(at)?)
            }
        }
    })
}

/// Computes a stack address in the guest pointer width and rejects accesses
/// crossing its upper bound. x86 effective-address addition is modulo 2^32;
/// a scalar access itself must remain inside the 32-bit flat data segment.
fn stack_addr(arch: WinArch, base: u64, offset: u64, width: u64) -> Result<u64, MemFault> {
    let fault = |addr| MemFault { addr, write: false };
    let at = if arch == WinArch::X86 {
        u64::from((base as u32).wrapping_add(offset as u32))
    } else {
        base.checked_add(offset).ok_or_else(|| fault(u64::MAX))?
    };
    let last = at.checked_add(width - 1).ok_or_else(|| fault(u64::MAX))?;
    if arch == WinArch::X86 && last > u64::from(u32::MAX) {
        return Err(fault(0x1_0000_0000));
    }
    Ok(at)
}

/// Reads the raw bits of scalar argument `index` with checked guest access.
/// A narrow stack argument reads 4 bytes even when its ABI slot is 8 bytes;
/// unspecified upper padding is never read. Register arguments retain their
/// unspecified high bits, so callers must truncate to the parameter type.
pub fn read_arg(
    cpu: &WinCpu,
    mem: &impl Mem,
    entry_sp: u64,
    args: &[Arg],
    conv: Conv,
    index: usize,
) -> Result<u64, MemFault> {
    let loc = locate(cpu.arch(), args, conv, index)?;
    let width = match args.get(index) {
        Some(Arg::I32 | Arg::F32) => 4,
        Some(Arg::I64 | Arg::F64) => 8,
        _ => cpu.arch().ptr_size(),
    };
    read_loc(cpu, mem, entry_sp, loc, width)
}

impl Ctx<'_> {
    /// The raw bits of parameter `i`: zero-extended 32-bit value for a
    /// 32-bit parameter on x86, the full register or slot elsewhere (the
    /// upper bits of a 32-bit parameter in a 64-bit register are
    /// unspecified; use [`Ctx::u32`]). An inaccessible slot is a fault.
    pub fn arg(&self, i: usize) -> Result<u64, MemFault> {
        read_arg(
            &self.t.cpu,
            &self.p.space,
            self.entry_sp,
            self.api.args,
            self.api.conv,
            i,
        )
    }

    /// Explicit checked spelling of [`Ctx::arg`].
    pub fn try_arg(&self, i: usize) -> Result<u64, MemFault> {
        self.arg(i)
    }

    /// Parameter `i` as a 32-bit unsigned integer.
    pub fn u32(&self, i: usize) -> Result<u32, MemFault> {
        self.arg(i).map(|v| v as u32)
    }

    /// Parameter `i` as a 32-bit signed integer.
    pub fn i32(&self, i: usize) -> Result<i32, MemFault> {
        self.arg(i).map(|v| v as u32 as i32)
    }

    /// Parameter `i` as a pointer (truncated to the pointer width).
    pub fn ptr(&self, i: usize) -> Result<u64, MemFault> {
        self.arg(i).map(|v| self.p.arch.ptr(v))
    }

    /// Parameter `i` as a `BOOL`.
    pub fn bool(&self, i: usize) -> Result<bool, MemFault> {
        self.u32(i).map(|v| v != 0)
    }

    /// Parameter `i` as a `double`.
    pub fn f64(&self, i: usize) -> Result<f64, MemFault> {
        self.arg(i).map(f64::from_bits)
    }

    /// Parameter `i` as a `float`.
    pub fn f32(&self, i: usize) -> Result<f32, MemFault> {
        self.arg(i).map(|v| f32::from_bits(v as u32))
    }

    /// Parameter `i` as a pointer-sized signed integer (`SSIZE_T`,
    /// `LONG_PTR`).
    pub fn iptr(&self, i: usize) -> Result<i64, MemFault> {
        self.arg(i).map(|v| match self.p.arch {
            WinArch::X86 => v as u32 as i32 as i64,
            _ => v as i64,
        })
    }

    /// The variadic arguments after the listed parameters.
    pub fn va(&self) -> Result<VaList, MemFault> {
        Ok(match self.p.arch {
            WinArch::X86 => VaList::Memory {
                addr: stack_addr(
                    self.p.arch,
                    self.entry_sp,
                    4 + stdcall_bytes(self.api.args),
                    1,
                )?,
                slot: 4,
            },
            _ => VaList::Args {
                next: self.api.args.len(),
            },
        })
    }

    /// A `va_list` value passed as parameter `i`.
    pub fn va_list(&self, i: usize) -> Result<VaList, MemFault> {
        Ok(VaList::Memory {
            addr: self.ptr(i)?,
            slot: if self.p.arch.is64() { 8 } else { 4 },
        })
    }

    /// Reads the next variadic argument as raw 64 bits (`wide` for a
    /// 64-bit value, which takes two x86 slots).
    pub fn va_next(&self, va: &mut VaList, wide: bool) -> Result<u64, MemFault> {
        read_va(
            &self.t.cpu,
            &self.p.space,
            self.entry_sp,
            self.api.args,
            va,
            wide,
        )
    }
}

/// Reads a variadic argument and advances the cursor only on success.
pub fn read_va(
    cpu: &WinCpu,
    mem: &impl Mem,
    entry_sp: u64,
    args: &[Arg],
    va: &mut VaList,
    wide: bool,
) -> Result<u64, MemFault> {
    match va {
        VaList::Memory { addr, slot } => {
            if !matches!(*slot, 4 | 8) {
                return Err(MemFault {
                    addr: *addr,
                    write: false,
                });
            }
            let size = if wide && *slot == 4 { 8 } else { *slot };
            let at = stack_addr(cpu.arch(), *addr, 0, size)?;
            let v = if wide || *slot == 8 {
                mem.u64(at)?
            } else {
                u64::from(mem.u32(at)?)
            };
            *addr = stack_addr(cpu.arch(), at, size, 1)?;
            Ok(v)
        }
        VaList::Args { next } => {
            let loc = locate(cpu.arch(), args, Conv::Variadic, *next)?;
            let advanced = next.checked_add(1).ok_or(MemFault {
                addr: u64::MAX,
                write: false,
            })?;
            // x64 passes a variadic double in the integer register too
            // (the caller duplicates it), so the integer view suffices.
            let loc = match loc {
                Loc::FReg(i) => Loc::Reg(i),
                l => l,
            };
            let width = if wide { 8 } else { cpu.arch().ptr_size() };
            let value = read_loc(cpu, mem, entry_sp, loc, width)?;
            *next = advanced;
            Ok(value)
        }
    }
}

/// A cursor over variadic arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaList {
    /// Consecutive stack slots at `addr` of `slot` bytes (x86 variadic
    /// calls and every `va_list`).
    Memory {
        /// Next slot.
        addr: u64,
        /// Slot size.
        slot: u64,
    },
    /// The call's own argument positions from `next` onward (x64, ARM64).
    Args {
        /// Next position.
        next: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::cpu::x86_64::RESERVED_PHYS;
    use crate::user::mm::{AddressSpace, Mapping, PAGE_SIZE, Perms, SpaceConfig};

    const STACK: u64 = 0x20000;

    fn cpu(arch: WinArch) -> (WinCpu, AddressSpace) {
        let space = AddressSpace::new(SpaceConfig {
            va_limit: 1 << 47,
            arena_bytes: 64 * PAGE_SIZE,
            reserved_phys: RESERVED_PHYS.to_vec(),
        })
        .unwrap();
        space
            .map(
                STACK,
                PAGE_SIZE,
                Mapping::anonymous(Perms::READ | Perms::WRITE),
            )
            .unwrap();
        (WinCpu::new(arch, &space), space)
    }

    #[test]
    fn x86_scalar_widths_and_cdecl_variadic_tail() {
        let args = [Arg::I32, Arg::I64, Arg::F32, Arg::F64, Arg::Ptr];
        assert_eq!(stdcall_bytes(&args), 28);
        for (i, expected) in [4, 8, 16, 20, 28, 32, 36].into_iter().enumerate() {
            assert_eq!(
                locate(WinArch::X86, &args, Conv::Variadic, i),
                Ok(Loc::Stack(expected))
            );
        }
        let (cpu, space) = cpu(WinArch::X86);
        space.w64(STACK + 8, 0x0123_4567_89AB_CDEF).unwrap();
        assert_eq!(
            read_arg(&cpu, &space, STACK, &args, Conv::Cdecl, 1),
            Ok(0x0123_4567_89AB_CDEF)
        );
    }

    #[test]
    fn x64_mixed_parameters_use_positions_and_32_byte_shadow_space() {
        let args = [Arg::I32, Arg::F64, Arg::I64, Arg::F32, Arg::Ptr];
        let expected = [
            Loc::Reg(0),
            Loc::FReg(1),
            Loc::Reg(2),
            Loc::FReg(3),
            Loc::Stack(40),
        ];
        for (i, loc) in expected.into_iter().enumerate() {
            assert_eq!(locate(WinArch::X64, &args, Conv::Stdcall, i), Ok(loc));
        }
        let (mut cpu, space) = cpu(WinArch::X64);
        cpu.set_gpr(1, 11);
        cpu.set_gpr(8, 33);
        cpu.x86_mut().unwrap().vcpu_mut().user_regs_mut().xmm[1][0] = 2.5f64.to_bits();
        space.w64(STACK + 40, 55).unwrap();
        assert_eq!(read_arg(&cpu, &space, STACK, &args, Conv::Cdecl, 0), Ok(11));
        assert_eq!(
            read_arg(&cpu, &space, STACK, &args, Conv::Cdecl, 1),
            Ok(2.5f64.to_bits())
        );
        assert_eq!(read_arg(&cpu, &space, STACK, &args, Conv::Cdecl, 2), Ok(33));
        assert_eq!(read_arg(&cpu, &space, STACK, &args, Conv::Cdecl, 4), Ok(55));
    }

    #[test]
    fn arm64_integer_and_float_register_allocation_is_independent() {
        let mut args = Vec::new();
        for _ in 0..9 {
            args.extend([Arg::I32, Arg::F64]);
        }
        for i in 0..8 {
            assert_eq!(
                locate(WinArch::Arm64, &args, Conv::Cdecl, 2 * i),
                Ok(Loc::Reg(i))
            );
            assert_eq!(
                locate(WinArch::Arm64, &args, Conv::Cdecl, 2 * i + 1),
                Ok(Loc::FReg(i))
            );
        }
        assert_eq!(
            locate(WinArch::Arm64, &args, Conv::Cdecl, 16),
            Ok(Loc::Stack(0))
        );
        assert_eq!(
            locate(WinArch::Arm64, &args, Conv::Cdecl, 17),
            Ok(Loc::Stack(8))
        );
        assert_eq!(
            locate(WinArch::Arm64, &args, Conv::Variadic, 7),
            Ok(Loc::Reg(7))
        );
        assert_eq!(
            locate(WinArch::Arm64, &args, Conv::Variadic, 8),
            Ok(Loc::Stack(0))
        );
    }

    #[test]
    fn argument_stack_fault_is_preserved() {
        for arch in WinArch::ALL {
            let (cpu, space) = cpu(arch);
            let count = match arch {
                WinArch::X86 => 1,
                WinArch::X64 => 5,
                WinArch::Arm64 => 9,
            };
            let args = vec![Arg::Ptr; count];
            let result = read_arg(&cpu, &space, 0x40000, &args, Conv::Stdcall, count - 1);
            let off = match arch {
                WinArch::X86 => 4,
                WinArch::X64 => 40,
                WinArch::Arm64 => 0,
            };
            assert_eq!(
                result,
                Err(MemFault {
                    addr: 0x40000 + off,
                    write: false
                })
            );
        }
    }

    #[test]
    fn narrow_stack_argument_does_not_read_unspecified_padding() {
        let (cpu, space) = cpu(WinArch::X64);
        let end = STACK + PAGE_SIZE;
        space.w32(end - 4, 0xAABB_CCDD).unwrap();
        let mut args = [Arg::Ptr; 5];
        args[4] = Arg::I32;
        assert_eq!(
            read_arg(&cpu, &space, end - 44, &args, Conv::Cdecl, 4),
            Ok(0xAABB_CCDD)
        );
        args[4] = Arg::I64;
        assert_eq!(
            read_arg(&cpu, &space, end - 44, &args, Conv::Cdecl, 4),
            Err(MemFault {
                addr: end,
                write: false
            })
        );
    }

    #[test]
    fn pointer_addition_obeys_guest_width_and_checks_access_bounds() {
        assert_eq!(stack_addr(WinArch::X86, 0xFFFF_FFFC, 8, 4), Ok(4));
        assert_eq!(
            stack_addr(WinArch::X86, 0xFFFF_FFFC, 0, 8),
            Err(MemFault {
                addr: 0x1_0000_0000,
                write: false
            })
        );
        assert_eq!(
            stack_addr(WinArch::X64, u64::MAX - 3, 8, 4),
            Err(MemFault {
                addr: u64::MAX,
                write: false
            })
        );
        assert!(locate(WinArch::X64, &[], Conv::Variadic, usize::MAX).is_err());
        assert!(locate(WinArch::Arm64, &[], Conv::Variadic, usize::MAX).is_err());
    }

    #[test]
    fn variadic_fault_does_not_advance_memory_or_argument_cursor() {
        for arch in WinArch::ALL {
            let (cpu, space) = cpu(arch);
            let mut va = VaList::Memory {
                addr: 0x40000,
                slot: arch.ptr_size(),
            };
            let initial = va;
            assert!(read_va(&cpu, &space, STACK, &[], &mut va, true).is_err());
            assert_eq!(va, initial);
        }
        for arch in [WinArch::X64, WinArch::Arm64] {
            let (cpu, space) = cpu(arch);
            let mut va = VaList::Args { next: 8 };
            assert!(read_va(&cpu, &space, 0x40000, &[], &mut va, true).is_err());
            assert_eq!(va, VaList::Args { next: 8 });
        }
    }

    #[test]
    fn variadic_double_uses_x64_duplicate_integer_register() {
        let (mut cpu, space) = cpu(WinArch::X64);
        cpu.set_gpr(2, 3.25f64.to_bits());
        cpu.x86_mut().unwrap().vcpu_mut().user_regs_mut().xmm[1][0] = 9.5f64.to_bits();
        let mut va = VaList::Args { next: 1 };
        assert_eq!(
            read_va(&cpu, &space, STACK, &[Arg::Ptr, Arg::F64], &mut va, true),
            Ok(3.25f64.to_bits())
        );
        assert_eq!(va, VaList::Args { next: 2 });
    }

    #[test]
    fn variadic_x86_wide_value_advances_two_slots() {
        let (cpu, space) = cpu(WinArch::X86);
        space.w64(STACK, 0xFEDC_BA98_7654_3210).unwrap();
        space.w32(STACK + 8, 0xABCD_EF01).unwrap();
        let mut va = VaList::Memory {
            addr: STACK,
            slot: 4,
        };
        assert_eq!(
            read_va(&cpu, &space, STACK, &[], &mut va, true),
            Ok(0xFEDC_BA98_7654_3210)
        );
        assert_eq!(
            read_va(&cpu, &space, STACK, &[], &mut va, false),
            Ok(0xABCD_EF01)
        );
        assert_eq!(
            va,
            VaList::Memory {
                addr: STACK + 12,
                slot: 4
            }
        );
    }
}
