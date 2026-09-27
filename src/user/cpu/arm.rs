//! AArch32 user-mode adapter.
//!
//! Drives an [`Armv7Cpu`] in User mode through the direct executor, which
//! runs one decoded instruction and leaves the rest of the instruction
//! cycle to its caller. This adapter is that caller: it fetches the
//! instruction with execute permission (an A32 word, or a T32 halfword and,
//! for the 32-bit encodings, the halfword after it), decodes it, runs it,
//! and advances the PC and the Thumb IT state. `SVC`, `BKPT`, UNDEFINED
//! instructions, and faulting accesses end a run with the PC and IT state
//! at the Arm ARM's preferred return address: past an `SVC`, at anything
//! else.
//!
//! The CPU is an ARMv8-A core's AArch32 EL0 under an arm64 kernel, which
//! differs from the ARMv7 core it runs on in what it leaves out:
//!
//! - `SWP` and `SWPB` are UNDEFINED (ARMv8 removed them from AArch32);
//! - `SETEND` is UNDEFINED: the core has no mixed-endian data support at
//!   EL0 (`ID_AA64MMFR0_EL1.BigEndEL0 = 0`, `SCTLR_EL1.SED` set);
//! - the CP15 barriers are UNDEFINED (`SCTLR_EL1.CP15BEN` clear, as Linux
//!   leaves it while it emulates them);
//! - FP/SIMD is enabled (`CPACR_EL1.FPEN`), which the ARMv7 core models as
//!   `FPEXC.EN`.
//!
//! Memory accesses go through [`UserA32Memory`], which translates every
//! access with the address space's page permissions; unaligned word and
//! halfword accesses are permitted (Linux runs EL0 with `SCTLR_EL1.A`
//! clear), while the exclusive and ordered accesses, which must be aligned
//! whatever `SCTLR.A` says, raise alignment faults. The core has no code
//! cache, so code written through the address space is seen at its next
//! fetch.

use std::cell::Cell;

use super::{AccessFault, AccessFaultKind};
use crate::error::{GuestMemoryFault, MemoryAccessKind, MemoryFaultKind};
use crate::isa::arm::decoder::ThumbDecoder;
use crate::isa::arm::execution::{ArmMemory, MemoryError};
use crate::isa::arm::instructions::ExclusiveMonitor;
use crate::isa::arm::{
    Armv7Cpu, Decoder, ExceptionType, ExecResult, ExecutionState, Executor, Mnemonic,
    ProcessorMode, Psr,
};
use crate::user::mm::AddressSpace;

/// The AArch32 core's memory interface over a user address space. The
/// interface reports a failed access by address only, so the translation
/// fault behind it is kept for the adapter to report.
#[derive(Debug)]
pub struct UserA32Memory {
    space: AddressSpace,
    fault: Cell<Option<GuestMemoryFault>>,
}

impl UserA32Memory {
    /// Creates a memory view of `space`.
    pub fn new(space: AddressSpace) -> Self {
        UserA32Memory {
            space,
            fault: Cell::new(None),
        }
    }

    /// The fault of the last failed access, which it clears.
    fn take_fault(&self) -> Option<GuestMemoryFault> {
        self.fault.take()
    }

    fn failed(&self, fault: GuestMemoryFault) -> MemoryError {
        self.fault.set(Some(fault));
        let addr = fault.address as u32;
        match fault.kind {
            MemoryFaultKind::Unmapped => MemoryError::OutOfBounds(addr),
            MemoryFaultKind::Permission => MemoryError::PermissionDenied(addr),
            MemoryFaultKind::Other => MemoryError::BusError(addr),
        }
    }

    fn load<const N: usize>(&self, addr: u32) -> Result<[u8; N], MemoryError> {
        let mut b = [0u8; N];
        self.space
            .read(u64::from(addr), &mut b)
            .map_err(|f| self.failed(f))?;
        Ok(b)
    }

    fn store(&mut self, addr: u32, data: &[u8]) -> Result<(), MemoryError> {
        self.space
            .write(u64::from(addr), data)
            .map_err(|f| self.failed(f))
    }
}

impl ArmMemory for UserA32Memory {
    fn read_word(&self, addr: u32) -> Result<u32, MemoryError> {
        self.load(addr).map(u32::from_le_bytes)
    }

    fn write_word(&mut self, addr: u32, value: u32) -> Result<(), MemoryError> {
        self.store(addr, &value.to_le_bytes())
    }

    fn read_halfword(&self, addr: u32) -> Result<u16, MemoryError> {
        self.load(addr).map(u16::from_le_bytes)
    }

    fn write_halfword(&mut self, addr: u32, value: u16) -> Result<(), MemoryError> {
        self.store(addr, &value.to_le_bytes())
    }

    fn read_byte(&self, addr: u32) -> Result<u8, MemoryError> {
        self.load::<1>(addr).map(|b| b[0])
    }

    fn write_byte(&mut self, addr: u32, value: u8) -> Result<(), MemoryError> {
        self.store(addr, &[value])
    }
}

/// Why an AArch32 user-mode run ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum A32Exit {
    /// `SVC` at `pc`; the PC is past it and a Thumb IT block advanced.
    Svc {
        /// The immediate (24 bits in A32, 8 in T32), which EABI ignores.
        imm: u32,
        /// Address of the `SVC`.
        pc: u64,
    },
    /// `BKPT #imm` at `pc`; the PC is left at it.
    Bkpt {
        /// The 16-bit immediate.
        imm: u16,
        /// Address of the `BKPT`.
        pc: u64,
    },
    /// An UNDEFINED instruction at `pc`; the PC and IT state are left at it.
    Undefined {
        /// Address of the instruction.
        pc: u64,
        /// The encoding: an A32 word, a T16 halfword, or a T32 instruction
        /// with its first halfword in bits 31:16.
        insn: u32,
        /// Whether it is a T32 (Thumb) instruction.
        thumb: bool,
        /// Why the core rejected it.
        reason: String,
    },
    /// A memory access faulted (including the fetch, and a PC alignment
    /// fault in A32 state); the PC is left at the instruction.
    Fault(AccessFault),
    /// The instruction budget was spent, or a `WFI`/`WFE` completed.
    Yield,
    /// The core failed in a way no guest program can cause.
    Internal(String),
}

/// An AArch32 guest thread's CPU.
pub struct A32UserCpu {
    cpu: Armv7Cpu,
    mem: UserA32Memory,
    monitor: ExclusiveMonitor,
    decoder: Decoder,
}

impl A32UserCpu {
    /// Creates a CPU in User mode (A32 state, flags and interrupt masks
    /// clear) with zeroed registers over `space`.
    pub fn new(space: &AddressSpace) -> Self {
        let mut cpu = Armv7Cpu::new();
        cpu.change_mode(ProcessorMode::User);
        cpu.cpsr = Psr::from_u32(ProcessorMode::User as u32);
        cpu.regs = [0; 16];
        cpu.vfp.fpexc = 1 << 30;
        cpu.cp15.sctlr = crate::isa::arm::cp15::Sctlr::from_bits(0);
        A32UserCpu {
            cpu,
            mem: UserA32Memory::new(space.clone()),
            monitor: ExclusiveMonitor::new(),
            decoder: Decoder::new(ExecutionState::Arm),
        }
    }

    /// A new CPU for another thread of the same process with this CPU's
    /// register state: R0-R15, the CPSR's user fields, D0-D31, FPSCR,
    /// TPIDRURW, and TPIDRURO.
    pub fn clone_thread(&self) -> Self {
        let mut child = A32UserCpu::new(&self.mem.space);
        child.cpu.regs = self.cpu.regs;
        child.cpu.cpsr = self.cpu.cpsr.clone();
        child.cpu.vfp.dregs = self.cpu.vfp.dregs;
        child.cpu.vfp.fpscr = self.cpu.vfp.fpscr;
        child.cpu.cp15.tpidrurw = self.cpu.cp15.tpidrurw;
        child.cpu.cp15.tpidruro = self.cpu.cp15.tpidruro;
        child
    }

    /// The underlying core.
    pub fn core(&self) -> &Armv7Cpu {
        &self.cpu
    }

    /// Mutable access to the underlying core.
    pub fn core_mut(&mut self) -> &mut Armv7Cpu {
        &mut self.cpu
    }

    /// The address space this CPU executes in.
    pub fn space(&self) -> &AddressSpace {
        &self.mem.space
    }

    /// Current PC (the address of the next instruction).
    pub fn pc(&self) -> u64 {
        u64::from(self.cpu.regs[15])
    }

    /// Sets the PC; bit 0 is cleared, the instruction set unchanged.
    pub fn set_pc(&mut self, pc: u64) {
        self.cpu.regs[15] = pc as u32 & !1;
    }

    /// Current SP (R13).
    pub fn sp(&self) -> u64 {
        u64::from(self.cpu.regs[13])
    }

    /// Sets SP (R13).
    pub fn set_sp(&mut self, value: u64) {
        self.cpu.regs[13] = value as u32;
    }

    /// Whether the thread executes T32 (Thumb) code.
    pub fn thumb(&self) -> bool {
        self.cpu.cpsr.t
    }

    /// Runs at most `budget` instructions, stopping at the first operating
    /// system event.
    pub fn run(&mut self, budget: u64) -> A32Exit {
        let exit = (0..budget)
            .find_map(|_| self.step())
            .unwrap_or(A32Exit::Yield);
        // Leaving the guest is an exception entry, which clears the local
        // exclusive monitor.
        self.monitor.clear();
        exit
    }

    /// Fetches `buf` from `addr` for the instruction at `pc`.
    fn fetch(&self, pc: u32, addr: u32, buf: &mut [u8]) -> Result<(), A32Exit> {
        self.mem
            .space
            .fetch(u64::from(addr), buf)
            .map_err(|f| A32Exit::Fault(AccessFault::from_memory(f, u64::from(pc))))
    }

    fn undefined(&self, pc: u32, insn: u32, thumb: bool, reason: String) -> A32Exit {
        A32Exit::Undefined {
            pc: u64::from(pc),
            insn,
            thumb,
            reason,
        }
    }

    /// Runs one instruction; the event it ended with, if any.
    fn step(&mut self) -> Option<A32Exit> {
        let pc = self.cpu.regs[15];
        let thumb = self.cpu.cpsr.t;
        // An A32 PC that is not word-aligned (after a branch to one) takes a
        // PC alignment fault at the fetch.
        if !thumb && pc & 3 != 0 {
            return Some(A32Exit::Fault(AccessFault {
                addr: u64::from(pc),
                access: MemoryAccessKind::Fetch,
                kind: AccessFaultKind::Alignment,
                pc: u64::from(pc),
            }));
        }
        let mut bytes = [0u8; 4];
        let (len, insn) = if thumb {
            if let Err(e) = self.fetch(pc, pc, &mut bytes[..2]) {
                return Some(e);
            }
            let hw1 = u16::from_le_bytes([bytes[0], bytes[1]]);
            if ThumbDecoder::is_32bit_instruction(hw1) {
                if let Err(e) = self.fetch(pc, pc.wrapping_add(2), &mut bytes[2..]) {
                    return Some(e);
                }
                let hw2 = u16::from_le_bytes([bytes[2], bytes[3]]);
                (4, (u32::from(hw1) << 16) | u32::from(hw2))
            } else {
                (2, u32::from(hw1))
            }
        } else {
            if let Err(e) = self.fetch(pc, pc, &mut bytes) {
                return Some(e);
            }
            (4, u32::from_le_bytes(bytes))
        };
        self.decoder.set_state(if thumb {
            ExecutionState::Thumb
        } else {
            ExecutionState::Arm
        });
        let decoded = match self.decoder.decode(&bytes[..len as usize]) {
            Ok(d) => d,
            Err(e) => return Some(self.undefined(pc, insn, thumb, format!("decode: {e:?}"))),
        };
        if decoded.mnemonic == Mnemonic::SWP {
            return Some(self.undefined(pc, insn, thumb, "SWP is not in ARMv8".into()));
        }
        if is_setend(insn, thumb, len) {
            return Some(self.undefined(pc, insn, thumb, "no mixed-endian EL0".into()));
        }

        let in_it = thumb && self.cpu.cpsr.in_it_block();
        self.mem.fault.set(None);
        let mut exec = Executor::new(&mut self.cpu, &mut self.mem);
        exec.exclusive_monitor = std::mem::take(&mut self.monitor);
        let result = exec.execute(&decoded);
        self.monitor = std::mem::take(&mut exec.exclusive_monitor);

        let next = |cpu: &mut Armv7Cpu| {
            cpu.regs[15] = pc.wrapping_add(len);
            if in_it {
                cpu.cpsr.advance_it_state();
            }
        };
        match result {
            ExecResult::Continue => {
                next(&mut self.cpu);
                None
            }
            ExecResult::Branch(target) => {
                // The executor sets the T bit of an interworking branch; a
                // target with bit 0 set is Thumb code in either case.
                if target & 1 != 0 {
                    self.cpu.cpsr.t = true;
                }
                self.cpu.regs[15] = target & !1;
                if in_it {
                    self.cpu.cpsr.advance_it_state();
                }
                None
            }
            ExecResult::Exception(ExceptionType::SupervisorCall(imm)) => {
                next(&mut self.cpu);
                Some(A32Exit::Svc {
                    imm,
                    pc: u64::from(pc),
                })
            }
            ExecResult::Exception(ExceptionType::Breakpoint(imm)) => Some(A32Exit::Bkpt {
                imm,
                pc: u64::from(pc),
            }),
            ExecResult::Exception(ExceptionType::UndefinedInstruction) | ExecResult::Undefined => {
                let reason = format!("undefined {:?}", decoded.mnemonic);
                Some(self.undefined(pc, insn, thumb, reason))
            }
            ExecResult::Halt => {
                // WFI and WFE complete at once: nothing interrupts a user
                // thread. A wait usually spins on another thread, so yield.
                self.cpu.is_halted = false;
                next(&mut self.cpu);
                Some(A32Exit::Yield)
            }
            ExecResult::MemoryFault(e) => Some(match (self.mem.take_fault(), e) {
                (Some(f), _) => A32Exit::Fault(AccessFault::from_memory(f, u64::from(pc))),
                // An alignment fault the executor raises itself (exclusive
                // and ordered accesses must be naturally aligned).
                (None, MemoryError::Unaligned(addr)) => A32Exit::Fault(AccessFault {
                    addr: u64::from(addr),
                    access: if is_store(decoded.mnemonic) {
                        MemoryAccessKind::Write
                    } else {
                        MemoryAccessKind::Read
                    },
                    kind: AccessFaultKind::Alignment,
                    pc: u64::from(pc),
                }),
                (None, e) => A32Exit::Internal(format!("{e} at {pc:#x} without an access fault")),
            }),
            ExecResult::Exception(other) => Some(A32Exit::Internal(format!(
                "unexpected AArch32 exception {other:?} at {pc:#x}"
            ))),
        }
    }
}

/// `SETEND` (A32 `1111 0001 0000 0001 0000 00E0 0000 0000`, T16
/// `1011 0110 010E 0000`).
fn is_setend(insn: u32, thumb: bool, len: u32) -> bool {
    match (thumb, len) {
        (false, _) => insn & 0xFFFF_FDFF == 0xF101_0000,
        (true, 2) => insn & 0xFFF7 == 0xB650,
        (true, _) => false,
    }
}

/// The stores among the instructions whose alignment the executor checks.
fn is_store(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::STXR
            | Mnemonic::STXRB
            | Mnemonic::STXRH
            | Mnemonic::STXP
            | Mnemonic::STLXR
            | Mnemonic::STLXRB
            | Mnemonic::STLXRH
            | Mnemonic::STLXP
            | Mnemonic::STLR
            | Mnemonic::STLRB
            | Mnemonic::STLRH
    )
}
