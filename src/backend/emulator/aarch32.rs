//! AArch32 (ARMv7-A, ARM and Thumb state) vCPU for instruction-level
//! embedders.
//!
//! Drives the AArch32 [`Armv7Cpu`] and [`Executor`] over guest memory that the
//! embedder owns completely: there is no SoC device window, interrupt
//! controller, or timer, unlike the S3C64xx machine vCPU
//! (`crate::machine::s3c64xx::runtime::Armv6Vcpu`). The ARMv6/v7
//! short-descriptor MMU configured through CP15 still applies.
//!
//! The fault policy matches the AArch64 instruction engine
//! ([`super::aarch64::Aarch64Vcpu::new_micro`]): `SVC` and `BKPT` are taken
//! architecturally through the vector table, while a memory fault or an
//! UNDEFINED instruction is returned to the embedder at the faulting
//! instruction, which does not retire. `WFI`/`WFE` report [`VcpuExit::Hlt`].

use std::cell::RefCell;
use std::sync::Arc;

use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use crate::error::{Error, GuestMemoryFault, MemoryAccessKind, MemoryFaultKind, Result};
use crate::isa::arm::execution::{ArmMemory, MemoryError};
use crate::isa::arm::instructions::ExclusiveMonitor;
use crate::isa::arm::mmu_v6::{self, V6Access, V6Fault, V6MmuConfig};
use crate::isa::arm::vfp::Fpscr;
use crate::isa::arm::{
    Armv7Cpu, Decoder, ExceptionType, ExecResult, ExecutionState, Executor, Mnemonic,
    ProcessorMode, Psr,
};
use crate::vm::vcpu::{
    Aarch32CpuState, Aarch32Registers, Aarch32SystemRegisters, CpuState, MemAccess, VCpu, VcpuExit,
};

/// Short-descriptor fault status codes that report a permission or domain
/// violation (ARMv7-A ARM, "Short-descriptor translation table format fault
/// status"): section/page domain faults 0b01001/0b01011 and permission faults
/// 0b01101/0b01111.
fn is_permission_fsr(fsr: u32) -> bool {
    matches!(fsr & 0x40F, 0x9 | 0xB | 0xD | 0xF)
}

/// Guest memory through the CP15-configured MMU. Physical addresses index the
/// embedder's guest memory directly; an access with no backing fails with the
/// first inaccessible physical byte.
struct EmbedBridge {
    mem: Arc<GuestMemoryMmap>,
    state: RefCell<BridgeState>,
}

#[derive(Default)]
struct BridgeState {
    mmu: V6MmuConfig,
    privileged: bool,
    /// The fault that made the last failing access fail.
    fault: Option<GuestMemoryFault>,
}

impl EmbedBridge {
    fn fail(&self, fault: GuestMemoryFault) -> MemoryError {
        self.state.borrow_mut().fault = Some(fault);
        MemoryError::BusError(fault.address as u32)
    }

    /// Translates `va` for `access`, recording an MMU fault.
    fn translate(
        &self,
        va: u32,
        access: MemoryAccessKind,
    ) -> std::result::Result<u32, MemoryError> {
        let (mmu, privileged) = {
            let state = self.state.borrow();
            (state.mmu, state.privileged)
        };
        if !mmu.enabled {
            return Ok(va);
        }
        let v6 = match access {
            MemoryAccessKind::Read => V6Access::Read,
            MemoryAccessKind::Write => V6Access::Write,
            MemoryAccessKind::Fetch => V6Access::Execute,
        };
        let walk = |pa: u32| -> Option<u32> {
            let mut buf = [0u8; 4];
            self.mem
                .read_slice(&mut buf, GuestAddress(u64::from(pa)))
                .ok()?;
            Some(u32::from_le_bytes(buf))
        };
        mmu_v6::translate_v6(&mmu, va, privileged, v6, walk)
            .map(|t| t.pa)
            .map_err(|V6Fault { fsr, .. }| {
                // A guest translation fault is not missing host backing.
                self.fail(GuestMemoryFault {
                    address: u64::from(va),
                    size: 0,
                    access,
                    kind: if is_permission_fsr(fsr) {
                        MemoryFaultKind::Permission
                    } else {
                        MemoryFaultKind::Other
                    },
                })
            })
    }

    fn read(
        &self,
        va: u32,
        buf: &mut [u8],
        access: MemoryAccessKind,
    ) -> std::result::Result<(), MemoryError> {
        let pa = self.translate(va, access)?;
        let len = buf.len();
        self.mem
            .read_slice(buf, GuestAddress(u64::from(pa)))
            .map_err(|error| self.fail(physical_fault(pa, len, access, error)))
    }

    fn write(&self, va: u32, data: &[u8]) -> std::result::Result<(), MemoryError> {
        let pa = self.translate(va, MemoryAccessKind::Write)?;
        // Check the whole physical range first so a failing store publishes
        // nothing.
        if !self
            .mem
            .check_range(GuestAddress(u64::from(pa)), data.len())
        {
            let mut probe = vec![0u8; data.len()];
            let error = self
                .mem
                .read_slice(&mut probe, GuestAddress(u64::from(pa)))
                .err()
                .unwrap_or(vm_memory::GuestMemoryError::InvalidGuestAddress(
                    GuestAddress(u64::from(pa)),
                ));
            return Err(self.fail(physical_fault(
                pa,
                data.len(),
                MemoryAccessKind::Write,
                error,
            )));
        }
        self.mem
            .write_slice(data, GuestAddress(u64::from(pa)))
            .map_err(|error| {
                self.fail(physical_fault(
                    pa,
                    data.len(),
                    MemoryAccessKind::Write,
                    error,
                ))
            })
    }

    fn fetch_halfword(&self, va: u32) -> std::result::Result<u16, MemoryError> {
        let mut b = [0u8; 2];
        self.read(va, &mut b, MemoryAccessKind::Fetch)?;
        Ok(u16::from_le_bytes(b))
    }

    fn fetch_word(&self, va: u32) -> std::result::Result<u32, MemoryError> {
        let mut b = [0u8; 4];
        self.read(va, &mut b, MemoryAccessKind::Fetch)?;
        Ok(u32::from_le_bytes(b))
    }
}

/// The fault for a physical access `[pa, pa + len)` that `error` rejected:
/// the first inaccessible byte is past the bytes that were available.
fn physical_fault(
    pa: u32,
    len: usize,
    access: MemoryAccessKind,
    error: vm_memory::GuestMemoryError,
) -> GuestMemoryFault {
    let address = match error {
        vm_memory::GuestMemoryError::PartialBuffer { completed, .. } => {
            u64::from(pa).saturating_add(completed as u64)
        }
        vm_memory::GuestMemoryError::InvalidGuestAddress(address) => address.0,
        _ => u64::from(pa),
    };
    GuestMemoryFault::unmapped(address, len, access)
}

impl ArmMemory for EmbedBridge {
    fn read_word(&self, addr: u32) -> std::result::Result<u32, MemoryError> {
        let mut b = [0u8; 4];
        self.read(addr, &mut b, MemoryAccessKind::Read)?;
        Ok(u32::from_le_bytes(b))
    }

    fn write_word(&mut self, addr: u32, value: u32) -> std::result::Result<(), MemoryError> {
        self.write(addr, &value.to_le_bytes())
    }

    fn read_halfword(&self, addr: u32) -> std::result::Result<u16, MemoryError> {
        let mut b = [0u8; 2];
        self.read(addr, &mut b, MemoryAccessKind::Read)?;
        Ok(u16::from_le_bytes(b))
    }

    fn write_halfword(&mut self, addr: u32, value: u16) -> std::result::Result<(), MemoryError> {
        self.write(addr, &value.to_le_bytes())
    }

    fn read_byte(&self, addr: u32) -> std::result::Result<u8, MemoryError> {
        let mut b = [0u8; 1];
        self.read(addr, &mut b, MemoryAccessKind::Read)?;
        Ok(b[0])
    }

    fn write_byte(&mut self, addr: u32, value: u8) -> std::result::Result<(), MemoryError> {
        self.write(addr, &[value])
    }
}

/// AArch32 vCPU for embedders that own the whole address space.
pub struct Aarch32Vcpu {
    id: u32,
    cpu: Armv7Cpu,
    bridge: EmbedBridge,
    decoder: Decoder,
    excl: ExclusiveMonitor,
    insn_count: u64,
}

impl Aarch32Vcpu {
    /// Creates a vCPU over `mem` in the ARMv7 reset state (Supervisor mode,
    /// ARM state, MMU off).
    pub fn new(id: u32, mem: Arc<GuestMemoryMmap>) -> Self {
        Aarch32Vcpu {
            id,
            cpu: Armv7Cpu::new(),
            bridge: EmbedBridge {
                mem,
                state: RefCell::new(BridgeState::default()),
            },
            decoder: Decoder::new_aarch32(),
            excl: ExclusiveMonitor::default(),
            insn_count: 0,
        }
    }

    /// Refreshes the bridge's MMU view from CP15 and the current mode.
    fn sync_mmu(&mut self) {
        let cp = &self.cpu.cp15;
        let mut state = self.bridge.state.borrow_mut();
        state.mmu = V6MmuConfig {
            enabled: cp.sctlr.m(),
            ttbr0: cp.ttbr0 as u32,
            ttbr1: cp.ttbr1 as u32,
            ttbcr_n: cp.ttbcr & 0x7,
            dacr: cp.dacr,
            afe: false,
        };
        state.privileged = self.cpu.cpsr.mode != ProcessorMode::User as u8;
        state.fault = None;
    }

    /// The fault the bridge recorded for a failed access, or a generic one
    /// at `addr` when the executor reported a failure the bridge did not see
    /// (for example an alignment check).
    fn take_fault(&mut self, addr: u32, access: MemoryAccessKind) -> Error {
        let fault = self
            .bridge
            .state
            .borrow_mut()
            .fault
            .take()
            .unwrap_or(GuestMemoryFault {
                address: u64::from(addr),
                size: 0,
                access,
                kind: MemoryFaultKind::Other,
            });
        Error::GuestAccess(fault)
    }

    fn take_exception(&mut self, exception: ExceptionType) {
        let vbar = self.cpu.cp15.sctlr.vector_base();
        let mut exec = Executor::with_vbar(&mut self.cpu, &mut self.bridge, vbar);
        exec.exclusive_monitor = self.excl.clone();
        exec.take_exception(exception);
        self.excl = exec.exclusive_monitor.clone();
    }

    fn undefined(&self, pc: u32, raw: u32) -> Error {
        Error::InvalidInstruction {
            pc: u64::from(pc),
            diagnosis: format!("undefined AArch32 encoding {raw:#x}"),
        }
    }

    /// Executes one instruction.
    fn step_one(&mut self) -> Result<Option<VcpuExit>> {
        if self.cpu.is_halted {
            // WFI/WFE with no interrupt source: stay waiting until woken.
            return Ok(Some(VcpuExit::Hlt));
        }
        self.sync_mmu();
        let pc = self.cpu.regs[15];
        let is_thumb = self.cpu.cpsr.t;

        // Decode bytes stay in memory order: a 32-bit Thumb instruction is
        // hw1 then hw2.
        let mut len = 4u32;
        let mut bytes = [0u8; 4];
        let raw = if is_thumb {
            let hw1 = self
                .bridge
                .fetch_halfword(pc)
                .map_err(|_| self.take_fault(pc, MemoryAccessKind::Fetch))?;
            bytes[..2].copy_from_slice(&hw1.to_le_bytes());
            if (hw1 >> 11) >= 0x1D {
                let hw2 = self
                    .bridge
                    .fetch_halfword(pc.wrapping_add(2))
                    .map_err(|_| self.take_fault(pc.wrapping_add(2), MemoryAccessKind::Fetch))?;
                bytes[2..].copy_from_slice(&hw2.to_le_bytes());
                (u32::from(hw1) << 16) | u32::from(hw2)
            } else {
                len = 2;
                u32::from(hw1)
            }
        } else {
            let word = self
                .bridge
                .fetch_word(pc)
                .map_err(|_| self.take_fault(pc, MemoryAccessKind::Fetch))?;
            bytes = word.to_le_bytes();
            word
        };

        self.decoder.set_state(if is_thumb {
            ExecutionState::Thumb
        } else {
            ExecutionState::Aarch32
        });
        let insn = self
            .decoder
            .decode(&bytes[..len as usize])
            .map_err(|_| self.undefined(pc, raw))?;

        let vbar = self.cpu.cp15.sctlr.vector_base();
        let advance_it = is_thumb && self.cpu.cpsr.in_it_block();
        let snapshot = (self.cpu.regs, self.cpu.cpsr.clone());
        let result = {
            let mut exec = Executor::with_vbar(&mut self.cpu, &mut self.bridge, vbar);
            // The exclusive monitor survives across instructions (the
            // executor is rebuilt for each one).
            exec.exclusive_monitor = self.excl.clone();
            let result = exec.execute(&insn);
            self.excl = exec.exclusive_monitor.clone();
            result
        };

        let retired = match result {
            ExecResult::Continue => {
                self.cpu.regs[15] = pc.wrapping_add(len);
                if advance_it {
                    self.cpu.cpsr.advance_it_state();
                }
                None
            }
            ExecResult::Branch(target) => {
                if insn.mnemonic == Mnemonic::RFE {
                    // RFE restored CPSR, including T, itself.
                    self.cpu.regs[15] = target & !1;
                } else if target & 1 != 0 {
                    self.cpu.cpsr.t = true;
                    self.cpu.regs[15] = target & !1;
                } else {
                    self.cpu.regs[15] = target;
                }
                if advance_it {
                    self.cpu.cpsr.advance_it_state();
                }
                None
            }
            ExecResult::Halt => {
                self.cpu.regs[15] = pc.wrapping_add(len);
                if advance_it {
                    self.cpu.cpsr.advance_it_state();
                }
                self.cpu.is_halted = true;
                Some(VcpuExit::Hlt)
            }
            ExecResult::Exception(ExceptionType::UndefinedInstruction) | ExecResult::Undefined => {
                (self.cpu.regs, self.cpu.cpsr) = snapshot;
                return Err(self.undefined(pc, raw));
            }
            ExecResult::Exception(exception) => {
                // PC still addresses the instruction; the exception entry
                // computes the return address from it.
                self.take_exception(exception);
                None
            }
            ExecResult::MemoryFault(_) => {
                // The access failed before the instruction retired.
                (self.cpu.regs, self.cpu.cpsr) = snapshot;
                self.cpu.regs[15] = pc;
                return Err(self.take_fault(pc, MemoryAccessKind::Read));
            }
        };
        self.insn_count += 1;
        Ok(retired)
    }
}

impl VCpu for Aarch32Vcpu {
    fn run(&mut self) -> Result<VcpuExit> {
        loop {
            if let Some(exit) = self.step_one()? {
                return Ok(exit);
            }
        }
    }

    fn step_insn(&mut self) -> Result<Option<VcpuExit>> {
        self.step_one()
    }

    fn supports_stepping(&self) -> bool {
        true
    }

    fn current_pc(&self) -> u64 {
        u64::from(self.cpu.regs[15])
    }

    fn set_current_pc(&mut self, pc: u64) -> Result<()> {
        self.cpu.regs[15] = pc as u32;
        Ok(())
    }

    fn wake(&mut self) {
        self.cpu.is_halted = false;
    }

    fn translate_addr(&mut self, vaddr: u64, access: MemAccess) -> Result<u64> {
        self.sync_mmu();
        let access = match access {
            MemAccess::Read => MemoryAccessKind::Read,
            MemAccess::Write => MemoryAccessKind::Write,
            MemAccess::Exec => MemoryAccessKind::Fetch,
        };
        let va = u32::try_from(vaddr)
            .map_err(|_| Error::GuestAccess(GuestMemoryFault::unmapped(vaddr, 0, access)))?;
        match self.bridge.translate(va, access) {
            Ok(pa) => Ok(u64::from(pa)),
            Err(_) => Err(self.take_fault(va, access)),
        }
    }

    fn get_state(&self) -> Result<CpuState> {
        let mut regs = Aarch32Registers::default();
        regs.r.copy_from_slice(&self.cpu.regs[..13]);
        regs.sp = self.cpu.regs[13];
        regs.lr = self.cpu.regs[14];
        regs.pc = self.cpu.regs[15];
        regs.cpsr = self.cpu.cpsr.to_u32();
        regs.spsr = self.cpu.get_current_spsr().map_or(0, |spsr| spsr.to_u32());
        let vfp = &self.cpu.vfp;
        regs.fpscr = vfp.fpscr.bits();
        for i in 0..32 {
            regs.s[i] = vfp.read_s_bits(i as u8);
        }
        for i in 0..16 {
            regs.d_high[i] = vfp.read_d_bits((16 + i) as u8);
        }
        let cp = &self.cpu.cp15;
        let sregs = Aarch32SystemRegisters {
            sctlr: cp.sctlr.bits(),
            ttbr0: cp.ttbr0 as u32,
            ttbr1: cp.ttbr1 as u32,
            ttbcr: cp.ttbcr,
            dacr: cp.dacr,
            dfsr: cp.dfsr,
            ifsr: cp.ifsr,
            dfar: cp.dfar,
            ifar: cp.ifar,
            // The exception base follows SCTLR.V; there is no separate VBAR.
            vbar: cp.sctlr.vector_base(),
            contextidr: cp.contextidr,
            ..Default::default()
        };
        Ok(CpuState::Aarch32(Aarch32CpuState { regs, sregs }))
    }

    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        let CpuState::Aarch32(state) = state else {
            return Err(Error::Emulator(
                "expected aarch32 state for aarch32 vCPU".to_string(),
            ));
        };
        // Apply the mode first so the banked SP/LR/SPSR land in it.
        let cpsr = Psr::from_u32(state.regs.cpsr);
        if let Some(mode) = ProcessorMode::from_bits(cpsr.mode) {
            self.cpu.change_mode(mode);
        }
        self.cpu.cpsr = cpsr;
        self.cpu.regs[..13].copy_from_slice(&state.regs.r);
        self.cpu.regs[13] = state.regs.sp;
        self.cpu.regs[14] = state.regs.lr;
        self.cpu.regs[15] = state.regs.pc;
        if let Some(spsr) = self.cpu.get_current_spsr_mut() {
            *spsr = Psr::from_u32(state.regs.spsr);
        }
        self.cpu.vfp.fpscr = Fpscr::from_bits(state.regs.fpscr);
        for i in 0..32 {
            self.cpu.vfp.write_s_bits(i as u8, state.regs.s[i]);
        }
        for i in 0..16 {
            self.cpu
                .vfp
                .write_d_bits((16 + i) as u8, state.regs.d_high[i]);
        }
        let s = &state.sregs;
        let cp = &mut self.cpu.cp15;
        cp.sctlr = crate::isa::arm::cp15::Sctlr::from_bits(s.sctlr);
        cp.ttbr0 = u64::from(s.ttbr0);
        cp.ttbr1 = u64::from(s.ttbr1);
        cp.ttbcr = s.ttbcr;
        cp.dacr = s.dacr;
        cp.dfsr = s.dfsr;
        cp.ifsr = s.ifsr;
        cp.dfar = s.dfar;
        cp.ifar = s.ifar;
        cp.contextidr = s.contextidr;
        Ok(())
    }

    fn complete_io_in(&mut self, _data: &[u8]) {}

    fn id(&self) -> u32 {
        self.id
    }

    fn instruction_count(&self) -> u64 {
        self.insn_count
    }
}

#[cfg(test)]
#[path = "aarch32_tests.rs"]
mod tests;
