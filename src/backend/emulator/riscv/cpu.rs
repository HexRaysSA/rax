//! RISC-V vCPU: drives the [`crate::isa::riscv::RiscVCpu`] interpreter over guest
//! memory and maps its exits onto [`VcpuExit`].
//!
//! Guest memory is bridged through [`GuestBridge`], a [`Memory`] implementation
//! over the VMM's [`GuestMemoryMmap`]. Accesses to the 16550 UART window are
//! intercepted: status-register reads are serviced synchronously (the
//! transmitter is always ready), and THR writes are buffered into a shared sink
//! that the run loop drains into a [`VcpuExit::MmioWrite`] so the VMM's serial
//! device produces console output. (The library interpreter executes one whole
//! instruction per step and cannot suspend mid-instruction, so MMIO *writes* are
//! surfaced after the step rather than during it.)
//!
//! [`RiscVVcpu::new_user`] builds a process-level (user-mode) hart for
//! embedders that implement the operating system themselves: it runs in
//! U-mode without device windows, translates every access through a
//! [`FlatTranslation`] that enforces page permissions, and reports `ECALL` as
//! [`VcpuExit::SystemCall`] and other synchronous exceptions as
//! [`Error::GuestEvent`] instead of entering the M-mode trap vector (see
//! [`RvUserTrap`]).

use std::sync::{Arc, Mutex};

use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use crate::error::{Error, GuestMemoryFault, MemoryAccessKind, Result};
use crate::isa::riscv::cpu::{Priv, cause};
use crate::isa::riscv::{MemError, MemResult, Memory, RiscVConfig, RiscVCpu, RiscVExit};
use crate::vm::memory::FlatTranslation;
use crate::vm::vcpu::{CpuState, MemAccess, RiscVRegisters, VCpu, VcpuExit};

/// 16550 UART MMIO base/length (matches `RiscvVirtMachine::serial_mmio_base`).
const UART_BASE: u64 = 0x1000_0000;
const UART_LEN: u64 = 8;
/// 16550 Line Status Register offset and the "ready to transmit" bits.
const LSR_OFFSET: u64 = 5;
const LSR_THRE_TEMT: u8 = 0x60;
/// Bound on instructions executed per `run()` call (keeps the loop responsive).
const MAX_ITERS: u64 = 2_000_000;

/// A pending MMIO write surfaced to the run loop.
type MmioSink = Arc<Mutex<Option<(u64, Vec<u8>)>>>;
/// A pending guest-requested exit surfaced to the run loop.
type ExitSink = Arc<Mutex<Option<VcpuExit>>>;

/// Guest memory bridge: RAM via [`GuestMemoryMmap`], with the UART window
/// intercepted.
struct GuestBridge {
    mem: Arc<GuestMemoryMmap>,
    pending: MmioSink,
    pending_exit: ExitSink,
    tohost_addr: Arc<Mutex<Option<u64>>>,
    /// The bare-metal machine's UART window and HTIF `tohost` port. An
    /// embedder that owns the whole address space ([`RiscVVcpu::new_embedded`])
    /// sees ordinary guest memory there instead.
    devices_enabled: bool,
}

impl std::fmt::Debug for GuestBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestBridge").finish()
    }
}

#[inline]
fn in_uart(addr: u64) -> bool {
    addr >= UART_BASE && addr < UART_BASE + UART_LEN
}

/// [`Memory`] for a user-mode hart: every access is translated and
/// permission-checked one 4 KiB page at a time, and the precise first
/// inaccessible byte of a failed access is recorded for the vCPU.
struct UserBridge {
    mem: Arc<GuestMemoryMmap>,
    translation: Arc<dyn FlatTranslation>,
    last_fault: Arc<Mutex<Option<GuestMemoryFault>>>,
}

impl std::fmt::Debug for UserBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserBridge").finish()
    }
}

impl UserBridge {
    fn fail(&self, fault: GuestMemoryFault, size: usize) -> MemError {
        *self.last_fault.lock().unwrap() = Some(fault);
        MemError::OutOfBounds {
            addr: fault.address,
            size,
        }
    }

    /// Translates each page of `[addr, addr + len)` and calls `f` with its
    /// guest-memory address and byte range within the access.
    fn pages(
        &self,
        addr: u64,
        len: usize,
        access: MemoryAccessKind,
        mut f: impl FnMut(u64, std::ops::Range<usize>) -> MemResult<()>,
    ) -> MemResult<()> {
        let mut done = 0usize;
        while done < len {
            let linear = addr.wrapping_add(done as u64);
            let chunk = ((0x1000 - (linear & 0xFFF)) as usize).min(len - done);
            let target = self
                .translation
                .translate(linear, access)
                .map_err(|fault| self.fail(fault, len - done))?;
            f(target, done..done + chunk)?;
            done += chunk;
        }
        Ok(())
    }

    fn load(&self, addr: u64, buf: &mut [u8], access: MemoryAccessKind) -> MemResult<()> {
        let len = buf.len();
        self.pages(addr, len, access, |target, range| {
            self.mem
                .read_slice(&mut buf[range.clone()], GuestAddress(target))
                .map_err(|_| {
                    self.fail(
                        GuestMemoryFault::unmapped(target, range.end - range.start, access),
                        len - range.start,
                    )
                })
        })
    }
}

impl Memory for UserBridge {
    fn probe(&self, addr: u64, size: usize, write: bool) -> MemResult<()> {
        let access = if write {
            MemoryAccessKind::Write
        } else {
            MemoryAccessKind::Read
        };
        self.pages(addr, size, access, |target, range| {
            if self
                .mem
                .check_range(GuestAddress(target), range.end - range.start)
            {
                Ok(())
            } else {
                Err(self.fail(
                    GuestMemoryFault::unmapped(target, range.end - range.start, access),
                    size - range.start,
                ))
            }
        })
    }

    fn read(&self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        self.load(addr, buf, MemoryAccessKind::Read)
    }

    fn write(&mut self, addr: u64, data: &[u8]) -> MemResult<()> {
        // A store that faults on a later page publishes nothing.
        self.probe(addr, data.len(), true)?;
        let len = data.len();
        self.pages(addr, len, MemoryAccessKind::Write, |target, range| {
            self.mem
                .write_slice(&data[range.clone()], GuestAddress(target))
                .map_err(|_| {
                    self.fail(
                        GuestMemoryFault::unmapped(
                            target,
                            range.end - range.start,
                            MemoryAccessKind::Write,
                        ),
                        len - range.start,
                    )
                })
        })
    }

    fn fetch_u16(&self, addr: u64) -> MemResult<u16> {
        let mut parcel = [0u8; 2];
        self.load(addr, &mut parcel, MemoryAccessKind::Fetch)?;
        Ok(u16::from_le_bytes(parcel))
    }
}

/// A U-mode event a user-mode hart ([`RiscVVcpu::new_user`]) reported to its
/// embedder instead of entering the M-mode trap vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RvUserTrap {
    /// `ECALL` at `pc`. The vCPU completed it for the embedder: the PC is
    /// `pc + 4`, where the supervisor's `sret` would resume.
    Ecall { pc: u64 },
    /// A synchronous exception raised by the instruction at `pc`, which did
    /// not retire: the PC is `pc`. `cause` and `tval` are the `mcause` and
    /// `mtval` values the trap would have written (for example
    /// [`cause::BREAKPOINT`] or [`cause::ILLEGAL_INSTR`]).
    Exception { cause: u64, tval: u64, pc: u64 },
}

/// Per-vCPU user-mode state.
struct RvUser {
    translation: Arc<dyn FlatTranslation>,
    last_fault: Arc<Mutex<Option<GuestMemoryFault>>>,
    trap: Option<RvUserTrap>,
    /// `ECALL`s completed for the embedder. The hart does not retire an
    /// exception-raising instruction, but the embedder-visible instruction
    /// count includes each completed system call.
    ecalls: u64,
}

impl GuestBridge {
    #[inline]
    fn is_uart(&self, addr: u64) -> bool {
        self.devices_enabled && in_uart(addr)
    }
}

impl Memory for GuestBridge {
    fn probe(&self, addr: u64, size: usize, _write: bool) -> MemResult<()> {
        if self.is_uart(addr) || self.mem.check_range(GuestAddress(addr), size) {
            Ok(())
        } else {
            Err(MemError::OutOfBounds { addr, size })
        }
    }

    fn read(&self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        if self.is_uart(addr) {
            for (i, b) in buf.iter_mut().enumerate() {
                let off = (addr + i as u64) - UART_BASE;
                *b = if off == LSR_OFFSET { LSR_THRE_TEMT } else { 0 };
            }
            return Ok(());
        }
        self.mem
            .read_slice(buf, GuestAddress(addr))
            .map_err(|_| MemError::OutOfBounds {
                addr,
                size: buf.len(),
            })
    }

    fn write(&mut self, addr: u64, data: &[u8]) -> MemResult<()> {
        if self.is_uart(addr) {
            *self.pending.lock().unwrap() = Some((addr, data.to_vec()));
            return Ok(());
        }
        if self.devices_enabled && *self.tohost_addr.lock().unwrap() == Some(addr) {
            let mut raw = [0u8; 8];
            let len = data.len().min(raw.len());
            raw[..len].copy_from_slice(&data[..len]);
            let value = u64::from_le_bytes(raw);
            if value == 1 {
                *self.pending_exit.lock().unwrap() = Some(VcpuExit::Shutdown);
            } else if value & 1 == 1 {
                *self.pending_exit.lock().unwrap() = Some(VcpuExit::Unknown(format!(
                    "riscv tohost failure: value={value:#x} test={}",
                    value >> 1
                )));
            } else if value != 0 {
                *self.pending_exit.lock().unwrap() = Some(VcpuExit::Unknown(format!(
                    "unsupported riscv tohost value: {value:#x}"
                )));
            }
        }
        self.mem
            .write_slice(data, GuestAddress(addr))
            .map_err(|_| MemError::OutOfBounds {
                addr,
                size: data.len(),
            })
    }
}

/// RISC-V vCPU backed by the software interpreter.
pub struct RiscVVcpu {
    id: u32,
    cpu: RiscVCpu,
    pending: MmioSink,
    pending_exit: ExitSink,
    tohost_addr: Arc<Mutex<Option<u64>>>,
    halted: bool,
    /// Process-level execution in U-mode ([`RiscVVcpu::new_user`]).
    user: Option<RvUser>,
}

impl RiscVVcpu {
    pub fn new(id: u32, mem: Arc<GuestMemoryMmap>) -> Self {
        Self::new_with_config(id, mem, RiscVConfig::rv64gc())
    }

    pub fn new_with_config(id: u32, mem: Arc<GuestMemoryMmap>, cfg: RiscVConfig) -> Self {
        Self::build(id, mem, cfg, true)
    }

    /// Instruction-level hart for embedders that own the complete address
    /// space: every address is guest memory (no UART window or HTIF `tohost`
    /// port). Execution otherwise matches [`RiscVVcpu::new_with_config`].
    pub fn new_embedded(id: u32, mem: Arc<GuestMemoryMmap>, cfg: RiscVConfig) -> Self {
        Self::build(id, mem, cfg, false)
    }

    fn build(id: u32, mem: Arc<GuestMemoryMmap>, cfg: RiscVConfig, devices_enabled: bool) -> Self {
        let pending: MmioSink = Arc::new(Mutex::new(None));
        let pending_exit: ExitSink = Arc::new(Mutex::new(None));
        let tohost_addr = Arc::new(Mutex::new(None));
        let bridge = GuestBridge {
            mem,
            pending: pending.clone(),
            pending_exit: pending_exit.clone(),
            tohost_addr: tohost_addr.clone(),
            devices_enabled,
        };
        let cpu = RiscVCpu::new(cfg, Box::new(bridge));
        RiscVVcpu {
            id,
            cpu,
            pending,
            pending_exit,
            tohost_addr,
            halted: false,
            user: None,
        }
    }

    /// Process-level (user-mode) hart: it executes in U-mode, and every load,
    /// store, and instruction fetch is translated and permission-checked by
    /// `translation`, whose results index `mem`. There is no UART window and
    /// no HTIF `tohost` handling. `ECALL` returns [`VcpuExit::SystemCall`]
    /// with the PC past it; `EBREAK`, illegal instructions, and misaligned
    /// accesses return [`Error::GuestEvent`] without retiring; a translation
    /// fault returns [`Error::GuestAccess`] with the first inaccessible byte.
    /// Each (except the memory fault) records an [`RvUserTrap`] for
    /// [`RiscVVcpu::take_user_trap`]. The counter CSRs keep their reset
    /// `mcounteren` of zero, so U-mode reads of `cycle`, `time`, and
    /// `instret` raise an illegal-instruction exception.
    pub fn new_user(
        id: u32,
        mem: Arc<GuestMemoryMmap>,
        cfg: RiscVConfig,
        translation: Arc<dyn FlatTranslation>,
    ) -> Self {
        let last_fault = Arc::new(Mutex::new(None));
        let bridge = UserBridge {
            mem,
            translation: translation.clone(),
            last_fault: last_fault.clone(),
        };
        let mut cpu = RiscVCpu::new(cfg, Box::new(bridge));
        cpu.set_privilege(Priv::User);
        RiscVVcpu {
            id,
            cpu,
            pending: Arc::new(Mutex::new(None)),
            pending_exit: Arc::new(Mutex::new(None)),
            tohost_addr: Arc::new(Mutex::new(None)),
            halted: false,
            user: Some(RvUser {
                translation,
                last_fault,
                trap: None,
                ecalls: 0,
            }),
        }
    }

    /// Whether this hart executes in U-mode for a user-mode embedder.
    pub fn user_mode_enabled(&self) -> bool {
        self.user.is_some()
    }

    /// Removes and returns the event that ended the last user-mode step.
    pub fn take_user_trap(&mut self) -> Option<RvUserTrap> {
        self.user.as_mut().and_then(|user| user.trap.take())
    }

    /// Executes one U-mode instruction for a user-mode embedder.
    fn step_user(&mut self) -> Result<Option<VcpuExit>> {
        let Some(user) = self.user.as_mut() else {
            return Err(Error::Emulator(
                "RISC-V user-mode step on a system vCPU".to_string(),
            ));
        };
        *user.last_fault.lock().unwrap() = None;
        let pc = self.cpu.pc();
        let exit = self.cpu.step();
        match exit {
            RiscVExit::Continue | RiscVExit::Wfi => Ok(None),
            RiscVExit::Ecall => {
                // The supervisor's return from the call resumes after it.
                self.cpu.set_pc(pc.wrapping_add(4));
                self.cpu.clear_reservation();
                user.ecalls = user.ecalls.wrapping_add(1);
                user.trap = Some(RvUserTrap::Ecall { pc });
                Ok(Some(VcpuExit::SystemCall))
            }
            RiscVExit::Ebreak => {
                self.cpu.clear_reservation();
                user.trap = Some(RvUserTrap::Exception {
                    cause: cause::BREAKPOINT,
                    tval: pc,
                    pc,
                });
                Err(Error::GuestEvent {
                    vector: cause::BREAKPOINT as u8,
                })
            }
            RiscVExit::Trap(trap) => {
                // Undo the M-mode trap entry: the embedder is the supervisor.
                let epc = self.cpu.csr_read(0x341).unwrap_or(pc);
                self.cpu.set_privilege(Priv::User);
                self.cpu.set_pc(epc);
                self.cpu.clear_reservation();
                let recorded = user.last_fault.lock().unwrap().take();
                match trap.cause {
                    cause::INSTR_ACCESS_FAULT
                    | cause::LOAD_ACCESS_FAULT
                    | cause::STORE_ACCESS_FAULT => {
                        let access = match trap.cause {
                            cause::INSTR_ACCESS_FAULT => MemoryAccessKind::Fetch,
                            cause::LOAD_ACCESS_FAULT => MemoryAccessKind::Read,
                            _ => MemoryAccessKind::Write,
                        };
                        // A fault the translation did not see (an address
                        // beyond XLEN masking) reports the trap value.
                        let fault = recorded
                            .unwrap_or_else(|| GuestMemoryFault::unmapped(trap.tval, 0, access));
                        Err(Error::GuestAccess(fault))
                    }
                    other => {
                        user.trap = Some(RvUserTrap::Exception {
                            cause: other,
                            tval: trap.tval,
                            pc: epc,
                        });
                        Err(Error::GuestEvent {
                            vector: other.min(u64::from(u8::MAX)) as u8,
                        })
                    }
                }
            }
        }
    }
}

impl VCpu for RiscVVcpu {
    fn run(&mut self) -> Result<VcpuExit> {
        if self.user.is_some() {
            for _ in 0..MAX_ITERS {
                if let Some(exit) = self.step_user()? {
                    return Ok(exit);
                }
            }
            // The end of a batch; WFI completes as a hint in user mode, so
            // `Hlt` here never reports a halted hart.
            return Ok(VcpuExit::Hlt);
        }
        if self.halted {
            return Ok(VcpuExit::Hlt);
        }
        for _ in 0..MAX_ITERS {
            let exit = self.cpu.step();
            if let Some(exit) = self.pending_exit.lock().unwrap().take() {
                self.halted = matches!(exit, VcpuExit::Shutdown);
                return Ok(exit);
            }
            // Surface any UART output produced by this instruction first.
            if let Some((addr, data)) = self.pending.lock().unwrap().take() {
                return Ok(VcpuExit::MmioWrite { addr, data });
            }
            match exit {
                RiscVExit::Continue => {}
                RiscVExit::Ecall => {
                    let syscall = self.cpu.x(17);
                    let code = self.cpu.x(10);
                    self.halted = true;
                    if syscall == 93 && code != 0 {
                        return Ok(VcpuExit::Unknown(format!(
                            "riscv ecall failure: code={code:#x}"
                        )));
                    }
                    return Ok(VcpuExit::Shutdown);
                }
                RiscVExit::Ebreak => {
                    self.halted = true;
                    return Ok(VcpuExit::Debug);
                }
                RiscVExit::Wfi => {}
                RiscVExit::Trap(t) => {
                    self.halted = true;
                    return Ok(VcpuExit::Unknown(format!(
                        "riscv trap: cause={} tval={:#x} pc={:#x}",
                        t.cause,
                        t.tval,
                        self.cpu.pc()
                    )));
                }
            }
        }
        Ok(VcpuExit::Hlt)
    }

    fn get_state(&self) -> Result<CpuState> {
        let mut regs = RiscVRegisters::default();
        for i in 0..32u8 {
            regs.x[i as usize] = self.cpu.x(i);
            regs.f[i as usize] = self.cpu.f(i);
        }
        regs.pc = self.cpu.pc();
        regs.fcsr = self.cpu.fcsr();
        regs.tohost_addr = *self.tohost_addr.lock().unwrap();
        regs.privilege = Some(self.cpu.privilege() as u8);
        regs.csrs = self.cpu.export_csrs();
        regs.vector = self.cpu.export_vector();
        Ok(CpuState::riscv(regs))
    }

    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        let state = match state {
            CpuState::RiscV(s) => s,
            _ => {
                return Err(Error::Emulator(
                    "expected riscv state for riscv vCPU".to_string(),
                ));
            }
        };
        for i in 0..32u8 {
            self.cpu.set_x(i, state.regs.x[i as usize]);
            self.cpu.set_f(i, state.regs.f[i as usize]);
        }
        self.cpu.set_pc(state.regs.pc);
        self.cpu.set_fcsr(state.regs.fcsr);
        *self.tohost_addr.lock().unwrap() = state.regs.tohost_addr;
        if let Some(level) = state.regs.privilege {
            let privilege = RiscVCpu::privilege_from_level(level).ok_or_else(|| {
                Error::Emulator(format!("invalid RISC-V privilege level {level}"))
            })?;
            // A user-mode hart stays in U-mode.
            if self.user.is_none() {
                self.cpu.set_privilege(privilege);
            }
        }
        self.cpu.import_csrs(&state.regs.csrs);
        if let Some(vector) = &state.regs.vector {
            self.cpu.import_vector(vector).map_err(Error::Emulator)?;
        }
        self.halted = false;
        if let Some(user) = self.user.as_mut() {
            user.trap = None;
        }
        Ok(())
    }

    fn complete_io_in(&mut self, _data: &[u8]) {
        // UART reads are serviced synchronously inside the bridge; no resume
        // state is pending.
    }

    fn id(&self) -> u32 {
        self.id
    }

    fn instruction_count(&self) -> u64 {
        let ecalls = self.user.as_ref().map_or(0, |user| user.ecalls);
        self.cpu.instret().wrapping_add(ecalls)
    }

    fn supports_stepping(&self) -> bool {
        true
    }

    fn current_pc(&self) -> u64 {
        self.cpu.pc()
    }

    fn wake(&mut self) {
        self.halted = false;
    }

    fn translate_addr(&mut self, vaddr: u64, access: MemAccess) -> Result<u64> {
        let Some(user) = self.user.as_ref() else {
            return Ok(vaddr);
        };
        let access = match access {
            MemAccess::Read => MemoryAccessKind::Read,
            MemAccess::Write => MemoryAccessKind::Write,
            MemAccess::Exec => MemoryAccessKind::Fetch,
        };
        user.translation
            .translate(vaddr, access)
            .map_err(Error::from)
    }

    fn step_insn(&mut self) -> Result<Option<VcpuExit>> {
        if self.user.is_some() {
            return self.step_user();
        }
        if self.halted {
            return Ok(Some(VcpuExit::Hlt));
        }
        // One iteration of the run() loop body.
        let exit = self.cpu.step();
        if let Some(exit) = self.pending_exit.lock().unwrap().take() {
            self.halted = matches!(exit, VcpuExit::Shutdown);
            return Ok(Some(exit));
        }
        if let Some((addr, data)) = self.pending.lock().unwrap().take() {
            return Ok(Some(VcpuExit::MmioWrite { addr, data }));
        }
        match exit {
            RiscVExit::Continue => Ok(None),
            RiscVExit::Ecall => {
                let syscall = self.cpu.x(17);
                let code = self.cpu.x(10);
                self.halted = true;
                if syscall == 93 && code != 0 {
                    Ok(Some(VcpuExit::Unknown(format!(
                        "riscv ecall failure: code={code:#x}"
                    ))))
                } else {
                    Ok(Some(VcpuExit::Shutdown))
                }
            }
            RiscVExit::Ebreak => {
                self.halted = true;
                Ok(Some(VcpuExit::Debug))
            }
            RiscVExit::Wfi => Ok(None),
            RiscVExit::Trap(t) => {
                self.halted = true;
                Ok(Some(VcpuExit::Unknown(format!(
                    "riscv trap: cause={} tval={:#x} pc={:#x}",
                    t.cause,
                    t.tval,
                    self.cpu.pc()
                ))))
            }
        }
    }
}

#[cfg(test)]
#[path = "cpu_user_tests.rs"]
mod user_tests;

#[cfg(test)]
#[path = "cpu_state_tests.rs"]
mod state_tests;
