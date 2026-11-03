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

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

#[path = "cpu_context.rs"]
mod context;

use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use crate::error::{Error, GuestMemoryFault, MemoryAccessKind, Result};
use crate::isa::riscv::cpu::{Priv, cause};
use crate::isa::riscv::{MemError, MemResult, Memory, RiscVConfig, RiscVCpu, RiscVExit};
use crate::vm::memory::FlatTranslation;
use crate::vm::memory::reservations::{MemoryDomain, Monitor};
#[cfg(test)]
#[path = "cpu_atomic_tests.rs"]
mod atomic_tests;
#[path = "cpu_reservations.rs"]
mod reservations;
use crate::vm::vcpu::{CpuState, MemAccess, VCpu, VcpuExit};
use reservations::overlaps_uart;

/// 16550 UART MMIO base/length (matches `RiscvVirtMachine::serial_mmio_base`).
const UART_BASE: u64 = 0x1000_0000;
const UART_LEN: u64 = 8;
/// 16550 Line Status Register offset and the "ready to transmit" bits.
const LSR_OFFSET: u64 = 5;
const LSR_THRE_TEMT: u8 = 0x60;
/// Bound on instructions executed per `run()` call (keeps the loop responsive).
const MAX_ITERS: u64 = 2_000_000;

/// Events remain ordered across a multi-access instruction and its terminal
/// result. They are drained before the next instruction executes.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
enum PendingEvent {
    MmioWrite { addr: u64, data: Vec<u8> },
    Shutdown,
    Failure { reason: String, halt: bool },
    Debug,
}
type EventSink = Arc<Mutex<VecDeque<PendingEvent>>>;

/// Guest memory bridge: RAM via [`GuestMemoryMmap`], with the UART window
/// intercepted.
struct GuestBridge {
    mem: Arc<GuestMemoryMmap>,
    exclusive: Monitor,
    pending: EventSink,
    tohost_addr: Arc<Mutex<Option<u64>>>,
    /// The bare-metal machine's UART window and HTIF `tohost` port. An
    /// embedder that owns the whole address space ([`RiscVVcpu::new_embedded`])
    /// sees ordinary guest memory there instead.
    devices_enabled: bool,
    platform: Option<Arc<super::platform::Platform>>,
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
    exclusive: Monitor,
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
            self.exclusive
                .read(&self.mem, target, &mut buf[range.clone()])
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
    fn atomic(
        &mut self,
        address: u64,
        size: u8,
        operation: crate::isa::riscv::memory::AtomicOp,
    ) -> MemResult<u128> {
        operation.validate(address, size)?;
        let physical = self.atomic_address(address, usize::from(size))?;
        crate::isa::riscv::memory::shared::atomic(
            &self.mem,
            &self.exclusive,
            physical,
            size,
            operation,
        )
        .map_err(|_| {
            self.fail(
                GuestMemoryFault::unmapped(address, usize::from(size), MemoryAccessKind::Write),
                usize::from(size),
            )
        })
    }

    fn load_reserved(&mut self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        let result = self
            .reserved_address(addr, buf.len(), MemoryAccessKind::Read)
            .and_then(|physical| {
                crate::isa::riscv::memory::shared::load(&self.mem, &self.exclusive, physical, buf)
            });
        if result.is_err() {
            self.exclusive.clear();
        }
        result
    }

    fn store_conditional(&mut self, addr: u64, data: &[u8], eligible: bool) -> MemResult<bool> {
        let result = self
            .reserved_address(addr, data.len(), MemoryAccessKind::Write)
            .and_then(|physical| {
                crate::isa::riscv::memory::shared::store(
                    &self.mem,
                    &self.exclusive,
                    physical,
                    data,
                    eligible,
                )
            });
        if result.is_err() {
            self.exclusive.clear();
        }
        result
    }

    fn clear_reservation(&mut self) {
        self.exclusive.clear();
    }

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
            crate::vm::memory::reservations::write(&self.mem, target, &data[range.clone()]).map_err(
                |_| {
                    self.fail(
                        GuestMemoryFault::unmapped(
                            target,
                            range.end - range.start,
                            MemoryAccessKind::Write,
                        ),
                        len - range.start,
                    )
                },
            )
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

impl GuestBridge {
    fn publish_tohost(&self, addr: u64, data: &[u8]) {
        if self.devices_enabled && *self.tohost_addr.lock().unwrap() == Some(addr) {
            let mut raw = [0u8; 8];
            let len = data.len().min(raw.len());
            raw[..len].copy_from_slice(&data[..len]);
            let value = u64::from_le_bytes(raw);
            let event = if value == 1 {
                Some(PendingEvent::Shutdown)
            } else if value & 1 == 1 {
                Some(PendingEvent::Failure {
                    reason: format!("riscv tohost failure: value={value:#x} test={}", value >> 1),
                    halt: false,
                })
            } else if value != 0 {
                Some(PendingEvent::Failure {
                    reason: format!("unsupported riscv tohost value: {value:#x}"),
                    halt: false,
                })
            } else {
                None
            };
            if let Some(event) = event {
                self.pending.lock().unwrap().push_back(event);
            }
        }
    }
}

impl GuestBridge {
    fn in_platform(&self, address: u64, size: usize) -> bool {
        self.platform
            .as_ref()
            .is_some_and(|platform| platform.claims(address, size))
    }
}
impl Memory for GuestBridge {
    fn atomic(
        &mut self,
        address: u64,
        size: u8,
        operation: crate::isa::riscv::memory::AtomicOp,
    ) -> MemResult<u128> {
        operation.validate(address, size)?;
        if (self.devices_enabled && overlaps_uart(address, usize::from(size)))
            || self.in_platform(address, usize::from(size))
        {
            return Err(MemError::OutOfBounds {
                addr: address,
                size: usize::from(size),
            });
        }
        let old = crate::isa::riscv::memory::shared::atomic(
            &self.mem,
            &self.exclusive,
            address,
            size,
            operation,
        )?;
        if let Some(new) = operation.replacement(old, size) {
            // The event describes this committed transaction, outside RAM locks.
            self.publish_tohost(address, &new.to_le_bytes()[..usize::from(size)]);
        }
        Ok(old)
    }

    fn load_reserved(&mut self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        if (self.devices_enabled && overlaps_uart(addr, buf.len()))
            || self.in_platform(addr, buf.len())
        {
            self.exclusive.clear();
            return Err(MemError::OutOfBounds {
                addr,
                size: buf.len(),
            });
        }
        crate::isa::riscv::memory::shared::load(&self.mem, &self.exclusive, addr, buf)
    }

    fn store_conditional(&mut self, addr: u64, data: &[u8], eligible: bool) -> MemResult<bool> {
        if (self.devices_enabled && overlaps_uart(addr, data.len()))
            || self.in_platform(addr, data.len())
        {
            self.exclusive.clear();
            return Err(MemError::OutOfBounds {
                addr,
                size: data.len(),
            });
        }
        let stored = crate::isa::riscv::memory::shared::store(
            &self.mem,
            &self.exclusive,
            addr,
            data,
            eligible,
        )?;
        if stored {
            self.publish_tohost(addr, data);
        }
        Ok(stored)
    }

    fn clear_reservation(&mut self) {
        self.exclusive.clear();
    }

    fn probe(&self, addr: u64, size: usize, _write: bool) -> MemResult<()> {
        if self.in_platform(addr, size) {
            return self
                .platform
                .as_ref()
                .ok_or(MemError::OutOfBounds { addr, size })?
                .probe(addr, size);
        }
        if self.is_uart(addr) || self.mem.check_range(GuestAddress(addr), size) {
            Ok(())
        } else {
            Err(MemError::OutOfBounds { addr, size })
        }
    }

    fn read(&self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        if self.in_platform(addr, buf.len()) {
            return self
                .platform
                .as_ref()
                .ok_or(MemError::OutOfBounds {
                    addr,
                    size: buf.len(),
                })?
                .read(addr, buf);
        }
        if self.is_uart(addr) {
            for (i, b) in buf.iter_mut().enumerate() {
                let off = (addr + i as u64) - UART_BASE;
                *b = if off == LSR_OFFSET { LSR_THRE_TEMT } else { 0 };
            }
            return Ok(());
        }
        self.exclusive
            .read(&self.mem, addr, buf)
            .map_err(|_| MemError::OutOfBounds {
                addr,
                size: buf.len(),
            })
    }

    fn write(&mut self, addr: u64, data: &[u8]) -> MemResult<()> {
        if self.in_platform(addr, data.len()) {
            return self
                .platform
                .as_ref()
                .ok_or(MemError::OutOfBounds {
                    addr,
                    size: data.len(),
                })?
                .write(addr, data);
        }
        if self.is_uart(addr) {
            self.pending
                .lock()
                .unwrap()
                .push_back(PendingEvent::MmioWrite {
                    addr,
                    data: data.to_vec(),
                });
            return Ok(());
        }
        crate::vm::memory::reservations::write(&self.mem, addr, data).map_err(|_| {
            MemError::OutOfBounds {
                addr,
                size: data.len(),
            }
        })?;
        self.publish_tohost(addr, data);
        Ok(())
    }
}

/// RISC-V vCPU backed by the software interpreter.
pub struct RiscVVcpu {
    id: u32,
    cpu: RiscVCpu,
    pending: EventSink,
    tohost_addr: Arc<Mutex<Option<u64>>>,
    halted: bool,
    devices_enabled: bool,
    platform: Option<Arc<super::platform::Platform>>,
    /// Process-level execution in U-mode ([`RiscVVcpu::new_user`]).
    user: Option<RvUser>,
    physical_memory: Arc<GuestMemoryMmap>,
    exclusive: Monitor,
    checkpoint_activation: Option<context::PendingActivation>,
}

impl RiscVVcpu {
    fn apply_public_state(&mut self, state: &CpuState) -> Result<()> {
        self.validate_checkpoint_state(state, &Default::default())?;

        let state = match state {
            CpuState::RiscV(s) => s,
            _ => {
                return Err(Error::Emulator(
                    "expected riscv state for riscv vCPU".to_string(),
                ));
            }
        };
        let mut tohost = self.tohost_addr.lock().map_err(|_| {
            Error::Emulator("RISC-V tohost lock poisoned during restore".to_string())
        })?;
        for i in 0..32u8 {
            self.cpu.set_x(i, state.regs.x[i as usize]);
            self.cpu.set_f(i, state.regs.f[i as usize]);
        }
        self.cpu.set_pc(state.regs.pc);
        self.cpu.set_fcsr(state.regs.fcsr);
        *tohost = state.regs.tohost_addr;
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
        Ok(())
    }
}

impl RiscVVcpu {
    pub fn new(id: u32, mem: Arc<GuestMemoryMmap>) -> Self {
        Self::new_with_config(id, mem, RiscVConfig::rv64gc())
    }

    pub fn new_with_config(id: u32, mem: Arc<GuestMemoryMmap>, cfg: RiscVConfig) -> Self {
        Self::build(id, mem, cfg, true, None)
    }

    /// Instruction-level hart for embedders that own the complete address
    /// space: every address is guest memory (no UART window or HTIF `tohost`
    /// port). Execution otherwise matches [`RiscVVcpu::new_with_config`].
    pub fn new_embedded(id: u32, mem: Arc<GuestMemoryMmap>, cfg: RiscVConfig) -> Self {
        Self::build(id, mem, cfg, false, None)
    }

    pub(crate) fn new_in_platform(
        id: u32,
        mem: Arc<GuestMemoryMmap>,
        cfg: RiscVConfig,
        platform: Arc<super::platform::Platform>,
    ) -> Result<Self> {
        if cfg.xlen != crate::isa::riscv::Xlen::Rv64 || !platform.contains_hart(id) {
            return Err(Error::InvalidConfig(
                "RISC-V hart outside configured topology".into(),
            ));
        }
        Ok(Self::build(id, mem, cfg, true, Some(platform)))
    }

    fn build(
        id: u32,
        mem: Arc<GuestMemoryMmap>,
        cfg: RiscVConfig,
        devices_enabled: bool,
        platform: Option<Arc<super::platform::Platform>>,
    ) -> Self {
        let pending: EventSink = Arc::new(Mutex::new(VecDeque::new()));
        let tohost_addr = Arc::new(Mutex::new(None));
        let exclusive = MemoryDomain::for_memory(&mem).register();
        let bridge = GuestBridge {
            mem: mem.clone(),
            exclusive: exclusive.clone(),
            pending: pending.clone(),
            tohost_addr: tohost_addr.clone(),
            devices_enabled,
            platform: platform.clone(),
        };
        let cpu = RiscVCpu::new_with_hart_id(cfg, Box::new(bridge), u64::from(id));
        RiscVVcpu {
            id,
            cpu,
            pending,
            tohost_addr,
            halted: false,
            devices_enabled,
            platform,
            user: None,
            physical_memory: mem,
            exclusive,
            checkpoint_activation: None,
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
        let exclusive = MemoryDomain::for_memory(&mem).register();
        let bridge = UserBridge {
            mem: mem.clone(),
            exclusive: exclusive.clone(),
            translation: translation.clone(),
            last_fault: last_fault.clone(),
        };
        let mut cpu = RiscVCpu::new_with_hart_id(cfg, Box::new(bridge), u64::from(id));
        cpu.set_privilege(Priv::User);
        RiscVVcpu {
            id,
            cpu,
            pending: Arc::new(Mutex::new(VecDeque::new())),
            tohost_addr: Arc::new(Mutex::new(None)),
            halted: false,
            devices_enabled: false,
            platform: None,
            physical_memory: mem,
            exclusive,
            checkpoint_activation: None,
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
    fn pop_event(&mut self) -> Result<Option<VcpuExit>> {
        let event = self
            .pending
            .lock()
            .map_err(|_| Error::Emulator("RISC-V event queue poisoned".into()))?
            .pop_front();
        Ok(event.map(|event| match event {
            PendingEvent::MmioWrite { addr, data } => VcpuExit::MmioWrite { addr, data },
            PendingEvent::Shutdown => {
                self.halted = true;
                VcpuExit::Shutdown
            }
            PendingEvent::Failure { reason, halt } => {
                self.halted = halt;
                VcpuExit::Unknown(reason)
            }
            PendingEvent::Debug => {
                self.halted = true;
                VcpuExit::Debug
            }
        }))
    }

    fn step_system(&mut self) -> Result<Option<VcpuExit>> {
        if self.halted {
            return Ok(Some(VcpuExit::Hlt));
        }
        if let Some(exit) = self.pop_event()? {
            return Ok(Some(exit));
        }
        self.poll_vm_clock()?;
        let exit = self.cpu.step();
        self.poll_vm_clock()?;
        let terminal = match exit {
            RiscVExit::Continue | RiscVExit::Wfi => None,
            RiscVExit::Ecall => {
                let syscall = self.cpu.x(17);
                let code = self.cpu.x(10);
                Some(if syscall == 93 && code != 0 {
                    PendingEvent::Failure {
                        reason: format!("riscv ecall failure: code={code:#x}"),
                        halt: true,
                    }
                } else {
                    PendingEvent::Shutdown
                })
            }
            RiscVExit::Ebreak => Some(PendingEvent::Debug),
            RiscVExit::Trap(t) => Some(PendingEvent::Failure {
                reason: format!(
                    "riscv trap: cause={} tval={:#x} pc={:#x}",
                    t.cause,
                    t.tval,
                    self.cpu.pc()
                ),
                halt: true,
            }),
        };
        if let Some(event) = terminal {
            self.pending
                .lock()
                .map_err(|_| Error::Emulator("RISC-V event queue poisoned".into()))?
                .push_back(event);
        }
        self.pop_event()
    }
}

pub(crate) fn context_uses_platform(raw: &[u8]) -> Result<bool> {
    context::platform_profile(raw)
}

impl VCpu for RiscVVcpu {
    fn poll_vm_clock(&mut self) -> Result<()> {
        if let Some(platform) = &self.platform
            && let Some((time, software, timer)) = platform.signals(self.id)?
        {
            self.cpu.set_time(time);
            self.cpu.set_interrupt_pending(1 << 3, software);
            self.cpu.set_interrupt_pending(1 << 7, timer);
        }
        Ok(())
    }

    fn required_private_checkpoint_kind(&self) -> Option<u32> {
        Some(crate::vm::snapshot::RISCV_CONTEXT)
    }

    fn validate_checkpoint_for_machine(
        &self,
        config: &crate::config::CheckpointConfig,
        state: &CpuState,
        emulator: &crate::vm::snapshot::EmulatorState,
        context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<()> {
        self.validate_checkpoint_context(state, emulator, context)?;
        let profile = match context {
            Some(context) => self.context_configuration(&context.data)?,
            None => *self.cpu.config(),
        };
        if config.arch != crate::config::ArchKind::Riscv64
            || profile.xlen != crate::isa::riscv::Xlen::Rv64
        {
            return Err(Error::InvalidConfig(
                "Riscv64 checkpoint requires an RV64 backend profile".into(),
            ));
        }
        Ok(())
    }

    fn riscv_configuration(&self) -> Option<RiscVConfig> {
        Some(*self.cpu.config())
    }

    fn capture_backend_context_for_mapping(
        &self,
        memory: &GuestMemoryMmap,
    ) -> Result<Option<crate::vm::snapshot::BackendContext>> {
        Ok(Some(crate::vm::snapshot::BackendContext {
            kind: crate::vm::snapshot::RISCV_CONTEXT,
            data: self.context_for_mapping(memory)?,
        }))
    }

    fn mapping_reservation(&self) -> Option<crate::vm::memory::MappingReservation> {
        Some(self.exclusive.mapping_witness())
    }

    fn reconcile_mapping_reservation(
        &mut self,
        source: &crate::vm::memory::MappingReservation,
    ) -> Result<()> {
        if !self.exclusive.retain_from(source) {
            self.cpu.clear_reservation();
        }
        Ok(())
    }

    fn capture_backend_context_in_scope(
        &self,
        scope: &crate::vm::memory::checkpoint::CheckpointPublication<'_>,
    ) -> Result<Option<crate::vm::snapshot::BackendContext>> {
        Ok(Some(crate::vm::snapshot::BackendContext {
            kind: crate::vm::snapshot::RISCV_CONTEXT,
            data: self.context_in_scope(scope)?,
        }))
    }

    fn prepare_checkpoint_publication<'scope, 'bindings>(
        &mut self,
        scope: &'scope crate::vm::memory::checkpoint::CheckpointPublication<'bindings>,
    ) -> Result<crate::vm::memory::checkpoint::CpuPublication<'scope, 'bindings>> {
        self.publication(scope)
    }

    fn prepare_checkpoint_replacement(
        &self,
        state: &CpuState,
        emulator: &crate::vm::snapshot::EmulatorState,
        context: Option<&crate::vm::snapshot::BackendContext>,
        _resources: &crate::vm::snapshot::PreparedResources,
    ) -> Result<Option<Box<dyn VCpu>>> {
        self.validate_checkpoint_context(state, emulator, context)?;
        let candidate = match context {
            Some(raw) => self.prepare_context(&raw.data)?,
            None => {
                let mut candidate = match &self.user {
                    Some(user) => Self::new_user(
                        self.id,
                        self.physical_memory.clone(),
                        *self.cpu.config(),
                        user.translation.clone(),
                    ),
                    None => Self::build(
                        self.id,
                        self.physical_memory.clone(),
                        *self.cpu.config(),
                        self.devices_enabled,
                        self.platform.clone(),
                    ),
                };
                candidate.set_state(state)?;
                candidate.stage_without_reservation();
                candidate
            }
        };
        Ok(Some(Box::new(candidate)))
    }

    fn capture_backend_context(&self) -> Result<Option<crate::vm::snapshot::BackendContext>> {
        Ok(Some(crate::vm::snapshot::BackendContext {
            kind: crate::vm::snapshot::RISCV_CONTEXT,
            data: self.save_context()?,
        }))
    }

    fn validate_checkpoint_context(
        &self,
        state: &CpuState,
        emulator: &crate::vm::snapshot::EmulatorState,
        context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<()> {
        self.validate_checkpoint_state(state, emulator)?;
        if let Some(context) = context {
            if context.kind != crate::vm::snapshot::RISCV_CONTEXT {
                return Err(Error::InvalidConfig(
                    "RISC-V checkpoint context producer differs from target backend".into(),
                ));
            }
            self.validate_context_record(state, &context.data)?;
        }
        Ok(())
    }

    fn restore_checkpoint_context(
        &mut self,
        state: &CpuState,
        emulator: &crate::vm::snapshot::EmulatorState,
        context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<()> {
        self.validate_checkpoint_context(state, emulator, context)?;
        if let Some(context) = context {
            self.restore_context(&context.data)
        } else {
            self.set_state(state)
        }
    }

    fn run(&mut self) -> Result<VcpuExit> {
        self.ensure_checkpoint_active()?;
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
        for _ in 0..MAX_ITERS {
            if let Some(exit) = self.step_system()? {
                return Ok(exit);
            }
        }
        Ok(VcpuExit::Hlt)
    }

    fn get_state(&self) -> Result<CpuState> {
        let tohost = *self
            .tohost_addr
            .lock()
            .map_err(|_| Error::Emulator("RISC-V tohost lock poisoned during capture".into()))?;
        Ok(CpuState::riscv(self.cpu.public_registers(tohost)))
    }

    fn validate_checkpoint_state(
        &self,
        state: &CpuState,
        _emulator: &crate::vm::snapshot::EmulatorState,
    ) -> Result<()> {
        let CpuState::RiscV(state) = state else {
            return Err(Error::Emulator(
                "expected riscv state for riscv vCPU".to_string(),
            ));
        };
        if let Some(level) = state.regs.privilege {
            RiscVCpu::privilege_from_level(level).ok_or_else(|| {
                Error::Emulator(format!("invalid RISC-V privilege level {level}"))
            })?;
        }
        if let Some(vector) = &state.regs.vector {
            self.cpu
                .validate_vector_state(vector)
                .map_err(Error::Emulator)?;
        }
        drop(self.tohost_addr.lock().map_err(|_| {
            Error::Emulator("RISC-V tohost lock poisoned during restore".to_string())
        })?);
        Ok(())
    }

    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        self.apply_public_state(state)?;
        self.cpu.clear_reservation();
        self.halted = false;
        if let Some(user) = self.user.as_mut() {
            user.trap = None;
        }
        Ok(())
    }

    fn update_state(&mut self, state: &CpuState) -> Result<()> {
        self.apply_public_state(state)
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

    fn set_current_pc(&mut self, pc: u64) -> Result<()> {
        self.cpu.set_pc(pc);
        Ok(())
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
        self.ensure_checkpoint_active()?;
        if self.user.is_some() {
            return self.step_user();
        }
        self.step_system()
    }
}

#[cfg(test)]
#[path = "cpu_user_tests.rs"]
mod user_tests;

#[cfg(test)]
#[path = "cpu_state_tests.rs"]
mod state_tests;

#[cfg(test)]
mod checkpoint_lock_tests {
    use super::*;
    #[test]
    fn poisoned_tohost_rejects_restore_before_register_assignment() {
        let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
        let mut cpu = RiscVVcpu::new(0, memory);
        let before = crate::codec::serialize(&cpu.get_state().unwrap()).unwrap();
        let mut state = cpu.get_state().unwrap();
        let CpuState::RiscV(regs) = &mut state else {
            unreachable!()
        };
        regs.regs.x[5] = 0x12345678;
        let shared = cpu.tohost_addr.clone();
        assert!(
            std::thread::spawn(move || {
                let _guard = shared.lock().unwrap();
                panic!("owned tohost poison fixture");
            })
            .join()
            .is_err()
        );
        assert!(
            cpu.validate_checkpoint_state(&state, &Default::default())
                .is_err()
        );
        assert!(cpu.set_state(&state).is_err());
        // get_state also reads tohost. Recover only the test lock marker;
        // state itself must be exactly as captured before the failed restore.
        cpu.tohost_addr.clear_poison();
        assert_eq!(
            crate::codec::serialize(&cpu.get_state().unwrap()).unwrap(),
            before
        );
    }
}

#[cfg(test)]
#[path = "cpu_reservation_tests.rs"]
mod reservation_tests;

#[cfg(test)]
#[path = "cpu_platform_tests.rs"]
mod platform_tests;
