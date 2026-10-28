//! AArch64 vCPU: drives the software [`crate::isa::arm::aarch64::AArch64Cpu`]
//! system emulator over guest memory and maps its exits onto [`VcpuExit`].
//!
//! Guest memory is bridged through [`GuestBridge`], an [`ArmMemory`] over the
//! VMM's [`GuestMemoryMmap`] with two device windows intercepted:
//!
//! - the GICv3 distributor/redistributor frames are routed into the CPU's
//!   shared [`Gic`] model (the same instance the ICC system registers act on),
//! - the PL011 window is serviced synchronously against the VMM's shared
//!   [`Pl011`] device, so console TX appears immediately and RX state is the
//!   one the VMM feeds from the host terminal. After every UART access the
//!   bridge re-mirrors the UART interrupt level onto GIC SPI 33.
//!
//! PSCI calls (the device tree advertises `method = "hvc"`) surface as
//! [`CpuExit::Hvc`]/[`CpuExit::Smc`] and are implemented here.
//!
//! [`Aarch64Vcpu::new_user`] builds a process-level (user-mode) vCPU for
//! embedders that implement the operating system themselves: it executes at
//! EL0, translates every access through a [`FlatTranslation`] that enforces
//! page permissions, and reports `SVC` as [`VcpuExit::SystemCall`] and other
//! synchronous exceptions as [`Error::GuestEvent`] instead of taking them to
//! EL1 (see [`A64UserTrap`]).

mod checkpoint;
pub(crate) mod cluster;
mod exclusive;
mod psci;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use tracing::{debug, info};
use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

use crate::devices::pl011::{Pl011, Pl011MmioDevice};
use crate::error::{Error, GuestMemoryFault, MemoryAccessKind, MemoryFaultKind, Result};
use crate::isa::arm::aarch64::{AArch64Config, AArch64Cpu, Gic};
use crate::isa::arm::cpu_trait::{AccessType, ArmCpu, ArmError, CpuExit, ProcessorState};
use crate::isa::arm::memory::{ArmMemory, MemResult, MemoryError, MmioHandler};
use crate::machine::arm_virt::{AARCH64_GICD_BASE, AARCH64_GICR_BASE, AARCH64_UART_IRQ};
use crate::vm::memory::FlatTranslation;
use crate::vm::vcpu::{CpuState, MemAccess, MemRecord, VCpu, VcpuExit};

/// GICv3 distributor frame size.
const GICD_SIZE: u64 = 0x1_0000;
/// GICv3 redistributor frame size (RD + SGI frames, one CPU).
const GICR_SIZE: u64 = 0x2_0000;
/// PL011 window.
const UART_BASE: u64 = crate::machine::arm_virt::AARCH64_UART_BASE;
const UART_SIZE: u64 = 0x1000;

/// Instructions executed per `run()` call before yielding to the VMM loop
/// (console polling, checkpoint hotkeys). ~1-2ms of guest time.
const BATCH: u32 = 65_536;

/// Boot-debug physical watchpoint (RAX_WATCH=hex PA): the bridge flags a hit,
/// the run loop attributes it to the guest PC.
static WATCH_HIT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn watch_addr() -> Option<u64> {
    static ADDR: OnceLock<Option<u64>> = OnceLock::new();
    *ADDR.get_or_init(|| {
        std::env::var("RAX_WATCH")
            .ok()
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
    })
}

/// Boot-debug register tracer (RAX_TRACE_REG=reg:start:end, decimal): logs
/// every change of X<reg> within the instruction-count window.
fn trace_reg() -> Option<(u8, u64, u64)> {
    static CFG: OnceLock<Option<(u8, u64, u64)>> = OnceLock::new();
    *CFG.get_or_init(|| {
        let s = std::env::var("RAX_TRACE_REG").ok()?;
        let mut it = s.split(':');
        Some((
            it.next()?.parse().ok()?,
            it.next()?.parse().ok()?,
            it.next()?.parse().ok()?,
        ))
    })
}

/// Shared parts the bridge needs that only exist after construction.
#[derive(Default)]
struct LateBound {
    gic: OnceLock<Arc<Mutex<Gic>>>,
    uart: OnceLock<Arc<Mutex<Pl011>>>,
}

/// Instruction-scoped memory observation shared by the vCPU and its memory
/// bridge. The C API enables it only while memory hooks are active and drains
/// it after every step, so the enabled buffer is bounded by one instruction.
#[derive(Default)]
struct MemRecorder {
    enabled: AtomicBool,
    records: Mutex<Vec<MemRecord>>,
}

impl MemRecorder {
    fn record(&self, access: MemAccess, addr: u64, bytes: &[u8]) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        let mut low = [0u8; 8];
        let copied = bytes.len().min(low.len());
        low[..copied].copy_from_slice(&bytes[..copied]);
        if let Ok(mut records) = self.records.lock() {
            records.push(MemRecord {
                access,
                addr,
                size: bytes.len().min(u8::MAX as usize) as u8,
                value: if access == MemAccess::Exec {
                    0
                } else {
                    u64::from_le_bytes(low)
                },
                rip: 0,
            });
        }
    }

    fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
        if !enabled {
            if let Ok(mut records) = self.records.lock() {
                records.clear();
            }
        }
    }

    fn drain(&self, out: &mut Vec<MemRecord>) {
        if let Ok(mut records) = self.records.lock() {
            out.append(&mut records);
        }
    }
}

/// Guest memory bridge: RAM via [`GuestMemoryMmap`], GIC and UART windows
/// intercepted.
struct GuestBridge {
    mem: Arc<GuestMemoryMmap>,
    late: Arc<LateBound>,
    recorder: Arc<MemRecorder>,
    /// Full-machine construction owns fixed UART/GIC windows; an instruction
    /// embedder owns its complete address space through explicit mappings.
    devices_enabled: bool,
    gic_cpus: u8,
    gic_high_base: u64,
    /// User mode: every access is translated and permission-checked here,
    /// one page at a time, before guest memory is touched.
    translation: Option<Arc<dyn FlatTranslation>>,
    /// Local exclusive monitor: (address, size) of the open reservation.
    exclusive: crate::vm::memory::reservations::Monitor,
}

impl std::fmt::Debug for GuestBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestBridge").finish()
    }
}

#[inline]
fn in_window(addr: u64, base: u64, size: u64) -> bool {
    addr >= base && addr < base + size
}

/// The core's memory error for a user-mode translation fault. `size` is the
/// number of bytes of the access from the first inaccessible byte onward.
fn user_fault(fault: GuestMemoryFault, size: usize) -> MemoryError {
    let access = match fault.access {
        MemoryAccessKind::Read => AccessType::Read,
        MemoryAccessKind::Write => AccessType::Write,
        MemoryAccessKind::Fetch => AccessType::InstructionFetch,
    };
    match fault.kind {
        MemoryFaultKind::Unmapped => MemoryError::Unmapped {
            addr: fault.address,
            size,
            access,
        },
        MemoryFaultKind::Permission => MemoryError::Permission {
            addr: fault.address,
            access,
            reason: String::new(),
        },
        MemoryFaultKind::Other => MemoryError::BusError {
            addr: fault.address,
        },
    }
}

/// Translates `[addr, addr + len)` one 4 KiB page at a time and calls `f`
/// with each chunk's guest-memory address and its byte range within the
/// access. Stops at the first translation fault or `f` error.
fn for_each_user_page(
    translation: &dyn FlatTranslation,
    addr: u64,
    len: usize,
    access: MemoryAccessKind,
    mut f: impl FnMut(u64, std::ops::Range<usize>) -> MemResult<()>,
) -> MemResult<()> {
    let mut done = 0usize;
    while done < len {
        let linear = addr.wrapping_add(done as u64);
        let chunk = ((0x1000 - (linear & 0xFFF)) as usize).min(len - done);
        let target = translation
            .translate(linear, access)
            .map_err(|fault| user_fault(fault, len - done))?;
        f(target, done..done + chunk)?;
        done += chunk;
    }
    Ok(())
}

impl GuestBridge {
    /// A user-mode load or fetch through the installed translation.
    fn user_read(
        &self,
        translation: &dyn FlatTranslation,
        addr: u64,
        buf: &mut [u8],
        access: MemoryAccessKind,
    ) -> MemResult<()> {
        let len = buf.len();
        let arm_access = match access {
            MemoryAccessKind::Fetch => AccessType::InstructionFetch,
            _ => AccessType::Read,
        };
        for_each_user_page(translation, addr, len, access, |target, range| {
            self.mem
                .read_slice(&mut buf[range], GuestAddress(target))
                .map_err(|error| MemoryError::Unmapped {
                    addr: Self::failed_address(target, error),
                    size: len,
                    access: arm_access,
                })
        })
    }

    /// A user-mode store through the installed translation. Every page is
    /// translated and checked before any byte is written, so a store that
    /// faults on a later page publishes nothing.
    fn user_write(
        &self,
        translation: &dyn FlatTranslation,
        addr: u64,
        data: &[u8],
    ) -> MemResult<()> {
        let len = data.len();
        for_each_user_page(
            translation,
            addr,
            len,
            MemoryAccessKind::Write,
            |target, range| {
                if self
                    .mem
                    .check_range(GuestAddress(target), range.end - range.start)
                {
                    Ok(())
                } else {
                    Err(MemoryError::Unmapped {
                        addr: target,
                        size: len - range.start,
                        access: AccessType::Write,
                    })
                }
            },
        )?;
        for_each_user_page(
            translation,
            addr,
            len,
            MemoryAccessKind::Write,
            |target, range| {
                crate::vm::memory::reservations::write(&self.mem, target, &data[range]).map_err(
                    |error| MemoryError::Unmapped {
                        addr: Self::failed_address(target, error),
                        size: len,
                        access: AccessType::Write,
                    },
                )
            },
        )
    }

    /// Recompute the PL011's level-triggered SPI after a UART access.
    fn sync_uart_irq(&self) {
        let (Some(gic), Some(uart)) = (self.late.gic.get(), self.late.uart.get()) else {
            return;
        };
        let level = uart.lock().map(|u| u.irq_pending()).unwrap_or(false);
        if let Ok(mut gic) = gic.lock() {
            if level {
                gic.set_pending(AARCH64_UART_IRQ);
            } else {
                gic.clear_pending(AARCH64_UART_IRQ);
            }
        }
    }

    fn read_redist(&self, gic: &Gic, address: u64) -> u32 {
        let Some((cpu, offset)) = crate::machine::arm_virt::aarch64_redist_frame(
            address,
            self.gic_cpus,
            self.gic_high_base,
        ) else {
            return 0;
        };
        let mut value = gic.read_redist(cpu, offset);
        if offset == 8 {
            // IHI0069H12.11.37: Last terminates each contiguous series of
            // redistributor pages. The board can split that series at UART.
            let low_frames =
                crate::machine::arm_virt::aarch64_redist_regions(self.gic_cpus, self.gic_high_base)
                    [0]
                .1 / GICR_SIZE;
            let last = cpu as u64 + 1 == low_frames || cpu + 1 == usize::from(self.gic_cpus);
            value = (value & !16) | (u32::from(last) << 4);
        }
        value
    }

    fn gic_read(&self, addr: u64, buf: &mut [u8]) {
        let Some(gic) = self.late.gic.get() else {
            buf.fill(0);
            return;
        };
        let Ok(gic) = gic.lock() else {
            buf.fill(0);
            return;
        };
        // Serve arbitrary widths out of the 32-bit register file.
        for (i, b) in buf.iter_mut().enumerate() {
            let byte_addr = addr + i as u64;
            let reg_addr = byte_addr & !0x3;
            let lane = (byte_addr & 0x3) as usize;
            let value = if in_window(reg_addr, AARCH64_GICD_BASE, GICD_SIZE) {
                gic.read_dist(reg_addr - AARCH64_GICD_BASE)
            } else {
                self.read_redist(&gic, reg_addr)
            };
            *b = value.to_le_bytes()[lane];
        }
    }

    fn gic_write(&self, addr: u64, data: &[u8]) {
        let Some(gic) = self.late.gic.get() else {
            return;
        };
        let Ok(mut gic) = gic.lock() else {
            return;
        };
        // Fold writes into whole 32-bit registers (read-modify-write for
        // partial widths).
        let mut offset = 0usize;
        while offset < data.len() {
            let byte_addr = addr + offset as u64;
            let reg_addr = byte_addr & !0x3;
            let lane = (byte_addr & 0x3) as usize;
            let take = (4 - lane).min(data.len() - offset);

            let dist = in_window(reg_addr, AARCH64_GICD_BASE, GICD_SIZE);
            let mut value = if dist {
                gic.read_dist(reg_addr - AARCH64_GICD_BASE)
            } else {
                self.read_redist(&gic, reg_addr)
            };
            let mut bytes = value.to_le_bytes();
            bytes[lane..lane + take].copy_from_slice(&data[offset..offset + take]);
            value = u32::from_le_bytes(bytes);

            if dist {
                gic.write_dist(reg_addr - AARCH64_GICD_BASE, value);
            } else {
                if let Some((cpu, offset)) = crate::machine::arm_virt::aarch64_redist_frame(
                    reg_addr,
                    self.gic_cpus,
                    self.gic_high_base,
                ) {
                    gic.write_redist(cpu, offset, value);
                }
            }
            offset += take;
        }
    }

    fn failed_address(addr: u64, error: vm_memory::GuestMemoryError) -> u64 {
        match error {
            vm_memory::GuestMemoryError::PartialBuffer { completed, .. } => {
                addr.saturating_add(completed as u64)
            }
            vm_memory::GuestMemoryError::InvalidGuestAddress(address) => address.0,
            _ => addr,
        }
    }

    fn read_unrecorded(&self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        if self.devices_enabled && in_window(addr, UART_BASE, UART_SIZE) {
            if let Some(uart) = self.late.uart.get() {
                let mut dev = Pl011MmioDevice::new(UART_BASE, uart.clone());
                crate::devices::bus::MmioDevice::read(&mut dev, addr, buf);
            } else {
                buf.fill(0);
            }
            self.sync_uart_irq();
            return Ok(());
        }
        if self.devices_enabled
            && (in_window(addr, AARCH64_GICD_BASE, GICD_SIZE)
                || crate::machine::arm_virt::aarch64_redist_frame(
                    addr,
                    self.gic_cpus,
                    self.gic_high_base,
                )
                .is_some())
        {
            self.gic_read(addr, buf);
            return Ok(());
        }
        self.mem
            .read_slice(buf, GuestAddress(addr))
            .map_err(|error| MemoryError::Unmapped {
                addr: Self::failed_address(addr, error),
                access: AccessType::Read,
                size: buf.len(),
            })
    }
}

impl ArmMemory for GuestBridge {
    fn read(&self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        match self.translation.as_deref() {
            Some(translation) => self.user_read(translation, addr, buf, MemoryAccessKind::Read)?,
            None => self.read_unrecorded(addr, buf)?,
        }
        self.recorder.record(MemAccess::Read, addr, buf);
        Ok(())
    }

    fn write(&mut self, addr: u64, data: &[u8]) -> MemResult<()> {
        if let Some(translation) = self.translation.as_deref() {
            self.user_write(translation, addr, data)?;
            self.recorder.record(MemAccess::Write, addr, data);
            return Ok(());
        }
        // Boot-debug physical watchpoint (set RAX_WATCH=hexaddr).
        if let Some(w) = watch_addr() {
            if addr < w + 8 && addr + data.len() as u64 > w {
                WATCH_HIT.store(true, Ordering::Relaxed);
                debug!(addr = format!("{addr:#x}"), ?data, "watch: store");
            }
        }
        if self.devices_enabled && in_window(addr, UART_BASE, UART_SIZE) {
            if let Some(uart) = self.late.uart.get() {
                let mut dev = Pl011MmioDevice::new(UART_BASE, uart.clone());
                crate::devices::bus::MmioDevice::write(&mut dev, addr, data);
            }
            self.sync_uart_irq();
            self.recorder.record(MemAccess::Write, addr, data);
            return Ok(());
        }
        if self.devices_enabled
            && (in_window(addr, AARCH64_GICD_BASE, GICD_SIZE)
                || crate::machine::arm_virt::aarch64_redist_frame(
                    addr,
                    self.gic_cpus,
                    self.gic_high_base,
                )
                .is_some())
        {
            self.gic_write(addr, data);
            self.recorder.record(MemAccess::Write, addr, data);
            return Ok(());
        }
        // Preflight all ordinary RAM before an ordinary crossing store. Do not
        // publish its first bytes if a later region is missing.
        let mut done = 0usize;
        while done < data.len() {
            let current = addr.checked_add(done as u64).ok_or(MemoryError::Unmapped {
                addr,
                size: data.len(),
                access: AccessType::Write,
            })?;
            let region =
                self.mem
                    .find_region(GuestAddress(current))
                    .ok_or(MemoryError::Unmapped {
                        addr: current,
                        size: data.len() - done,
                        access: AccessType::Write,
                    })?;
            let available = region.len() - (current - region.start_addr().0);
            done += (available as usize).min(data.len() - done);
        }
        crate::vm::memory::reservations::write(&self.mem, addr, data).map_err(|error| {
            MemoryError::Unmapped {
                addr: Self::failed_address(addr, error),
                access: AccessType::Write,
                size: data.len(),
            }
        })?;
        self.recorder.record(MemAccess::Write, addr, data);
        Ok(())
    }

    fn fetch(&self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        if let Some(translation) = self.translation.as_deref() {
            self.user_read(translation, addr, buf, MemoryAccessKind::Fetch)?;
            self.recorder.record(MemAccess::Exec, addr, buf);
            return Ok(());
        }
        self.read_unrecorded(addr, buf)
            .map_err(|error| match error {
                MemoryError::Unmapped { addr, size, .. } => MemoryError::Unmapped {
                    addr,
                    size,
                    access: AccessType::InstructionFetch,
                },
                other => other,
            })?;
        self.recorder.record(MemAccess::Exec, addr, buf);
        Ok(())
    }

    fn mark_exclusive(&mut self, addr: u64, size: u8) {
        self.exclusive.mark(addr, size);
    }
    fn check_exclusive(&mut self, addr: u64, size: u8) -> bool {
        self.exclusive.check(addr, size)
    }
    fn clear_exclusive(&mut self) {
        self.exclusive.clear();
    }

    fn read_exclusive(&mut self, addr: u64, size: usize) -> MemResult<Vec<u8>> {
        let physical = self.exclusive_physical(addr, size, MemoryAccessKind::Read)?;
        let data = self
            .exclusive
            .read_exclusive(&self.mem, physical, size)
            .map_err(|error| MemoryError::Unmapped {
                addr: Self::failed_address(addr, error),
                access: AccessType::Read,
                size,
            })?;
        self.recorder.record(MemAccess::Read, addr, &data);
        Ok(data)
    }
    fn write_exclusive(&mut self, addr: u64, data: &[u8]) -> MemResult<bool> {
        let physical = self.exclusive_physical(addr, data.len(), MemoryAccessKind::Write)?;
        let written = self
            .exclusive
            .write_exclusive(&self.mem, physical, data)
            .map_err(|error| MemoryError::Unmapped {
                addr: Self::failed_address(addr, error),
                access: AccessType::Write,
                size: data.len(),
            })?;
        if written {
            self.recorder.record(MemAccess::Write, addr, data);
        }
        Ok(written)
    }

    fn requires_alignment(&self) -> bool {
        // AArch64 permits unaligned accesses to normal memory when SCTLR.A=0
        // (the kernel relies on this, e.g. unaligned u64 loads while scanning
        // the FDT). Alignment-checked instruction forms enforce their own
        // rules in the CPU.
        false
    }

    fn register_mmio(&mut self, _base: u64, _size: u64, _handler: Box<dyn MmioHandler>) {
        // Device windows are fixed for this machine.
    }

    fn unregister_mmio(&mut self, _base: u64) {}
}

/// `ESR_ELx.EC` for an exception with an unknown reason (UNDEFINED
/// instructions, including EL1-only system registers and `HVC`/`SMC`/`HLT`
/// executed at EL0).
pub const A64_EC_UNKNOWN: u8 = 0x00;
/// `ESR_ELx.EC` for a `BRK` instruction executed in AArch64 state.
pub const A64_EC_BRK: u8 = 0x3C;
/// `ESR_ELx.EC` for an AArch32 `BKPT`, including Thumb after a width handoff.
pub const A64_EC_BKPT32: u8 = 0x38;

/// An EL0 event a user-mode vCPU ([`Aarch64Vcpu::new_user`]) reported to its
/// embedder instead of taking it to EL1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum A64UserTrap {
    /// `SVC #imm` at `pc` executed; the PC is the following instruction, the
    /// preferred return address of the exception.
    Svc { imm: u16, pc: u64 },
    /// ARM/Thumb SVC after a checked mixed-width state restore.
    Aarch32Svc { imm: u32, pc: u64, len: u8 },
    /// A synchronous exception raised by the instruction at `pc`, which did
    /// not retire: the PC is `pc`, the preferred return address. `ec` and
    /// `iss` are the `ESR_EL1` fields an EL1 handler would receive
    /// (including [`A64_EC_BRK`], [`A64_EC_BKPT32`], authentication failures,
    /// and [`A64_EC_UNKNOWN`]).
    Exception { ec: u8, iss: u32, pc: u64 },
}

/// Per-vCPU user-mode state.
struct A64User {
    /// The translation the memory bridge applies, for debugger-style
    /// [`VCpu::translate_addr`] queries.
    translation: Arc<dyn FlatTranslation>,
    trap: Option<A64UserTrap>,
    /// Instructions the core counted as executed that the user-mode contract
    /// reports as not retired (an exception-raising `BRK`, `HVC`, `SMC`, or
    /// `HLT`); subtracted from [`VCpu::instruction_count`].
    not_retired: u64,
}

/// AArch64 vCPU backed by the software system emulator.
pub struct Aarch64Vcpu {
    id: u32,
    cpu: AArch64Cpu,
    late: Arc<LateBound>,
    recorder: Arc<MemRecorder>,
    /// Total instructions executed (also read for snapshot bookkeeping).
    insn_count: Arc<AtomicU64>,
    /// Last heartbeat log (wall clock).
    last_heartbeat: crate::host::time::Instant,
    heartbeat_offset: std::time::Duration,
    /// Last value seen by the register tracer.
    trace_reg_last: u64,
    shutdown: bool,
    /// C API instruction execution reports faults instead of entering guest vectors.
    fault_exits: bool,
    /// Process-level execution at EL0 ([`Aarch64Vcpu::new_user`]).
    user: Option<A64User>,
    cluster: Option<Arc<cluster::ArmCluster>>,
    powered_off: bool,
    physical_memory: Arc<GuestMemoryMmap>,
    exclusive: crate::vm::memory::reservations::Monitor,
    checkpoint_activation: Option<checkpoint::PendingActivation>,
}

impl Aarch64Vcpu {
    pub fn new(id: u32, mem: Arc<GuestMemoryMmap>) -> Self {
        Self::with_machine_devices(id, mem, true)
    }

    fn with_machine_devices(id: u32, mem: Arc<GuestMemoryMmap>, devices_enabled: bool) -> Self {
        Self::build(
            id,
            mem,
            devices_enabled,
            None,
            AArch64Config::default(),
            None,
        )
    }

    fn build(
        id: u32,
        mem: Arc<GuestMemoryMmap>,
        devices_enabled: bool,
        translation: Option<Arc<dyn FlatTranslation>>,
        config: AArch64Config,
        binding: Option<(Arc<cluster::ArmCluster>, Arc<AtomicBool>)>,
    ) -> Self {
        let late = Arc::new(LateBound::default());
        let recorder = Arc::new(MemRecorder::default());
        let physical_memory = mem.clone();
        let monitor = crate::vm::memory::reservations::MemoryDomain::for_memory(&mem).register();
        let gic_cpus = binding.as_ref().map_or(1, |(cluster, _)| cluster.count());
        let gic_high_base = binding.as_ref().map_or(
            crate::machine::arm_virt::AARCH64_GICR_HIGH_BASE,
            |(cluster, _)| cluster.high_redist_base,
        );
        let bridge = GuestBridge {
            mem,
            late: late.clone(),
            recorder: recorder.clone(),
            devices_enabled,
            gic_cpus,
            gic_high_base,
            translation,
            exclusive: monitor.clone(),
        };
        let mut cpu = AArch64Cpu::new_with_cpu_id(config, Box::new(bridge), id);
        if let Some((platform, line)) = &binding {
            cpu.bind_platform_gic(platform.gic.clone(), id as usize, line.clone());
            cpu.configure_nonsecure_reset();
        }
        // The CPU owns the GIC; hand the bridge a reference to the same
        // instance so MMIO and ICC system registers agree.
        if let Some(gic) = cpu.gic_handle() {
            let _ = late.gic.set(gic);
        }
        Aarch64Vcpu {
            id,
            cpu,
            late,
            recorder,
            insn_count: Arc::new(AtomicU64::new(0)),
            last_heartbeat: crate::host::time::Instant::now(),
            heartbeat_offset: std::time::Duration::ZERO,
            trace_reg_last: 0,
            shutdown: false,
            fault_exits: !devices_enabled,
            user: None,
            cluster: binding.map(|(cluster, _)| cluster),
            powered_off: false,
            physical_memory,
            exclusive: monitor,
            checkpoint_activation: None,
        }
    }

    pub(super) fn new_in_cluster(
        id: u32,
        mem: Arc<GuestMemoryMmap>,
        cluster: Arc<cluster::ArmCluster>,
    ) -> Result<Self> {
        if id >= u32::from(cluster.count()) {
            return Err(Error::InvalidConfig(
                "AArch64 CPU id exceeds configured topology".into(),
            ));
        }
        let line = cluster
            .gic
            .lock()
            .map_err(|_| Error::Emulator("GIC lock poisoned".into()))?
            .irq_line(id as usize)
            .ok_or_else(|| Error::InvalidConfig("missing CPU IRQ binding".into()))?;
        let mut cpu = Self::build(
            id,
            mem,
            true,
            None,
            AArch64Config::default(),
            Some((cluster, line)),
        );
        cpu.powered_off = id != 0;
        Ok(cpu)
    }

    /// Instruction-level engine for embedders without a guest exception handler.
    /// The ordinary constructor retains full-machine architectural delivery.
    pub fn new_micro(id: u32, mem: Arc<GuestMemoryMmap>) -> Self {
        Self::with_machine_devices(id, mem, false)
    }

    /// Process-level (user-mode) engine: the core executes at EL0 (`EL0t`)
    /// with the Linux `execve` PSTATE, and every load, store, and instruction
    /// fetch is translated and permission-checked by `translation`, whose
    /// results index `mem`. There is no interrupt controller and no device
    /// window. `SVC` retires and returns [`VcpuExit::SystemCall`]; `BRK` and
    /// UNDEFINED instructions return [`Error::GuestEvent`] without retiring;
    /// a translation fault returns [`Error::GuestAccess`]. Each records an
    /// [`A64UserTrap`] (except the memory fault) for
    /// [`Aarch64Vcpu::take_user_trap`].
    pub fn new_user(
        id: u32,
        mem: Arc<GuestMemoryMmap>,
        translation: Arc<dyn FlatTranslation>,
    ) -> Self {
        let config = AArch64Config {
            // No interrupt controller: user mode has no asynchronous
            // interrupts, and the GIC would be locked on every step.
            gic_config: None,
            ..AArch64Config::default()
        };
        let mut vcpu = Self::build(id, mem, false, Some(translation.clone()), config, None);
        vcpu.cpu.enter_el0();
        vcpu.user = Some(A64User {
            translation,
            trap: None,
            not_retired: 0,
        });
        vcpu
    }

    /// Whether this vCPU executes at EL0 for a user-mode embedder.
    pub fn user_mode_enabled(&self) -> bool {
        self.user.is_some()
    }

    /// Actual entries into a single-instruction native PAuth region. Zero on
    /// hosts/builds without AArch64 native execution; never counts compilation.
    pub fn native_pauth_entry_count(&self) -> u64 {
        self.cpu.native_pauth_entry_count()
    }

    /// Removes and returns the event that ended the last user-mode step.
    pub fn take_user_trap(&mut self) -> Option<A64UserTrap> {
        self.user.as_mut().and_then(|user| user.trap.take())
    }

    /// Executes one EL0 instruction for a user-mode embedder.
    fn step_user(&mut self) -> Result<Option<VcpuExit>> {
        let pc = self.cpu.get_pc();
        let before = self.cpu.instruction_count();
        let record_memory = self.recorder.enabled.load(Ordering::Relaxed);
        let stepped = self.cpu.step_user_pauth(!record_memory);
        let counted = self.cpu.instruction_count().wrapping_sub(before);
        let event = |cpu: &mut AArch64Cpu,
                     user: &mut A64User,
                     ec: u8,
                     iss: u32|
         -> Result<Option<VcpuExit>> {
            // The exception's preferred return address is the instruction.
            cpu.set_pc(pc);
            user.not_retired = user.not_retired.wrapping_add(counted);
            user.trap = Some(A64UserTrap::Exception { ec, iss, pc });
            // Taking an exception clears the local exclusive monitor.
            cpu.clear_exclusive_monitor();
            Err(Error::GuestEvent { vector: ec })
        };
        let Some(user) = self.user.as_mut() else {
            return Err(Error::Emulator(
                "AArch64 user-mode step on a system vCPU".to_string(),
            ));
        };
        let result = match stepped {
            Ok(CpuExit::Continue) => Ok(None),
            Ok(CpuExit::Svc(imm)) => {
                user.trap = Some(if self.cpu.pstate_bits() & 16 != 0 {
                    A64UserTrap::Aarch32Svc {
                        imm,
                        pc,
                        len: self.cpu.instruction_size(),
                    }
                } else {
                    A64UserTrap::Svc {
                        imm: imm as u16,
                        pc,
                    }
                });
                self.cpu.clear_exclusive_monitor();
                Ok(Some(VcpuExit::SystemCall))
            }
            Ok(CpuExit::Breakpoint(imm)) => event(&mut self.cpu, user, A64_EC_BRK, imm & 0xFFFF),
            Ok(CpuExit::Halt) => {
                // HLT without halting debug enabled is UNDEFINED.
                self.cpu.clear_halt();
                event(&mut self.cpu, user, A64_EC_UNKNOWN, 0)
            }
            Ok(CpuExit::Hvc(_) | CpuExit::Smc(_) | CpuExit::Undefined(_)) => {
                event(&mut self.cpu, user, A64_EC_UNKNOWN, 0)
            }
            Ok(CpuExit::Wfi | CpuExit::Wfe) => {
                // Linux lets EL0 execute WFI/WFE; with no interrupt or event
                // source in user mode they complete as hints.
                self.cpu.clear_wait();
                Ok(None)
            }
            Ok(other) => Err(Error::Emulator(format!(
                "unexpected AArch64 user-mode exit at {pc:#x}: {other:?}"
            ))),
            Err(ArmError::ArchitecturalException { ec, iss, .. }) => {
                event(&mut self.cpu, user, ec, iss)
            }
            Err(ArmError::MemoryError(info)) => {
                self.cpu.set_pc(pc);
                let access = match info.access {
                    AccessType::Write | AccessType::Atomic => MemoryAccessKind::Write,
                    AccessType::Read => MemoryAccessKind::Read,
                    AccessType::InstructionFetch => MemoryAccessKind::Fetch,
                };
                let kind = match info.fault_type {
                    crate::isa::arm::common::cpu::MemoryFaultType::Translation => {
                        MemoryFaultKind::Unmapped
                    }
                    crate::isa::arm::common::cpu::MemoryFaultType::Permission => {
                        MemoryFaultKind::Permission
                    }
                    _ => MemoryFaultKind::Other,
                };
                Err(GuestMemoryFault {
                    address: info.address,
                    size: 0,
                    access,
                    kind,
                }
                .into())
            }
            Err(
                ArmError::UndefinedInstruction(_)
                | ArmError::InvalidExceptionLevel(_)
                | ArmError::Unimplemented(_),
            ) => event(&mut self.cpu, user, A64_EC_UNKNOWN, 0),
            Err(error) => Err(Error::Emulator(format!(
                "AArch64 user-mode instruction failed at {pc:#x}: {error}"
            ))),
        };
        let not_retired = self.user.as_ref().map_or(0, |user| user.not_retired);
        self.insn_count.store(
            self.cpu.instruction_count().wrapping_sub(not_retired),
            Ordering::Relaxed,
        );
        result
    }

    /// Boot-debug heartbeat: where is the guest and how fast is it going?
    fn heartbeat(&mut self) {
        if self
            .last_heartbeat
            .elapsed()
            .saturating_add(self.heartbeat_offset)
            >= std::time::Duration::from_secs(2)
        {
            debug!(
                insns = self.cpu.instruction_count(),
                pc = format!("{:#x}", self.cpu.get_pc()),
                el = self.cpu.current_el(),
                lr = format!("{:#x}", self.cpu.get_lr()),
                x0 = format!("{:#x}", self.cpu.get_gpr(0)),
                x1 = format!("{:#x}", self.cpu.get_gpr(1)),
                x2 = format!("{:#x}", self.cpu.get_gpr(2)),
                x3 = format!("{:#x}", self.cpu.get_gpr(3)),
                "aarch64 emulator heartbeat"
            );
            self.last_heartbeat = crate::host::time::Instant::now();
            self.heartbeat_offset = std::time::Duration::ZERO;
        }
    }

    /// Mirror the UART interrupt level into the GIC. Called at batch
    /// boundaries to pick up console input queued by the VMM.
    fn sync_uart_irq(&self) {
        let (Some(gic), Some(uart)) = (self.late.gic.get(), self.late.uart.get()) else {
            return;
        };
        let level = uart.lock().map(|u| u.irq_pending()).unwrap_or(false);
        if let Ok(mut gic) = gic.lock() {
            if level {
                gic.set_pending(AARCH64_UART_IRQ);
            } else {
                gic.clear_pending(AARCH64_UART_IRQ);
            }
        }
    }
}

#[path = "aarch64_step.rs"]
mod stepping;

#[path = "aarch64/vcpu.rs"]
mod vcpu;

#[cfg(test)]
#[path = "aarch64_user_tests.rs"]
mod user_tests;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use vm_memory::{GuestAddress, GuestMemoryMmap};

    use super::*;
    use crate::isa::arm::cpu_trait::ArmCpu;
    use crate::vm::vcpu::{Aarch64Registers, Aarch64SystemRegisters, CpuState, VcpuExit};

    fn test_vcpu() -> Aarch64Vcpu {
        let mem =
            Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
        Aarch64Vcpu::new(0, mem)
    }

    #[test]
    fn fault_exit_preserves_system_delivery_for_other_events() {
        for micro in [false, true] {
            let mem = Arc::new(
                GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
            );
            let mut vcpu = if micro {
                Aarch64Vcpu::new_micro(0, mem)
            } else {
                Aarch64Vcpu::new(0, mem)
            };
            // SVC still enters the architectural vector in either mode.
            write_insns(&mut vcpu, &[0xd400_0001]);
            assert!(vcpu.step_insn().unwrap().is_none());
            assert_eq!(vcpu.cpu.get_pc(), 0x200);
        }
    }

    #[test]
    fn ordinary_machine_delivers_unmapped_fault_to_guest() {
        let mut vcpu = test_vcpu();
        write_insns(&mut vcpu, &[0xf940_0020]); // LDR X0,[X1]
        vcpu.cpu.set_gpr(1, 0x200_0000);
        assert!(vcpu.step_insn().unwrap().is_none());
        assert_eq!(vcpu.cpu.get_pc(), 0x200);
    }

    fn write_insns(vcpu: &mut Aarch64Vcpu, insns: &[u32]) {
        for (i, insn) in insns.iter().enumerate() {
            vcpu.cpu
                .write_memory((i * 4) as u64, &insn.to_le_bytes())
                .unwrap();
        }
    }

    fn encode_mrs(rt: u8, op0: u8, op1: u8, crn: u8, crm: u8, op2: u8) -> u32 {
        (0x354 << 22)
            | (1 << 21)
            | ((op0 as u32) << 19)
            | ((op1 as u32) << 16)
            | ((crn as u32) << 12)
            | ((crm as u32) << 8)
            | ((op2 as u32) << 5)
            | rt as u32
    }

    fn encode_msr(rt: u8, op0: u8, op1: u8, crn: u8, crm: u8, op2: u8) -> u32 {
        (0x354 << 22)
            | ((op0 as u32) << 19)
            | ((op1 as u32) << 16)
            | ((crn as u32) << 12)
            | ((crm as u32) << 8)
            | ((op2 as u32) << 5)
            | rt as u32
    }

    fn hlt() -> u32 {
        0xd440_0000
    }

    fn tpidr_el0(rt: u8) -> u32 {
        encode_mrs(rt, 3, 3, 13, 0, 2)
    }

    fn tpidrro_el0(rt: u8) -> u32 {
        encode_mrs(rt, 3, 3, 13, 0, 3)
    }

    fn msr_tpidr_el0(rt: u8) -> u32 {
        encode_msr(rt, 3, 3, 13, 0, 2)
    }

    #[test]
    fn set_state_round_trips_modeled_sregs() {
        let mut vcpu = test_vcpu();
        let mut regs = Aarch64Registers::default();
        regs.pc = 0x1000;
        regs.sp = 0x8000;
        regs.x[0] = 0x1234;
        regs.v[0] = [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210];
        regs.v[31] = [0xa5a5_a5a5_a5a5_a5a5, 0x5a5a_5a5a_5a5a_5a5a];
        regs.fpcr = 1 << 24;
        regs.fpsr = 1 << 27;

        let mut sregs = Aarch64SystemRegisters::default();
        sregs.sctlr_el1 = 0x2;
        sregs.tcr_el1 = 0x8080_3518;
        sregs.ttbr0_el1 = 0x4000_0000;
        sregs.ttbr1_el1 = 0xffff_0000_4000_0000;
        sregs.mair_el1 = 0xff00_0400;
        sregs.vbar_el1 = 0xffff_0000_0000_0000;
        sregs.esr_el1 = 0x9600_0004;
        sregs.far_el1 = 0xdead_beef_cafe_babe;
        sregs.elr_el1 = 0xffff_0000_0000_1000;
        sregs.spsr_el1 = 0x3c5;
        sregs.sp_el0 = 0x7000;
        sregs.sp_el1 = regs.sp;
        sregs.tpidr_el0 = 0x1111_2222_3333_4444;
        sregs.tpidr_el1 = 0x5555_6666_7777_8888;
        sregs.tpidrro_el0 = 0x9999_aaaa_bbbb_cccc;
        sregs.cntp_ctl_el0 = 0x3;
        sregs.cntp_cval_el0 = 0x1234_5678_9abc_def0;
        sregs.cntv_ctl_el0 = 0x1;
        sregs.cntv_cval_el0 = 0x0fed_cba9_8765_4321;

        vcpu.set_state(&CpuState::aarch64(regs, sregs.clone()))
            .unwrap();

        let CpuState::Aarch64(state) = vcpu.get_state().unwrap() else {
            panic!("expected aarch64 state");
        };

        assert_eq!(state.regs.x[0], 0x1234);
        assert_eq!(state.regs.pc, 0x1000);
        assert_eq!(state.regs.sp, 0x8000);
        assert_eq!(
            state.regs.v[0],
            [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210]
        );
        assert_eq!(
            state.regs.v[31],
            [0xa5a5_a5a5_a5a5_a5a5, 0x5a5a_5a5a_5a5a_5a5a]
        );
        assert_eq!(state.regs.fpcr, 1 << 24);
        assert_eq!(state.regs.fpsr, 1 << 27);
        assert_eq!(state.sregs.sctlr_el1, sregs.sctlr_el1);
        assert_eq!(state.sregs.tcr_el1, sregs.tcr_el1);
        assert_eq!(state.sregs.ttbr0_el1, sregs.ttbr0_el1);
        assert_eq!(state.sregs.ttbr1_el1, sregs.ttbr1_el1);
        assert_eq!(state.sregs.mair_el1, sregs.mair_el1);
        assert_eq!(state.sregs.vbar_el1, sregs.vbar_el1);
        assert_eq!(state.sregs.esr_el1, sregs.esr_el1);
        assert_eq!(state.sregs.far_el1, sregs.far_el1);
        assert_eq!(state.sregs.elr_el1, sregs.elr_el1);
        assert_eq!(state.sregs.spsr_el1, sregs.spsr_el1);
        assert_eq!(state.sregs.sp_el0, sregs.sp_el0);
        assert_eq!(state.sregs.sp_el1, sregs.sp_el1);
        assert_eq!(state.sregs.tpidr_el0, sregs.tpidr_el0);
        assert_eq!(state.sregs.tpidr_el1, sregs.tpidr_el1);
        assert_eq!(state.sregs.tpidrro_el0, sregs.tpidrro_el0);
        assert_eq!(state.sregs.cntp_ctl_el0, sregs.cntp_ctl_el0);
        assert_eq!(state.sregs.cntp_cval_el0, sregs.cntp_cval_el0);
        assert_eq!(state.sregs.cntv_ctl_el0, sregs.cntv_ctl_el0);
        assert_eq!(state.sregs.cntv_cval_el0, sregs.cntv_cval_el0);
    }

    #[test]
    fn seeded_thread_id_registers_are_guest_visible() {
        let mut vcpu = test_vcpu();
        write_insns(&mut vcpu, &[tpidr_el0(5), tpidrro_el0(6), hlt()]);

        let regs = Aarch64Registers::default();
        let mut sregs = Aarch64SystemRegisters::default();
        sregs.tpidr_el0 = 0x1111_2222_3333_4444;
        sregs.tpidrro_el0 = 0x5555_6666_7777_8888;
        vcpu.set_state(&CpuState::aarch64(regs, sregs)).unwrap();

        assert!(matches!(vcpu.run().unwrap(), VcpuExit::Shutdown));
        let CpuState::Aarch64(state) = vcpu.get_state().unwrap() else {
            panic!("expected aarch64 state");
        };
        assert_eq!(state.regs.x[5], 0x1111_2222_3333_4444);
        assert_eq!(state.regs.x[6], 0x5555_6666_7777_8888);
    }

    #[test]
    fn guest_thread_id_writes_are_reflected_in_state() {
        let mut vcpu = test_vcpu();
        write_insns(&mut vcpu, &[msr_tpidr_el0(1), tpidr_el0(2), hlt()]);

        let mut regs = Aarch64Registers::default();
        regs.x[1] = 0xfeed_face_cafe_beef;
        vcpu.set_state(&CpuState::aarch64(regs, Aarch64SystemRegisters::default()))
            .unwrap();

        assert!(matches!(vcpu.run().unwrap(), VcpuExit::Shutdown));
        let CpuState::Aarch64(state) = vcpu.get_state().unwrap() else {
            panic!("expected aarch64 state");
        };
        assert_eq!(state.regs.x[2], 0xfeed_face_cafe_beef);
        assert_eq!(state.sregs.tpidr_el0, 0xfeed_face_cafe_beef);
    }
}
