//! S5L8900 (iPod Touch 1G / iPhone 1) vCPU: boots Apple's iBoot on the
//! software ARMv6 emulator.
//!
//! Drives the AArch32 [`Armv7Cpu`] + [`Executor`] over guest memory with the
//! S5L8900 platform device set (clock, timer, PL192 VIC pair, SYSIC, GPIO,
//! chip-ID, UART, 8900 crypto engine) served at their physical MMIO windows.
//! Firmware (bootrom, iBoot, NOR) and the bootrom-call patches are placed in
//! guest RAM by the arch boot setup; the CPU resets to IBOOT_BASE.

use std::cell::RefCell;
use std::sync::{Arc, Mutex, OnceLock};

use tracing::debug;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use crate::arm::execution::{ArmMemory, MemoryError};
use crate::arm::mmu_v6::{self, V6Access, V6Fault, V6MmuConfig};
use crate::arm::{
    Armv7Cpu, Decoder, ExceptionType, ExecResult, ExecutionState, Executor, ProcessorMode,
};
use crate::cpu::{
    Aarch32CpuState, Aarch32Registers, Aarch32SystemRegisters, CpuState, VCpu, VcpuExit,
};
use crate::devices::s3c64xx::S3cUart;
use crate::devices::s5l8900::{
    Pl192, S5lChipId, S5lClock, S5lGpio, S5lI2c, S5lSysic, S5lTimer,
};
use crate::error::{Error, Result};

// Device MMIO base addresses (see the QEMU iPod Touch 1G reference).
const CLOCK0_BASE: u32 = 0x3810_0000;
const CLOCK1_BASE: u32 = 0x3C50_0000;
const VIC0_BASE: u32 = 0x38E0_0000;
const VIC1_BASE: u32 = 0x38E0_1000;
const SYSIC_BASE: u32 = 0x39A0_0000;
const TIMER1_BASE: u32 = 0x3E20_0000;
const GPIO_BASE: u32 = 0x3E40_0000;
const CHIPID_BASE: u32 = 0x3E50_0000;
const UART0_BASE: u32 = 0x3CC0_0000;
const I2C0_BASE: u32 = 0x3C60_0000;
const I2C1_BASE: u32 = 0x3C90_0000;
const ENGINE_8900_BASE: u32 = 0x3F00_0000;

const IBOOT_BASE: u32 = 0x1800_0000;
const LLB_BASE: u32 = 0x2200_0000;

// IRQ line numbers on VIC0.
const TIMER1_IRQ: u32 = 0x7;
const UART0_IRQ: u32 = 24;

/// Instructions per `run()` batch before yielding to the VMM loop.
const BATCH: u32 = 65_536;

/// Last memory fault recorded by the bridge (for DFSR/DFAR reporting).
#[derive(Clone, Copy, Default)]
struct LastFault {
    addr: u32,
    fsr: u32,
    domain: u32,
    access: u32,
}

/// Mutable bridge internals (RefCell: the executor's read path is `&self`).
struct BridgeInner {
    mmu: V6MmuConfig,
    privileged: bool,
    last_fault: LastFault,
    clock0: S5lClock,
    clock1: S5lClock,
    vic0: Pl192,
    vic1: Pl192,
    sysic: S5lSysic,
    gpio: S5lGpio,
    timer: S5lTimer,
    i2c0: S5lI2c,
    i2c1: S5lI2c,
    uart: Arc<OnceLock<Arc<Mutex<S3cUart>>>>,
    /// Pending 8900-engine decryption request: the physical address of the
    /// image header written to the engine MMIO. Serviced by the vCPU step.
    engine_8900_req: Option<u32>,
    /// Budget-limited log of accesses to unmapped MMIO windows.
    openbus_log_budget: u32,
}

/// Memory bridge: VA→PA via the v6 MMU, S5L8900 device windows at their
/// physical addresses, everything else through the flat guest memory (which
/// backs RAM, iBoot, VROM, LLB and NOR).
struct S5lBridge {
    mem: Arc<GuestMemoryMmap>,
    inner: RefCell<BridgeInner>,
}

impl S5lBridge {
    fn translate(
        mem: &GuestMemoryMmap,
        inner: &mut BridgeInner,
        va: u32,
        access: V6Access,
    ) -> std::result::Result<u32, MemoryError> {
        let walk = |pa: u32| -> Option<u32> {
            let mut buf = [0u8; 4];
            mem.read_slice(&mut buf, GuestAddress(pa as u64)).ok()?;
            Some(u32::from_le_bytes(buf))
        };
        match mmu_v6::translate_v6(&inner.mmu, va, inner.privileged, access, walk) {
            Ok(t) => Ok(t.pa),
            Err(V6Fault { fsr, domain }) => {
                inner.last_fault = LastFault {
                    addr: va,
                    fsr,
                    domain,
                    access: match access {
                        V6Access::Read => 0,
                        V6Access::Write => 1,
                        V6Access::Execute => 2,
                    } | if inner.privileged { 4 } else { 0 },
                };
                Err(MemoryError::PermissionDenied(va))
            }
        }
    }
}

impl BridgeInner {
    /// Device-window read at a PHYSICAL address. Returns None when the address
    /// is plain memory (RAM/firmware) and should fall through to the mmap.
    fn dev_read(&mut self, pa: u32) -> Option<u32> {
        let off = |base: u32| pa - base;
        match pa {
            _ if (CLOCK0_BASE..CLOCK0_BASE + 0x1000).contains(&pa) => {
                Some(self.clock0.read(off(CLOCK0_BASE)))
            }
            _ if (CLOCK1_BASE..CLOCK1_BASE + 0x1000).contains(&pa) => {
                Some(self.clock1.read(off(CLOCK1_BASE)))
            }
            _ if (VIC0_BASE..VIC0_BASE + 0x1000).contains(&pa) => {
                Some(self.vic0.read(off(VIC0_BASE)))
            }
            _ if (VIC1_BASE..VIC1_BASE + 0x1000).contains(&pa) => {
                Some(self.vic1.read(off(VIC1_BASE)))
            }
            _ if (SYSIC_BASE..SYSIC_BASE + 0x1000).contains(&pa) => {
                Some(self.sysic.read(off(SYSIC_BASE)))
            }
            _ if (TIMER1_BASE..TIMER1_BASE + 0x10004).contains(&pa) => {
                Some(self.timer.read(off(TIMER1_BASE)))
            }
            _ if (GPIO_BASE..GPIO_BASE + 0x10000).contains(&pa) => {
                Some(self.gpio.read(off(GPIO_BASE)))
            }
            _ if (CHIPID_BASE..CHIPID_BASE + 0x10).contains(&pa) => {
                Some(S5lChipId::read(off(CHIPID_BASE)))
            }
            _ if (I2C0_BASE..I2C0_BASE + 0x1000).contains(&pa) => {
                Some(self.i2c0.read(off(I2C0_BASE)))
            }
            _ if (I2C1_BASE..I2C1_BASE + 0x1000).contains(&pa) => {
                Some(self.i2c1.read(off(I2C1_BASE)))
            }
            _ if (UART0_BASE..UART0_BASE + 0x1000).contains(&pa) => Some(
                self.uart
                    .get()
                    .and_then(|u| u.lock().ok().map(|mut u| u.read(off(UART0_BASE))))
                    .unwrap_or(0),
            ),
            _ if (ENGINE_8900_BASE..ENGINE_8900_BASE + 0x100).contains(&pa) => Some(0),
            // Plain memory.
            _ if is_memory(pa) => None,
            // Unmapped MMIO: open bus (read as zero).
            _ => {
                if self.openbus_log_budget > 0 {
                    self.openbus_log_budget -= 1;
                    debug!(pa = format!("{pa:#x}"), "openbus read");
                }
                Some(0)
            }
        }
    }

    /// Device-window write. Returns true if the write was consumed by a device
    /// (or open bus); false if it should fall through to plain memory.
    fn dev_write(&mut self, pa: u32, value: u32) -> bool {
        let off = |base: u32| pa - base;
        match pa {
            _ if (CLOCK0_BASE..CLOCK0_BASE + 0x1000).contains(&pa) => {
                self.clock0.write(off(CLOCK0_BASE), value);
                true
            }
            _ if (CLOCK1_BASE..CLOCK1_BASE + 0x1000).contains(&pa) => {
                self.clock1.write(off(CLOCK1_BASE), value);
                true
            }
            _ if (VIC0_BASE..VIC0_BASE + 0x1000).contains(&pa) => {
                self.vic0.write(off(VIC0_BASE), value);
                true
            }
            _ if (VIC1_BASE..VIC1_BASE + 0x1000).contains(&pa) => {
                self.vic1.write(off(VIC1_BASE), value);
                true
            }
            _ if (SYSIC_BASE..SYSIC_BASE + 0x1000).contains(&pa) => {
                self.sysic.write(off(SYSIC_BASE), value);
                true
            }
            _ if (TIMER1_BASE..TIMER1_BASE + 0x10004).contains(&pa) => {
                self.timer.write(off(TIMER1_BASE), value);
                true
            }
            _ if (GPIO_BASE..GPIO_BASE + 0x10000).contains(&pa) => {
                self.gpio.write(off(GPIO_BASE), value);
                true
            }
            _ if (CHIPID_BASE..CHIPID_BASE + 0x10).contains(&pa) => true,
            _ if (I2C0_BASE..I2C0_BASE + 0x1000).contains(&pa) => {
                self.i2c0.write(off(I2C0_BASE), value);
                true
            }
            _ if (I2C1_BASE..I2C1_BASE + 0x1000).contains(&pa) => {
                self.i2c1.write(off(I2C1_BASE), value);
                true
            }
            _ if (UART0_BASE..UART0_BASE + 0x1000).contains(&pa) => {
                if let Some(u) = self.uart.get() {
                    if let Ok(mut u) = u.lock() {
                        u.write(off(UART0_BASE), value);
                    }
                }
                true
            }
            _ if (ENGINE_8900_BASE..ENGINE_8900_BASE + 0x100).contains(&pa) => {
                // Writing the image header address to offset 0 triggers
                // in-place AES-CBC decryption (serviced by the vCPU step).
                if off(ENGINE_8900_BASE) == 0 {
                    self.engine_8900_req = Some(value);
                }
                true
            }
            _ if is_memory(pa) => false,
            _ => {
                if self.openbus_log_budget > 0 {
                    self.openbus_log_budget -= 1;
                    debug!(pa = format!("{pa:#x}"), val = format!("{value:#x}"), "openbus write");
                }
                true
            }
        }
    }

    fn read_pa(
        &mut self,
        mem: &GuestMemoryMmap,
        pa: u32,
        buf: &mut [u8],
    ) -> std::result::Result<(), MemoryError> {
        if buf.len() <= 4 && !is_memory(pa) {
            if let Some(v) = self.dev_read(pa & !0x3) {
                let lane = (pa & 0x3) as usize;
                let bytes = v.to_le_bytes();
                for (i, b) in buf.iter_mut().enumerate() {
                    *b = *bytes.get(lane + i).unwrap_or(&0);
                }
                return Ok(());
            }
        }
        mem.read_slice(buf, GuestAddress(pa as u64))
            .map_err(|_| MemoryError::BusError(pa))
    }

    fn write_pa(
        &mut self,
        mem: &GuestMemoryMmap,
        pa: u32,
        data: &[u8],
    ) -> std::result::Result<(), MemoryError> {
        if data.len() <= 4 && !is_memory(pa) {
            let reg = pa & !0x3;
            let lane = (pa & 0x3) as usize;
            let mut cur = self.dev_read(reg).unwrap_or(0).to_le_bytes();
            for (i, b) in data.iter().enumerate() {
                if lane + i < 4 {
                    cur[lane + i] = *b;
                }
            }
            if self.dev_write(reg, u32::from_le_bytes(cur)) {
                return Ok(());
            }
        }
        mem.write_slice(data, GuestAddress(pa as u64))
            .map_err(|_| MemoryError::BusError(pa))
    }
}

/// Whether a physical address is plain memory (RAM/firmware/NOR), as opposed
/// to a device MMIO window. The S5L8900 devices all live in 0x38000000..
/// 0x40000000; everything below 0x38000000 and the NOR window are memory.
fn is_memory(pa: u32) -> bool {
    !(0x3800_0000..0x4000_0000).contains(&pa)
}

impl S5lBridge {
    fn access(
        &self,
        addr: u32,
        access: V6Access,
        data: Option<&[u8]>,
        out: Option<&mut [u8]>,
    ) -> std::result::Result<(), MemoryError> {
        let mut inner = self.inner.borrow_mut();
        let pa = Self::translate(&self.mem, &mut inner, addr, access)?;
        if let Some(buf) = out {
            inner.read_pa(&self.mem, pa, buf)
        } else if let Some(d) = data {
            inner.write_pa(&self.mem, pa, d)
        } else {
            Ok(())
        }
    }
}

impl ArmMemory for S5lBridge {
    fn read_word(&self, addr: u32) -> std::result::Result<u32, MemoryError> {
        let mut b = [0u8; 4];
        self.access(addr, V6Access::Read, None, Some(&mut b))?;
        Ok(u32::from_le_bytes(b))
    }

    fn read_halfword(&self, addr: u32) -> std::result::Result<u16, MemoryError> {
        let mut b = [0u8; 2];
        self.access(addr, V6Access::Read, None, Some(&mut b))?;
        Ok(u16::from_le_bytes(b))
    }

    fn read_byte(&self, addr: u32) -> std::result::Result<u8, MemoryError> {
        let mut b = [0u8; 1];
        self.access(addr, V6Access::Read, None, Some(&mut b))?;
        Ok(b[0])
    }

    fn write_word(&mut self, addr: u32, value: u32) -> std::result::Result<(), MemoryError> {
        self.access(addr, V6Access::Write, Some(&value.to_le_bytes()), None)
    }

    fn write_halfword(&mut self, addr: u32, value: u16) -> std::result::Result<(), MemoryError> {
        self.access(addr, V6Access::Write, Some(&value.to_le_bytes()), None)
    }

    fn write_byte(&mut self, addr: u32, value: u8) -> std::result::Result<(), MemoryError> {
        self.access(addr, V6Access::Write, Some(&[value]), None)
    }
}

/// S5L8900 vCPU backed by the AArch32 interpreter.
pub struct S5L8900Vcpu {
    id: u32,
    cpu: Armv7Cpu,
    bridge: S5lBridge,
    decoder: Decoder,
    uart: Arc<OnceLock<Arc<Mutex<S3cUart>>>>,
    insn_count: u64,
    excl: crate::arm::instructions::ExclusiveMonitor,
    pc_ring: [u32; 512],
    pc_ring_idx: usize,
    zero_slide: u32,
    trace_pcs: Vec<u32>,
    trace_log_budget: u32,
    fault_log_budget: u32,
    last_heartbeat: std::time::Instant,
    shutdown: bool,
}

enum StepOutcome {
    Progress,
    Idle,
}

impl S5L8900Vcpu {
    pub fn new(id: u32, mem: Arc<GuestMemoryMmap>) -> Self {
        // The console UART is provided by the VMM via attach_s3c_uart() so that
        // host stdin feeds the same instance the bridge serves.
        let uart = Arc::new(OnceLock::new());
        let bridge = S5lBridge {
            mem,
            inner: RefCell::new(BridgeInner {
                mmu: V6MmuConfig::default(),
                privileged: true,
                last_fault: LastFault::default(),
                clock0: S5lClock::new(),
                clock1: S5lClock::new(),
                vic0: Pl192::new(),
                vic1: Pl192::new(),
                sysic: S5lSysic::new(),
                gpio: S5lGpio::new(),
                timer: S5lTimer::new(),
                i2c0: S5lI2c::new(false),
                i2c1: S5lI2c::new(true), // PMU (pcf50633) lives on I2C1
                uart: uart.clone(),
                engine_8900_req: None,
                openbus_log_budget: 256,
            }),
        };
        let mut cpu = Armv7Cpu::new();
        // ARM1176JZF-S (ARMv6K), the S5L8900 core.
        cpu.cp15.midr = 0x410F_B767;
        cpu.cp15.ctr = 0x1D15_2152;
        S5L8900Vcpu {
            id,
            cpu,
            bridge,
            decoder: Decoder::new_aarch32(),
            uart,
            insn_count: 0,
            excl: crate::arm::instructions::ExclusiveMonitor::default(),
            pc_ring: [0; 512],
            pc_ring_idx: 0,
            zero_slide: 0,
            trace_pcs: std::env::var("RAX_TRACE_PC")
                .ok()
                .map(|v| {
                    v.split(',')
                        .filter_map(|a| u32::from_str_radix(a.trim_start_matches("0x"), 16).ok())
                        .collect()
                })
                .unwrap_or_default(),
            trace_log_budget: 400,
            fault_log_budget: 64,
            last_heartbeat: std::time::Instant::now(),
            shutdown: false,
        }
    }

    fn sync_mmu(&mut self) {
        let cp = &self.cpu.cp15;
        let mut inner = self.bridge.inner.borrow_mut();
        inner.mmu = V6MmuConfig {
            enabled: cp.sctlr.m(),
            ttbr0: cp.ttbr0 as u32,
            ttbr1: cp.ttbr1 as u32,
            ttbcr_n: cp.ttbcr & 0x7,
            dacr: cp.dacr,
            afe: false,
        };
        inner.privileged = self.cpu.cpsr.mode != ProcessorMode::User as u8;
    }

    /// Recompute VIC line levels from device state; return CPU IRQ assertion.
    fn sync_irqs(&mut self) -> bool {
        let uart_lvl = self
            .uart
            .get()
            .and_then(|u| u.lock().ok().map(|u| u.irq_pending()))
            .unwrap_or(false);
        let mut inner = self.bridge.inner.borrow_mut();
        let timer_lvl = inner.timer.irq_pending();
        inner.vic0.set_line(TIMER1_IRQ, timer_lvl);
        inner.vic0.set_line(UART0_IRQ, uart_lvl);
        // VIC1 daisy-chains into VIC0.
        let daisy = inner.vic1.irq_asserted();
        inner.vic0.daisy_input = daisy;
        inner.vic0.update();
        inner.vic0.irq_asserted()
    }

    fn take_exception(&mut self, exc: ExceptionType) {
        let vbar = self.cpu.cp15.sctlr.vector_base();
        let mut exec = Executor::with_vbar(&mut self.cpu, &mut self.bridge, vbar);
        exec.take_exception(exc);
    }

    /// Service a pending 8900-engine decryption request, if any.
    fn service_engine_8900(&mut self) {
        let req = self.bridge.inner.borrow_mut().engine_8900_req.take();
        if let Some(addr) = req {
            self.decrypt_8900(addr);
        }
    }

    fn step(&mut self) -> StepOutcome {
        self.sync_mmu();
        self.bridge.inner.borrow_mut().timer.tick(1);

        let irq_pending = self.sync_irqs();
        if irq_pending {
            self.cpu.is_halted = false;
        }
        if irq_pending && !self.cpu.cpsr.i {
            self.take_exception(ExceptionType::Irq);
            return StepOutcome::Progress;
        }

        if self.cpu.is_halted {
            self.bridge.inner.borrow_mut().timer.tick(256);
            return StepOutcome::Idle;
        }

        let pc = self.cpu.regs[15];
        self.pc_ring[self.pc_ring_idx] = pc;
        self.pc_ring_idx = (self.pc_ring_idx + 1) % self.pc_ring.len();
        let is_thumb = self.cpu.cpsr.t;

        let mut insn_len = 4u32;
        // Decode bytes in MEMORY order (the decoder reads hw1 from bytes[0..2],
        // hw2 from bytes[2..4]). For ARM and 16-bit Thumb this is just the
        // little-endian word/halfword.
        let mut decode_bytes = [0u8; 4];
        let raw = if is_thumb {
            let hw1 = match self.bridge.read_halfword(pc) {
                Ok(v) => v,
                Err(_) => return self.prefetch_abort(pc),
            };
            decode_bytes[0..2].copy_from_slice(&hw1.to_le_bytes());
            if (hw1 >> 11) >= 0x1D {
                let hw2 = match self.bridge.read_halfword(pc.wrapping_add(2)) {
                    Ok(v) => v,
                    Err(_) => return self.prefetch_abort(pc),
                };
                decode_bytes[2..4].copy_from_slice(&hw2.to_le_bytes());
                ((hw1 as u32) << 16) | hw2 as u32
            } else {
                insn_len = 2;
                hw1 as u32
            }
        } else {
            let w = match self.bridge.read_word(pc) {
                Ok(v) => v,
                Err(_) => return self.prefetch_abort(pc),
            };
            decode_bytes.copy_from_slice(&w.to_le_bytes());
            w
        };

        // Derail detector: a long run of all-zero instruction words means the
        // CPU has branched into zeroed memory. Dump the recent PC history so
        // the bad branch can be located, then stop.
        if raw == 0 && pc < 0x1800_0000 {
            self.zero_slide += 1;
            if self.zero_slide == 48 && std::env::var("RAX_S5L_DERAIL").is_ok() {
                let mut trail = Vec::new();
                for i in 0..self.pc_ring.len() {
                    let idx = (self.pc_ring_idx + i) % self.pc_ring.len();
                    let p = self.pc_ring[idx];
                    if p >= 0x1800_0000 {
                        trail.push(format!("{p:#x}"));
                    }
                }
                debug!(trail = trail.join(" "), insns = self.insn_count, "derail trail");
                self.shutdown = true;
                return StepOutcome::Idle;
            }
        } else {
            self.zero_slide = 0;
        }

        if std::env::var("RAX_S5L_TRACE").is_ok() {
            debug!(
                pc = format!("{pc:#x}"),
                raw = format!("{raw:#010x}"),
                insns = self.insn_count,
                "insn"
            );
        }
        if self.trace_pcs.contains(&pc) && self.trace_log_budget > 0 {
            self.trace_log_budget -= 1;
            let regs: Vec<String> =
                (0..16).map(|i| format!("r{i}={:#x}", self.cpu.regs[i])).collect();
            debug!(
                regs = regs.join(" "),
                cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
                insns = self.insn_count,
                "trace-pc hit"
            );
        }

        let state = if is_thumb {
            ExecutionState::Thumb
        } else {
            ExecutionState::Aarch32
        };
        let slice: &[u8] = if insn_len == 2 {
            &decode_bytes[..2]
        } else {
            &decode_bytes
        };
        self.decoder.set_state(state);
        let insn = match self.decoder.decode(slice) {
            Ok(i) => i,
            Err(_) => {
                self.take_exception(ExceptionType::UndefinedInstruction);
                return StepOutcome::Progress;
            }
        };

        let vbar = self.cpu.cp15.sctlr.vector_base();
        let mut exec = Executor::with_vbar(&mut self.cpu, &mut self.bridge, vbar);
        exec.exclusive_monitor = self.excl.clone();
        let result = exec.execute(&insn);
        self.excl = exec.exclusive_monitor.clone();
        self.insn_count += 1;

        // Service any decryption request the just-executed store triggered.
        if self.bridge.inner.borrow().engine_8900_req.is_some() {
            self.service_engine_8900();
        }

        match result {
            ExecResult::Continue => {
                self.cpu.regs[15] = self.cpu.regs[15].wrapping_add(insn_len);
                if self.cpu.cpsr.in_it_block() {
                    self.cpu.cpsr.advance_it_state();
                }
                StepOutcome::Progress
            }
            ExecResult::Branch(target) => {
                if target & 1 != 0 {
                    self.cpu.cpsr.t = true;
                    self.cpu.regs[15] = target & !1;
                } else {
                    self.cpu.regs[15] = target;
                }
                StepOutcome::Progress
            }
            ExecResult::Exception(exc) => {
                self.take_exception(exc);
                StepOutcome::Progress
            }
            ExecResult::Halt => {
                self.cpu.is_halted = true;
                StepOutcome::Idle
            }
            ExecResult::Undefined => {
                self.take_exception(ExceptionType::UndefinedInstruction);
                StepOutcome::Progress
            }
            ExecResult::MemoryFault(_) => {
                let f = self.bridge.inner.borrow().last_fault;
                if self.fault_log_budget > 0 {
                    self.fault_log_budget -= 1;
                    debug!(
                        pc = format!("{:#x}", self.cpu.regs[15]),
                        addr = format!("{:#x}", f.addr),
                        fsr = format!("{:#x}", f.fsr),
                        insns = self.insn_count,
                        "data abort"
                    );
                }
                self.cpu.cp15.dfsr =
                    f.fsr | (f.domain << 4) | if f.access & 3 == 1 { 1 << 11 } else { 0 };
                self.cpu.cp15.dfar = f.addr;
                self.take_exception(ExceptionType::DataAbort(f.addr));
                StepOutcome::Progress
            }
        }
    }

    fn prefetch_abort(&mut self, pc: u32) -> StepOutcome {
        let f = self.bridge.inner.borrow().last_fault;
        if self.fault_log_budget > 0 {
            self.fault_log_budget -= 1;
            debug!(
                pc = format!("{pc:#x}"),
                fsr = format!("{:#x}", f.fsr),
                lr = format!("{:#x}", self.cpu.regs[14]),
                insns = self.insn_count,
                "prefetch abort"
            );
        }
        self.cpu.cp15.ifsr = f.fsr | (f.domain << 4);
        self.cpu.cp15.ifar = pc;
        self.take_exception(ExceptionType::PrefetchAbort(pc));
        StepOutcome::Progress
    }

    fn heartbeat(&mut self) {
        if self.last_heartbeat.elapsed() >= std::time::Duration::from_secs(2) {
            debug!(
                insns = self.insn_count,
                pc = format!("{:#x}", self.cpu.regs[15]),
                lr = format!("{:#x}", self.cpu.regs[14]),
                cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
                mmu = self.bridge.inner.borrow().mmu.enabled,
                "s5l8900 emulator heartbeat"
            );
            // Debug aid: dump the LCD framebuffer (physical 0x0fe00000,
            // 320x480 BGRA) to a file so the rendered boot image can be
            // inspected. Gated by RAX_S5L_FBDUMP=<path>.
            if let Ok(path) = std::env::var("RAX_S5L_FBDUMP") {
                let mut buf = vec![0u8; 320 * 480 * 4];
                if self
                    .bridge
                    .mem
                    .read_slice(&mut buf, GuestAddress(0x0fe0_0000))
                    .is_ok()
                {
                    let _ = std::fs::write(&path, &buf);
                }
            }
            self.last_heartbeat = std::time::Instant::now();
        }
    }
}

impl VCpu for S5L8900Vcpu {
    fn run(&mut self) -> Result<VcpuExit> {
        if self.shutdown {
            return Ok(VcpuExit::Shutdown);
        }
        for _ in 0..BATCH {
            match self.step() {
                StepOutcome::Progress => {}
                StepOutcome::Idle => {
                    self.heartbeat();
                    return Ok(VcpuExit::Hlt);
                }
            }
        }
        self.heartbeat();
        Ok(VcpuExit::Hlt)
    }

    fn get_state(&self) -> Result<CpuState> {
        let mut regs = Aarch32Registers::default();
        for i in 0..13 {
            regs.r[i] = self.cpu.regs[i];
        }
        regs.sp = self.cpu.regs[13];
        regs.lr = self.cpu.regs[14];
        regs.pc = self.cpu.regs[15];
        regs.cpsr = self.cpu.cpsr.to_u32();
        Ok(CpuState::Aarch32(Aarch32CpuState {
            regs,
            sregs: Aarch32SystemRegisters::default(),
        }))
    }

    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        let state = match state {
            CpuState::Aarch32(s) => s,
            _ => {
                return Err(Error::Emulator(
                    "expected aarch32 state for s5l8900 vCPU".to_string(),
                ));
            }
        };
        let cpsr = crate::arm::Psr::from_u32(state.regs.cpsr);
        if let Some(mode) = ProcessorMode::from_bits(cpsr.mode) {
            self.cpu.change_mode(mode);
        }
        for i in 0..13 {
            self.cpu.regs[i] = state.regs.r[i];
        }
        self.cpu.regs[13] = state.regs.sp;
        self.cpu.regs[14] = state.regs.lr;
        self.cpu.regs[15] = state.regs.pc;
        self.cpu.cpsr = cpsr;
        Ok(())
    }

    fn complete_io_in(&mut self, _data: &[u8]) {}

    fn attach_s3c_uart(
        &mut self,
        uart: std::sync::Arc<std::sync::Mutex<crate::devices::s3c64xx::S3cUart>>,
    ) {
        // The S5L8900 UART is register-compatible with the Samsung s3c UART,
        // so it reuses the VMM's console plumbing (host stdin → guest serial).
        let _ = self.uart.set(uart);
    }

    fn id(&self) -> u32 {
        self.id
    }

    fn instruction_count(&self) -> u64 {
        self.insn_count
    }
}

impl S5L8900Vcpu {
    /// Service an 8900-engine in-place AES-CBC decryption request. `addr` is
    /// the physical address of the 8900 image header; the body that follows
    /// is decrypted in place. Currently a logged no-op — the bootrom-call
    /// patch already reports success, so iBoot's verification proceeds; real
    /// decryption is added when an encrypted image is actually loaded.
    fn decrypt_8900(&mut self, addr: u32) {
        if self.fault_log_budget > 0 {
            self.fault_log_budget -= 1;
            debug!(addr = format!("{addr:#x}"), "8900 decrypt request (stub)");
        }
    }
}
