//! AArch64 CPU Implementation
//!
//! This module implements a complete AArch64 CPU emulator supporting:
//! - All exception levels (EL0-EL3)
//! - Full system register set
//! - MMU with page table walks
//! - GIC interrupt controller
//! - All ARMv8/v9 instruction categories

use std::collections::HashSet;
use std::fmt::Debug;

use super::exceptions::{
    ExceptionType, SyndromeRegister, build_spsr, exception_target_el, parse_spsr, vector_offset,
};
use super::gic::{Gic, GicConfig};
use super::mmu::{Mmu, MmuConfig, TranslationFault, TranslationGranule};
use super::sysregs::SystemRegisters;
use super::{NUM_ELS, NUM_GPRS, NUM_SIMD_REGS, sctlr};

use crate::isa::arm::common::cpu::{
    ArmCpu, ArmError, ArmException, ArmProfile, ArmVersion, CpuExit, MemoryFaultInfo,
    MemoryFaultType, ProcessorState, WatchpointKind,
};
use crate::isa::arm::common::features::ArmFeatures;
use crate::isa::arm::common::memory::ArmMemory;
use crate::isa::arm::common::sysreg::Aarch64SysRegEncoding;
use crate::vm::vcpu::Aarch64SystemRegisters;

// ---- module tree (auto-split) ----
mod branch;
pub use branch::*;
mod exec;
pub use exec::*;
mod math;
pub use math::*;
mod memory;
pub use memory::*;
mod registers;
pub use registers::*;
mod simd;
pub use simd::*;
mod sve;
pub use sve::*;
mod system;
mod system_step;
pub use system::*;
#[cfg(test)]
mod tests;

// =============================================================================
// CPU Configuration
// =============================================================================

/// AArch64 CPU configuration.
#[derive(Clone, Debug)]
pub struct AArch64Config {
    /// Architecture version.
    pub version: ArmVersion,
    /// Enabled features.
    pub features: ArmFeatures,
    /// Initial exception level (1, 2, or 3).
    pub initial_el: u8,
    /// GIC configuration.
    pub gic_config: Option<GicConfig>,
    /// Number of breakpoint registers.
    pub num_breakpoints: u8,
    /// Number of watchpoint registers.
    pub num_watchpoints: u8,
}

impl Default for AArch64Config {
    fn default() -> Self {
        Self {
            version: ArmVersion::V8_0A,
            features: ArmFeatures::armv8_0_base(),
            initial_el: 1,
            gic_config: Some(GicConfig::default()),
            num_breakpoints: 6,
            num_watchpoints: 4,
        }
    }
}

impl AArch64Config {
    /// Create configuration for ARMv8.0-A.
    pub fn v8_0() -> Self {
        Self {
            version: ArmVersion::V8_0A,
            features: ArmFeatures::armv8_0_base(),
            ..Default::default()
        }
    }

    /// Create configuration for ARMv8.1-A.
    pub fn v8_1() -> Self {
        Self {
            version: ArmVersion::V8_1A,
            features: ArmFeatures::armv8_1_base(),
            ..Default::default()
        }
    }

    /// Create configuration for ARMv8.2-A.
    pub fn v8_2() -> Self {
        Self {
            version: ArmVersion::V8_2A,
            features: ArmFeatures::armv8_2_base(),
            ..Default::default()
        }
    }

    /// Create configuration for ARMv9.0-A.
    pub fn v9_0() -> Self {
        Self {
            version: ArmVersion::V9_0A,
            features: ArmFeatures::armv9_0_base(),
            ..Default::default()
        }
    }
}

// =============================================================================
// AArch64 CPU
// =============================================================================

/// AArch64 CPU emulator.
pub struct AArch64Cpu {
    // Note: Debug derived manually below due to Box<dyn ArmMemory>
    // =========================================================================
    // General Purpose Registers
    // =========================================================================
    /// X0-X30 (64-bit general purpose registers).
    x: [u64; NUM_GPRS],

    /// Stack pointers for each EL.
    sp_el: [u64; NUM_ELS],

    /// Program Counter.
    pc: u64,

    // =========================================================================
    // Processor State (PSTATE)
    // =========================================================================
    /// NZCV condition flags.
    nzcv: u8,

    /// DAIF interrupt masks (D, A, I, F).
    daif: u8,

    /// Current exception level (0-3).
    current_el: u8,

    /// SP selection (false = SP_EL0, true = SP_ELx).
    sp_sel: bool,

    /// PAN (Privileged Access Never).
    pan: bool,

    /// UAO (User Access Override).
    uao: bool,

    /// DIT (Data Independent Timing).
    dit: bool,

    /// SSBS (Speculative Store Bypass Safe).
    ssbs: bool,

    /// TCO (Tag Check Override).
    tco: bool,

    /// BTYPE (Branch Type for BTI).
    btype: u8,

    /// IL (Illegal execution state).
    il: bool,

    /// SS (Software Step).
    ss: bool,

    // =========================================================================
    // SIMD/FP Registers
    // =========================================================================
    /// V0-V31 (128-bit SIMD/FP registers).
    v: [u128; NUM_SIMD_REGS],

    /// Floating-point Control Register.
    fpcr: u32,

    /// Floating-point Status Register.
    fpsr: u32,

    // =========================================================================
    // SVE (Scalable Vector Extension)
    // =========================================================================
    /// SVE Vector Length in bits (must be multiple of 128, min 128, max 2048).
    /// For simplicity, we use VL=128 which makes Z registers equivalent to V registers.
    sve_vl: u16,

    /// SVE Predicate registers P0-P15.
    /// Each bit corresponds to one byte of the vector (VL/8 bits per predicate).
    /// For VL=128: 16 bits, VL=256: 32 bits, etc.
    /// We use u32 to support up to VL=256.
    sve_p: [u32; 16],

    /// First-fault register (FFR) - special predicate for first-fault loads.
    sve_ffr: u32,

    // =========================================================================
    // System Registers
    // =========================================================================
    /// All system registers.
    sysregs: SystemRegisters,

    // =========================================================================
    // MMU
    // =========================================================================
    /// Memory Management Unit.
    mmu: Mmu,

    // =========================================================================
    // GIC
    // =========================================================================
    /// Generic Interrupt Controller, shared with the memory bridge so that
    /// distributor/redistributor MMIO and the CPU's ICC system registers
    /// observe the same state.
    gic: Option<std::sync::Arc<std::sync::Mutex<Gic>>>,
    /// Lock-free mirror of this CPU's GIC IRQ line (published by the GIC on
    /// every state change); checked on the hot path of `step_system`.
    gic_irq_line: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Cached generic-timer output levels mirrored into GIC PPIs (virt PPI 27,
    /// phys PPI 30); avoids locking the GIC when nothing changed.
    timer_levels: (bool, bool),
    /// Translation level of the most recent MMU fault, for abort syndromes.
    /// (Atomic only for interior mutability behind `&self`; the CPU is
    /// single-threaded.)
    last_fault_level: std::sync::atomic::AtomicU8,
    /// Remaining debug-log quota for delivered faults.
    fault_log_budget: u32,
    /// Ring buffer of recently executed PCs (boot debugging).
    pc_ring: [u64; 64],
    pc_ring_idx: usize,

    // =========================================================================
    // Memory
    // =========================================================================
    /// Physical memory.
    memory: Box<dyn ArmMemory>,

    // =========================================================================
    // Execution State
    // =========================================================================
    /// Instruction count.
    insn_count: u64,

    /// Cycle count.
    cycle_count: u64,

    /// SMIR hot-block JIT tier state (region cache + hotness counters). Present
    /// only on an aarch64 host with the `smir-jit` feature.
    #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
    jit: Aarch64JitState,

    /// CPU halted.
    halted: bool,

    /// Waiting for interrupt.
    wfi: bool,

    /// Waiting for event.
    wfe: bool,

    /// Event signaled.
    event_register: bool,

    /// Pending exceptions.
    pending_exceptions: Vec<ArmException>,

    // =========================================================================
    // Debug
    // =========================================================================
    /// Breakpoints (PC addresses).
    breakpoints: HashSet<u64>,

    /// Watchpoints (address, size, kind).
    watchpoints: Vec<(u64, usize, WatchpointKind)>,

    // =========================================================================
    // Configuration
    // =========================================================================
    /// CPU configuration.
    config: AArch64Config,
}

impl std::fmt::Debug for AArch64Cpu {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AArch64Cpu")
            .field("pc", &format_args!("0x{:016x}", self.pc))
            .field("current_el", &self.current_el)
            .field("sp_sel", &self.sp_sel)
            .field("nzcv", &format_args!("{:04b}", self.nzcv))
            .field("daif", &format_args!("{:04b}", self.daif))
            .field("insn_count", &self.insn_count)
            .field("halted", &self.halted)
            .finish_non_exhaustive()
    }
}

// =============================================================================
// ArmCpu Trait Implementation
// =============================================================================

// =============================================================================
// System-mode execution (full-machine emulation)
// =============================================================================
//
// `ArmCpu::step` surfaces faults and exception-generating instructions as
// errors/exits — the right behavior for the instruction-level oracle tests.
// Booting an OS instead requires architectural delivery: SVC vectors to the
// EL1 handler, page faults become data aborts with a syndrome, and GIC/timer
// interrupts asynchronously enter the vector table. `step_system` wraps the
// same execution core with that delivery layer.

/// Map an MMU walk fault to the internal fault-type enum (for AT/PAR).
fn translation_fault_type_of(fault: &TranslationFault) -> MemoryFaultType {
    use super::mmu::TranslationFaultType as T;
    match fault.fault_type {
        T::Translation => MemoryFaultType::Translation,
        T::Permission => MemoryFaultType::Permission,
        T::Alignment => MemoryFaultType::Alignment,
        T::AccessFlag => MemoryFaultType::AccessFlag,
        T::AddressSize => MemoryFaultType::AddressSize,
        T::ExternalAbort => MemoryFaultType::External,
    }
}

/// Map an internal fault type + translation level to the architectural fault
/// status code.
fn fsc_for_fault(fault_type: MemoryFaultType, level: u8) -> super::exceptions::FaultStatusCode {
    use super::exceptions::FaultStatusCode as F;
    let level = level.min(3);
    match fault_type {
        MemoryFaultType::Translation => match level {
            0 => F::TranslationL0,
            1 => F::TranslationL1,
            2 => F::TranslationL2,
            _ => F::TranslationL3,
        },
        MemoryFaultType::AccessFlag => match level {
            1 => F::AccessFlagL1,
            2 => F::AccessFlagL2,
            _ => F::AccessFlagL3,
        },
        MemoryFaultType::Permission => match level {
            1 => F::PermissionL1,
            2 => F::PermissionL2,
            _ => F::PermissionL3,
        },
        MemoryFaultType::Alignment => F::Alignment,
        MemoryFaultType::AddressSize => match level {
            0 => F::AddressSizeL0,
            1 => F::AddressSizeL1,
            2 => F::AddressSizeL2,
            _ => F::AddressSizeL3,
        },
        _ => F::SyncExternal,
    }
}

// ============================================================================
// SMIR hot-block JIT tier (aarch64 host; opt-in via the `smir-jit` feature).
//
// Mirrors the x86_64 tier (`src/isa/x86_64/cpu.rs`): when a guest
// loop head turns hot, the region is lifted to SMIR (Aarch64Lifter), optimized,
// lowered to native AArch64 under the identity register map (Aarch64Lowerer),
// W^X-mapped (ExecMem), and run in one call through the rax_a64_enter_native
// trampoline. Frontier terminators (RET/BR/SVC/...) lower to native-exit stubs
// that record the resume guest PC; memory ops (when jit.mem is set) route
// through the rax_a64_mem_* helpers (MMU-translated, fault-bail). Validated
// differentially against the interpreter.
// ============================================================================

/// Back-edge hits to a loop head before it is promoted (compiled).
#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
const A64_JIT_HOT_THRESHOLD: u32 = 64;

/// A compiled native AArch64 region: W^X executable code + its entry offset.
#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
pub(crate) struct JitRegion {
    exec: crate::smir::lower::runtime::ExecMem,
    entry_offset: usize,
    /// The region touches V (SIMD/FP) registers, so it must run through the FP
    /// trampoline that additionally marshals V0-V31 + FPCR/FPSR. Integer-only
    /// regions use the cheaper GPR-only trampoline.
    uses_fp: bool,
}

/// Per-CPU JIT tier state.
#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[derive(Default)]
pub(crate) struct Aarch64JitState {
    /// Compiled regions keyed by (head guest PC, mode tag). `Some` ⇒ runnable;
    /// `None` ⇒ memoized-ineligible (skipped until an SMC cache wipe).
    cache: std::collections::HashMap<(u64, u64), Option<std::sync::Arc<JitRegion>>>,
    /// Per-head back-edge hit counter (promotion trigger).
    hot: std::collections::HashMap<u64, u32>,
    /// Route memory ops through MMU helper call-outs (vs. bail to interpreter).
    mem: bool,
    /// Per-instance kill switch (default enabled). Used by differential tests to
    /// get a pure-interpreter oracle run; complements the process-global
    /// `RAX_NO_JIT` env. When set, no region is ever promoted, so the cache
    /// stays empty and the fast path never fires.
    disabled: bool,
    /// 4 KiB page bases covered by some cached region's guest code. A guest
    /// write into one of these pages marks the cache stale (self-modifying
    /// code); the next `step_system` drains it. Empty ⇒ the SMC write-check is
    /// a single `is_empty()` on the hot store path.
    code_pages: std::collections::HashSet<u64>,
    /// Set when a write hit a `code_pages` entry; drained (whole-cache evict) at
    /// the top of the next `step_system`. Deferred so a write performed *inside*
    /// a running region doesn't pull the executing code out from under it.
    smc_dirty: bool,
}

/// AAPCS64 16-byte load-helper return: value in x0, ok in x1.
#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[repr(C)]
struct A64LoadRet {
    value: u64,
    ok: u64,
}

/// JIT memory-load helper: MMU-translate + read through the vcpu. `ok == 0` on a
/// fault — the region records the faulting PC and bails to the interpreter,
/// which re-executes the access and raises the architectural fault.
///
/// # Safety
/// `ctx` must be the live `*mut AArch64Cpu` the JIT installed for this run.
#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
unsafe extern "C" fn rax_a64_mem_load(
    ctx: *mut AArch64Cpu,
    addr: u64,
    size: u32,
    signed: u32,
) -> A64LoadRet {
    let cpu = unsafe { &*ctx };
    let res = match size {
        1 => cpu.mem_read_u8(addr).map(|v| {
            if signed != 0 {
                v as i8 as i64 as u64
            } else {
                v as u64
            }
        }),
        2 => cpu.mem_read_u16(addr).map(|v| {
            if signed != 0 {
                v as i16 as i64 as u64
            } else {
                v as u64
            }
        }),
        4 => cpu.mem_read_u32(addr).map(|v| {
            if signed != 0 {
                v as i32 as i64 as u64
            } else {
                v as u64
            }
        }),
        _ => cpu.mem_read_u64(addr),
    };
    match res {
        Ok(value) => A64LoadRet { value, ok: 1 },
        Err(_) => A64LoadRet { value: 0, ok: 0 },
    }
}

/// JIT memory-store helper. Returns 0 on fault (region bails to the interpreter).
///
/// # Safety
/// `ctx` must be the live `*mut AArch64Cpu` the JIT installed for this run.
#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
unsafe extern "C" fn rax_a64_mem_store(
    ctx: *mut AArch64Cpu,
    addr: u64,
    value: u64,
    size: u32,
) -> u64 {
    let cpu = unsafe { &mut *ctx };
    let res = match size {
        1 => cpu.mem_write_u8(addr, value as u8),
        2 => cpu.mem_write_u16(addr, value as u16),
        4 => cpu.mem_write_u32(addr, value as u32),
        _ => cpu.mem_write_u64(addr, value),
    };
    if res.is_ok() { 1 } else { 0 }
}

/// JIT vector-load helper. Reads `size` bytes (8 or 16) from guest memory and
/// writes them (zero-extended to 128 bits) into the destination V register's
/// slot in the state struct (`state.v[2*dst_idx..]`); the lowered code then
/// reloads that V register. `state` is `*mut Aarch64GuestRegs`; the vcpu is
/// reached via `state.ctx`. Returns 0 on a fault (region bails).
///
/// # Safety
/// `state` must be the live state struct the JIT installed for this run, with a
/// valid `ctx`.
#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
unsafe extern "C" fn rax_a64_vec_load(
    state: *mut crate::smir::lower::runtime::Aarch64GuestRegs,
    addr: u64,
    dst_idx: u32,
    size: u32,
) -> u64 {
    let st = unsafe { &mut *state };
    let cpu = unsafe { &*(st.ctx as *const AArch64Cpu) };
    // Translate and permission-check each byte independently, exactly like the
    // interpreter's SIMD load path. A single mem_read_u64 per 8-byte chunk would
    // translate only the chunk's first byte, so a vector load straddling a guest
    // page boundary would read the second page from adjacent PHYSICAL memory,
    // bypassing that page's mapping/permissions. (#45)
    let mut bytes = [0u8; 16];
    for j in 0..(size as usize).min(16) {
        match cpu.mem_read_u8(addr.wrapping_add(j as u64)) {
            Ok(b) => bytes[j] = b,
            Err(_) => return 0,
        }
    }
    // bytes[8..16] stay zero for an 8-byte (D-register) load, zeroing the top half.
    let lo = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let hi = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let i = (dst_idx as usize) * 2;
    st.v[i] = lo;
    st.v[i + 1] = hi;
    1
}

/// JIT vector-store helper. Reads the source V register from its state slot
/// (`state.v[2*src_idx..]`, which the lowered code has just published) and stores
/// `size` bytes to guest memory. Returns 0 on a fault.
///
/// # Safety
/// As [`rax_a64_vec_load`].
#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
unsafe extern "C" fn rax_a64_vec_store(
    state: *mut crate::smir::lower::runtime::Aarch64GuestRegs,
    addr: u64,
    src_idx: u32,
    size: u32,
) -> u64 {
    let st = unsafe { &*state };
    let cpu = unsafe { &mut *(st.ctx as *mut AArch64Cpu) };
    let i = (src_idx as usize) * 2;
    // Translate and permission-check each byte independently, like the
    // interpreter's SIMD store path — a per-8-byte mem_write_u64 would translate
    // only the first byte and let a page-straddling vector store overwrite the
    // second page's adjacent physical memory, bypassing its mapping. (#45)
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&st.v[i].to_le_bytes());
    bytes[8..16].copy_from_slice(&st.v[i + 1].to_le_bytes());
    for j in 0..(size as usize).min(16) {
        if cpu
            .mem_write_u8(addr.wrapping_add(j as u64), bytes[j])
            .is_err()
        {
            return 0;
        }
    }
    1
}

impl ArmCpu for AArch64Cpu {
    fn step(&mut self) -> Result<CpuExit, ArmError> {
        if self.halted {
            return Ok(CpuExit::Halt);
        }

        // Check for WFI/WFE completion
        if self.wfi {
            if let Some(_) = self.check_pending_interrupts()? {
                self.wfi = false;
            } else {
                return Ok(CpuExit::Wfi);
            }
        }

        if self.wfe {
            if self.event_register {
                self.event_register = false;
                self.wfe = false;
            } else {
                return Ok(CpuExit::Wfe);
            }
        }

        // Check for pending interrupts
        if let Some(exit) = self.check_pending_interrupts()? {
            return Ok(exit);
        }

        // Execute one instruction
        self.execute_instruction()
    }

    fn reset(&mut self) {
        // Reset all registers
        self.x = [0; NUM_GPRS];
        self.sp_el = [0; NUM_ELS];
        self.pc = 0;

        self.nzcv = 0;
        self.daif = 0xF; // All exceptions masked
        self.current_el = self.config.initial_el;
        self.sp_sel = true;
        self.pan = false;
        self.uao = false;
        self.dit = false;
        self.ssbs = false;
        self.tco = false;
        self.btype = 0;
        self.il = false;
        self.ss = false;

        self.v = [0; NUM_SIMD_REGS];
        self.fpcr = 0;
        self.fpsr = 0;

        // SVE state (mirrors `new()`): reset() previously left predicate/FFR/VL
        // state dirty, which is incorrect after an architectural reset.
        self.sve_vl = 128;
        self.sve_p = [0; 16];
        self.sve_ffr = 0;

        self.sysregs.reset();
        self.mmu = Mmu::new();
        if let Some(ref gic) = self.gic {
            if let Ok(mut gic) = gic.lock() {
                gic.reset();
            }
        }
        self.timer_levels = (false, false);

        self.insn_count = 0;
        self.cycle_count = 0;
        self.halted = false;
        self.wfi = false;
        self.wfe = false;
        self.event_register = false;
        self.pending_exceptions.clear();
        self.breakpoints.clear();
        self.watchpoints.clear();
    }

    fn get_gpr(&self, reg: u8) -> u64 {
        self.get_x(reg)
    }

    fn set_gpr(&mut self, reg: u8, value: u64) {
        self.set_x(reg, value);
    }

    fn get_pc(&self) -> u64 {
        self.pc
    }

    fn set_pc(&mut self, value: u64) {
        self.pc = value;
    }

    fn get_sp(&self) -> u64 {
        self.current_sp()
    }

    fn set_sp(&mut self, value: u64) {
        self.set_current_sp(value);
    }

    fn get_lr(&self) -> u64 {
        self.get_x(30) // X30 is the link register in AArch64
    }

    fn set_lr(&mut self, value: u64) {
        self.set_x(30, value);
    }

    fn get_pstate(&self) -> ProcessorState {
        ProcessorState {
            n: self.get_n(),
            z: self.get_z(),
            c: self.get_c(),
            v: self.get_v(),
            q: false,
            ge: 0,
            el: self.current_el,
            sp_sel: self.sp_sel,
            t: false, // Not applicable to AArch64
            i: (self.daif & 0x2) != 0,
            f: (self.daif & 0x1) != 0,
            a: (self.daif & 0x4) != 0,
            d: (self.daif & 0x8) != 0,
            e: false, // Little endian
            it_state: 0,
            mode: 0,
        }
    }

    fn set_pstate(&mut self, state: ProcessorState) {
        self.set_nzcv(state.n, state.z, state.c, state.v);
        self.current_el = state.el;
        self.sp_sel = state.sp_sel;
        self.daif = ((state.d as u8) << 3)
            | ((state.a as u8) << 2)
            | ((state.i as u8) << 1)
            | (state.f as u8);
    }

    fn is_privileged(&self) -> bool {
        self.current_el > 0
    }

    fn is_secure(&self) -> bool {
        // Check SCR_EL3.NS bit
        (self.sysregs.scr_el3 & 1) == 0
    }

    fn current_el(&self) -> u8 {
        self.current_el
    }

    fn read_memory(&self, addr: u64, size: usize) -> Result<Vec<u8>, ArmError> {
        let mut data = vec![0u8; size];
        for i in 0..size {
            data[i] = self.mem_read_u8(addr.wrapping_add(i as u64))?;
        }
        Ok(data)
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), ArmError> {
        for (i, &byte) in data.iter().enumerate() {
            self.mem_write_u8(addr.wrapping_add(i as u64), byte)?;
        }
        Ok(())
    }

    fn arch_version(&self) -> ArmVersion {
        self.config.version
    }

    fn profile(&self) -> ArmProfile {
        ArmProfile::A
    }

    fn features(&self) -> ArmFeatures {
        self.config.features
    }

    fn pending_exceptions(&self) -> Vec<ArmException> {
        self.pending_exceptions.clone()
    }

    fn inject_exception(&mut self, exception: ArmException) -> Result<(), ArmError> {
        self.pending_exceptions.push(exception);
        Ok(())
    }

    fn set_breakpoint(&mut self, addr: u64) -> Result<(), ArmError> {
        self.breakpoints.insert(addr);
        Ok(())
    }

    fn clear_breakpoint(&mut self, addr: u64) -> Result<(), ArmError> {
        self.breakpoints.remove(&addr);
        Ok(())
    }

    fn set_watchpoint(
        &mut self,
        addr: u64,
        size: usize,
        kind: WatchpointKind,
    ) -> Result<(), ArmError> {
        // Check if watchpoint already exists
        if !self
            .watchpoints
            .iter()
            .any(|(a, s, k)| *a == addr && *s == size && *k == kind)
        {
            self.watchpoints.push((addr, size, kind));
        }
        Ok(())
    }

    fn clear_watchpoint(&mut self, addr: u64) -> Result<(), ArmError> {
        self.watchpoints.retain(|(a, _, _)| *a != addr);
        Ok(())
    }

    fn instruction_count(&self) -> u64 {
        self.insn_count
    }

    fn cycle_count(&self) -> Option<u64> {
        Some(self.cycle_count)
    }

    fn has_fpu(&self) -> bool {
        true // AArch64 always has FP
    }

    fn get_simd_reg(&self, reg: u8) -> Option<(u64, u64)> {
        if reg < 32 {
            let val = self.v[reg as usize];
            Some((val as u64, (val >> 64) as u64))
        } else {
            None
        }
    }

    fn set_simd_reg(&mut self, reg: u8, low: u64, high: u64) -> Result<(), ArmError> {
        if reg < 32 {
            self.v[reg as usize] = (high as u128) << 64 | (low as u128);
            Ok(())
        } else {
            Err(ArmError::InvalidRegister(reg))
        }
    }

    fn get_fpcr(&self) -> Option<u32> {
        Some(mask_fpcr(self.fpcr))
    }

    fn set_fpcr(&mut self, value: u32) -> Result<(), ArmError> {
        self.fpcr = mask_fpcr(value);
        Ok(())
    }

    fn get_fpsr(&self) -> Option<u32> {
        Some(mask_fpsr(self.fpsr))
    }

    fn set_fpsr(&mut self, value: u32) -> Result<(), ArmError> {
        self.fpsr = mask_fpsr(value);
        Ok(())
    }
}
