//! x86_64 CPU state and core execution loop.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::atomic::{AtomicU64, AtomicUsize};

#[cfg(feature = "trace")]
use crate::observability::trace;

#[cfg(feature = "profiling")]
use crate::observability::profiling;

/// Global tracker for current RIP (for debugging write watchpoints)
pub static CURRENT_RIP: AtomicU64 = AtomicU64::new(0);

/// Circular buffer of last 16 RIPs for debugging crashes
pub static RIP_HISTORY: [AtomicU64; 16] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
pub static RIP_IDX: AtomicUsize = AtomicUsize::new(0);

/// Log an IF state transition with context (disabled for performance)
#[inline]
pub fn log_if_transition(_rip: u64, _old_if: bool, _new_if: bool, _source: &str) {
    // Disabled - IF flag logic verified working correctly
}

use vm_memory::GuestMemoryMmap;

use super::decode::Decoder;
use super::execute;
use super::mmu::Mmu;
use crate::isa::x86_64::flags;
#[cfg(all(
    feature = "smir-jit",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use crate::smir::ir::types::BlockId;
use crate::vm::vcpu::{CpuState, Registers, SystemRegisters, VCpu, VcpuExit, X86_64CpuState};

/// Byte offset of each GPR field within `Registers`, indexed by x86 register
/// encoding (0=rax,1=rcx,2=rdx,3=rbx,4=rsp,5=rbp,6=rsi,7=rdi, 8..=15 = r8..=r15,
/// 16..=31 = r16..=r31). Built with `offset_of!`, so it reflects the actual
/// field layout for any `repr` and lets `get_reg`/`set_reg` index a register
/// branchlessly instead of via a 32-arm match (which the profiler showed as a
/// hot jump table inside every ALU handler).
const GPR_OFFSETS: [usize; 32] = [
    std::mem::offset_of!(Registers, rax),
    std::mem::offset_of!(Registers, rcx),
    std::mem::offset_of!(Registers, rdx),
    std::mem::offset_of!(Registers, rbx),
    std::mem::offset_of!(Registers, rsp),
    std::mem::offset_of!(Registers, rbp),
    std::mem::offset_of!(Registers, rsi),
    std::mem::offset_of!(Registers, rdi),
    std::mem::offset_of!(Registers, r8),
    std::mem::offset_of!(Registers, r9),
    std::mem::offset_of!(Registers, r10),
    std::mem::offset_of!(Registers, r11),
    std::mem::offset_of!(Registers, r12),
    std::mem::offset_of!(Registers, r13),
    std::mem::offset_of!(Registers, r14),
    std::mem::offset_of!(Registers, r15),
    std::mem::offset_of!(Registers, r16),
    std::mem::offset_of!(Registers, r17),
    std::mem::offset_of!(Registers, r18),
    std::mem::offset_of!(Registers, r19),
    std::mem::offset_of!(Registers, r20),
    std::mem::offset_of!(Registers, r21),
    std::mem::offset_of!(Registers, r22),
    std::mem::offset_of!(Registers, r23),
    std::mem::offset_of!(Registers, r24),
    std::mem::offset_of!(Registers, r25),
    std::mem::offset_of!(Registers, r26),
    std::mem::offset_of!(Registers, r27),
    std::mem::offset_of!(Registers, r28),
    std::mem::offset_of!(Registers, r29),
    std::mem::offset_of!(Registers, r30),
    std::mem::offset_of!(Registers, r31),
];
use crate::error::{Error, Result};

/// x87 FPU state.
#[derive(Clone, Debug)]
pub struct FpuState {
    /// FPU control word (default 0x037F)
    pub control_word: u16,
    /// FPU status word (default 0x0000)
    pub status_word: u16,
    /// FPU tag word (default 0xFFFF - all empty)
    pub tag_word: u16,
    /// FPU data pointer
    pub data_ptr: u64,
    /// FPU instruction pointer
    pub instr_ptr: u64,
    /// FPU last opcode
    pub last_opcode: u16,
    /// FPU register stack (8 x 80-bit, stored as f64 for simplicity)
    pub st: [f64; 8],
    /// Top of stack pointer (0-7), stored in status word bits 11-13
    pub top: u8,
}

impl Default for FpuState {
    fn default() -> Self {
        FpuState {
            control_word: 0x037F, // Round to nearest, all exceptions masked, 64-bit precision
            status_word: 0x0000,
            tag_word: 0xFFFF, // All registers empty
            data_ptr: 0,
            instr_ptr: 0,
            last_opcode: 0,
            st: [0.0; 8],
            top: 0,
        }
    }
}

impl FpuState {
    /// Initialize FPU to default state (FINIT/FNINIT)
    pub fn init(&mut self) {
        self.control_word = 0x037F;
        self.status_word = 0x0000;
        self.tag_word = 0xFFFF;
        self.data_ptr = 0;
        self.instr_ptr = 0;
        self.last_opcode = 0;
        self.top = 0;
        // Note: register values are preserved, just tagged as empty
    }

    /// Get physical register index from stack-relative index
    #[inline]
    pub fn st_index(&self, i: u8) -> usize {
        ((self.top.wrapping_add(i)) & 7) as usize
    }

    /// Push a value onto the FPU stack
    pub fn push(&mut self, value: f64) {
        // New TOP is the register below the current one. Per the x87 spec, if it
        // is not already empty (tag != 3) the push is a stack OVERFLOW: raise the
        // invalid-operation (IE) and stack-fault (SF) exceptions, set C1 to flag
        // the overflow direction, and raise the error-summary (ES) bit. With the
        // exception masked (the default) the push still completes.
        let dst = self.top.wrapping_sub(1) & 7;
        let dst_tag = (self.tag_word >> ((dst as u16) * 2)) & 3;
        if dst_tag != 3 {
            // IE (bit 0) | SF (bit 6) | C1 (bit 9, overflow direction).
            // With the default masked invalid-operation exception, ES remains clear.
            self.status_word |= 0x0001 | 0x0040 | 0x0200;
        }
        self.top = dst;
        self.st[self.top as usize] = value;
        // Update tag for this register (mark as valid)
        let tag_shift = (self.top as u16) * 2;
        self.tag_word &= !(3 << tag_shift);
        // 0 = valid, 1 = zero, 2 = special, 3 = empty
        if value == 0.0 {
            self.tag_word |= 1 << tag_shift;
        }
        // Update TOP in status word
        self.status_word = (self.status_word & !0x3800) | ((self.top as u16) << 11);
    }

    /// Pop a value from the FPU stack
    pub fn pop(&mut self) -> f64 {
        // If the current TOP register is empty (tag == 3) the pop is a stack
        // UNDERFLOW: raise invalid-operation (IE), stack-fault (SF), and clear
        // C1 to flag the underflow direction.
        let tag_shift = (self.top as u16) * 2;
        let underflow = (self.tag_word >> tag_shift) & 3 == 3;
        if underflow {
            // Set IE (bit 0) | SF (bit 6); clear C1 (bit 9) for underflow.
            // Masked invalid-operation exceptions return the x87 indefinite
            // value without setting ES.
            self.status_word = (self.status_word | 0x0001 | 0x0040) & !0x0200;
        }
        let value = if underflow {
            f64::from_bits(0xfff8_0000_0000_0000)
        } else {
            self.st[self.top as usize]
        };
        // Mark register as empty
        self.tag_word |= 3 << tag_shift;
        self.top = self.top.wrapping_add(1) & 7;
        // Update TOP in status word
        self.status_word = (self.status_word & !0x3800) | ((self.top as u16) << 11);
        value
    }

    /// Get ST(i) value
    #[inline]
    pub fn get_st(&self, i: u8) -> f64 {
        self.st[self.st_index(i)]
    }

    /// Set ST(i) value
    #[inline]
    pub fn set_st(&mut self, i: u8, value: f64) {
        let idx = self.st_index(i);
        self.st[idx] = value;
        let tag_shift = (idx as u16) * 2;
        self.tag_word &= !(3 << tag_shift);
        if value == 0.0 {
            self.tag_word |= 1 << tag_shift;
        }
    }
}

/// Type of lazy flag operation - determines how to compute flags on demand
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum LazyFlagOp {
    /// No lazy flags - rflags is valid
    None,
    /// Add operation: CF = result < a, OF = signed overflow
    Add,
    /// Sub/CMP operation: CF = a < b (borrow), OF = signed overflow
    Sub,
    /// Logic operation (AND/OR/XOR/TEST): CF=OF=0
    Logic,
    /// Inc operation: like Add but CF preserved
    Inc,
    /// Dec operation: like Sub but CF preserved
    Dec,
}

/// Lazy flag state - stores operands to compute flags on demand
#[derive(Clone, Copy, Debug)]
pub(super) struct LazyFlags {
    pub op: LazyFlagOp,
    pub result: u64,
    pub src: u64, // First operand (a)
    pub dst: u64, // Second operand (b) - only used for Add/Sub
    pub size: u8,
}

impl Default for LazyFlags {
    fn default() -> Self {
        LazyFlags {
            op: LazyFlagOp::None,
            result: 0,
            src: 0,
            dst: 0,
            size: 4,
        }
    }
}

/// Emulated x86_64 vCPU.
pub struct X86_64Vcpu {
    id: u32,
    /// Per-vCPU retired-instruction counter. Published to the global counter
    /// only at run() yield boundaries so the hot loop stays atomic-free. The
    /// architectural TSC uses the separate real-time guest clock in [`Self::tsc`].
    pub(super) insn_count: u64,
    pub(super) regs: Registers,
    pub(super) sregs: SystemRegisters,
    pub(super) mmu: Mmu,
    pub(super) fpu: FpuState,
    pub(super) halted: bool,
    /// STI/MOV-SS maskable-interrupt shadow. When true, external maskable
    /// interrupt injection remains blocked through the next instruction
    /// boundary. The direct `step()` wrapper consumes the prior shadow before
    /// attempting that instruction; a qualifying instruction can establish a
    /// fresh shadow while it executes.
    pub(super) interrupt_inhibit: bool,
    io_pending: Option<IoPending>,
    /// IA32_KERNEL_GS_BASE MSR (0xC0000102) for SWAPGS
    pub(super) kernel_gs_base: u64,
    /// IA32_TSC_ADJUST MSR (0x3B).
    pub(super) tsc_adjust: u64,
    /// IA32_TSC_AUX MSR (0xC0000103), consumed by RDPID and RDTSCP.
    pub(super) tsc_aux: u32,
    /// IA32_MISC_ENABLE MSR (0x1A0) for the deterministic Intel CPU profile.
    pub(super) misc_enable: u64,
    /// IA32_PAT MSR (0x277). The MMU currently treats memory types uniformly,
    /// but the architectural register remains validated and snapshot-visible.
    pub(super) pat: u64,
    /// IA32_UMWAIT_CONTROL MSR (0xE1), exposed with WAITPKG.
    pub(super) umwait_control: u64,
    /// Protection Key Rights Register (PKRU).
    pub(super) pkru: u32,
    /// SIMD floating-point control/status register used by LDMXCSR/STMXCSR and
    /// by the MXCSR slots in FXSAVE/FXRSTOR and XSAVE/XRSTOR.
    pub(super) mxcsr: u32,
    /// Extended control register XCR0 (XSAVE feature-enable mask): bit0 x87
    /// (always 1), bit1 SSE, bit2 AVX (YMM_Hi128). Written by XSETBV, read by
    /// XGETBV, and consulted by XSAVE/XRSTOR and CPUID leaf 0xD.
    pub(super) xcr0: u64,
    /// Value returned by XGETBV when ECX=1. This defaults to zero (matching
    /// IA32_XSS on the base KVM harness) but can be configured by harnesses
    /// that install XCRS state externally before guest execution.
    pub(super) xgetbv1_value: u64,
    /// Enable Xeon Phi-only AVX-512 subsets (AVX512ER, AVX512PF,
    /// AVX512_4FMAPS, and AVX512_4VNNIW). The default CPUID profile does not
    /// expose these bits, so their opcodes must #UD unless a semantic harness
    /// opts in explicitly.
    pub(super) xeon_phi_avx512: bool,
    /// Enable AVX512_VP2INTERSECT. The base emulated CPUID profile does not
    /// advertise this extension, so the opcode is disabled unless a semantic
    /// harness opts in explicitly.
    pub(super) vp2intersect: bool,
    /// Enable AMD SSE4A instructions. The base emulated CPUID profile does not
    /// advertise this extension, so its opcodes must #UD unless a semantic
    /// harness opts in explicitly.
    pub(super) sse4a: bool,
    /// Enable AMD TBM instructions. The base emulated CPUID profile does not
    /// advertise this extension, so its XOP encodings must #UD unless a
    /// semantic harness opts in explicitly.
    pub(super) tbm: bool,
    /// Enable AMD XOP packed-vector instructions. The base emulated CPUID
    /// profile does not advertise XOP, so its encodings must #UD unless a
    /// semantic harness opts in explicitly.
    pub(super) xop: bool,
    /// Enable AVX10.2 media dot-product instructions (AVX_VNNI_INT8 and
    /// AVX_VNNI_INT16 families). The base emulated CPUID profile does not
    /// advertise these extensions, so their opcodes must #UD unless a semantic
    /// harness opts in explicitly.
    pub(super) avx10_media: bool,
    /// Enable AVX10.2 VMINMAX floating-point min/max instructions. The base
    /// emulated CPUID profile does not advertise this extension, so its opcodes
    /// must #UD unless a semantic harness opts in explicitly.
    pub(super) avx10_vminmax: bool,
    /// Enable AVX10.2 saturation conversion instructions. The base emulated
    /// CPUID profile does not advertise this extension, so its opcodes must #UD
    /// unless a semantic harness opts in explicitly.
    pub(super) avx10_sat_convert: bool,
    /// Enable Intel APX instruction forms (REX2 and EVEX MAP4). The base
    /// emulated CPUID profile does not advertise APX, so its opcodes must #UD
    /// unless a semantic harness opts in explicitly.
    pub(super) apx: bool,
    /// Decoded instruction cache for avoiding re-decode in hot loops
    pub(super) decode_cache: Box<[DecodeCacheEntry; DECODE_CACHE_SIZE]>,
    /// Lazy flag state for deferred flag computation. A plain field (not a Cell):
    /// every writer holds `&mut self`, and the two `&self` readers
    /// (`compute_materialized_rflags`, `get_emulator_state`) only copy it out, so
    /// no interior mutability is needed. Keeping it inline lets the optimizer hold
    /// the hot lazy state in registers instead of routing through a Cell.
    pub(super) lazy_flags: LazyFlags,
    /// Single-step mode for GDB debugging.
    #[cfg(feature = "debug")]
    single_step: bool,
    /// True while the GDB stub is enabled for this vCPU. Debug execution must
    /// stay on the interpreter so breakpoints and single-step stops happen at
    /// exact guest instruction boundaries.
    #[cfg(feature = "debug")]
    debugger_active: bool,
    /// Internal debugger execute breakpoints. These are intentionally tracked
    /// out-of-band instead of patching guest memory with INT3, preserving guest
    /// code bytes and natural INT3/#BP behavior.
    #[cfg(feature = "debug")]
    debug_breakpoints: std::collections::HashSet<u64>,
    /// Per-vCPU El-Torito boot CD served by the real-mode mini-BIOS.
    pub(super) bios_cdrom: Option<Arc<Vec<u8>>>,
    /// Guest RAM size reported by real-mode BIOS memory-detection calls.
    pub(super) bios_mem_bytes: u64,
    /// SMIR hot-block JIT: compiled native regions keyed by (RIP, mode_tag);
    /// `Some` = runnable, `None` = known-ineligible (don't recompile). Evicted
    /// when the guest writes the corresponding code page (SMC).
    #[cfg(all(
        feature = "smir-jit",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    jit_cache: std::collections::HashMap<(u64, u64), Option<std::sync::Arc<JitRegion>>>,
    /// SMIR hot-block JIT: per-loop-head backward-branch hit counter; a head is
    /// promoted (compiled) once it crosses the hotness threshold.
    #[cfg(all(
        feature = "smir-jit",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    jit_hot: std::collections::HashMap<u64, u32>,
    /// SMIR hot-block JIT: known-ineligible heads memoized as `(head, mode_tag)
    /// -> exact bounded code snapshot`. UNLIKE `jit_cache`, this is NOT wiped by SMC: when a
    /// guest writes a page that merely shares a 4 KiB frame with code (common in
    /// TempleOS, whose compiler keeps data beside code), the cache+hotness wipe
    /// would otherwise re-promote the same ineligible head thousands of times,
    /// re-running the (futile) lift/optimize each time. An exact snapshot of the
    /// largest readable prefix in the JIT's lift window self-corrects the memo: a
    /// genuine code change re-triggers compilation; an unchanged head is skipped
    /// cheaply. Only
    /// ineligible verdicts are memoized here — compiled regions stay in
    /// `jit_cache` and are still SMC-invalidated for correctness.
    #[cfg(all(
        feature = "smir-jit",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    jit_ineligible: std::collections::HashMap<(u64, u64), Vec<u8>>,
    /// Ineligible memo keys whose bounded code windows overlap an SMC-invalidated
    /// page. Clean memos return in O(1); dirty memos compare their exact snapshot
    /// once before either remaining memoized or becoming eligible for re-lifting.
    #[cfg(all(
        feature = "smir-jit",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    jit_ineligible_dirty: std::collections::HashSet<(u64, u64)>,
    /// Inclusive virtual source-page range of the native region currently in
    /// flight. The bounded contiguous lift window makes this a compact exact
    /// representation without allocating on every region entry.
    #[cfg(all(
        feature = "smir-jit",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    jit_active_source_range: Option<(u64, u64)>,
    /// Set when an interpreter callout invalidates a source page belonging to
    /// the in-flight native region. The callout then exits at its current guest
    /// PC instead of returning into a stale native continuation.
    #[cfg(all(
        feature = "smir-jit",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    jit_active_region_stale: bool,
    /// JIT of memory-touching regions (Load/Store via MMU helper calls). Enabled
    /// by default; `RAX_JIT_NO_MEM` disables it. Independently settable in tests.
    #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
    jit_mem: bool,
    /// Lift guest calls into interpreter callouts while retaining the native
    /// caller region. Enabled by default; `RAX_JIT_NO_CALL` disables it.
    /// Independently settable in regression tests.
    #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
    jit_call: bool,
    /// Set by [`rax_jit_call`] (the lift-through-calls helper) when a callee
    /// yields a VMM-bound exit (I/O, HLT, …): `jit_run_region_native` recovers it
    /// and propagates it so the run loop returns it to the VMM. `None` otherwise.
    #[cfg(all(
        feature = "smir-jit",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    jit_callout_exit: Option<VcpuExit>,
    /// When `Some`, the memory-JIT store helper logs each store's `(addr, size,
    /// old_value)` here so verify mode can UNDO the region's writes and re-run
    /// the interpreter for a store-sound differential. `None` in normal use.
    #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
    jit_mem_log: Option<Vec<(u64, u8, u64)>>,
    /// When `Some`, every data memory access funnelled through `read_mem` /
    /// `write_mem` is appended as `(kind, addr, size, value)` (kind 0=load,
    /// 1=store). Verify mode captures the native run's trace and the interpreter
    /// re-run's trace, then diffs them to pinpoint the exact diverging access.
    #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
    jit_mem_trace: Option<Vec<(u8, u64, u8, u64)>>,
    /// Verification-only intra-instruction frontier; absent during execution.
    #[cfg(any(test, all(feature = "smir-jit", target_arch = "x86_64")))]
    pub(in crate::isa::x86_64) jit_verify_vsib_stop: Option<JitVerifyVsibStop>,
    /// One-shot direct restart after a native VSIB lane/helper or mode guard
    /// defers at its instruction PC. This prevents cached-entry re-entry from
    /// retrying the same deferred access indefinitely.
    #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
    jit_vsib_resume_pc: Option<u64>,
}

/// Pending I/O operation.
enum IoInTarget {
    Reg,
    Mem { addr: u64 },
}

struct IoPending {
    size: u8,
    target: IoInTarget,
    /// Element count: 1 for a normal IN, N for a batched `rep ins` block (the
    /// destination is then `count` consecutive `size`-byte elements starting at
    /// the `Mem` address).
    count: u32,
}

/// Maximum instruction length in bytes.
pub const MAX_INSN_LEN: usize = 15;

/// Decode cache size (must be power of 2 for fast indexing)
const DECODE_CACHE_SIZE: usize = 4096;

/// How often run() performs periodic housekeeping (LAPIC poll, VMM yield,
/// counter publish). Keeps clock reads and RefCell borrows off the per-insn path.
const LAPIC_POLL_STRIDE: u64 = 1024;
pub(super) const DECODE_CACHE_MASK: usize = DECODE_CACHE_SIZE - 1;

/// Uniform-signature instruction handler. Resolved once on a decode-cache miss
/// (see [`X86_64Vcpu::resolve_handler`]) and stored in the cache entry so a hit
/// can call the handler directly, skipping the big `execute` opcode match and
/// the escape/two-byte call chain. Opcode-/cc-derived arguments are recovered
/// from `InsnContext::opcode` by thin shim wrappers.
pub(super) type HandlerFn = fn(&mut X86_64Vcpu, &mut InsnContext) -> Result<Option<VcpuExit>>;

/// Cached decoded instruction entry
#[derive(Clone, Copy, Debug)]
pub(super) struct DecodeCacheEntry {
    /// RIP where this instruction lives (0 = invalid)
    pub(super) rip: u64,
    /// Primary opcode byte
    pub(super) opcode: u8,
    /// Decoded operand size
    pub(super) op_size: u8,
    /// Cursor position after prefix decode (start of opcode)
    pub(super) cursor: usize,
    /// REX prefix if present
    pub(super) rex: Option<u8>,
    /// REX2 prefix if present
    pub(super) rex2: Option<Rex2Prefix>,
    /// 0x66 prefix
    pub(super) operand_size_override: bool,
    /// 0x67 prefix
    pub(super) address_size_override: bool,
    /// REP/REPNE prefix
    pub(super) rep_prefix: Option<u8>,
    /// Segment override prefix (0x64=FS, 0x65=GS, etc.)
    pub(super) segment_override: Option<u8>,
    /// Address-space + CPU-mode tag: part of the key so a hit never reuses
    /// stale bytes/decode across a context or mode switch.
    pub(super) mode_tag: u64,
    /// Raw instruction bytes captured at fill time. Hits re-fetch and compare
    /// against this window before reusing the cached decode.
    pub(super) bytes: [u8; MAX_INSN_LEN],
    /// Number of valid bytes in `bytes`.
    pub(super) bytes_len: usize,
    /// Whether a LOCK (0xF0) prefix is present. Computed once on the fill path so
    /// the per-instruction hit path can skip the prefix-byte scan and only pay the
    /// (cold) legality check when LOCK is actually present.
    pub(super) has_lock: bool,
    /// Handler resolved on the fill (miss) path. On a hit it is called directly,
    /// skipping the `execute` opcode match. Invalidated with the rest of the
    /// entry (SMC / mode switch zero `rip`, so a stale handler can never run).
    pub(super) handler: HandlerFn,
}

/// Placeholder handler stored in freshly-defaulted (invalid, `rip == 0`) cache
/// entries. It can never actually run: an entry only dispatches after a key
/// match, which requires a non-zero `rip` installed by the fill path together
/// with a real resolved handler.
fn unreachable_handler(_vcpu: &mut X86_64Vcpu, _ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    Err(Error::Emulator(
        "decode-cache handler invoked on an invalid entry".to_string(),
    ))
}

impl Default for DecodeCacheEntry {
    #[inline(always)]
    fn default() -> Self {
        DecodeCacheEntry {
            rip: 0,
            opcode: 0,
            op_size: 4,
            cursor: 0,
            rex: None,
            rex2: None,
            operand_size_override: false,
            address_size_override: false,
            rep_prefix: None,
            segment_override: None,
            mode_tag: 0,
            bytes: [0; MAX_INSN_LEN],
            bytes_len: 0,
            has_lock: false,
            handler: unreachable_handler,
        }
    }
}

/// Decoded instruction context passed to instruction handlers.
pub(super) struct InsnContext {
    /// Instruction bytes (fixed-size to avoid allocation)
    pub bytes: [u8; MAX_INSN_LEN],
    /// Actual number of valid bytes
    pub bytes_len: usize,
    pub cursor: usize,
    pub rex: Option<u8>,
    /// REX2 prefix state (if present) - APX extension
    pub rex2: Option<Rex2Prefix>,
    pub operand_size_override: bool,
    pub address_size_override: bool,
    pub rep_prefix: Option<u8>,
    pub op_size: u8,
    pub rip_relative_offset: usize,
    /// Segment override prefix (0x26=ES, 0x2E=CS, 0x36=SS, 0x3E=DS, 0x64=FS, 0x65=GS)
    pub segment_override: Option<u8>,
    /// EVEX prefix state (if present)
    pub evex: Option<EvexPrefix>,
    /// Primary opcode byte. Set by `step()` before dispatch so uniform-signature
    /// handler shims (resolved via the fn-pointer dispatch path) can recover the
    /// opcode-derived register / condition-code arguments without it being passed
    /// as a separate parameter.
    pub opcode: u8,
    /// Set when `fetch` truncated the instruction-byte buffer because the
    /// instruction stream crossed from canonical into non-canonical linear space.
    /// When true, running past `bytes_len` surfaces #GP(0) — an architectural fault
    /// — instead of a fatal internal "instruction too short" error. See
    /// `out_of_bytes()`.
    pub boundary_gp: bool,
}

/// REX2 prefix decoded fields (2-byte prefix for APX EGPR access)
/// Format: 0xD5 [M:R4:X4:B4:W:R:X:B]. Field names below preserve older
/// internal naming: r3/x3/b3 are the high (+16) extension bits, and r4/x4/b4
/// are the low (+8) extension bits.
#[derive(Clone, Copy, Debug)]
pub(super) struct Rex2Prefix {
    /// M bit: opcode map select (0=legacy map, 1=0F map)
    pub m: bool,
    /// W bit: operand size (0=default, 1=64-bit)
    pub w: bool,
    /// High ModR/M reg extension bit (+16)
    pub r3: bool,
    /// High SIB index extension bit (+16)
    pub x3: bool,
    /// High ModR/M r/m or SIB base extension bit (+16)
    pub b3: bool,
    /// Low ModR/M reg extension bit (+8)
    pub r4: bool,
    /// Low SIB index extension bit (+8)
    pub x4: bool,
    /// Low ModR/M r/m extension bit (+8)
    pub b4: bool,
}

/// EVEX prefix decoded fields (4-byte prefix for AVX-512)
#[derive(Clone, Copy, Debug)]
pub(super) struct EvexPrefix {
    /// R bit (inverted, extends ModR/M reg field to 4 bits)
    pub r: bool,
    /// X bit (inverted, extends SIB index field)
    pub x: bool,
    /// B bit (inverted, extends ModR/M r/m or SIB base)
    pub b: bool,
    /// R' bit (inverted, extends reg field to 5 bits for ZMM16-31)
    pub r_prime: bool,
    /// mm field (opcode map: 1=0F, 2=0F38, 3=0F3A, 5=MAP5, 6=MAP6)
    pub mm: u8,
    /// W bit (operand size: 0=32-bit, 1=64-bit elements)
    pub w: bool,
    /// vvvv field (inverted, non-destructive source register)
    pub vvvv: u8,
    /// pp field (implied prefix: 0=none, 1=66, 2=F3, 3=F2)
    pub pp: u8,
    /// z bit (zeroing-masking: 0=merge, 1=zero)
    pub z: bool,
    /// L'L field (vector length: 0=128, 1=256, 2=512)
    pub ll: u8,
    /// b bit (broadcast/rounding control)
    pub broadcast: bool,
    /// V' bit (inverted, extends vvvv to 5 bits)
    pub v_prime: bool,
    /// aaa field (opmask register k0-k7)
    pub aaa: u8,
    // APX-specific fields
    /// B4 bit (APX MAP4 P0[3], extends r/m to EGPR R16-R31)
    pub b4: bool,
    /// X4 bit (inverted, extends SIB index to 5 bits for EGPR R16-R31)
    pub x4: bool,
    /// ND bit (New Data Destination - 3-operand form)
    pub nd: bool,
    /// NF bit (No Flags - suppress RFLAGS updates)
    pub nf: bool,
    /// APX mode indicator (for EVEX-encoded GPR instructions)
    pub apx_mode: bool,
}

impl InsnContext {
    /// Get REX.W flag.
    #[inline(always)]
    pub fn rex_w(&self) -> bool {
        self.rex.map_or(false, |r| r & 0x08 != 0)
    }

    /// Get REX.R flag (extends ModR/M reg field).
    #[inline(always)]
    pub fn rex_r(&self) -> u8 {
        self.rex.map_or(0, |r| (r & 0x04) << 1)
    }

    /// Get REX.B flag (extends ModR/M r/m field or opcode reg).
    #[inline(always)]
    pub fn rex_b(&self) -> u8 {
        self.rex.map_or(0, |r| (r & 0x01) << 3)
    }

    // =========================================================================
    // REX2 helper methods (APX)
    // =========================================================================

    /// Check if REX2 prefix is present
    #[inline(always)]
    pub fn has_rex2(&self) -> bool {
        self.rex2.is_some()
    }

    /// Check if any REX-type prefix is present (REX or REX2)
    #[inline(always)]
    pub fn has_any_rex(&self) -> bool {
        self.rex.is_some() || self.rex2.is_some()
    }

    /// Get REX2.W flag (64-bit operand size)
    #[inline(always)]
    pub fn rex2_w(&self) -> bool {
        self.rex2.map_or(false, |r| r.w)
    }

    /// Get W flag from either REX or REX2
    #[inline(always)]
    pub fn any_rex_w(&self) -> bool {
        self.rex_w() || self.rex2_w()
    }

    /// Get REX2.M flag (opcode map: 0=legacy, 1=0F map)
    #[inline(always)]
    pub fn rex2_m(&self) -> bool {
        self.rex2.map_or(false, |r| r.m)
    }

    /// Get full 5-bit reg extension from REX2.
    #[inline(always)]
    pub fn rex2_r(&self) -> u8 {
        self.rex2.map_or(0, |r| {
            let r3 = if r.r3 { 16 } else { 0 };
            let r4 = if r.r4 { 8 } else { 0 };
            r3 | r4
        })
    }

    /// Get full 5-bit r/m extension from REX2.
    #[inline(always)]
    pub fn rex2_b(&self) -> u8 {
        self.rex2.map_or(0, |r| {
            let b3 = if r.b3 { 16 } else { 0 };
            let b4 = if r.b4 { 8 } else { 0 };
            b3 | b4
        })
    }

    /// Get full 5-bit index extension from REX2.
    #[inline(always)]
    pub fn rex2_x(&self) -> u8 {
        self.rex2.map_or(0, |r| {
            let x3 = if r.x3 { 16 } else { 0 };
            let x4 = if r.x4 { 8 } else { 0 };
            x3 | x4
        })
    }

    /// Get combined reg extension from REX or REX2
    #[inline(always)]
    pub fn any_rex_r(&self) -> u8 {
        if self.rex2.is_some() {
            self.rex2_r()
        } else {
            self.rex_r()
        }
    }

    /// Get combined r/m extension from REX or REX2
    #[inline(always)]
    pub fn any_rex_b(&self) -> u8 {
        if self.rex2.is_some() {
            self.rex2_b()
        } else {
            self.rex_b()
        }
    }

    // =========================================================================
    // EVEX helper methods
    // =========================================================================

    /// Get full 5-bit destination register (ModR/M reg extended by EVEX.R and EVEX.R')
    pub fn evex_dest_reg(&self) -> u8 {
        if let Some(evex) = &self.evex {
            // reg field from ModR/M (3 bits) + R (bit 3) + R' (bit 4)
            let r_ext = if evex.r { 0 } else { 8 };
            let r_prime_ext = if evex.r_prime { 0 } else { 16 };
            r_ext | r_prime_ext
        } else {
            self.rex_r()
        }
    }

    /// Get full 5-bit source register (EVEX.vvvv extended by EVEX.V')
    pub fn evex_vvvv(&self) -> u8 {
        if let Some(evex) = &self.evex {
            // vvvv is inverted, V' extends to 5 bits
            let v_prime_ext = if evex.v_prime { 0 } else { 16 };
            (evex.vvvv ^ 0xF) | v_prime_ext
        } else {
            0
        }
    }

    /// Get full 5-bit r/m register (extended by EVEX.B and EVEX.X for certain encodings)
    /// For APX mode, uses B4 bit for EGPR extension
    pub fn evex_rm_reg(&self) -> u8 {
        if let Some(evex) = &self.evex {
            let b_ext = if evex.b { 0 } else { 8 };
            // For APX, P0[3] is the non-inverted B4 bit; for vector EVEX,
            // X is the inverted high extension bit used by some encodings.
            let high_ext = if evex.apx_mode {
                if evex.b4 { 16 } else { 0 }
            } else {
                if evex.x { 0 } else { 16 }
            };
            b_ext | high_ext
        } else {
            self.rex_b()
        }
    }

    /// Get full 5-bit SIB index register for APX (uses X4 for EGPR)
    pub fn evex_index_reg(&self) -> u8 {
        if let Some(evex) = &self.evex {
            let x_ext = if evex.x { 0 } else { 8 };
            if evex.apx_mode {
                let x4_ext = if evex.x4 { 0 } else { 16 };
                x_ext | x4_ext
            } else {
                x_ext
            }
        } else {
            // Fall back to REX.X
            self.rex.map_or(0, |r| (r & 0x02) << 2)
        }
    }

    /// Get vector length from EVEX.L'L (0=128, 1=256, 2=512 bits)
    pub fn evex_vl(&self) -> u16 {
        if let Some(evex) = &self.evex {
            match evex.ll {
                0 => 128,
                1 => 256,
                2 => 512,
                _ => 128,
            }
        } else {
            128
        }
    }

    /// Check if EVEX zeroing-masking is enabled
    pub fn evex_zeroing(&self) -> bool {
        self.evex.map_or(false, |e| e.z)
    }

    /// Get opmask register index (k0-k7)
    pub fn evex_mask(&self) -> u8 {
        self.evex.map_or(0, |e| e.aaa)
    }

    /// Check if EVEX broadcast is enabled
    pub fn evex_broadcast(&self) -> bool {
        self.evex.map_or(false, |e| e.broadcast)
    }

    /// Get EVEX.W bit (element width)
    pub fn evex_w(&self) -> bool {
        self.evex.map_or(false, |e| e.w)
    }

    // =========================================================================
    // APX-specific helper methods
    // =========================================================================

    /// Check if this is an APX (EVEX-encoded GPR) instruction
    #[inline(always)]
    pub fn is_apx(&self) -> bool {
        self.evex.map_or(false, |e| e.apx_mode)
    }

    /// Check if NDD (New Data Destination) mode is enabled
    /// In NDD mode, the vvvv field specifies a separate destination register
    #[inline(always)]
    pub fn apx_ndd(&self) -> bool {
        self.evex.map_or(false, |e| e.nd)
    }

    /// Check if NF (No Flags) mode is enabled
    /// In NF mode, arithmetic operations don't update RFLAGS
    #[inline(always)]
    pub fn apx_nf(&self) -> bool {
        self.evex.map_or(false, |e| e.nf)
    }

    /// Get the NDD destination register (from vvvv field with V4 extension)
    /// Only valid when apx_ndd() returns true
    #[inline(always)]
    pub fn apx_ndd_reg(&self) -> u8 {
        self.evex_vvvv()
    }

    /// Error to return when the decoder runs out of fetched instruction bytes.
    /// If `fetch` truncated the byte buffer at a canonical-address boundary
    /// (`boundary_gp`), the missing bytes are not an internal error: the
    /// instruction stream ran into non-canonical linear space, which is a #GP(0).
    /// The run loop then injects #GP instead of aborting the VM. (#PF truncation is
    /// returned eagerly by `fetch`, so a truncated fetch is always the #GP case.)
    #[inline]
    pub(super) fn out_of_bytes(&self) -> Error {
        if self.boundary_gp {
            Error::GeneralProtection { error_code: 0 }
        } else {
            Error::Emulator("instruction too short".to_string())
        }
    }

    /// Consume and return the next byte.
    #[inline(always)]
    pub fn consume_u8(&mut self) -> Result<u8> {
        if self.cursor >= self.bytes_len {
            return Err(self.out_of_bytes());
        }
        let b = self.bytes[self.cursor];
        self.cursor += 1;
        Ok(b)
    }

    /// Peek at the next byte without consuming.
    #[inline(always)]
    #[allow(dead_code)]
    pub fn peek_u8(&self) -> Result<u8> {
        if self.cursor >= self.bytes_len {
            return Err(self.out_of_bytes());
        }
        Ok(self.bytes[self.cursor])
    }

    /// Consume and return a little-endian u16.
    #[inline(always)]
    pub fn consume_u16(&mut self) -> Result<u16> {
        if self.cursor + 2 > self.bytes_len {
            return Err(self.out_of_bytes());
        }
        let val = u16::from_le_bytes([self.bytes[self.cursor], self.bytes[self.cursor + 1]]);
        self.cursor += 2;
        Ok(val)
    }

    /// Consume and return a little-endian u32.
    #[inline(always)]
    pub fn consume_u32(&mut self) -> Result<u32> {
        if self.cursor + 4 > self.bytes_len {
            return Err(self.out_of_bytes());
        }
        let val = u32::from_le_bytes([
            self.bytes[self.cursor],
            self.bytes[self.cursor + 1],
            self.bytes[self.cursor + 2],
            self.bytes[self.cursor + 3],
        ]);
        self.cursor += 4;
        Ok(val)
    }

    /// Consume and return a little-endian u64.
    #[inline(always)]
    pub fn consume_u64(&mut self) -> Result<u64> {
        if self.cursor + 8 > self.bytes_len {
            return Err(self.out_of_bytes());
        }
        let val = u64::from_le_bytes([
            self.bytes[self.cursor],
            self.bytes[self.cursor + 1],
            self.bytes[self.cursor + 2],
            self.bytes[self.cursor + 3],
            self.bytes[self.cursor + 4],
            self.bytes[self.cursor + 5],
            self.bytes[self.cursor + 6],
            self.bytes[self.cursor + 7],
        ]);
        self.cursor += 8;
        Ok(val)
    }

    /// Read an immediate value of the specified size.
    pub fn consume_imm(&mut self, size: u8) -> Result<u64> {
        match size {
            1 => Ok(self.consume_u8()? as u64),
            2 => Ok(self.consume_u16()? as u64),
            4 => Ok(self.consume_u32()? as u64),
            8 => Ok(self.consume_u64()?),
            _ => Err(Error::Emulator(format!("invalid immediate size: {}", size))),
        }
    }
}

impl X86_64Vcpu {
    pub fn new(id: u32, mem: Arc<GuestMemoryMmap>) -> Self {
        // Use vec! to heap-allocate the cache, then convert to boxed array
        let cache_vec = vec![DecodeCacheEntry::default(); DECODE_CACHE_SIZE];
        let decode_cache: Box<[DecodeCacheEntry; DECODE_CACHE_SIZE]> =
            cache_vec.into_boxed_slice().try_into().unwrap();

        X86_64Vcpu {
            id,
            insn_count: 0,
            regs: Registers::default(),
            sregs: SystemRegisters::default(),
            mmu: Mmu::new(mem),
            fpu: FpuState::default(),
            halted: false,
            interrupt_inhibit: false,
            io_pending: None,
            kernel_gs_base: 0,
            tsc_adjust: 0,
            tsc_aux: 0,
            misc_enable: execute::system::IA32_MISC_ENABLE_RESET,
            pat: execute::system::IA32_PAT_RESET,
            umwait_control: 0,
            pkru: 0,
            mxcsr: 0x1F80,
            xcr0: 1, // x87 state component always enabled
            xgetbv1_value: 0,
            xeon_phi_avx512: false,
            vp2intersect: false,
            sse4a: false,
            tbm: false,
            xop: false,
            avx10_media: false,
            avx10_vminmax: false,
            avx10_sat_convert: false,
            apx: false,

            decode_cache,
            lazy_flags: LazyFlags::default(),
            #[cfg(feature = "debug")]
            single_step: false,
            #[cfg(feature = "debug")]
            debugger_active: false,
            #[cfg(feature = "debug")]
            debug_breakpoints: std::collections::HashSet::new(),
            bios_cdrom: None,
            bios_mem_bytes: 0,
            #[cfg(all(
                feature = "smir-jit",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            jit_cache: std::collections::HashMap::new(),
            #[cfg(all(
                feature = "smir-jit",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            jit_hot: std::collections::HashMap::new(),
            #[cfg(all(
                feature = "smir-jit",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            jit_ineligible: std::collections::HashMap::new(),
            #[cfg(all(
                feature = "smir-jit",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            jit_ineligible_dirty: std::collections::HashSet::new(),
            #[cfg(all(
                feature = "smir-jit",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            jit_active_source_range: None,
            #[cfg(all(
                feature = "smir-jit",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            jit_active_region_stale: false,
            #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
            jit_mem: jit_mem_enabled() || jit_call_enabled(),
            #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
            jit_call: jit_call_enabled(),
            #[cfg(all(
                feature = "smir-jit",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            jit_callout_exit: None,
            #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
            jit_mem_log: None,
            #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
            jit_mem_trace: None,
            #[cfg(any(test, all(feature = "smir-jit", target_arch = "x86_64")))]
            jit_verify_vsib_stop: None,
            #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
            jit_vsib_resume_pc: None,
        }
    }

    /// Configure the value returned by `XGETBV` with `ECX=1`.
    ///
    /// KVM exposes this as part of externally installed extended-control state;
    /// regular guests leave it at the architectural zero default.
    pub fn set_xgetbv1_value(&mut self, value: u64) {
        self.xgetbv1_value = value;
    }

    /// Enable or disable Xeon Phi-only AVX-512 subsets for semantic harnesses.
    pub fn set_xeon_phi_avx512_enabled(&mut self, enabled: bool) {
        self.xeon_phi_avx512 = enabled;
    }

    #[inline]
    pub(in crate::isa::x86_64) fn xeon_phi_avx512_enabled(&self) -> bool {
        self.xeon_phi_avx512
    }

    /// Enable or disable AVX512_VP2INTERSECT for semantic harnesses.
    pub fn set_vp2intersect_enabled(&mut self, enabled: bool) {
        self.vp2intersect = enabled;
    }

    #[inline]
    pub(in crate::isa::x86_64) fn vp2intersect_enabled(&self) -> bool {
        self.vp2intersect
    }

    /// Enable or disable AMD SSE4A instructions for semantic harnesses.
    pub fn set_sse4a_enabled(&mut self, enabled: bool) {
        self.sse4a = enabled;
    }

    #[inline]
    pub(in crate::isa::x86_64) fn sse4a_enabled(&self) -> bool {
        self.sse4a
    }

    /// Enable or disable AMD TBM instructions for semantic harnesses.
    pub fn set_tbm_enabled(&mut self, enabled: bool) {
        self.tbm = enabled;
    }

    #[inline]
    pub(in crate::isa::x86_64) fn tbm_enabled(&self) -> bool {
        self.tbm
    }

    /// Enable or disable AMD XOP packed-vector instructions for semantic
    /// harnesses.
    pub fn set_xop_enabled(&mut self, enabled: bool) {
        self.xop = enabled;
    }

    #[inline]
    pub(in crate::isa::x86_64) fn xop_enabled(&self) -> bool {
        self.xop
    }

    /// Enable or disable AVX10.2 media dot-product instructions for semantic harnesses.
    pub fn set_avx10_media_enabled(&mut self, enabled: bool) {
        self.avx10_media = enabled;
    }

    #[inline]
    pub(in crate::isa::x86_64) fn avx10_media_enabled(&self) -> bool {
        self.avx10_media
    }

    /// Enable or disable AVX10.2 VMINMAX instructions for semantic harnesses.
    pub fn set_avx10_vminmax_enabled(&mut self, enabled: bool) {
        self.avx10_vminmax = enabled;
    }

    #[inline]
    pub(in crate::isa::x86_64) fn avx10_vminmax_enabled(&self) -> bool {
        self.avx10_vminmax
    }

    /// Enable or disable AVX10.2 saturation conversion instructions for semantic harnesses.
    pub fn set_avx10_sat_convert_enabled(&mut self, enabled: bool) {
        self.avx10_sat_convert = enabled;
    }

    #[inline]
    pub(in crate::isa::x86_64) fn avx10_sat_convert_enabled(&self) -> bool {
        self.avx10_sat_convert
    }

    /// Enable or disable Intel APX instructions for semantic harnesses.
    pub fn set_apx_enabled(&mut self, enabled: bool) {
        self.apx = enabled;
    }

    #[inline]
    pub(in crate::isa::x86_64) fn apx_enabled(&self) -> bool {
        self.apx
    }

    #[cfg(feature = "debug")]
    #[inline]
    fn debug_breakpoint_at_current_rip(&self) -> Option<u64> {
        let rip = self.regs.rip;
        self.debug_breakpoints.contains(&rip).then_some(rip)
    }

    #[cfg(all(
        feature = "smir-jit",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[inline]
    fn jit_disabled_for_debugger(&self) -> bool {
        #[cfg(feature = "debug")]
        {
            self.debugger_active
        }
        #[cfg(not(feature = "debug"))]
        {
            false
        }
    }

    /// Run-loop periodic work shared by interpreter execution and JIT call-outs.
    /// Returns true when execution should yield back to the VMM.
    #[inline]
    fn poll_periodic_housekeeping(&mut self, start_time: &std::time::Instant) -> bool {
        if let Some(vector) = self.mmu.tick_lapic_timer() {
            if self.can_inject_interrupt() && self.inject_interrupt(vector).unwrap_or(false) {
                self.mmu.clear_lapic_pending();
                self.halted = false;
            }
        }

        start_time.elapsed().as_millis() >= 1
    }

    #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
    #[inline]
    fn jit_callout_should_yield(&mut self, start_time: &std::time::Instant, steps: u64) -> bool {
        steps % LAPIC_POLL_STRIDE == 0 && self.poll_periodic_housekeeping(start_time)
    }

    /// Materialize lazy flags into rflags.
    /// Call this before any instruction that reads flags (Jcc, CMOVcc, SETcc, ADC, SBB, PUSHF, LAHF).
    #[inline]
    pub(super) fn materialize_flags(&mut self) {
        let lf = self.lazy_flags;
        if lf.op == LazyFlagOp::None {
            return; // Flags already materialized
        }

        let result = lf.result;
        let a = lf.src;
        let b = lf.dst;
        let size = lf.size;

        let mask = match size {
            1 => 0xFFu64,
            2 => 0xFFFFu64,
            4 => 0xFFFF_FFFFu64,
            _ => u64::MAX,
        };
        let result_m = result & mask;
        let a_m = a & mask;
        let b_m = b & mask;

        let sign_bit = match size {
            1 => 0x80u64,
            2 => 0x8000u64,
            4 => 0x8000_0000u64,
            _ => 0x8000_0000_0000_0000u64,
        };

        // Common flags for all operations
        let zf = result_m == 0;
        let sf = (result_m & sign_bit) != 0;
        let pf = (result as u8).count_ones() % 2 == 0;

        // Clear status flags (preserve CF for Inc/Dec)
        let cf_mask = if lf.op == LazyFlagOp::Inc || lf.op == LazyFlagOp::Dec {
            0 // Don't clear CF for INC/DEC
        } else {
            flags::bits::CF
        };
        self.regs.rflags &= !(cf_mask
            | flags::bits::ZF
            | flags::bits::SF
            | flags::bits::PF
            | flags::bits::OF
            | flags::bits::AF);

        // Set common flags
        if zf {
            self.regs.rflags |= flags::bits::ZF;
        }
        if sf {
            self.regs.rflags |= flags::bits::SF;
        }
        if pf {
            self.regs.rflags |= flags::bits::PF;
        }

        // Operation-specific flags
        match lf.op {
            LazyFlagOp::Add | LazyFlagOp::Inc => {
                let cf = result_m < a_m;
                let of = ((a_m ^ result_m) & (b_m ^ result_m) & sign_bit) != 0;
                let af = ((a_m ^ b_m ^ result_m) & 0x10) != 0;
                if lf.op == LazyFlagOp::Add && cf {
                    self.regs.rflags |= flags::bits::CF;
                }
                if of {
                    self.regs.rflags |= flags::bits::OF;
                }
                if af {
                    self.regs.rflags |= flags::bits::AF;
                }
            }
            LazyFlagOp::Sub | LazyFlagOp::Dec => {
                let cf = a_m < b_m;
                let of = ((a_m ^ b_m) & (a_m ^ result_m) & sign_bit) != 0;
                let af = ((a_m ^ b_m ^ result_m) & 0x10) != 0;
                if lf.op == LazyFlagOp::Sub && cf {
                    self.regs.rflags |= flags::bits::CF;
                }
                if of {
                    self.regs.rflags |= flags::bits::OF;
                }
                if af {
                    self.regs.rflags |= flags::bits::AF;
                }
            }
            LazyFlagOp::Logic => {
                // CF=0, OF=0 already cleared above; AF is undefined
            }
            LazyFlagOp::None => {}
        }

        // Mark flags as materialized
        self.lazy_flags = LazyFlags {
            op: LazyFlagOp::None,
            ..lf
        };
    }

    /// Compute what rflags would be if lazy flags were materialized (without modifying self).
    /// Used by get_state() to return accurate flags via &self.
    #[inline]
    fn compute_materialized_rflags(&self) -> u64 {
        let lf = self.lazy_flags;
        if lf.op == LazyFlagOp::None {
            return self.regs.rflags; // Already materialized
        }

        let result = lf.result;
        let a = lf.src;
        let b = lf.dst;
        let size = lf.size;

        let mask = match size {
            1 => 0xFFu64,
            2 => 0xFFFFu64,
            4 => 0xFFFF_FFFFu64,
            _ => u64::MAX,
        };
        let result_m = result & mask;
        let a_m = a & mask;
        let b_m = b & mask;

        let sign_bit = match size {
            1 => 0x80u64,
            2 => 0x8000u64,
            4 => 0x8000_0000u64,
            _ => 0x8000_0000_0000_0000u64,
        };

        // Common flags for all operations
        let zf = result_m == 0;
        let sf = (result_m & sign_bit) != 0;
        let pf = (result as u8).count_ones() % 2 == 0;

        // Start with current rflags, clear status flags (preserve CF for Inc/Dec)
        let cf_mask = if lf.op == LazyFlagOp::Inc || lf.op == LazyFlagOp::Dec {
            0 // Don't clear CF for INC/DEC
        } else {
            flags::bits::CF
        };
        let mut rflags = self.regs.rflags
            & !(cf_mask
                | flags::bits::ZF
                | flags::bits::SF
                | flags::bits::PF
                | flags::bits::OF
                | flags::bits::AF);

        // Set common flags
        if zf {
            rflags |= flags::bits::ZF;
        }
        if sf {
            rflags |= flags::bits::SF;
        }
        if pf {
            rflags |= flags::bits::PF;
        }

        // Operation-specific flags
        match lf.op {
            LazyFlagOp::Add | LazyFlagOp::Inc => {
                let cf = result_m < a_m;
                let of = ((a_m ^ result_m) & (b_m ^ result_m) & sign_bit) != 0;
                let af = ((a_m ^ b_m ^ result_m) & 0x10) != 0;
                if lf.op == LazyFlagOp::Add && cf {
                    rflags |= flags::bits::CF;
                }
                if of {
                    rflags |= flags::bits::OF;
                }
                if af {
                    rflags |= flags::bits::AF;
                }
            }
            LazyFlagOp::Sub | LazyFlagOp::Dec => {
                let cf = a_m < b_m;
                let of = ((a_m ^ b_m) & (a_m ^ result_m) & sign_bit) != 0;
                let af = ((a_m ^ b_m ^ result_m) & 0x10) != 0;
                if lf.op == LazyFlagOp::Sub && cf {
                    rflags |= flags::bits::CF;
                }
                if of {
                    rflags |= flags::bits::OF;
                }
                if af {
                    rflags |= flags::bits::AF;
                }
            }
            LazyFlagOp::Logic => {
                // CF=0, OF=0 already cleared above; AF is undefined
            }
            LazyFlagOp::None => {}
        }

        rflags
    }

    /// Set lazy flags for an Add operation
    #[inline(always)]
    pub(super) fn set_lazy_add(&mut self, a: u64, b: u64, result: u64, size: u8) {
        self.lazy_flags = LazyFlags {
            op: LazyFlagOp::Add,
            result,
            src: a,
            dst: b,
            size,
        };
    }

    /// Set lazy flags for a Sub/CMP operation
    #[inline(always)]
    pub(super) fn set_lazy_sub(&mut self, a: u64, b: u64, result: u64, size: u8) {
        self.lazy_flags = LazyFlags {
            op: LazyFlagOp::Sub,
            result,
            src: a,
            dst: b,
            size,
        };
    }

    /// Set lazy flags for a Logic operation (AND/OR/XOR/TEST)
    #[inline(always)]
    pub(super) fn set_lazy_logic(&mut self, result: u64, size: u8) {
        self.lazy_flags = LazyFlags {
            op: LazyFlagOp::Logic,
            result,
            src: 0,
            dst: 0,
            size,
        };
    }

    /// Set lazy flags for an Inc operation (CF preserved)
    #[inline(always)]
    pub(super) fn set_lazy_inc(&mut self, a: u64, result: u64, size: u8) {
        self.lazy_flags = LazyFlags {
            op: LazyFlagOp::Inc,
            result,
            src: a,
            dst: 1,
            size,
        };
    }

    /// Set lazy flags for a Dec operation (CF preserved)
    #[inline(always)]
    pub(super) fn set_lazy_dec(&mut self, a: u64, result: u64, size: u8) {
        self.lazy_flags = LazyFlags {
            op: LazyFlagOp::Dec,
            result,
            src: a,
            dst: 1,
            size,
        };
    }

    /// Clear lazy flags state (call after directly writing to rflags)
    #[inline(always)]
    pub(super) fn clear_lazy_flags(&mut self) {
        let lf = self.lazy_flags;
        self.lazy_flags = LazyFlags {
            op: LazyFlagOp::None,
            ..lf
        };
    }

    /// Resolve ONLY the CF bit of any pending lazy op into `regs.rflags`, leaving
    /// the lazy op intact for later full materialization. Used by INC/DEC, which
    /// preserve CF: before switching the lazy state to Inc/Dec we must lock in the
    /// CF that the pending op would have produced, without paying for a full
    /// 6-flag computation. Inc/Dec/None already have valid CF in `rflags`, so
    /// those are no-ops; Logic forces CF=0; Add/Sub compute the single carry bit.
    #[inline(always)]
    pub(super) fn resolve_lazy_cf(&mut self) {
        let lf = self.lazy_flags;
        match lf.op {
            LazyFlagOp::None | LazyFlagOp::Inc | LazyFlagOp::Dec => {
                // CF in rflags is already authoritative for these.
            }
            LazyFlagOp::Logic => {
                self.regs.rflags &= !flags::bits::CF;
            }
            LazyFlagOp::Add => {
                let mask = Self::size_mask(lf.size);
                let cf = (lf.result & mask) < (lf.src & mask);
                if cf {
                    self.regs.rflags |= flags::bits::CF;
                } else {
                    self.regs.rflags &= !flags::bits::CF;
                }
            }
            LazyFlagOp::Sub => {
                let mask = Self::size_mask(lf.size);
                let cf = (lf.src & mask) < (lf.dst & mask);
                if cf {
                    self.regs.rflags |= flags::bits::CF;
                } else {
                    self.regs.rflags &= !flags::bits::CF;
                }
            }
        }
    }

    /// Operand-size mask shared by the lazy-flag paths.
    #[inline(always)]
    fn size_mask(size: u8) -> u64 {
        match size {
            1 => 0xFFu64,
            2 => 0xFFFFu64,
            4 => 0xFFFF_FFFFu64,
            _ => u64::MAX,
        }
    }

    /// Fetch instruction bytes from RIP into a stack buffer.
    /// Returns (buffer, actual_length).
    #[inline]
    /// Fetch instruction bytes at RIP. Returns `(buf, len, boundary_gp)` where
    /// `boundary_gp` is true when the byte window was truncated to `len` because
    /// the bytes beyond it cross into non-canonical linear space (a #GP, not #PF).
    /// The decoder defers that #GP until/unless it actually needs a truncated byte,
    /// so a short instruction that merely sits near the boundary still executes.
    pub(super) fn fetch(&mut self) -> Result<([u8; MAX_INSN_LEN], usize, bool)> {
        // The fetch linear address is CS.base + RIP. In 64-bit mode (CS.L=1) the
        // CS base is architecturally ignored for address generation (treated as
        // 0) even if a descriptor load recorded a non-zero base — so a far
        // transfer that adopts a based 64-bit segment still fetches flat. In
        // every other mode (IA-32e compatibility, legacy protected, real) the
        // base IS applied (selector<<4 in real mode, descriptor base otherwise).
        let cs_base = if self.sregs.cs.l {
            0
        } else {
            self.sregs.cs.base
        };
        let rip = cs_base.wrapping_add(self.regs.rip);
        // Mark this page as containing code for self-modifying code detection
        self.mmu.mark_code_page(rip);

        // Suppress per-access recording for the fetch-window read; the fetch is
        // reported once below (one Exec record per instruction, not Reads of the
        // 15-byte window). Zero cost when recording is off.
        self.mmu.set_fetch_active(true);
        let result = self.fetch_window(rip);
        self.mmu.set_fetch_active(false);
        if let Ok((_, len, _)) = &result {
            self.mmu.record_fetch(rip, (*len).min(MAX_INSN_LEN) as u8);
        }
        result
    }

    /// Reads the up-to-15-byte instruction window at linear address `rip`,
    /// retrying shorter lengths near a page/canonical boundary.
    fn fetch_window(&mut self, rip: u64) -> Result<([u8; MAX_INSN_LEN], usize, bool)> {
        let mut buf = [0u8; MAX_INSN_LEN];
        let mut last_err = None;
        match self.mmu.read(rip, &mut buf, &self.sregs) {
            Ok(()) => return Ok((buf, MAX_INSN_LEN, false)),
            Err(Error::PageFault { vaddr, error_code }) => {
                // Instruction fetch page fault - add instruction fetch bit to error code
                return Err(Error::PageFault {
                    vaddr,
                    error_code: error_code | 0x10,
                });
            }
            Err(e) => last_err = Some(e), // Try smaller amounts
        }
        // If we can't read 15 bytes, try smaller amounts
        for len in (1..MAX_INSN_LEN).rev() {
            match self.mmu.read(rip, &mut buf[..len], &self.sregs) {
                Ok(()) => {
                    // A shorter read succeeded only because the bytes past `len`
                    // were unreadable. #PF is returned eagerly above, so the only
                    // way to land here with a pending fault is a non-canonical
                    // boundary (#GP). Flag it so the decoder, if it needs one of the
                    // missing bytes, raises #GP(0) instead of a fatal "instruction
                    // too short" — but a short instruction that fits in `len` bytes
                    // still executes normally.
                    let boundary_gp = matches!(last_err, Some(Error::GeneralProtection { .. }));
                    return Ok((buf, len, boundary_gp));
                }
                Err(Error::PageFault { vaddr, error_code }) => {
                    return Err(Error::PageFault {
                        vaddr,
                        error_code: error_code | 0x10,
                    });
                }
                Err(e) => last_err = Some(e),
            }
        }
        // If not even a single byte was fetchable, the failure is architectural,
        // not internal. A non-canonical RIP fails every length above with #GP;
        // surface that fault so the run loop delivers it instead of aborting the
        // VM with a generic emulator error. (#PF already returned above; the
        // smaller-length retries handle a short instruction whose 15-byte fetch
        // window merely spills past a page or canonical boundary.)
        if let Some(e @ Error::GeneralProtection { .. }) = last_err {
            return Err(e);
        }
        // Debug: print the actual error
        if let Some(e) = &last_err {
            eprintln!(
                "[FETCH FAIL] RIP={:#x} CR3={:#x} CR0={:#x} EFER={:#x} error: {:?}",
                rip, self.sregs.cr3, self.sregs.cr0, self.sregs.efer, e
            );
        }
        Err(Error::Emulator(format!(
            "failed to fetch instruction at RIP={:#x}",
            rip
        )))
    }

    /// Compute decode cache index from RIP
    #[inline(always)]
    fn decode_cache_index(rip: u64) -> usize {
        (rip as usize) & DECODE_CACHE_MASK
    }

    /// Address-space + CPU-mode discriminator for decode-cache entries.
    #[inline(always)]
    pub(super) fn decode_mode_tag(&self) -> u64 {
        let real_mode_cs_base = if self.sregs.cr0 & 1 == 0 {
            self.sregs.cs.base
        } else {
            0
        };
        (self.sregs.cr3 & !0xFFF)
            | (self.sregs.cs.l as u64)
            | ((self.sregs.cs.db as u64) << 1)
            | real_mode_cs_base
    }

    /// A key match is not enough for a safe cache hit: the current MMU fetch
    /// must still succeed and return the same byte window that was decoded.
    #[inline(always)]
    pub(super) fn decode_cache_bytes_current(
        cached: &DecodeCacheEntry,
        bytes: &[u8; MAX_INSN_LEN],
        bytes_len: usize,
        boundary_gp: bool,
    ) -> bool {
        !boundary_gp
            && cached.bytes_len == bytes_len
            && cached.bytes[..bytes_len] == bytes[..bytes_len]
    }

    /// Execute a single instruction.
    #[inline]
    /// Per-vCPU timestamp counter. Real-time: tracks host wall-clock elapsed
    /// since emulator start, scaled to the advertised 3 GHz (3 cycles/ns), and
    /// applies the architectural per-vCPU IA32_TSC_ADJUST offset.
    #[inline(always)]
    pub(super) fn tsc(&self) -> u64 {
        crate::vm::timing::elapsed_nanos()
            .wrapping_mul(3)
            .wrapping_add(self.tsc_adjust)
    }

    /// Execute one instruction attempt and consume any STI/MOV-SS interrupt
    /// shadow that protected this boundary. Fetch/decode/execution faults also
    /// consume the shadow because delivery of that event ends inhibition.
    pub fn step(&mut self) -> Result<Option<VcpuExit>> {
        self.interrupt_inhibit = false;
        self.step_inner()
    }

    #[inline]
    fn step_inner(&mut self) -> Result<Option<VcpuExit>> {
        // Retired-instruction counter. Plain add - no atomics on the hot path
        // (published to the global counter at run() yield boundaries).
        self.insn_count = self.insn_count.wrapping_add(1);

        // Start profiling timer
        #[cfg(feature = "profiling")]
        let prof_start = profiling::begin_instruction();

        // Crash-diagnostic RIP telemetry (debug builds only - these are atomics).
        #[cfg(feature = "debug")]
        {
            CURRENT_RIP.store(self.regs.rip, Ordering::Relaxed);
            let idx = RIP_IDX.fetch_add(1, Ordering::Relaxed) % 16;
            RIP_HISTORY[idx].store(self.regs.rip, Ordering::Relaxed);
        }

        let rip = self.regs.rip;

        let cache_idx = Self::decode_cache_index(rip);
        // Key on address space (CR3) + CPU mode so a hit can never dispatch stale
        // bytes/decode across a context or mode switch. In real mode there is no
        // paging (cr3 unused) and the fetch linear address is CS.base + RIP, so
        // CS.base must be part of the key — otherwise the same offset under
        // different segments (common in real-mode relocators) would alias to one
        // cached decode. CS.base is 0 in long mode, so this is a no-op there.
        let mode_tag = self.decode_mode_tag();

        // Check decode cache for a hit (copy to avoid borrow issues). A filled
        // entry always has bytes_len >= 1; default/invalidated entries have
        // bytes_len == 0. This guard matters in real mode, where the empty
        // sentinel (rip==0, mode_tag==0) would otherwise collide with a guest
        // legitimately executing at offset 0 of a segment.
        let cached = self.decode_cache[cache_idx];
        let mut fetched_miss = None;
        if cached.bytes_len != 0 && cached.rip == rip && cached.mode_tag == mode_tag {
            // Validate the hit against the current MMU state. This preserves
            // instruction-fetch faults and catches remaps or permission changes
            // that are not represented in the cache key.
            let (bytes, bytes_len, boundary_gp) = self.fetch()?;
            if Self::decode_cache_bytes_current(&cached, &bytes, bytes_len, boundary_gp) {
                // Cache hit! Record for profiling only after validation, so a
                // stale entry that falls through to full decode counts as a miss.
                #[cfg(feature = "profiling")]
                profiling::record_cache_hit();

                let mut ctx = InsnContext {
                    bytes,
                    bytes_len,
                    cursor: if cached.rex2.map_or(false, |r| r.m) {
                        cached.cursor
                    } else {
                        cached.cursor + 1 // Skip past opcode byte
                    },
                    rex: cached.rex,
                    rex2: cached.rex2,
                    operand_size_override: cached.operand_size_override,
                    address_size_override: cached.address_size_override,
                    rep_prefix: cached.rep_prefix,
                    op_size: cached.op_size,
                    rip_relative_offset: 0,
                    segment_override: cached.segment_override,
                    evex: None,
                    opcode: cached.opcode,
                    // Boundary-truncated instructions are never cached (see the fill
                    // path below), so a cache hit always has the full instruction.
                    boundary_gp: false,
                };

                if self.reject_invalid_rex2_prefix_order(&ctx)? {
                    return Ok(None);
                }

                if self.reject_reserved_rex2_opcode(&ctx, cached.opcode)? {
                    return Ok(None);
                }

                if self.reject_disabled_apx(&ctx)? {
                    return Ok(None);
                }

                // Enforce LOCK-prefix legality (#UD on illegal use) before dispatch.
                // The LOCK-present verdict was computed once on the fill path, so the
                // hit path skips the prefix-byte scan and only takes the (cold)
                // legality check when a 0xF0 prefix is actually present.
                if cached.has_lock {
                    if self.enforce_lock_prefix_cold(&ctx, cached.opcode)? {
                        return Ok(None);
                    }
                }

                // Function-pointer dispatch: call the handler resolved on the fill
                // path directly, skipping the `execute` opcode match and the
                // two-byte / escape call chain. Equivalent to `trace_and_execute`
                // when tracing is off (the common build); the `trace` build keeps
                // the instrumented path so traces stay complete.
                let result = self.trace_and_execute_cached(cached.handler, &mut ctx, rip);

                // End profiling for this instruction
                #[cfg(feature = "profiling")]
                {
                    // Use precise opcode key if set by dispatch, otherwise fall back to simple key
                    let key = profiling::take_current_opcode_key()
                        .unwrap_or_else(|| profiling::build_simple_opcode_key(cached.opcode));
                    profiling::end_instruction(key, prof_start);
                }

                return result;
            }

            // Fetched bytes no longer match the cached decode, or the fetch is
            // now boundary-truncated. Drop the stale entry and fall through to a
            // full decode using the fresh fetch.
            self.decode_cache[cache_idx] = DecodeCacheEntry::default();
            fetched_miss = Some((bytes, bytes_len, boundary_gp));
        }

        // Cache miss - do full decode
        #[cfg(feature = "profiling")]
        profiling::record_cache_miss();

        let (bytes, bytes_len, boundary_gp) = match fetched_miss {
            Some(fetched) => fetched,
            None => self.fetch()?,
        };

        // Decode prefixes (mode-aware: 0xD5 is REX2 in long mode, AAD otherwise)
        let mut ctx = Decoder::decode_prefixes(bytes, bytes_len, boundary_gp, self.sregs.cs.l)?;

        // Determine operand size (64-bit mode defaults to 32-bit; compat depends on CS.D).
        ctx.op_size = if self.sregs.cs.l {
            if ctx.any_rex_w() {
                8
            } else if ctx.operand_size_override {
                2
            } else {
                4
            }
        } else {
            let default_16bit = !self.sregs.cs.db;
            let is_16bit = default_16bit ^ ctx.operand_size_override;
            if is_16bit { 2 } else { 4 }
        };

        // Save cursor before consuming opcode (for cache)
        let opcode_cursor = ctx.cursor;

        // Get opcode. REX2.M selects the 0F opcode map without encoding an
        // actual 0x0F byte, so leave the cursor on the map opcode and dispatch
        // through the normal two-byte handler.
        let opcode = if ctx.rex2_m() {
            0x0F
        } else {
            ctx.consume_u8()?
        };
        ctx.opcode = opcode;

        // Resolve the handler once, here on the (cold) miss path, so subsequent
        // hits dispatch via the stored fn-pointer. `None` => opcode unimplemented
        // in `execute`; store a shim that re-enters `execute` to yield the exact
        // same error the match would (keeps the slow path byte-for-byte correct).
        let handler = Self::resolve_handler(opcode).unwrap_or(Self::execute_via_match);

        // Detect a LOCK (0xF0) prefix once, here on the fill path, and cache the
        // verdict so hits skip the prefix-byte scan entirely.
        let has_lock = ctx.bytes[..opcode_cursor.min(ctx.bytes_len)].contains(&0xF0);

        // Cache the decoded instruction and the byte window it was decoded from.
        // Never cache a boundary-truncated fetch: its byte window is short, so a
        // later cache hit would re-run the handler and hit "instruction too short"
        // without the boundary_gp flag, turning the architectural #GP back into a
        // fatal error. A fresh decode re-derives boundary_gp every time instead.
        if !boundary_gp {
            self.decode_cache[cache_idx] = DecodeCacheEntry {
                rip,
                mode_tag,
                opcode,
                op_size: ctx.op_size,
                cursor: opcode_cursor,
                rex: ctx.rex,
                rex2: ctx.rex2,
                operand_size_override: ctx.operand_size_override,
                address_size_override: ctx.address_size_override,
                rep_prefix: ctx.rep_prefix,
                segment_override: ctx.segment_override,
                bytes: ctx.bytes,
                bytes_len: ctx.bytes_len,
                has_lock,
                handler,
            };
        }

        if self.reject_invalid_rex2_prefix_order(&ctx)? {
            return Ok(None);
        }

        if self.reject_reserved_rex2_opcode(&ctx, opcode)? {
            return Ok(None);
        }

        if self.reject_disabled_apx(&ctx)? {
            return Ok(None);
        }

        // Enforce LOCK-prefix legality (#UD on illegal use) before dispatch.
        // `opcode_cursor` is the primary-opcode offset; prefixes precede it. Only
        // pay the legality check when a LOCK prefix is actually present.
        if has_lock {
            if self.enforce_lock_prefix_cold(&ctx, opcode)? {
                return Ok(None);
            }
        }

        // Execute instruction
        let result = self.trace_and_execute(opcode, &mut ctx, rip);

        // End profiling for this instruction
        #[cfg(feature = "profiling")]
        {
            // Use precise opcode key if set by dispatch, otherwise fall back to simple key
            let key = profiling::take_current_opcode_key()
                .unwrap_or_else(|| profiling::build_simple_opcode_key(opcode));
            profiling::end_instruction(key, prof_start);
        }

        result
    }

    /// Execute instruction with optional tracing (when trace feature is enabled)
    #[cfg(feature = "trace")]
    #[inline]
    fn trace_and_execute(
        &mut self,
        opcode: u8,
        ctx: &mut InsnContext,
        rip: u64,
    ) -> Result<Option<VcpuExit>> {
        if trace::is_enabled() {
            // Save pre-execution state for comparison
            let pre_regs = self.regs.clone();
            let pre_xmm = self.regs.xmm.clone();

            // Execute the instruction
            let result = self.execute(opcode, ctx);

            // Format instruction bytes as hex
            let insn_len = ctx.cursor.min(15);
            let mut insn_hex = String::with_capacity(insn_len * 3);
            for i in 0..insn_len {
                if i > 0 {
                    insn_hex.push(' ');
                }
                insn_hex.push_str(&format!("{:02x}", ctx.bytes[i]));
            }

            // Build register change description
            let mut changes = String::new();

            // Check for GPR changes
            if self.regs.rax != pre_regs.rax {
                changes.push_str(&format!("rax = 0x{:x}", self.regs.rax));
            }
            if self.regs.rcx != pre_regs.rcx {
                if !changes.is_empty() {
                    changes.push_str(", ");
                }
                changes.push_str(&format!("rcx = 0x{:x}", self.regs.rcx));
            }
            if self.regs.rdx != pre_regs.rdx {
                if !changes.is_empty() {
                    changes.push_str(", ");
                }
                changes.push_str(&format!("rdx = 0x{:x}", self.regs.rdx));
            }
            if self.regs.rbx != pre_regs.rbx {
                if !changes.is_empty() {
                    changes.push_str(", ");
                }
                changes.push_str(&format!("rbx = 0x{:x}", self.regs.rbx));
            }
            if self.regs.rsp != pre_regs.rsp {
                if !changes.is_empty() {
                    changes.push_str(", ");
                }
                changes.push_str(&format!("rsp = 0x{:x}", self.regs.rsp));
            }
            if self.regs.rbp != pre_regs.rbp {
                if !changes.is_empty() {
                    changes.push_str(", ");
                }
                changes.push_str(&format!("rbp = 0x{:x}", self.regs.rbp));
            }
            if self.regs.rsi != pre_regs.rsi {
                if !changes.is_empty() {
                    changes.push_str(", ");
                }
                changes.push_str(&format!("rsi = 0x{:x}", self.regs.rsi));
            }
            if self.regs.rdi != pre_regs.rdi {
                if !changes.is_empty() {
                    changes.push_str(", ");
                }
                changes.push_str(&format!("rdi = 0x{:x}", self.regs.rdi));
            }
            if self.regs.rflags != pre_regs.rflags {
                if !changes.is_empty() {
                    changes.push_str(", ");
                }
                changes.push_str(&format!("rflags = 0x{:x}", self.regs.rflags));
            }

            // Write instruction trace
            trace::write_insn(rip, &insn_hex, &changes);

            // Check for XMM changes and output them
            for i in 0..16 {
                if self.regs.xmm[i] != pre_xmm[i] {
                    trace::write_xmm(i, self.regs.xmm[i][0], self.regs.xmm[i][1]);
                }
            }

            result
        } else {
            self.execute(opcode, ctx)
        }
    }

    /// Execute instruction (no tracing - default when trace feature is disabled)
    #[cfg(not(feature = "trace"))]
    #[inline(always)]
    fn trace_and_execute(
        &mut self,
        opcode: u8,
        ctx: &mut InsnContext,
        _rip: u64,
    ) -> Result<Option<VcpuExit>> {
        self.execute(opcode, ctx)
    }

    /// Uniform-signature wrapper around the `execute` opcode match, used as the
    /// stored handler for opcodes the resolver leaves unmapped (the `_ =>`
    /// unimplemented arm of `execute`). Recovers the opcode from `ctx` so the
    /// stored fn-pointer reproduces the match's behaviour (including its error)
    /// byte-for-byte.
    #[inline(never)]
    #[cold]
    pub(super) fn execute_via_match(&mut self, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
        let opcode = ctx.opcode;
        self.execute(opcode, ctx)
    }

    #[inline(always)]
    pub(in crate::isa::x86_64) fn inject_undefined_instruction(
        &mut self,
    ) -> Result<Option<VcpuExit>> {
        self.inject_exception(6, None)?;
        Ok(None)
    }

    #[inline(always)]
    pub(in crate::isa::x86_64) fn reject_rex2_for_legacy_simd(
        &mut self,
        ctx: &InsnContext,
    ) -> Result<bool> {
        if ctx.rex2.is_none() {
            return Ok(false);
        }

        self.inject_exception(6, None)?;
        Ok(true)
    }

    /// Intel APX requires REX2 to be the final prefix and defines an immediately
    /// preceding legacy REX prefix as #UD. Prefix decoding retains both fields
    /// so the cold and decode-cache-hit paths can enforce the rule identically.
    #[inline(always)]
    pub(super) fn reject_invalid_rex2_prefix_order(&mut self, ctx: &InsnContext) -> Result<bool> {
        if ctx.rex.is_some() && ctx.rex2.is_some() {
            self.inject_exception(6, None)?;
            return Ok(true);
        }

        Ok(false)
    }

    #[inline(always)]
    pub(super) fn reject_disabled_apx(&mut self, ctx: &InsnContext) -> Result<bool> {
        if ctx.rex2.is_some() && !self.apx_enabled() {
            self.inject_exception(6, None)?;
            return Ok(true);
        }

        Ok(false)
    }

    /// Dispatch a decode-cache HIT through the pre-resolved handler fn-pointer.
    ///
    /// In the default (non-`trace`) build this is the whole point of the
    /// fn-pointer cache: one indirect call straight into the handler, skipping
    /// the `execute` match and escape chain.
    #[cfg(not(feature = "trace"))]
    #[inline(always)]
    fn trace_and_execute_cached(
        &mut self,
        handler: HandlerFn,
        ctx: &mut InsnContext,
        _rip: u64,
    ) -> Result<Option<VcpuExit>> {
        handler(self, ctx)
    }

    /// Tracing build: route the cached hit back through the instrumented
    /// `trace_and_execute` (opcode match) so trace output stays complete and
    /// identical to the pre-fn-pointer behaviour. The resolved handler is
    /// equivalent to the match arm, so correctness is unaffected.
    #[cfg(feature = "trace")]
    #[inline]
    fn trace_and_execute_cached(
        &mut self,
        _handler: HandlerFn,
        ctx: &mut InsnContext,
        rip: u64,
    ) -> Result<Option<VcpuExit>> {
        let opcode = ctx.opcode;
        self.trace_and_execute(opcode, ctx, rip)
    }

    // Register access methods
    #[inline(always)]
    pub(super) fn get_reg(&self, reg: u8, size: u8) -> u64 {
        // Branchless GPR read: index the precomputed field-offset table (which
        // respects the actual struct layout via `offset_of!`, so it is sound for
        // any `repr`) instead of a 32-arm match that the profiler showed as a
        // hot jump table inside every ALU handler.
        let off = GPR_OFFSETS[(reg & 0x1F) as usize];
        // SAFETY: `off` is the real byte offset of a `u64` GPR field within
        // `Registers`; the struct and each `u64` field are 8-byte aligned, so
        // the access is in-bounds and aligned. `&self.regs` is a valid base.
        let val =
            unsafe { *((&self.regs as *const Registers as *const u8).add(off) as *const u64) };
        match size {
            1 => val & 0xFF,
            2 => val & 0xFFFF,
            4 => val & 0xFFFF_FFFF,
            _ => val,
        }
    }

    /// Set an 8-bit register value, correctly handling AH/CH/DH/BH when no REX prefix
    #[inline(always)]
    pub(super) fn set_reg8(&mut self, reg: u8, value: u64, has_rex: bool) {
        // In 64-bit mode, without REX prefix, reg 4-7 are AH/CH/DH/BH
        // With REX prefix, reg 4-7 are SPL/BPL/SIL/DIL
        if !has_rex {
            match reg & 0x07 {
                4 => {
                    self.regs.rax = (self.regs.rax & !0xFF00) | ((value & 0xFF) << 8);
                    return;
                }
                5 => {
                    self.regs.rcx = (self.regs.rcx & !0xFF00) | ((value & 0xFF) << 8);
                    return;
                }
                6 => {
                    self.regs.rdx = (self.regs.rdx & !0xFF00) | ((value & 0xFF) << 8);
                    return;
                }
                7 => {
                    self.regs.rbx = (self.regs.rbx & !0xFF00) | ((value & 0xFF) << 8);
                    return;
                }
                _ => {}
            }
        }
        self.set_reg(reg, value, 1);
    }

    /// Get an 8-bit register value, correctly handling AH/CH/DH/BH when no REX prefix
    #[inline(always)]
    pub(super) fn get_reg8(&self, reg: u8, has_rex: bool) -> u64 {
        // In 64-bit mode, without REX prefix, reg 4-7 are AH/CH/DH/BH
        // With REX prefix, reg 4-7 are SPL/BPL/SIL/DIL
        if !has_rex {
            match reg & 0x07 {
                4 => return (self.regs.rax >> 8) & 0xFF,
                5 => return (self.regs.rcx >> 8) & 0xFF,
                6 => return (self.regs.rdx >> 8) & 0xFF,
                7 => return (self.regs.rbx >> 8) & 0xFF,
                _ => {}
            }
        }
        self.get_reg(reg, 1)
    }

    #[inline(always)]
    pub(super) fn set_reg(&mut self, reg: u8, value: u64, size: u8) {
        // Branchless GPR write via the `offset_of!` table (see GPR_OFFSETS /
        // get_reg). Partial-width semantics are preserved exactly: 8/16-bit
        // writes merge into the low bits, 32-bit writes zero-extend, 64-bit
        // writes replace the register.
        let off = GPR_OFFSETS[(reg & 0x1F) as usize];
        // SAFETY: `off` is the real byte offset of a `u64` GPR field within
        // `Registers`; the field is 8-byte aligned and in-bounds, and `&mut
        // self.regs` grants exclusive access for the duration of the write.
        let reg_ref =
            unsafe { &mut *((&mut self.regs as *mut Registers as *mut u8).add(off) as *mut u64) };
        match size {
            1 => *reg_ref = (*reg_ref & !0xFF) | (value & 0xFF),
            2 => *reg_ref = (*reg_ref & !0xFFFF) | (value & 0xFFFF),
            4 => *reg_ref = value & 0xFFFF_FFFF, // 32-bit ops zero-extend
            8 => *reg_ref = value,
            _ => {}
        }
    }

    // Memory access helpers
    #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
    #[inline(always)]
    pub(in crate::isa::x86_64) fn push_jit_mem_trace(&mut self, access: (u8, u64, u8, u64)) {
        let over_limit = match self.jit_mem_trace.as_ref() {
            Some(trace) => trace.len() >= JIT_VERIFY_MEM_TRACE_LIMIT,
            None => false,
        };
        if over_limit {
            self.jit_mem_trace = None;
            return;
        }
        if let Some(trace) = self.jit_mem_trace.as_mut() {
            trace.push(access);
        }
    }

    #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
    #[inline(always)]
    pub(super) fn push_jit_mem_log(&mut self, access: (u64, u8, u64)) {
        let over_limit = match self.jit_mem_log.as_ref() {
            Some(log) => log.len() >= JIT_VERIFY_MEM_LOG_LIMIT,
            None => false,
        };
        if over_limit {
            self.jit_mem_log = None;
            return;
        }
        if let Some(log) = self.jit_mem_log.as_mut() {
            log.push(access);
        }
    }

    #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
    #[inline(always)]
    pub(in crate::isa::x86_64) fn jit_mem_log_active(&self) -> bool {
        self.jit_mem_log.is_some()
    }

    #[inline(always)]
    pub(super) fn read_mem(&mut self, addr: u64, size: u8) -> Result<u64> {
        let val = match size {
            1 => self.mmu.read_u8(addr, &self.sregs)? as u64,
            2 => self.mmu.read_u16(addr, &self.sregs)? as u64,
            4 => self.mmu.read_u32(addr, &self.sregs)? as u64,
            8 => self.mmu.read_u64(addr, &self.sregs)?,
            _ => {
                return Err(Error::Emulator(format!(
                    "invalid memory access size: {}",
                    size
                )));
            }
        };
        #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
        self.push_jit_mem_trace((0, addr, size, val));
        Ok(val)
    }

    /// Read the two adjacent qwords of an aligned APX POP2 as one MMU
    /// transaction. The caller performs the architectural register/RSP commit
    /// only after this returns successfully.
    #[inline]
    pub(super) fn read_mem_pair(&mut self, addr: u64) -> Result<(u64, u64)> {
        let (low, high) = self.mmu.read_aligned_u64_pair(addr, &self.sregs)?;
        #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
        {
            self.push_jit_mem_trace((0, addr, 8, low));
            self.push_jit_mem_trace((0, addr.wrapping_add(8), 8, high));
        }
        Ok((low, high))
    }

    /// Drain the MMU's self-modifying-code journal (code pages written by ANY
    /// store, including the ~39 handlers that call `mmu.write_u*` directly) and
    /// invalidate the decode + JIT caches for each. Called at every instruction
    /// boundary so a modified instruction is always re-decoded before it next
    /// executes. The `has_smc_dirty` guard keeps the hot path free of work when
    /// no code page has been written.
    #[inline(always)]
    fn drain_smc(&mut self) {
        if self.mmu.has_smc_dirty() {
            for page_base in self.mmu.take_smc_dirty() {
                self.invalidate_code_page(page_base);
            }
        }
    }

    /// Invalidate every cached decode and JIT region overlapping the 4 KiB page
    /// at `page_base`. The decode cache is indexed by `RIP & 0xFFF`, so all 4096
    /// entries are scanned. Runnable JIT regions retain their exact source-page
    /// sets; hotness and ineligible memos retain the conservative entry-page or
    /// preceding-page test implied by the ≤512-byte lift window.
    fn invalidate_code_page(&mut self, page_base: u64) {
        for idx in 0..DECODE_CACHE_SIZE {
            let entry = &mut self.decode_cache[idx];
            // Use bytes_len (not rip) as the validity sentinel — matching the
            // cache-hit guard — so a legitimately-cached instruction at RIP 0 is
            // still invalidated when its page is written. (#77)
            if entry.bytes_len != 0 && (entry.rip & !0xFFF) == page_base {
                entry.rip = 0; // Invalidate
                entry.bytes_len = 0; // mark empty so a real rip==0 can't false-hit
            }
        }

        #[cfg(all(
            feature = "smir-jit",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            if self
                .jit_active_source_range
                .is_some_and(|(first, last)| page_base >= first && page_base <= last)
            {
                self.jit_active_region_stale = true;
            }
            let prev_page = page_base.wrapping_sub(0x1000);
            let overlaps = |rip: u64| {
                let p = rip & !0xFFF;
                p == page_base || p == prev_page
            };
            if !self.jit_cache.is_empty() || !self.jit_hot.is_empty() {
                self.jit_cache.retain(|&(rip, _), region| match region {
                    Some(region) if !region.source_pages.is_empty() => {
                        !region.source_pages.contains(&page_base)
                    }
                    _ => !overlaps(rip),
                });
                self.jit_hot.retain(|&rip, _| !overlaps(rip));
            }
            for &(rip, mode_tag) in self.jit_ineligible.keys() {
                if overlaps(rip) {
                    self.jit_ineligible_dirty.insert((rip, mode_tag));
                }
            }
        }
    }

    #[inline(always)]
    pub(super) fn write_mem(&mut self, addr: u64, value: u64, size: u8) -> Result<()> {
        // Self-modifying-code is handled by the MMU's write journal (`note_smc`
        // in every `write_u*`) drained once per instruction in `run()` BEFORE the
        // next fetch — so no per-store invalidation is needed here. (An immediate
        // `check_smc` used to run a full decode-cache scan PER store; for code
        // pages that meant N redundant scans per multi-store instruction on top
        // of the drain's single deduplicated one. Removed — see `drain_smc`.)
        let r = match size {
            1 => self.mmu.write_u8(addr, value as u8, &self.sregs),
            2 => self.mmu.write_u16(addr, value as u16, &self.sregs),
            4 => self.mmu.write_u32(addr, value as u32, &self.sregs),
            8 => self.mmu.write_u64(addr, value, &self.sregs),
            _ => Err(Error::Emulator(format!(
                "invalid memory access size: {}",
                size
            ))),
        };
        #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
        if r.is_ok() {
            let mask = match size {
                1 => 0xFFu64,
                2 => 0xFFFF,
                4 => 0xFFFF_FFFF,
                _ => u64::MAX,
            };
            self.push_jit_mem_trace((1, addr, size, value & mask));
        }
        r
    }

    /// Write the two adjacent qwords of an aligned APX PUSH2 as one MMU
    /// transaction. At the architectural 16-byte alignment required by APX,
    /// the transfer cannot cross a 4 KiB page, so translation and permission
    /// checking precede the complete physical write.
    #[inline]
    pub(super) fn write_mem_pair(&mut self, addr: u64, low: u64, high: u64) -> Result<()> {
        let result = self
            .mmu
            .write_aligned_u64_pair(addr, low, high, &self.sregs);
        #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
        if result.is_ok() {
            self.push_jit_mem_trace((1, addr, 8, low));
            self.push_jit_mem_trace((1, addr.wrapping_add(8), 8, high));
        }
        result
    }

    // FPU memory access helpers
    #[inline(always)]
    pub(super) fn read_mem16(&mut self, addr: u64) -> Result<u16> {
        self.mmu.read_u16(addr, &self.sregs)
    }

    #[inline(always)]
    pub(super) fn write_mem16(&mut self, addr: u64, value: u16) -> Result<()> {
        self.mmu.write_u16(addr, value, &self.sregs)
    }

    #[inline(always)]
    pub(super) fn read_mem32(&mut self, addr: u64) -> Result<u32> {
        self.mmu.read_u32(addr, &self.sregs)
    }

    #[inline(always)]
    pub(super) fn write_mem32(&mut self, addr: u64, value: u32) -> Result<()> {
        self.mmu.write_u32(addr, value, &self.sregs)
    }

    #[inline(always)]
    pub(super) fn read_mem64(&mut self, addr: u64) -> Result<u64> {
        self.mmu.read_u64(addr, &self.sregs)
    }

    #[inline(always)]
    pub(super) fn write_mem64(&mut self, addr: u64, value: u64) -> Result<()> {
        // Use the generic write_mem which has watchpoints
        self.write_mem(addr, value, 8)
    }

    #[inline(always)]
    pub(super) fn read_f32(&mut self, addr: u64) -> Result<f32> {
        let bits = self.mmu.read_u32(addr, &self.sregs)?;
        Ok(f32::from_bits(bits))
    }

    #[inline(always)]
    pub(super) fn write_f32(&mut self, addr: u64, value: f32) -> Result<()> {
        self.mmu.write_u32(addr, value.to_bits(), &self.sregs)
    }

    #[inline(always)]
    pub(super) fn read_f64(&mut self, addr: u64) -> Result<f64> {
        let bits = self.mmu.read_u64(addr, &self.sregs)?;
        Ok(f64::from_bits(bits))
    }

    #[inline(always)]
    pub(super) fn write_f64(&mut self, addr: u64, value: f64) -> Result<()> {
        self.mmu.write_u64(addr, value.to_bits(), &self.sregs)
    }

    #[inline]
    pub(super) fn read_bytes(&mut self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.mmu.read(addr, &mut buf, &self.sregs)?;
        Ok(buf)
    }

    #[inline]
    pub(super) fn write_bytes(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        self.mmu.write(addr, data, &self.sregs)
    }

    // Stack helpers
    // NOTE: These must NOT modify RSP if the write fails, otherwise page fault
    // handling will corrupt the stack (RSP gets decremented twice on retry).
    #[inline(always)]
    fn stack_segment_base(&self) -> u64 {
        if self.sregs.cs.l {
            0
        } else {
            self.sregs.ss.base
        }
    }

    #[inline(always)]
    fn stack_address_size(&self) -> u8 {
        if self.sregs.cs.l {
            8
        } else if self.sregs.ss.db {
            4
        } else {
            2
        }
    }

    #[inline(always)]
    pub(super) fn stack_pointer_offset(&self) -> u64 {
        match self.stack_address_size() {
            2 => self.regs.rsp & 0xffff,
            4 => self.regs.rsp & 0xffff_ffff,
            8 => self.regs.rsp,
            _ => unreachable!(),
        }
    }

    #[inline(always)]
    pub(super) fn set_stack_pointer_offset(&mut self, value: u64) {
        match self.stack_address_size() {
            2 => {
                self.regs.rsp = (self.regs.rsp & !0xffff) | (value & 0xffff);
            }
            4 => {
                self.regs.rsp = value & 0xffff_ffff;
            }
            8 => {
                self.regs.rsp = value;
            }
            _ => unreachable!(),
        }
    }

    #[inline(always)]
    pub(super) fn stack_pointer_wrapping_sub(&self, delta: u64) -> u64 {
        match self.stack_address_size() {
            2 => u64::from((self.stack_pointer_offset() as u16).wrapping_sub(delta as u16)),
            4 => u64::from((self.stack_pointer_offset() as u32).wrapping_sub(delta as u32)),
            8 => self.stack_pointer_offset().wrapping_sub(delta),
            _ => unreachable!(),
        }
    }

    #[inline(always)]
    fn stack_pointer_wrapping_add(&self, delta: u64) -> u64 {
        match self.stack_address_size() {
            2 => u64::from((self.stack_pointer_offset() as u16).wrapping_add(delta as u16)),
            4 => u64::from((self.stack_pointer_offset() as u32).wrapping_add(delta as u32)),
            8 => self.stack_pointer_offset().wrapping_add(delta),
            _ => unreachable!(),
        }
    }

    pub(super) fn push64(&mut self, value: u64) -> Result<()> {
        let new_rsp = self.stack_pointer_wrapping_sub(8);
        self.mmu.write_u64(
            self.stack_segment_base().wrapping_add(new_rsp),
            value,
            &self.sregs,
        )?;
        self.set_stack_pointer_offset(new_rsp);
        Ok(())
    }

    /// Push a 64-bit value to the stack with supervisor privilege.
    /// Used during exception/interrupt delivery where the kernel stack
    /// is accessed regardless of current CPL.
    fn push64_supervisor(&mut self, value: u64) -> Result<()> {
        let new_rsp = self.regs.rsp.wrapping_sub(8);
        self.mmu.write_u64_supervisor(new_rsp, value, &self.sregs)?;
        self.regs.rsp = new_rsp;
        Ok(())
    }

    pub(super) fn pop64(&mut self) -> Result<u64> {
        let rsp = self.stack_pointer_offset();
        let value = self
            .mmu
            .read_u64(self.stack_segment_base().wrapping_add(rsp), &self.sregs)?;
        let new_rsp = self.stack_pointer_wrapping_add(8);
        self.set_stack_pointer_offset(new_rsp);
        Ok(value)
    }

    pub(super) fn push32(&mut self, value: u32) -> Result<()> {
        let new_rsp = self.stack_pointer_wrapping_sub(4);
        self.mmu.write_u32(
            self.stack_segment_base().wrapping_add(new_rsp),
            value,
            &self.sregs,
        )?;
        self.set_stack_pointer_offset(new_rsp);
        Ok(())
    }

    pub(super) fn push_segment32(&mut self, value: u16) -> Result<()> {
        let new_rsp = self.stack_pointer_wrapping_sub(4);
        self.mmu.write_u16(
            self.stack_segment_base().wrapping_add(new_rsp),
            value,
            &self.sregs,
        )?;
        self.set_stack_pointer_offset(new_rsp);
        Ok(())
    }

    pub(super) fn pop32(&mut self) -> Result<u32> {
        let rsp = self.stack_pointer_offset();
        let value = self
            .mmu
            .read_u32(self.stack_segment_base().wrapping_add(rsp), &self.sregs)?;
        let new_rsp = self.stack_pointer_wrapping_add(4);
        self.set_stack_pointer_offset(new_rsp);
        Ok(value)
    }

    pub(super) fn push16(&mut self, value: u16) -> Result<()> {
        let new_rsp = self.stack_pointer_wrapping_sub(2);
        self.mmu.write_u16(
            self.stack_segment_base().wrapping_add(new_rsp),
            value,
            &self.sregs,
        )?;
        self.set_stack_pointer_offset(new_rsp);
        Ok(())
    }

    pub(super) fn pop16(&mut self) -> Result<u16> {
        let rsp = self.stack_pointer_offset();
        let value = self
            .mmu
            .read_u16(self.stack_segment_base().wrapping_add(rsp), &self.sregs)?;
        let new_rsp = self.stack_pointer_wrapping_add(2);
        self.set_stack_pointer_offset(new_rsp);
        Ok(value)
    }

    // I/O pending helpers
    pub(super) fn set_io_pending_reg(&mut self, size: u8) {
        self.io_pending = Some(IoPending {
            size,
            target: IoInTarget::Reg,
            count: 1,
        });
    }

    pub(super) fn set_io_pending_mem(&mut self, size: u8, addr: u64) {
        self.io_pending = Some(IoPending {
            size,
            target: IoInTarget::Mem { addr },
            count: 1,
        });
    }

    /// Stage a batched `rep ins` block: `count` consecutive `size`-byte elements
    /// written to memory starting at `addr` (forward). Completed in one shot by
    /// [`Self::complete_io_in`] from the data the backend reads off the port.
    pub(super) fn set_io_pending_block(&mut self, size: u8, addr: u64, count: u32) {
        self.io_pending = Some(IoPending {
            size,
            target: IoInTarget::Mem { addr },
            count,
        });
    }

    // Segment register access
    pub(super) fn get_sreg(&self, sreg: u8) -> u16 {
        match sreg {
            0 => self.sregs.es.selector,
            1 => self.sregs.cs.selector,
            2 => self.sregs.ss.selector,
            3 => self.sregs.ds.selector,
            4 => self.sregs.fs.selector,
            5 => self.sregs.gs.selector,
            _ => 0,
        }
    }

    pub(super) fn set_sreg(&mut self, sreg: u8, value: u16) {
        // Real mode (CR0.PE=0) loads a segment base of selector<<4 directly,
        // with a 64 KiB limit and 16-bit addressing — no descriptor lookup.
        let real_mode = self.sregs.cr0 & 1 == 0;
        if !real_mode {
            let _ = self.mark_descriptor_accessed(value);
        }
        // 64-bit (long) mode keeps flat data segments and MSR-based FS/GS bases,
        // so it does NOT consult the descriptor table here. In 32-bit protected
        // mode a segment load takes its base/limit/attributes from the GDT/LDT
        // descriptor (resolved up front, before the &mut segment borrow). Require
        // a present code/data (S=1, P=1) descriptor; otherwise fall back to flat.
        let long_mode = (self.sregs.efer & 0x400) != 0 && self.sregs.cs.l;
        let desc = if !real_mode && !long_mode {
            self.read_descriptor(value)
                .ok()
                .flatten()
                .filter(|d| (d >> 44) & 1 != 0 && (d >> 47) & 1 != 0)
        } else {
            None
        };
        let seg = match sreg {
            0 => &mut self.sregs.es,
            1 => &mut self.sregs.cs,
            2 => &mut self.sregs.ss,
            3 => &mut self.sregs.ds,
            4 => &mut self.sregs.fs,
            5 => &mut self.sregs.gs,
            _ => return,
        };
        let preserve_mode = sreg == 1;
        let prev_db = seg.db;
        let prev_l = seg.l;
        seg.selector = value;
        if real_mode {
            // Real mode: the segment base is selector<<4, the limit is 64 KiB,
            // and addressing is 16-bit. (No descriptor table is consulted.)
            seg.base = (value as u64) << 4;
            seg.limit = 0xFFFF;
            seg.type_ = 0x03;
            seg.present = true;
            seg.dpl = 0;
            seg.db = false;
            seg.s = true;
            seg.l = false;
            seg.g = false;
        } else if let Some(d) = desc {
            // 32-bit protected mode: decode base/limit/attributes from the
            // descriptor (e.g. TempleOS uses based data segments during boot).
            let base = ((d >> 16) & 0x00FF_FFFF) | (((d >> 56) & 0xFF) << 24);
            let lim = ((d & 0xFFFF) | (((d >> 48) & 0xF) << 16)) as u32;
            let g = (d >> 55) & 1 != 0;
            seg.base = base;
            seg.limit = if g { (lim << 12) | 0xFFF } else { lim };
            seg.type_ = ((d >> 40) & 0xF) as u8;
            seg.s = true;
            seg.dpl = ((d >> 45) & 3) as u8;
            seg.present = true;
            seg.db = if preserve_mode {
                prev_db
            } else {
                (d >> 54) & 1 != 0
            };
            seg.l = if preserve_mode {
                prev_l
            } else {
                (d >> 53) & 1 != 0
            };
            seg.g = g;
        } else {
            // Flat fallback: long mode, a null selector, or a non-usable
            // descriptor (matches the prior always-flat behavior).
            seg.base = 0;
            seg.limit = 0xFFFF_FFFF;
            seg.type_ = 0x03; // Data segment, read/write, accessed
            seg.present = true;
            seg.dpl = 0;
            seg.db = if preserve_mode { prev_db } else { true };
            seg.s = true;
            seg.l = if preserve_mode { prev_l } else { false };
            seg.g = true;
        }
    }

    fn descriptor_addr(&self, selector: u16) -> Result<Option<u64>> {
        if selector & 0xFFFC == 0 {
            return Ok(None);
        }

        let ti = (selector & 0x4) != 0;
        let index = (selector >> 3) as u64;
        let (table_base, table_limit) = if ti {
            (self.sregs.ldt.base, self.sregs.ldt.limit as u64)
        } else {
            (self.sregs.gdt.base, self.sregs.gdt.limit as u64)
        };

        let offset = index * 8;
        if offset + 7 > table_limit {
            return Err(Error::Emulator(format!(
                "descriptor selector {:#x} outside descriptor table limit (#GP)",
                selector
            )));
        }

        Ok(Some(table_base + offset))
    }

    fn mark_descriptor_accessed(&mut self, selector: u16) -> Result<()> {
        let Some(addr) = self.descriptor_addr(selector)? else {
            return Ok(());
        };
        let raw = self.mmu.read_u64_supervisor(addr, &self.sregs)?;
        let present = (raw >> 47) & 1 != 0;
        let code_or_data = (raw >> 44) & 1 != 0;
        if present && code_or_data && raw & (1u64 << 40) == 0 {
            self.mmu
                .write_u64_supervisor(addr, raw | (1u64 << 40), &self.sregs)?;
        }
        Ok(())
    }

    /// Read the raw 8-byte segment descriptor selected by `selector` from the
    /// active descriptor table (GDT, or LDT when the TI bit is set).
    ///
    /// Returns `Ok(None)` for a null selector (selector index 0, TI=0). Returns
    /// `Err` (#GP-style) if the selector lies outside the table limit. Otherwise
    /// returns the raw little-endian descriptor qword.
    pub(super) fn read_descriptor(&mut self, selector: u16) -> Result<Option<u64>> {
        let Some(addr) = self.descriptor_addr(selector)? else {
            return Ok(None);
        };
        let raw = self.mmu.read_u64_supervisor(addr, &self.sregs)?;
        Ok(Some(raw))
    }

    /// Decode a raw descriptor qword into the architectural fields of a code
    /// segment, validating presence and type. On success the CS register's
    /// base/limit/l/db/dpl/type/s/g are populated from the descriptor and the
    /// selector is written with the supplied RPL/CPL bits preserved.
    ///
    /// `selector` carries the RPL the caller wants recorded in CS.selector.
    fn apply_code_descriptor(&mut self, selector: u16, raw: u64) -> Result<()> {
        // Field extraction (legacy 8-byte descriptor layout).
        let limit_lo = (raw & 0xFFFF) as u32;
        let limit_hi = ((raw >> 48) & 0xF) as u32;
        let mut limit = (limit_hi << 16) | limit_lo;

        let base_lo = ((raw >> 16) & 0xFFFF) as u64;
        let base_mid = ((raw >> 32) & 0xFF) as u64;
        let base_hi = ((raw >> 56) & 0xFF) as u64;
        let base = base_lo | (base_mid << 16) | (base_hi << 24);

        let access = ((raw >> 40) & 0xFF) as u8;
        let present = (access & 0x80) != 0;
        let dpl = (access >> 5) & 0x3;
        let s = (access & 0x10) != 0; // 1 = code/data, 0 = system
        let type_ = access & 0x0F;

        let flags = ((raw >> 52) & 0xF) as u8;
        let avl = (flags & 0x1) != 0;
        let l = (flags & 0x2) != 0; // 64-bit code segment
        let db = (flags & 0x4) != 0; // default operand/address size
        let g = (flags & 0x8) != 0; // granularity

        // Present check: a not-present code segment raises #NP.
        if !present {
            return Err(Error::Emulator(format!(
                "load_code_segment: selector {:#x} not present (#NP)",
                selector
            )));
        }

        // Type check: must be a code segment (S=1 and type bit 3 set => executable).
        if !s || (type_ & 0x08) == 0 {
            return Err(Error::Emulator(format!(
                "load_code_segment: selector {:#x} is not a code segment (#GP)",
                selector
            )));
        }
        self.mark_descriptor_accessed(selector)?;

        // Apply granularity scaling: G=1 means limit is in 4 KiB units, so the
        // byte limit is (limit << 12) | 0xFFF.
        if g {
            limit = (limit << 12) | 0xFFF;
        }

        self.sregs.cs.selector = selector;
        self.sregs.cs.base = base;
        self.sregs.cs.limit = limit;
        self.sregs.cs.type_ = type_ | 1;
        self.sregs.cs.present = true;
        self.sregs.cs.dpl = dpl;
        self.sregs.cs.s = true;
        self.sregs.cs.avl = avl;
        self.sregs.cs.g = g;
        // In a 64-bit code segment L=1 forces D=0; otherwise honor the D bit.
        if l {
            self.sregs.cs.l = true;
            self.sregs.cs.db = false;
        } else {
            self.sregs.cs.l = false;
            self.sregs.cs.db = db;
        }
        self.sregs.cs.unusable = false;
        Ok(())
    }

    /// Load CS from a real GDT/LDT descriptor on a far control transfer.
    ///
    /// For a non-null selector this reads the 8-byte descriptor, validates that
    /// it is present (#NP otherwise) and a code segment (#GP otherwise), and
    /// populates CS.base/limit (with G granularity scaling), CS.l (64-bit),
    /// CS.db (D bit), CS.dpl and CS.selector. A null selector is rejected (#GP)
    /// because CS may never be loaded with a null selector.
    pub(super) fn load_code_segment(&mut self, selector: u16) -> Result<()> {
        match self.read_descriptor(selector)? {
            None => Err(Error::Emulator(
                "load_code_segment: null CS selector (#GP)".to_string(),
            )),
            Some(raw) => self.apply_code_descriptor(selector, raw),
        }
    }

    /// Test/integration entry point for strict CS descriptor loading.
    ///
    /// Exposes [`Self::load_code_segment`] (which the lenient instruction paths
    /// wrap) so out-of-crate tests can exercise the architectural #NP/#GP
    /// validation directly against a hand-built descriptor table.
    pub fn load_code_segment_strict(&mut self, selector: u16) -> Result<()> {
        self.load_code_segment(selector)
    }

    /// Best-effort CS load for far transfers used by the emulated instruction
    /// paths. When the selected descriptor is a present code segment, the real
    /// architectural fields (base, granularity-scaled limit, DPL, type, S, G,
    /// AVL) are loaded from the descriptor via [`Self::apply_code_descriptor`].
    /// When the descriptor table slot is absent or holds something that is not
    /// a usable present code segment, this falls back to the historical
    /// flat-segment behavior of [`Self::set_sreg`] so code that runs against a
    /// sparsely-populated descriptor table keeps working. The caller must
    /// already have validated table limits via `validate_far_selector`.
    ///
    /// NOTE: unlike the strict [`Self::load_code_segment`], this preserves the
    /// *prior* CS.l/CS.db (execution mode) rather than adopting the descriptor's
    /// L/D bits. The test harness installs a single 64-bit (L=1) code descriptor
    /// at selector 0x08 that both 64-bit and compatibility-mode code transfers
    /// through; honoring its L bit would switch compatibility-mode code into
    /// 64-bit mode mid-stream. Preserving the mode here keeps existing behavior
    /// intact while still loading the real base/limit/DPL the audit cares about.
    /// Callers that need true descriptor-driven mode switching use
    /// [`Self::load_code_segment`].
    pub(super) fn load_code_segment_lenient(&mut self, selector: u16) {
        // Real mode (CR0.PE=0): CS.base = selector<<4 directly, no descriptor
        // lookup (the GDT is not consulted in real mode).
        if self.sregs.cr0 & 1 == 0 {
            self.set_sreg(1, selector);
            return;
        }
        let prev_l = self.sregs.cs.l;
        let prev_db = self.sregs.cs.db;
        match self.read_descriptor(selector) {
            Ok(Some(raw)) => {
                // Only adopt the real descriptor when it is a present code
                // segment; otherwise fall back to flat segmentation.
                if self.apply_code_descriptor(selector, raw).is_ok() {
                    // A far transfer adopts the descriptor's D/L bits — this is
                    // exactly how the mode switches take effect: real→protected
                    // (D: 16→32) outside long mode, and the 32-bit-compat→64-bit
                    // switch a guest performs after enabling long mode (it runs
                    // 32-bit (D=1) compatibility code under the 4-level page
                    // tables, then far-jumps to its 64-bit code segment).
                    //
                    // The one carve-out is the audit/test fixtures, which route
                    // transfers through a single 64-bit (L=1) descriptor while
                    // running 16-bit compatibility code (prev D=0) and must stay
                    // in that mode. So inside long mode preserve the prior mode
                    // ONLY when leaving 16-bit compatibility (prev D=0); a real
                    // OS never enters 64-bit mode from 16-bit compat. 64-bit
                    // code (also D=0) likewise preserves — through an L=1
                    // descriptor that is a no-op anyway.
                    let in_long_mode = self.sregs.efer & 0x400 != 0;
                    if in_long_mode && !prev_db {
                        self.sregs.cs.l = prev_l;
                        self.sregs.cs.db = prev_db;
                    }
                } else {
                    self.set_sreg(1, selector);
                }
            }
            // Null selector or out-of-limit selector: preserve legacy behavior.
            Ok(None) | Err(_) => self.set_sreg(1, selector),
        }
    }

    /// Load CS for a far JMP. Wraps [`Self::load_code_segment_lenient`] but
    /// enforces that a far JMP never *gains* privilege.
    ///
    /// The emulator derives the current privilege level from `CS.selector & 3`,
    /// and an architectural far JMP leaves CPL unchanged (it cannot switch ring
    /// the way a call gate or interrupt can). Without this, a guest running at
    /// CPL > 0 could far-JMP to a selector whose RPL is lower (e.g. a ring-0
    /// kernel code selector) and the lenient load would write those low bits
    /// straight into `CS.selector`, making the emulator treat the vCPU as CPL0 —
    /// bypassing privileged-instruction checks and user/supervisor page
    /// permissions. In protected/long mode we re-pin the loaded CS RPL to the
    /// prior CPL whenever the transfer would lower it. (Real mode has no CPL; its
    /// CS selector is a raw segment base, so it is left untouched.)
    pub(super) fn load_code_segment_far_jmp(&mut self, selector: u16) {
        let protected = self.sregs.cr0 & 1 != 0;
        let old_cpl = self.sregs.cs.selector & 0x3;
        self.load_code_segment_lenient(selector);
        if protected && (self.sregs.cs.selector & 0x3) < old_cpl {
            self.sregs.cs.selector = (self.sregs.cs.selector & !0x3) | old_cpl;
        }
    }

    // Condition checking for Jcc/SETcc/CMOVcc - materializes lazy flags first
    pub(super) fn check_condition(&mut self, cc: u8) -> bool {
        // Evaluate the predicate without materializing RFLAGS (a conditional
        // branch doesn't modify flags, so the lazy op is left intact). ZF/SF are
        // cheap and computed eagerly; CF/OF/PF are closures so a condition only
        // pays for the flags it actually reads — e.g. JZ/JNZ touch ZF alone and
        // skip the PF popcount + OF/CF work entirely. Results are identical to
        // materialize-then-read; this just avoids computing unused flags + the
        // RFLAGS round-trip on every Jcc/SETcc/CMOVcc.
        let lf = self.lazy_flags;
        let materialized = lf.op == LazyFlagOp::None;
        let rflags = self.regs.rflags;

        // Geometry of the pending lazy op (ignored when already materialized).
        let (mask, sign_bit) = match lf.size {
            1 => (0xFFu64, 0x80u64),
            2 => (0xFFFFu64, 0x8000u64),
            4 => (0xFFFF_FFFFu64, 0x8000_0000u64),
            _ => (u64::MAX, 0x8000_0000_0000_0000u64),
        };
        let result_m = lf.result & mask;
        let a_m = lf.src & mask;
        let b_m = lf.dst & mask;

        let zf = if materialized {
            rflags & flags::bits::ZF != 0
        } else {
            result_m == 0
        };
        let sf = if materialized {
            rflags & flags::bits::SF != 0
        } else {
            (result_m & sign_bit) != 0
        };
        let cf = || {
            if materialized {
                rflags & flags::bits::CF != 0
            } else {
                match lf.op {
                    LazyFlagOp::Add => result_m < a_m,
                    LazyFlagOp::Sub => a_m < b_m,
                    // INC/DEC preserve CF (its prior value lives in RFLAGS).
                    LazyFlagOp::Inc | LazyFlagOp::Dec => rflags & flags::bits::CF != 0,
                    _ => false, // Logic
                }
            }
        };
        let of = || {
            if materialized {
                rflags & flags::bits::OF != 0
            } else {
                match lf.op {
                    LazyFlagOp::Add | LazyFlagOp::Inc => {
                        ((a_m ^ result_m) & (b_m ^ result_m) & sign_bit) != 0
                    }
                    LazyFlagOp::Sub | LazyFlagOp::Dec => {
                        ((a_m ^ b_m) & (a_m ^ result_m) & sign_bit) != 0
                    }
                    _ => false, // Logic
                }
            }
        };
        let pf = || {
            if materialized {
                rflags & flags::bits::PF != 0
            } else {
                (lf.result as u8).count_ones() & 1 == 0
            }
        };

        match cc {
            0x0 => of(),                // O
            0x1 => !of(),               // NO
            0x2 => cf(),                // B/NAE/C
            0x3 => !cf(),               // NB/AE/NC
            0x4 => zf,                  // E/Z
            0x5 => !zf,                 // NE/NZ
            0x6 => cf() || zf,          // BE/NA
            0x7 => !cf() && !zf,        // NBE/A
            0x8 => sf,                  // S
            0x9 => !sf,                 // NS
            0xA => pf(),                // P/PE
            0xB => !pf(),               // NP/PO
            0xC => sf != of(),          // L/NGE
            0xD => sf == of(),          // NL/GE
            0xE => zf || (sf != of()),  // LE/NG
            0xF => !zf && (sf == of()), // NLE/G
            _ => false,
        }
    }

    /// Inject a page fault exception (#PF, vector 14) into the guest.
    /// This allows the kernel's page fault handler to run and set up page tables on demand.
    pub(super) fn inject_page_fault(&mut self, vaddr: u64, error_code: u64) -> Result<()> {
        // Page fault logging disabled for performance

        // Set CR2 to the faulting virtual address
        self.sregs.cr2 = vaddr;
        self.inject_exception(14, Some(error_code))
    }
}

/// Spawn a one-shot background thread (when `RAX_MIPS` is set) that prints the
/// retired-instruction rate once a second. Reads the global counter published at
/// run-exit boundaries, so it reports interpreted throughput (native JIT regions
/// do not tick it). Used to A/B emulator-speed changes against a live boot.
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
fn maybe_spawn_mips_reporter() {
    use std::sync::OnceLock;
    static STARTED: OnceLock<()> = OnceLock::new();
    if std::env::var_os("RAX_MIPS").is_none() {
        return;
    }
    STARTED.get_or_init(|| {
        std::thread::spawn(|| {
            let mut last = 0u64;
            let mut secs = 0u64;
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
                let now = get_total_instruction_count();
                secs += 1;
                let delta = now.saturating_sub(last);
                last = now;
                eprintln!(
                    "[MIPS] t={secs}s  +{:.2} MIPS  (total {} insns)",
                    delta as f64 / 1.0e6,
                    now
                );
            }
        });
    });
}

impl X86_64Vcpu {
    /// Execute exactly one guest instruction with the same fault-delivery
    /// semantics as [`run`](Self::run): self-modifying-code caches are drained
    /// first, the instruction is decoded and executed, and any page fault or
    /// #GP it raises is delivered to the guest (returning `Ok(None)` so the
    /// next call resumes in the handler) precisely as the free-running loop
    /// would. The JIT and periodic LAPIC/yield housekeeping are intentionally
    /// bypassed so each call retires exactly one architectural instruction —
    /// this is the precise primitive the embedding/debugger API steps with.
    pub fn step_with_faults(&mut self) -> Result<Option<VcpuExit>> {
        if self.halted {
            return Ok(Some(VcpuExit::Hlt));
        }

        // Re-decode any code page modified since the previous instruction.
        self.drain_smc();

        match self.step() {
            Ok(exit) => Ok(exit),
            Err(Error::PageFault { vaddr, error_code }) => {
                // Deliver #PF; RIP still points at the faulting instruction so
                // the pushed frame restarts it once the handler returns.
                match self.inject_page_fault(vaddr, error_code) {
                    Ok(()) => Ok(None),
                    Err(Error::PageFault { .. }) => {
                        // Fault during #PF delivery: escalate to #DF (vector 8).
                        self.inject_exception(8, Some(0)).map_err(|e| {
                            Error::Emulator(format!(
                                "double fault delivery failed at RIP={:#x}: {e}",
                                self.regs.rip
                            ))
                        })?;
                        Ok(None)
                    }
                    Err(e) => Err(Error::Emulator(format!(
                        "#PF delivery failed at vaddr={vaddr:#x} (error_code={error_code:#x}): {e}"
                    ))),
                }
            }
            Err(Error::GeneralProtection { error_code }) => {
                self.inject_exception(13, Some(error_code))?;
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Reset architectural CPU state to power-on defaults, preserving the
    /// attached guest memory. Mirrors the field initialisation in [`new`] for
    /// every architectural and cache field touched by execution.
    pub fn reset_state(&mut self) {
        #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
        {
            self.jit_vsib_resume_pc = None;
        }
        self.insn_count = 0;
        self.regs = Registers::default();
        self.sregs = SystemRegisters::default();
        self.fpu = FpuState::default();
        self.lazy_flags = LazyFlags::default();
        self.halted = false;
        self.interrupt_inhibit = false;
        self.io_pending = None;
        self.kernel_gs_base = 0;
        self.tsc_adjust = 0;
        self.tsc_aux = 0;
        self.misc_enable = execute::system::IA32_MISC_ENABLE_RESET;
        self.pat = execute::system::IA32_PAT_RESET;
        self.umwait_control = 0;
        self.pkru = 0;
        self.xcr0 = 1;
        self.xgetbv1_value = 0;
        self.decode_cache.iter_mut().for_each(|e| {
            e.rip = 0;
            e.bytes_len = 0;
        });
        #[cfg(all(
            feature = "smir-jit",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            self.jit_cache.clear();
            self.jit_hot.clear();
            self.jit_ineligible.clear();
            self.jit_ineligible_dirty.clear();
        }
    }
}

#[path = "cpu_run.rs"]
mod run_loop;

impl VCpu for X86_64Vcpu {
    fn run(&mut self) -> Result<VcpuExit> {
        self.run_loop()
    }

    fn get_state(&self) -> Result<CpuState> {
        // Compute materialized rflags without modifying self
        let rflags = self.compute_materialized_rflags();
        let mut regs = self.regs.clone();
        regs.rflags = rflags;
        Ok(CpuState::X86_64(X86_64CpuState {
            regs,
            sregs: self.sregs.clone(),
        }))
    }

    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        let state = match state {
            CpuState::X86_64(state) => state,
            _ => {
                return Err(Error::Emulator(
                    "expected x86_64 state for x86_64 vCPU".to_string(),
                ));
            }
        };
        self.regs = state.regs.clone();
        self.sregs = state.sregs.clone();
        #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
        {
            self.jit_vsib_resume_pc = None;
        }
        // External state injection is a serializing boundary and does not carry
        // the emulator-private STI/MOV-SS interrupt shadow.
        self.interrupt_inhibit = false;
        // Injecting CPU state is a serializing event: drop the decode cache so we
        // re-decode from (possibly externally rewritten) code memory. Not hot -
        // set_state is only called at init / snapshot restore / GDB, never in run().
        self.decode_cache.iter_mut().for_each(|e| {
            e.rip = 0;
            e.bytes_len = 0;
        });
        Ok(())
    }

    fn step_insn(&mut self) -> Result<Option<VcpuExit>> {
        self.step_with_faults()
    }

    fn supports_stepping(&self) -> bool {
        true
    }

    fn translate_addr(&mut self, vaddr: u64, access: crate::vm::vcpu::MemAccess) -> Result<u64> {
        let at = match access {
            crate::vm::vcpu::MemAccess::Read => super::mmu::AccessType::Read,
            crate::vm::vcpu::MemAccess::Write => super::mmu::AccessType::Write,
            crate::vm::vcpu::MemAccess::Exec => super::mmu::AccessType::Execute,
        };
        self.mmu.translate(vaddr, at, &self.sregs)
    }

    fn reset(&mut self) -> Result<()> {
        self.reset_state();
        Ok(())
    }

    fn current_pc(&self) -> u64 {
        self.regs.rip
    }

    fn supports_mem_hooks(&self) -> bool {
        true
    }

    fn set_mem_recording(&mut self, on: bool) {
        self.mmu.set_mem_recording(on);
    }

    fn drain_mem_records(&mut self, out: &mut Vec<crate::vm::vcpu::MemRecord>) {
        self.mmu.drain_mem_records(out);
    }

    fn set_pci_bridge(
        &mut self,
        bridge: std::sync::Arc<std::sync::Mutex<crate::devices::pci::PciStub>>,
        ap_base: u64,
        ap_end: u64,
    ) {
        self.mmu.set_pci_bridge(bridge, ap_base, ap_end);
    }

    fn attach_x86_64_bios(&mut self, cdrom: Option<Arc<Vec<u8>>>, mem_bytes: u64) {
        self.bios_cdrom = cdrom;
        self.bios_mem_bytes = mem_bytes;
    }

    fn complete_io_in(&mut self, data: &[u8]) {
        if let Some(pending) = self.io_pending.take() {
            let sz = pending.size as usize;
            // Batched `rep ins` block: write `count` consecutive elements from
            // `data` to memory starting at the staged address (forward).
            if pending.count > 1 {
                if let IoInTarget::Mem { addr } = pending.target {
                    for i in 0..pending.count as usize {
                        let off = i * sz;
                        if off + sz > data.len() {
                            break;
                        }
                        let value = match pending.size {
                            1 => data[off] as u64,
                            2 => u16::from_le_bytes([data[off], data[off + 1]]) as u64,
                            _ => u32::from_le_bytes([
                                data[off],
                                data[off + 1],
                                data[off + 2],
                                data[off + 3],
                            ]) as u64,
                        };
                        let _ = self.write_mem(addr + off as u64, value, pending.size);
                    }
                }
                return;
            }

            let value = match pending.size {
                1 => data.first().copied().unwrap_or(0) as u64,
                2 if data.len() >= 2 => u16::from_le_bytes([data[0], data[1]]) as u64,
                4 if data.len() >= 4 => {
                    u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64
                }
                _ => 0,
            };

            match pending.target {
                IoInTarget::Reg => match pending.size {
                    1 => self.regs.rax = (self.regs.rax & !0xFF) | value,
                    2 => self.regs.rax = (self.regs.rax & !0xFFFF) | value,
                    4 => self.regs.rax = value,
                    _ => {}
                },
                IoInTarget::Mem { addr } => {
                    let _ = self.write_mem(addr, value, pending.size);
                }
            }
        }
    }

    fn id(&self) -> u32 {
        self.id
    }

    fn can_inject_interrupt(&self) -> bool {
        // IF is set/cleared only by STI/CLI/POPF/IRET (written straight to
        // regs.rflags), never by the lazy ALU-flag engine - so read it directly.
        // A successful IF 0->1 STI additionally blocks maskable injection
        // through the following instruction boundary.
        (self.regs.rflags & flags::bits::IF) != 0 && !self.interrupt_inhibit
    }

    fn inject_interrupt(&mut self, vector: u8) -> Result<bool> {
        // Check if interrupts are enabled
        if !self.can_inject_interrupt() {
            return Ok(false);
        }

        // Inject the external interrupt
        // External interrupts don't push an error code
        self.inject_external_event(vector, None)?;

        // Clear the halted state if we were halted
        self.halted = false;

        Ok(true)
    }

    fn inject_nmi(&mut self) -> Result<bool> {
        // NMI is vector 2 and ignores IF flag
        // TODO: Track NMI blocking (NMIs are blocked until IRET after an NMI)
        self.inject_external_event(2, None)?;
        self.halted = false;
        tracing::debug!("Injected NMI");
        Ok(true)
    }

    #[cfg(feature = "debug")]
    fn set_single_step(&mut self, enabled: bool) {
        self.single_step = enabled;
    }

    #[cfg(feature = "debug")]
    fn is_single_step(&self) -> bool {
        self.single_step
    }

    #[cfg(feature = "debug")]
    fn set_debugger_active(&mut self, active: bool) {
        self.debugger_active = active;

        #[cfg(all(
            feature = "smir-jit",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        if active {
            self.jit_cache.clear();
            self.jit_hot.clear();
        }
    }

    #[cfg(feature = "debug")]
    fn set_debug_breakpoint(&mut self, addr: u64) -> Result<()> {
        self.debug_breakpoints.insert(addr);
        Ok(())
    }

    #[cfg(feature = "debug")]
    fn clear_debug_breakpoint(&mut self, addr: u64) -> Result<()> {
        self.debug_breakpoints.remove(&addr);
        Ok(())
    }

    #[cfg(feature = "debug")]
    fn invalidate_code_cache(&mut self, addr: u64) {
        self.invalidate_code_page(addr & !0xFFF);
    }

    fn instruction_count(&self) -> u64 {
        // The accurate per-vCPU retired-instruction counter. (The process-global
        // counter, exposed via `get_total_instruction_count`, is only published
        // at run() yield boundaries and aggregates across vCPUs, so it is not a
        // faithful per-engine count for embedders or for single stepping.)
        self.insn_count
    }

    fn get_emulator_state(&self) -> Option<crate::vm::snapshot::EmulatorState> {
        use crate::vm::snapshot::{EmulatorState, FpuSnapshot, LazyFlagsSnapshot};

        let lf = self.lazy_flags;
        Some(EmulatorState {
            fpu: FpuSnapshot {
                control_word: self.fpu.control_word,
                status_word: self.fpu.status_word,
                tag_word: self.fpu.tag_word,
                data_ptr: self.fpu.data_ptr,
                instr_ptr: self.fpu.instr_ptr,
                last_opcode: self.fpu.last_opcode,
                st: self.fpu.st,
                top: self.fpu.top,
            },
            lazy_flags: LazyFlagsSnapshot {
                op: match lf.op {
                    LazyFlagOp::None => 0,
                    LazyFlagOp::Add => 1,
                    LazyFlagOp::Sub => 2,
                    LazyFlagOp::Logic => 3,
                    LazyFlagOp::Inc => 4,
                    LazyFlagOp::Dec => 5,
                },
                result: lf.result,
                src: lf.src,
                dst: lf.dst,
                size: lf.size,
            },
            kernel_gs_base: self.kernel_gs_base,
            tsc_adjust: self.tsc_adjust,
            tsc_aux: self.tsc_aux,
            misc_enable: self.misc_enable,
            pat: self.pat,
            umwait_control: self.umwait_control,
            pkru: self.pkru,
            mxcsr: self.mxcsr,
            halted: self.halted,
            interrupt_inhibit: self.interrupt_inhibit,
        })
    }

    fn set_emulator_state(&mut self, state: &crate::vm::snapshot::EmulatorState) -> Result<()> {
        #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
        {
            self.jit_vsib_resume_pc = None;
        }
        // Restore FPU state
        self.fpu.control_word = state.fpu.control_word;
        self.fpu.status_word = state.fpu.status_word;
        self.fpu.tag_word = state.fpu.tag_word;
        self.fpu.data_ptr = state.fpu.data_ptr;
        self.fpu.instr_ptr = state.fpu.instr_ptr;
        self.fpu.last_opcode = state.fpu.last_opcode;
        self.fpu.st = state.fpu.st;
        self.fpu.top = state.fpu.top;

        // Restore lazy flags
        let op = match state.lazy_flags.op {
            0 => LazyFlagOp::None,
            1 => LazyFlagOp::Add,
            2 => LazyFlagOp::Sub,
            3 => LazyFlagOp::Logic,
            4 => LazyFlagOp::Inc,
            5 => LazyFlagOp::Dec,
            _ => LazyFlagOp::None,
        };
        self.lazy_flags = LazyFlags {
            op,
            result: state.lazy_flags.result,
            src: state.lazy_flags.src,
            dst: state.lazy_flags.dst,
            size: state.lazy_flags.size,
        };

        // Restore other state
        self.kernel_gs_base = state.kernel_gs_base;
        self.tsc_adjust = state.tsc_adjust;
        self.tsc_aux = state.tsc_aux;
        self.misc_enable = state.misc_enable;
        self.pat = state.pat;
        self.umwait_control = state.umwait_control;
        self.pkru = state.pkru;
        self.mxcsr = state.mxcsr;
        self.halted = state.halted;
        self.interrupt_inhibit = state.interrupt_inhibit;

        Ok(())
    }
}

/// Global instruction counter for snapshotting
static GLOBAL_INSN_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Get the total instruction count
pub fn get_total_instruction_count() -> u64 {
    GLOBAL_INSN_COUNT.load(std::sync::atomic::Ordering::Relaxed)
}

/// Publish a vCPU's retired-instruction count to the global counter. Called at
/// run() exit boundaries (not per-instruction) for snapshot/diagnostic readers.
#[inline]
pub fn publish_instruction_count(count: u64) {
    GLOBAL_INSN_COUNT.store(count, std::sync::atomic::Ordering::Relaxed);
}

// ============================================================================
// SMIR native hot-block JIT tier (opt-in via the `smir-jit` feature).
//
// This is an additive fast tier that sits BESIDE the interpreter — it never
// touches the `step()` hot path. Given a self-contained basic-block region at
// the current RIP (a hot loop / ALU chain that exits via HLT), it lifts the
// region to SMIR, verifies it is clobber-safe under the 1:1 identity register
// map, lowers it through the current host backend (x86-64 or AArch64), and runs
// it through that host's native trampoline. The AArch64 host path is initially
// limited to scalar legacy x86 GPRs and representable flag contracts.
// Explicit `jit_try_block` calls keep internal branches native; run-loop auto
// promotion lowers backward edges as exits so housekeeping can run between loop
// iterations. Host-specific regression suites compare complete architectural
// state against the interpreter; x86-64 additionally has KVM differentials.
// ============================================================================
/// Backward-branch hits at a loop head before the JIT promotes (compiles) it.
/// Low enough to catch real hot loops quickly, high enough to skip loops that
/// run only a handful of times (where lift+lower would not pay off).
#[cfg(all(
    feature = "smir-jit",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const JIT_HOT_THRESHOLD: u32 = 64;

/// Maximum guest-code prefix examined for one JIT region and retained for an
/// exact ineligibility memo. The 8192-entry memo cap therefore bounds snapshot
/// payload to 8192 * 512 B = 4,194,304 B, excluding map/vector metadata.
#[cfg(all(
    feature = "smir-jit",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const JIT_LIFT_WINDOW: usize = 512;

#[cfg(all(
    feature = "smir-jit",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const JIT_INELIGIBLE_CAP: usize = 8192;

#[cfg(all(feature = "smir-jit", target_arch = "x86_64", not(test)))]
const JIT_VERIFY_MEM_LOG_LIMIT: usize = 1_000_000;

#[cfg(all(feature = "smir-jit", target_arch = "x86_64", not(test)))]
const JIT_VERIFY_MEM_TRACE_LIMIT: usize = 1_000_000;

#[cfg(all(feature = "smir-jit", target_arch = "x86_64", test))]
const JIT_VERIFY_MEM_LOG_LIMIT: usize = 4;

#[cfg(all(feature = "smir-jit", target_arch = "x86_64", test))]
const JIT_VERIFY_MEM_TRACE_LIMIT: usize = 4;

#[cfg(all(
    feature = "smir-jit",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[path = "cpu_jit_state.rs"]
mod jit_state;
#[cfg(all(
    feature = "smir-jit",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use jit_state::JitRegion;
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
use jit_state::{jit_mxcsr_masks_all_exceptions, merge_native_rflags};

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_verify.rs"]
mod jit_verify;

#[cfg(any(test, all(feature = "smir-jit", target_arch = "x86_64")))]
#[path = "cpu_jit_vsib_verify.rs"]
mod jit_vsib_verify;
#[cfg(any(test, all(feature = "smir-jit", target_arch = "x86_64")))]
pub(in crate::isa::x86_64) use jit_vsib_verify::JitVerifyVsibStop;

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_mem_load.rs"]
mod jit_mem_load;
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
use jit_mem_load::rax_jit_mem_load;

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_mem_store.rs"]
mod jit_mem_store;
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
use jit_mem_store::rax_jit_mem_store;

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_cmpccxadd.rs"]
mod jit_cmpccxadd;
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
use jit_cmpccxadd::rax_jit_cmpccxadd;

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_io.rs"]
mod jit_io;
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
use jit_io::rax_jit_io;

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_enter.rs"]
mod jit_enter;
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
use jit_enter::rax_jit_enter;

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_stack_flags.rs"]
mod jit_stack_flags;
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
use jit_stack_flags::rax_jit_stack_flags;

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_vector_memory.rs"]
mod jit_vector_memory;
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
use jit_vector_memory::{rax_jit_vec_load, rax_jit_vec_store};

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_x87_state.rs"]
mod jit_x87_state;

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_call.rs"]
mod jit_call;
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
use jit_call::{
    jit_call_enabled, jit_call_target_supported, jit_call_target_uses_mem_helper, rax_jit_call,
};

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_cpuid.rs"]
mod jit_cpuid;
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
use jit_cpuid::rax_jit_cpuid;

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_control.rs"]
mod jit_control;
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
use jit_control::rax_jit_write_control;

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_cli.rs"]
mod jit_cli;
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
use jit_cli::rax_jit_cli;

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_sti.rs"]
mod jit_sti;
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
use jit_sti::rax_jit_sti;

#[path = "cpu_invlpg.rs"]
mod invlpg;
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
use invlpg::{rax_jit_invlpg, rax_jit_invpcid};

#[path = "cpu_descriptor_table.rs"]
mod descriptor_table;
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
use descriptor_table::{
    rax_jit_descriptor_table_load, rax_jit_descriptor_table_store, rax_jit_system_selector,
    rax_jit_system_selector_load,
};

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_far_jump.rs"]
mod jit_far_jump;
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
use jit_far_jump::rax_jit_far_jump;

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_far_call.rs"]
mod jit_far_call;
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
use jit_far_call::rax_jit_far_call;

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_far_return.rs"]
mod jit_far_return;
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
use jit_far_return::rax_jit_far_return;

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_fast_system_transfer.rs"]
mod jit_fast_system_transfer;
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
use jit_fast_system_transfer::rax_jit_fast_system_transfer;

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_msr.rs"]
mod jit_msr;
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
use jit_msr::rax_jit_msr;

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_pmc.rs"]
mod jit_pmc;
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
use jit_pmc::rax_jit_pmc;

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_tsc.rs"]
mod jit_tsc;
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
use jit_tsc::rax_jit_tsc;

/// RAX_JIT_BAIL=1 logs why each hot region is rejected by the JIT (diagnostic
/// for expanding the whitelist toward the highest-frequency bail reasons).
#[cfg(all(
    feature = "smir-jit",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn jit_bail_log() -> bool {
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("RAX_JIT_BAIL").is_some())
}

/// Memory-touching hot regions are enabled by default: register Load/Store lower
/// to MMU helper calls (`rax_jit_mem_load`/`rax_jit_mem_store`) with per-op
/// fault-bail to the interpreter. `RAX_JIT_NO_MEM=1` restores register-only JIT.
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
fn jit_default_enabled(disable_present: bool) -> bool {
    !disable_present
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
fn jit_mem_enabled() -> bool {
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| jit_default_enabled(std::env::var_os("RAX_JIT_NO_MEM").is_some()))
}

/// Guest entry PC of the JIT region currently executing natively (RAX_JIT_TRACE).
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
static JIT_LAST_ENTRY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Host executable mapping currently entered by the native JIT. These bounds
/// let the crash handler report a stable native offset and nearby bytes without
/// allocation, locking, or symbolization in signal context.
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
static JIT_LAST_HOST_BASE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
static JIT_LAST_HOST_LEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// SIGSEGV/SIGBUS/SIGILL handler: a host fault inside native JIT code prints
/// the guest region entry + faulting address, restores any raw terminal state,
/// then restores the default disposition and re-raises.
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
extern "C" fn jit_crash_handler(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    _ctx: *mut libc::c_void,
) {
    use std::sync::atomic::Ordering;
    // Build the complete crash location and bounded byte window in a fixed
    // buffer. libc::write is the only external operation on this path.
    let mut buf = [0u8; 256];
    let mut n = 0usize;
    let mut put = |s: &[u8], buf: &mut [u8; 256], n: &mut usize| {
        for &b in s {
            if *n < buf.len() {
                buf[*n] = b;
                *n += 1;
            }
        }
    };
    let mut put_hex = |mut v: u64, buf: &mut [u8; 256], n: &mut usize| {
        put(b"0x", buf, n);
        let mut started = false;
        for shift in (0..16).rev() {
            let nib = ((v >> (shift * 4)) & 0xf) as u8;
            if nib != 0 || started || shift == 0 {
                started = true;
                let c = if nib < 10 {
                    b'0' + nib
                } else {
                    b'a' + nib - 10
                };
                if *n < buf.len() {
                    buf[*n] = c;
                    *n += 1;
                }
            }
        }
        let _ = &mut v;
    };
    put(b"\n[JIT-CRASH] sig=", &mut buf, &mut n);
    put_hex(sig as u64, &mut buf, &mut n);
    put(b" entry=", &mut buf, &mut n);
    put_hex(JIT_LAST_ENTRY.load(Ordering::Relaxed), &mut buf, &mut n);
    put(b" addr=", &mut buf, &mut n);
    let addr = unsafe { (*info).si_addr() } as u64;
    put_hex(addr, &mut buf, &mut n);
    let host_base = JIT_LAST_HOST_BASE.load(Ordering::Relaxed);
    let host_len = JIT_LAST_HOST_LEN.load(Ordering::Relaxed);
    let host_end = host_base.saturating_add(host_len);
    if addr >= host_base && addr < host_end {
        put(b" host_off=", &mut buf, &mut n);
        put_hex(addr - host_base, &mut buf, &mut n);
        put(b" bytes=", &mut buf, &mut n);
        let start = addr.saturating_sub(8).max(host_base);
        let end = addr.saturating_add(16).min(host_end);
        for byte_addr in start..end {
            let byte = unsafe { core::ptr::read_volatile(byte_addr as *const u8) };
            for nibble in [byte >> 4, byte & 0x0F] {
                if n < buf.len() {
                    buf[n] = if nibble < 10 {
                        b'0' + nibble
                    } else {
                        b'a' + nibble - 10
                    };
                    n += 1;
                }
            }
        }
    }
    put(b"\n", &mut buf, &mut n);
    unsafe {
        libc::write(2, buf.as_ptr() as *const libc::c_void, n);
    }
    jit_crash_cleanup();
    unsafe {
        // Restore default disposition and re-raise to produce the core dump.
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
fn jit_crash_cleanup() {
    crate::host::terminal::restore_terminal();
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
fn jit_install_crash_handler() {
    use std::sync::OnceLock;
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = jit_crash_handler as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGSEGV, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGBUS, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGILL, &sa, std::ptr::null_mut());
    });
}

/// JIT APX POP2 helper. A complete aligned 16-byte read is staged before any
/// architectural state changes. `dst_low` is the EVEX V register and receives
/// `[RSP]`; `dst_high` is the ModRM B register and receives `[RSP+8]`.
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
unsafe extern "C" fn rax_jit_pair_load(
    state: *mut crate::smir::lower::runtime::GuestRegs,
    dst_low: u32,
    dst_high: u32,
) -> u64 {
    let Some(state) = (unsafe { state.as_mut() }) else {
        return 0;
    };
    if state.apx_enabled == 0
        || dst_low >= 32
        || dst_high >= 32
        || dst_low == 4
        || dst_high == 4
        || dst_low == dst_high
    {
        return 0;
    }
    let rsp = state.gpr[4];
    if rsp & 0xF != 0 {
        return 0;
    }
    let Some(vcpu) = (unsafe { (state.ctx as *mut X86_64Vcpu).as_mut() }) else {
        return 0;
    };
    let Ok((low, high)) = vcpu.read_mem_pair(rsp) else {
        return 0;
    };

    state.gpr[4] = rsp.wrapping_add(16);
    state.gpr[dst_low as usize] = low;
    state.gpr[dst_high as usize] = high;
    1
}

/// JIT APX PUSH2 helper. The two values are submitted to the MMU as one
/// aligned 16-byte transfer, providing the architectural both-or-neither fault
/// behavior without promising a single atomic 16-byte physical store.
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
unsafe extern "C" fn rax_jit_pair_store(
    state: *mut crate::smir::lower::runtime::GuestRegs,
    src_low: u32,
    src_high: u32,
) -> u64 {
    let Some(state) = (unsafe { state.as_mut() }) else {
        return 0;
    };
    if state.apx_enabled == 0 || src_low >= 32 || src_high >= 32 || src_low == 4 || src_high == 4 {
        return 0;
    }
    let old_rsp = state.gpr[4];
    if old_rsp & 0xF != 0 {
        return 0;
    }
    let Some(vcpu) = (unsafe { (state.ctx as *mut X86_64Vcpu).as_mut() }) else {
        return 0;
    };
    let new_rsp = old_rsp.wrapping_sub(16);
    if vcpu.mmu.is_code_page(new_rsp) || vcpu.mmu.is_code_page(new_rsp.wrapping_add(15)) {
        return 0;
    }

    if vcpu.jit_mem_log.is_some() {
        let saved_trace = vcpu.jit_mem_trace.take();
        let old = vcpu.read_mem_pair(new_rsp);
        vcpu.jit_mem_trace = saved_trace;
        match old {
            Ok((low, high)) => {
                vcpu.push_jit_mem_log((new_rsp, 8, low));
                if vcpu.jit_mem_log.is_some() {
                    vcpu.push_jit_mem_log((new_rsp.wrapping_add(8), 8, high));
                }
            }
            Err(_) => vcpu.jit_mem_log = None,
        }
    }

    let low = state.gpr[src_low as usize];
    let high = state.gpr[src_high as usize];
    if vcpu.write_mem_pair(new_rsp, low, high).is_err() {
        return 0;
    }
    state.gpr[4] = new_rsp;
    1
}

/// Classify the first reason an executed block of `func` fails the clobber gate:
/// the offending op's variant name, or `rsp/rbp` / `virtual-dst`.
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
fn jit_classify_bail(
    func: &crate::smir::ir::SmirFunction,
    exits: &std::collections::HashMap<crate::smir::ir::types::BlockId, u64>,
    allow_mem: bool,
) -> String {
    use crate::smir::ir::types::{ArchReg, VReg, X86Reg};
    use crate::smir::lower::runtime::{
        is_x86_native_vector_op, x86_jit_mmx_mem_shape_valid, x86_jit_pop_candidate,
        x86_jit_pop_sequence_len, x86_jit_pop2_candidate, x86_jit_pop2_sequence_len,
        x86_jit_push_candidate, x86_jit_push_sequence_len, x86_jit_push2_candidate,
        x86_jit_push2_sequence_len, x86_jit_scalar_alu_immediate_valid,
        x86_jit_vector_mem_shape_valid, x86_state_backed_stack_alu_valid,
        x86_state_backed_stack_mov_valid,
    };
    let is_sp_bp = |v: &VReg| {
        matches!(
            v,
            VReg::Arch(ArchReg::X86(X86Reg::Rsp)) | VReg::Arch(ArchReg::X86(X86Reg::Rbp))
        )
    };
    let variant = |k: &crate::smir::ir::ops::OpKind| -> String {
        let s = format!("{k:?}");
        s.split([' ', '{', '(']).next().unwrap_or("?").to_string()
    };
    use crate::smir::ir::Terminator;
    use crate::smir::ir::ops::OpKind;
    for b in &func.blocks {
        if exits.contains_key(&b.id) {
            continue;
        }
        let n = b.ops.len();
        let mut virtual_definitions = std::collections::HashMap::new();
        let mut virtual_uses = std::collections::HashMap::new();
        for op in &b.ops {
            for reg in op.kind.dests() {
                if matches!(reg, VReg::Virtual(_)) {
                    *virtual_definitions.entry(reg).or_insert(0usize) += 1;
                }
            }
            for reg in op.kind.source_vregs() {
                if matches!(reg, VReg::Virtual(_)) {
                    *virtual_uses.entry(reg).or_insert(0usize) += 1;
                }
            }
        }
        let mut i = 0;
        while i < n {
            if let Some(consumed) =
                x86_jit_pop2_sequence_len(b, i, allow_mem, &virtual_definitions, &virtual_uses)
            {
                i += consumed;
                continue;
            }
            if x86_jit_pop2_candidate(b, i) {
                return "pop2-shape".to_string();
            }
            if let Some(consumed) =
                x86_jit_push2_sequence_len(b, i, allow_mem, &virtual_definitions, &virtual_uses)
            {
                i += consumed;
                continue;
            }
            if x86_jit_push2_candidate(b, i) {
                return "push2-shape".to_string();
            }
            if let Some(consumed) =
                x86_jit_pop_sequence_len(b, i, allow_mem, &virtual_definitions, &virtual_uses)
            {
                i += consumed;
                continue;
            }
            if x86_jit_pop_candidate(b, i) {
                return "pop-shape".to_string();
            }
            if let Some(consumed) =
                x86_jit_push_sequence_len(b, i, allow_mem, &virtual_definitions, &virtual_uses)
            {
                i += consumed;
                continue;
            }
            if x86_jit_push_candidate(b, i) {
                return "push-shape".to_string();
            }
            let op = &b.ops[i];
            // Mirror block_is_clobber_safe: a trailing TestCondition feeding the
            // block's CondBranch is folded to a direct Jcc (exempt), not a bail.
            if i + 1 == n {
                if let (Terminator::CondBranch { cond, .. }, OpKind::TestCondition { dst, .. }) =
                    (&b.terminator, &op.kind)
                {
                    if dst == cond {
                        i += 1;
                        continue;
                    }
                }
            }
            let mem_ok = allow_mem
                && (matches!(op.kind, OpKind::Load { .. } | OpKind::Store { .. })
                    || x86_jit_vector_mem_shape_valid(&op.kind)
                    || x86_jit_mmx_mem_shape_valid(op));
            let vector_ok = is_x86_native_vector_op(&op.kind);
            let stack_mov_ok = x86_state_backed_stack_mov_valid(&op.kind);
            let stack_alu_ok = x86_state_backed_stack_alu_valid(&op.kind);
            let stack_state_ok = stack_mov_ok || stack_alu_ok;
            if !op.is_jit_safe() && !mem_ok && !vector_ok {
                return variant(&op.kind);
            }
            if !x86_jit_scalar_alu_immediate_valid(&op.kind) {
                return format!("unencodable-immediate:{}", variant(&op.kind));
            }
            if op
                .kind
                .dests()
                .iter()
                .any(|d| matches!(d, VReg::Virtual(_)))
            {
                return format!("virtual-dst:{}", variant(&op.kind));
            }
            if (!stack_state_ok && op.kind.dests().iter().any(is_sp_bp))
                || (!mem_ok
                    && !stack_state_ok
                    && op.kind.source_vregs().iter().any(|v| is_sp_bp(v)))
            {
                return format!("rsp/rbp:{}", variant(&op.kind));
            }
            i += 1;
        }
    }
    "?".to_string()
}

#[cfg(all(
    feature = "smir-jit",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
impl X86_64Vcpu {
    /// Attempt to JIT-compile and natively execute the hot region at the current
    /// RIP, handing control back to the interpreter at the region's exit.
    /// Returns `Ok(true)` if it ran natively (guest registers updated and RIP
    /// advanced to the exit address — the caller should continue interpreting
    /// from there), or `Ok(false)` if the region is ineligible (caller falls
    /// back to `step()`).
    ///
    /// The region is the CFG reachable from RIP up to "frontier" terminals
    /// (HLT / RET / CALL / indirect / syscall / switch); internal Branch and
    /// CondBranch edges (loop back-edges, if/else) execute natively. Each
    /// frontier block lowers to an exit stub that records its guest PC into
    /// `exit_pc`; the JIT runs UP TO but not THROUGH it, so the interpreter
    /// resumes there and re-executes that block. Eligibility: the entry block
    /// must not itself be a frontier (else there is no native work), every
    /// block must be clobber-safe (writes only architectural registers, with
    /// state-backed lowering for admitted RSP/RBP forms and validated fusions
    /// for selected virtuals), and the region must lower with no unresolved
    /// relocations. An uneliminated virtual
    /// temporary would corrupt a guest GPR under the identity register map.
    ///
    /// CAVEAT: a guest infinite loop with no reachable frontier would spin in
    /// native code uninterruptibly — callers should only invoke this for
    /// regions known to terminate (e.g. promoted hot loops with an exit edge).
    pub fn jit_try_block(&mut self) -> Result<bool> {
        if self.interrupt_inhibit || self.jit_disabled_for_debugger() {
            return Ok(false);
        }

        match self.jit_compile_region()? {
            Some(region) => {
                if std::env::var_os("RAX_JIT_LOG").is_some() {
                    eprintln!(
                        "[JIT] compiled hot region @ {:#x} (regions cached: {})",
                        self.regs.rip,
                        self.jit_region_count()
                    );
                }
                self.jit_run_region(&region);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Compile the hot region at the current RIP into a native [`JitRegion`], or
    /// return `Ok(None)` if it is ineligible (see [`Self::jit_try_block`] for the
    /// eligibility rules). This is the cacheable half — the returned region is
    /// register-state-independent and may be re-run for any later entry to the
    /// same RIP (until the underlying guest code changes; see SMC invalidation).
    pub(super) fn jit_compile_region(&mut self) -> Result<Option<JitRegion>> {
        if self.jit_disabled_for_debugger() {
            return Ok(None);
        }

        self.jit_compile_region_with_edge_exits(false)
    }

    /// Read the largest contiguous guest-code prefix, up to `max_len`, that is
    /// currently accessible. JIT compilation must not require an entire fixed
    /// lookahead window to be mapped: the lifter can terminate at the readable
    /// boundary and return to the interpreter there.
    ///
    /// Guest prefix readability is monotonic in `len`, so binary search needs
    /// O(log(max_len)) MMU probes and retains the bytes from the largest
    /// successful probe without an additional read.
    fn jit_read_lift_window(&mut self, entry: u64, max_len: usize) -> Option<Vec<u8>> {
        let mut readable = 0usize;
        let mut unreadable = max_len;
        let mut best = None;

        // Compilation lookahead is not a retired guest data access. Suppress
        // memory tracing for every probe, as the ordinary instruction-fetch
        // path does around decoder lookahead.
        self.mmu.set_fetch_active(true);
        while readable < unreadable {
            let len = readable + (unreadable - readable).div_ceil(2);
            match self.read_bytes(entry, len) {
                Ok(bytes) => {
                    readable = len;
                    best = Some(bytes);
                }
                Err(_) => unreadable = len - 1,
            }
        }
        self.mmu.set_fetch_active(false);

        best
    }

    fn jit_backward_native_exit_edges(
        func: &crate::smir::ir::SmirFunction,
        exits: &std::collections::HashMap<BlockId, u64>,
    ) -> std::collections::HashMap<(BlockId, BlockId), u64> {
        use crate::smir::ir::Terminator;
        use std::collections::HashMap;

        let guest_pcs: HashMap<_, _> = func.blocks.iter().map(|b| (b.id, b.guest_pc)).collect();
        let mut edge_exits = HashMap::new();

        for block in &func.blocks {
            if exits.contains_key(&block.id) {
                continue;
            }

            // O2 may merge a forward setup block with a later loop body while
            // retaining the setup block's original `guest_pc`. The terminator
            // is then located after that entry address; classifying against the
            // stale block start misses edges that are backward from the actual
            // branch (and lets a yielded native slice run extra iterations).
            // The final semantic op carries the terminator boundary PC emitted
            // by the lifter and follows the terminator across block merging.
            let terminator_pc = block
                .ops
                .last()
                .map(|op| op.guest_pc)
                .unwrap_or(block.guest_pc);
            let mut add_backward_edge = |target| {
                if exits.contains_key(&target) {
                    return;
                }
                if let Some(&target_pc) = guest_pcs.get(&target) {
                    // A distinct fallthrough block may start at the same guest
                    // PC as the source block's final condition-materialization
                    // op. Equality is backward only for a genuine self-loop.
                    if target_pc < terminator_pc || target == block.id {
                        edge_exits.insert((block.id, target), target_pc);
                    }
                }
            };

            match &block.terminator {
                Terminator::Branch { target } => add_backward_edge(*target),
                Terminator::CondBranch {
                    true_target,
                    false_target,
                    ..
                } => {
                    add_backward_edge(*true_target);
                    add_backward_edge(*false_target);
                }
                _ => {}
            }
        }

        edge_exits
    }

    /// Compile a region, optionally lowering internal backward Branch/CondBranch
    /// edges as native exits. The yielding mode is for run-loop auto promotion:
    /// it bounds each native invocation to an acyclic slice of the lifted CFG.
    fn jit_compile_region_with_edge_exits(
        &mut self,
        yield_backward_edges: bool,
    ) -> Result<Option<JitRegion>> {
        use crate::smir::ir::Terminator;
        use crate::smir::ir::memory::MemoryError;
        #[cfg(target_arch = "x86_64")]
        use crate::smir::ir::ops::OpKind;
        use crate::smir::ir::types::SourceArch;
        use crate::smir::lift::x86_64::X86_64Lifter;
        use crate::smir::lift::{LiftContext, MemoryReader, SmirLifter};
        use crate::smir::lower::SmirLowerer;
        #[cfg(target_arch = "aarch64")]
        use crate::smir::lower::aarch64::Aarch64Lowerer;
        use crate::smir::lower::runtime::ExecMem;
        #[cfg(target_arch = "aarch64")]
        use crate::smir::lower::runtime::is_x86_aarch64_native_clobber_safe_excluding;
        #[cfg(target_arch = "x86_64")]
        use crate::smir::lower::runtime::{
            is_native_clobber_safe_excluding, uses_x86_mxcsr_state_excluding,
            uses_x86_native_mmx_excluding, uses_x86_native_vectors_excluding,
            uses_x86_x87_environment_state_excluding, uses_x86_x87_tag_state_excluding,
            uses_x86_xmm_state_excluding, x86_jit_op_uses_mem_helper,
            x86_native_mmx_features_supported_excluding, x86_native_mmx_pairs_valid_excluding,
            x86_native_scalar_features_supported_excluding,
            x86_native_vector_features_supported_excluding,
            x86_native_vector_uses_avx_ymm16_only_excluding,
            x86_native_vector_uses_k16_opmasks_excluding,
        };
        #[cfg(target_arch = "x86_64")]
        use crate::smir::lower::x86_64::{
            X86_64Lowerer, x86_far_call_terminal_shape_valid, x86_far_jump_terminal_shape_valid,
            x86_far_return_terminal_shape_valid, x86_fast_system_transfer_terminal_shape_valid,
        };
        use crate::smir::optimize::{OptLevel, optimize_function};
        use std::collections::HashMap;

        let entry = self.regs.rip;

        // Snapshot the largest readable prefix of a bounded guest-code window.
        // 512 B covers typical hot loops; an unmapped suffix becomes an explicit
        // interpreter frontier instead of rejecting an otherwise liftable
        // prefix.
        let bytes = match self.jit_read_lift_window(entry, JIT_LIFT_WINDOW) {
            Some(bytes) => bytes,
            None => return Ok(None),
        };

        struct Win {
            base: u64,
            bytes: Vec<u8>,
        }
        impl MemoryReader for Win {
            fn read(&self, addr: u64, size: usize) -> core::result::Result<Vec<u8>, MemoryError> {
                let off = addr
                    .checked_sub(self.base)
                    .filter(|&o| (o as usize) < self.bytes.len())
                    .ok_or(MemoryError::OutOfBounds { addr })? as usize;
                let n = (self.bytes.len() - off).min(size);
                Ok(self.bytes[off..off + n].to_vec())
            }
        }
        let reader = Win { base: entry, bytes };

        // Try lift-through-calls first (a call-heavy loop body lifts into one
        // native region with runtime call-outs). If that bigger region is
        // ineligible, retry WITHOUT call-mode (the smaller call-as-frontier
        // region). This makes lift-through-calls STRICTLY ADDITIVE — never worse
        // than the baseline mem/register JIT coverage.
        #[cfg(target_arch = "x86_64")]
        // The callout helper implements the 64-bit near-CALL contract: an
        // 8-byte return-address push and a 64-bit target. Compatibility-mode
        // CALL widths remain exact interpreter frontiers.
        let want_call = self.jit_call && self.sregs.cs.l;
        #[cfg(target_arch = "aarch64")]
        let want_call = false;
        let modes: &[bool] = if want_call { &[true, false] } else { &[false] };
        'modes: for &cm in modes {
            let mut lifter = X86_64Lifter::strict();
            lifter.set_interpreter_frontiers(true);
            if cm {
                lifter.set_lift_through_calls(512);
            }
            let mut lctx = LiftContext::new(SourceArch::X86_64);
            let mut func = match lifter.lift_function(entry, &reader, &mut lctx) {
                Ok(f) => f,
                Err(e) => {
                    if jit_bail_log() {
                        eprintln!("[JIT-BAIL] lift-err:{e:?} @ {entry:#x} (call={cm})");
                    }
                    continue 'modes;
                }
            };

            // Capture source pages before optimization can merge or discard IR
            // structure. A runnable region with incomplete provenance cannot be
            // protected against self-modifying code and therefore fails closed.
            let Some(source_pages) = JitRegion::collect_source_pages(&func) else {
                if jit_bail_log() {
                    eprintln!("[JIT-BAIL] source-pages @ {entry:#x} (call={cm})");
                }
                continue 'modes;
            };

            // Optimize before computing exits / lowering (frontier-aware, see note).
            if std::env::var_os("RAX_JIT_NO_OPT").is_none() {
                optimize_function(&mut func, OptLevel::O2);
            }

            // Mark every frontier terminal as a native-exit stub (records guest
            // PC); internal Branch/CondBranch edges stay native (loops, if/else).
            let mut exits: HashMap<_, u64> = HashMap::new();
            // Block ids present in the lifted function — to validate a CALL's
            // continuation was lifted before lowering it as a call-out.
            let lifted: std::collections::HashSet<_> = func.blocks.iter().map(|b| b.id).collect();
            for b in &func.blocks {
                let frontier = match &b.terminator {
                    Terminator::Trap { .. }
                    | Terminator::Return { .. }
                    | Terminator::TailCall { .. }
                    | Terminator::IndirectBranchMem { .. }
                    | Terminator::Switch { .. } => true,
                    Terminator::IndirectBranch { .. } => {
                        #[cfg(target_arch = "x86_64")]
                        {
                            !(x86_far_jump_terminal_shape_valid(b)
                                || x86_far_call_terminal_shape_valid(b)
                                || x86_far_return_terminal_shape_valid(b)
                                || x86_fast_system_transfer_terminal_shape_valid(b))
                        }
                        #[cfg(target_arch = "aarch64")]
                        {
                            true
                        }
                    }
                    // Lift-through-calls: a CALL is NOT a frontier when call-mode
                    // is on, the continuation was lifted, and the target form is
                    // supported — it lowers to a runtime call-out and continues
                    // natively at `continuation`.
                    Terminator::Call {
                        target,
                        continuation,
                        ..
                    } => {
                        #[cfg(target_arch = "x86_64")]
                        let target_ok = jit_call_target_supported(target, self.jit_mem);
                        #[cfg(target_arch = "aarch64")]
                        let target_ok = false;
                        !(cm && target_ok && lifted.contains(continuation))
                    }
                    _ => false,
                };
                if frontier {
                    exits.insert(b.id, b.guest_pc);
                }
            }
            // Auto-promotion bounds every invocation by converting internal
            // backward edges into native exits. This also makes a closed loop
            // eligible even when it has no terminal frontier: the run loop
            // regains control at each iteration for SMC/interrupt housekeeping.
            // Explicit `jit_try_block` compilation does not request edge exits,
            // so a frontier-less loop still declines instead of running forever.
            let edge_exits = if yield_backward_edges {
                Self::jit_backward_native_exit_edges(&func, &exits)
            } else {
                HashMap::new()
            };
            #[cfg(target_arch = "x86_64")]
            let mut yielded_backward_exit_pcs: Vec<u64> = edge_exits.values().copied().collect();
            #[cfg(target_arch = "x86_64")]
            {
                yielded_backward_exit_pcs.sort_unstable();
                yielded_backward_exit_pcs.dedup();
            }
            #[cfg(target_arch = "x86_64")]
            let mut callout_boundaries = Vec::new();
            #[cfg(target_arch = "x86_64")]
            if cm {
                let block_pcs: HashMap<_, _> = func
                    .blocks
                    .iter()
                    .map(|block| (block.id, block.guest_pc))
                    .collect();
                let mut metadata_complete = true;
                for block in &func.blocks {
                    let Terminator::Call {
                        target,
                        continuation,
                        ..
                    } = &block.terminator
                    else {
                        continue;
                    };
                    if !jit_call_target_supported(target, self.jit_mem)
                        || !lifted.contains(continuation)
                    {
                        continue;
                    }
                    let Some(&return_pc) = block_pcs.get(continuation) else {
                        metadata_complete = false;
                        break;
                    };
                    let mut sites = func.x86_instruction_bytes.iter().filter_map(
                        |(&(instruction_block, pc), instruction)| {
                            (instruction_block == block.id
                                && pc.checked_add(instruction.as_slice().len() as u64)
                                    == Some(return_pc))
                            .then_some(pc)
                        },
                    );
                    let Some(call_pc) = sites.next() else {
                        metadata_complete = false;
                        break;
                    };
                    if sites.next().is_some() {
                        metadata_complete = false;
                        break;
                    }
                    callout_boundaries.push((call_pc, return_pc));
                }
                if !metadata_complete {
                    // The lowerer also rejects missing/ambiguous CALL
                    // provenance. Fail this mode before producing unverifiable
                    // runtime metadata and retry the call-as-frontier mode.
                    continue 'modes;
                }
                callout_boundaries.sort_unstable();
            }
            #[cfg(target_arch = "x86_64")]
            let has_native_terminal = func
                .blocks
                .iter()
                .filter(|block| !exits.contains_key(&block.id))
                .any(|block| {
                    x86_far_jump_terminal_shape_valid(block)
                        || x86_far_call_terminal_shape_valid(block)
                        || x86_far_return_terminal_shape_valid(block)
                        || x86_fast_system_transfer_terminal_shape_valid(block)
                });
            #[cfg(target_arch = "aarch64")]
            let has_native_terminal = false;
            if exits.is_empty() && edge_exits.is_empty() && !has_native_terminal {
                if jit_bail_log() {
                    eprintln!("[JIT-BAIL] no-frontier @ {entry:#x} (call={cm})");
                }
                continue 'modes;
            }
            // Entry block is itself a frontier ⇒ no native work.
            if exits.contains_key(&func.entry) {
                if jit_bail_log() {
                    // Diagnostic: WHY is the entry a frontier? Print the entry
                    // terminator's shape (and, for a Call, why it stayed a
                    // frontier) so we can see what lift-through-calls must crack.
                    let why = func
                        .blocks
                        .iter()
                        .find(|b| b.id == func.entry)
                        .map(|b| match &b.terminator {
                            Terminator::Trap { .. } => "Trap".to_string(),
                            Terminator::Return { .. } => "Return".to_string(),
                            Terminator::TailCall { .. } => "TailCall".to_string(),
                            Terminator::IndirectBranch { .. } => "IndirectBranch".to_string(),
                            Terminator::IndirectBranchMem { .. } => "IndirectBranchMem".to_string(),
                            Terminator::Switch { .. } => "Switch".to_string(),
                            Terminator::Call {
                                target,
                                continuation,
                                ..
                            } => {
                                let tk = target.kind_name();
                                format!("Call/{tk}(lifted-cont={})", lifted.contains(continuation))
                            }
                            _ => "other".to_string(),
                        })
                        .unwrap_or_else(|| "?".to_string());
                    eprintln!("[JIT-BAIL] entry-frontier:{why} @ {entry:#x} (call={cm})");
                }
                continue 'modes;
            }
            // Standalone x86-64 SMIR models original-VEX CMPccXADD plus the
            // 64-bit FSGSBASE/SWAPGS and MONITOR/MWAIT/WAITPKG contracts, but
            // this CPU can also compile compatibility-mode regions. Reject
            // these mode-dependent ops before native admission and let the
            // direct decoder apply compatibility-mode operand/address and
            // exception rules. CS.L is in the JIT cache tag.
            #[cfg(target_arch = "x86_64")]
            if !self.sregs.cs.l
                && func
                    .blocks
                    .iter()
                    .filter(|block| !exits.contains_key(&block.id))
                    .flat_map(|block| &block.ops)
                    .any(|op| {
                        matches!(
                            op.kind,
                            OpKind::AtomicCmpXadd { .. }
                                | OpKind::X86FsGsBase { .. }
                                | OpKind::X86SwapGs { .. }
                                | OpKind::X86MonitorMwait(..)
                                | OpKind::X86WaitPkg(..)
                                | OpKind::X86LoadMxcsr { .. }
                                | OpKind::X86StoreMxcsr { .. }
                                | OpKind::X86Msr(..)
                                | OpKind::X86ReadControl { .. }
                                | OpKind::X86Smsw(..)
                                | OpKind::X86Lmsw(..)
                                | OpKind::X86DescriptorTableStore(..)
                                | OpKind::X86DescriptorTableLoad(..)
                                | OpKind::X86Invlpg(..)
                                | OpKind::X86Invpcid(..)
                                | OpKind::X86SystemSelectorStore(..)
                                | OpKind::X86SystemSelectorLoad(..)
                                | OpKind::X86SelectorVerify(..)
                                | OpKind::X86SelectorQuery(..)
                                | OpKind::X86FarJump(..)
                                | OpKind::X86FarCall(..)
                                | OpKind::X86FarReturn(..)
                                | OpKind::X86Enter(..)
                                | OpKind::X86Leave(..)
                                | OpKind::X86StackFlags(..)
                                | OpKind::X86FastSystemTransfer(..)
                                | OpKind::X86WriteControl { .. }
                                | OpKind::X86ReadDebug { .. }
                                | OpKind::X86WriteDebug { .. }
                        )
                    })
            {
                if jit_bail_log() {
                    eprintln!("[JIT-BAIL] long-mode-system-op @ {entry:#x}");
                }
                continue 'modes;
            }
            // Fail-safe gate over the EXECUTED (non-exit) blocks.
            #[cfg(target_arch = "x86_64")]
            let allow_mem = self.jit_mem;
            #[cfg(target_arch = "x86_64")]
            let uses_vector = {
                if !x86_native_scalar_features_supported_excluding(&func, &exits) {
                    if jit_bail_log() {
                        eprintln!("[JIT-BAIL] host-scalar-features @ {entry:#x} (call={cm})");
                    }
                    continue 'modes;
                }
                let uses_vector = uses_x86_native_vectors_excluding(&func, &exits);
                if uses_vector && !x86_native_vector_features_supported_excluding(&func, &exits) {
                    if jit_bail_log() {
                        eprintln!("[JIT-BAIL] host-vector-features @ {entry:#x} (call={cm})");
                    }
                    continue 'modes;
                }
                if uses_vector && !jit_mxcsr_masks_all_exceptions(self.mxcsr) {
                    if jit_bail_log() {
                        eprintln!("[JIT-BAIL] unmasked-mxcsr @ {entry:#x} (call={cm})");
                    }
                    continue 'modes;
                }
                uses_vector
            };
            #[cfg(target_arch = "x86_64")]
            let avx_ymm16_vector_state =
                uses_vector && x86_native_vector_uses_avx_ymm16_only_excluding(&func, &exits);
            #[cfg(target_arch = "x86_64")]
            let narrow_vector_opmasks = uses_vector
                && !avx_ymm16_vector_state
                && x86_native_vector_uses_k16_opmasks_excluding(&func, &exits);
            #[cfg(target_arch = "x86_64")]
            let uses_xmm_state = uses_x86_xmm_state_excluding(&func, &exits);
            #[cfg(target_arch = "x86_64")]
            let uses_mxcsr_state = uses_x86_mxcsr_state_excluding(&func, &exits);
            #[cfg(target_arch = "x86_64")]
            let uses_mmx = uses_x86_native_mmx_excluding(&func, &exits);
            #[cfg(target_arch = "x86_64")]
            let uses_x87_tag_state = uses_x86_x87_tag_state_excluding(&func, &exits);
            #[cfg(target_arch = "x86_64")]
            let uses_x87_environment_state =
                uses_x86_x87_environment_state_excluding(&func, &exits);
            #[cfg(target_arch = "x86_64")]
            let uses_timestamp = func
                .blocks
                .iter()
                .filter(|block| !exits.contains_key(&block.id))
                .flat_map(|block| &block.ops)
                .any(|op| {
                    matches!(
                        op.kind,
                        OpKind::X86ReadTsc(..) | OpKind::X86ReadPmc(..) | OpKind::X86Msr(..)
                    )
                });
            #[cfg(target_arch = "x86_64")]
            let uses_io = JitRegion::uses_io_excluding(&func, &exits);
            #[cfg(target_arch = "x86_64")]
            let Some(vsib_instructions) =
                JitRegion::collect_vsib_instructions_excluding(&func, &exits)
            else {
                continue 'modes;
            };
            #[cfg(target_arch = "x86_64")]
            if uses_mmx && !x86_native_mmx_features_supported_excluding(&func, &exits) {
                if jit_bail_log() {
                    eprintln!("[JIT-BAIL] host-mmx-features @ {entry:#x} (call={cm})");
                }
                continue 'modes;
            }
            #[cfg(target_arch = "x86_64")]
            if !x86_native_mmx_pairs_valid_excluding(&func, &exits) {
                if jit_bail_log() {
                    eprintln!("[JIT-BAIL] mmx-state-pair @ {entry:#x} (call={cm})");
                }
                continue 'modes;
            }
            #[cfg(target_arch = "x86_64")]
            let uses_mem_helpers = allow_mem
                && func
                    .blocks
                    .iter()
                    .filter(|block| !exits.contains_key(&block.id))
                    .any(|block| {
                        block
                            .ops
                            .iter()
                            .any(|op| x86_jit_op_uses_mem_helper(&op.kind))
                            || matches!(
                                &block.terminator,
                                Terminator::Call { target, .. }
                                    if jit_call_target_uses_mem_helper(target)
                            )
                    });
            #[cfg(target_arch = "x86_64")]
            {
                if !is_native_clobber_safe_excluding(&func, &exits, allow_mem) {
                    if jit_bail_log() {
                        eprintln!(
                            "[JIT-BAIL] gate:{} @ {:#x} (call={cm})",
                            jit_classify_bail(&func, &exits, allow_mem),
                            entry
                        );
                    }
                    continue 'modes;
                }
            }
            #[cfg(target_arch = "aarch64")]
            if !is_x86_aarch64_native_clobber_safe_excluding(&func, &exits) {
                if jit_bail_log() {
                    eprintln!("[JIT-BAIL] x86-aarch64-gate @ {entry:#x}");
                }
                continue 'modes;
            }

            #[cfg(target_arch = "aarch64")]
            let mut lowerer = Aarch64Lowerer::new();
            #[cfg(target_arch = "aarch64")]
            lowerer.set_x86_guest_state_guards(true);
            #[cfg(target_arch = "x86_64")]
            let mut lowerer = X86_64Lowerer::new();
            #[cfg(target_arch = "x86_64")]
            lowerer.set_narrow_vector_opmask_helpers(narrow_vector_opmasks);
            #[cfg(target_arch = "x86_64")]
            lowerer.set_avx_ymm16_vector_state(avx_ymm16_vector_state);
            #[cfg(target_arch = "x86_64")]
            lowerer.set_native_vector_state_active(uses_vector);
            #[cfg(target_arch = "x86_64")]
            lowerer.set_guest_pcrel_lea_immediates(true);
            #[cfg(target_arch = "x86_64")]
            lowerer.set_jit_fault_deopt_guards(true);
            #[cfg(target_arch = "x86_64")]
            lowerer.set_preserve_mmx_helpers(uses_mmx);
            #[cfg(target_arch = "x86_64")]
            lowerer.set_preserve_vector_system_helpers(uses_vector);
            lowerer.set_native_exits(exits);
            lowerer.set_native_exit_edges(edge_exits);
            #[cfg(target_arch = "x86_64")]
            if allow_mem {
                lowerer.set_mem_helpers(true);
                lowerer.set_preserve_vector_mem_helpers(uses_vector && uses_mem_helpers);
            }
            #[cfg(target_arch = "x86_64")]
            if cm {
                // Lower CALL terminators as runtime call-outs (rax_jit_call).
                lowerer.set_call_helpers(true);
                lowerer.set_preserve_vector_call_helpers(uses_vector);
            }
            let res = match lowerer.lower_function(&func) {
                Ok(r) if r.relocations.is_empty() => r,
                Ok(r) => {
                    if jit_bail_log() {
                        eprintln!(
                            "[JIT-BAIL] relocs:{} @ {:#x} (call={cm})",
                            r.relocations.len(),
                            entry
                        );
                    }
                    continue 'modes;
                }
                Err(e) => {
                    if jit_bail_log() {
                        eprintln!("[JIT-BAIL] lower-err:{e:?} @ {entry:#x} (call={cm})");
                    }
                    continue 'modes;
                }
            };
            let code = match lowerer.finalize() {
                Ok(c) => c,
                Err(_) => continue 'modes,
            };
            let exec = match ExecMem::new(&code) {
                Ok(m) => m,
                Err(_) => continue 'modes,
            };
            return Ok(Some(JitRegion {
                exec,
                entry_offset: res.entry_offset,
                source_pages,
                #[cfg(target_arch = "x86_64")]
                vsib_instructions,
                #[cfg(target_arch = "x86_64")]
                uses_vector,
                #[cfg(target_arch = "x86_64")]
                uses_xmm_state,
                #[cfg(target_arch = "x86_64")]
                uses_mxcsr_state,
                #[cfg(target_arch = "x86_64")]
                avx_ymm16_vector_state,
                #[cfg(target_arch = "x86_64")]
                narrow_vector_opmasks,
                #[cfg(target_arch = "x86_64")]
                uses_mmx,
                #[cfg(target_arch = "x86_64")]
                uses_x87_tag_state,
                #[cfg(target_arch = "x86_64")]
                uses_x87_environment_state,
                #[cfg(target_arch = "x86_64")]
                uses_timestamp,
                #[cfg(target_arch = "x86_64")]
                uses_io,
                #[cfg(target_arch = "x86_64")]
                yielded_backward_exit_pcs,
                #[cfg(target_arch = "x86_64")]
                callout_boundaries,
            }));
        }
        Ok(None)
    }

    /// Execute a (possibly cached) compiled region with the current guest state,
    /// then resume at the recorded exit PC. Marshals guest GPRs+flags and, when
    /// required, the complete vector/opmask state into the native file, runs,
    /// and bridges the result back. The trampoline never loads guest RSP into
    /// hardware RSP; admitted RSP updates occur through `GuestRegs`.
    pub(super) fn jit_run_region(&mut self, region: &JitRegion) {
        // Self-verifying mode (RAX_JIT_VERIFY=1): run the region natively, then
        // re-run the INTERPRETER from the identical entry state up to the JIT's
        // exit PC and diff the architectural state. On the first divergence,
        // dump the region (entry/exit PC, code bytes, lifted+optimized ops, and
        // the diverging registers) and abort — this pinpoints a miscompiled hot
        // region on a live boot. Register-only regions touch no guest memory,
        // so re-executing the interpreter from the snapshot is side-effect-free.
        #[cfg(target_arch = "x86_64")]
        {
            use std::sync::OnceLock;
            static VERIFY: OnceLock<bool> = OnceLock::new();
            if *VERIFY.get_or_init(|| std::env::var_os("RAX_JIT_VERIFY").is_some()) {
                self.jit_run_region_verified(region);
                return;
            }
        }
        self.jit_run_region_native(region);
    }

    /// Native-only execution of a compiled region (the production path).
    #[cfg(target_arch = "x86_64")]
    pub(super) fn jit_run_region_native(&mut self, region: &JitRegion) -> (u64, u64) {
        use crate::smir::lower::runtime::GuestRegs;

        self.jit_vsib_resume_pc = None;
        self.jit_enter_region(region);

        // Crash diagnostic (RAX_JIT_TRACE=1): record the region entry about to run
        // natively and install a SIGSEGV/SIGBUS/SIGILL handler that prints it + the
        // faulting address. Lets a host crash IN native JIT code be traced to the
        // exact guest region. Opt-in, so default runs are untouched.
        #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
        {
            use std::sync::OnceLock;
            use std::sync::atomic::Ordering;
            static TRACE: OnceLock<bool> = OnceLock::new();
            if *TRACE.get_or_init(|| std::env::var_os("RAX_JIT_TRACE").is_some()) {
                jit_install_crash_handler();
                JIT_LAST_ENTRY.store(self.regs.rip, Ordering::Relaxed);
                let (host_base, host_len) = region.exec.mapping_bounds();
                JIT_LAST_HOST_BASE.store(host_base as u64, Ordering::Relaxed);
                JIT_LAST_HOST_LEN.store(host_len as u64, Ordering::Relaxed);
                static DUMP_AT: OnceLock<Option<u64>> = OnceLock::new();
                let dump_at = *DUMP_AT.get_or_init(|| {
                    std::env::var("RAX_JIT_DUMP")
                        .ok()
                        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                });
                if dump_at == Some(self.regs.rip) {
                    static DONE: OnceLock<()> = OnceLock::new();
                    if DONE.set(()).is_ok() {
                        let rip = self.regs.rip;
                        eprintln!("[JIT-DUMP] region {rip:#x}:\n{}", self.jit_dump_region(rip));
                    }
                }
            }
        }

        // The interpreter keeps RFLAGS LAZY: `self.regs.rflags` is stale while a
        // lazy op is pending (the truth lives in `self.lazy_flags`). Materialize
        // it first so the value bridged into the native region is the real
        // architectural RFLAGS (the region's entry may read CF/etc., and the
        // trampoline `popfq`s `gr.rflags`).
        self.materialize_flags();
        // Guest RFLAGS before the region — every bit except the six status flags
        // and DF must be preserved across the native region: admitted operations
        // can change only those fields, and the trampoline's
        // user-mode `popfq`/`pushfq` does NOT round-trip IF/IOPL/etc. (`pushfq`
        // returns the HOST's IF=1), so taking those bits from the native result
        // would spuriously ENABLE guest interrupts mid-boot and crash the kernel.
        let pre_rflags = self.regs.rflags;

        let mut gr = GuestRegs::default();
        // Memory-helper channel: the vcpu pointer + helper addresses, used only
        // by regions lowered with the MMU helper-call path (RAX_JIT_MEM).
        gr.ctx = self as *mut X86_64Vcpu as u64;
        gr.load_fn = rax_jit_mem_load as usize as u64;
        gr.store_fn = rax_jit_mem_store as usize as u64;
        gr.vec_load_fn = rax_jit_vec_load as usize as u64;
        gr.vec_store_fn = rax_jit_vec_store as usize as u64;
        gr.pair_load_fn = rax_jit_pair_load as usize as u64;
        gr.pair_store_fn = rax_jit_pair_store as usize as u64;
        gr.cmpccxadd_fn = rax_jit_cmpccxadd as usize as u64;
        gr.io_fn = rax_jit_io as usize as u64;
        gr.enter_fn = rax_jit_enter as usize as u64;
        gr.stack_flags_fn = rax_jit_stack_flags as usize as u64;
        // Lift-through-calls channel (RAX_JIT_CALL): a guest CALL in the region
        // calls out here to run its callee in the interpreter, then resumes.
        gr.call_fn = rax_jit_call as usize as u64;
        // Deterministic guest CPUID evaluator. The lowered block separately
        // executes a fixed host CPUID only as a serialization barrier.
        gr.cpuid_fn = rax_jit_cpuid as usize as u64;
        // Guest-clock evaluator used by RDTSC/RDTSCP. Native code must not
        // expose the host TSC or its frequency/offset domain.
        gr.tsc_fn = rax_jit_tsc as usize as u64;
        // Canonical MOV-to-control-register validator/commit helper. Successful
        // writes end the region immediately after this call.
        gr.control_write_fn = rax_jit_write_control as usize as u64;
        gr.msr_fn = rax_jit_msr as usize as u64;
        gr.pmc_fn = rax_jit_pmc as usize as u64;
        gr.descriptor_store_fn = rax_jit_descriptor_table_store as usize as u64;
        gr.descriptor_load_fn = rax_jit_descriptor_table_load as usize as u64;
        gr.system_selector_fn = rax_jit_system_selector as usize as u64;
        gr.system_selector_load_fn = rax_jit_system_selector_load as usize as u64;
        gr.far_jump_fn = rax_jit_far_jump as usize as u64;
        gr.far_call_fn = rax_jit_far_call as usize as u64;
        gr.far_return_fn = rax_jit_far_return as usize as u64;
        gr.fast_system_transfer_fn = rax_jit_fast_system_transfer as usize as u64;
        gr.cli_fn = rax_jit_cli as usize as u64;
        gr.sti_fn = rax_jit_sti as usize as u64;
        gr.invlpg_fn = rax_jit_invlpg as usize as u64;
        gr.invpcid_fn = rax_jit_invpcid as usize as u64;
        // Segment bases for `fs:`/`gs:`-overridden operands (Address::SegmentRel).
        gr.fs_base = self.sregs.fs.base;
        gr.gs_base = self.sregs.gs.base;
        gr.kernel_gs_base = self.kernel_gs_base;
        gr.tsc_adjust = self.tsc_adjust;
        gr.tsc_aux = self.tsc_aux;
        gr.misc_enable = self.misc_enable;
        gr.pat = self.pat;
        gr.umwait_control = self.umwait_control;
        gr.star = self.sregs.star;
        gr.lstar = self.sregs.lstar;
        gr.cstar = self.sregs.cstar;
        gr.fmask = self.sregs.fmask;
        gr.sysenter_cs = self.sregs.sysenter_cs;
        gr.sysenter_esp = self.sregs.sysenter_esp;
        gr.sysenter_eip = self.sregs.sysenter_eip;
        gr.pkru = self.pkru;
        gr.xcr0 = self.xcr0;
        gr.xgetbv1 = self.xgetbv1_value;
        gr.cr4 = self.sregs.cr4;
        gr.cr0 = self.sregs.cr0;
        gr.cr2 = self.sregs.cr2;
        gr.cr3 = self.sregs.cr3;
        gr.cr8 = self.sregs.cr8;
        gr.dr0 = self.sregs.dr0;
        gr.dr1 = self.sregs.dr1;
        gr.dr2 = self.sregs.dr2;
        gr.dr3 = self.sregs.dr3;
        gr.dr6 = self.sregs.dr6;
        gr.dr7 = self.sregs.dr7;
        gr.efer = self.sregs.efer;
        gr.cs_l = u64::from(self.sregs.cs.l);
        gr.tr_type = u64::from(self.sregs.tr.type_ & 0x0F);
        gr.cpl = if self.regs.rflags & flags::bits::VM != 0 {
            3
        } else {
            u64::from(self.sregs.cs.selector & 3)
        };
        gr.apx_enabled = u64::from(self.apx_enabled());
        gr.cpuid_xeon_phi_avx512 = u64::from(self.xeon_phi_avx512_enabled());
        gr.cpuid_vp2intersect = u64::from(self.vp2intersect_enabled());
        gr.cpuid_sse4a = u64::from(self.sse4a_enabled());
        gr.cpuid_tbm = u64::from(self.tbm_enabled());
        gr.cpuid_xop = u64::from(self.xop_enabled());
        gr.gpr[0] = self.regs.rax;
        gr.gpr[1] = self.regs.rcx;
        gr.gpr[2] = self.regs.rdx;
        gr.gpr[3] = self.regs.rbx;
        gr.gpr[4] = self.regs.rsp;
        gr.gpr[5] = self.regs.rbp;
        gr.gpr[6] = self.regs.rsi;
        gr.gpr[7] = self.regs.rdi;
        gr.gpr[8] = self.regs.r8;
        gr.gpr[9] = self.regs.r9;
        gr.gpr[10] = self.regs.r10;
        gr.gpr[11] = self.regs.r11;
        gr.gpr[12] = self.regs.r12;
        gr.gpr[13] = self.regs.r13;
        gr.gpr[14] = self.regs.r14;
        gr.gpr[15] = self.regs.r15;
        gr.gpr[16] = self.regs.r16;
        gr.gpr[17] = self.regs.r17;
        gr.gpr[18] = self.regs.r18;
        gr.gpr[19] = self.regs.r19;
        gr.gpr[20] = self.regs.r20;
        gr.gpr[21] = self.regs.r21;
        gr.gpr[22] = self.regs.r22;
        gr.gpr[23] = self.regs.r23;
        gr.gpr[24] = self.regs.r24;
        gr.gpr[25] = self.regs.r25;
        gr.gpr[26] = self.regs.r26;
        gr.gpr[27] = self.regs.r27;
        gr.gpr[28] = self.regs.r28;
        gr.gpr[29] = self.regs.r29;
        gr.gpr[30] = self.regs.r30;
        gr.gpr[31] = self.regs.r31;
        gr.rflags = self.regs.rflags & !flags::bits::AC;
        gr.ac_flag = u64::from(self.regs.rflags & flags::bits::AC != 0);
        gr.interrupt_flags = self.regs.rflags
            & crate::isa::x86_64::execute::system::X86_INTERRUPT_CONTROL_RFLAGS_MASK;
        gr.interrupt_inhibit = u64::from(self.interrupt_inhibit);
        gr.exit_pc = self.regs.rip; // fallback (an exit stub overwrites this)
        if region.uses_vector || region.uses_xmm_state {
            for index in 0..16 {
                gr.set_zmm(
                    index,
                    [
                        self.regs.xmm[index][0],
                        self.regs.xmm[index][1],
                        self.regs.ymm_high[index][0],
                        self.regs.ymm_high[index][1],
                        self.regs.zmm_high[index][0],
                        self.regs.zmm_high[index][1],
                        self.regs.zmm_high[index][2],
                        self.regs.zmm_high[index][3],
                    ],
                );
                gr.set_zmm(index + 16, self.regs.zmm_ext[index]);
            }
        }
        if region.uses_vector {
            gr.k = self.regs.k;
            gr.vector_active = if region.avx_ymm16_vector_state {
                crate::smir::lower::runtime::X86_VECTOR_STATE_YMM16
            } else if region.narrow_vector_opmasks {
                crate::smir::lower::runtime::X86_VECTOR_STATE_K16
            } else {
                crate::smir::lower::runtime::X86_VECTOR_STATE_K64
            };
        }
        if region.uses_vector || region.uses_mxcsr_state {
            gr.mxcsr = self.mxcsr;
        }
        gr.xmm_state_active = u64::from(region.uses_xmm_state);
        gr.mxcsr_state_active = u64::from(region.uses_mxcsr_state);
        if region.uses_mmx {
            gr.mm = self.regs.mm;
            gr.mmx_active = 1;
        }
        if region.uses_x87_tag_state || region.uses_x87_environment_state {
            self.marshal_x87_to_jit_entry(&mut gr);
        }

        region.exec.run(region.entry_offset, &mut gr);

        // Lift-through-calls: if a call-out bailed (a callee yielded a VMM-bound
        // exit or errored), the helper already synced the vcpu's full
        // architectural state — RIP = exit_pc, complete RFLAGS, all GPRs. Do NOT
        // re-marshal `gr` here: the status-only flag merge below would drop the
        // callee's IF/DF changes. Leave the vcpu exactly as the helper left it
        // (the run loop reads `jit_callout_exit` and returns the stashed exit).
        #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
        if self.jit_callout_exit.is_some() {
            self.lazy_flags = LazyFlags {
                op: LazyFlagOp::None,
                ..Default::default()
            };
            return (0, 0);
        }

        // Stateful control instructions and interpreter callouts commit through
        // the marshalled ABI before returning at a precise next-instruction PC.
        self.xcr0 = gr.xcr0;
        self.pkru = gr.pkru;
        self.tsc_adjust = gr.tsc_adjust;
        self.tsc_aux = gr.tsc_aux;
        self.misc_enable = gr.misc_enable;
        self.pat = gr.pat;
        self.umwait_control = gr.umwait_control;
        self.sregs.cr0 = gr.cr0;
        self.sregs.cr2 = gr.cr2;
        self.sregs.cr3 = gr.cr3;
        self.sregs.cr4 = gr.cr4;
        self.sregs.cr8 = gr.cr8;
        self.sregs.dr0 = gr.dr0;
        self.sregs.dr1 = gr.dr1;
        self.sregs.dr2 = gr.dr2;
        self.sregs.dr3 = gr.dr3;
        self.sregs.dr6 = gr.dr6;
        self.sregs.dr7 = gr.dr7;
        self.sregs.efer = gr.efer;
        self.sregs.star = gr.star;
        self.sregs.lstar = gr.lstar;
        self.sregs.cstar = gr.cstar;
        self.sregs.fmask = gr.fmask;
        self.sregs.sysenter_cs = gr.sysenter_cs;
        self.sregs.sysenter_esp = gr.sysenter_esp;
        self.sregs.sysenter_eip = gr.sysenter_eip;
        self.sregs.fs.base = gr.fs_base;
        self.sregs.gs.base = gr.gs_base;
        self.kernel_gs_base = gr.kernel_gs_base;

        self.regs.rax = gr.gpr[0];
        self.regs.rcx = gr.gpr[1];
        self.regs.rdx = gr.gpr[2];
        self.regs.rbx = gr.gpr[3];
        self.regs.rsp = gr.gpr[4];
        self.regs.rbp = gr.gpr[5];
        self.regs.rsi = gr.gpr[6];
        self.regs.rdi = gr.gpr[7];
        self.regs.r8 = gr.gpr[8];
        self.regs.r9 = gr.gpr[9];
        self.regs.r10 = gr.gpr[10];
        self.regs.r11 = gr.gpr[11];
        self.regs.r12 = gr.gpr[12];
        self.regs.r13 = gr.gpr[13];
        self.regs.r14 = gr.gpr[14];
        self.regs.r15 = gr.gpr[15];
        self.regs.r16 = gr.gpr[16];
        self.regs.r17 = gr.gpr[17];
        self.regs.r18 = gr.gpr[18];
        self.regs.r19 = gr.gpr[19];
        self.regs.r20 = gr.gpr[20];
        self.regs.r21 = gr.gpr[21];
        self.regs.r22 = gr.gpr[22];
        self.regs.r23 = gr.gpr[23];
        self.regs.r24 = gr.gpr[24];
        self.regs.r25 = gr.gpr[25];
        self.regs.r26 = gr.gpr[26];
        self.regs.r27 = gr.gpr[27];
        self.regs.r28 = gr.gpr[28];
        self.regs.r29 = gr.gpr[29];
        self.regs.r30 = gr.gpr[30];
        self.regs.r31 = gr.gpr[31];
        if region.uses_vector || region.uses_xmm_state {
            for index in 0..16 {
                let low = gr.get_zmm(index);
                self.regs.xmm[index] = [low[0], low[1]];
                self.regs.ymm_high[index] = [low[2], low[3]];
                self.regs.zmm_high[index] = [low[4], low[5], low[6], low[7]];
                self.regs.zmm_ext[index] = gr.get_zmm(index + 16);
            }
            if region.uses_vector {
                self.regs.k = gr.k;
            }
        }
        if region.uses_vector || region.uses_mxcsr_state {
            self.mxcsr = gr.mxcsr;
        }
        if region.uses_mmx {
            self.regs.mm = gr.mm;
        }
        if region.uses_x87_tag_state || region.uses_x87_environment_state {
            self.marshal_x87_from_jit_exit(&gr);
        }
        // Merge status flags and DF from the host-safe native image, AC and
        // virtualized interrupt controls from their dedicated shadows, and
        // preserve every other architectural bit from the pre-region value.
        self.regs.rflags = if gr.stack_flags_rflags_valid == 1 {
            gr.stack_flags_rflags
        } else {
            merge_native_rflags(pre_rflags, gr.rflags, gr.ac_flag != 0, gr.interrupt_flags)
        };
        self.interrupt_inhibit = gr.interrupt_inhibit != 0;
        self.regs.rip = gr.exit_pc;
        let vsib_guard_deferred = region
            .vsib_instructions
            .binary_search_by_key(&gr.exit_pc, |&(pc, _)| pc)
            .ok()
            .and_then(|index| {
                region.vsib_instructions[index]
                    .1
                    .evex_vsib_memory_encoding()
            })
            .is_some_and(|encoding| gr.cs_l == 0 || (encoding.requires_apx && gr.apx_enabled == 0));
        self.jit_vsib_resume_pc =
            (gr.x86_vsib_frontier_lane_plus_one != 0 || vsib_guard_deferred).then_some(gr.exit_pc);
        // The native region produced fully-materialized RFLAGS. Mark the lazy
        // state as materialized so the interpreter, on resume, reads
        // `self.regs.rflags` (the JIT result) instead of recomputing from a
        // STALE lazy op left over from before the region — the desync that
        // corrupted kernel state across the JIT/interp boundary.
        self.lazy_flags = LazyFlags {
            op: LazyFlagOp::None,
            ..Default::default()
        };
        self.jit_leave_region();
        self.complete_jit_io_request(&mut gr);
        (
            gr.x86_vsib_frontier_lane_plus_one,
            gr.x86_vsib_instruction_ordinal,
        )
    }

    /// Execute x86-lifted scalar SMIR as AArch64 identity-mapped code. Legacy
    /// x86 GPR encodings map one-to-one onto X0-X15; the AArch64 trampoline keeps
    /// its state pointer/link/stack in X28/X30/SP, outside that guest set.
    #[cfg(target_arch = "aarch64")]
    pub(super) fn jit_run_region_native(&mut self, region: &JitRegion) {
        use crate::smir::lower::runtime::{
            Aarch64GuestRegs, merge_aarch64_nzcv_into_x86_rflags, x86_rflags_to_aarch64_nzcv,
        };

        self.jit_enter_region(region);

        // The interpreter defers flag computation. Materialize before exporting
        // CF/ZF/SF/OF into NZCV and retain the complete snapshot so PF/AF and all
        // control/reserved bits survive the four-flag bridge exactly.
        self.materialize_flags();
        let pre_rflags = self.regs.rflags;

        let mut state = Aarch64GuestRegs {
            pc: self.regs.rip,
            nzcv: x86_rflags_to_aarch64_nzcv(pre_rflags),
            x86_apx_enabled: u64::from(self.apx_enabled()),
            x86_tbm_enabled: u64::from(self.tbm_enabled()),
            x86_tbm_mode_valid: u64::from(
                self.sregs.cr0 & 1 != 0
                    && self.sregs.cs.l
                    && self.regs.rflags & flags::bits::VM == 0,
            ),
            ..Default::default()
        };
        for index in 0_u8..16 {
            state.x[usize::from(index)] = self.get_reg(index, 8);
        }

        region
            .exec
            .run_aarch64_identity(region.entry_offset, &mut state);

        for index in 0_u8..16 {
            self.set_reg(index, state.x[usize::from(index)], 8);
        }
        self.regs.rflags = merge_aarch64_nzcv_into_x86_rflags(pre_rflags, state.nzcv);
        self.regs.rip = state.pc;
        self.lazy_flags = LazyFlags {
            op: LazyFlagOp::None,
            ..Default::default()
        };
        self.jit_leave_region();
    }

    /// Re-lift + optimize the region at `entry` and pretty-print its blocks/ops
    /// for the verify-mode divergence dump.
    pub fn jit_dump_region(&mut self, entry: u64) -> String {
        use crate::smir::ir::memory::MemoryError;
        use crate::smir::ir::types::SourceArch;
        use crate::smir::lift::x86_64::X86_64Lifter;
        use crate::smir::lift::{LiftContext, MemoryReader, SmirLifter};
        use crate::smir::optimize::{OptLevel, optimize_function};

        let bytes = match self.jit_read_lift_window(entry, JIT_LIFT_WINDOW) {
            Some(bytes) => bytes,
            None => return "<unreadable>".to_string(),
        };
        struct Win {
            base: u64,
            bytes: Vec<u8>,
        }
        impl MemoryReader for Win {
            fn read(&self, addr: u64, size: usize) -> core::result::Result<Vec<u8>, MemoryError> {
                let off = addr
                    .checked_sub(self.base)
                    .filter(|&o| (o as usize) < self.bytes.len())
                    .ok_or(MemoryError::OutOfBounds { addr })? as usize;
                let n = (self.bytes.len() - off).min(size);
                Ok(self.bytes[off..off + n].to_vec())
            }
        }
        let reader = Win { base: entry, bytes };
        let mut lifter = X86_64Lifter::strict();
        lifter.set_interpreter_frontiers(true);
        let mut lctx = LiftContext::new(SourceArch::X86_64);
        let mut func = match lifter.lift_function(entry, &reader, &mut lctx) {
            Ok(f) => f,
            Err(e) => return format!("<lift error: {e:?}>"),
        };
        optimize_function(&mut func, OptLevel::O2);
        let mut s = String::new();
        for b in &func.blocks {
            s.push_str(&format!("  block {:?} @ {:#x}:\n", b.id, b.guest_pc));
            for op in &b.ops {
                s.push_str(&format!("    {:#x}: {:?}\n", op.guest_pc, op.kind));
            }
            s.push_str(&format!("    term: {:?}\n", b.terminator));
        }
        s
    }

    /// Loop-head hotness sampling: called after an interpreted instruction. If
    /// the instruction was a BACKWARD branch (rip decreased) — i.e. a loop
    /// back-edge to `rip` — bump that head's counter and, once hot, compile +
    /// cache the region (and run it immediately). Auto-promoted regions lower
    /// internal backward edges as exits, so native execution returns to the run
    /// loop before another loop iteration. RIP now equals the head, so the JIT
    /// compiles exactly there. Ineligible heads are cached as `None` so they are
    /// never retried.
    fn jit_sample_backedge(&mut self, rip_before: u64) {
        if self.interrupt_inhibit || self.jit_disabled_for_debugger() {
            return;
        }

        // Diagnostic kill-switch: RAX_NO_JIT disables hot-region promotion so the
        // interpreter handles everything (isolates JIT-codegen bugs from the
        // sampling/SMC infrastructure). Cached once — back-edges are hot.
        {
            use std::sync::OnceLock;
            static OFF: OnceLock<bool> = OnceLock::new();
            if *OFF.get_or_init(|| std::env::var_os("RAX_NO_JIT").is_some()) {
                return;
            }
        }
        let head = self.regs.rip;
        if head >= rip_before {
            return; // forward/fallthrough — not a loop back-edge
        }
        let mt = self.jit_mode_tag();
        if self.jit_cache.contains_key(&(head, mt)) {
            return; // already promoted (runnable) this session
        }
        // Known-ineligible memo (survives SMC). Skip the futile re-lift unless the
        // head's actual code bytes changed — a self-modifying-code write to a
        // page that merely shares a frame with this head must not re-promote it.
        let memo_on = {
            use std::sync::OnceLock;
            static ON: OnceLock<bool> = OnceLock::new();
            *ON.get_or_init(|| std::env::var_os("RAX_JIT_NOMEMO").is_none())
        };
        if memo_on {
            if self.jit_ineligible_unchanged((head, mt)) {
                return;
            }
        }
        let hot = {
            let c = self.jit_hot.entry(head).or_insert(0);
            *c = c.saturating_add(1);
            *c
        };
        if hot < JIT_HOT_THRESHOLD {
            return;
        }
        self.jit_hot.remove(&head);
        let region = self
            .jit_compile_region_with_edge_exits(true)
            .ok()
            .flatten()
            .map(std::sync::Arc::new);
        if std::env::var_os("RAX_JIT_LOG").is_some() {
            eprintln!(
                "[JIT] promote @ {head:#x} -> {}",
                if region.is_some() {
                    "compiled"
                } else {
                    "ineligible"
                }
            );
        }
        match &region {
            Some(r) => {
                let r = r.clone();
                self.jit_cache.insert((head, mt), region);
                self.jit_run_region(&r);
            }
            None => {
                if memo_on {
                    // Soft-cap the table so a long-running guest cannot grow it
                    // without bound (cleared wholesale; snapshots rebuild on
                    // demand). `RAX_JIT_NOMEMO` bypasses both lookup and storage.
                    if self.jit_ineligible.len() >= JIT_INELIGIBLE_CAP {
                        self.jit_ineligible.clear();
                        self.jit_ineligible_dirty.clear();
                    }
                    let key = (head, mt);
                    let snapshot = self.jit_code_snapshot(head);
                    self.jit_ineligible.insert(key, snapshot);
                    self.jit_ineligible_dirty.remove(&key);
                }
            }
        }
    }

    /// Return whether an existing ineligible memo still applies. A clean key has
    /// observed no overlapping code-page write and returns without touching the
    /// MMU. A dirty key compares the exact lift-window snapshot once, eliminating
    /// both the former 16-byte blind suffix and hash-collision false matches.
    fn jit_ineligible_unchanged(&mut self, key: (u64, u64)) -> bool {
        if !self.jit_ineligible.contains_key(&key) {
            self.jit_ineligible_dirty.remove(&key);
            return false;
        }
        if !self.jit_ineligible_dirty.remove(&key) {
            return true;
        }

        let current = self.jit_code_snapshot(key.0);
        if self
            .jit_ineligible
            .get(&key)
            .is_some_and(|saved| saved == &current)
        {
            return true;
        }

        self.jit_ineligible.remove(&key);
        false
    }

    /// Snapshot the exact largest readable prefix used for JIT lifting. An empty
    /// vector is the stable representation of an unreadable entry address.
    fn jit_code_snapshot(&mut self, head: u64) -> Vec<u8> {
        self.jit_read_lift_window(head, JIT_LIFT_WINDOW)
            .unwrap_or_default()
    }

    /// Number of distinct regions the JIT has compiled (cache entries that
    /// produced runnable native code). For tests / diagnostics.
    pub fn jit_region_count(&self) -> usize {
        self.jit_cache.values().filter(|v| v.is_some()).count()
    }

    /// Enable/disable JIT of memory-touching regions (Load/Store via MMU helper
    /// calls). For tests; production defaults on unless `RAX_JIT_NO_MEM` is set.
    #[cfg(target_arch = "x86_64")]
    pub fn set_jit_mem(&mut self, on: bool) {
        self.jit_mem = on;
    }

    /// Enable lift-through-calls for tests. Callouts require the MMU helper path
    /// for the guest return-address push, so enabling calls also enables memory
    /// helpers.
    #[cfg(target_arch = "x86_64")]
    pub fn set_jit_call(&mut self, on: bool) {
        self.jit_call = on;
        if on {
            self.jit_mem = true;
        }
    }
}

#[cfg(test)]
mod stack_segment_tests {
    use super::*;
    use std::sync::Arc;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    const EFER_LMA: u64 = 1 << 10;

    fn test_vcpu() -> X86_64Vcpu {
        let mem =
            Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
        X86_64Vcpu::new(0, mem)
    }

    fn enable_long_mode(vcpu: &mut X86_64Vcpu) {
        vcpu.sregs.efer = EFER_LMA;
        vcpu.sregs.cs.l = true;
    }

    #[test]
    fn long_mode_stack_helpers_ignore_ss_base() {
        let mut vcpu = test_vcpu();
        enable_long_mode(&mut vcpu);
        vcpu.sregs.ss.base = 0x1000;

        vcpu.regs.rsp = 0x2000;
        vcpu.push64(0x1122_3344_5566_7788).unwrap();
        assert_eq!(vcpu.regs.rsp, 0x1ff8);
        assert_eq!(
            vcpu.mmu.read_u64(0x1ff8, &vcpu.sregs).unwrap(),
            0x1122_3344_5566_7788
        );
        assert_eq!(vcpu.mmu.read_u64(0x2ff8, &vcpu.sregs).unwrap(), 0);
        vcpu.mmu
            .write_u64(0x2ff8, 0x8877_6655_4433_2211, &vcpu.sregs)
            .unwrap();
        assert_eq!(vcpu.pop64().unwrap(), 0x1122_3344_5566_7788);
        assert_eq!(vcpu.regs.rsp, 0x2000);

        vcpu.regs.rsp = 0x2100;
        vcpu.push32(0xaabb_ccdd).unwrap();
        assert_eq!(vcpu.regs.rsp, 0x20fc);
        assert_eq!(vcpu.mmu.read_u32(0x20fc, &vcpu.sregs).unwrap(), 0xaabb_ccdd);
        assert_eq!(vcpu.mmu.read_u32(0x30fc, &vcpu.sregs).unwrap(), 0);
        vcpu.mmu
            .write_u32(0x30fc, 0xddcc_bbaa, &vcpu.sregs)
            .unwrap();
        assert_eq!(vcpu.pop32().unwrap(), 0xaabb_ccdd);
        assert_eq!(vcpu.regs.rsp, 0x2100);

        vcpu.regs.rsp = 0x2200;
        vcpu.push16(0xeeff).unwrap();
        assert_eq!(vcpu.regs.rsp, 0x21fe);
        assert_eq!(vcpu.mmu.read_u16(0x21fe, &vcpu.sregs).unwrap(), 0xeeff);
        assert_eq!(vcpu.mmu.read_u16(0x31fe, &vcpu.sregs).unwrap(), 0);
        vcpu.mmu.write_u16(0x31fe, 0xffee, &vcpu.sregs).unwrap();
        assert_eq!(vcpu.pop16().unwrap(), 0xeeff);
        assert_eq!(vcpu.regs.rsp, 0x2200);
    }

    #[test]
    fn non_long_mode_stack_helpers_use_ss_base() {
        let mut vcpu = test_vcpu();
        vcpu.sregs.ss.base = 0x1000;

        vcpu.regs.rsp = 0x2000;
        vcpu.push64(0x0102_0304_0506_0708).unwrap();

        assert_eq!(vcpu.regs.rsp, 0x1ff8);
        assert_eq!(vcpu.mmu.read_u64(0x1ff8, &vcpu.sregs).unwrap(), 0);
        assert_eq!(
            vcpu.mmu.read_u64(0x2ff8, &vcpu.sregs).unwrap(),
            0x0102_0304_0506_0708
        );
    }
}

#[cfg(test)]
mod decode_cache_invalidation_tests {
    use super::*;
    use std::sync::Arc;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    fn test_vcpu_with_mem() -> (X86_64Vcpu, Arc<GuestMemoryMmap>) {
        let mem =
            Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
        (X86_64Vcpu::new(0, mem.clone()), mem)
    }

    fn test_vcpu() -> X86_64Vcpu {
        test_vcpu_with_mem().0
    }

    // Regression for issue #77: the decode-cache validity sentinel is bytes_len
    // (a real-mode instruction may legitimately be cached at RIP 0), but the
    // self-modifying-code / breakpoint invalidation paths used to require
    // entry.rip != 0 — so a cached decode for RIP 0 was never cleared when its
    // page was written, letting stale bytes keep executing at offset 0.
    #[test]
    fn invalidate_code_page_clears_rip0_entry() {
        let mut vcpu = test_vcpu();

        // Seed a valid (bytes_len != 0) cached decode for RIP 0 on page 0.
        let idx = X86_64Vcpu::decode_cache_index(0);
        vcpu.decode_cache[idx].rip = 0;
        vcpu.decode_cache[idx].bytes_len = 4;
        vcpu.decode_cache[idx].mode_tag = 0;

        // Also seed a valid entry on a different page AND a different cache index
        // (0x2000 & 0xFFF == 0 would collide with index 0) that must survive a
        // page-0 invalidation.
        let other_idx = X86_64Vcpu::decode_cache_index(0x5100);
        assert_ne!(
            other_idx, idx,
            "test addresses must use distinct cache indices"
        );
        vcpu.decode_cache[other_idx].rip = 0x5100;
        vcpu.decode_cache[other_idx].bytes_len = 4;
        vcpu.decode_cache[other_idx].mode_tag = 0;

        // A write anywhere on page 0 must invalidate the RIP-0 entry.
        vcpu.invalidate_code_page(0);

        assert_eq!(
            vcpu.decode_cache[idx].bytes_len, 0,
            "a cached decode for RIP 0 must be invalidated when its page is written",
        );
        assert_eq!(
            vcpu.decode_cache[other_idx].bytes_len, 4,
            "an entry on a different page must survive a page-0 invalidation",
        );
    }

    #[test]
    fn decode_cache_hit_refetches_current_guest_bytes() {
        let (mut vcpu, mem) = test_vcpu_with_mem();
        vcpu.sregs.efer = 1 << 10;
        vcpu.sregs.cs.l = true;

        // MOV EAX,1. This fills the decode cache for RIP 0.
        mem.write_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00], GuestAddress(0))
            .unwrap();
        assert!(vcpu.step().unwrap().is_none());
        assert_eq!(vcpu.regs.rax, 1);
        assert_ne!(
            vcpu.decode_cache[X86_64Vcpu::decode_cache_index(0)].bytes_len,
            0,
            "first execution should fill the RIP 0 decode-cache entry",
        );

        // Rewrite guest RAM directly, bypassing MMU write journaling. A key-only
        // cache hit would keep executing the stale immediate from cached bytes.
        mem.write_slice(&[0xB8, 0x02, 0x00, 0x00, 0x00], GuestAddress(0))
            .unwrap();
        vcpu.regs.rip = 0;
        vcpu.regs.rax = 0;

        assert!(vcpu.step().unwrap().is_none());
        assert_eq!(
            vcpu.regs.rax, 2,
            "decode-cache hit must validate against the current fetched bytes",
        );
    }

    #[cfg(all(
        feature = "smir-jit",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn ineligible_jit_memo_tracks_exact_lift_window_after_smc() {
        let (mut vcpu, mem) = test_vcpu_with_mem();
        let head = 0x2000;
        let key = (head, vcpu.jit_mode_tag());
        let original = vcpu.jit_code_snapshot(head);
        assert_eq!(original.len(), JIT_LIFT_WINDOW);
        vcpu.jit_ineligible.insert(key, original);

        // Clean memos are O(1): without an SMC invalidation, even a direct test
        // mutation beyond the former 16-byte fingerprint is not re-read.
        mem.write_slice(&[0xA5], GuestAddress(head + 32)).unwrap();
        assert!(vcpu.jit_ineligible_unchanged(key));

        // Once the page is invalidated, the exact snapshot observes that suffix
        // edit and removes the stale verdict so the head can be re-lifted.
        vcpu.invalidate_code_page(head & !0xFFF);
        assert!(vcpu.jit_ineligible_dirty.contains(&key));
        assert!(!vcpu.jit_ineligible_unchanged(key));
        assert!(!vcpu.jit_ineligible.contains_key(&key));
        assert!(!vcpu.jit_ineligible_dirty.contains(&key));

        // A same-page write outside [head, head + 512) dirties the conservative
        // page-level candidate but retains it after one exact comparison.
        let unchanged_snapshot = vcpu.jit_code_snapshot(head);
        vcpu.jit_ineligible.insert(key, unchanged_snapshot);
        mem.write_slice(&[0x5A], GuestAddress(head + 0x800))
            .unwrap();
        vcpu.invalidate_code_page(head & !0xFFF);
        assert!(vcpu.jit_ineligible_dirty.contains(&key));
        assert!(vcpu.jit_ineligible_unchanged(key));
        assert!(vcpu.jit_ineligible.contains_key(&key));
        assert!(!vcpu.jit_ineligible_dirty.contains(&key));

        // A head in the final 512 B of page P overlaps P+1; invalidating P+1
        // must compare and reject a snapshot changed across that boundary.
        vcpu.jit_ineligible.clear();
        vcpu.jit_ineligible_dirty.clear();
        let crossing_head = 0x2F00;
        let crossing_key = (crossing_head, vcpu.jit_mode_tag());
        let crossing_snapshot = vcpu.jit_code_snapshot(crossing_head);
        vcpu.jit_ineligible.insert(crossing_key, crossing_snapshot);
        mem.write_slice(&[0x3C], GuestAddress(0x3010)).unwrap();
        vcpu.invalidate_code_page(0x3000);
        assert!(vcpu.jit_ineligible_dirty.contains(&crossing_key));
        assert!(!vcpu.jit_ineligible_unchanged(crossing_key));
        assert!(!vcpu.jit_ineligible.contains_key(&crossing_key));
    }

    #[cfg(all(
        feature = "smir-jit",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn auto_promoted_closed_loop_exits_at_each_backedge() {
        let (mut vcpu, mem) = test_vcpu_with_mem();
        // inc eax; jmp 0. The CFG has no terminal frontier; its self-edge is the
        // only safe point at which an auto-promoted native slice can return.
        mem.write_slice(&[0xFF, 0xC0, 0xEB, 0xFC], GuestAddress(0))
            .unwrap();
        vcpu.sregs.efer = 1 << 10;
        vcpu.sregs.cs.l = true;
        vcpu.regs.rip = 0;
        vcpu.regs.rax = 41;
        vcpu.regs.rflags = 2;

        assert!(
            vcpu.jit_compile_region().unwrap().is_none(),
            "explicit unbounded compilation must still reject a closed loop"
        );

        vcpu.jit_hot.insert(0, JIT_HOT_THRESHOLD - 1);
        vcpu.jit_sample_backedge(2);

        assert_eq!(vcpu.jit_region_count(), 1);
        assert_eq!(vcpu.regs.rax, 42);
        assert_eq!(
            vcpu.regs.rip, 0,
            "the synthesized backedge exit must resume at the loop head"
        );
    }

    #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
    #[test]
    fn jit_verifier_replays_a_region_that_exits_at_its_entry_pc() {
        let (mut vcpu, mem) = test_vcpu_with_mem();
        // inc eax; jmp 0. Yielding compilation turns the backward edge into an
        // exit at RIP=0, equal to the region's entry. The verifier must replay
        // the increment and jump instead of treating the initial RIP match as
        // completion.
        mem.write_slice(&[0xFF, 0xC0, 0xEB, 0xFC], GuestAddress(0))
            .unwrap();
        vcpu.sregs.efer = 1 << 10;
        vcpu.sregs.cs.l = true;
        vcpu.regs.rip = 0;
        vcpu.regs.rax = 41;
        vcpu.regs.rflags = 2;

        let region = vcpu
            .jit_compile_region_with_edge_exits(true)
            .unwrap()
            .expect("yielded closed loop must be JIT eligible");
        vcpu.jit_run_region_verified(&region);

        assert_eq!(vcpu.regs.rax, 42);
        assert_eq!(vcpu.regs.rip, 0);
    }

    #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
    #[test]
    fn jit_verifier_ignores_forward_arrival_at_an_internal_backedge_target() {
        let (mut vcpu, mem) = test_vcpu_with_mem();
        // jmp body; hlt; nop; body: inc eax; jmp body. The yielded native
        // slice exits at PC=4 only after the jump at PC=6. Interpreter replay
        // first reaches PC=4 through the forward entry edge and must not stop
        // there.
        mem.write_slice(
            &[0xEB, 0x02, 0xF4, 0x90, 0xFF, 0xC0, 0xEB, 0xFC],
            GuestAddress(0),
        )
        .unwrap();
        vcpu.sregs.efer = 1 << 10;
        vcpu.sregs.cs.l = true;
        vcpu.regs.rip = 0;
        vcpu.regs.rax = 41;
        vcpu.regs.rflags = 2;

        let region = vcpu
            .jit_compile_region_with_edge_exits(true)
            .unwrap()
            .expect("internal-target loop must be JIT eligible");
        assert_eq!(region.yielded_backward_exit_pcs, vec![4]);
        vcpu.jit_run_region_verified(&region);

        assert_eq!(vcpu.regs.rax, 42);
        assert_eq!(vcpu.regs.rip, 4);
    }
}

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_mmx_tests.rs"]
mod jit_mmx_tests;

#[cfg(test)]
#[path = "cpu_mmx_xmm_transfer_tests.rs"]
mod mmx_xmm_transfer_tests;

#[cfg(test)]
#[path = "cpu_enter_tests.rs"]
mod enter_tests;

#[cfg(test)]
#[path = "cpu_leave_tests.rs"]
mod leave_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_enter_tests.rs"]
mod jit_enter_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_leave_tests.rs"]
mod jit_leave_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_vsib_tests.rs"]
mod jit_vsib_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_stack_flags_tests.rs"]
mod jit_stack_flags_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_opmask_tests.rs"]
mod jit_opmask_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_mmx_memory_source_tests.rs"]
mod jit_mmx_memory_source_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_vector_memory_source_tests.rs"]
mod jit_vector_memory_source_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_call_tests.rs"]
mod jit_call_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_cmpccxadd_tests.rs"]
mod jit_cmpccxadd_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_scalar_tests.rs"]
mod jit_scalar_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_fp_estimate_tests.rs"]
mod jit_fp_estimate_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_mxcsr_tests.rs"]
mod jit_mxcsr_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_cpuid_tests.rs"]
mod jit_cpuid_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_fsgsbase_tests.rs"]
mod jit_fsgsbase_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_fence_alias_tests.rs"]
mod jit_fence_alias_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_x87_reserved_tests.rs"]
mod jit_x87_reserved_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_x87_control_tests.rs"]
mod jit_x87_control_tests;

#[cfg(test)]
#[path = "cpu_waitpkg_tests.rs"]
mod waitpkg_tests;

#[cfg(test)]
#[path = "cpu_ptwrite_tests.rs"]
mod ptwrite_tests;

#[cfg(test)]
#[path = "cpu_xop_tests.rs"]
mod xop_tests;

#[cfg(test)]
#[path = "cpu_xop_vpcom_tests.rs"]
mod xop_vpcom_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_hypercall_tests.rs"]
mod jit_hypercall_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_pkru_tests.rs"]
mod jit_pkru_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_swapgs_tests.rs"]
mod jit_swapgs_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_monitor_mwait_tests.rs"]
mod jit_monitor_mwait_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_tsc_tests.rs"]
mod jit_tsc_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_pmc_tests.rs"]
mod jit_pmc_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_msr_tests.rs"]
mod jit_msr_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_ac_tests.rs"]
mod jit_ac_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_clts_tests.rs"]
mod jit_clts_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_cli_tests.rs"]
mod jit_cli_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_reserved_nop_tests.rs"]
mod jit_reserved_nop_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_apx_prefix_tests.rs"]
mod jit_apx_prefix_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_apx_crc32_tests.rs"]
mod jit_apx_crc32_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_apx_group3_tests.rs"]
mod jit_apx_group3_tests;

#[cfg(test)]
#[path = "cpu_rex2_admission_tests.rs"]
mod rex2_admission_tests;

#[cfg(test)]
#[path = "cpu_sti_tests.rs"]
mod sti_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_sti_tests.rs"]
mod jit_sti_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_invlpg_tests.rs"]
mod jit_invlpg_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_invpcid_tests.rs"]
mod jit_invpcid_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_string_io_tests.rs"]
mod jit_string_io_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_io_tests.rs"]
mod jit_io_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_read_control_tests.rs"]
mod jit_read_control_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_smsw_tests.rs"]
mod jit_smsw_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_lmsw_tests.rs"]
mod jit_lmsw_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_descriptor_table_tests.rs"]
mod jit_descriptor_table_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_selector_tests.rs"]
mod jit_selector_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_selector_query_tests.rs"]
mod jit_selector_query_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_selector_verify_tests.rs"]
mod jit_selector_verify_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_pop_segment_tests.rs"]
mod jit_pop_segment_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_far_pointer_load_tests.rs"]
mod jit_far_pointer_load_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_far_jump_tests.rs"]
mod jit_far_jump_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_far_call_tests.rs"]
mod jit_far_call_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_far_return_tests.rs"]
mod jit_far_return_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_fast_system_transfer_tests.rs"]
mod jit_fast_system_transfer_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_read_debug_tests.rs"]
mod jit_read_debug_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_write_debug_tests.rs"]
mod jit_write_debug_tests;

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
#[path = "cpu_jit_write_control_tests.rs"]
mod jit_write_control_tests;

#[cfg(all(test, feature = "debug"))]
mod debugger_breakpoint_tests {
    use super::*;
    use std::sync::Arc;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    fn test_vcpu_with_mem(code: &[u8]) -> (X86_64Vcpu, Arc<GuestMemoryMmap>) {
        let mem =
            Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
        mem.write_slice(code, GuestAddress(0)).unwrap();
        (X86_64Vcpu::new(0, mem.clone()), mem)
    }

    #[test]
    fn debug_breakpoint_stops_without_patching_guest_memory() {
        let code = [
            0xb8, 0x34, 0x12, 0x00, 0x00, // MOV EAX, 0x1234
            0xf4, // HLT
        ];
        let (mut vcpu, mem) = test_vcpu_with_mem(&code);

        vcpu.set_debug_breakpoint(0).unwrap();

        let exit = vcpu.run().unwrap();
        assert!(matches!(exit, VcpuExit::GdbBreakpoint { addr: 0 }));
        assert_eq!(vcpu.regs.rip, 0, "breakpoint stop must not advance RIP");
        assert_eq!(vcpu.regs.rax, 0, "breakpoint stop must not execute code");

        let mut first_byte = [0u8; 1];
        mem.read_slice(&mut first_byte, GuestAddress(0)).unwrap();
        assert_eq!(
            first_byte[0], code[0],
            "debugger breakpoints must not patch guest code bytes"
        );

        vcpu.clear_debug_breakpoint(0).unwrap();
        assert!(matches!(vcpu.run().unwrap(), VcpuExit::Hlt));
        assert_eq!(vcpu.regs.rax, 0x1234);
    }

    #[test]
    fn breakpoint_on_real_int3_preserves_guest_int3_after_clear() {
        let (mut vcpu, mem) = test_vcpu_with_mem(&[0xcc, 0xf4]);

        vcpu.set_debug_breakpoint(0).unwrap();
        let exit = vcpu.run().unwrap();
        assert!(matches!(exit, VcpuExit::GdbBreakpoint { addr: 0 }));
        assert_eq!(vcpu.regs.rip, 0);

        let mut first_byte = [0u8; 1];
        mem.read_slice(&mut first_byte, GuestAddress(0)).unwrap();
        assert_eq!(first_byte[0], 0xcc, "the guest's real INT3 must remain");

        vcpu.clear_debug_breakpoint(0).unwrap();
        let err = vcpu.run().unwrap_err().to_string();
        assert!(
            err.contains("IDT entry 3 not present"),
            "after the debugger breakpoint is removed, the real guest INT3 must inject #BP"
        );
    }

    #[test]
    fn single_step_executes_current_rip_even_with_internal_breakpoint() {
        let code = [
            0xb8, 0x34, 0x12, 0x00, 0x00, // MOV EAX, 0x1234
            0xf4, // HLT
        ];
        let (mut vcpu, mem) = test_vcpu_with_mem(&code);

        vcpu.set_debug_breakpoint(0).unwrap();
        vcpu.set_single_step(true);

        assert!(matches!(vcpu.run().unwrap(), VcpuExit::GdbStep));
        assert_eq!(vcpu.regs.rip, 3);
        assert_eq!(vcpu.regs.rax, 0x1234);

        let mut first_byte = [0u8; 1];
        mem.read_slice(&mut first_byte, GuestAddress(0)).unwrap();
        assert_eq!(
            first_byte[0], code[0],
            "single-step must not patch guest code bytes either"
        );
    }
}

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
mod tests {
    use super::*;
    use std::sync::Arc;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    fn test_vcpu() -> X86_64Vcpu {
        let mem =
            Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
        X86_64Vcpu::new(0, mem)
    }

    #[test]
    fn jit_verify_diagnostic_buffers_disable_at_caps() {
        let mut vcpu = test_vcpu();

        vcpu.jit_mem_trace = Some(Vec::new());
        for i in 0..JIT_VERIFY_MEM_TRACE_LIMIT {
            vcpu.push_jit_mem_trace((0, i as u64, 8, i as u64));
        }
        assert_eq!(
            vcpu.jit_mem_trace.as_ref().unwrap().len(),
            JIT_VERIFY_MEM_TRACE_LIMIT
        );
        vcpu.push_jit_mem_trace((0, 0xdead, 1, 0));
        assert!(vcpu.jit_mem_trace.is_none());

        vcpu.jit_mem_log = Some(Vec::new());
        for i in 0..JIT_VERIFY_MEM_LOG_LIMIT {
            vcpu.push_jit_mem_log((i as u64, 8, i as u64));
        }
        assert_eq!(
            vcpu.jit_mem_log.as_ref().unwrap().len(),
            JIT_VERIFY_MEM_LOG_LIMIT
        );
        vcpu.push_jit_mem_log((0xbeef, 1, 0));
        assert!(vcpu.jit_mem_log.is_none());
    }

    #[test]
    fn jit_memory_and_call_capabilities_default_on_with_explicit_opt_out() {
        assert!(jit_default_enabled(false));
        assert!(!jit_default_enabled(true));
    }

    #[test]
    fn jit_bail_classifier_skips_admitted_memory_operations() {
        use crate::smir::ir::FunctionBuilder;
        use crate::smir::ir::Terminator;
        use crate::smir::ir::ops::OpKind;
        use crate::smir::ir::types::{
            Address, ArchReg, Avx10FP16Op, FpRoundMode, FunctionId, MemWidth, SignExtend, VReg,
            VecElementType, VecWidth, X86Reg,
        };

        let arch = |reg| VReg::Arch(ArchReg::X86(reg));
        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
        builder.push_op(
            0x1000,
            OpKind::Load {
                dst: arch(X86Reg::Rax),
                addr: Address::Direct(arch(X86Reg::Rbx)),
                width: MemWidth::B8,
                sign: SignExtend::Zero,
            },
        );
        builder.push_op(
            0x1001,
            OpKind::VConflict {
                dst: arch(X86Reg::Zmm(1)),
                src: arch(X86Reg::Zmm(2)),
                mask: None,
                elem: VecElementType::I32,
                width: VecWidth::V512,
                zeroing: false,
            },
        );
        builder.push_op(
            0x1002,
            OpKind::VLeadingZeros {
                dst: arch(X86Reg::Zmm(10)),
                src: arch(X86Reg::Zmm(11)),
                mask: None,
                elem: VecElementType::I64,
                width: VecWidth::V512,
                zeroing: false,
            },
        );
        builder.push_op(
            0x1003,
            OpKind::VCvtFP32ToBF16 {
                dst: arch(X86Reg::Ymm(3)),
                src1: arch(X86Reg::Zmm(4)),
                src2: None,
                mask: None,
                width: VecWidth::V512,
                zeroing: false,
            },
        );
        builder.push_op(
            0x1004,
            OpKind::VFP16Arith {
                dst: arch(X86Reg::Zmm(5)),
                src1: arch(X86Reg::Zmm(6)),
                src2: arch(X86Reg::Zmm(7)),
                mask: None,
                op: Avx10FP16Op::Add,
                round: FpRoundMode::Dynamic,
                width: VecWidth::V512,
                lanes: 32,
                zeroing: false,
            },
        );
        builder.push_op(
            0x1005,
            OpKind::X86PermuteBytesWords {
                dst: arch(X86Reg::Zmm(12)),
                table1: arch(X86Reg::Zmm(13)),
                table2: None,
                indices: arch(X86Reg::Zmm(14)),
                mask: None,
                elem: VecElementType::I8,
                width: VecWidth::V512,
                overwrite_table: false,
                zeroing: false,
            },
        );
        builder.push_op(
            0x1006,
            OpKind::VCompress {
                dst: arch(X86Reg::Zmm(15)),
                src: arch(X86Reg::Zmm(16)),
                mask: None,
                elem: VecElementType::I32,
                width: VecWidth::V512,
                zeroing: false,
            },
        );
        builder.push_op(
            0x1007,
            OpKind::VExpand {
                dst: arch(X86Reg::Zmm(17)),
                src: arch(X86Reg::Zmm(18)),
                mask: None,
                elem: VecElementType::F64,
                width: VecWidth::V512,
                zeroing: false,
            },
        );
        builder.push_op(
            0x1008,
            OpKind::X86NarrowInt {
                dst: arch(X86Reg::Ymm(19)),
                src: arch(X86Reg::Zmm(20)),
                mask: None,
                src_elem: VecElementType::I16,
                dst_elem: VecElementType::I8,
                width: VecWidth::V512,
                mode: crate::smir::ir::types::X86NarrowMode::Truncate,
                zeroing: false,
            },
        );
        builder.push_op(
            0x1009,
            OpKind::VCvtBF16ToFP32 {
                dst: arch(X86Reg::Zmm(8)),
                src: arch(X86Reg::Zmm(9)),
                width: VecWidth::V512,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();
        let exits = std::collections::HashMap::new();

        assert_eq!(jit_classify_bail(&func, &exits, false), "Load");
        assert_eq!(jit_classify_bail(&func, &exits, true), "VCvtBF16ToFP32");
    }

    #[cfg(feature = "debug")]
    #[test]
    fn debugger_active_disables_jit_sampling() {
        let mut vcpu = test_vcpu();
        vcpu.regs.rip = 0x80;
        vcpu.jit_hot.insert(0x80, 7);

        vcpu.set_debugger_active(true);
        assert!(
            vcpu.jit_hot.is_empty(),
            "entering debugger mode should drop pending JIT hotness state"
        );
        assert!(vcpu.jit_disabled_for_debugger());

        vcpu.jit_hot.insert(0x80, 7);
        vcpu.jit_sample_backedge(0x100);
        assert_eq!(
            vcpu.jit_hot.get(&0x80),
            Some(&7),
            "debugger mode must not sample or promote JIT regions"
        );
        assert!(
            !vcpu.jit_try_block().unwrap(),
            "explicit JIT execution must be disabled while a debugger is active"
        );
        assert!(
            vcpu.jit_compile_region().unwrap().is_none(),
            "explicit JIT compilation must be disabled while a debugger is active"
        );
    }

    #[test]
    fn jit_backward_native_exit_edges_marks_only_internal_back_edges() {
        use crate::smir::ir::types::{BlockId, FunctionId, VReg};
        use crate::smir::ir::{SmirBlock, SmirFunction, Terminator, TrapKind};
        use std::collections::HashMap;

        let entry = BlockId(0);
        let body = BlockId(1);
        let self_loop = BlockId(2);
        let exit = BlockId(3);

        let mut func = SmirFunction::new(FunctionId(0), entry, 0x1000);

        let mut entry_block = SmirBlock::new(entry, 0x1000);
        entry_block.set_terminator(Terminator::Branch { target: body });
        func.add_block(entry_block);

        let mut body_block = SmirBlock::new(body, 0x1010);
        body_block.set_terminator(Terminator::CondBranch {
            cond: VReg::virt(0),
            true_target: entry,
            false_target: self_loop,
        });
        func.add_block(body_block);

        let mut self_loop_block = SmirBlock::new(self_loop, 0x1020);
        self_loop_block.set_terminator(Terminator::CondBranch {
            cond: VReg::virt(1),
            true_target: self_loop,
            false_target: exit,
        });
        func.add_block(self_loop_block);

        let mut exit_block = SmirBlock::new(exit, 0x1030);
        exit_block.set_terminator(Terminator::Trap {
            kind: TrapKind::Halt,
        });
        func.add_block(exit_block);

        let mut exits = HashMap::new();
        exits.insert(exit, 0x1030);

        let edges = X86_64Vcpu::jit_backward_native_exit_edges(&func, &exits);

        assert_eq!(edges.len(), 2);
        assert_eq!(edges.get(&(body, entry)), Some(&0x1000));
        assert_eq!(edges.get(&(self_loop, self_loop)), Some(&0x1020));
        assert!(!edges.contains_key(&(entry, body)));
        assert!(!edges.contains_key(&(body, self_loop)));
        assert!(!edges.contains_key(&(self_loop, exit)));
    }

    #[test]
    fn jit_backward_edge_detection_uses_post_merge_terminator_pc() {
        use crate::smir::ir::types::{BlockId, FunctionId, VReg};
        use crate::smir::ir::{SmirBlock, SmirFunction, Terminator};
        use std::collections::HashMap;

        let merged = BlockId(0);
        let loop_target = BlockId(1);
        let exit = BlockId(2);
        let mut function = SmirFunction::new(FunctionId(0), merged, 0x1000);

        // Model O2's forward merge: the block retains entry PC 1000h, but its
        // appended loop-body terminator is at 1020h and branches to 1010h.
        let mut merged_block = SmirBlock::new(merged, 0x1000);
        merged_block.push_op(crate::smir::ir::ops::SmirOp::new(
            crate::smir::ir::types::OpId(0),
            0x1020,
            crate::smir::ir::ops::OpKind::Nop,
        ));
        merged_block.set_terminator(Terminator::CondBranch {
            cond: VReg::virt(0),
            true_target: loop_target,
            false_target: exit,
        });
        function.add_block(merged_block);

        let mut target_block = SmirBlock::new(loop_target, 0x1010);
        target_block.set_terminator(Terminator::Branch { target: merged });
        function.add_block(target_block);

        let mut exit_block = SmirBlock::new(exit, 0x1030);
        exit_block.set_terminator(Terminator::Return { values: Vec::new() });
        function.add_block(exit_block);

        let exits = HashMap::from([(exit, 0x1030)]);
        let edges = X86_64Vcpu::jit_backward_native_exit_edges(&function, &exits);

        assert_eq!(edges.get(&(merged, loop_target)), Some(&0x1010));
    }

    #[test]
    fn jit_backward_edge_detection_keeps_equal_pc_fallthrough_internal() {
        use crate::smir::ir::types::{BlockId, FunctionId, OpId, VReg};
        use crate::smir::ir::{SmirBlock, SmirFunction, Terminator};
        use std::collections::HashMap;

        let entry = BlockId(0);
        let fallthrough = BlockId(1);
        let exit = BlockId(2);
        let mut function = SmirFunction::new(FunctionId(0), entry, 0x1000);

        let mut entry_block = SmirBlock::new(entry, 0x1000);
        entry_block.push_op(crate::smir::ir::ops::SmirOp::new(
            OpId(0),
            0x1010,
            crate::smir::ir::ops::OpKind::Nop,
        ));
        entry_block.set_terminator(Terminator::CondBranch {
            cond: VReg::virt(0),
            true_target: exit,
            false_target: fallthrough,
        });
        function.add_block(entry_block);

        let mut fallthrough_block = SmirBlock::new(fallthrough, 0x1010);
        fallthrough_block.set_terminator(Terminator::Return { values: Vec::new() });
        function.add_block(fallthrough_block);

        let mut exit_block = SmirBlock::new(exit, 0x1020);
        exit_block.set_terminator(Terminator::Return { values: Vec::new() });
        function.add_block(exit_block);

        let exits = HashMap::from([(exit, 0x1020)]);
        let edges = X86_64Vcpu::jit_backward_native_exit_edges(&function, &exits);

        assert!(!edges.contains_key(&(entry, fallthrough)));
    }

    #[cfg(unix)]
    #[test]
    fn jit_crash_cleanup_restores_terminal_raw_state() {
        crate::host::terminal::test_mark_raw_for_restore();
        assert!(crate::host::terminal::test_raw_enabled());

        jit_crash_cleanup();

        assert!(!crate::host::terminal::test_raw_enabled());
    }
}
