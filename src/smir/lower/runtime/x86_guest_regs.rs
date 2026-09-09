//! x86-64 guest-state ABI shared by native lowering and execution.

use crate::smir::lower::{X86_GUEST_GPR_COUNT, X86_GUEST_RFLAGS_OFFSET};

/// Guest register file marshalled in/out of a lowered native block.
///
/// `gpr[i]` is indexed by x86 register *encoding*
/// (0=RAX, 1=RCX, 2=RDX, 3=RBX, 4=RSP, 5=RBP, 6=RSI, 7=RDI, 8..=15=R8..=R15,
/// 16..=31=R16..=R31). `rflags` holds the host-safe materialized flag image;
/// `ac_flag` separately carries guest RFLAGS.AC because host AC must remain
/// clear. `repr(C)` has a fixed layout — the trampoline reads/writes by byte
/// offset (`gpr[i]` at `i*8`, `rflags` at [`X86_GUEST_RFLAGS_OFFSET`]).
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestRegs {
    /// General-purpose registers, indexed by x86 encoding.
    pub gpr: [u64; X86_GUEST_GPR_COUNT],
    /// Host-safe materialized RFLAGS image; `ac_flag` carries guest AC.
    pub rflags: u64,
    /// Resume guest PC, written by an exit stub when a block lowered with the
    /// general-exit ABI hands control back to the interpreter. Only meaningful
    /// for blocks run via [`super::ExecMem::run_with_exit`]. See
    /// the native entry trampoline (the R15-reserved trampoline) and the lowerer's
    /// `native_exit` mode.
    pub exit_pc: u64,
    /// Opaque context pointer passed as arg0 to the memory helpers (the
    /// `*mut X86_64Vcpu`). Set by the JIT before each run.
    pub ctx: u64,
    /// Address of the load helper `fn(ctx, addr, size, signed) -> (value, ok)`
    /// (SysV: value in RAX, ok in RDX).
    pub load_fn: u64,
    /// Address of the store helper `fn(ctx, addr, value, size) -> ok`.
    pub store_fn: u64,
    /// IA32_FS_BASE. The lowered code adds
    /// this to the effective address of an `fs:`-overridden memory operand
    /// ([`crate::smir::ir::types::Address::SegmentRel`]). Set from
    /// `sregs.fs.base` before each run.
    pub fs_base: u64,
    /// IA32_GS_BASE. As `fs_base` but for
    /// `gs:`-overridden operands (per-CPU data in the Linux kernel).
    pub gs_base: u64,
    /// Address of the call helper
    /// `fn(gr, target_pc, return_pc, call_pc) -> ok`. Used by the
    /// lift-through-calls path (RAX_JIT_CALL): a guest CALL in a JIT region
    /// lowers to a call-out into this helper, which runs the interpreter for the
    /// callee until it returns to `return_pc`, then resumes native execution.
    /// `ok == 0` means the callee bailed to the interpreter (an exit/exception)
    /// and the region must return; the helper has set `exit_pc`. NOTE: arg0 is
    /// the `*mut GuestRegs` itself (not `ctx`), because the helper needs the
    /// full marshalled guest state, and `gr.ctx` carries the vcpu pointer.
    /// `call_pc` is the precise deoptimization PC if the architectural
    /// return-address push faults.
    pub call_fn: u64,
    /// Complete architectural ZMM0-ZMM31 state. XMM and YMM values occupy the
    /// corresponding low 128/256 bits. Kept in one canonical representation so
    /// the native trampoline can import/export the entire overlapping register
    /// file with one 64-byte transfer per physical register.
    pub zmm: [[u64; 8]; 32],
    /// AVX-512 architectural opmask registers K0-K7.
    pub k: [u64; 8],
    /// Native vector-state mode. Zero disables vector marshalling; one
    /// imports/exports ZMM0-ZMM31 and all 64 opmask bits with KMOVQ; two uses
    /// the same ZMM bridge but imports/exports only K[15:0] with AVX512F KMOVW;
    /// and three delegates YMM0-YMM15 to the AVX-only wrapper while leaving
    /// upper ZMM halves and all opmasks state-backed.
    pub vector_active: u64,
    /// Guest architectural MXCSR control/status. Loaded before native vector
    /// execution and captured afterward.
    pub mxcsr: u32,
    /// Host-thread MXCSR saved by the trampoline. Helper call boundaries switch
    /// to this value so Rust code never executes under guest FP control state.
    pub host_mxcsr: u32,
    /// Guest IA32_TSC_AUX MSR. RDPID reads this state-backed value rather than
    /// exposing the host thread's processor identifier.
    pub tsc_aux: u32,
    /// Guest PKRU. RDPKRU/WRPKRU use this state-backed value rather than the
    /// host thread's protection-key rights register.
    pub pkru: u32,
    /// Guest XCR0 extended-state enable bitmap.
    pub xcr0: u64,
    /// Guest XGETBV(ECX=1) XINUSE bitmap. The lowered instruction masks it by
    /// XCR0, matching the architectural definition of enabled in-use state.
    pub xgetbv1: u64,
    /// Guest CR4. XGETBV deoptimizes unless OSXSAVE (bit 18) is set, allowing
    /// the interpreter to deliver the architectural #UD precisely.
    pub cr4: u64,
    /// Guest CR0. XSETBV checks PE before enforcing CPL0; CLTS checks PE/CPL
    /// and clears TS (bit 3) in this state-backed value.
    pub cr0: u64,
    /// Effective current privilege level derived from CS.RPL, with virtual-8086
    /// mode represented as CPL3.
    pub cpl: u64,
    /// Non-zero when the emulator exposes APX and permits XCR0.APX_F.
    pub apx_enabled: u64,
    /// Address of `extern "C" fn(state, addr, dst_idx, size, zero_upper) -> ok`.
    /// Architectural indices write a complete post-load ZMM slot. The reserved
    /// internal index 32 writes a 1/2/4/8/16/32/64-byte operand to `vector_scratch`
    /// without modifying guest state.
    pub vec_load_fn: u64,
    /// Address of `extern "C" fn(state, addr, src_idx, size) -> ok`.
    /// Indices 0..=31 read ZMM state; reserved internal index 32 reads vector scratch.
    pub vec_store_fn: u64,
    /// Address of `extern "C" fn(state, dst_low, dst_high) -> ok`.
    /// The helper performs one complete APX POP2 stack transfer and commits the
    /// two destinations plus RSP only after the complete 16-byte read succeeds.
    pub pair_load_fn: u64,
    /// Address of `extern "C" fn(state, src_low, src_high) -> ok`.
    /// The helper performs one complete APX PUSH2 stack transfer and commits
    /// RSP only after the complete 16-byte write succeeds.
    pub pair_store_fn: u64,
    /// Architectural MM0-MM7 values. This native ABI carries the emulator's
    /// canonical MMX view used by lifted packed-integer operations.
    pub mm: [u64; 8],
    /// Non-zero only for a region containing admitted native MMX operations.
    /// The trampoline uses this to avoid entering MMX state for all other code.
    pub mmx_active: u64,
    /// Guest architectural x87 tag word. Native `EnterMmx` commits zero and
    /// native `EmptyMmx` commits `0xFFFF` at their exact instruction points;
    /// trampoline `EMMS` affects only host state and must not overwrite it.
    pub x87_tag_word: u64,
    /// Address of `extern "C" fn(state)` implementing the emulator's
    /// deterministic guest CPUID profile. The helper reads EAX/ECX and commits
    /// zero-extended EAX/EBX/ECX/EDX through this structure.
    pub cpuid_fn: u64,
    /// Non-zero when CPUID leaf 7 enumerates Xeon Phi AVX-512 extensions.
    pub cpuid_xeon_phi_avx512: u64,
    /// Non-zero when CPUID leaf 7 enumerates AVX512_VP2INTERSECT.
    pub cpuid_vp2intersect: u64,
    /// Non-zero when CPUID leaf 0x80000001 enumerates SSE4A.
    pub cpuid_sse4a: u64,
    /// IA32_KERNEL_GS_BASE. SWAPGS exchanges this with `gs_base` without ever
    /// executing the host's privileged SWAPGS instruction.
    pub kernel_gs_base: u64,
    /// Address of `extern "C" fn(state)` implementing the emulator's guest
    /// timestamp counter. The helper commits zero-extended EAX and EDX slots;
    /// RDTSCP lowering separately commits guest IA32_TSC_AUX to ECX.
    pub tsc_fn: u64,
    /// Authoritative guest RFLAGS.AC value (zero or one). Host AC is never
    /// loaded because CPL3 alignment checking would expose guest state to the
    /// emulator process as #AC/SIGBUS.
    pub ac_flag: u64,
    /// Guest CR2 page-fault linear-address state. Appended to preserve every
    /// pre-existing native helper ABI offset.
    pub cr2: u64,
    /// Guest CR3 paging-structure root and process-context state.
    pub cr3: u64,
    /// Guest CR8 task-priority state.
    pub cr8: u64,
    /// Guest breakpoint linear-address registers.
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    /// Guest debug status register.
    pub dr6: u64,
    /// Guest debug control register.
    pub dr7: u64,
    /// Guest IA32_EFER, including processor-maintained LMA state.
    pub efer: u64,
    /// Nonzero when the current guest code segment has CS.L=1.
    pub cs_l: u64,
    /// Low four bits of the current task-register descriptor type.
    pub tr_type: u64,
    /// Address of `extern "C" fn(state, control, value) -> ok`, implementing
    /// canonical MOV-to-control-register validation and TLB synchronization.
    pub control_write_fn: u64,
    /// Address of `extern "C" fn(state, write) -> ok`, implementing the
    /// complete deterministic RDMSR/WRMSR profile.
    pub msr_fn: u64,
    /// IA32_TSC_ADJUST local timestamp-counter offset.
    pub tsc_adjust: u64,
    /// System-call and SYSENTER MSRs not otherwise represented by dedicated
    /// native state fields.
    pub star: u64,
    pub lstar: u64,
    pub cstar: u64,
    pub fmask: u64,
    pub sysenter_cs: u64,
    pub sysenter_esp: u64,
    pub sysenter_eip: u64,
    /// Address of `extern "C" fn(state) -> ok`, implementing the deterministic
    /// legacy-PMU RDPMC profile and committing EDX:EAX only on success.
    pub pmc_fn: u64,
    /// Address of `extern "C" fn(state, addr, table) -> ok`, implementing one
    /// fault-precise 10-byte SGDT/SIDT memory transfer. `table` is zero for
    /// GDTR and one for IDTR.
    pub descriptor_store_fn: u64,
    /// Address of `extern "C" fn(state, addr, table) -> ok`, implementing one
    /// fault-precise 10-byte LGDT/LIDT memory transfer and committing the
    /// selected implicit descriptor-table state only after the full read.
    pub descriptor_load_fn: u64,
    /// Address of `extern "C" fn(state, selector) -> value`, returning LDTR,
    /// TR, ES, CS, SS, DS, FS, or GS for selector IDs zero through seven after
    /// any prior interpreter callout.
    pub system_selector_fn: u64,
    /// Address of `extern "C" fn(state, operand, encoding) -> ok` for LLDT/LTR,
    /// MOV-Sreg, POP-FS/GS, and LSS/LFS/LGS. Bit zero marks memory, bit one
    /// records REX2/APX, bits 4:2 select the segment register, bit five marks an
    /// 8-byte selector source, and bit six marks a POP stack source. Bit seven
    /// marks a far pointer; then bits 12:8 select its GPR and bits 14:13 encode
    /// its 2-, 4-, or 8-byte offset. All architectural destinations commit only
    /// after source and descriptor effects succeed. Internal tagged namespaces
    /// additionally carry VERR/VERW and LAR/LSL queries through this helper;
    /// they return one for ZF=0, two for ZF=1, and zero for precise replay.
    pub system_selector_load_fn: u64,
    /// Address of `extern "C" fn(state, pointer_address, encoding) -> ok` for
    /// long-mode `FF /5`. Encoding bits 1:0 select W16/W32/W64 and bit two
    /// records a REX2/APX encoding; bit three records an SS-based memory
    /// operand for exact noncanonical-address fault selection. Success commits
    /// CS and dynamic `exit_pc`.
    pub far_jump_fn: u64,
    /// Address of `extern "C" fn(state, pointer_address, encoding, return_pc)
    /// -> ok` for long-mode `FF /3`. Success commits the complete far-CALL
    /// frame plus CS:RIP:RSP[:SS] and leaves the dynamic target in `exit_pc`.
    pub far_call_fn: u64,
    /// Address of `extern "C" fn(state, encoding) -> ok` for protected
    /// IA-32e `CA`/`CB`. Encoding bits 1:0 select W16/W32/W64, bit two records
    /// REX2/APX, and bits 31:16 carry the immediate parameter-release count.
    pub far_return_fn: u64,
    /// Guest RFLAGS.IF/IOPL/VM/VIF/VIP shadow. These control fields cannot be
    /// imported into or recovered from the host thread's user-mode RFLAGS.
    pub interrupt_flags: u64,
    /// Address of `extern "C" fn(state, requires_apx) -> ok`, implementing the
    /// architectural CLI privilege/virtualization decision and committing only
    /// IF or VIF in `interrupt_flags` on success.
    pub cli_fn: u64,
    /// Zero or one STI/MOV-SS maskable-interrupt shadow. This field is distinct
    /// from architectural RFLAGS and survives immediate native-to-direct
    /// handoff at a successful serializing frontier.
    pub interrupt_inhibit: u64,
    /// Address of `extern "C" fn(state, requires_apx) -> ok`, implementing the
    /// architectural STI privilege/VIP decision and committing IF/VIF plus the
    /// interrupt shadow only on success.
    pub sti_fn: u64,
    /// Address of `extern "C" fn(state, addr, requires_apx) -> ok`, applying
    /// INVLPG's dynamic validity checks and synchronizing every translation-
    /// dependent cache in the owning vCPU for a canonical linear address.
    pub invlpg_fn: u64,
    /// Address of `extern "C" fn(state, kind, operand64) -> ok` implementing
    /// Intel SYSENTER (`kind=0`) and SYSEXIT (`kind=1`). Success installs the
    /// fixed CS/SS caches through the owning vCPU and commits dynamic RSP/RIP
    /// through `gpr[4]` and `exit_pc`; failure requests exact direct replay.
    pub fast_system_transfer_fn: u64,
    /// Address of `extern "C" fn(state, addr, type, requires_apx) -> ok`.
    /// The helper reads and validates one complete 128-bit INVPCID descriptor,
    /// then synchronizes every translation-dependent cache in the owning vCPU.
    pub invpcid_fn: u64,
    /// Model MSRs are appended so every established native helper ABI offset
    /// above remains stable.
    pub misc_enable: u64,
    pub pat: u64,
    pub umwait_control: u64,
    /// Non-zero when a region reads or writes vector state directly through
    /// `zmm` without activating the host AVX-512 entry trampoline. Interpreter
    /// callouts use this marker to synchronize the same state-backed image.
    pub xmm_state_active: u64,
    /// Non-zero when a region reads or writes architectural MXCSR without
    /// activating the native vector entry trampoline. Interpreter callouts use
    /// this marker to synchronize `mxcsr` independently of the vector file.
    pub mxcsr_state_active: u64,
    /// Nonarchitectural helper transfer slot used by exact fused vector-memory
    /// sequences. It is never imported or exported by the native trampoline.
    pub vector_scratch: [u64; 8],
    /// Non-zero when CPUID leaf 0x80000001 enumerates TBM. This field is
    /// append-only so every established native helper/state offset is stable.
    pub cpuid_tbm: u64,
    /// Non-zero when CPUID leaf 0x80000001 enumerates XOP. This field is
    /// append-only so every established native helper/state offset is stable.
    pub cpuid_xop: u64,
    /// Address of `extern "C" fn(state, addr, cmp, add, size, cc) -> ok`,
    /// implementing one original-VEX CMPccXADD transaction. This field is
    /// append-only so every established native helper/state offset is stable.
    pub cmpccxadd_fn: u64,
    /// Address of `extern "C" fn(state, port, size, output) -> ok`.
    /// The helper validates dynamic I/O permission and publishes one external
    /// exit through `io_request`; it never executes a host port instruction.
    pub io_fn: u64,
    /// Packed native-to-vCPU port-I/O request. Bits 15:0 are the port, bits
    /// 23:16 the byte width, bit 24 the output direction, and bits 63:32 the
    /// zero-extended output value. Zero denotes no request.
    pub io_request: u64,
    /// Address of `extern "C" fn(state, allocation, nesting, width,
    /// requires_apx) -> ok`, implementing one complete long-mode ENTER stack
    /// transaction. This field is append-only so established offsets remain
    /// stable.
    pub enter_fn: u64,
    /// Address of `extern "C" fn(state, kind, width, requires_apx,
    /// native_rflags) -> ok`, implementing one complete long-mode PUSHF/POPF
    /// transaction. `kind` is zero for push and one for pop.
    pub stack_flags_fn: u64,
    /// Complete architectural post-POPF RFLAGS. This separate channel is
    /// required because host user-mode POPFQ cannot import guest IF/IOPL/TF/AC.
    pub stack_flags_rflags: u64,
    /// Exactly one after a successful POPF transaction; zero for every other
    /// native exit. The CPU marshal uses the complete image above only then.
    pub stack_flags_rflags_valid: u64,
    /// Exact x87 environment fields used by state-backed native operations.
    pub x87_control_word: u64,
    pub x87_status_word: u64,
    pub x87_data_ptr: u64,
    pub x87_instr_ptr: u64,
    pub x87_last_opcode: u64,
    /// Non-zero when a native region reads or writes the x87 environment or
    /// tag word. Interpreter callouts use it to synchronize the environment.
    pub x87_state_active: u64,
    /// Raw IEEE 754 binary64 bits for the direct engine's eight physical x87
    /// register slots. The direct engine currently projects binary80 payloads
    /// to `f64`; retaining raw bits here makes sign-only native operations
    /// preserve zeros, infinities, subnormals, and NaN payload/sign exactly
    /// within that established representation.
    pub x87_payload: [u64; 8],
    /// Non-zero when `x87_payload` participates in native execution or an
    /// interpreter callout. This separate append-only marker preserves the
    /// behavior of legacy manually constructed call frames that carry only the
    /// environment channel.
    pub x87_payload_active: u64,
    /// Exact partial-completion frontier for native EVEX gather/scatter.
    /// Zero denotes an ordinary instruction boundary; values 1..=16 encode
    /// the failed/deferred lane index plus one. Only a failed lane helper
    /// publishes this marker, after all lower active lanes have committed.
    /// It is execution metadata, never architectural state or a replay mask.
    pub x86_vsib_frontier_lane_plus_one: u64,
    /// Dynamic ordinal of the last native VSIB instruction entered in this
    /// region. Incremented after its mode/feature guards and before lane work;
    /// distinguishes repeated visits to one guest PC in a native loop.
    pub x86_vsib_instruction_ordinal: u64,
}

pub const X86_VECTOR_STATE_INACTIVE: u64 = 0;
pub const X86_VECTOR_STATE_K64: u64 = 1;
pub const X86_VECTOR_STATE_K16: u64 = 2;
pub const X86_VECTOR_STATE_YMM16: u64 = 3;

impl Default for GuestRegs {
    fn default() -> Self {
        Self {
            gpr: [0; X86_GUEST_GPR_COUNT],
            rflags: 0,
            exit_pc: 0,
            ctx: 0,
            load_fn: 0,
            store_fn: 0,
            fs_base: 0,
            gs_base: 0,
            call_fn: 0,
            zmm: [[0; 8]; 32],
            k: [0; 8],
            vector_active: X86_VECTOR_STATE_INACTIVE,
            mxcsr: 0x1F80,
            host_mxcsr: 0,
            tsc_aux: 0,
            pkru: 0,
            xcr0: 1,
            xgetbv1: 0,
            cr4: 0,
            cr0: 0,
            cpl: 0,
            apx_enabled: 0,
            vec_load_fn: 0,
            vec_store_fn: 0,
            pair_load_fn: 0,
            pair_store_fn: 0,
            mm: [0; 8],
            mmx_active: 0,
            x87_tag_word: 0xFFFF,
            cpuid_fn: 0,
            cpuid_xeon_phi_avx512: 0,
            cpuid_vp2intersect: 0,
            cpuid_sse4a: 0,
            kernel_gs_base: 0,
            tsc_fn: 0,
            ac_flag: 0,
            cr2: 0,
            cr3: 0,
            cr8: 0,
            dr0: 0,
            dr1: 0,
            dr2: 0,
            dr3: 0,
            dr6: 0,
            dr7: 0,
            efer: 0,
            cs_l: 0,
            tr_type: 0,
            control_write_fn: 0,
            msr_fn: 0,
            tsc_adjust: 0,
            star: 0,
            lstar: 0,
            cstar: 0,
            fmask: 0,
            sysenter_cs: 0,
            sysenter_esp: 0,
            sysenter_eip: 0,
            pmc_fn: 0,
            descriptor_store_fn: 0,
            descriptor_load_fn: 0,
            system_selector_fn: 0,
            system_selector_load_fn: 0,
            far_jump_fn: 0,
            far_call_fn: 0,
            far_return_fn: 0,
            interrupt_flags: 0,
            cli_fn: 0,
            interrupt_inhibit: 0,
            sti_fn: 0,
            invlpg_fn: 0,
            fast_system_transfer_fn: 0,
            invpcid_fn: 0,
            misc_enable: crate::isa::x86_64::execute::system::IA32_MISC_ENABLE_RESET,
            pat: crate::isa::x86_64::execute::system::IA32_PAT_RESET,
            umwait_control: 0,
            xmm_state_active: 0,
            mxcsr_state_active: 0,
            vector_scratch: [0; 8],
            cpuid_tbm: 0,
            cpuid_xop: 0,
            cmpccxadd_fn: 0,
            io_fn: 0,
            io_request: 0,
            enter_fn: 0,
            stack_flags_fn: 0,
            stack_flags_rflags: 0,
            stack_flags_rflags_valid: 0,
            x87_control_word: 0x037F,
            x87_status_word: 0,
            x87_data_ptr: 0,
            x87_instr_ptr: 0,
            x87_last_opcode: 0,
            x87_state_active: 0,
            x87_payload: [0; 8],
            x87_payload_active: 0,
            x86_vsib_frontier_lane_plus_one: 0,
            x86_vsib_instruction_ordinal: 0,
        }
    }
}

impl GuestRegs {
    const IO_OUTPUT_BIT: u64 = 1 << 24;
    const IO_RESERVED_MASK: u64 = 0xFE00_0000;

    /// Install one complete architectural vector register.
    pub fn set_zmm(&mut self, index: usize, value: [u64; 8]) {
        self.zmm[index] = value;
    }

    /// Read one complete architectural vector register.
    pub fn get_zmm(&self, index: usize) -> [u64; 8] {
        self.zmm[index]
    }

    /// Publish one validated external port-I/O exit for post-trampoline
    /// delivery. The packed channel stays append-only and allocation-free.
    pub(crate) fn set_io_request(&mut self, port: u16, size: u8, output: bool, value: u32) {
        debug_assert!(matches!(size, 1 | 2 | 4));
        debug_assert!(output || value == 0);
        self.io_request = u64::from(port)
            | (u64::from(size) << 16)
            | (if output { Self::IO_OUTPUT_BIT } else { 0 })
            | (u64::from(value) << 32);
    }

    /// Consume a packed I/O request, rejecting every reserved or malformed
    /// state. Tuple fields are `(port, size_bytes, output, output_value)`.
    pub(crate) fn take_io_request(&mut self) -> Option<(u16, u8, bool, u32)> {
        let request = std::mem::take(&mut self.io_request);
        let size = ((request >> 16) & 0xFF) as u8;
        let output = request & Self::IO_OUTPUT_BIT != 0;
        let value = (request >> 32) as u32;
        let value_fits_width = match size {
            1 => value <= u32::from(u8::MAX),
            2 => value <= u32::from(u16::MAX),
            4 => true,
            _ => false,
        };
        if request == 0
            || request & Self::IO_RESERVED_MASK != 0
            || !matches!(size, 1 | 2 | 4)
            || (!output && value != 0)
            || !value_fits_width
        {
            return None;
        }
        Some((request as u16, size, output, value))
    }
}
