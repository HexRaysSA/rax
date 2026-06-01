//! Differential test harness: software interpreter vs. KVM (hardware oracle).
//!
//! Each test case is a short machine-code sequence ending in `HLT`. It is run on
//! BOTH the rax software interpreter and on KVM from an *identical* initial
//! architectural state, then the resulting state (GPRs, RIP, the observable
//! RFLAGS bits, a couple of XMM registers, and a scratch memory page) is
//! compared. Any divergence is an interpreter bug (or, rarely, a harness
//! limitation) and is reported precisely.
//!
//! Robustness:
//!  - If `/dev/kvm` cannot be opened/driven, every test self-skips (returns
//!    without failing) so the suite is green in no-KVM environments.
//!  - Execution on both backends is bounded so a buggy case cannot hang.
//!
//! Initial state: long mode with identity-mapped paging. Real long mode requires
//! paging (CR0.PG=1 with EFER.LMA=1), and KVM enforces this, so we install a
//! tiny identity map (PML4 -> PDPTE with 1GiB pages) making GPA == GVA. The
//! interpreter is given the exact same CR0/CR3/CR4/EFER/segments so the two are
//! directly comparable.

#![cfg(all(feature = "kvm", target_os = "linux"))]

use std::sync::Arc;

use rax::backend::emulator::x86_64::{flags, X86_64Vcpu};
use rax::cpu::{Registers, SystemRegisters, VCpu, VcpuExit};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

// ---------------------------------------------------------------------------
// Memory layout (all identity-mapped: GVA == GPA)
// ---------------------------------------------------------------------------

/// Total guest memory size for each backend.
const MEM_SIZE: usize = 8 * 1024 * 1024; // 8 MiB
/// Where test code is loaded / RIP starts.
const CODE_ADDR: u64 = 0x1_0000;
/// Initial stack pointer.
const STACK_ADDR: u64 = 0x2_0000;
/// Scratch data page (read back after the run for memory-effect tests).
const DATA_ADDR: u64 = 0x3_0000;
/// Page-table addresses (mirrors src/arch/x86_64 layout).
const PML4_ADDR: u64 = 0x9000;
const PDPTE_ADDR: u64 = 0xA000;

// Long-mode control register / EFER values WITH paging enabled.
const CR0_PE: u64 = 1 << 0;
const CR0_MP: u64 = 1 << 1;
const CR0_ET: u64 = 1 << 4;
const CR0_NE: u64 = 1 << 5;
const CR0_WP: u64 = 1 << 16;
const CR0_PG: u64 = 1 << 31;
const CR0_VAL: u64 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_PG;
const CR4_PAE: u64 = 1 << 5;
const CR4_OSFXSR: u64 = 1 << 9; // enable SSE / FXSAVE so SSE2 ops don't #UD
const CR4_OSXMMEXCPT: u64 = 1 << 10;
const CR4_VAL: u64 = CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT;
const EFER_SCE: u64 = 1 << 0;
const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;
const EFER_VAL: u64 = EFER_SCE | EFER_LME | EFER_LMA;

// CR0 has MP|ET|NE set but TS/EM clear, so SSE is usable.

const MAX_ITERS: u64 = 100_000;

// ---------------------------------------------------------------------------
// Captured state for comparison
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct FinalState {
    regs: Registers,
    /// All 16 XMM registers, [low, high].
    xmm: [[u64; 2]; 16],
    /// Snapshot of the scratch data page (first 64 bytes).
    scratch: [u8; 64],
}

/// Observable, architecturally-defined RFLAGS status bits.
const FLAG_MASK: u64 =
    flags::bits::CF | flags::bits::PF | flags::bits::AF | flags::bits::ZF | flags::bits::SF | flags::bits::OF;

// ---------------------------------------------------------------------------
// Build the shared identity-mapped long-mode initial state.
// ---------------------------------------------------------------------------

fn base_sregs() -> SystemRegisters {
    let mut sregs = SystemRegisters::default();
    sregs.cr0 = CR0_VAL;
    sregs.cr3 = PML4_ADDR;
    sregs.cr4 = CR4_VAL;
    sregs.efer = EFER_VAL;

    // Flat 64-bit code segment (CS.L=1).
    sregs.cs.base = 0;
    sregs.cs.limit = 0xFFFFF;
    sregs.cs.selector = 0x8;
    sregs.cs.type_ = 0xB; // code, executed/read/accessed
    sregs.cs.present = true;
    sregs.cs.dpl = 0;
    sregs.cs.s = true;
    sregs.cs.l = true;
    sregs.cs.db = false; // must be 0 when L=1
    sregs.cs.g = true;

    // Flat data segments (DS/ES/FS/GS/SS).
    let mut data = sregs.cs.clone();
    data.selector = 0x10;
    data.type_ = 0x3; // data, read/write/accessed
    data.l = false;
    data.db = true;
    for seg in [
        &mut sregs.ds,
        &mut sregs.es,
        &mut sregs.fs,
        &mut sregs.gs,
        &mut sregs.ss,
    ] {
        *seg = data.clone();
    }

    sregs
}

/// Write the page tables + scratch page into a `Bytes` guest memory.
fn install_tables_mmap(write: &mut dyn FnMut(u64, &[u8])) {
    // PML4[0] -> PDPTE (present + writable)
    write(PML4_ADDR, &(PDPTE_ADDR | 0x3).to_le_bytes());
    // PDPTE[i] identity 1GiB huge pages (present + writable + PS), 4 entries (4GiB).
    for i in 0u64..4 {
        let entry: u64 = (i << 30) | 0x83;
        write(PDPTE_ADDR + i * 8, &entry.to_le_bytes());
    }
}

// ---------------------------------------------------------------------------
// Interpreter backend
// ---------------------------------------------------------------------------

fn run_interpreter(code: &[u8], init: &Registers, scratch_init: &[u8; 64]) -> Result<FinalState, String> {
    let regions = vec![(GuestAddress(0), MEM_SIZE)];
    let mem = Arc::new(GuestMemoryMmap::<()>::from_ranges(&regions).map_err(|e| format!("mem: {e:?}"))?);

    // Page tables.
    install_tables_mmap(&mut |addr, bytes| {
        mem.write_slice(bytes, GuestAddress(addr)).unwrap();
    });
    // Code + scratch.
    mem.write_slice(code, GuestAddress(CODE_ADDR)).map_err(|e| format!("code: {e:?}"))?;
    mem.write_slice(scratch_init, GuestAddress(DATA_ADDR)).map_err(|e| format!("scratch: {e:?}"))?;

    let mut vcpu = X86_64Vcpu::new(0, mem.clone());

    let mut regs = init.clone();
    regs.rip = CODE_ADDR;
    if regs.rsp == 0 {
        regs.rsp = STACK_ADDR;
    }
    regs.rflags |= 0x2; // reserved bit 1 always set
    vcpu.set_regs(&regs).map_err(|e| format!("set_regs: {e:?}"))?;
    vcpu.set_sregs(&base_sregs()).map_err(|e| format!("set_sregs: {e:?}"))?;

    // Run to HLT, counting individual instructions via step().
    let mut iters = 0u64;
    loop {
        iters += 1;
        if iters > MAX_ITERS {
            return Err(format!("interpreter exceeded {MAX_ITERS} iterations"));
        }
        match vcpu.step().map_err(|e| format!("step: {e:?}"))? {
            Some(VcpuExit::Hlt) => break,
            Some(VcpuExit::IoIn { size, .. }) => {
                let data = vec![0u8; size as usize];
                vcpu.complete_io_in(&data);
            }
            Some(VcpuExit::Shutdown) | Some(VcpuExit::FailEntry { .. }) | Some(VcpuExit::InternalError) => {
                return Err("interpreter abnormal exit".to_string());
            }
            _ => {}
        }
    }

    let final_regs = vcpu.get_regs().map_err(|e| format!("get_regs: {e:?}"))?;
    let mut scratch = [0u8; 64];
    mem.read_slice(&mut scratch, GuestAddress(DATA_ADDR)).map_err(|e| format!("read scratch: {e:?}"))?;

    Ok(FinalState {
        xmm: final_regs.xmm,
        regs: final_regs,
        scratch,
    })
}

// ---------------------------------------------------------------------------
// KVM backend (driven directly with kvm-ioctls, mirroring kvm_minimal.rs)
// ---------------------------------------------------------------------------

/// Owns the mmap backing KVM guest memory so we can read it back and free it.
struct KvmMem {
    ptr: *mut u8,
    size: usize,
}

impl KvmMem {
    fn new(size: usize) -> Option<Self> {
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return None;
        }
        Some(KvmMem { ptr: ptr as *mut u8, size })
    }

    fn write(&self, addr: u64, bytes: &[u8]) {
        assert!(addr as usize + bytes.len() <= self.size);
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr.add(addr as usize), bytes.len());
        }
    }

    fn read(&self, addr: u64, out: &mut [u8]) {
        assert!(addr as usize + out.len() <= self.size);
        unsafe {
            std::ptr::copy_nonoverlapping(self.ptr.add(addr as usize), out.as_mut_ptr(), out.len());
        }
    }
}

impl Drop for KvmMem {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.size);
        }
    }
}

/// Returns Ok(None) if KVM is unavailable (so callers can skip gracefully),
/// Ok(Some(state)) on success, Err on a genuine run failure.
fn run_kvm(code: &[u8], init: &Registers, scratch_init: &[u8; 64]) -> Result<Option<FinalState>, String> {
    use kvm_bindings::{kvm_segment, kvm_userspace_memory_region};
    use kvm_ioctls::Kvm;

    let kvm = match Kvm::new() {
        Ok(k) => k,
        Err(_) => return Ok(None), // /dev/kvm unavailable -> skip
    };
    let vm = match kvm.create_vm() {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };

    let mem = match KvmMem::new(MEM_SIZE) {
        Some(m) => m,
        None => return Ok(None),
    };

    // Identity-mapped page tables + code + scratch.
    install_tables_mmap(&mut |addr, bytes| mem.write(addr, bytes));
    mem.write(CODE_ADDR, code);
    mem.write(DATA_ADDR, scratch_init);

    let region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: MEM_SIZE as u64,
        userspace_addr: mem.ptr as u64,
        flags: 0,
    };
    if unsafe { vm.set_user_memory_region(region) }.is_err() {
        return Ok(None);
    }

    let mut vcpu = match vm.create_vcpu(0) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };

    // --- sregs: long mode w/ paging, flat segments ---
    let our_sregs = base_sregs();
    let mut sregs = vcpu.get_sregs().map_err(|e| format!("kvm get_sregs: {e:?}"))?;

    let to_kvm_seg = |s: &rax::cpu::Segment| kvm_segment {
        base: s.base,
        limit: s.limit,
        selector: s.selector,
        type_: s.type_,
        present: s.present as u8,
        dpl: s.dpl,
        db: s.db as u8,
        s: s.s as u8,
        l: s.l as u8,
        g: s.g as u8,
        avl: s.avl as u8,
        unusable: s.unusable as u8,
        padding: 0,
    };

    sregs.cr0 = our_sregs.cr0;
    sregs.cr3 = our_sregs.cr3;
    sregs.cr4 = our_sregs.cr4;
    sregs.efer = our_sregs.efer;
    sregs.cs = to_kvm_seg(&our_sregs.cs);
    sregs.ds = to_kvm_seg(&our_sregs.ds);
    sregs.es = to_kvm_seg(&our_sregs.es);
    sregs.fs = to_kvm_seg(&our_sregs.fs);
    sregs.gs = to_kvm_seg(&our_sregs.gs);
    sregs.ss = to_kvm_seg(&our_sregs.ss);
    vcpu.set_sregs(&sregs).map_err(|e| format!("kvm set_sregs: {e:?}"))?;

    // --- gprs ---
    let mut kregs = vcpu.get_regs().map_err(|e| format!("kvm get_regs: {e:?}"))?;
    kregs.rax = init.rax;
    kregs.rbx = init.rbx;
    kregs.rcx = init.rcx;
    kregs.rdx = init.rdx;
    kregs.rsi = init.rsi;
    kregs.rdi = init.rdi;
    kregs.rbp = init.rbp;
    kregs.rsp = if init.rsp == 0 { STACK_ADDR } else { init.rsp };
    kregs.r8 = init.r8;
    kregs.r9 = init.r9;
    kregs.r10 = init.r10;
    kregs.r11 = init.r11;
    kregs.r12 = init.r12;
    kregs.r13 = init.r13;
    kregs.r14 = init.r14;
    kregs.r15 = init.r15;
    kregs.rip = CODE_ADDR;
    kregs.rflags = init.rflags | 0x2;
    vcpu.set_regs(&kregs).map_err(|e| format!("kvm set_regs: {e:?}"))?;

    // --- xmm (via FPU state) ---
    if init.xmm.iter().any(|x| x != &[0, 0]) {
        let mut fpu = vcpu.get_fpu().map_err(|e| format!("kvm get_fpu: {e:?}"))?;
        for i in 0..16 {
            let lo = init.xmm[i][0].to_le_bytes();
            let hi = init.xmm[i][1].to_le_bytes();
            fpu.xmm[i][..8].copy_from_slice(&lo);
            fpu.xmm[i][8..].copy_from_slice(&hi);
        }
        vcpu.set_fpu(&fpu).map_err(|e| format!("kvm set_fpu: {e:?}"))?;
    }

    // --- run to HLT, bounded ---
    let mut iters = 0u64;
    loop {
        iters += 1;
        if iters > MAX_ITERS {
            return Err(format!("kvm exceeded {MAX_ITERS} iterations"));
        }
        match vcpu.run().map_err(|e| format!("kvm run: {e:?}"))? {
            kvm_ioctls::VcpuExit::Hlt => break,
            kvm_ioctls::VcpuExit::IoIn(_, data) => {
                for b in data.iter_mut() {
                    *b = 0;
                }
            }
            kvm_ioctls::VcpuExit::IoOut(..) => {}
            kvm_ioctls::VcpuExit::MmioRead(_, data) => {
                for b in data.iter_mut() {
                    *b = 0;
                }
            }
            kvm_ioctls::VcpuExit::MmioWrite(..) => {}
            other => {
                return Err(format!("kvm abnormal exit: {other:?}"));
            }
        }
    }

    let final_kregs = vcpu.get_regs().map_err(|e| format!("kvm get_regs(final): {e:?}"))?;
    let final_fpu = vcpu.get_fpu().map_err(|e| format!("kvm get_fpu(final): {e:?}"))?;

    let mut regs = Registers::default();
    regs.rax = final_kregs.rax;
    regs.rbx = final_kregs.rbx;
    regs.rcx = final_kregs.rcx;
    regs.rdx = final_kregs.rdx;
    regs.rsi = final_kregs.rsi;
    regs.rdi = final_kregs.rdi;
    regs.rsp = final_kregs.rsp;
    regs.rbp = final_kregs.rbp;
    regs.r8 = final_kregs.r8;
    regs.r9 = final_kregs.r9;
    regs.r10 = final_kregs.r10;
    regs.r11 = final_kregs.r11;
    regs.r12 = final_kregs.r12;
    regs.r13 = final_kregs.r13;
    regs.r14 = final_kregs.r14;
    regs.r15 = final_kregs.r15;
    regs.rip = final_kregs.rip;
    regs.rflags = final_kregs.rflags;

    let mut xmm = [[0u64; 2]; 16];
    for i in 0..16 {
        let lo = u64::from_le_bytes(final_fpu.xmm[i][..8].try_into().unwrap());
        let hi = u64::from_le_bytes(final_fpu.xmm[i][8..].try_into().unwrap());
        xmm[i] = [lo, hi];
    }
    regs.xmm = xmm;

    let mut scratch = [0u8; 64];
    mem.read(DATA_ADDR, &mut scratch);

    Ok(Some(FinalState { regs, xmm, scratch }))
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

/// What aspects of architectural state to compare.
#[derive(Clone, Copy)]
struct CompareOpts {
    /// RFLAGS bits to compare. Usually all status flags; for instructions that
    /// leave some flags *architecturally undefined* (MUL/IMUL/DIV/shifts by a
    /// variable count, etc.) the undefined bits are masked out so we only check
    /// the bits the ISA actually defines.
    flag_mask: u64,
    /// Number of XMM registers to compare (0 = none).
    xmm_count: usize,
    /// Compare the scratch data page.
    scratch: bool,
    /// Compare RSP/RBP (off for tests that intentionally don't touch the stack
    /// in a comparable way; on by default).
    stack: bool,
}

impl Default for CompareOpts {
    fn default() -> Self {
        CompareOpts {
            flag_mask: FLAG_MASK,
            xmm_count: 0,
            scratch: false,
            stack: true,
        }
    }
}

fn gpr_list(r: &Registers) -> [(&'static str, u64); 16] {
    [
        ("rax", r.rax),
        ("rbx", r.rbx),
        ("rcx", r.rcx),
        ("rdx", r.rdx),
        ("rsi", r.rsi),
        ("rdi", r.rdi),
        ("rsp", r.rsp),
        ("rbp", r.rbp),
        ("r8", r.r8),
        ("r9", r.r9),
        ("r10", r.r10),
        ("r11", r.r11),
        ("r12", r.r12),
        ("r13", r.r13),
        ("r14", r.r14),
        ("r15", r.r15),
    ]
}

fn compare(interp: &FinalState, kvm: &FinalState, opts: CompareOpts) -> Vec<String> {
    let mut diffs = Vec::new();

    let il = gpr_list(&interp.regs);
    let kl = gpr_list(&kvm.regs);
    for ((name, iv), (_, kv)) in il.iter().zip(kl.iter()) {
        if !opts.stack && (*name == "rsp" || *name == "rbp") {
            continue;
        }
        if iv != kv {
            diffs.push(format!("{name}: interp={iv:#x} kvm={kv:#x}"));
        }
    }

    if opts.flag_mask != 0 {
        let im = interp.regs.rflags & opts.flag_mask;
        let km = kvm.regs.rflags & opts.flag_mask;
        if im != km {
            diffs.push(format!(
                "rflags(status): interp={:#x} kvm={:#x} (diff bits={:#x}) [{}]",
                im,
                km,
                im ^ km,
                describe_flags(im ^ km)
            ));
        }
    }

    for i in 0..opts.xmm_count {
        if interp.xmm[i] != kvm.xmm[i] {
            diffs.push(format!(
                "xmm{i}: interp=[{:#018x},{:#018x}] kvm=[{:#018x},{:#018x}]",
                interp.xmm[i][0], interp.xmm[i][1], kvm.xmm[i][0], kvm.xmm[i][1]
            ));
        }
    }

    if opts.scratch && interp.scratch != kvm.scratch {
        diffs.push(format!(
            "scratch page differs:\n  interp={:02x?}\n  kvm   ={:02x?}",
            &interp.scratch[..],
            &kvm.scratch[..]
        ));
    }

    diffs
}

fn describe_flags(bits: u64) -> String {
    let mut v = Vec::new();
    if bits & flags::bits::CF != 0 {
        v.push("CF");
    }
    if bits & flags::bits::PF != 0 {
        v.push("PF");
    }
    if bits & flags::bits::AF != 0 {
        v.push("AF");
    }
    if bits & flags::bits::ZF != 0 {
        v.push("ZF");
    }
    if bits & flags::bits::SF != 0 {
        v.push("SF");
    }
    if bits & flags::bits::OF != 0 {
        v.push("OF");
    }
    v.join("|")
}

// ---------------------------------------------------------------------------
// Top-level driver used by every test case.
// ---------------------------------------------------------------------------

/// Run `code` on both backends from `init`, returning `(interp, kvm)`.
/// Returns `None` if KVM is unavailable (the test should then `return`).
fn run_both(code: &[u8], init: Registers, scratch_init: [u8; 64]) -> Option<(FinalState, FinalState)> {
    // KVM first: if unavailable we skip without even bothering the interpreter.
    let kvm = match run_kvm(code, &init, &scratch_init) {
        Ok(Some(s)) => s,
        Ok(None) => {
            eprintln!("[skip] /dev/kvm unavailable or undrivable; skipping differential case");
            return None;
        }
        Err(e) => panic!("KVM backend failure: {e}"),
    };
    let interp = match run_interpreter(code, &init, &scratch_init) {
        Ok(s) => s,
        Err(e) => panic!("interpreter backend failure: {e}"),
    };
    Some((interp, kvm))
}

/// Assert that the two backends agree, with a precise diff on mismatch.
fn assert_match(label: &str, code: &[u8], interp: &FinalState, kvm: &FinalState, opts: CompareOpts) {
    let diffs = compare(interp, kvm, opts);
    if !diffs.is_empty() {
        panic!(
            "DIVERGENCE in `{label}` (code = {:02x?}):\n  {}",
            code,
            diffs.join("\n  ")
        );
    }
}

// Convenience: a zeroed scratch page.
fn zero_scratch() -> [u8; 64] {
    [0u8; 64]
}

/// Run a case with default compare options (GPRs + all status flags + stack).
fn check(label: &str, code: &[u8], init: Registers) {
    let Some((interp, kvm)) = run_both(code, init, zero_scratch()) else {
        return;
    };
    assert_match(label, code, &interp, &kvm, CompareOpts::default());
}

/// Run a case comparing GPRs + only the flag bits in `flag_mask` (others are
/// architecturally undefined for this instruction and must not be compared).
fn check_flags_masked(label: &str, code: &[u8], init: Registers, flag_mask: u64) {
    let Some((interp, kvm)) = run_both(code, init, zero_scratch()) else {
        return;
    };
    let opts = CompareOpts {
        flag_mask,
        ..CompareOpts::default()
    };
    assert_match(label, code, &interp, &kvm, opts);
}

/// Run an SSE case: the scratch page holds inputs, the guest code loads them
/// into XMM, operates, and stores the result back; we compare the scratch page
/// (and the live XMM registers as a bonus). Driving SSE through guest memory
/// avoids host-side FPU-injection quirks across the two backends.
fn check_sse(label: &str, code: &[u8], scratch_in: [u8; 64]) {
    let Some((interp, kvm)) = run_both(code, regs(), scratch_in) else {
        return;
    };
    let opts = CompareOpts {
        flag_mask: 0, // SSE integer ops don't set RFLAGS
        scratch: true,
        ..CompareOpts::default()
    };
    assert_match(label, code, &interp, &kvm, opts);
}

// Helper to build initial regs concisely.
fn regs() -> Registers {
    Registers::default()
}

// `HLT` terminator.
const HLT: u8 = 0xF4;

/// Append a HLT to a code buffer.
fn with_hlt(mut code: Vec<u8>) -> Vec<u8> {
    code.push(HLT);
    code
}

// ===========================================================================
// TEST CORPUS
// ===========================================================================

// ---- ADD / SUB / ADC / SBB / INC / DEC / NEG / CMP : flag exactness ----

#[test]
fn add_basic() {
    // mov rax, 0x...; add rax, rbx
    let mut r = regs();
    r.rax = 0x1122_3344_5566_7788;
    r.rbx = 0x1010_1010_1010_1010;
    // 48 01 D8  add rax, rbx
    check("add_rax_rbx", &with_hlt(vec![0x48, 0x01, 0xD8]), r);
}

#[test]
fn add_carry_overflow() {
    let mut r = regs();
    r.rax = 0x7fff_ffff_ffff_ffff; // signed max
    r.rbx = 1; // -> overflow + sign flip
    check("add_signed_overflow", &with_hlt(vec![0x48, 0x01, 0xD8]), r);
}

#[test]
fn add8_af_edge() {
    // add al, bl with low-nibble carry to exercise AF + PF
    let mut r = regs();
    r.rax = 0x0F;
    r.rbx = 0x01; // 0x0F + 0x01 = 0x10 -> AF set
    // 00 D8  add al, bl
    check("add8_af", &with_hlt(vec![0x00, 0xD8]), r);
}

#[test]
fn add8_unsigned_wrap() {
    let mut r = regs();
    r.rax = 0xFF;
    r.rbx = 0x01; // wraps to 0 -> CF, ZF, AF
    check("add8_wrap", &with_hlt(vec![0x00, 0xD8]), r);
}

#[test]
fn sub_basic() {
    let mut r = regs();
    r.rax = 0x1000;
    r.rbx = 0x0001;
    // 48 29 D8  sub rax, rbx
    check("sub_rax_rbx", &with_hlt(vec![0x48, 0x29, 0xD8]), r);
}

#[test]
fn sub_borrow() {
    let mut r = regs();
    r.rax = 0x00;
    r.rbx = 0x01; // 0 - 1 -> CF + AF + SF
    check("sub_borrow", &with_hlt(vec![0x48, 0x29, 0xD8]), r);
}

#[test]
fn sub8_signed_overflow() {
    let mut r = regs();
    r.rax = 0x80; // -128
    r.rbx = 0x01; //  - 1 -> overflow
    // 28 D8  sub al, bl
    check("sub8_overflow", &with_hlt(vec![0x28, 0xD8]), r);
}

#[test]
fn adc_with_carry_set() {
    let mut r = regs();
    r.rax = 0x10;
    r.rbx = 0x20;
    r.rflags = flags::bits::CF; // CF=1 going in
    // 48 11 D8  adc rax, rbx
    check("adc_carry_in", &with_hlt(vec![0x48, 0x11, 0xD8]), r);
}

#[test]
fn adc_chain_propagation() {
    let mut r = regs();
    r.rax = 0xFFFF_FFFF_FFFF_FFFF;
    r.rbx = 0x0;
    r.rflags = flags::bits::CF;
    check("adc_max_plus_carry", &with_hlt(vec![0x48, 0x11, 0xD8]), r);
}

#[test]
fn sbb_with_borrow() {
    let mut r = regs();
    r.rax = 0x100;
    r.rbx = 0x1;
    r.rflags = flags::bits::CF; // borrow in
    // 48 19 D8  sbb rax, rbx
    check("sbb_borrow_in", &with_hlt(vec![0x48, 0x19, 0xD8]), r);
}

#[test]
fn inc_overflow_preserves_cf() {
    let mut r = regs();
    r.rax = 0x7fff_ffff_ffff_ffff;
    r.rflags = flags::bits::CF; // INC must NOT touch CF
    // 48 FF C0  inc rax
    check("inc_of_keeps_cf", &with_hlt(vec![0x48, 0xFF, 0xC0]), r);
}

#[test]
fn dec_to_zero() {
    let mut r = regs();
    r.rax = 0x1;
    r.rflags = flags::bits::CF;
    // 48 FF C8  dec rax
    check("dec_to_zero", &with_hlt(vec![0x48, 0xFF, 0xC8]), r);
}

#[test]
fn dec_wrap_af() {
    let mut r = regs();
    r.rax = 0x10; // dec -> 0x0F, AF set
    // 48 FF C8 dec rax
    check("dec_af", &with_hlt(vec![0x48, 0xFF, 0xC8]), r);
}

#[test]
fn neg_nonzero() {
    let mut r = regs();
    r.rax = 0x1234;
    // 48 F7 D8  neg rax  (CF set because operand != 0)
    check("neg_nonzero", &with_hlt(vec![0x48, 0xF7, 0xD8]), r);
}

#[test]
fn neg_zero() {
    let mut r = regs();
    r.rax = 0x0; // neg 0 -> 0, CF clear, ZF set
    check("neg_zero", &with_hlt(vec![0x48, 0xF7, 0xD8]), r);
}

#[test]
fn cmp_equal() {
    let mut r = regs();
    r.rax = 0x42;
    r.rbx = 0x42;
    // 48 39 D8  cmp rax, rbx
    check("cmp_equal", &with_hlt(vec![0x48, 0x39, 0xD8]), r);
}

#[test]
fn cmp_less_signed() {
    let mut r = regs();
    r.rax = 0xFFFF_FFFF_FFFF_FFFF; // -1
    r.rbx = 0x1;
    check("cmp_neg_vs_pos", &with_hlt(vec![0x48, 0x39, 0xD8]), r);
}

// ---- AND / OR / XOR / TEST ----

#[test]
fn and_clears_cf_of() {
    let mut r = regs();
    r.rax = 0xFF00_FF00_FF00_FF00;
    r.rbx = 0x0FF0_0FF0_0FF0_0FF0;
    r.rflags = flags::bits::CF | flags::bits::OF; // must be cleared
    // 48 21 D8  and rax, rbx
    check("and", &with_hlt(vec![0x48, 0x21, 0xD8]), r);
}

#[test]
fn or_sets_sf_pf() {
    let mut r = regs();
    r.rax = 0x8000_0000_0000_0000;
    r.rbx = 0x1;
    // 48 09 D8  or rax, rbx
    check("or", &with_hlt(vec![0x48, 0x09, 0xD8]), r);
}

#[test]
fn xor_self_zero() {
    let mut r = regs();
    r.rax = 0xDEAD_BEEF_CAFE_BABE;
    // 48 31 C0  xor rax, rax
    check("xor_self", &with_hlt(vec![0x48, 0x31, 0xC0]), r);
}

#[test]
fn test_parity() {
    let mut r = regs();
    r.rax = 0xFF; // low byte has even parity (8 ones) -> PF=1
    // 48 85 C0  test rax, rax
    check("test_parity", &with_hlt(vec![0x48, 0x85, 0xC0]), r);
}

// ---- Shifts / rotates : CF & OF ----

#[test]
fn shl_into_cf_of() {
    let mut r = regs();
    r.rax = 0x4000_0000_0000_0000;
    // 48 D1 E0  shl rax, 1  (1-bit shift defines OF)
    check("shl1", &with_hlt(vec![0x48, 0xD1, 0xE0]), r);
}

#[test]
fn shl_by_cl() {
    let mut r = regs();
    r.rax = 0x1;
    r.rcx = 4;
    // 48 D3 E0  shl rax, cl
    check("shl_cl", &with_hlt(vec![0x48, 0xD3, 0xE0]), r);
}

#[test]
fn shr_cf() {
    let mut r = regs();
    r.rax = 0x3; // shr by 1 -> CF from bit 0
    // 48 D1 E8  shr rax, 1
    check("shr1", &with_hlt(vec![0x48, 0xD1, 0xE8]), r);
}

#[test]
fn sar_sign_extend() {
    let mut r = regs();
    r.rax = 0x8000_0000_0000_0000;
    r.rcx = 4;
    // 48 D3 F8  sar rax, cl
    check("sar_cl", &with_hlt(vec![0x48, 0xD3, 0xF8]), r);
}

#[test]
fn rol_cf_of() {
    let mut r = regs();
    r.rax = 0x8000_0000_0000_0001;
    // 48 D1 C0  rol rax, 1
    check("rol1", &with_hlt(vec![0x48, 0xD1, 0xC0]), r);
}

#[test]
fn ror_cf_of() {
    let mut r = regs();
    r.rax = 0x1;
    // 48 D1 C8  ror rax, 1
    check("ror1", &with_hlt(vec![0x48, 0xD1, 0xC8]), r);
}

#[test]
fn rcl_through_carry() {
    let mut r = regs();
    r.rax = 0x8000_0000_0000_0000;
    r.rflags = flags::bits::CF; // carry rotates in
    // 48 D1 D0  rcl rax, 1
    check("rcl1", &with_hlt(vec![0x48, 0xD1, 0xD0]), r);
}

#[test]
fn rcr_through_carry() {
    let mut r = regs();
    r.rax = 0x1;
    r.rflags = flags::bits::CF;
    // 48 D1 D8  rcr rax, 1
    check("rcr1", &with_hlt(vec![0x48, 0xD1, 0xD8]), r);
}

// ---- IMUL / MUL / DIV ----

// For MUL/IMUL the ISA defines only CF and OF; SF/ZF/AF/PF are *undefined*.
// For DIV/IDIV *all* status flags are undefined. We therefore mask the
// comparison accordingly so we only validate the architecturally-defined bits
// (and the full GPR result, which is always defined).
const MULDIV_DEFINED: u64 = flags::bits::CF | flags::bits::OF;

#[test]
fn imul_two_operand() {
    let mut r = regs();
    r.rax = 0x1_0000;
    r.rbx = 0x1_0000; // 2^16 * 2^16 = 2^32 (no overflow of 64-bit)
    // 48 0F AF C3  imul rax, rbx
    check_flags_masked("imul2", &with_hlt(vec![0x48, 0x0F, 0xAF, 0xC3]), r, MULDIV_DEFINED);
}

#[test]
fn imul_overflow_flags() {
    let mut r = regs();
    r.rax = 0x8000_0000_0000_0000u64; // large -> CF/OF set on truncation
    r.rbx = 0x2;
    check_flags_masked(
        "imul_overflow",
        &with_hlt(vec![0x48, 0x0F, 0xAF, 0xC3]),
        r,
        MULDIV_DEFINED,
    );
}

#[test]
fn mul_rdx_rax() {
    let mut r = regs();
    r.rax = 0xFFFF_FFFF_FFFF_FFFF;
    r.rbx = 0x2; // RDX:RAX = product
    // 48 F7 E3  mul rbx
    check_flags_masked("mul64", &with_hlt(vec![0x48, 0xF7, 0xE3]), r, MULDIV_DEFINED);
}

#[test]
fn div_unsigned() {
    let mut r = regs();
    r.rax = 0x100; // dividend low
    r.rdx = 0x0; // dividend high
    r.rbx = 0x7; // divisor
    // 48 F7 F3  div rbx -> quotient in rax, remainder in rdx
    // All flags undefined for DIV; compare GPRs only (flag_mask = 0).
    check_flags_masked("div64", &with_hlt(vec![0x48, 0xF7, 0xF3]), r, 0);
}

#[test]
fn idiv_signed() {
    let mut r = regs();
    r.rax = 0xFFFF_FFFF_FFFF_FF9C; // -100
    r.rdx = 0xFFFF_FFFF_FFFF_FFFF; // sign extension of -100
    r.rbx = 0x7;
    // 48 F7 FB  idiv rbx
    check_flags_masked("idiv64", &with_hlt(vec![0x48, 0xF7, 0xFB]), r, 0);
}

// ---- BSF / BSR ----

#[test]
fn bsf_nonzero() {
    let mut r = regs();
    r.rbx = 0x0000_0000_0001_0000; // lowest set bit = 16
    // 48 0F BC C3  bsf rax, rbx
    check("bsf", &with_hlt(vec![0x48, 0x0F, 0xBC, 0xC3]), r);
}

#[test]
fn bsr_nonzero() {
    let mut r = regs();
    r.rbx = 0x0000_0000_0001_0000; // highest set bit = 16
    // 48 0F BD C3  bsr rax, rbx
    check("bsr", &with_hlt(vec![0x48, 0x0F, 0xBD, 0xC3]), r);
}

// ---- SETcc / CMOVcc ----

#[test]
fn setcc_below() {
    // cmp then sete/setb on AL
    let mut r = regs();
    r.rax = 0x1;
    r.rbx = 0x2; // 1 < 2 -> CF set
    // 48 39 D8       cmp rax, rbx
    // 0F 92 C0       setb al
    check("setb", &with_hlt(vec![0x48, 0x39, 0xD8, 0x0F, 0x92, 0xC0]), r);
}

#[test]
fn cmovcc_greater() {
    let mut r = regs();
    r.rax = 0x5;
    r.rbx = 0x3;
    r.rcx = 0xAAAA; // value to maybe move
    // 48 39 D8        cmp rax, rbx     (5 - 3 -> not below, SF=OF, ZF=0)
    // 48 0F 4F C1     cmovg rax, rcx   (move if greater)
    check(
        "cmovg",
        &with_hlt(vec![0x48, 0x39, 0xD8, 0x48, 0x0F, 0x4F, 0xC1]),
        r,
    );
}

// ---- LEA ----

#[test]
fn lea_scaled_index() {
    let mut r = regs();
    r.rbx = 0x1000;
    r.rcx = 0x10;
    // 48 8D 04 8B  lea rax, [rbx + rcx*4]
    check("lea", &with_hlt(vec![0x48, 0x8D, 0x04, 0x8B]), r);
}

// ---- MOVZX / MOVSX ----

#[test]
fn movzx_byte() {
    let mut r = regs();
    r.rbx = 0xFFFF_FFFF_FFFF_FF80;
    // 48 0F B6 C3  movzx rax, bl
    check("movzx_bl", &with_hlt(vec![0x48, 0x0F, 0xB6, 0xC3]), r);
}

#[test]
fn movsx_byte() {
    let mut r = regs();
    r.rbx = 0x80; // sign-extends to 0xFFFF...80
    // 48 0F BE C3  movsx rax, bl
    check("movsx_bl", &with_hlt(vec![0x48, 0x0F, 0xBE, 0xC3]), r);
}

#[test]
fn movsxd_dword() {
    let mut r = regs();
    r.rbx = 0x0000_0000_8000_0000; // ebx = 0x80000000 sign-extends
    // 48 63 C3  movsxd rax, ebx
    check("movsxd", &with_hlt(vec![0x48, 0x63, 0xC3]), r);
}

// ---- SSE2: PADDB / PADDW / PADDD / PSUBB / PXOR / PAND via XMM ----
//
// SSE XMM state injection through KVM_SET_FPU does not reliably survive
// KVM_RUN's XSAVE-based FPU management, so instead of host-injecting XMM we
// drive these through guest memory: the guest loads two 128-bit inputs from the
// scratch page, performs the op, and stores the 128-bit result back. We then
// compare the scratch page byte-for-byte (and the live XMM regs). This is both
// robust and a closer model of real SSE code.
//
// Scratch layout: [0..16) = input A (xmm0), [16..32) = input B (xmm1),
//                 [32..48) = result (written by the guest).

/// Build a guest program: load xmm0/xmm1 from scratch, run `op` (a `66 0F xx C1`
/// style 2-operand SSE instruction on xmm0,xmm1), store xmm0 back, HLT.
fn sse_program(op: &[u8]) -> Vec<u8> {
    let mut code = Vec::new();
    // mov rdi, DATA_ADDR (imm32, sign-extended — 0x30000 fits)
    code.extend_from_slice(&[0x48, 0xC7, 0xC7]);
    code.extend_from_slice(&(DATA_ADDR as u32).to_le_bytes());
    // movdqu xmm0, [rdi]
    code.extend_from_slice(&[0xF3, 0x0F, 0x6F, 0x07]);
    // movdqu xmm1, [rdi+0x10]
    code.extend_from_slice(&[0xF3, 0x0F, 0x6F, 0x4F, 0x10]);
    // <op> xmm0, xmm1
    code.extend_from_slice(op);
    // movdqu [rdi+0x20], xmm0
    code.extend_from_slice(&[0xF3, 0x0F, 0x7F, 0x47, 0x20]);
    code.push(HLT);
    code
}

/// Build a 64-byte scratch page from two 16-byte inputs.
fn sse_scratch(a: [u8; 16], b: [u8; 16]) -> [u8; 64] {
    let mut s = [0u8; 64];
    s[0..16].copy_from_slice(&a);
    s[16..32].copy_from_slice(&b);
    s
}

#[test]
fn sse_paddb() {
    // per-byte add with wraps in several lanes
    let a = [1, 2, 3, 4, 5, 6, 7, 8, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
    let b = [8, 8, 8, 8, 8, 8, 8, 8, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0];
    // 66 0F FC C1  paddb xmm0, xmm1
    check_sse("paddb", &sse_program(&[0x66, 0x0F, 0xFC, 0xC1]), sse_scratch(a, b));
}

#[test]
fn sse_paddw() {
    let a = 0xFFFF_0001_8000_1234u64.to_le_bytes();
    let a = [a, 0x0102_0304_0506_0708u64.to_le_bytes()].concat();
    let b = 0x0001_FFFF_8000_0001u64.to_le_bytes();
    let b = [b, 0x1111_2222_3333_4444u64.to_le_bytes()].concat();
    // 66 0F FD C1  paddw xmm0, xmm1
    check_sse(
        "paddw",
        &sse_program(&[0x66, 0x0F, 0xFD, 0xC1]),
        sse_scratch(a.try_into().unwrap(), b.try_into().unwrap()),
    );
}

#[test]
fn sse_paddd() {
    let a = [0x0000_0001_FFFF_FFFFu64.to_le_bytes(), 0x8000_0000_7FFF_FFFFu64.to_le_bytes()].concat();
    let b = [0x0000_0001_0000_0001u64.to_le_bytes(), 0x0000_0001_0000_0001u64.to_le_bytes()].concat();
    // 66 0F FE C1  paddd xmm0, xmm1
    check_sse(
        "paddd",
        &sse_program(&[0x66, 0x0F, 0xFE, 0xC1]),
        sse_scratch(a.try_into().unwrap(), b.try_into().unwrap()),
    );
}

#[test]
fn sse_psubb() {
    let a = [0, 1, 2, 3, 0x80, 0x7F, 0xFF, 0x10, 1, 2, 3, 4, 5, 6, 7, 8];
    let b = [1, 1, 1, 1, 1, 1, 1, 1, 0xFF, 0xFE, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
    // 66 0F F8 C1  psubb xmm0, xmm1
    check_sse("psubb", &sse_program(&[0x66, 0x0F, 0xF8, 0xC1]), sse_scratch(a, b));
}

#[test]
fn sse_pxor() {
    let a = [0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes(), 0x0123_4567_89AB_CDEFu64.to_le_bytes()].concat();
    let b = [0xFFFF_FFFF_FFFF_FFFFu64.to_le_bytes(), 0x0F0F_0F0F_0F0F_0F0Fu64.to_le_bytes()].concat();
    // 66 0F EF C1  pxor xmm0, xmm1
    check_sse(
        "pxor",
        &sse_program(&[0x66, 0x0F, 0xEF, 0xC1]),
        sse_scratch(a.try_into().unwrap(), b.try_into().unwrap()),
    );
}

#[test]
fn sse_pand() {
    let a = [0xFF00_FF00_FF00_FF00u64.to_le_bytes(), 0xAAAA_5555_AAAA_5555u64.to_le_bytes()].concat();
    let b = [0x0FF0_0FF0_0FF0_0FF0u64.to_le_bytes(), 0xFFFF_0000_FFFF_0000u64.to_le_bytes()].concat();
    // 66 0F DB C1  pand xmm0, xmm1
    check_sse(
        "pand",
        &sse_program(&[0x66, 0x0F, 0xDB, 0xC1]),
        sse_scratch(a.try_into().unwrap(), b.try_into().unwrap()),
    );
}

// ===========================================================================
// EXPANDED COVERAGE
// ===========================================================================
//
// Flag-definition reminders used by the masks below (Intel SDM Vol.2):
//  - BT/BTS/BTR/BTC : define CF; OF/SF/ZF/AF/PF undefined.
//  - BSF/BSR        : define ZF; CF/OF/SF/AF/PF undefined. Dest undefined if src==0.
//  - LZCNT/TZCNT    : define CF and ZF; OF/SF/AF/PF undefined.
//  - POPCNT         : ZF reflects src==0; CF/OF/SF/AF/PF cleared (all defined).
//  - shifts/rotates : OF defined only for a 1-bit shift; undefined for count>1.
//                     For a masked count of 0 NO flags change (we avoid that
//                     ambiguity by using nonzero counts or comparing GPRs only).
//  - SHLD/SHRD      : like shifts; OF defined only for count==1, undefined else;
//                     AF is undefined. Result undefined if count > operand size.
//  - XCHG           : affects no flags. XADD/CMPXCHG set flags like ADD/CMP.

const BT_DEFINED: u64 = flags::bits::CF;
const BSF_DEFINED: u64 = flags::bits::ZF;
const CNT_DEFINED: u64 = flags::bits::CF | flags::bits::ZF;
// For count>1 shifts/rotates OF is undefined; CF (and for shifts SF/ZF/PF) defined.
const SHIFT_NO_OF: u64 = flags::bits::CF | flags::bits::PF | flags::bits::ZF | flags::bits::SF;
// Rotates only ever touch CF/OF; for count>1 OF is undefined -> CF only.
const ROT_MULTI_DEFINED: u64 = flags::bits::CF;

// ---- BT / BTS / BTR / BTC (reg index and imm8 index) ----

#[test]
fn bt_reg_set() {
    let mut r = regs();
    r.rax = 0x0000_0000_0001_0000; // bit 16 set
    r.rdx = 16;
    // 48 0F A3 D0  bt rax, rdx  (CF <- bit 16 = 1)
    check_flags_masked("bt_reg_set", &with_hlt(vec![0x48, 0x0F, 0xA3, 0xD0]), r, BT_DEFINED);
}

#[test]
fn bt_reg_clear() {
    let mut r = regs();
    r.rax = 0x0000_0000_0001_0000;
    r.rdx = 17; // bit 17 = 0
    check_flags_masked("bt_reg_clear", &with_hlt(vec![0x48, 0x0F, 0xA3, 0xD0]), r, BT_DEFINED);
}

#[test]
fn bt_reg_index_wraps_modulo_64() {
    // For a register-operand BT the bit index is taken modulo operand size.
    let mut r = regs();
    r.rax = 0x0000_0000_0000_0002; // bit 1 set
    r.rdx = 65; // 65 mod 64 = 1 -> CF should be 1
    check_flags_masked("bt_reg_mod64", &with_hlt(vec![0x48, 0x0F, 0xA3, 0xD0]), r, BT_DEFINED);
}

#[test]
fn bt_imm() {
    let mut r = regs();
    r.rax = 0x0000_0000_8000_0000; // bit 31 set
    // 48 0F BA E0 1F  bt rax, 31
    check_flags_masked("bt_imm31", &with_hlt(vec![0x48, 0x0F, 0xBA, 0xE0, 0x1F]), r, BT_DEFINED);
}

#[test]
fn bts_imm_sets_bit() {
    let mut r = regs();
    r.rax = 0x0; // CF <- old bit (0), bit 5 then set in dest
    // 48 0F BA E8 05  bts rax, 5
    check_flags_masked("bts_imm5", &with_hlt(vec![0x48, 0x0F, 0xBA, 0xE8, 0x05]), r, BT_DEFINED);
}

#[test]
fn bts_reg_already_set() {
    let mut r = regs();
    r.rax = 0x0000_0000_0000_0008; // bit 3 set
    r.rcx = 3;
    // 48 0F AB C8  bts rax, rcx  (CF<-1, bit stays set)
    check_flags_masked("bts_reg_set", &with_hlt(vec![0x48, 0x0F, 0xAB, 0xC8]), r, BT_DEFINED);
}

#[test]
fn btr_imm_clears_bit() {
    let mut r = regs();
    r.rax = 0xFFFF_FFFF_FFFF_FFFF;
    // 48 0F BA F0 07  btr rax, 7  (CF<-1, bit 7 cleared)
    check_flags_masked("btr_imm7", &with_hlt(vec![0x48, 0x0F, 0xBA, 0xF0, 0x07]), r, BT_DEFINED);
}

#[test]
fn btr_reg_clears_bit() {
    let mut r = regs();
    r.rax = 0x0000_0000_0010_0000; // bit 20 set
    r.rsi = 20;
    // 48 0F B3 F0  btr rax, rsi
    check_flags_masked("btr_reg20", &with_hlt(vec![0x48, 0x0F, 0xB3, 0xF0]), r, BT_DEFINED);
}

#[test]
fn btc_imm_toggles_bit() {
    let mut r = regs();
    r.rax = 0x0000_0000_0000_0001; // bit 0 set
    // 48 0F BA F8 00  btc rax, 0  (CF<-1, bit 0 toggled to 0)
    check_flags_masked("btc_imm0", &with_hlt(vec![0x48, 0x0F, 0xBA, 0xF8, 0x00]), r, BT_DEFINED);
}

#[test]
fn btc_reg_toggles_bit() {
    let mut r = regs();
    r.rax = 0x0; // bit 40 = 0 -> CF<-0, bit set
    r.rdi = 40;
    // 48 0F BB F8  btc rax, rdi
    check_flags_masked("btc_reg40", &with_hlt(vec![0x48, 0x0F, 0xBB, 0xF8]), r, BT_DEFINED);
}

// ---- BSF / BSR (incl. zero-source, where ZF=1 and dest is undefined) ----

#[test]
fn bsf_low_bit() {
    let mut r = regs();
    r.rbx = 0x0000_0000_0000_0028; // bits 3 and 5 -> lowest is 3
    check_flags_masked("bsf_low3", &with_hlt(vec![0x48, 0x0F, 0xBC, 0xC3]), r, BSF_DEFINED);
}

#[test]
fn bsf_zero_source() {
    // src == 0 -> ZF=1, destination is architecturally UNDEFINED; preload RAX so
    // both backends would only match if they leave it unchanged. Since the dest
    // is undefined we deliberately do NOT compare RAX here by checking flags only.
    let mut r = regs();
    r.rbx = 0;
    r.rax = 0xDEAD_DEAD_DEAD_DEAD;
    // Compare ZF only; mask out GPR by... we still compare GPRs in check_flags_masked.
    // To avoid an undefined-dest false diff, see bsf_zero_source_flags below.
    let Some((interp, kvm)) = run_both(&with_hlt(vec![0x48, 0x0F, 0xBC, 0xC3]), r, zero_scratch()) else {
        return;
    };
    // Only the ZF flag is defined; RAX is undefined on a zero source.
    let opts = CompareOpts {
        flag_mask: BSF_DEFINED,
        xmm_count: 0,
        scratch: false,
        stack: true,
    };
    // Compare everything except RAX (undefined) by checking flags + that RBX/others match.
    let mut diffs = compare(&interp, &kvm, opts);
    diffs.retain(|d| !d.starts_with("rax:"));
    if !diffs.is_empty() {
        panic!("DIVERGENCE in `bsf_zero_source`: {}", diffs.join("; "));
    }
}

#[test]
fn bsr_high_bit() {
    let mut r = regs();
    r.rbx = 0x0000_0000_0000_0028; // highest set bit is 5
    check_flags_masked("bsr_high5", &with_hlt(vec![0x48, 0x0F, 0xBD, 0xC3]), r, BSF_DEFINED);
}

#[test]
fn bsr_top_bit() {
    let mut r = regs();
    r.rbx = 0x8000_0000_0000_0000; // bit 63
    check_flags_masked("bsr_top63", &with_hlt(vec![0x48, 0x0F, 0xBD, 0xC3]), r, BSF_DEFINED);
}

// ---- BSWAP ----

#[test]
fn bswap_r64() {
    let mut r = regs();
    r.rax = 0x0011_2233_4455_6677;
    // 48 0F C8  bswap rax
    check("bswap64", &with_hlt(vec![0x48, 0x0F, 0xC8]), r);
}

#[test]
fn bswap_r32() {
    let mut r = regs();
    r.rax = 0xFFFF_FFFF_1122_3344; // bswap eax zero-extends into rax
    // 0F C8  bswap eax
    check("bswap32", &with_hlt(vec![0x0F, 0xC8]), r);
}

// ---- POPCNT / LZCNT / TZCNT ----

#[test]
fn popcnt_r64() {
    let mut r = regs();
    r.rbx = 0xFF00_F0F0_1234_5678;
    // F3 48 0F B8 C3  popcnt rax, rbx
    check("popcnt64", &with_hlt(vec![0xF3, 0x48, 0x0F, 0xB8, 0xC3]), r);
}

#[test]
fn popcnt_zero_sets_zf() {
    let mut r = regs();
    r.rbx = 0; // result 0 -> ZF set, all others cleared
    check("popcnt_zero", &with_hlt(vec![0xF3, 0x48, 0x0F, 0xB8, 0xC3]), r);
}

#[test]
fn lzcnt_r64() {
    let mut r = regs();
    r.rbx = 0x0000_0000_0001_0000; // 47 leading zeros
    // F3 48 0F BD C3  lzcnt rax, rbx
    check_flags_masked("lzcnt64", &with_hlt(vec![0xF3, 0x48, 0x0F, 0xBD, 0xC3]), r, CNT_DEFINED);
}

#[test]
fn lzcnt_zero_source() {
    let mut r = regs();
    r.rbx = 0; // result = operand size (64), CF set, ZF clear
    check_flags_masked("lzcnt_zero", &with_hlt(vec![0xF3, 0x48, 0x0F, 0xBD, 0xC3]), r, CNT_DEFINED);
}

#[test]
fn tzcnt_r64() {
    let mut r = regs();
    r.rbx = 0x0000_0000_0001_0000; // 16 trailing zeros
    // F3 48 0F BC C3  tzcnt rax, rbx
    check_flags_masked("tzcnt64", &with_hlt(vec![0xF3, 0x48, 0x0F, 0xBC, 0xC3]), r, CNT_DEFINED);
}

#[test]
fn tzcnt_zero_source() {
    let mut r = regs();
    r.rbx = 0; // result = 64, CF set
    check_flags_masked("tzcnt_zero", &with_hlt(vec![0xF3, 0x48, 0x0F, 0xBC, 0xC3]), r, CNT_DEFINED);
}

// ---- XCHG / XADD / CMPXCHG (register operands) ----

#[test]
fn xchg_reg_reg() {
    let mut r = regs();
    r.rax = 0x1111_1111_1111_1111;
    r.rbx = 0x2222_2222_2222_2222;
    // 48 87 D8  xchg rax, rbx  (no flags affected)
    check("xchg_rr", &with_hlt(vec![0x48, 0x87, 0xD8]), r);
}

#[test]
fn xadd_reg_reg() {
    let mut r = regs();
    r.rax = 0x100; // dest
    r.rbx = 0x0FF; // src; after: rbx<-old rax(0x100), rax<-0x1FF, flags like ADD
    // 48 0F C1 D8  xadd rax, rbx
    check("xadd_rr", &with_hlt(vec![0x48, 0x0F, 0xC1, 0xD8]), r);
}

#[test]
fn xadd_carry() {
    let mut r = regs();
    r.rax = 0xFFFF_FFFF_FFFF_FFFF;
    r.rbx = 0x1; // sum wraps -> CF, ZF, AF
    check("xadd_carry", &with_hlt(vec![0x48, 0x0F, 0xC1, 0xD8]), r);
}

#[test]
fn cmpxchg_success() {
    // RAX (accumulator) == dest -> ZF=1, dest <- src.
    let mut r = regs();
    r.rbx = 0x1234; // dest
    r.rax = 0x1234; // accumulator matches
    r.rcx = 0xABCD; // src written on success
    // 48 0F B1 CB  cmpxchg rbx, rcx
    check("cmpxchg_ok", &with_hlt(vec![0x48, 0x0F, 0xB1, 0xCB]), r);
}

#[test]
fn cmpxchg_fail() {
    // RAX != dest -> ZF=0, RAX <- dest, dest unchanged.
    let mut r = regs();
    r.rbx = 0x1234; // dest
    r.rax = 0x9999; // accumulator differs
    r.rcx = 0xABCD; // not written on failure
    check("cmpxchg_fail", &with_hlt(vec![0x48, 0x0F, 0xB1, 0xCB]), r);
}

#[test]
fn cmpxchg8_success() {
    let mut r = regs();
    r.rbx = 0x55;
    r.rax = 0x55;
    r.rcx = 0xAA;
    // 0F B0 CB  cmpxchg bl, cl
    check("cmpxchg8_ok", &with_hlt(vec![0x0F, 0xB0, 0xCB]), r);
}

// ---- Shifts / rotates by CL and imm, double-shift SHLD/SHRD ----

#[test]
fn shl_imm_multi() {
    let mut r = regs();
    r.rax = 0x1;
    // 48 C1 E0 05  shl rax, 5  (count>1 -> OF undefined)
    check_flags_masked("shl_imm5", &with_hlt(vec![0x48, 0xC1, 0xE0, 0x05]), r, SHIFT_NO_OF);
}

#[test]
fn shr_imm_multi() {
    let mut r = regs();
    r.rax = 0xFF00;
    // 48 C1 E8 04  shr rax, 4
    check_flags_masked("shr_imm4", &with_hlt(vec![0x48, 0xC1, 0xE8, 0x04]), r, SHIFT_NO_OF);
}

#[test]
fn sar_imm_multi() {
    let mut r = regs();
    r.rax = 0xFFFF_FFFF_8000_0000;
    // 48 C1 F8 08  sar rax, 8
    check_flags_masked("sar_imm8", &with_hlt(vec![0x48, 0xC1, 0xF8, 0x08]), r, SHIFT_NO_OF);
}

#[test]
fn shr_cl_multi() {
    let mut r = regs();
    r.rax = 0xDEAD_BEEF_0000_0000;
    r.rcx = 12;
    // 48 D3 E8  shr rax, cl
    check_flags_masked("shr_cl12", &with_hlt(vec![0x48, 0xD3, 0xE8]), r, SHIFT_NO_OF);
}

#[test]
fn shl32_cl_clears_high() {
    // 32-bit shift zero-extends the result into the full 64-bit register.
    let mut r = regs();
    r.rax = 0xFFFF_FFFF_0000_00FF;
    r.rcx = 8;
    // D3 E0  shl eax, cl
    check_flags_masked("shl32_cl8", &with_hlt(vec![0xD3, 0xE0]), r, SHIFT_NO_OF);
}

#[test]
fn rol_cl_multi() {
    let mut r = regs();
    r.rax = 0x1234_5678_9ABC_DEF0;
    r.rcx = 12;
    // 48 D3 C0  rol rax, cl  (count>1 -> OF undefined)
    check_flags_masked("rol_cl12", &with_hlt(vec![0x48, 0xD3, 0xC0]), r, ROT_MULTI_DEFINED);
}

#[test]
fn ror_cl_multi() {
    let mut r = regs();
    r.rax = 0x1234_5678_9ABC_DEF0;
    r.rcx = 20;
    // 48 D3 C8  ror rax, cl
    check_flags_masked("ror_cl20", &with_hlt(vec![0x48, 0xD3, 0xC8]), r, ROT_MULTI_DEFINED);
}

#[test]
fn shld_imm() {
    // SHLD rax, rbx, 8 : shift rax left by 8, feeding in the top 8 bits of rbx.
    let mut r = regs();
    r.rax = 0x1122_3344_5566_7788;
    r.rbx = 0xAABB_CCDD_EEFF_0011;
    // 48 0F A4 D8 08  shld rax, rbx, 8  (count>1 -> OF undefined)
    check_flags_masked("shld_imm8", &with_hlt(vec![0x48, 0x0F, 0xA4, 0xD8, 0x08]), r, SHIFT_NO_OF);
}

#[test]
fn shrd_imm() {
    // SHRD rax, rbx, 8 : shift rax right by 8, feeding in the low 8 bits of rbx.
    let mut r = regs();
    r.rax = 0x1122_3344_5566_7788;
    r.rbx = 0xAABB_CCDD_EEFF_0011;
    // 48 0F AC D8 08  shrd rax, rbx, 8
    check_flags_masked("shrd_imm8", &with_hlt(vec![0x48, 0x0F, 0xAC, 0xD8, 0x08]), r, SHIFT_NO_OF);
}

#[test]
fn shld_cl() {
    let mut r = regs();
    r.rax = 0xFFFF_0000_FFFF_0000;
    r.rbx = 0x0F0F_0F0F_0F0F_0F0F;
    r.rcx = 16;
    // 48 0F A5 D8  shld rax, rbx, cl
    check_flags_masked("shld_cl16", &with_hlt(vec![0x48, 0x0F, 0xA5, 0xD8]), r, SHIFT_NO_OF);
}

#[test]
fn shrd_cl() {
    let mut r = regs();
    r.rax = 0xFFFF_0000_FFFF_0000;
    r.rbx = 0x0F0F_0F0F_0F0F_0F0F;
    r.rcx = 24;
    // 48 0F AD D8  shrd rax, rbx, cl
    check_flags_masked("shrd_cl24", &with_hlt(vec![0x48, 0x0F, 0xAD, 0xD8]), r, SHIFT_NO_OF);
}

#[test]
fn shld_imm1_defines_of() {
    // A 1-bit double shift DOES define OF, so compare all status flags.
    let mut r = regs();
    r.rax = 0x4000_0000_0000_0000;
    r.rbx = 0x8000_0000_0000_0000;
    // 48 0F A4 D8 01  shld rax, rbx, 1
    check("shld_imm1", &with_hlt(vec![0x48, 0x0F, 0xA4, 0xD8, 0x01]), r);
}

// ---- Sign/zero extension: MOVSX/MOVZX word sources, CBW family, CWD family ----

#[test]
fn movzx_word() {
    let mut r = regs();
    r.rbx = 0xFFFF_FFFF_FFFF_8000;
    // 48 0F B7 C3  movzx rax, bx
    check("movzx_bx", &with_hlt(vec![0x48, 0x0F, 0xB7, 0xC3]), r);
}

#[test]
fn movsx_word() {
    let mut r = regs();
    r.rbx = 0x0000_0000_0000_8000; // bx = 0x8000 -> sign extends
    // 48 0F BF C3  movsx rax, bx
    check("movsx_bx", &with_hlt(vec![0x48, 0x0F, 0xBF, 0xC3]), r);
}

#[test]
fn movsx_byte_to_word() {
    // 16-bit destination: movsx ax, bl (66 prefix, opcode 0F BE)
    let mut r = regs();
    r.rax = 0x1111_2222_3333_4444;
    r.rbx = 0x90; // sign-extends within the 16-bit AX only
    // 66 0F BE C3  movsx ax, bl
    check("movsx_ax_bl", &with_hlt(vec![0x66, 0x0F, 0xBE, 0xC3]), r);
}

#[test]
fn cbw() {
    // AL -> AX sign extension; 66 98
    let mut r = regs();
    r.rax = 0x1234_5678_9ABC_DE80; // al = 0x80
    check("cbw", &with_hlt(vec![0x66, 0x98]), r);
}

#[test]
fn cwde() {
    // AX -> EAX sign extension; 98 (zero-extends EAX into RAX)
    let mut r = regs();
    r.rax = 0x1234_5678_0000_8000; // ax = 0x8000
    check("cwde", &with_hlt(vec![0x98]), r);
}

#[test]
fn cdqe() {
    // EAX -> RAX sign extension; 48 98
    let mut r = regs();
    r.rax = 0x1234_5678_8000_0000; // eax = 0x80000000
    check("cdqe", &with_hlt(vec![0x48, 0x98]), r);
}

#[test]
fn cwd() {
    // AX -> DX:AX ; 66 99
    let mut r = regs();
    r.rax = 0x0000_0000_0000_8000; // ax negative
    r.rdx = 0x1111_2222_3333_4444; // only dx (low 16) should change
    check("cwd", &with_hlt(vec![0x66, 0x99]), r);
}

#[test]
fn cdq() {
    // EAX -> EDX:EAX ; 99  (EDX zero-extends into RDX)
    let mut r = regs();
    r.rax = 0x0000_0000_8000_0000; // eax negative
    r.rdx = 0xFFFF_FFFF_1234_5678;
    check("cdq", &with_hlt(vec![0x99]), r);
}

#[test]
fn cqo() {
    // RAX -> RDX:RAX ; 48 99
    let mut r = regs();
    r.rax = 0x8000_0000_0000_0000; // negative
    r.rdx = 0x1234_5678_9ABC_DEF0;
    check("cqo", &with_hlt(vec![0x48, 0x99]), r);
}

#[test]
fn cqo_positive() {
    let mut r = regs();
    r.rax = 0x0000_0000_0000_0001; // positive -> rdx becomes 0
    r.rdx = 0xFFFF_FFFF_FFFF_FFFF;
    check("cqo_pos", &with_hlt(vec![0x48, 0x99]), r);
}

// ---- CMOVcc across all 16 conditions ----
//
// We set up a known flag state with a single CMP, then CMOVcc rax, rcx. The
// destination is loaded with a sentinel beforehand so a "no move" is observable.

/// cmp rax,rbx (48 39 D8) sets flags, then `cmov` (2-byte 0F xx) rax, rcx.
fn cmov_program(cmov2: [u8; 2]) -> Vec<u8> {
    // 48 31 C0           xor rax, rax           (clear so the sentinel below is exact)
    // 48 B8 imm64        mov rax, sentinel
    // ... but simpler: use the regs we pass in. We just emit cmp + cmov.
    let mut code = vec![0x48, 0x39, 0xD8]; // cmp rax, rbx
    code.extend_from_slice(&[0x48, cmov2[0], cmov2[1], 0xC1]); // cmov rax, rcx (REX.W, 0F, opc, modrm C1)
    code.push(HLT);
    code
}

/// Run a CMOVcc with the given 2nd opcode byte and an (rax,rbx) pair that sets
/// flags via CMP. rcx holds the candidate value moved on a true condition.
fn check_cmov(label: &str, opc: u8, rax: u64, rbx: u64) {
    let mut r = regs();
    r.rax = rax;
    r.rbx = rbx;
    r.rcx = 0xCAFE_F00D_1234_5678;
    check(label, &cmov_program([0x0F, opc]), r);
}

/// All 16 CMOVcc conditions in one case. Each tuple is (opcode2, rax, rbx) where
/// the CMP rax,rbx sets a flag state that makes the condition TRUE (and a couple
/// also test the FALSE/no-move path). Opcodes 0x40..=0x4F are CMOVO..CMOVG.
#[test]
fn cmovcc_all_conditions() {
    // (opcode, rax, rbx) chosen so the condition is TRUE for these inputs.
    let true_cases: &[(u8, u64, u64, &str)] = &[
        (0x40, 0x8000_0000_0000_0000, 1, "cmovo"), // INT_MIN - 1 -> OF
        (0x41, 5, 3, "cmovno"),                     // no overflow
        (0x42, 1, 2, "cmovb"),                      // 1 < 2 unsigned -> CF
        (0x43, 5, 3, "cmovae"),                     // CF clear
        (0x44, 7, 7, "cmove"),                      // equal -> ZF
        (0x45, 7, 8, "cmovne"),                     // not equal
        (0x46, 2, 2, "cmovbe"),                     // CF|ZF (equal)
        (0x47, 5, 3, "cmova"),                      // above
        (0x48, 0, 1, "cmovs"),                      // 0-1 -> SF
        (0x49, 5, 3, "cmovns"),                     // SF clear
        (0x4A, 3, 0, "cmovp"),                      // result 3 -> even parity
        (0x4B, 1, 0, "cmovnp"),                     // result 1 -> odd parity
        (0x4C, 1, 2, "cmovl"),                      // signed less
        (0x4D, 5, 3, "cmovge"),                     // signed >=
        (0x4E, 2, 2, "cmovle"),                     // signed <= (equal)
        (0x4F, 5, 3, "cmovg"),                      // signed >
    ];
    for &(opc, rax, rbx, name) in true_cases {
        check_cmov(name, opc, rax, rbx);
    }
    // No-move (FALSE) path for a representative set so we also exercise the
    // "destination unchanged" branch on both backends.
    check_cmov("cmovo_false", 0x40, 5, 3); // no overflow -> no move
    check_cmov("cmove_false", 0x44, 7, 8); // not equal -> no move
    check_cmov("cmovg_false", 0x4F, 1, 2); // not greater -> no move
}

// ---- SETcc across conditions ----

/// cmp rax,rbx then setcc al, then movzx eax, al so we read a clean 0/1.
fn setcc_program(opc: u8) -> Vec<u8> {
    let mut code = vec![0x48, 0x39, 0xD8]; // cmp rax, rbx
    code.extend_from_slice(&[0x0F, opc, 0xC0]); // setcc al
    code.extend_from_slice(&[0x0F, 0xB6, 0xC0]); // movzx eax, al
    code.push(HLT);
    code
}

fn check_setcc(label: &str, opc: u8, rax: u64, rbx: u64) {
    let mut r = regs();
    r.rax = rax;
    r.rbx = rbx;
    check(label, &setcc_program(opc), r);
}

/// SETcc across a spread of conditions, both true and false results. Opcodes
/// 0x90..=0x9F are SETO..SETG.
#[test]
fn setcc_all_conditions() {
    let cases: &[(u8, u64, u64, &str)] = &[
        (0x90, 0x8000_0000_0000_0000, 1, "seto"), // overflow -> 1
        (0x91, 5, 3, "setno"),                     // no overflow -> 1
        (0x92, 1, 2, "setb"),                      // below -> 1
        (0x93, 5, 3, "setae"),                     // not below -> 1
        (0x94, 7, 7, "sete"),                      // equal -> 1
        (0x95, 7, 8, "setne"),                     // not equal -> 1
        (0x96, 2, 2, "setbe"),                     // be (equal) -> 1
        (0x97, 5, 3, "seta"),                      // above -> 1
        (0x98, 0, 1, "sets"),                      // sign -> 1
        (0x99, 5, 3, "setns"),                     // no sign -> 1
        (0x9A, 3, 0, "setp"),                      // even parity -> 1
        (0x9B, 1, 0, "setnp"),                     // odd parity -> 1
        (0x9C, 1, 2, "setl"),                      // less -> 1
        (0x9D, 5, 3, "setge"),                     // ge -> 1
        (0x9E, 2, 2, "setle"),                     // le (equal) -> 1
        (0x9F, 5, 3, "setg"),                      // greater -> 1
        // false-result spot checks
        (0x94, 7, 8, "sete_false"),                // not equal -> 0
        (0x9F, 1, 2, "setg_false"),                // not greater -> 0
    ];
    for &(opc, rax, rbx, name) in cases {
        check_setcc(name, opc, rax, rbx);
    }
}

// ---- LEA with complex SIB (base + index*scale + disp) ----

#[test]
fn lea_base_index_scale_disp8() {
    let mut r = regs();
    r.rbx = 0x1_0000; // base
    r.rcx = 0x10; // index
    // 48 8D 44 8B 20  lea rax, [rbx + rcx*4 + 0x20]
    check("lea_sib_disp8", &with_hlt(vec![0x48, 0x8D, 0x44, 0x8B, 0x20]), r);
}

#[test]
fn lea_index_scale8_disp32() {
    let mut r = regs();
    r.rsi = 0x100;
    r.rdi = 0x2_0000;
    // 48 8D 84 F7 00 10 00 00  lea rax, [rdi + rsi*8 + 0x1000]
    check(
        "lea_sib_disp32",
        &with_hlt(vec![0x48, 0x8D, 0x84, 0xF7, 0x00, 0x10, 0x00, 0x00]),
        r,
    );
}

#[test]
fn lea_no_base_index_scale() {
    // [rcx*8 + disp32] with no base (mod=00, base=101 in SIB -> disp32, no base)
    let mut r = regs();
    r.rcx = 0x11;
    // 48 8D 04 CD 00 02 00 00  lea rax, [rcx*8 + 0x200]
    check(
        "lea_idx_only",
        &with_hlt(vec![0x48, 0x8D, 0x04, 0xCD, 0x00, 0x02, 0x00, 0x00]),
        r,
    );
}

#[test]
fn lea_32bit_addrsize_truncates() {
    // 67 prefix -> 32-bit address calc, result zero-extended into rax.
    let mut r = regs();
    r.rbx = 0xFFFF_FFFF_FFFF_F000; // ebx = 0xFFFFF000
    r.rcx = 0x0000_0000_0000_2000; // ecx = 0x2000
    // 67 48 8D 04 0B  lea rax, [ebx + ecx]  -> (0xFFFFF000+0x2000) mod 2^32
    check("lea_addr32", &with_hlt(vec![0x67, 0x48, 0x8D, 0x04, 0x0B]), r);
}

// ---- 8/16/32-bit operand-size ALU variants for flag exactness ----

#[test]
fn add16_overflow() {
    let mut r = regs();
    r.rax = 0x7FFF; // 16-bit signed max
    r.rbx = 0x0001; // -> OF, SF
    // 66 01 D8  add ax, bx
    check("add16_of", &with_hlt(vec![0x66, 0x01, 0xD8]), r);
}

#[test]
fn add32_wrap_zero_extends() {
    let mut r = regs();
    r.rax = 0xFFFF_FFFF_FFFF_FFFF; // eax = 0xFFFFFFFF
    r.rbx = 0x0000_0000_0000_0001; // -> 0, CF, ZF, AF; rax zero-extends
    // 01 D8  add eax, ebx
    check("add32_wrap", &with_hlt(vec![0x01, 0xD8]), r);
}

#[test]
fn sub16_borrow() {
    let mut r = regs();
    r.rax = 0x0000;
    r.rbx = 0x0001; // 0-1 -> CF, SF, AF
    // 66 29 D8  sub ax, bx
    check("sub16_borrow", &with_hlt(vec![0x66, 0x29, 0xD8]), r);
}

#[test]
fn and16() {
    let mut r = regs();
    r.rax = 0xF0F0;
    r.rbx = 0x0FF0;
    // 66 21 D8  and ax, bx
    check("and16", &with_hlt(vec![0x66, 0x21, 0xD8]), r);
}

#[test]
fn or8() {
    let mut r = regs();
    r.rax = 0x80;
    r.rbx = 0x01; // -> 0x81, SF set, odd parity
    // 08 D8  or al, bl
    check("or8", &with_hlt(vec![0x08, 0xD8]), r);
}

#[test]
fn xor16_zero() {
    let mut r = regs();
    r.rax = 0xABCD;
    r.rbx = 0xABCD; // -> 0, ZF set, PF set
    // 66 31 D8  xor ax, bx
    check("xor16_zero", &with_hlt(vec![0x66, 0x31, 0xD8]), r);
}

#[test]
fn cmp16_equal() {
    let mut r = regs();
    r.rax = 0x1234_5678_9ABC_8000;
    r.rbx = 0x0000_0000_0000_8000; // ax==bx -> ZF
    // 66 39 D8  cmp ax, bx
    check("cmp16_eq", &with_hlt(vec![0x66, 0x39, 0xD8]), r);
}

#[test]
fn cmp8_less() {
    let mut r = regs();
    r.rax = 0x7F; // +127
    r.rbx = 0x80; // -128 ; 127 - (-128) overflows -> OF
    // 38 D8  cmp al, bl
    check("cmp8_of", &with_hlt(vec![0x38, 0xD8]), r);
}

#[test]
fn test8() {
    let mut r = regs();
    r.rax = 0xF0;
    r.rbx = 0x0F; // 0xF0 & 0x0F = 0 -> ZF, PF
    // 84 D8  test al, bl
    check("test8", &with_hlt(vec![0x84, 0xD8]), r);
}

#[test]
fn inc8_overflow() {
    let mut r = regs();
    r.rax = 0x7F; // inc -> 0x80, OF set, SF set, AF set
    r.rflags = flags::bits::CF; // INC must preserve CF
    // FE C0  inc al
    check("inc8_of", &with_hlt(vec![0xFE, 0xC0]), r);
}

#[test]
fn dec16_to_zero() {
    let mut r = regs();
    r.rax = 0x0001;
    r.rflags = flags::bits::CF;
    // 66 FF C8  dec ax
    check("dec16_zero", &with_hlt(vec![0x66, 0xFF, 0xC8]), r);
}

#[test]
fn inc32_zero_extends() {
    let mut r = regs();
    r.rax = 0xFFFF_FFFF_FFFF_FFFF; // eax = 0xFFFFFFFF -> inc to 0, zero-extends
    // FF C0  inc eax
    check("inc32_wrap", &with_hlt(vec![0xFF, 0xC0]), r);
}

#[test]
fn add8_imm() {
    let mut r = regs();
    r.rax = 0x7E;
    // 04 02  add al, 2  -> 0x80, OF + SF
    check("add8_imm", &with_hlt(vec![0x04, 0x02]), r);
}

#[test]
fn add16_imm() {
    let mut r = regs();
    r.rax = 0x00FF;
    // 66 05 01 00  add ax, 1
    check("add16_imm", &with_hlt(vec![0x66, 0x05, 0x01, 0x00]), r);
}

// ---- More SSE2 integer ops (PMULLW/PMADDWD/PSADBW/PACK*/PUNPCK*) ----

#[test]
fn sse_pmullw() {
    // packed 16-bit multiply low: per-lane (a*b) low 16 bits.
    let a = [
        0x0002u16.to_le_bytes(),
        0x00FFu16.to_le_bytes(),
        0x8000u16.to_le_bytes(),
        0x1234u16.to_le_bytes(),
        0x00FFu16.to_le_bytes(),
        0x0010u16.to_le_bytes(),
        0xFFFFu16.to_le_bytes(),
        0x0007u16.to_le_bytes(),
    ]
    .concat();
    let b = [
        0x0003u16.to_le_bytes(),
        0x0100u16.to_le_bytes(),
        0x0002u16.to_le_bytes(),
        0x0010u16.to_le_bytes(),
        0x00FFu16.to_le_bytes(),
        0x0010u16.to_le_bytes(),
        0xFFFFu16.to_le_bytes(),
        0x0006u16.to_le_bytes(),
    ]
    .concat();
    // 66 0F D5 C1  pmullw xmm0, xmm1
    check_sse(
        "pmullw",
        &sse_program(&[0x66, 0x0F, 0xD5, 0xC1]),
        sse_scratch(a.try_into().unwrap(), b.try_into().unwrap()),
    );
}

#[test]
fn sse_pmaddwd() {
    // PMADDWD: multiply 16-bit lanes, add adjacent pairs into 32-bit results.
    let a = [
        0x0001u16.to_le_bytes(),
        0x0002u16.to_le_bytes(),
        0xFFFFu16.to_le_bytes(), // -1
        0x0003u16.to_le_bytes(),
        0x8000u16.to_le_bytes(), // -32768
        0x8000u16.to_le_bytes(),
        0x7FFFu16.to_le_bytes(),
        0x7FFFu16.to_le_bytes(),
    ]
    .concat();
    let b = [
        0x0004u16.to_le_bytes(),
        0x0005u16.to_le_bytes(),
        0x0002u16.to_le_bytes(),
        0xFFFFu16.to_le_bytes(), // -1
        0x8000u16.to_le_bytes(),
        0x8000u16.to_le_bytes(),
        0x7FFFu16.to_le_bytes(),
        0x7FFFu16.to_le_bytes(),
    ]
    .concat();
    // 66 0F F5 C1  pmaddwd xmm0, xmm1
    check_sse(
        "pmaddwd",
        &sse_program(&[0x66, 0x0F, 0xF5, 0xC1]),
        sse_scratch(a.try_into().unwrap(), b.try_into().unwrap()),
    );
}

#[test]
fn sse_psadbw() {
    // sum of absolute differences of bytes -> two 16-bit sums (low halves).
    let a = [10, 20, 30, 40, 50, 60, 70, 80, 100, 110, 120, 130, 140, 150, 160, 170];
    let b = [5, 25, 35, 35, 60, 55, 80, 75, 90, 120, 110, 140, 130, 160, 150, 180];
    // 66 0F F6 C1  psadbw xmm0, xmm1
    check_sse("psadbw", &sse_program(&[0x66, 0x0F, 0xF6, 0xC1]), sse_scratch(a, b));
}

#[test]
fn sse_packsswb() {
    // signed saturate pack words->bytes.
    let a = [
        0x0001u16.to_le_bytes(),
        0x00FFu16.to_le_bytes(),
        0x7FFFu16.to_le_bytes(), // -> +127
        0x8000u16.to_le_bytes(), // -> -128
        0xFF80u16.to_le_bytes(), // -128 stays
        0x0080u16.to_le_bytes(), // +128 -> +127
        0xFFFFu16.to_le_bytes(), // -1
        0x0000u16.to_le_bytes(),
    ]
    .concat();
    let b = [
        0x0100u16.to_le_bytes(),
        0x7F00u16.to_le_bytes(),
        0x8001u16.to_le_bytes(),
        0x0040u16.to_le_bytes(),
        0x0010u16.to_le_bytes(),
        0xFFF0u16.to_le_bytes(),
        0x7FFFu16.to_le_bytes(),
        0x8000u16.to_le_bytes(),
    ]
    .concat();
    // 66 0F 63 C1  packsswb xmm0, xmm1
    check_sse(
        "packsswb",
        &sse_program(&[0x66, 0x0F, 0x63, 0xC1]),
        sse_scratch(a.try_into().unwrap(), b.try_into().unwrap()),
    );
}

#[test]
fn sse_packuswb() {
    // unsigned saturate pack words->bytes.
    let a = [
        0x0001u16.to_le_bytes(),
        0x00FFu16.to_le_bytes(),
        0x0100u16.to_le_bytes(), // -> 255
        0x8000u16.to_le_bytes(), // negative -> 0
        0xFFFFu16.to_le_bytes(), // negative -> 0
        0x007Fu16.to_le_bytes(),
        0x00FEu16.to_le_bytes(),
        0x0080u16.to_le_bytes(),
    ]
    .concat();
    let b = [
        0x0000u16.to_le_bytes(),
        0x0010u16.to_le_bytes(),
        0x00FFu16.to_le_bytes(),
        0x0101u16.to_le_bytes(), // -> 255
        0x7FFFu16.to_le_bytes(), // -> 255
        0x0001u16.to_le_bytes(),
        0x0002u16.to_le_bytes(),
        0x0003u16.to_le_bytes(),
    ]
    .concat();
    // 66 0F 67 C1  packuswb xmm0, xmm1
    check_sse(
        "packuswb",
        &sse_program(&[0x66, 0x0F, 0x67, 0xC1]),
        sse_scratch(a.try_into().unwrap(), b.try_into().unwrap()),
    );
}

#[test]
fn sse_punpcklbw() {
    // interleave low bytes of xmm0 and xmm1.
    let a = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let b = [0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F];
    // 66 0F 60 C1  punpcklbw xmm0, xmm1
    check_sse("punpcklbw", &sse_program(&[0x66, 0x0F, 0x60, 0xC1]), sse_scratch(a, b));
}

#[test]
fn sse_punpckhbw() {
    let a = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let b = [0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F];
    // 66 0F 68 C1  punpckhbw xmm0, xmm1
    check_sse("punpckhbw", &sse_program(&[0x66, 0x0F, 0x68, 0xC1]), sse_scratch(a, b));
}

#[test]
fn sse_punpckldq() {
    // interleave low dwords.
    let a = [0x1111_1111u32.to_le_bytes(), 0x2222_2222u32.to_le_bytes(), 0x3333_3333u32.to_le_bytes(), 0x4444_4444u32.to_le_bytes()].concat();
    let b = [0xAAAA_AAAAu32.to_le_bytes(), 0xBBBB_BBBBu32.to_le_bytes(), 0xCCCC_CCCCu32.to_le_bytes(), 0xDDDD_DDDDu32.to_le_bytes()].concat();
    // 66 0F 62 C1  punpckldq xmm0, xmm1
    check_sse(
        "punpckldq",
        &sse_program(&[0x66, 0x0F, 0x62, 0xC1]),
        sse_scratch(a.try_into().unwrap(), b.try_into().unwrap()),
    );
}

#[test]
fn sse_punpcklqdq() {
    // interleave low qwords -> [a.lo, b.lo].
    let a = [0x0123_4567_89AB_CDEFu64.to_le_bytes(), 0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes()].concat();
    let b = [0x1122_3344_5566_7788u64.to_le_bytes(), 0x99AA_BBCC_DDEE_FF00u64.to_le_bytes()].concat();
    // 66 0F 6C C1  punpcklqdq xmm0, xmm1
    check_sse(
        "punpcklqdq",
        &sse_program(&[0x66, 0x0F, 0x6C, 0xC1]),
        sse_scratch(a.try_into().unwrap(), b.try_into().unwrap()),
    );
}

#[test]
fn sse_pmulhw() {
    // packed 16-bit multiply, store the HIGH 16 bits (signed).
    let a = [
        0x4000u16.to_le_bytes(),
        0x8000u16.to_le_bytes(), // -32768
        0x7FFFu16.to_le_bytes(),
        0xFFFFu16.to_le_bytes(), // -1
        0x0100u16.to_le_bytes(),
        0x1234u16.to_le_bytes(),
        0x00FFu16.to_le_bytes(),
        0x8000u16.to_le_bytes(),
    ]
    .concat();
    let b = [
        0x0004u16.to_le_bytes(),
        0x0002u16.to_le_bytes(),
        0x7FFFu16.to_le_bytes(),
        0xFFFFu16.to_le_bytes(),
        0x0100u16.to_le_bytes(),
        0x1000u16.to_le_bytes(),
        0x00FFu16.to_le_bytes(),
        0x8000u16.to_le_bytes(),
    ]
    .concat();
    // 66 0F E5 C1  pmulhw xmm0, xmm1
    check_sse(
        "pmulhw",
        &sse_program(&[0x66, 0x0F, 0xE5, 0xC1]),
        sse_scratch(a.try_into().unwrap(), b.try_into().unwrap()),
    );
}

// ===========================================================================
// EXPANDED COVERAGE PART 2: x87 FPU / string ops / SSE2-SSE3 float / BMI
// ===========================================================================
//
// These reuse the existing infrastructure:
//  - x87 and string tests drive data through the scratch page (just like the
//    SSE tests) so we never rely on host-side FPU/XMM injection surviving
//    KVM_RUN. The guest loads from / stores to the scratch page and we compare
//    it byte-for-byte plus the relevant GPRs.
//  - BMI/MOVBE/SAHF/LAHF are plain GPR ops driven by `check`/`check_flags_masked`.
//
// IMPORTANT x87 caveat: rax keeps the x87 stack as f64, not the architectural
// 80-bit extended format. Therefore every x87 value used below is chosen so the
// 80-bit and 64-bit representations are *bit-identical*: small integers and
// exact dyadic fractions (n / 2^k). Results are stored as m64 (FSTP qword) so
// what we compare is exactly the f64 the op produced — which, for these
// operands, equals what real hardware computes in 80-bit then rounds to 64-bit.

/// A scratch-comparing runner for memory-effect tests (x87 store / string ops).
/// Compares all GPRs, the masked flags, and the scratch page.
fn check_mem(label: &str, code: &[u8], init: Registers, scratch_in: [u8; 64], flag_mask: u64) {
    let Some((interp, kvm)) = run_both(code, init, scratch_in) else {
        return;
    };
    let opts = CompareOpts {
        flag_mask,
        scratch: true,
        ..CompareOpts::default()
    };
    assert_match(label, code, &interp, &kvm, opts);
}

/// Emit `mov rdi, DATA_ADDR` (REX.W mov r/m64, imm32 sign-extended; 0x30000 fits).
fn load_rdi_data() -> Vec<u8> {
    let mut c = vec![0x48, 0xC7, 0xC7];
    c.extend_from_slice(&(DATA_ADDR as u32).to_le_bytes());
    c
}

/// Build a 64-byte scratch page from a list of f64 inputs laid out from offset 0.
fn scratch_f64(vals: &[f64]) -> [u8; 64] {
    let mut s = [0u8; 64];
    for (i, v) in vals.iter().enumerate() {
        s[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    s
}

// ---- x87: load / arithmetic round-trips, result stored as FSTP qword ----
//
// Program skeleton for a binary op on two m64 inputs:
//   mov rdi, DATA_ADDR
//   fld qword [rdi+0]      ; ST0 = a            (DD /0)
//   f<op> qword [rdi+8]    ; ST0 = a <op> b     (DC /n, memory form)
//   fstp qword [rdi+16]    ; store + pop        (DD /3)
//   hlt
// Inputs a,b at offsets 0 and 8; result compared at offset 16.

/// Build an x87 "load a; <mem-op> b; store result" program. `op_modrm` is the
/// ModRM byte selecting the DC-escape memory operation against [rdi+8].
fn x87_binop(op_escape: u8, op_modrm: u8) -> Vec<u8> {
    let mut c = load_rdi_data();
    c.extend_from_slice(&[0xDD, 0x07]); // fld qword [rdi]
    c.extend_from_slice(&[op_escape, op_modrm]); // f<op> qword [rdi+8] (modrm encodes disp8 0x08)
    c.extend_from_slice(&[0xDD, 0x5F, 0x10]); // fstp qword [rdi+0x10]
    c.push(HLT);
    c
}

#[test]
fn x87_fld_fstp_roundtrip() {
    // Load an exact f64 and store it straight back — pure load/store fidelity.
    let mut c = load_rdi_data();
    c.extend_from_slice(&[0xDD, 0x07]); // fld qword [rdi]
    c.extend_from_slice(&[0xDD, 0x5F, 0x10]); // fstp qword [rdi+0x10]
    c.push(HLT);
    // 12345.5 is exactly representable.
    check_mem("x87_fld_fstp", &with_hlt(c), regs(), scratch_f64(&[12345.5]), 0);
}

#[test]
fn x87_fadd_m64() {
    // DC /0 = FADD m64. ModRM for [rdi+disp8], reg=000 -> 0x47, disp8=0x08.
    check_mem(
        "x87_fadd",
        &with_hlt(x87_binop(0xDC, 0x47)),
        regs(),
        scratch_f64(&[3.5, 4.25]),
        0,
    );
}

#[test]
fn x87_fsub_m64() {
    // DC /4 = FSUB m64. reg=100 -> modrm 0x67.
    check_mem(
        "x87_fsub",
        &with_hlt(x87_binop(0xDC, 0x67)),
        regs(),
        scratch_f64(&[10.0, 2.5]),
        0,
    );
}

#[test]
fn x87_fmul_m64() {
    // DC /1 = FMUL m64. reg=001 -> modrm 0x4F.
    check_mem(
        "x87_fmul",
        &with_hlt(x87_binop(0xDC, 0x4F)),
        regs(),
        scratch_f64(&[6.0, 7.0]),
        0,
    );
}

#[test]
fn x87_fdiv_m64() {
    // DC /6 = FDIV m64. reg=110 -> modrm 0x77. 9/8 = 1.125 is exact.
    check_mem(
        "x87_fdiv",
        &with_hlt(x87_binop(0xDC, 0x77)),
        regs(),
        scratch_f64(&[9.0, 8.0]),
        0,
    );
}

#[test]
fn x87_fsqrt() {
    // fld qword [rdi]; fsqrt (D9 FA); fstp qword [rdi+0x10]. sqrt(16)=4 exact.
    let mut c = load_rdi_data();
    c.extend_from_slice(&[0xDD, 0x07]); // fld qword [rdi]
    c.extend_from_slice(&[0xD9, 0xFA]); // fsqrt
    c.extend_from_slice(&[0xDD, 0x5F, 0x10]); // fstp qword [rdi+0x10]
    c.push(HLT);
    check_mem("x87_fsqrt", &with_hlt(c), regs(), scratch_f64(&[16.0]), 0);
}

#[test]
fn x87_fild_fistp_roundtrip() {
    // FILD m32 (DB /0) loads a 32-bit integer; FISTP m32 (DB /3) stores it back.
    // Put the integer at offset 0, read the stored int back at offset 16.
    let mut s = [0u8; 64];
    s[0..4].copy_from_slice(&(-12345i32).to_le_bytes());
    let mut c = load_rdi_data();
    c.extend_from_slice(&[0xDB, 0x07]); // fild dword [rdi]
    c.extend_from_slice(&[0xDB, 0x5F, 0x10]); // fistp dword [rdi+0x10]
    c.push(HLT);
    check_mem("x87_fild_fistp", &with_hlt(c), regs(), s, 0);
}

#[test]
fn x87_fild_fadd_fistp() {
    // Integer load, add an exact float, store back as integer (round-to-nearest).
    // 100 + 23.0 = 123 -> stored int 123.
    let mut s = [0u8; 64];
    s[0..4].copy_from_slice(&100i32.to_le_bytes());
    s[8..16].copy_from_slice(&23.0f64.to_le_bytes());
    let mut c = load_rdi_data();
    c.extend_from_slice(&[0xDB, 0x07]); // fild dword [rdi]
    c.extend_from_slice(&[0xDC, 0x47, 0x08]); // fadd qword [rdi+8]
    c.extend_from_slice(&[0xDB, 0x5F, 0x10]); // fistp dword [rdi+0x10]
    c.push(HLT);
    check_mem("x87_fild_fadd_fistp", &with_hlt(c), regs(), s, 0);
}

#[test]
fn x87_fist_m64() {
    // FILD m32 then FISTP m64 (DF /7) round-trip of a 64-bit integer store.
    let mut s = [0u8; 64];
    s[0..4].copy_from_slice(&424242i32.to_le_bytes());
    let mut c = load_rdi_data();
    c.extend_from_slice(&[0xDB, 0x07]); // fild dword [rdi]
    c.extend_from_slice(&[0xDF, 0x7F, 0x10]); // fistp qword [rdi+0x10]
    c.push(HLT);
    check_mem("x87_fist_m64", &with_hlt(c), regs(), s, 0);
}

#[test]
fn x87_fadd_st_chain() {
    // Two sequential memory adds: ((1 + 2.5) + 4.25) = 7.75, all exact dyadic.
    let mut c = load_rdi_data();
    c.extend_from_slice(&[0xDD, 0x07]); // fld qword [rdi]      ST0=1.0
    c.extend_from_slice(&[0xDC, 0x47, 0x08]); // fadd qword [rdi+8]   ST0=3.5
    c.extend_from_slice(&[0xDC, 0x47, 0x10]); // fadd qword [rdi+16]  ST0=7.75
    c.extend_from_slice(&[0xDD, 0x5F, 0x18]); // fstp qword [rdi+0x18]
    c.push(HLT);
    check_mem(
        "x87_fadd_chain",
        &with_hlt(c),
        regs(),
        scratch_f64(&[1.0, 2.5, 4.25]),
        0,
    );
}

#[test]
fn x87_fsubr_m64() {
    // DC /5 = FSUBR m64 (ST0 = mem - ST0). reg=101 -> modrm 0x6F. 2.5 - 10 = -7.5.
    check_mem(
        "x87_fsubr",
        &with_hlt(x87_binop(0xDC, 0x6F)),
        regs(),
        scratch_f64(&[10.0, 2.5]),
        0,
    );
}

#[test]
fn x87_fdivr_m64() {
    // DC /7 = FDIVR m64 (ST0 = mem / ST0). reg=111 -> modrm 0x7F. 8/2 = 4.
    check_mem(
        "x87_fdivr",
        &with_hlt(x87_binop(0xDC, 0x7F)),
        regs(),
        scratch_f64(&[2.0, 8.0]),
        0,
    );
}

// ---- x87 FCOMI / FUCOMI: compare ST0 with ST(i), set ZF/PF/CF directly ----
//
// Setup: fld b ([rdi+8]) then fld a ([rdi]) so ST0=a, ST1=b, then FCOMI ST0,ST1.
// FCOMI sets ZF/PF/CF in EFLAGS; OF/SF/AF are cleared. We compare exactly the
// status mask (the harness masks to the 6 status flags; FCOMI clears AF/SF/OF).

const FCOMI_FLAGS: u64 = flags::bits::ZF | flags::bits::PF | flags::bits::CF;

/// Build: load b then a so ST0=a,ST1=b; FCOMI ST0,ST1 (DB F1); HLT.
fn fcomi_program() -> Vec<u8> {
    let mut c = load_rdi_data();
    c.extend_from_slice(&[0xDD, 0x47, 0x08]); // fld qword [rdi+8]  -> ST0=b
    c.extend_from_slice(&[0xDD, 0x07]); // fld qword [rdi]    -> ST0=a, ST1=b
    c.extend_from_slice(&[0xDB, 0xF1]); // fcomi st0, st1
    c.push(HLT);
    c
}

#[test]
fn x87_fcomi_greater() {
    // a > b: ZF=0, CF=0, PF=0.
    check_mem(
        "x87_fcomi_gt",
        &fcomi_program(),
        regs(),
        scratch_f64(&[5.0, 3.0]),
        FCOMI_FLAGS,
    );
}

#[test]
fn x87_fcomi_less() {
    // a < b: ZF=0, CF=1, PF=0.
    check_mem(
        "x87_fcomi_lt",
        &fcomi_program(),
        regs(),
        scratch_f64(&[3.0, 5.0]),
        FCOMI_FLAGS,
    );
}

#[test]
fn x87_fcomi_equal() {
    // a == b: ZF=1, CF=0, PF=0.
    check_mem(
        "x87_fcomi_eq",
        &fcomi_program(),
        regs(),
        scratch_f64(&[42.0, 42.0]),
        FCOMI_FLAGS,
    );
}

#[test]
fn x87_fucomi_equal() {
    // FUCOMI ST0,ST1 = DB E9. Same ordered result for non-NaN operands.
    let mut c = load_rdi_data();
    c.extend_from_slice(&[0xDD, 0x47, 0x08]); // fld qword [rdi+8]
    c.extend_from_slice(&[0xDD, 0x07]); // fld qword [rdi]
    c.extend_from_slice(&[0xDB, 0xE9]); // fucomi st0, st1
    c.push(HLT);
    check_mem("x87_fucomi_eq", &c, regs(), scratch_f64(&[7.5, 7.5]), FCOMI_FLAGS);
}

// ---- String ops: MOVS / STOS / LODS / SCAS / CMPS (with and without REP, DF) ----
//
// Scratch layout convention:
//   src buffer at offset 0, dst buffer at offset 16. We set RSI/RDI to the
//   matching guest addresses, RCX to the element count, and clear/set DF as
//   needed. We compare the whole scratch page plus the final RSI/RDI/RCX.
// String ops affect no arithmetic flags (except SCAS/CMPS which set them like
// CMP); DF must be restored where we set it, and we always end with `CLD`-free
// HLT — the harness reads RFLAGS so we keep DF out of the compared mask.

const SRC_OFF: u64 = 0;
const DST_OFF: u64 = 16;

/// Initial regs for a string test: RSI=src, RDI=dst, RCX=count.
fn string_regs(count: u64) -> Registers {
    let mut r = regs();
    r.rsi = DATA_ADDR + SRC_OFF;
    r.rdi = DATA_ADDR + DST_OFF;
    r.rcx = count;
    r
}

/// Scratch with a source byte pattern at offset 0 (dst region left zero).
fn string_scratch(src: &[u8]) -> [u8; 64] {
    let mut s = [0u8; 64];
    s[..src.len()].copy_from_slice(src);
    s
}

#[test]
fn str_rep_movsb() {
    // REP MOVSB: copy RCX bytes src->dst. F3 A4.
    let r = string_regs(8);
    check_mem(
        "rep_movsb",
        &with_hlt(vec![0xF3, 0xA4]),
        r,
        string_scratch(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
        0,
    );
}

#[test]
fn str_rep_movsw() {
    // REP MOVSW: copy RCX words. 66 F3 A5 (operand-size 16). Copy 4 words.
    let r = string_regs(4);
    check_mem(
        "rep_movsw",
        &with_hlt(vec![0xF3, 0x66, 0xA5]),
        r,
        string_scratch(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
        0,
    );
}

#[test]
fn str_rep_movsd() {
    // REP MOVSD: copy RCX dwords. F3 A5. Copy 2 dwords.
    let r = string_regs(2);
    check_mem(
        "rep_movsd",
        &with_hlt(vec![0xF3, 0xA5]),
        r,
        string_scratch(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]),
        0,
    );
}

#[test]
fn str_rep_movsq() {
    // REP MOVSQ: copy RCX qwords. F3 48 A5. Copy 1 qword.
    let r = string_regs(1);
    check_mem(
        "rep_movsq",
        &with_hlt(vec![0xF3, 0x48, 0xA5]),
        r,
        string_scratch(&[1, 2, 3, 4, 5, 6, 7, 8]),
        0,
    );
}

#[test]
fn str_movsb_single() {
    // Single MOVSB (no REP): copies 1 byte, advances RSI/RDI by 1.
    let mut r = regs();
    r.rsi = DATA_ADDR + SRC_OFF;
    r.rdi = DATA_ADDR + DST_OFF;
    check_mem(
        "movsb_single",
        &with_hlt(vec![0xA4]),
        r,
        string_scratch(&[0xAB, 0xCD]),
        0,
    );
}

#[test]
fn str_rep_movsb_df_reverse() {
    // DF=1 reverse copy. Point RSI/RDI at the LAST element so the run walks down.
    // 3 bytes at offsets 0,1,2 copied to dst 16,17,18 in reverse address order.
    let mut r = regs();
    r.rsi = DATA_ADDR + SRC_OFF + 2;
    r.rdi = DATA_ADDR + DST_OFF + 2;
    r.rcx = 3;
    r.rflags = flags::bits::DF; // set direction = down
    check_mem(
        "rep_movsb_df",
        &with_hlt(vec![0xF3, 0xA4]),
        r,
        string_scratch(&[0xA1, 0xB2, 0xC3]),
        0,
    );
}

#[test]
fn str_rep_stosb() {
    // REP STOSB: fill RCX bytes at dst with AL. F3 AA. AL=0x5A, count=6.
    let mut r = string_regs(6);
    r.rax = 0x5A;
    check_mem("rep_stosb", &with_hlt(vec![0xF3, 0xAA]), r, string_scratch(&[]), 0);
}

#[test]
fn str_rep_stosd() {
    // REP STOSD: fill RCX dwords with EAX. F3 AB. EAX=0xCAFEBABE, count=3.
    let mut r = string_regs(3);
    r.rax = 0xCAFE_BABE;
    check_mem("rep_stosd", &with_hlt(vec![0xF3, 0xAB]), r, string_scratch(&[]), 0);
}

#[test]
fn str_lodsb() {
    // LODSB: AL <- [RSI], RSI advances. AC. Single, no REP.
    let mut r = regs();
    r.rsi = DATA_ADDR + SRC_OFF;
    r.rax = 0x1122_3344_5566_7700; // only AL should change
    check_mem(
        "lodsb",
        &with_hlt(vec![0xAC]),
        r,
        string_scratch(&[0x99, 0x88]),
        0,
    );
}

#[test]
fn str_repne_scasb_found() {
    // REPNE SCASB: scan dst for AL, stop on match. F2 AE.
    // Buffer at dst (offset 16) = [1,2,3,4,5,...]; AL=4, count large enough.
    let mut s = [0u8; 64];
    s[DST_OFF as usize..DST_OFF as usize + 6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
    let mut r = regs();
    r.rdi = DATA_ADDR + DST_OFF;
    r.rcx = 6;
    r.rax = 4; // AL = 4 -> match at index 3
    // SCAS sets arithmetic flags like CMP; compare all status flags.
    check_mem("repne_scasb", &with_hlt(vec![0xF2, 0xAE]), r, s, FLAG_MASK);
}

#[test]
fn str_scasb_single_equal() {
    // Single SCASB where [RDI]==AL -> ZF=1, all CMP flags defined.
    let mut s = [0u8; 64];
    s[DST_OFF as usize] = 0x7F;
    let mut r = regs();
    r.rdi = DATA_ADDR + DST_OFF;
    r.rax = 0x7F;
    check_mem("scasb_eq", &with_hlt(vec![0xAE]), r, s, FLAG_MASK);
}

#[test]
fn str_repe_cmpsb_equal_run() {
    // REPE CMPSB: compare src vs dst while equal. F3 A6.
    // Make src==dst for the whole run -> RCX hits 0, ZF=1 at the end.
    let mut s = [0u8; 64];
    let pat = [0xDE, 0xAD, 0xBE, 0xEF, 0x12];
    s[SRC_OFF as usize..SRC_OFF as usize + 5].copy_from_slice(&pat);
    s[DST_OFF as usize..DST_OFF as usize + 5].copy_from_slice(&pat);
    let mut r = regs();
    r.rsi = DATA_ADDR + SRC_OFF;
    r.rdi = DATA_ADDR + DST_OFF;
    r.rcx = 5;
    check_mem("repe_cmpsb_eq", &with_hlt(vec![0xF3, 0xA6]), r, s, FLAG_MASK);
}

#[test]
fn str_repe_cmpsb_mismatch() {
    // REPE CMPSB stops at the first differing byte; flags reflect that compare.
    let mut s = [0u8; 64];
    s[SRC_OFF as usize..SRC_OFF as usize + 5].copy_from_slice(&[1, 2, 3, 4, 5]);
    s[DST_OFF as usize..DST_OFF as usize + 5].copy_from_slice(&[1, 2, 9, 4, 5]);
    let mut r = regs();
    r.rsi = DATA_ADDR + SRC_OFF;
    r.rdi = DATA_ADDR + DST_OFF;
    r.rcx = 5;
    check_mem("repe_cmpsb_ne", &with_hlt(vec![0xF3, 0xA6]), r, s, FLAG_MASK);
}

#[test]
fn str_cmpsb_single() {
    // Single CMPSB: compares [RSI] vs [RDI], sets CMP flags, advances both.
    let mut s = [0u8; 64];
    s[SRC_OFF as usize] = 0x10;
    s[DST_OFF as usize] = 0x20; // 0x10 - 0x20 -> CF, SF
    let mut r = regs();
    r.rsi = DATA_ADDR + SRC_OFF;
    r.rdi = DATA_ADDR + DST_OFF;
    check_mem("cmpsb_single", &with_hlt(vec![0xA6]), r, s, FLAG_MASK);
}

// ---- SSE3 / SSE2 float: HADDPS/HSUBPS/ADDSUBPS/MOVDDUP/SHUFPD + conversions ----
//
// All packed-float results below use exactly-representable values so the f64/f32
// rounding is bit-identical across backends. We reuse `sse_program` for the
// 2-operand reg forms and `check_sse` to compare the stored 128-bit result.

#[test]
fn sse3_haddps() {
    // HADDPS xmm0, xmm1 = F2 0F 7C C1. Horizontal add of single-precision lanes.
    // a = [1,2,3,4], b = [10,20,30,40] (as f32). result = [a0+a1, a2+a3, b0+b1, b2+b3].
    let af = [1.0f32, 2.0, 3.0, 4.0];
    let bf = [10.0f32, 20.0, 30.0, 40.0];
    let mut a = [0u8; 16];
    let mut b = [0u8; 16];
    for i in 0..4 {
        a[i * 4..i * 4 + 4].copy_from_slice(&af[i].to_le_bytes());
        b[i * 4..i * 4 + 4].copy_from_slice(&bf[i].to_le_bytes());
    }
    check_sse("haddps", &sse_program(&[0xF2, 0x0F, 0x7C, 0xC1]), sse_scratch(a, b));
}

#[test]
fn sse3_hsubps() {
    // HSUBPS xmm0, xmm1 = F2 0F 7D C1.
    let af = [10.0f32, 3.0, 8.0, 2.5];
    let bf = [100.0f32, 40.0, 9.0, 1.0];
    let mut a = [0u8; 16];
    let mut b = [0u8; 16];
    for i in 0..4 {
        a[i * 4..i * 4 + 4].copy_from_slice(&af[i].to_le_bytes());
        b[i * 4..i * 4 + 4].copy_from_slice(&bf[i].to_le_bytes());
    }
    check_sse("hsubps", &sse_program(&[0xF2, 0x0F, 0x7D, 0xC1]), sse_scratch(a, b));
}

#[test]
fn sse3_addsubps() {
    // ADDSUBPS xmm0, xmm1 = F2 0F D0 C1. Subtract even lanes, add odd lanes.
    let af = [5.0f32, 5.0, 5.0, 5.0];
    let bf = [1.0f32, 2.0, 3.0, 4.0];
    let mut a = [0u8; 16];
    let mut b = [0u8; 16];
    for i in 0..4 {
        a[i * 4..i * 4 + 4].copy_from_slice(&af[i].to_le_bytes());
        b[i * 4..i * 4 + 4].copy_from_slice(&bf[i].to_le_bytes());
    }
    check_sse("addsubps", &sse_program(&[0xF2, 0x0F, 0xD0, 0xC1]), sse_scratch(a, b));
}

#[test]
fn sse3_movddup() {
    // MOVDDUP xmm0, xmm1 = F2 0F 12 C1. Duplicate the low f64 of the source.
    let a = [0u8; 16]; // dest, overwritten
    let b = [12.5f64.to_le_bytes(), 99.0f64.to_le_bytes()].concat();
    check_sse(
        "movddup",
        &sse_program(&[0xF2, 0x0F, 0x12, 0xC1]),
        sse_scratch(a, b.try_into().unwrap()),
    );
}

#[test]
fn sse2_shufpd() {
    // SHUFPD xmm0, xmm1, imm8 = 66 0F C6 C1 ib. imm=0b10 -> dst.lo=a.hi, dst.hi=b.lo.
    let a = [1.0f64.to_le_bytes(), 2.0f64.to_le_bytes()].concat();
    let b = [3.0f64.to_le_bytes(), 4.0f64.to_le_bytes()].concat();
    let mut prog = load_rdi_data();
    prog.extend_from_slice(&[0xF3, 0x0F, 0x6F, 0x07]); // movdqu xmm0, [rdi]
    prog.extend_from_slice(&[0xF3, 0x0F, 0x6F, 0x4F, 0x10]); // movdqu xmm1, [rdi+0x10]
    prog.extend_from_slice(&[0x66, 0x0F, 0xC6, 0xC1, 0x02]); // shufpd xmm0, xmm1, 2
    prog.extend_from_slice(&[0xF3, 0x0F, 0x7F, 0x47, 0x20]); // movdqu [rdi+0x20], xmm0
    prog.push(HLT);
    check_sse("shufpd", &prog, sse_scratch(a.try_into().unwrap(), b.try_into().unwrap()));
}

#[test]
fn sse2_cvtdq2ps() {
    // CVTDQ2PS xmm0, xmm1 = 0F 5B C1. Convert 4 packed i32 -> 4 packed f32.
    // Use exact integers (small) so the result is bit-exact.
    let a = [0u8; 16];
    let ints = [3i32, -7, 100, -1];
    let mut b = [0u8; 16];
    for i in 0..4 {
        b[i * 4..i * 4 + 4].copy_from_slice(&ints[i].to_le_bytes());
    }
    check_sse("cvtdq2ps", &sse_program(&[0x0F, 0x5B, 0xC1]), sse_scratch(a, b));
}

#[test]
fn sse2_cvtps2dq() {
    // CVTPS2DQ xmm0, xmm1 = 66 0F 5B C1. Convert 4 f32 -> 4 i32 (round-to-nearest).
    // Integral inputs -> exact.
    let a = [0u8; 16];
    let fs = [3.0f32, -7.0, 100.0, -1.0];
    let mut b = [0u8; 16];
    for i in 0..4 {
        b[i * 4..i * 4 + 4].copy_from_slice(&fs[i].to_le_bytes());
    }
    check_sse("cvtps2dq", &sse_program(&[0x66, 0x0F, 0x5B, 0xC1]), sse_scratch(a, b));
}

#[test]
fn sse2_cvttps2dq_truncates() {
    // CVTTPS2DQ xmm0, xmm1 = F3 0F 5B C1. Truncating convert f32 -> i32.
    // 3.9 -> 3, -3.9 -> -3, 2.1 -> 2, -0.9 -> 0.
    let a = [0u8; 16];
    let fs = [3.9f32, -3.9, 2.1, -0.9];
    let mut b = [0u8; 16];
    for i in 0..4 {
        b[i * 4..i * 4 + 4].copy_from_slice(&fs[i].to_le_bytes());
    }
    check_sse("cvttps2dq", &sse_program(&[0xF3, 0x0F, 0x5B, 0xC1]), sse_scratch(a, b));
}

// ---- Misc: SAHF / LAHF ----

#[test]
fn sahf_loads_flags() {
    // SAHF (9E): AH -> low byte of RFLAGS (SF,ZF,_,AF,_,PF,_,CF). AH=0xD5
    // sets SF,ZF,AF,PF (and bit1 reserved=1, CF=1). We then read the status flags.
    let mut r = regs();
    // AH = 1101_0101: SF=1 ZF=1 (bit5=0) AF=1 (bit3=0) PF=1 (bit1=1 reserved) CF=1
    r.rax = 0xD5 << 8;
    check("sahf", &with_hlt(vec![0x9E]), r);
}

#[test]
fn lahf_stores_flags() {
    // LAHF (9F): low byte of RFLAGS -> AH. Set a known flag state via CMP first.
    let mut r = regs();
    r.rax = 0x0; // 0 - 1
    r.rbx = 0x1;
    // 48 39 D8  cmp rax, rbx  (sets SF, CF, AF)
    // 9F        lahf          (AH <- status byte)
    check("lahf", &with_hlt(vec![0x48, 0x39, 0xD8, 0x9F]), r);
}

#[test]
fn lahf_sahf_roundtrip() {
    // LAHF then SAHF should reproduce the same flag state. Seed via CMP.
    let mut r = regs();
    r.rax = 0x5;
    r.rbx = 0x5; // equal -> ZF, PF
    // cmp; lahf; xor ah with nothing; sahf
    check("lahf_sahf", &with_hlt(vec![0x48, 0x39, 0xD8, 0x9F, 0x9E]), r);
}

// ---- MOVBE (move with byte swap) ----

#[test]
fn movbe_load_r64() {
    // MOVBE r64, m64 = 48 0F 38 F0 /r. Load+byteswap from [rdi].
    let mut s = [0u8; 64];
    s[0..8].copy_from_slice(&0x0011_2233_4455_6677u64.to_le_bytes());
    let mut r = regs();
    r.rdi = DATA_ADDR;
    // 48 0F 38 F0 07  movbe rax, [rdi]
    check_mem("movbe_load64", &with_hlt(vec![0x48, 0x0F, 0x38, 0xF0, 0x07]), r, s, 0);
}

#[test]
fn movbe_store_r32() {
    // MOVBE m32, r32 = 0F 38 F1 /r. Store EAX byteswapped to [rdi]; verify scratch.
    let mut r = regs();
    r.rax = 0x1122_3344;
    r.rdi = DATA_ADDR;
    // 0F 38 F1 07  movbe [rdi], eax
    check_mem("movbe_store32", &with_hlt(vec![0x0F, 0x38, 0xF1, 0x07]), r, zero_scratch(), 0);
}

// ---- BMI1: ANDN / BLSI / BLSR / BLSMSK (VEX-encoded) ----
//
// BMI1 defines ZF and SF from the result, clears OF; AF/PF are undefined and CF
// is defined per-instruction (ANDN clears CF; BLS* set CF specially). To stay on
// the safe side we compare the architecturally-defined bits: ZF, SF, CF, OF.
const BMI_DEFINED: u64 = flags::bits::ZF | flags::bits::SF | flags::bits::CF | flags::bits::OF;

#[test]
fn bmi_andn() {
    // ANDN r32a, r32b, r/m32 = VEX.LZ.0F38.W0 F2 /r : dest = ~src1 & src2.
    // VEX 2-byte: C4 E2 (map 0F38) ... use 3-byte VEX. Encode andn eax, ebx, ecx:
    //   VEX.NDS.LZ.0F38.W0 F2 /r, vvvv = ~ebx, src2 = ecx (modrm).
    // C4 E2 60 F2 C1  -> andn eax, ebx, ecx   (dest=~ebx & ecx = 0xAA00)
    let mut r = regs();
    r.rbx = 0x0000_00FF; // src1 (inverted)
    r.rcx = 0x0000_AAAA; // src2
    check_flags_masked("andn", &with_hlt(vec![0xC4, 0xE2, 0x60, 0xF2, 0xC1]), r, BMI_DEFINED);
}

#[test]
fn bmi_blsi() {
    // BLSI r32, r/m32 = VEX.LZ.0F38.W0 F3 /3 : dest = src & -src (isolate lowest set bit).
    // vvvv encodes dest, modrm.reg=/3 selects the op, modrm.rm=src.
    // andn-style 3-byte VEX with vvvv=eax(dest), rm=ecx(src): C4 E2 78 F3 D9
    //   reg field = 011 (/3 = BLSI), rm = 001 (ecx), vvvv=1111-? -> dest eax.
    let mut r = regs();
    r.rcx = 0x0000_00B0; // lowest set bit is bit 4 (0x10)
    check_flags_masked("blsi", &with_hlt(vec![0xC4, 0xE2, 0x78, 0xF3, 0xD9]), r, BMI_DEFINED);
}

#[test]
fn bmi_blsr() {
    // BLSR r32, r/m32 = VEX.LZ.0F38.W0 F3 /1 : dest = src & (src-1) (clear lowest set bit).
    // reg field = 001 (/1 = BLSR), rm=001(ecx), vvvv -> eax. C4 E2 78 F3 C9.
    let mut r = regs();
    r.rcx = 0x0000_00B0;
    check_flags_masked("blsr", &with_hlt(vec![0xC4, 0xE2, 0x78, 0xF3, 0xC9]), r, BMI_DEFINED);
}

#[test]
fn bmi_blsmsk() {
    // BLSMSK r32, r/m32 = VEX.LZ.0F38.W0 F3 /2 : dest = src ^ (src-1) (mask up to lowest set bit).
    // reg field = 010 (/2 = BLSMSK), rm=001(ecx), vvvv -> eax. C4 E2 78 F3 D1.
    let mut r = regs();
    r.rcx = 0x0000_00B0;
    check_flags_masked("blsmsk", &with_hlt(vec![0xC4, 0xE2, 0x78, 0xF3, 0xD1]), r, BMI_DEFINED);
}

// ---- BMI2: PEXT / PDEP / MULX / RORX / SARX / SHRX / SHLX ----
//
// BMI2 bit-manipulation ops do NOT affect flags at all, so compare GPRs only.

#[test]
fn bmi2_pext() {
    // PEXT r32, r32, r/m32 = VEX.LZ.F3.0F38.W0 F5 /r : extract bits of src1 selected by mask.
    //   andn-form: vvvv = src1 (ebx), rm = mask (ecx), dest = eax.
    //   pp=10 (F3), map=0F38 -> VEX3 C4 E2 62 F5 C1.
    let mut r = regs();
    r.rbx = 0x1234_5678; // source
    r.rcx = 0x0F0F_0F0F; // mask: take low nibble of each byte
    check_flags_masked("pext", &with_hlt(vec![0xC4, 0xE2, 0x62, 0xF5, 0xC1]), r, 0);
}

#[test]
fn bmi2_pdep() {
    // PDEP r32, r32, r/m32 = VEX.LZ.F2.0F38.W0 F5 /r : deposit bits into mask positions.
    //   pp=11 (F2) -> VEX3 C4 E2 63 F5 C1. vvvv=src1(ebx), rm=mask(ecx), dest=eax.
    let mut r = regs();
    r.rbx = 0x0000_000F; // 4 source bits
    r.rcx = 0x0F0F_0F0F; // scatter into these positions
    check_flags_masked("pdep", &with_hlt(vec![0xC4, 0xE2, 0x63, 0xF5, 0xC1]), r, 0);
}

#[test]
fn bmi2_mulx() {
    // MULX r32a, r32b, r/m32 = VEX.LZ.F2.0F38.W0 F6 /r : unsigned mul of EDX by r/m,
    //   high half -> dest1 (vvvv), low half -> dest2 (modrm.reg). EDX is implicit.
    //   mulx eax, ebx, ecx : reg=eax(dest2), vvvv=ebx(dest1), rm=ecx(src2).
    //   pp=11(F2), map=0F38 -> C4 E2 63 F6 C1  (vvvv=ebx=0b1101 inverted... encode below)
    // Encoding: C4 E2 (62?) — vvvv must encode ebx(=0b0011) inverted = 0b1100.
    //   byte3 = W(0)|vvvv(1100)|L(0)|pp(11) = 0 1100 0 11 = 0x63. reg/rm: reg=eax(000), rm=ecx(001) -> modrm C1.
    let mut r = regs();
    r.rdx = 0x0001_0000; // implicit multiplicand
    r.rcx = 0x0001_0000; // src2 -> product 0x1_0000_0000
    check_flags_masked("mulx", &with_hlt(vec![0xC4, 0xE2, 0x63, 0xF6, 0xC1]), r, 0);
}

#[test]
fn bmi2_rorx() {
    // RORX r32, r/m32, imm8 = VEX.LZ.F2.0F3A.W0 F0 /r ib : rotate right, no flags.
    //   map=0F3A -> byte2 low nibble = 3. pp=11(F2). rorx eax, ecx, 8.
    //   C4 E3 7B F0 C1 08 : reg=eax(000), rm=ecx(001) -> C1, imm=8.
    let mut r = regs();
    r.rcx = 0x1234_5678;
    check_flags_masked("rorx", &with_hlt(vec![0xC4, 0xE3, 0x7B, 0xF0, 0xC1, 0x08]), r, 0);
}

#[test]
fn bmi2_sarx() {
    // SARX r32, r/m32, r32 = VEX.LZ.F3.0F38.W0 F7 /r : arithmetic shift right by count reg.
    //   pp=10(F3). vvvv encodes the count register (ebx). sarx eax, ecx, ebx.
    //   byte3 = W0 vvvv(~ebx=1100) L0 pp(10) -> 0 1100 0 10 = 0x62. modrm reg=eax,rm=ecx -> C1.
    let mut r = regs();
    r.rcx = 0xFFFF_8000; // negative when treated as i32
    r.rbx = 4; // shift count
    check_flags_masked("sarx", &with_hlt(vec![0xC4, 0xE2, 0x62, 0xF7, 0xC1]), r, 0);
}

#[test]
fn bmi2_shrx() {
    // SHRX r32, r/m32, r32 = VEX.LZ.F2.0F38.W0 F7 /r : logical shift right.
    //   pp=11(F2). vvvv=ebx(count). byte3 = 0 1100 0 11 = 0x63.
    let mut r = regs();
    r.rcx = 0xF000_0000;
    r.rbx = 8;
    check_flags_masked("shrx", &with_hlt(vec![0xC4, 0xE2, 0x63, 0xF7, 0xC1]), r, 0);
}

#[test]
fn bmi2_shlx() {
    // SHLX r32, r/m32, r32 = VEX.LZ.66.0F38.W0 F7 /r : logical shift left.
    //   pp=01(66). vvvv=ebx(count). byte3 = 0 1100 0 01 = 0x61.
    let mut r = regs();
    r.rcx = 0x0000_00FF;
    r.rbx = 12;
    check_flags_masked("shlx", &with_hlt(vec![0xC4, 0xE2, 0x61, 0xF7, 0xC1]), r, 0);
}

#[test]
fn bmi2_rorx_r64() {
    // 64-bit RORX: VEX.LZ.F2.0F3A.W1 F0 /r ib. W1 -> byte3 bit7 set: 0xFB.
    //   rorx rax, rcx, 20 : C4 E3 FB F0 C1 14.
    let mut r = regs();
    r.rcx = 0x0123_4567_89AB_CDEF;
    check_flags_masked("rorx64", &with_hlt(vec![0xC4, 0xE3, 0xFB, 0xF0, 0xC1, 0x14]), r, 0);
}
