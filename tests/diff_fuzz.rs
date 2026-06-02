//! Randomized differential fuzzer: software interpreter vs. KVM (hardware oracle).
//!
//! This is a standalone integration-test target, a sibling of `differential.rs`.
//! Where `differential.rs` runs hand-written, hand-checked corpus cases, this
//! file *generates* random-but-valid instruction encodings together with random
//! initial register / flag / memory state, runs each case on BOTH the rax
//! software interpreter and on KVM from an identical architectural state, and
//! compares the resulting state (GPRs, masked RFLAGS, scratch memory / XMM).
//!
//! Any divergence on architecturally-DEFINED state is an interpreter bug and is
//! reported precisely (encoding bytes, inputs, interp-vs-KVM outputs).
//!
//! Determinism: a fixed-seed SplitMix64 PRNG drives generation so every run is
//! byte-for-byte reproducible (Date/`rand` are unavailable / nondeterministic).
//!
//! Robustness: if `/dev/kvm` cannot be opened/driven, every test self-skips
//! (returns without failing). Execution on both backends is bounded.
//!
//! NOTE: The harness setup below is intentionally DUPLICATED from
//! `differential.rs` rather than imported — private test items cannot be shared
//! across separate integration-test crates. The proven setup (identity-mapped
//! long mode, the KVM driver, the comparison helpers, the undefined-flag masks)
//! is reused verbatim.

#![cfg(all(feature = "kvm", target_os = "linux"))]

use std::sync::Arc;

use rax::backend::emulator::x86_64::{flags, X86_64Vcpu};
use rax::cpu::{Registers, SystemRegisters, VCpu, VcpuExit};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

// ---------------------------------------------------------------------------
// Memory layout (all identity-mapped: GVA == GPA) — mirrors differential.rs
// ---------------------------------------------------------------------------

const MEM_SIZE: usize = 8 * 1024 * 1024; // 8 MiB
const CODE_ADDR: u64 = 0x1_0000;
const STACK_ADDR: u64 = 0x2_0000;
const DATA_ADDR: u64 = 0x3_0000;
const PML4_ADDR: u64 = 0x9000;
const PDPTE_ADDR: u64 = 0xA000;

const CR0_PE: u64 = 1 << 0;
const CR0_MP: u64 = 1 << 1;
const CR0_ET: u64 = 1 << 4;
const CR0_NE: u64 = 1 << 5;
const CR0_WP: u64 = 1 << 16;
const CR0_PG: u64 = 1 << 31;
const CR0_VAL: u64 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_PG;
const CR4_PAE: u64 = 1 << 5;
const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;
const CR4_VAL: u64 = CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT;
const EFER_SCE: u64 = 1 << 0;
const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;
const EFER_VAL: u64 = EFER_SCE | EFER_LME | EFER_LMA;

const MAX_ITERS: u64 = 100_000;

const HLT: u8 = 0xF4;

// ---------------------------------------------------------------------------
// Captured state for comparison
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct FinalState {
    regs: Registers,
    xmm: [[u64; 2]; 16],
    scratch: [u8; 64],
}

/// Observable, architecturally-defined RFLAGS status bits.
const FLAG_MASK: u64 =
    flags::bits::CF | flags::bits::PF | flags::bits::AF | flags::bits::ZF | flags::bits::SF | flags::bits::OF;

// ---------------------------------------------------------------------------
// Shared identity-mapped long-mode initial state.
// ---------------------------------------------------------------------------

fn base_sregs() -> SystemRegisters {
    let mut sregs = SystemRegisters::default();
    sregs.cr0 = CR0_VAL;
    sregs.cr3 = PML4_ADDR;
    sregs.cr4 = CR4_VAL;
    sregs.efer = EFER_VAL;

    sregs.cs.base = 0;
    sregs.cs.limit = 0xFFFFF;
    sregs.cs.selector = 0x8;
    sregs.cs.type_ = 0xB;
    sregs.cs.present = true;
    sregs.cs.dpl = 0;
    sregs.cs.s = true;
    sregs.cs.l = true;
    sregs.cs.db = false;
    sregs.cs.g = true;

    let mut data = sregs.cs.clone();
    data.selector = 0x10;
    data.type_ = 0x3;
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

fn install_tables_mmap(write: &mut dyn FnMut(u64, &[u8])) {
    write(PML4_ADDR, &(PDPTE_ADDR | 0x3).to_le_bytes());
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

    install_tables_mmap(&mut |addr, bytes| {
        mem.write_slice(bytes, GuestAddress(addr)).unwrap();
    });
    mem.write_slice(code, GuestAddress(CODE_ADDR)).map_err(|e| format!("code: {e:?}"))?;
    mem.write_slice(scratch_init, GuestAddress(DATA_ADDR)).map_err(|e| format!("scratch: {e:?}"))?;

    let mut vcpu = X86_64Vcpu::new(0, mem.clone());

    let mut regs = init.clone();
    regs.rip = CODE_ADDR;
    if regs.rsp == 0 {
        regs.rsp = STACK_ADDR;
    }
    regs.rflags |= 0x2;
    vcpu.set_regs(&regs).map_err(|e| format!("set_regs: {e:?}"))?;
    vcpu.set_sregs(&base_sregs()).map_err(|e| format!("set_sregs: {e:?}"))?;

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
// KVM backend
// ---------------------------------------------------------------------------

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

/// Returns Ok(None) if KVM is unavailable (callers skip gracefully),
/// Ok(Some(state)) on success, Err on a genuine run failure.
fn run_kvm(code: &[u8], init: &Registers, scratch_init: &[u8; 64]) -> Result<Option<FinalState>, String> {
    use kvm_bindings::{kvm_segment, kvm_userspace_memory_region};
    use kvm_ioctls::Kvm;

    let kvm = match Kvm::new() {
        Ok(k) => k,
        Err(_) => return Ok(None),
    };
    let vm = match kvm.create_vm() {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };

    let mem = match KvmMem::new(MEM_SIZE) {
        Some(m) => m,
        None => return Ok(None),
    };

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

#[derive(Clone, Copy)]
struct CompareOpts {
    flag_mask: u64,
    xmm_count: usize,
    scratch: bool,
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

/// Returns a list of human-readable divergences. `ignore_regs` lets a generator
/// suppress GPRs whose value is architecturally UNDEFINED for the case (e.g. the
/// destination of BSF/BSR on a zero source).
fn compare(interp: &FinalState, kvm: &FinalState, opts: CompareOpts, ignore_regs: &[&str]) -> Vec<String> {
    let mut diffs = Vec::new();

    let il = gpr_list(&interp.regs);
    let kl = gpr_list(&kvm.regs);
    for ((name, iv), (_, kv)) in il.iter().zip(kl.iter()) {
        if !opts.stack && (*name == "rsp" || *name == "rbp") {
            continue;
        }
        if ignore_regs.contains(name) {
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
            "scratch differs:\n      interp={:02x?}\n      kvm   ={:02x?}",
            &interp.scratch[..],
            &kvm.scratch[..]
        ));
    }

    diffs
}

// ---------------------------------------------------------------------------
// Deterministic PRNG: SplitMix64 (fixed seed -> reproducible runs).
// ---------------------------------------------------------------------------

struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        Rng { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    /// Uniform in [0, n).
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }

    /// A random operand value biased toward "interesting" boundary values so we
    /// hit carries, sign flips, all-ones, single-bit, etc. more often than pure
    /// uniform noise would.
    fn operand(&mut self) -> u64 {
        match self.below(8) {
            0 => 0,
            1 => 1,
            2 => u64::MAX,
            3 => 0x8000_0000_0000_0000,
            4 => 0x7FFF_FFFF_FFFF_FFFF,
            5 => 1u64 << self.below(64),       // single random bit
            6 => self.next_u64() & 0xFF,       // small value
            _ => self.next_u64(),              // full noise
        }
    }
}

// ---------------------------------------------------------------------------
// Mismatch collection
// ---------------------------------------------------------------------------

struct Mismatch {
    label: String,
    code: Vec<u8>,
    inputs: String,
    diffs: Vec<String>,
}

impl Mismatch {
    fn render(&self) -> String {
        format!(
            "  [{}] code={:02x?}\n    inputs: {}\n    {}",
            self.label,
            self.code,
            self.inputs,
            self.diffs.join("\n    ")
        )
    }
}

/// Holds the per-test KVM availability + accumulated mismatches.
struct Harness {
    rng: Rng,
    mismatches: Vec<Mismatch>,
    kvm_available: bool,
    /// number of cases actually run (KVM driven)
    ran: usize,
}

impl Harness {
    fn new(seed: u64) -> Self {
        Harness {
            rng: Rng::new(seed),
            mismatches: Vec::new(),
            kvm_available: true,
            ran: 0,
        }
    }

    /// Run one case. `init` is the architectural input state, `code` the program
    /// (already terminated with HLT). `opts` selects what to compare and the flag
    /// mask. `ignore_regs` masks GPRs whose value is undefined for this case.
    /// Returns false if KVM became unavailable (caller should stop the loop).
    fn run_case(
        &mut self,
        label: &str,
        code: &[u8],
        init: Registers,
        scratch_init: [u8; 64],
        opts: CompareOpts,
        inputs: String,
        ignore_regs: &[&str],
    ) -> bool {
        let kvm = match run_kvm(code, &init, &scratch_init) {
            Ok(Some(s)) => s,
            Ok(None) => {
                self.kvm_available = false;
                return false;
            }
            Err(e) => {
                // A genuine KVM run failure (e.g. abnormal exit) is itself a
                // signal worth recording rather than panicking the whole suite.
                self.mismatches.push(Mismatch {
                    label: format!("{label} (KVM backend error)"),
                    code: code.to_vec(),
                    inputs,
                    diffs: vec![e],
                });
                return true;
            }
        };
        let interp = match run_interpreter(code, &init, &scratch_init) {
            Ok(s) => s,
            Err(e) => {
                self.mismatches.push(Mismatch {
                    label: format!("{label} (interpreter backend error)"),
                    code: code.to_vec(),
                    inputs,
                    diffs: vec![e],
                });
                return true;
            }
        };
        self.ran += 1;
        let diffs = compare(&interp, &kvm, opts, ignore_regs);
        if !diffs.is_empty() {
            self.mismatches.push(Mismatch {
                label: label.to_string(),
                code: code.to_vec(),
                inputs,
                diffs,
            });
        }
        true
    }

    /// Final assertion: clean pass, graceful skip, or precise failure dump.
    fn finish(self, class: &str) {
        if !self.kvm_available && self.ran == 0 {
            eprintln!("[skip] /dev/kvm unavailable or undrivable; skipping {class} fuzzing");
            return;
        }
        if !self.mismatches.is_empty() {
            let mut out = format!(
                "DIVERGENCES in `{class}` fuzzer ({} of {} cases diverged):\n",
                self.mismatches.len(),
                self.ran
            );
            // Cap the dump so a systemic bug doesn't produce megabytes of output,
            // but always show enough to be actionable.
            for m in self.mismatches.iter().take(20) {
                out.push_str(&m.render());
                out.push('\n');
            }
            if self.mismatches.len() > 20 {
                out.push_str(&format!("  ... and {} more\n", self.mismatches.len() - 20));
            }
            panic!("{out}");
        }
        eprintln!("[ok] {class}: {} cases agree (interp == KVM)", self.ran);
    }
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/// The four operand sizes we fuzz, with their REX.W / 0x66 prefix conventions.
#[derive(Clone, Copy, PartialEq)]
enum Size {
    B8,
    B16,
    B32,
    B64,
}

impl Size {
    fn bits(self) -> u32 {
        match self {
            Size::B8 => 8,
            Size::B16 => 16,
            Size::B32 => 32,
            Size::B64 => 64,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Size::B8 => "b8",
            Size::B16 => "w16",
            Size::B32 => "d32",
            Size::B64 => "q64",
        }
    }
}

/// Set an initial register by index 0..=7 (rax..rdi order matching ModRM reg
/// numbering: 0=rax,1=rcx,2=rdx,3=rbx,4=rsp,5=rbp,6=rsi,7=rdi).
fn set_reg(r: &mut Registers, idx: u8, val: u64) {
    match idx & 7 {
        0 => r.rax = val,
        1 => r.rcx = val,
        2 => r.rdx = val,
        3 => r.rbx = val,
        4 => r.rsp = val,
        5 => r.rbp = val,
        6 => r.rsi = val,
        _ => r.rdi = val,
    }
}

fn reg_name(idx: u8) -> &'static str {
    match idx & 7 {
        0 => "rax",
        1 => "rcx",
        2 => "rdx",
        3 => "rbx",
        4 => "rsp",
        5 => "rbp",
        6 => "rsi",
        _ => "rdi",
    }
}

/// Pick a register operand 0..=7 but AVOID rsp/rbp (4,5) so generated code
/// never clobbers the stack pointer / frame pointer in a way that breaks the
/// run-to-HLT harness or makes stack comparison meaningless.
fn pick_gpr(rng: &mut Rng) -> u8 {
    loop {
        let v = rng.next_u32() as u8 & 7;
        if v != 4 && v != 5 {
            return v;
        }
    }
}

/// Emit the size prefix bytes (0x66 for 16-bit). REX is folded into modrm-emit.
fn size_prefix(size: Size) -> Vec<u8> {
    match size {
        Size::B16 => vec![0x66],
        _ => vec![],
    }
}

/// Build a REX byte if needed. For 64-bit ops W=1. We only use low-8 registers
/// here so R/X/B are 0; an empty REX (0x40) is still required for 8-bit ops that
/// would otherwise alias AH/BH/CH/DH — but since we restrict to rax..rdi (0..3)
/// and rsi/rdi (6,7) WITHOUT a REX, those map to AL/CL/DL/BL/AH/CH/DH/BH.
/// To keep 8-bit registers uniform (SPL/BPL/SIL/DIL low bytes) we always emit a
/// REX prefix for 8-bit ops. We never use rsp/rbp (4/5) as 8-bit so SPL/BPL are
/// avoided.
fn rex_byte(size: Size, force: bool) -> Option<u8> {
    match size {
        Size::B64 => Some(0x48),
        Size::B8 if force => Some(0x40),
        _ => None,
    }
}

// ===========================================================================
// GENERATOR (a): ALU reg,reg and reg,imm
// ===========================================================================
//
// ADD/OR/ADC/SBB/AND/SUB/XOR/CMP use the standard /r opcode groups. The
// "primary opcode" for the reg,reg (r/m <- r) form is one of 00/08/10/18/20/
// 28/30/38 (+1 for non-byte sizes). reg,imm uses group 0x80/0x81 with a /digit.
// INC/DEC/NEG/NOT/TEST round out the class.

#[derive(Clone, Copy)]
struct AluOp {
    name: &'static str,
    /// base opcode for the 8-bit r/m,r form (e.g. ADD = 0x00). The reg,reg form
    /// we emit is `[REX] base+? /r` writing into r/m.
    rm_r_op8: u8,
    /// /digit for the group-1 immediate form (0x80/0x81), and CF/OF semantics
    /// are identical to the reg,reg variant.
    imm_digit: u8,
    /// whether this op writes a result (vs CMP/TEST which only set flags).
    writes: bool,
}

const ALU_OPS: &[AluOp] = &[
    AluOp { name: "add", rm_r_op8: 0x00, imm_digit: 0, writes: true },
    AluOp { name: "or", rm_r_op8: 0x08, imm_digit: 1, writes: true },
    AluOp { name: "adc", rm_r_op8: 0x10, imm_digit: 2, writes: true },
    AluOp { name: "sbb", rm_r_op8: 0x18, imm_digit: 3, writes: true },
    AluOp { name: "and", rm_r_op8: 0x20, imm_digit: 4, writes: true },
    AluOp { name: "sub", rm_r_op8: 0x28, imm_digit: 5, writes: true },
    AluOp { name: "xor", rm_r_op8: 0x30, imm_digit: 6, writes: true },
    AluOp { name: "cmp", rm_r_op8: 0x38, imm_digit: 7, writes: false },
];

fn modrm(md: u8, reg: u8, rm: u8) -> u8 {
    ((md & 3) << 6) | ((reg & 7) << 3) | (rm & 7)
}

#[test]
fn fuzz_alu() {
    const CASES: usize = 400;
    let mut h = Harness::new(0x1111_2222_3333_4444);
    let sizes = [Size::B8, Size::B16, Size::B32, Size::B64];

    for _ in 0..CASES {
        let size = *h.rng.pick(&sizes);
        let op = *h.rng.pick(ALU_OPS);
        let dst = pick_gpr(&mut h.rng);
        let src = pick_gpr(&mut h.rng);
        let use_imm = h.rng.below(2) == 0;

        let mut r = Registers::default();
        let dval = h.rng.operand();
        let sval = h.rng.operand();
        set_reg(&mut r, dst, dval);
        if !use_imm {
            set_reg(&mut r, src, sval);
        }
        // random incoming CF for ADC/SBB.
        let cf_in = h.rng.below(2) == 1;
        if cf_in {
            r.rflags |= flags::bits::CF;
        }

        let mut code = size_prefix(size);
        if let Some(rex) = rex_byte(size, true) {
            code.push(rex);
        }

        let inputs;
        if use_imm {
            // group-1: 0x80 (8-bit) / 0x81 (others) with /digit in modrm.reg.
            let imm = h.rng.operand();
            let opc = if size == Size::B8 { 0x80 } else { 0x81 };
            code.push(opc);
            code.push(modrm(0b11, op.imm_digit, dst));
            match size {
                Size::B8 => code.push(imm as u8),
                Size::B16 => code.extend_from_slice(&(imm as u16).to_le_bytes()),
                // 32/64-bit imm form takes a 32-bit immediate (sign-extended for 64).
                _ => code.extend_from_slice(&(imm as u32).to_le_bytes()),
            }
            inputs = format!(
                "{} {} {}, imm={:#x} (cf_in={}); dst={:#x}",
                op.name, size.name(), reg_name(dst), imm, cf_in, dval
            );
        } else {
            // reg,reg writing into r/m: opcode = rm_r_op8 (+1 for non-byte).
            let opc = if size == Size::B8 { op.rm_r_op8 } else { op.rm_r_op8 + 1 };
            code.push(opc);
            code.push(modrm(0b11, src, dst)); // reg=src, rm=dst -> dst = dst OP src
            inputs = format!(
                "{} {} {}, {} (cf_in={}); dst={:#x} src={:#x}",
                op.name, size.name(), reg_name(dst), reg_name(src), cf_in, dval, sval
            );
        }
        code.push(HLT);

        let _ = op.writes; // (kept for clarity; all flags compared either way)
        let opts = CompareOpts::default();
        if !h.run_case("alu", &code, r, [0u8; 64], opts, inputs, &[]) {
            break;
        }
    }
    h.finish("alu");
}

// ===========================================================================
// GENERATOR: INC / DEC / NEG / NOT / TEST
// ===========================================================================

#[test]
fn fuzz_unary() {
    const CASES: usize = 300;
    let mut h = Harness::new(0x55AA_55AA_1234_9876);
    let sizes = [Size::B8, Size::B16, Size::B32, Size::B64];
    // (name, group opcode for non-byte, /digit, sets-CF?)
    // INC=FF/0, DEC=FF/1 (8-bit FE), NEG=F7/3, NOT=F7/2 (8-bit F6). TEST=group F7/0 with imm.
    #[derive(Clone, Copy)]
    enum U {
        Inc,
        Dec,
        Neg,
        Not,
        Test,
    }
    let ops = [U::Inc, U::Dec, U::Neg, U::Not, U::Test];

    for _ in 0..CASES {
        let size = *h.rng.pick(&sizes);
        let u = *h.rng.pick(&ops);
        let dst = pick_gpr(&mut h.rng);
        let mut r = Registers::default();
        let dval = h.rng.operand();
        set_reg(&mut r, dst, dval);
        // Preserve incoming CF to verify INC/DEC don't touch it.
        let cf_in = h.rng.below(2) == 1;
        if cf_in {
            r.rflags |= flags::bits::CF;
        }

        let mut code = size_prefix(size);
        if let Some(rex) = rex_byte(size, true) {
            code.push(rex);
        }
        let byte = size == Size::B8;
        let name;
        match u {
            U::Inc => {
                code.push(if byte { 0xFE } else { 0xFF });
                code.push(modrm(0b11, 0, dst));
                name = "inc";
            }
            U::Dec => {
                code.push(if byte { 0xFE } else { 0xFF });
                code.push(modrm(0b11, 1, dst));
                name = "dec";
            }
            U::Not => {
                code.push(if byte { 0xF6 } else { 0xF7 });
                code.push(modrm(0b11, 2, dst));
                name = "not";
            }
            U::Neg => {
                code.push(if byte { 0xF6 } else { 0xF7 });
                code.push(modrm(0b11, 3, dst));
                name = "neg";
            }
            U::Test => {
                // group F6/F7 /0 with immediate.
                let imm = h.rng.operand();
                code.push(if byte { 0xF6 } else { 0xF7 });
                code.push(modrm(0b11, 0, dst));
                match size {
                    Size::B8 => code.push(imm as u8),
                    Size::B16 => code.extend_from_slice(&(imm as u16).to_le_bytes()),
                    _ => code.extend_from_slice(&(imm as u32).to_le_bytes()),
                }
                name = "test";
            }
        }
        code.push(HLT);

        let inputs = format!("{} {} {} (cf_in={}); dst={:#x}", name, size.name(), reg_name(dst), cf_in, dval);
        if !h.run_case("unary", &code, r, [0u8; 64], CompareOpts::default(), inputs, &[]) {
            break;
        }
    }
    h.finish("unary");
}

// ===========================================================================
// GENERATOR (b): shifts / rotates by imm and by CL
// ===========================================================================
//
// Group-2 opcodes (D0/D1 = by 1, D2/D3 = by CL, C0/C1 = by imm8). The /digit
// selects ROL(0)/ROR(1)/RCL(2)/RCR(3)/SHL(4)/SHR(5)/SAR(7).
// SHLD/SHRD are 0F A4/A5 (imm/CL) and 0F AC/AD.
//
// Flag-definition: for a 1-bit count OF is defined; for count>1 OF is undefined.
// For a masked count of 0 NO flags change. We always compare GPRs; the flag mask
// depends on the count we generated.

// Exercises ROL/ROR/RCL/RCR/SHL/SHR/SAR across widths and counts vs KVM.
//
// REGRESSION GUARD: previously surfaced a real SAR CF bug — SAR by a 5-bit-masked
// count exceeding the operand width (e.g. `sar ax, 21` with AX=0xFFFF) computed
// CF=0 instead of the operand's sign bit. Fixed in src/backend/emulator/x86_64/
// insn/shift/core.rs (SAR arm: CF = sign bit when count > width). SHR/SHL leave
// CF undefined past the width, so the fuzzer masks CF out for those — only SAR's
// CF is defined (= sign bit) and checked here.
#[test]
fn fuzz_shifts() {
    const CASES: usize = 400;
    let mut h = Harness::new(0xDEAD_BEEF_F00D_CAFE);
    let sizes = [Size::B8, Size::B16, Size::B32, Size::B64];
    // (/digit, name); skip /6 (alias of SHL).
    let groups: &[(u8, &str)] = &[
        (0, "rol"),
        (1, "ror"),
        (2, "rcl"),
        (3, "rcr"),
        (4, "shl"),
        (5, "shr"),
        (7, "sar"),
    ];

    for _ in 0..CASES {
        let size = *h.rng.pick(&sizes);
        let &(digit, name) = h.rng.pick(groups);
        let dst = pick_gpr(&mut h.rng);
        let by_cl = h.rng.below(2) == 0;
        let is_rotate = digit <= 3;

        let mut r = Registers::default();
        let dval = h.rng.operand();
        set_reg(&mut r, dst, dval);
        // RCL/RCR feed CF in; randomize it.
        let cf_in = h.rng.below(2) == 1;
        if cf_in {
            r.rflags |= flags::bits::CF;
        }

        // Choose a shift count. The hardware masks the count to 5 bits (or 6 for
        // 64-bit). For RCL/RCR the modulo is by (opsize+1). Use a range that
        // exercises both small and large counts but is well-defined.
        let max_count = if size == Size::B64 { 63 } else { 31 };
        let count = (h.rng.below(max_count as u64 + 1)) as u8;

        let mut code = size_prefix(size);
        if let Some(rex) = rex_byte(size, true) {
            code.push(rex);
        }
        let byte = size == Size::B8;

        let inputs;
        if by_cl {
            r.rcx = count as u64;
            code.push(if byte { 0xD2 } else { 0xD3 });
            code.push(modrm(0b11, digit, dst));
            inputs = format!(
                "{} {} {}, cl={} (cf_in={}); dst={:#x}",
                name, size.name(), reg_name(dst), count, cf_in, dval
            );
        } else if count == 1 {
            // Use the dedicated by-1 form so OF is well-defined.
            code.push(if byte { 0xD0 } else { 0xD1 });
            code.push(modrm(0b11, digit, dst));
            inputs = format!(
                "{} {} {}, 1 (cf_in={}); dst={:#x}",
                name, size.name(), reg_name(dst), cf_in, dval
            );
        } else {
            code.push(if byte { 0xC0 } else { 0xC1 });
            code.push(modrm(0b11, digit, dst));
            code.push(count);
            inputs = format!(
                "{} {} {}, imm8={} (cf_in={}); dst={:#x}",
                name, size.name(), reg_name(dst), count, cf_in, dval
            );
        }
        code.push(HLT);

        // Flag mask. The hardware masks the count to 5 bits (6 for 64-bit) and
        // performs the shift by that masked count WITHOUT re-clamping to the
        // operand width. So for 8/16-bit ops the (masked) count can legitimately
        // exceed the operand width, which matters for CF definedness:
        //
        //  - masked count == 0 : nothing happens; ALL status flags unchanged.
        //  - count == 1        : OF defined. Rotate -> CF|OF; shift -> all.
        //  - 1 < count <= width: OF undefined. Rotate -> CF; shift -> CF|PF|ZF|SF.
        //  - count > width (only 8/16-bit):
        //      * SAR : result sign-fills, CF = sign bit (defined). -> CF|PF|ZF|SF.
        //      * SHL/SHR : result 0, but CF is architecturally UNDEFINED.
        //                  -> PF|ZF|SF only (drop CF and OF).
        //      * ROL/ROR/RCL/RCR : rotate amount is taken modulo (width) or
        //                  (width+1), so CF stays defined. -> CF.
        let mask_bits = if size == Size::B64 { 63u32 } else { 31u32 };
        let masked_count = (count as u32) & mask_bits;
        let width = size.bits();
        let is_sar = digit == 7;
        let shift_no_of = flags::bits::CF | flags::bits::PF | flags::bits::ZF | flags::bits::SF;
        let flag_mask = if masked_count == 0 {
            FLAG_MASK
        } else if masked_count == 1 {
            if is_rotate {
                flags::bits::CF | flags::bits::OF
            } else {
                FLAG_MASK
            }
        } else if is_rotate {
            flags::bits::CF
        } else if masked_count <= width {
            shift_no_of
        } else if is_sar {
            shift_no_of // SAR CF defined (= sign bit) even past the width.
        } else {
            // SHL/SHR past the width: CF undefined, result is 0 (PF/ZF/SF defined).
            flags::bits::PF | flags::bits::ZF | flags::bits::SF
        };

        let opts = CompareOpts {
            flag_mask,
            ..CompareOpts::default()
        };
        if !h.run_case("shifts", &code, r, [0u8; 64], opts, inputs, &[]) {
            break;
        }
    }
    h.finish("shifts");
}

#[test]
fn fuzz_double_shifts() {
    const CASES: usize = 250;
    let mut h = Harness::new(0x0F0F_1E2D_3C4B_5A69);
    let sizes = [Size::B16, Size::B32, Size::B64];

    for _ in 0..CASES {
        let size = *h.rng.pick(&sizes);
        let dst = pick_gpr(&mut h.rng);
        let mut src = pick_gpr(&mut h.rng);
        while src == dst {
            src = pick_gpr(&mut h.rng);
        }
        let left = h.rng.below(2) == 0; // SHLD vs SHRD
        let by_cl = h.rng.below(2) == 0;

        let mut r = Registers::default();
        let dval = h.rng.operand();
        let sval = h.rng.operand();
        set_reg(&mut r, dst, dval);
        set_reg(&mut r, src, sval);

        // Count must be < operand size to keep the result architecturally defined.
        let count = (h.rng.below(size.bits() as u64)) as u8;

        let mut code = size_prefix(size);
        if size == Size::B64 {
            code.push(0x48);
        }
        // SHLD imm = 0F A4, SHLD CL = 0F A5; SHRD imm = 0F AC, SHRD CL = 0F AD.
        code.push(0x0F);
        let name;
        if by_cl {
            r.rcx = count as u64;
            code.push(if left { 0xA5 } else { 0xAD });
            code.push(modrm(0b11, src, dst)); // reg=src, rm=dst
            name = if left { "shld_cl" } else { "shrd_cl" };
        } else {
            code.push(if left { 0xA4 } else { 0xAC });
            code.push(modrm(0b11, src, dst));
            code.push(count);
            name = if left { "shld_imm" } else { "shrd_imm" };
        }
        code.push(HLT);

        // OF defined only for count==1; AF undefined; count==0 -> no change.
        let flag_mask = if count == 0 {
            FLAG_MASK
        } else if count == 1 {
            flags::bits::CF | flags::bits::PF | flags::bits::ZF | flags::bits::SF | flags::bits::OF
        } else {
            flags::bits::CF | flags::bits::PF | flags::bits::ZF | flags::bits::SF
        };

        let inputs = format!(
            "{} {} {}, {}, {} ; dst={:#x} src={:#x}",
            name, size.name(), reg_name(dst), reg_name(src), count, dval, sval
        );
        let opts = CompareOpts {
            flag_mask,
            ..CompareOpts::default()
        };
        if !h.run_case("double_shifts", &code, r, [0u8; 64], opts, inputs, &[]) {
            break;
        }
    }
    h.finish("double_shifts");
}

// ===========================================================================
// GENERATOR (c): bit ops BT/BTS/BTR/BTC/BSF/BSR/POPCNT/LZCNT/TZCNT
// ===========================================================================

#[test]
fn fuzz_bitops() {
    const CASES: usize = 400;
    let mut h = Harness::new(0xBEEF_CAFE_1357_9BDF);
    // Only 32/64-bit for these (8/16-bit BT exists but is less interesting and
    // we want clean register-index modulo behavior).
    let sizes = [Size::B32, Size::B64];

    #[derive(Clone, Copy)]
    enum B {
        Bt,
        Bts,
        Btr,
        Btc,
        Bsf,
        Bsr,
        Popcnt,
        Lzcnt,
        Tzcnt,
    }
    let ops = [B::Bt, B::Bts, B::Btr, B::Btc, B::Bsf, B::Bsr, B::Popcnt, B::Lzcnt, B::Tzcnt];

    for _ in 0..CASES {
        let size = *h.rng.pick(&sizes);
        let op = *h.rng.pick(&ops);
        let dst = pick_gpr(&mut h.rng);
        let mut src = pick_gpr(&mut h.rng);
        while src == dst {
            src = pick_gpr(&mut h.rng);
        }
        let w64 = size == Size::B64;

        let mut r = Registers::default();
        let dval = h.rng.operand();
        set_reg(&mut r, dst, dval);

        let mut code = Vec::new();
        let name;
        let flag_mask;
        let mut ignore: Vec<&'static str> = Vec::new();
        let mut inputs;

        match op {
            B::Bt | B::Bts | B::Btr | B::Btc => {
                // BT(A3)/BTS(AB)/BTR(B3)/BTC(BB) reg form: [REX.W] 0F xx /r,
                // reg=index, rm=dst. Index register modulo operand size.
                let bitidx = h.rng.below(if w64 { 128 } else { 64 }); // exceed size to test modulo
                set_reg(&mut r, src, bitidx);
                if w64 {
                    code.push(0x48);
                }
                code.push(0x0F);
                let (opc, n) = match op {
                    B::Bt => (0xA3u8, "bt"),
                    B::Bts => (0xAB, "bts"),
                    B::Btr => (0xB3, "btr"),
                    _ => (0xBB, "btc"),
                };
                code.push(opc);
                code.push(modrm(0b11, src, dst));
                name = n;
                flag_mask = flags::bits::CF; // BT* define only CF.
                inputs = format!(
                    "{} {} {}, {}={} ; dst={:#x}",
                    name, size.name(), reg_name(dst), reg_name(src), bitidx, dval
                );
            }
            B::Bsf | B::Bsr => {
                // [REX.W] 0F BC/BD /r, reg=dst, rm=src.
                set_reg(&mut r, src, dval);
                let srcval = dval;
                // preload dst with a sentinel to detect undefined-dest mishandling
                let sentinel = 0xA5A5_A5A5_A5A5_A5A5u64;
                set_reg(&mut r, dst, sentinel);
                if w64 {
                    code.push(0x48);
                }
                code.push(0x0F);
                let (opc, n) = if matches!(op, B::Bsf) { (0xBCu8, "bsf") } else { (0xBD, "bsr") };
                code.push(opc);
                code.push(modrm(0b11, dst, src));
                name = n;
                flag_mask = flags::bits::ZF; // BSF/BSR define only ZF.
                                             // When src==0 the destination is architecturally undefined.
                let masked_src = if w64 { srcval } else { srcval & 0xFFFF_FFFF };
                if masked_src == 0 {
                    ignore.push(reg_name(dst));
                }
                inputs = format!(
                    "{} {} {}, {} ; src={:#x}",
                    name, size.name(), reg_name(dst), reg_name(src), srcval
                );
            }
            B::Popcnt | B::Lzcnt | B::Tzcnt => {
                // F3 [REX.W] 0F B8/BD/BC /r, reg=dst, rm=src.
                set_reg(&mut r, src, dval);
                code.push(0xF3);
                if w64 {
                    code.push(0x48);
                }
                code.push(0x0F);
                let (opc, n, fm) = match op {
                    B::Popcnt => (0xB8u8, "popcnt", FLAG_MASK), // POPCNT defines all flags (ZF + others cleared).
                    B::Lzcnt => (0xBD, "lzcnt", flags::bits::CF | flags::bits::ZF),
                    _ => (0xBC, "tzcnt", flags::bits::CF | flags::bits::ZF),
                };
                code.push(opc);
                code.push(modrm(0b11, dst, src));
                name = n;
                flag_mask = fm;
                inputs = format!(
                    "{} {} {}, {} ; src={:#x}",
                    name, size.name(), reg_name(dst), reg_name(src), dval
                );
            }
        }
        code.push(HLT);
        let _ = &mut inputs;

        let opts = CompareOpts {
            flag_mask,
            ..CompareOpts::default()
        };
        if !h.run_case("bitops", &code, r, [0u8; 64], opts, inputs, &ignore) {
            break;
        }
    }
    h.finish("bitops");
}

// ===========================================================================
// GENERATOR (d): MUL / IMUL / DIV / IDIV
// ===========================================================================
//
// One-operand forms (F6/F7 group): MUL=/4, IMUL=/5, DIV=/6, IDIV=/7. We avoid
// #DE for DIV/IDIV by constructing the dividend so the quotient always fits.
// MUL/IMUL define only CF/OF (others undefined). DIV/IDIV leave ALL flags
// undefined (mask 0). Also fuzz the two/three-operand IMUL forms.

#[test]
fn fuzz_muldiv() {
    const CASES: usize = 350;
    let mut h = Harness::new(0xABCD_1234_5678_9EF0);
    let sizes = [Size::B8, Size::B16, Size::B32, Size::B64];
    let muldiv_defined = flags::bits::CF | flags::bits::OF;

    for _ in 0..CASES {
        let size = *h.rng.pick(&sizes);
        let kind = h.rng.below(4); // 0=mul 1=imul1 2=div 3=idiv (one-operand)
        // 2-operand IMUL (0F AF) has no 8-bit form, so only for 16/32/64-bit.
        let two_op = kind == 1 && size != Size::B8 && h.rng.below(2) == 0;

        let mut r = Registers::default();
        let bits = size.bits();
        let mask: u128 = if bits == 64 { u128::MAX >> 64 } else { (1u128 << bits) - 1 };

        let src = pick_gpr(&mut h.rng);
        // Don't use rax/rdx as the explicit source for 1-op forms (they're implicit).
        let mut srcr = src;
        while srcr == 0 || srcr == 2 {
            srcr = pick_gpr(&mut h.rng);
        }

        let mut code = size_prefix(size);
        let inputs;
        let flag_mask;

        if two_op {
            // IMUL r, r/m : [REX.W] 0F AF /r  (reg = dest = reg * rm). 2-operand
            // defines CF/OF; result is the low half (truncated), GPR defined.
            let dst = pick_gpr(&mut h.rng);
            let a = h.rng.operand();
            let b = h.rng.operand();
            set_reg(&mut r, dst, a);
            let s2 = if dst == srcr { (srcr + 1) & 7 } else { srcr };
            let s2 = if s2 == 4 || s2 == 5 { 6 } else { s2 };
            set_reg(&mut r, s2, b);
            if size == Size::B64 {
                code.push(0x48);
            }
            code.push(0x0F);
            code.push(0xAF);
            code.push(modrm(0b11, dst, s2));
            code.push(HLT);
            flag_mask = muldiv_defined;
            inputs = format!(
                "imul2 {} {}, {} ; a={:#x} b={:#x}",
                size.name(), reg_name(dst), reg_name(s2), a, b
            );
            let opts = CompareOpts {
                flag_mask,
                ..CompareOpts::default()
            };
            if !h.run_case("muldiv", &code, r, [0u8; 64], opts, inputs, &[]) {
                break;
            }
            continue;
        }

        let byte = size == Size::B8;
        if size == Size::B64 {
            code.push(0x48);
        } else if byte {
            // Force a REX prefix for 8-bit so modrm.rm in {6,7} addresses
            // SIL/DIL (low bytes) rather than aliasing to DH/BH, which would
            // read garbage and spuriously raise #DE on the divide.
            code.push(0x40);
        }

        match kind {
            0 | 1 => {
                // MUL (/4) or IMUL (/5) one-operand. Implicit op in (R)AX,
                // result in (R)DX:(R)AX (or AX for 8-bit). Random operands.
                let a = h.rng.operand();
                let b = h.rng.operand();
                r.rax = a;
                set_reg(&mut r, srcr, b);
                code.push(if byte { 0xF6 } else { 0xF7 });
                code.push(modrm(0b11, if kind == 0 { 4 } else { 5 }, srcr));
                flag_mask = muldiv_defined;
                inputs = format!(
                    "{} {} {} ; rax={:#x} {}={:#x}",
                    if kind == 0 { "mul" } else { "imul1" },
                    size.name(),
                    reg_name(srcr),
                    a,
                    reg_name(srcr),
                    b
                );
            }
            _ => {
                // DIV (/6) or IDIV (/7). Build dividend so the quotient fits and
                // the divisor is nonzero, avoiding #DE entirely.
                let divisor = {
                    let mut d = h.rng.operand() & (mask as u64);
                    if d == 0 {
                        d = 1;
                    }
                    d
                };
                set_reg(&mut r, srcr, divisor);

                if kind == 2 {
                    // Unsigned: pick quotient < divisor-bound and remainder < divisor,
                    // then dividend = quotient*divisor + remainder fits in 2*bits.
                    let q = (h.rng.operand() as u128) & mask; // quotient fits in `bits`
                    let rem = (h.rng.operand() as u128) % (divisor as u128); // < divisor
                    // dividend = q*divisor + rem is exact and its high half fits in
                    // `bits` because q <= mask and the product can't exceed 2*bits.
                    let dividend = q * (divisor as u128) + rem;
                    let lo = dividend & mask;
                    let hi = (dividend >> bits) & mask;
                    place_dividend(&mut r, size, lo as u64, hi as u64);
                    code.push(if byte { 0xF6 } else { 0xF7 });
                    code.push(modrm(0b11, 6, srcr));
                    flag_mask = 0; // all flags undefined for DIV.
                    inputs = format!(
                        "div {} {}={:#x} ; dividend_lo={:#x} hi={:#x}",
                        size.name(), reg_name(srcr), divisor, lo as u64, hi as u64
                    );
                } else {
                    // Signed IDIV. Build from a signed quotient/remainder that fit.
                    let smax: i128 = if bits == 64 {
                        i64::MAX as i128
                    } else {
                        (1i128 << (bits - 1)) - 1
                    };
                    let sdiv = {
                        let mut d = sign_extend(divisor, bits) as i128;
                        if d == 0 {
                            d = 1;
                        }
                        d
                    };
                    // quotient in a safe range so it fits in `bits` signed and the
                    // product doesn't overflow the double-width dividend.
                    let q = (sign_extend(h.rng.operand(), bits) as i128) % (smax / sdiv.abs().max(1) + 1).max(1);
                    let rem_bound = sdiv.abs();
                    let mut rem = (h.rng.next_u64() as i128) % rem_bound.max(1);
                    // remainder sign follows the dividend; keep |rem| < |divisor|.
                    if q < 0 || (q == 0 && rem != 0 && h.rng.below(2) == 0) {
                        rem = -rem.abs();
                    } else {
                        rem = rem.abs();
                    }
                    let dividend: i128 = q * sdiv + rem;
                    let unsigned = (dividend as u128) & (mask | (mask << bits));
                    let lo = (unsigned & mask) as u64;
                    let hi = ((unsigned >> bits) & mask) as u64;
                    place_dividend(&mut r, size, lo, hi);
                    code.push(if byte { 0xF6 } else { 0xF7 });
                    code.push(modrm(0b11, 7, srcr));
                    flag_mask = 0;
                    inputs = format!(
                        "idiv {} {}={:#x} ; dividend_lo={:#x} hi={:#x} (q={} rem={})",
                        size.name(), reg_name(srcr), divisor, lo, hi, q, rem
                    );
                }
            }
        }
        code.push(HLT);

        let opts = CompareOpts {
            flag_mask,
            ..CompareOpts::default()
        };
        if !h.run_case("muldiv", &code, r, [0u8; 64], opts, inputs, &[]) {
            break;
        }
    }
    h.finish("muldiv");
}

fn sign_extend(v: u64, bits: u32) -> i64 {
    if bits >= 64 {
        return v as i64;
    }
    let shift = 64 - bits;
    (((v << shift) as i64) >> shift) as i64
}

/// Place a dividend into the implicit registers for a one-operand DIV/IDIV of
/// the given size: 8-bit uses AX (lo=AL, hi=AH packed), others use (R)DX:(R)AX.
fn place_dividend(r: &mut Registers, size: Size, lo: u64, hi: u64) {
    match size {
        Size::B8 => {
            // AX = (hi << 8) | lo
            r.rax = (r.rax & !0xFFFF) | ((hi & 0xFF) << 8) | (lo & 0xFF);
        }
        Size::B16 => {
            r.rax = (r.rax & !0xFFFF) | (lo & 0xFFFF);
            r.rdx = (r.rdx & !0xFFFF) | (hi & 0xFFFF);
        }
        Size::B32 => {
            // 32-bit ops zero-extend into the full 64-bit reg.
            r.rax = lo & 0xFFFF_FFFF;
            r.rdx = hi & 0xFFFF_FFFF;
        }
        Size::B64 => {
            r.rax = lo;
            r.rdx = hi;
        }
    }
}

// ===========================================================================
// GENERATOR (e): MOVSX / MOVZX / MOVSXD / BSWAP / SETcc / CMOVcc
// ===========================================================================

#[test]
fn fuzz_movext_bswap() {
    const CASES: usize = 300;
    let mut h = Harness::new(0x1A2B_3C4D_5E6F_7081);

    for _ in 0..CASES {
        let kind = h.rng.below(5); // 0=movzxb 1=movsxb 2=movzxw 3=movsxw 4=movsxd
        let dst = pick_gpr(&mut h.rng);
        let mut src = pick_gpr(&mut h.rng);
        while src == dst {
            src = pick_gpr(&mut h.rng);
        }
        // Destination 64-bit (REX.W) so we see the full extension.
        let mut r = Registers::default();
        let sval = h.rng.operand();
        set_reg(&mut r, src, sval);
        // Preload dst to detect partial-write bugs.
        set_reg(&mut r, dst, 0xCCCC_CCCC_CCCC_CCCC);

        let mut code = vec![0x48]; // REX.W
        let name;
        match kind {
            0 => {
                code.extend_from_slice(&[0x0F, 0xB6, modrm(0b11, dst, src)]);
                name = "movzx_b";
            }
            1 => {
                code.extend_from_slice(&[0x0F, 0xBE, modrm(0b11, dst, src)]);
                name = "movsx_b";
            }
            2 => {
                code.extend_from_slice(&[0x0F, 0xB7, modrm(0b11, dst, src)]);
                name = "movzx_w";
            }
            3 => {
                code.extend_from_slice(&[0x0F, 0xBF, modrm(0b11, dst, src)]);
                name = "movsx_w";
            }
            _ => {
                // MOVSXD r64, r/m32 = REX.W 63 /r.
                code.extend_from_slice(&[0x63, modrm(0b11, dst, src)]);
                name = "movsxd";
            }
        }
        code.push(HLT);

        let inputs = format!("{} {}, {} ; src={:#x}", name, reg_name(dst), reg_name(src), sval);
        // mov-extend ops don't touch flags -> compare all (they should be unchanged).
        if !h.run_case("movext", &code, r, [0u8; 64], CompareOpts::default(), inputs, &[]) {
            break;
        }
    }
    h.finish("movext");
}

#[test]
fn fuzz_bswap() {
    const CASES: usize = 200;
    let mut h = Harness::new(0x7777_3333_BBBB_DDDD);
    let sizes = [Size::B32, Size::B64];
    for _ in 0..CASES {
        let size = *h.rng.pick(&sizes);
        let reg = pick_gpr(&mut h.rng);
        let mut r = Registers::default();
        let v = h.rng.operand();
        set_reg(&mut r, reg, v);
        // BSWAP = [REX.W] 0F C8+rd. We restrict to rax..rdi (0..7) low regs.
        let mut code = Vec::new();
        if size == Size::B64 {
            code.push(0x48);
        }
        code.push(0x0F);
        code.push(0xC8 + (reg & 7));
        code.push(HLT);
        let inputs = format!("bswap {} {} ; v={:#x}", size.name(), reg_name(reg), v);
        if !h.run_case("bswap", &code, r, [0u8; 64], CompareOpts::default(), inputs, &[]) {
            break;
        }
    }
    h.finish("bswap");
}

#[test]
fn fuzz_setcc_cmovcc() {
    const CASES: usize = 400;
    let mut h = Harness::new(0x9988_7766_5544_3322);

    for _ in 0..CASES {
        // First establish a random flag state via CMP of two random values, then
        // run SETcc or CMOVcc and compare. The flag state is fully defined so we
        // compare all status flags and the destination.
        let cc = (h.rng.below(16)) as u8; // condition 0..15 -> opcode 0x90+cc / 0x40+cc
        let is_cmov = h.rng.below(2) == 0;

        let a = h.rng.operand();
        let b = h.rng.operand();
        let mut r = Registers::default();
        r.rax = a;
        r.rbx = b;

        // cmp rax, rbx (REX.W 39 /r): reg=rbx(3), rm=rax(0).
        let mut code = vec![0x48, 0x39, modrm(0b11, 3, 0)];
        let name;
        if is_cmov {
            // cmovcc rax, rcx : REX.W 0F (40+cc) /r, reg=rax(0), rm=rcx(1).
            let cval = h.rng.operand();
            r.rcx = cval;
            // sentinel already in rax via `a`; CMOV may or may not overwrite.
            code.extend_from_slice(&[0x48, 0x0F, 0x40 + cc, modrm(0b11, 0, 1)]);
            name = "cmov";
            code.push(HLT);
            let inputs = format!("cmp+cmov cc={:#x} ; a={:#x} b={:#x} c={:#x}", cc, a, b, cval);
            if !h.run_case("cmov", &code, r, [0u8; 64], CompareOpts::default(), inputs, &[]) {
                break;
            }
        } else {
            // setcc al : 0F (90+cc) /0, then movzx eax, al for a clean 0/1.
            code.extend_from_slice(&[0x0F, 0x90 + cc, modrm(0b11, 0, 0)]);
            code.extend_from_slice(&[0x0F, 0xB6, 0xC0]); // movzx eax, al
            name = "setcc";
            code.push(HLT);
            let inputs = format!("cmp+setcc cc={:#x} ; a={:#x} b={:#x}", cc, a, b);
            if !h.run_case("setcc", &code, r, [0u8; 64], CompareOpts::default(), inputs, &[]) {
                break;
            }
        }
        let _ = name;
    }
    h.finish("setcc/cmovcc");
}

// ===========================================================================
// GENERATOR (f): BMI1 / BMI2 (VEX-encoded)
// ===========================================================================
//
// Encodings adapted from differential.rs (proven correct against KVM). We fuzz
// the inputs and (where applicable) the register selection is fixed to the
// worked-out forms to keep VEX byte construction simple and correct:
//   ANDN  eax, ebx, ecx : C4 E2 60 F2 C1   (dest=~ebx & ecx)
//   BLSI  eax, ecx      : C4 E2 78 F3 D9
//   BLSR  eax, ecx      : C4 E2 78 F3 C9
//   BLSMSK eax, ecx     : C4 E2 78 F3 D1
//   PEXT  eax, ebx, ecx : C4 E2 62 F5 C1
//   PDEP  eax, ebx, ecx : C4 E2 63 F5 C1
//   MULX  eax, ebx, ecx : C4 E2 63 F6 C1   (edx implicit)
//   RORX  eax, ecx, imm : C4 E3 7B F0 C1 ib
//   SARX  eax, ecx, ebx : C4 E2 62 F7 C1
//   SHRX  eax, ecx, ebx : C4 E2 63 F7 C1
//   SHLX  eax, ecx, ebx : C4 E2 61 F7 C1
//   BZHI  eax, ecx, ebx : C4 E2 60 F5 C1
// 64-bit variants set the VEX.W bit (byte3 |= 0x80 for two-byte-payload group).

#[test]
fn fuzz_bmi() {
    const CASES: usize = 400;
    let mut h = Harness::new(0x2468_ACE0_1357_9BDF);
    let bmi_flags = flags::bits::ZF | flags::bits::SF | flags::bits::CF | flags::bits::OF;
    let bzhi_flags = flags::bits::ZF | flags::bits::CF | flags::bits::SF | flags::bits::OF;

    #[derive(Clone, Copy)]
    enum M {
        Andn,
        Blsi,
        Blsr,
        Blsmsk,
        Bzhi,
        Pext,
        Pdep,
        Mulx,
        Rorx,
        Sarx,
        Shrx,
        Shlx,
    }
    let ops = [
        M::Andn, M::Blsi, M::Blsr, M::Blsmsk, M::Bzhi, M::Pext, M::Pdep, M::Mulx, M::Rorx, M::Sarx, M::Shrx, M::Shlx,
    ];

    for _ in 0..CASES {
        let op = *h.rng.pick(&ops);
        let w64 = h.rng.below(2) == 1;
        let mut r = Registers::default();
        let ebx = h.rng.operand();
        let ecx = h.rng.operand();
        let edx = h.rng.operand();
        r.rbx = ebx;
        r.rcx = ecx;
        r.rdx = edx;

        // byte3 base (W0) per op; set W1 by OR-ing 0x80.
        let mut code = vec![0xC4u8];
        let inputs;
        let flag_mask;
        match op {
            M::Andn => {
                let b3 = 0x60 | if w64 { 0x80 } else { 0 };
                code.extend_from_slice(&[0xE2, b3, 0xF2, 0xC1]);
                flag_mask = bmi_flags;
                inputs = format!("andn{} eax,ebx,ecx ; ebx={:#x} ecx={:#x}", wbits(w64), ebx, ecx);
            }
            M::Blsi => {
                code.extend_from_slice(&[0xE2, 0x78 | if w64 { 0x80 } else { 0 }, 0xF3, 0xD9]);
                flag_mask = bmi_flags;
                inputs = format!("blsi{} eax,ecx ; ecx={:#x}", wbits(w64), ecx);
            }
            M::Blsr => {
                code.extend_from_slice(&[0xE2, 0x78 | if w64 { 0x80 } else { 0 }, 0xF3, 0xC9]);
                flag_mask = bmi_flags;
                inputs = format!("blsr{} eax,ecx ; ecx={:#x}", wbits(w64), ecx);
            }
            M::Blsmsk => {
                code.extend_from_slice(&[0xE2, 0x78 | if w64 { 0x80 } else { 0 }, 0xF3, 0xD1]);
                flag_mask = bmi_flags;
                inputs = format!("blsmsk{} eax,ecx ; ecx={:#x}", wbits(w64), ecx);
            }
            M::Bzhi => {
                code.extend_from_slice(&[0xE2, 0x60 | if w64 { 0x80 } else { 0 }, 0xF5, 0xC1]);
                flag_mask = bzhi_flags;
                inputs = format!("bzhi{} eax,ecx,ebx ; ecx={:#x} ebx={:#x}", wbits(w64), ecx, ebx);
            }
            M::Pext => {
                // pp=10(F3): byte3 = 0x62 (W0) / 0xE2 (W1).
                code.extend_from_slice(&[0xE2, if w64 { 0xE2 } else { 0x62 }, 0xF5, 0xC1]);
                flag_mask = 0;
                inputs = format!("pext{} eax,ebx,ecx ; ebx={:#x} ecx={:#x}", wbits(w64), ebx, ecx);
            }
            M::Pdep => {
                // pp=11(F2): byte3 = 0x63 (W0) / 0xE3 (W1).
                code.extend_from_slice(&[0xE2, if w64 { 0xE3 } else { 0x63 }, 0xF5, 0xC1]);
                flag_mask = 0;
                inputs = format!("pdep{} eax,ebx,ecx ; ebx={:#x} ecx={:#x}", wbits(w64), ebx, ecx);
            }
            M::Mulx => {
                // pp=11(F2): byte3 = 0x63 (W0) / 0xE3 (W1). edx implicit.
                code.extend_from_slice(&[0xE2, if w64 { 0xE3 } else { 0x63 }, 0xF6, 0xC1]);
                flag_mask = 0;
                inputs = format!("mulx{} eax,ebx,ecx ; edx={:#x} ecx={:#x}", wbits(w64), edx, ecx);
            }
            M::Rorx => {
                // map 0F3A, pp=11(F2): byte2=0xE3, byte3 = 0x7B (W0) / 0xFB (W1).
                let imm = (h.rng.below(if w64 { 64 } else { 32 })) as u8;
                code.extend_from_slice(&[0xE3, if w64 { 0xFB } else { 0x7B }, 0xF0, 0xC1, imm]);
                flag_mask = 0;
                inputs = format!("rorx{} eax,ecx,{} ; ecx={:#x}", wbits(w64), imm, ecx);
            }
            M::Sarx => {
                // pp=10(F3): byte3 = 0x62 (W0) / 0xE2 (W1). count in ebx (vvvv).
                code.extend_from_slice(&[0xE2, if w64 { 0xE2 } else { 0x62 }, 0xF7, 0xC1]);
                flag_mask = 0;
                inputs = format!("sarx{} eax,ecx,ebx ; ecx={:#x} ebx={:#x}", wbits(w64), ecx, ebx);
            }
            M::Shrx => {
                // pp=11(F2): byte3 = 0x63 (W0) / 0xE3 (W1).
                code.extend_from_slice(&[0xE2, if w64 { 0xE3 } else { 0x63 }, 0xF7, 0xC1]);
                flag_mask = 0;
                inputs = format!("shrx{} eax,ecx,ebx ; ecx={:#x} ebx={:#x}", wbits(w64), ecx, ebx);
            }
            M::Shlx => {
                // pp=01(66): byte3 = 0x61 (W0) / 0xE1 (W1).
                code.extend_from_slice(&[0xE2, if w64 { 0xE1 } else { 0x61 }, 0xF7, 0xC1]);
                flag_mask = 0;
                inputs = format!("shlx{} eax,ecx,ebx ; ecx={:#x} ebx={:#x}", wbits(w64), ecx, ebx);
            }
        }
        code.push(HLT);

        let opts = CompareOpts {
            flag_mask,
            ..CompareOpts::default()
        };
        if !h.run_case("bmi", &code, r, [0u8; 64], opts, inputs, &[]) {
            break;
        }
    }
    h.finish("bmi");
}

fn wbits(w64: bool) -> &'static str {
    if w64 {
        "64"
    } else {
        "32"
    }
}

// ===========================================================================
// GENERATOR (g): SSE2 integer ops via the scratch-memory pattern
// ===========================================================================
//
// As in differential.rs: the guest loads two 128-bit inputs from the scratch
// page into xmm0/xmm1, runs a 2-operand SSE op, and stores xmm0 back. We feed
// random 16-byte inputs and compare the result page byte-for-byte. SSE integer
// ops don't set RFLAGS.

fn sse_program(op: &[u8]) -> Vec<u8> {
    let mut code = Vec::new();
    // mov rdi, DATA_ADDR (imm32 sign-extended)
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

#[test]
fn fuzz_sse2() {
    const CASES: usize = 400;
    let mut h = Harness::new(0xF1E2_D3C4_B5A6_9788);

    // (name, opcode-bytes-after-modrm-C1). All are `66 0F xx /r` 2-operand forms
    // on xmm0,xmm1 except where noted. PSHUFD takes an imm8.
    // Each entry: (name, opcode_prefix_bytes, takes_imm)
    struct SseOp {
        name: &'static str,
        // bytes BEFORE the C1 modrm (i.e. prefix + 0F + opcode); we append modrm
        // 0xC1 (xmm0,xmm1) and optional imm.
        bytes: &'static [u8],
        takes_imm: bool,
    }
    let ops: &[SseOp] = &[
        SseOp { name: "paddb", bytes: &[0x66, 0x0F, 0xFC], takes_imm: false },
        SseOp { name: "paddw", bytes: &[0x66, 0x0F, 0xFD], takes_imm: false },
        SseOp { name: "paddd", bytes: &[0x66, 0x0F, 0xFE], takes_imm: false },
        SseOp { name: "paddq", bytes: &[0x66, 0x0F, 0xD4], takes_imm: false },
        SseOp { name: "psubb", bytes: &[0x66, 0x0F, 0xF8], takes_imm: false },
        SseOp { name: "psubw", bytes: &[0x66, 0x0F, 0xF9], takes_imm: false },
        SseOp { name: "psubd", bytes: &[0x66, 0x0F, 0xFA], takes_imm: false },
        SseOp { name: "psubq", bytes: &[0x66, 0x0F, 0xFB], takes_imm: false },
        SseOp { name: "paddsb", bytes: &[0x66, 0x0F, 0xEC], takes_imm: false },
        SseOp { name: "paddsw", bytes: &[0x66, 0x0F, 0xED], takes_imm: false },
        SseOp { name: "paddusb", bytes: &[0x66, 0x0F, 0xDC], takes_imm: false },
        SseOp { name: "paddusw", bytes: &[0x66, 0x0F, 0xDD], takes_imm: false },
        SseOp { name: "psubsb", bytes: &[0x66, 0x0F, 0xE8], takes_imm: false },
        SseOp { name: "psubsw", bytes: &[0x66, 0x0F, 0xE9], takes_imm: false },
        SseOp { name: "psubusb", bytes: &[0x66, 0x0F, 0xD8], takes_imm: false },
        SseOp { name: "psubusw", bytes: &[0x66, 0x0F, 0xD9], takes_imm: false },
        SseOp { name: "pand", bytes: &[0x66, 0x0F, 0xDB], takes_imm: false },
        SseOp { name: "pandn", bytes: &[0x66, 0x0F, 0xDF], takes_imm: false },
        SseOp { name: "por", bytes: &[0x66, 0x0F, 0xEB], takes_imm: false },
        SseOp { name: "pxor", bytes: &[0x66, 0x0F, 0xEF], takes_imm: false },
        SseOp { name: "pcmpeqb", bytes: &[0x66, 0x0F, 0x74], takes_imm: false },
        SseOp { name: "pcmpeqw", bytes: &[0x66, 0x0F, 0x75], takes_imm: false },
        SseOp { name: "pcmpeqd", bytes: &[0x66, 0x0F, 0x76], takes_imm: false },
        SseOp { name: "pcmpgtb", bytes: &[0x66, 0x0F, 0x64], takes_imm: false },
        SseOp { name: "pcmpgtw", bytes: &[0x66, 0x0F, 0x65], takes_imm: false },
        SseOp { name: "pcmpgtd", bytes: &[0x66, 0x0F, 0x66], takes_imm: false },
        SseOp { name: "pmullw", bytes: &[0x66, 0x0F, 0xD5], takes_imm: false },
        SseOp { name: "pmulhw", bytes: &[0x66, 0x0F, 0xE5], takes_imm: false },
        SseOp { name: "pmulhuw", bytes: &[0x66, 0x0F, 0xE4], takes_imm: false },
        SseOp { name: "pmuludq", bytes: &[0x66, 0x0F, 0xF4], takes_imm: false },
        SseOp { name: "pmaddwd", bytes: &[0x66, 0x0F, 0xF5], takes_imm: false },
        SseOp { name: "psadbw", bytes: &[0x66, 0x0F, 0xF6], takes_imm: false },
        SseOp { name: "pavgb", bytes: &[0x66, 0x0F, 0xE0], takes_imm: false },
        SseOp { name: "pavgw", bytes: &[0x66, 0x0F, 0xE3], takes_imm: false },
        SseOp { name: "pminub", bytes: &[0x66, 0x0F, 0xDA], takes_imm: false },
        SseOp { name: "pmaxub", bytes: &[0x66, 0x0F, 0xDE], takes_imm: false },
        SseOp { name: "pminsw", bytes: &[0x66, 0x0F, 0xEA], takes_imm: false },
        SseOp { name: "pmaxsw", bytes: &[0x66, 0x0F, 0xEE], takes_imm: false },
        SseOp { name: "packsswb", bytes: &[0x66, 0x0F, 0x63], takes_imm: false },
        SseOp { name: "packssdw", bytes: &[0x66, 0x0F, 0x6B], takes_imm: false },
        SseOp { name: "packuswb", bytes: &[0x66, 0x0F, 0x67], takes_imm: false },
        SseOp { name: "punpcklbw", bytes: &[0x66, 0x0F, 0x60], takes_imm: false },
        SseOp { name: "punpcklwd", bytes: &[0x66, 0x0F, 0x61], takes_imm: false },
        SseOp { name: "punpckldq", bytes: &[0x66, 0x0F, 0x62], takes_imm: false },
        SseOp { name: "punpcklqdq", bytes: &[0x66, 0x0F, 0x6C], takes_imm: false },
        SseOp { name: "punpckhbw", bytes: &[0x66, 0x0F, 0x68], takes_imm: false },
        SseOp { name: "punpckhwd", bytes: &[0x66, 0x0F, 0x69], takes_imm: false },
        SseOp { name: "punpckhdq", bytes: &[0x66, 0x0F, 0x6A], takes_imm: false },
        SseOp { name: "punpckhqdq", bytes: &[0x66, 0x0F, 0x6D], takes_imm: false },
        SseOp { name: "pshufd", bytes: &[0x66, 0x0F, 0x70], takes_imm: true },
    ];

    for _ in 0..CASES {
        let op = h.rng.pick(ops);
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        for i in 0..16 {
            a[i] = h.rng.next_u32() as u8;
            b[i] = h.rng.next_u32() as u8;
        }
        // Occasionally bias to all-equal / all-zero / sign-boundary lanes.
        match h.rng.below(6) {
            0 => b = a,                                // equality
            1 => a = [0; 16],
            2 => a = [0xFF; 16],
            3 => b = [0x80; 16],
            _ => {}
        }

        let mut opbytes = op.bytes.to_vec();
        opbytes.push(0xC1); // modrm: xmm0, xmm1
        let imm = (h.rng.next_u32() & 0xFF) as u8;
        if op.takes_imm {
            opbytes.push(imm);
        }
        let code = sse_program(&opbytes);

        let mut scratch = [0u8; 64];
        scratch[0..16].copy_from_slice(&a);
        scratch[16..32].copy_from_slice(&b);

        let inputs = format!(
            "{}{} ; a={:02x?} b={:02x?}",
            op.name,
            if op.takes_imm { format!(" imm={imm:#x}") } else { String::new() },
            a,
            b
        );
        let opts = CompareOpts {
            flag_mask: 0,
            scratch: true,
            ..CompareOpts::default()
        };
        if !h.run_case("sse2", &code, Registers::default(), scratch, opts, inputs, &[]) {
            break;
        }
    }
    h.finish("sse2");
}

// ===========================================================================
// GENERATOR: SSE2 shifts by immediate (PSLLW/PSRLW/PSRAW/PSLLD.../PSLLQ/PSRLQ)
// ===========================================================================
//
// These use the group-12/13/14 encodings with the count in modrm.reg and an
// imm8 count: 66 0F 71/72/73 /digit ib operating on xmm0. The shift acts on
// xmm0 in place; we store it back and compare. No flags.

#[test]
fn fuzz_sse_shift_imm() {
    const CASES: usize = 250;
    let mut h = Harness::new(0x0BAD_C0DE_DEAD_F00D);

    // (group_opcode, /digit, name)
    // 71: word ops  -> /2 PSRLW, /4 PSRAW, /6 PSLLW
    // 72: dword ops -> /2 PSRLD, /4 PSRAD, /6 PSLLD
    // 73: qword ops -> /2 PSRLQ, /6 PSLLQ, /3 PSRLDQ(byte), /7 PSLLDQ(byte)
    let variants: &[(u8, u8, &str)] = &[
        (0x71, 2, "psrlw"),
        (0x71, 4, "psraw"),
        (0x71, 6, "psllw"),
        (0x72, 2, "psrld"),
        (0x72, 4, "psrad"),
        (0x72, 6, "pslld"),
        (0x73, 2, "psrlq"),
        (0x73, 6, "psllq"),
        (0x73, 3, "psrldq"),
        (0x73, 7, "pslldq"),
    ];

    for _ in 0..CASES {
        let &(grp, digit, name) = h.rng.pick(variants);
        let mut a = [0u8; 16];
        for i in 0..16 {
            a[i] = h.rng.next_u32() as u8;
        }
        // count: 0..=18 so we exercise in-range, exactly-size, and over-size
        // (which the ISA defines as zeroing for element shifts; byte shifts
        // saturate at 16).
        let count = (h.rng.below(19)) as u8;

        // Program: load xmm0 from scratch, run the shift on xmm0 (modrm.rm=xmm0),
        // store back. modrm = 11 <digit> 000 (rm=xmm0=0).
        let mut code = Vec::new();
        code.extend_from_slice(&[0x48, 0xC7, 0xC7]);
        code.extend_from_slice(&(DATA_ADDR as u32).to_le_bytes());
        code.extend_from_slice(&[0xF3, 0x0F, 0x6F, 0x07]); // movdqu xmm0, [rdi]
        code.extend_from_slice(&[0x66, 0x0F, grp, modrm(0b11, digit, 0), count]);
        code.extend_from_slice(&[0xF3, 0x0F, 0x7F, 0x47, 0x20]); // movdqu [rdi+0x20], xmm0
        code.push(HLT);

        let mut scratch = [0u8; 64];
        scratch[0..16].copy_from_slice(&a);

        let inputs = format!("{} xmm0, {} ; a={:02x?}", name, count, a);
        let opts = CompareOpts {
            flag_mask: 0,
            scratch: true,
            ..CompareOpts::default()
        };
        if !h.run_case("sse_shift_imm", &code, Registers::default(), scratch, opts, inputs, &[]) {
            break;
        }
    }
    h.finish("sse_shift_imm");
}

// ===========================================================================
// GENERATOR: memory-operand address decoding (ModRM / SIB / disp / RIP-rel)
// ===========================================================================
//
// Every other generator uses mod=0b11 (register-direct operands), so the
// effective-address computation path (`decode_modrm_addr`: base + index*scale
// + displacement, the SIB byte, the mod=00/rm=5 RIP-relative form, and the
// SIB base=5 "disp32, no base" form) was entirely unexercised against KVM.
// This generates MOV load/store instructions whose memory operand exercises
// every one of those forms, arranging registers + displacements so the
// effective address always lands inside the 64-byte scratch region. A wrong
// decoded address surfaces as a wrong loaded register (load) or wrong scratch
// bytes (store).
//
// Fixed register assignment (all distinct, none rsp/rbp):
//   reg field (moved register) = rax (enc 0)
//   base                       = rbx (enc 3)
//   index                      = rsi (enc 6)
#[derive(Clone, Copy)]
enum AddrForm {
    Base,       // mod=00 rm=base          [rbx]
    BaseDisp8,  // mod=01 rm=base          [rbx+d8]
    BaseDisp32, // mod=10 rm=base          [rbx+d32]
    Sib,        // mod=00 rm=4 SIB         [rbx + rsi*s]
    SibDisp8,   // mod=01 rm=4 SIB + d8    [rbx + rsi*s + d8]
    SibDisp32,  // mod=10 rm=4 SIB + d32   [rbx + rsi*s + d32]
    SibNoIndex, // mod=00 rm=4 SIB idx=4   [rbx]            (no-index encoding)
    SibNoBase,  // mod=00 rm=4 SIB base=5  [rsi*s + disp32] (no base)
    RipRel,     // mod=00 rm=5             [rip + disp32]
}

#[test]
fn fuzz_mem_addressing() {
    const CASES: usize = 700;
    let mut h = Harness::new(0xADD4_E55F_0FF5_E701);
    let sizes = [Size::B8, Size::B16, Size::B32, Size::B64];
    let forms = [
        AddrForm::Base,
        AddrForm::BaseDisp8,
        AddrForm::BaseDisp32,
        AddrForm::Sib,
        AddrForm::SibDisp8,
        AddrForm::SibDisp32,
        AddrForm::SibNoIndex,
        AddrForm::SibNoBase,
        AddrForm::RipRel,
    ];

    const REG: u8 = 0; // rax, the moved register (reg field)
    const BASE: u8 = 3; // rbx
    const INDEX: u8 = 6; // rsi

    for _ in 0..CASES {
        let size = *h.rng.pick(&sizes);
        let bytes = (size.bits() / 8) as u64;
        let form = *h.rng.pick(&forms);
        let is_store = h.rng.below(2) == 0;

        // Effective address: keep [EA, EA+bytes) inside the 64-byte scratch.
        let target_off = h.rng.below(64 - bytes + 1);
        let ea = DATA_ADDR + target_off;

        let scale_bits = h.rng.below(4) as u8; // 0..3 -> *1,*2,*4,*8
        let scale = 1u64 << scale_bits;
        let idxv = h.rng.below(8); // small index value

        let mut r = Registers::default();
        let sval = h.rng.operand(); // source value for stores
        set_reg(&mut r, REG, sval);

        let mut code = size_prefix(size);
        if let Some(rex) = rex_byte(size, true) {
            code.push(rex);
        }
        let opcode = match (is_store, size == Size::B8) {
            (true, true) => 0x88,
            (true, false) => 0x89,
            (false, true) => 0x8A,
            (false, false) => 0x8B,
        };
        code.push(opcode);

        match form {
            AddrForm::Base => {
                code.push(modrm(0b00, REG, BASE));
                set_reg(&mut r, BASE, ea);
            }
            AddrForm::BaseDisp8 => {
                let d8 = (h.rng.next_u32() as i8) as i64;
                code.push(modrm(0b01, REG, BASE));
                set_reg(&mut r, BASE, ea.wrapping_sub(d8 as u64));
                code.push(d8 as u8);
            }
            AddrForm::BaseDisp32 => {
                let d32 = h.rng.next_u32() as i32 as i64;
                code.push(modrm(0b10, REG, BASE));
                set_reg(&mut r, BASE, ea.wrapping_sub(d32 as u64));
                code.extend_from_slice(&(d32 as i32).to_le_bytes());
            }
            AddrForm::Sib => {
                code.push(modrm(0b00, REG, 4));
                code.push((scale_bits << 6) | (INDEX << 3) | BASE);
                set_reg(&mut r, INDEX, idxv);
                set_reg(&mut r, BASE, ea.wrapping_sub(idxv.wrapping_mul(scale)));
            }
            AddrForm::SibDisp8 => {
                let d8 = (h.rng.next_u32() as i8) as i64;
                code.push(modrm(0b01, REG, 4));
                code.push((scale_bits << 6) | (INDEX << 3) | BASE);
                set_reg(&mut r, INDEX, idxv);
                set_reg(
                    &mut r,
                    BASE,
                    ea.wrapping_sub(idxv.wrapping_mul(scale)).wrapping_sub(d8 as u64),
                );
                code.push(d8 as u8);
            }
            AddrForm::SibDisp32 => {
                let d32 = h.rng.next_u32() as i32 as i64;
                code.push(modrm(0b10, REG, 4));
                code.push((scale_bits << 6) | (INDEX << 3) | BASE);
                set_reg(&mut r, INDEX, idxv);
                set_reg(
                    &mut r,
                    BASE,
                    ea.wrapping_sub(idxv.wrapping_mul(scale)).wrapping_sub(d32 as u64),
                );
                code.extend_from_slice(&(d32 as i32).to_le_bytes());
            }
            AddrForm::SibNoIndex => {
                // index=4 in SIB encodes "no index". EA = base.
                code.push(modrm(0b00, REG, 4));
                code.push((scale_bits << 6) | (4 << 3) | BASE);
                set_reg(&mut r, BASE, ea);
            }
            AddrForm::SibNoBase => {
                // mod=00, SIB base=5 => no base register, disp32 follows.
                // EA = index*scale + disp32.
                code.push(modrm(0b00, REG, 4));
                code.push((scale_bits << 6) | (INDEX << 3) | 5);
                set_reg(&mut r, INDEX, idxv);
                let disp = ea.wrapping_sub(idxv.wrapping_mul(scale)) as i64 as i32;
                code.extend_from_slice(&disp.to_le_bytes());
            }
            AddrForm::RipRel => {
                // mod=00, rm=5 => [rip + disp32], rip = address of NEXT insn.
                code.push(modrm(0b00, REG, 5));
                let rip_after = CODE_ADDR + code.len() as u64 + 4;
                let disp = ea.wrapping_sub(rip_after) as i64 as i32;
                code.extend_from_slice(&disp.to_le_bytes());
            }
        }
        code.push(HLT);

        // Random scratch contents (the load source / store target window).
        let mut scratch = [0u8; 64];
        for b in scratch.iter_mut() {
            *b = h.rng.next_u32() as u8;
        }

        let dir = if is_store { "store" } else { "load" };
        let inputs = format!(
            "mov.{} {} ea={:#x} off={} scale={} idxv={}",
            size.name(),
            dir,
            ea,
            target_off,
            scale,
            idxv
        );
        // MOV does not affect flags; compare scratch (stores) + all GPRs (loads).
        let opts = CompareOpts {
            flag_mask: 0,
            scratch: true,
            ..CompareOpts::default()
        };
        if !h.run_case("mem_addressing", &code, r, scratch, opts, inputs, &[]) {
            break;
        }
    }
    h.finish("mem_addressing");
}

// ===========================================================================
// GENERATOR: LEA (0x8D) — pure effective-address computation
// ===========================================================================
//
// LEA computes base + index*scale + disp into a register WITHOUT dereferencing
// memory, so it never faults and the base/index/disp values are unconstrained.
// That makes it the broadest possible test of `decode_modrm_addr` plus the
// operand-size truncation rules (16-bit preserves the upper 48 bits of the
// destination, 32-bit zero-extends, 64-bit is full) and the 0x67 address-size
// override (32-bit address arithmetic, wraps at 2^32). KVM is the oracle.
#[test]
fn fuzz_lea() {
    const CASES: usize = 700;
    let mut h = Harness::new(0x1EA5_1EA5_C0DE_F00D);
    let opsizes = [Size::B16, Size::B32, Size::B64];
    let forms = [
        AddrForm::Base,
        AddrForm::BaseDisp8,
        AddrForm::BaseDisp32,
        AddrForm::Sib,
        AddrForm::SibDisp8,
        AddrForm::SibDisp32,
        AddrForm::SibNoIndex,
        AddrForm::SibNoBase,
        AddrForm::RipRel,
    ];

    const REG: u8 = 0; // rax (dest)
    const BASE: u8 = 3; // rbx
    const INDEX: u8 = 6; // rsi

    for _ in 0..CASES {
        let size = *h.rng.pick(&opsizes);
        let form = *h.rng.pick(&forms);
        let addr32 = h.rng.below(4) == 0; // 0x67 address-size override
        let scale_bits = h.rng.below(4) as u8;

        let mut r = Registers::default();
        set_reg(&mut r, BASE, h.rng.operand());
        set_reg(&mut r, INDEX, h.rng.operand());
        set_reg(&mut r, REG, h.rng.operand()); // prior dest value (partial-write test)

        let mut code = Vec::new();
        if addr32 {
            code.push(0x67);
        }
        if size == Size::B16 {
            code.push(0x66);
        }
        if size == Size::B64 {
            code.push(0x48); // REX.W
        }
        code.push(0x8D); // LEA r, m

        let d8 = h.rng.next_u32() as u8;
        let d32 = h.rng.next_u32();
        match form {
            AddrForm::Base => {
                code.push(modrm(0b00, REG, BASE));
            }
            AddrForm::BaseDisp8 => {
                code.push(modrm(0b01, REG, BASE));
                code.push(d8);
            }
            AddrForm::BaseDisp32 => {
                code.push(modrm(0b10, REG, BASE));
                code.extend_from_slice(&d32.to_le_bytes());
            }
            AddrForm::Sib => {
                code.push(modrm(0b00, REG, 4));
                code.push((scale_bits << 6) | (INDEX << 3) | BASE);
            }
            AddrForm::SibDisp8 => {
                code.push(modrm(0b01, REG, 4));
                code.push((scale_bits << 6) | (INDEX << 3) | BASE);
                code.push(d8);
            }
            AddrForm::SibDisp32 => {
                code.push(modrm(0b10, REG, 4));
                code.push((scale_bits << 6) | (INDEX << 3) | BASE);
                code.extend_from_slice(&d32.to_le_bytes());
            }
            AddrForm::SibNoIndex => {
                code.push(modrm(0b00, REG, 4));
                code.push((scale_bits << 6) | (4 << 3) | BASE);
            }
            AddrForm::SibNoBase => {
                code.push(modrm(0b00, REG, 4));
                code.push((scale_bits << 6) | (INDEX << 3) | 5);
                code.extend_from_slice(&d32.to_le_bytes());
            }
            AddrForm::RipRel => {
                code.push(modrm(0b00, REG, 5));
                code.extend_from_slice(&d32.to_le_bytes());
            }
        }
        code.push(HLT);

        let inputs = format!(
            "lea.{} addr32={} form#{} scale={} rbx={:#x} rsi={:#x}",
            size.name(),
            addr32,
            form as u8,
            1u64 << scale_bits,
            r.rbx,
            r.rsi
        );
        let opts = CompareOpts {
            flag_mask: 0,
            scratch: false,
            ..CompareOpts::default()
        };
        if !h.run_case("lea", &code, r, [0u8; 64], opts, inputs, &[]) {
            break;
        }
    }
    h.finish("lea");
}

// ===========================================================================
// GENERATOR: ALU with a MEMORY operand (read-modify-write + flags + decode)
// ===========================================================================
//
// Combines three previously-separate concerns into one case: effective-address
// decode (mem operand at scratch), the ALU op itself, RFLAGS, and the memory
// write-back — and it drives reads AND writes through the host-pointer fast
// path (`ram_ptr`) under flag-setting ops, a stronger check of that path than
// the MOV-only `mem_addressing` generator. Covers both directions:
//   r/m <- r/m OP reg   (memory destination, opcode base +0/+1)
//   reg <- reg OP r/m   (register destination, opcode base +2/+3)
#[test]
fn fuzz_alu_mem() {
    const CASES: usize = 600;
    let mut h = Harness::new(0xA10_3E3F_DEAD_5E11);
    let sizes = [Size::B8, Size::B16, Size::B32, Size::B64];

    const REG: u8 = 0; // rax (the register operand)
    const BASE: u8 = 3; // rbx (memory base)

    for _ in 0..CASES {
        let size = *h.rng.pick(&sizes);
        let bytes = (size.bits() / 8) as u64;
        let op = *h.rng.pick(ALU_OPS);
        let mem_dest = h.rng.below(2) == 0; // true: [mem] OP= reg ; false: reg OP= [mem]
        let use_disp8 = h.rng.below(2) == 0;

        let target_off = h.rng.below(64 - bytes + 1);
        let ea = DATA_ADDR + target_off;

        let mut r = Registers::default();
        let rval = h.rng.operand();
        set_reg(&mut r, REG, rval);
        // random incoming CF for ADC/SBB
        let cf_in = h.rng.below(2) == 1;
        if cf_in {
            r.rflags |= flags::bits::CF;
        }

        let mut code = size_prefix(size);
        if let Some(rex) = rex_byte(size, true) {
            code.push(rex);
        }
        // base opcode: rm_r_op8 is the r/m8,r8 form; +1 non-byte. +2/+3 swap to r,r/m.
        let mut opc = op.rm_r_op8;
        if !mem_dest {
            opc += 2;
        }
        if size != Size::B8 {
            opc += 1;
        }
        code.push(opc);

        // modrm: reg=REG, rm=memory at [rbx] or [rbx+disp8]
        if use_disp8 {
            let d8 = (h.rng.next_u32() as i8) as i64;
            code.push(modrm(0b01, REG, BASE));
            set_reg(&mut r, BASE, ea.wrapping_sub(d8 as u64));
            code.push(d8 as u8);
        } else {
            code.push(modrm(0b00, REG, BASE));
            set_reg(&mut r, BASE, ea);
        }
        code.push(HLT);

        let mut scratch = [0u8; 64];
        for b in scratch.iter_mut() {
            *b = h.rng.next_u32() as u8;
        }

        let dir = if mem_dest { "[m]op=r" } else { "r op=[m]" };
        let inputs = format!(
            "{}.{} {} ea={:#x} reg={:#x} cf_in={}",
            op.name,
            size.name(),
            dir,
            ea,
            rval,
            cf_in
        );
        // ALU sets flags; compare flags + scratch (mem dest) + GPRs (reg dest).
        let opts = CompareOpts {
            scratch: true,
            ..CompareOpts::default()
        };
        if !h.run_case("alu_mem", &code, r, scratch, opts, inputs, &[]) {
            break;
        }
    }
    h.finish("alu_mem");
}

// ===========================================================================
// GENERATOR: REP MOVS / REP STOS (string copy/fill) vs KVM
// ===========================================================================
//
// String ops were entirely unfuzzed, yet they drive the bulk memcpy/memset
// fast paths (and the per-element fallback) through the host-pointer accessors.
// This sets RSI/RDI into two non-overlapping halves of the scratch region,
// RCX to a small count, DF=0 (forward), and runs REP MOVS / REP STOS across
// all four element sizes, comparing the destination bytes + RSI/RDI/RCX (which
// must end advanced by count*size, RCX=0) against KVM.
#[test]
fn fuzz_string_rep() {
    const CASES: usize = 500;
    let mut h = Harness::new(0x5717_900D_B01C_F00D);
    // element sizes 1/2/4/8
    let sizes = [Size::B8, Size::B16, Size::B32, Size::B64];

    for _ in 0..CASES {
        let size = *h.rng.pick(&sizes);
        let bytes = (size.bits() / 8) as u64;
        let is_stos = h.rng.below(2) == 0;
        // src in [0,32), dst in [32,64); count*size <= 32 so both stay in-bounds.
        let max_count = 32 / bytes;
        let count = 1 + h.rng.below(max_count); // 1..=max_count

        let mut r = Registers::default();
        r.rcx = count;
        r.rdi = DATA_ADDR + 32; // destination
        if is_stos {
            r.rax = h.rng.operand(); // value to store (AL/AX/EAX/RAX)
        } else {
            r.rsi = DATA_ADDR; // source
        }
        // DF=0 (forward) — default; rflags |= 0x2 added by harness.

        let mut code = Vec::new();
        code.push(0xF3); // REP
        if size == Size::B16 {
            code.push(0x66);
        }
        if size == Size::B64 {
            code.push(0x48); // REX.W
        }
        let opc = match (is_stos, size == Size::B8) {
            (false, true) => 0xA4,  // MOVSB
            (false, false) => 0xA5, // MOVSW/D/Q
            (true, true) => 0xAA,   // STOSB
            (true, false) => 0xAB,  // STOSW/D/Q
        };
        code.push(opc);
        code.push(HLT);

        let mut scratch = [0u8; 64];
        for b in scratch.iter_mut() {
            *b = h.rng.next_u32() as u8;
        }

        let op = if is_stos { "rep stos" } else { "rep movs" };
        let inputs = format!(
            "{}.{} count={} rax={:#x}",
            op,
            size.name(),
            count,
            r.rax
        );
        let opts = CompareOpts {
            scratch: true,
            ..CompareOpts::default()
        };
        if !h.run_case("string_rep", &code, r, scratch, opts, inputs, &[]) {
            break;
        }
    }
    h.finish("string_rep");
}

// ===========================================================================
// GENERATOR: CMPXCHG / XADD (atomic read-modify-write) vs KVM
// ===========================================================================
//
// CMPXCHG (0F B0/B1) compares the accumulator (AL/AX/EAX/RAX) with r/m: on
// equal it stores the source into r/m and sets ZF; on not-equal it loads r/m
// into the accumulator. XADD (0F C0/C1) sums r/m+reg into r/m and returns the
// old r/m in reg. Both set ADD/CMP-style flags and have fiddly accumulator /
// operand-aliasing behaviour — and were unfuzzed. Register-direct form keeps
// the encoding simple; KVM is the oracle for the conditional update + flags.
#[test]
fn fuzz_cmpxchg_xadd() {
    const CASES: usize = 500;
    let mut h = Harness::new(0xC0FFEE_A70319CE);
    let sizes = [Size::B8, Size::B16, Size::B32, Size::B64];

    for _ in 0..CASES {
        let size = *h.rng.pick(&sizes);
        let is_xadd = h.rng.below(2) == 0;
        let dst = pick_gpr(&mut h.rng); // r/m
        let src = pick_gpr(&mut h.rng); // reg

        let mut r = Registers::default();
        let dval = h.rng.operand();
        let sval = h.rng.operand();
        set_reg(&mut r, dst, dval);
        set_reg(&mut r, src, sval);
        // For CMPXCHG, force the equal-case ~half the time by seeding RAX with
        // the destination value (masked to size); else a random accumulator.
        if !is_xadd {
            if h.rng.below(2) == 0 {
                r.rax = dval; // likely-equal path (ZF=1, store src)
            } else {
                r.rax = h.rng.operand();
            }
        }
        let cf_in = h.rng.below(2) == 1;
        if cf_in {
            r.rflags |= flags::bits::CF;
        }

        let mut code = size_prefix(size);
        if let Some(rex) = rex_byte(size, true) {
            code.push(rex);
        }
        code.push(0x0F);
        let opc = match (is_xadd, size == Size::B8) {
            (false, true) => 0xB0,  // CMPXCHG r/m8, r8
            (false, false) => 0xB1, // CMPXCHG r/m, r
            (true, true) => 0xC0,   // XADD r/m8, r8
            (true, false) => 0xC1,  // XADD r/m, r
        };
        code.push(opc);
        code.push(modrm(0b11, src, dst)); // reg=src, rm=dst
        code.push(HLT);

        let op = if is_xadd { "xadd" } else { "cmpxchg" };
        let inputs = format!(
            "{}.{} {}, {}; dst={:#x} src={:#x} rax={:#x} cf_in={}",
            op,
            size.name(),
            reg_name(dst),
            reg_name(src),
            dval,
            sval,
            r.rax,
            cf_in
        );
        let opts = CompareOpts::default();
        if !h.run_case("cmpxchg_xadd", &code, r, [0u8; 64], opts, inputs, &[]) {
            break;
        }
    }
    h.finish("cmpxchg_xadd");
}

// ===========================================================================
// SMIR backend: lift x86 -> SMIR -> SMIR-interpret -> compare to KVM
// ===========================================================================
//
// The first milestone of integrating SMIR (src/smir/) as a tiered hot-block
// JIT: validate that the x86 lifter + SMIR interpreter reproduce KVM's
// architectural state bit-for-bit. We reuse this file's KVM oracle (run_kvm),
// the comparison logic (compare), and the random instruction generators.
//
// Key state-bridge facts (verified against src/smir):
//  * GPRs map 1:1 via ctx.write_arch_reg / read_arch_reg (RAX,RCX,RDX,RBX,...).
//  * FLAGS are double-stored: the interpreter updates ctx.flags (lazy/material),
//    NOT the x86.rflags field. So we SET init flags via MaterializedFlags::
//    from_rflags + clear lazy, and READ final flags via materialize_all()/
//    to_rflags() — NOT read_arch_reg(Rflags).
//  * RIP lives only in ctx.pc (interp never writes x86.rip); compare() ignores
//    rip, so the harness is unaffected.
//  * Lift in STRICT mode: unsupported opcodes -> Err -> skip the case (the
//    lifter covers ~65-75% of common integer user-mode insns; SIMD/atomics/
//    LOOP/SCAS etc. are gaps and are skipped, not failed).

enum SmirOutcome {
    Ran(FinalState),
    Skipped(String),
}

fn run_smir(code: &[u8], init: &Registers, scratch_init: &[u8; 64]) -> Result<SmirOutcome, String> {
    use rax::smir::context::{ExitReason, SmirContext};
    use rax::smir::flags::MaterializedFlags;
    use rax::smir::interp::SmirInterpreter;
    use rax::smir::lift::x86_64::X86_64Lifter;
    use rax::smir::lift::{LiftContext, MemoryReader, SmirLifter};
    use rax::smir::memory::{FlatMemory, MemoryError, SmirMemory};
    use rax::smir::types::{ArchReg, SourceArch, X86Reg};

    // Lifter reads code starting at CODE_ADDR.
    struct CodeReader {
        base: u64,
        bytes: Vec<u8>,
    }
    impl MemoryReader for CodeReader {
        fn read(&self, addr: u64, size: usize) -> Result<Vec<u8>, MemoryError> {
            let off = addr
                .checked_sub(self.base)
                .filter(|&o| (o as usize) < self.bytes.len())
                .ok_or(MemoryError::OutOfBounds { addr })? as usize;
            let n = (self.bytes.len() - off).min(size);
            Ok(self.bytes[off..off + n].to_vec())
        }
    }

    let reader = CodeReader {
        base: CODE_ADDR,
        bytes: code.to_vec(),
    };
    let mut lifter = X86_64Lifter::strict();
    let mut lctx = LiftContext::new(SourceArch::X86_64);
    let block = match lifter.lift_block(CODE_ADDR, &reader, &mut lctx) {
        Ok(b) => b,
        Err(e) => return Ok(SmirOutcome::Skipped(format!("lift: {e:?}"))),
    };

    let mut interp = SmirInterpreter::new();
    interp.set_max_insns(MAX_ITERS);
    interp.add_block(CODE_ADDR, block);

    // Flat execution memory covering code(0x10000)/stack(0x20000)/data(0x30000).
    let mut mem = FlatMemory::new(0x40_000);
    mem.load(CODE_ADDR as usize, code);
    mem.load(DATA_ADDR as usize, scratch_init);

    let mut ctx = SmirContext::new_x86_64();
    ctx.pc = CODE_ADDR;
    let gprs = [
        (X86Reg::Rax, init.rax),
        (X86Reg::Rcx, init.rcx),
        (X86Reg::Rdx, init.rdx),
        (X86Reg::Rbx, init.rbx),
        (X86Reg::Rsp, if init.rsp == 0 { STACK_ADDR } else { init.rsp }),
        (X86Reg::Rbp, init.rbp),
        (X86Reg::Rsi, init.rsi),
        (X86Reg::Rdi, init.rdi),
        (X86Reg::R8, init.r8),
        (X86Reg::R9, init.r9),
        (X86Reg::R10, init.r10),
        (X86Reg::R11, init.r11),
        (X86Reg::R12, init.r12),
        (X86Reg::R13, init.r13),
        (X86Reg::R14, init.r14),
        (X86Reg::R15, init.r15),
    ];
    for (r, v) in gprs {
        ctx.write_arch_reg(ArchReg::X86(r), v);
    }
    // Init flags through the lazy-flag model (NOT the dead x86.rflags field).
    ctx.flags.materialized = MaterializedFlags::from_rflags(init.rflags | 0x2);
    ctx.flags.lazy = None;

    let exit = interp.run(&mut ctx, &mut mem);
    match exit {
        ExitReason::Halt => {}
        other => return Ok(SmirOutcome::Skipped(format!("exit: {other:?}"))),
    }

    let mut regs = Registers::default();
    regs.rax = ctx.read_arch_reg(ArchReg::X86(X86Reg::Rax));
    regs.rcx = ctx.read_arch_reg(ArchReg::X86(X86Reg::Rcx));
    regs.rdx = ctx.read_arch_reg(ArchReg::X86(X86Reg::Rdx));
    regs.rbx = ctx.read_arch_reg(ArchReg::X86(X86Reg::Rbx));
    regs.rsp = ctx.read_arch_reg(ArchReg::X86(X86Reg::Rsp));
    regs.rbp = ctx.read_arch_reg(ArchReg::X86(X86Reg::Rbp));
    regs.rsi = ctx.read_arch_reg(ArchReg::X86(X86Reg::Rsi));
    regs.rdi = ctx.read_arch_reg(ArchReg::X86(X86Reg::Rdi));
    regs.r8 = ctx.read_arch_reg(ArchReg::X86(X86Reg::R8));
    regs.r9 = ctx.read_arch_reg(ArchReg::X86(X86Reg::R9));
    regs.r10 = ctx.read_arch_reg(ArchReg::X86(X86Reg::R10));
    regs.r11 = ctx.read_arch_reg(ArchReg::X86(X86Reg::R11));
    regs.r12 = ctx.read_arch_reg(ArchReg::X86(X86Reg::R12));
    regs.r13 = ctx.read_arch_reg(ArchReg::X86(X86Reg::R13));
    regs.r14 = ctx.read_arch_reg(ArchReg::X86(X86Reg::R14));
    regs.r15 = ctx.read_arch_reg(ArchReg::X86(X86Reg::R15));
    ctx.flags.materialize_all();
    regs.rflags = ctx.flags.materialized.to_rflags();
    regs.rip = ctx.pc;

    let mut scratch = [0u8; 64];
    mem.read(DATA_ADDR, &mut scratch)
        .map_err(|e| format!("scratch read: {e:?}"))?;

    Ok(SmirOutcome::Ran(FinalState {
        xmm: [[0u64; 2]; 16],
        regs,
        scratch,
    }))
}

/// Accumulator for a SMIR-vs-KVM generator: counts lifted/skipped cases and
/// collects divergences (mirrors `Harness` but for the SMIR backend).
struct SmirStats {
    ran: usize,
    skipped: usize,
    kvm_ok: bool,
    mismatches: Vec<Mismatch>,
}

impl SmirStats {
    fn new() -> Self {
        SmirStats { ran: 0, skipped: 0, kvm_ok: true, mismatches: Vec::new() }
    }

    fn check(
        &mut self,
        label: &str,
        code: &[u8],
        init: Registers,
        scratch_init: [u8; 64],
        opts: CompareOpts,
        inputs: String,
    ) -> bool {
        let kvm = match run_kvm(code, &init, &scratch_init) {
            Ok(Some(s)) => s,
            Ok(None) => {
                self.kvm_ok = false;
                return false;
            }
            Err(e) => {
                self.mismatches.push(Mismatch {
                    label: format!("{label} (kvm error)"),
                    code: code.to_vec(),
                    inputs,
                    diffs: vec![e],
                });
                return true;
            }
        };
        match run_smir(code, &init, &scratch_init) {
            Ok(SmirOutcome::Ran(smir)) => {
                self.ran += 1;
                let diffs = compare(&smir, &kvm, opts, &[]);
                if !diffs.is_empty() {
                    self.mismatches.push(Mismatch {
                        label: label.to_string(),
                        code: code.to_vec(),
                        inputs,
                        diffs,
                    });
                }
            }
            Ok(SmirOutcome::Skipped(_)) => self.skipped += 1,
            Err(e) => self.mismatches.push(Mismatch {
                label: format!("{label} (smir error)"),
                code: code.to_vec(),
                inputs,
                diffs: vec![e],
            }),
        }
        true
    }

    fn finish(self, class: &str) {
        if !self.kvm_ok && self.ran == 0 {
            eprintln!("[skip] /dev/kvm unavailable; skipping smir {class}");
            return;
        }
        if !self.mismatches.is_empty() {
            let mut out = format!(
                "SMIR DIVERGENCES in `{class}` (smir vs KVM): {} of {} lifted cases diverged ({} skipped/unsupported):\n",
                self.mismatches.len(),
                self.ran,
                self.skipped
            );
            for m in self.mismatches.iter().take(20) {
                out.push_str(&m.render());
                out.push('\n');
            }
            if self.mismatches.len() > 20 {
                out.push_str(&format!("  ... and {} more\n", self.mismatches.len() - 20));
            }
            panic!("{out}");
        }
        eprintln!(
            "[ok] smir {class}: {} lifted cases agree with KVM ({} skipped/unsupported)",
            self.ran, self.skipped
        );
    }
}

// SMIR validation: ALU reg,reg and reg,imm (the lifter's strongest area; the
// hardest test of the flag bridge). Mirrors fuzz_alu's generation.
#[test]
fn smir_alu() {
    const CASES: usize = 400;
    let mut rng = Rng::new(0x5317_A1FA_B0BA_CAFE);
    let mut stats = SmirStats::new();
    let sizes = [Size::B8, Size::B16, Size::B32, Size::B64];

    for _ in 0..CASES {
        let size = *rng.pick(&sizes);
        let op = *rng.pick(ALU_OPS);
        let dst = pick_gpr(&mut rng);
        let src = pick_gpr(&mut rng);
        let use_imm = rng.below(2) == 0;

        let mut r = Registers::default();
        let dval = rng.operand();
        let sval = rng.operand();
        set_reg(&mut r, dst, dval);
        if !use_imm {
            set_reg(&mut r, src, sval);
        }
        let cf_in = rng.below(2) == 1;
        if cf_in {
            r.rflags |= flags::bits::CF;
        }

        let mut code = size_prefix(size);
        if let Some(rex) = rex_byte(size, true) {
            code.push(rex);
        }
        let inputs;
        if use_imm {
            let imm = rng.operand();
            let opc = if size == Size::B8 { 0x80 } else { 0x81 };
            code.push(opc);
            code.push(modrm(0b11, op.imm_digit, dst));
            match size {
                Size::B8 => code.push(imm as u8),
                Size::B16 => code.extend_from_slice(&(imm as u16).to_le_bytes()),
                _ => code.extend_from_slice(&(imm as u32).to_le_bytes()),
            }
            inputs = format!(
                "{} {} {}, imm={:#x} (cf_in={}); dst={:#x}",
                op.name, size.name(), reg_name(dst), imm, cf_in, dval
            );
        } else {
            let opc = if size == Size::B8 { op.rm_r_op8 } else { op.rm_r_op8 + 1 };
            code.push(opc);
            code.push(modrm(0b11, src, dst));
            inputs = format!(
                "{} {} {}, {} (cf_in={}); dst={:#x} src={:#x}",
                op.name, size.name(), reg_name(dst), reg_name(src), cf_in, dval, sval
            );
        }
        code.push(HLT);

        if !stats.check("smir_alu", &code, r, [0u8; 64], CompareOpts::default(), inputs) {
            break;
        }
    }
    stats.finish("alu");
}


// SMIR validation: SHL/SHR/SAR/ROL/ROR/RCL/RCR by imm8/1/CL. Mirrors
// fuzz_shifts's generation EXACTLY (same opcodes/encodings/operands/flag masks)
// but drives the SMIR backend via SmirStats.
#[test]
fn smir_shifts() {
    const CASES: usize = 400;
    let mut rng = Rng::new(0xDEAD_BEEF_F00D_CAFE);
    let mut stats = SmirStats::new();
    let sizes = [Size::B8, Size::B16, Size::B32, Size::B64];
    // (/digit, name); skip /6 (alias of SHL).
    let groups: &[(u8, &str)] = &[
        (0, "rol"),
        (1, "ror"),
        (2, "rcl"),
        (3, "rcr"),
        (4, "shl"),
        (5, "shr"),
        (7, "sar"),
    ];

    for _ in 0..CASES {
        let size = *rng.pick(&sizes);
        let &(digit, name) = rng.pick(groups);
        let dst = pick_gpr(&mut rng);
        let by_cl = rng.below(2) == 0;
        let is_rotate = digit <= 3;

        let mut r = Registers::default();
        let dval = rng.operand();
        set_reg(&mut r, dst, dval);
        // RCL/RCR feed CF in; randomize it.
        let cf_in = rng.below(2) == 1;
        if cf_in {
            r.rflags |= flags::bits::CF;
        }

        // Choose a shift count. The hardware masks the count to 5 bits (or 6 for
        // 64-bit). For RCL/RCR the modulo is by (opsize+1). Use a range that
        // exercises both small and large counts but is well-defined.
        let max_count = if size == Size::B64 { 63 } else { 31 };
        let count = (rng.below(max_count as u64 + 1)) as u8;

        let mut code = size_prefix(size);
        if let Some(rex) = rex_byte(size, true) {
            code.push(rex);
        }
        let byte = size == Size::B8;

        let inputs;
        if by_cl {
            r.rcx = count as u64;
            code.push(if byte { 0xD2 } else { 0xD3 });
            code.push(modrm(0b11, digit, dst));
            inputs = format!(
                "{} {} {}, cl={} (cf_in={}); dst={:#x}",
                name, size.name(), reg_name(dst), count, cf_in, dval
            );
        } else if count == 1 {
            // Use the dedicated by-1 form so OF is well-defined.
            code.push(if byte { 0xD0 } else { 0xD1 });
            code.push(modrm(0b11, digit, dst));
            inputs = format!(
                "{} {} {}, 1 (cf_in={}); dst={:#x}",
                name, size.name(), reg_name(dst), cf_in, dval
            );
        } else {
            code.push(if byte { 0xC0 } else { 0xC1 });
            code.push(modrm(0b11, digit, dst));
            code.push(count);
            inputs = format!(
                "{} {} {}, imm8={} (cf_in={}); dst={:#x}",
                name, size.name(), reg_name(dst), count, cf_in, dval
            );
        }
        code.push(HLT);

        // Flag mask. The hardware masks the count to 5 bits (6 for 64-bit) and
        // performs the shift by that masked count WITHOUT re-clamping to the
        // operand width. So for 8/16-bit ops the (masked) count can legitimately
        // exceed the operand width, which matters for CF definedness:
        //
        //  - masked count == 0 : nothing happens; ALL status flags unchanged.
        //  - count == 1        : OF defined. Rotate -> CF|OF; shift -> all.
        //  - 1 < count <= width: OF undefined. Rotate -> CF; shift -> CF|PF|ZF|SF.
        //  - count > width (only 8/16-bit):
        //      * SAR : result sign-fills, CF = sign bit (defined). -> CF|PF|ZF|SF.
        //      * SHL/SHR : result 0, but CF is architecturally UNDEFINED.
        //                  -> PF|ZF|SF only (drop CF and OF).
        //      * ROL/ROR/RCL/RCR : rotate amount is taken modulo (width) or
        //                  (width+1), so CF stays defined. -> CF.
        let mask_bits = if size == Size::B64 { 63u32 } else { 31u32 };
        let masked_count = (count as u32) & mask_bits;
        let width = size.bits();
        let is_sar = digit == 7;
        let shift_no_of = flags::bits::CF | flags::bits::PF | flags::bits::ZF | flags::bits::SF;
        let flag_mask = if masked_count == 0 {
            FLAG_MASK
        } else if masked_count == 1 {
            if is_rotate {
                flags::bits::CF | flags::bits::OF
            } else {
                FLAG_MASK
            }
        } else if is_rotate {
            flags::bits::CF
        } else if masked_count <= width {
            shift_no_of
        } else if is_sar {
            shift_no_of // SAR CF defined (= sign bit) even past the width.
        } else {
            // SHL/SHR past the width: CF undefined, result is 0 (PF/ZF/SF defined).
            flags::bits::PF | flags::bits::ZF | flags::bits::SF
        };

        let opts = CompareOpts {
            flag_mask,
            ..CompareOpts::default()
        };
        if !stats.check("smir_shifts", &code, r, [0u8; 64], opts, inputs) {
            break;
        }
    }
    stats.finish("shifts");
}

// SMIR validation: SHLD/SHRD by imm8 and CL. Mirrors fuzz_double_shifts's
// generation exactly but drives the SMIR backend via SmirStats.
#[test]
fn smir_double_shifts() {
    const CASES: usize = 250;
    let mut rng = Rng::new(0x0F0F_1E2D_3C4B_5A69);
    let mut stats = SmirStats::new();
    let sizes = [Size::B16, Size::B32, Size::B64];

    for _ in 0..CASES {
        let size = *rng.pick(&sizes);
        let dst = pick_gpr(&mut rng);
        let mut src = pick_gpr(&mut rng);
        while src == dst {
            src = pick_gpr(&mut rng);
        }
        let left = rng.below(2) == 0; // SHLD vs SHRD
        let by_cl = rng.below(2) == 0;

        let mut r = Registers::default();
        let dval = rng.operand();
        let sval = rng.operand();
        set_reg(&mut r, dst, dval);
        set_reg(&mut r, src, sval);

        // Count must be < operand size to keep the result architecturally defined.
        let count = (rng.below(size.bits() as u64)) as u8;

        let mut code = size_prefix(size);
        if size == Size::B64 {
            code.push(0x48);
        }
        // SHLD imm = 0F A4, SHLD CL = 0F A5; SHRD imm = 0F AC, SHRD CL = 0F AD.
        code.push(0x0F);
        let name;
        if by_cl {
            r.rcx = count as u64;
            code.push(if left { 0xA5 } else { 0xAD });
            code.push(modrm(0b11, src, dst)); // reg=src, rm=dst
            name = if left { "shld_cl" } else { "shrd_cl" };
        } else {
            code.push(if left { 0xA4 } else { 0xAC });
            code.push(modrm(0b11, src, dst));
            code.push(count);
            name = if left { "shld_imm" } else { "shrd_imm" };
        }
        code.push(HLT);

        // OF defined only for count==1; AF undefined; count==0 -> no change.
        let flag_mask = if count == 0 {
            FLAG_MASK
        } else if count == 1 {
            flags::bits::CF | flags::bits::PF | flags::bits::ZF | flags::bits::SF | flags::bits::OF
        } else {
            flags::bits::CF | flags::bits::PF | flags::bits::ZF | flags::bits::SF
        };

        let inputs = format!(
            "{} {} {}, {}, {} ; dst={:#x} src={:#x}",
            name, size.name(), reg_name(dst), reg_name(src), count, dval, sval
        );
        let opts = CompareOpts {
            flag_mask,
            ..CompareOpts::default()
        };
        if !stats.check("smir_double_shifts", &code, r, [0u8; 64], opts, inputs) {
            break;
        }
    }
    stats.finish("double_shifts");
}

// SMIR validation: MUL/IMUL/DIV/IDIV. Mirrors fuzz_muldiv's generation exactly
// (same opcodes/encodings/operands), but drives the SMIR backend.
#[test]
fn smir_muldiv() {
    const CASES: usize = 350;
    let mut rng = Rng::new(0xABCD_1234_5678_9EF0);
    let mut stats = SmirStats::new();
    let sizes = [Size::B8, Size::B16, Size::B32, Size::B64];
    let muldiv_defined = flags::bits::CF | flags::bits::OF;

    for _ in 0..CASES {
        let size = *rng.pick(&sizes);
        let kind = rng.below(4); // 0=mul 1=imul1 2=div 3=idiv (one-operand)
        // 2-operand IMUL (0F AF) has no 8-bit form, so only for 16/32/64-bit.
        let two_op = kind == 1 && size != Size::B8 && rng.below(2) == 0;

        let mut r = Registers::default();
        let bits = size.bits();
        let mask: u128 = if bits == 64 { u128::MAX >> 64 } else { (1u128 << bits) - 1 };

        let src = pick_gpr(&mut rng);
        // Don't use rax/rdx as the explicit source for 1-op forms (they're implicit).
        let mut srcr = src;
        while srcr == 0 || srcr == 2 {
            srcr = pick_gpr(&mut rng);
        }

        let mut code = size_prefix(size);
        let inputs;
        let flag_mask;

        if two_op {
            // IMUL r, r/m : [REX.W] 0F AF /r  (reg = dest = reg * rm). 2-operand
            // defines CF/OF; result is the low half (truncated), GPR defined.
            let dst = pick_gpr(&mut rng);
            let a = rng.operand();
            let b = rng.operand();
            set_reg(&mut r, dst, a);
            let s2 = if dst == srcr { (srcr + 1) & 7 } else { srcr };
            let s2 = if s2 == 4 || s2 == 5 { 6 } else { s2 };
            set_reg(&mut r, s2, b);
            if size == Size::B64 {
                code.push(0x48);
            }
            code.push(0x0F);
            code.push(0xAF);
            code.push(modrm(0b11, dst, s2));
            code.push(HLT);
            flag_mask = muldiv_defined;
            inputs = format!(
                "imul2 {} {}, {} ; a={:#x} b={:#x}",
                size.name(), reg_name(dst), reg_name(s2), a, b
            );
            let opts = CompareOpts {
                flag_mask,
                ..CompareOpts::default()
            };
            if !stats.check("smir_muldiv", &code, r, [0u8; 64], opts, inputs) {
                break;
            }
            continue;
        }

        let byte = size == Size::B8;
        if size == Size::B64 {
            code.push(0x48);
        } else if byte {
            // Force a REX prefix for 8-bit so modrm.rm in {6,7} addresses
            // SIL/DIL (low bytes) rather than aliasing to DH/BH, which would
            // read garbage and spuriously raise #DE on the divide.
            code.push(0x40);
        }

        match kind {
            0 | 1 => {
                // MUL (/4) or IMUL (/5) one-operand. Implicit op in (R)AX,
                // result in (R)DX:(R)AX (or AX for 8-bit). Random operands.
                let a = rng.operand();
                let b = rng.operand();
                r.rax = a;
                set_reg(&mut r, srcr, b);
                code.push(if byte { 0xF6 } else { 0xF7 });
                code.push(modrm(0b11, if kind == 0 { 4 } else { 5 }, srcr));
                flag_mask = muldiv_defined;
                inputs = format!(
                    "{} {} {} ; rax={:#x} {}={:#x}",
                    if kind == 0 { "mul" } else { "imul1" },
                    size.name(),
                    reg_name(srcr),
                    a,
                    reg_name(srcr),
                    b
                );
            }
            _ => {
                // DIV (/6) or IDIV (/7). Build dividend so the quotient fits and
                // the divisor is nonzero, avoiding #DE entirely.
                let divisor = {
                    let mut d = rng.operand() & (mask as u64);
                    if d == 0 {
                        d = 1;
                    }
                    d
                };
                set_reg(&mut r, srcr, divisor);

                if kind == 2 {
                    // Unsigned: pick quotient < divisor-bound and remainder < divisor,
                    // then dividend = quotient*divisor + remainder fits in 2*bits.
                    let q = (rng.operand() as u128) & mask; // quotient fits in `bits`
                    let rem = (rng.operand() as u128) % (divisor as u128); // < divisor
                    // dividend = q*divisor + rem is exact and its high half fits in
                    // `bits` because q <= mask and the product can't exceed 2*bits.
                    let dividend = q * (divisor as u128) + rem;
                    let lo = dividend & mask;
                    let hi = (dividend >> bits) & mask;
                    place_dividend(&mut r, size, lo as u64, hi as u64);
                    code.push(if byte { 0xF6 } else { 0xF7 });
                    code.push(modrm(0b11, 6, srcr));
                    flag_mask = 0; // all flags undefined for DIV.
                    inputs = format!(
                        "div {} {}={:#x} ; dividend_lo={:#x} hi={:#x}",
                        size.name(), reg_name(srcr), divisor, lo as u64, hi as u64
                    );
                } else {
                    // Signed IDIV. Build from a signed quotient/remainder that fit.
                    let smax: i128 = if bits == 64 {
                        i64::MAX as i128
                    } else {
                        (1i128 << (bits - 1)) - 1
                    };
                    let sdiv = {
                        let mut d = sign_extend(divisor, bits) as i128;
                        if d == 0 {
                            d = 1;
                        }
                        d
                    };
                    // quotient in a safe range so it fits in `bits` signed and the
                    // product doesn't overflow the double-width dividend.
                    let q = (sign_extend(rng.operand(), bits) as i128) % (smax / sdiv.abs().max(1) + 1).max(1);
                    let rem_bound = sdiv.abs();
                    let mut rem = (rng.next_u64() as i128) % rem_bound.max(1);
                    // remainder sign follows the dividend; keep |rem| < |divisor|.
                    if q < 0 || (q == 0 && rem != 0 && rng.below(2) == 0) {
                        rem = -rem.abs();
                    } else {
                        rem = rem.abs();
                    }
                    let dividend: i128 = q * sdiv + rem;
                    let unsigned = (dividend as u128) & (mask | (mask << bits));
                    let lo = (unsigned & mask) as u64;
                    let hi = ((unsigned >> bits) & mask) as u64;
                    place_dividend(&mut r, size, lo, hi);
                    code.push(if byte { 0xF6 } else { 0xF7 });
                    code.push(modrm(0b11, 7, srcr));
                    flag_mask = 0;
                    inputs = format!(
                        "idiv {} {}={:#x} ; dividend_lo={:#x} hi={:#x} (q={} rem={})",
                        size.name(), reg_name(srcr), divisor, lo, hi, q, rem
                    );
                }
            }
        }
        code.push(HLT);

        let opts = CompareOpts {
            flag_mask,
            ..CompareOpts::default()
        };
        if !stats.check("smir_muldiv", &code, r, [0u8; 64], opts, inputs) {
            break;
        }
    }
    stats.finish("muldiv");
}

// SMIR validation: INC/DEC (preserve CF), NEG, NOT, TEST — partial-register +
// flag edge cases. Mirrors fuzz_unary's generation exactly but drives SMIR.
#[test]
fn smir_unary() {
    const CASES: usize = 300;
    let mut rng = Rng::new(0x55AA_55AA_1234_9876);
    let mut stats = SmirStats::new();
    let sizes = [Size::B8, Size::B16, Size::B32, Size::B64];
    // (name, group opcode for non-byte, /digit, sets-CF?)
    // INC=FF/0, DEC=FF/1 (8-bit FE), NEG=F7/3, NOT=F7/2 (8-bit F6). TEST=group F7/0 with imm.
    #[derive(Clone, Copy)]
    enum U {
        Inc,
        Dec,
        Neg,
        Not,
        Test,
    }
    let ops = [U::Inc, U::Dec, U::Neg, U::Not, U::Test];

    for _ in 0..CASES {
        let size = *rng.pick(&sizes);
        let u = *rng.pick(&ops);
        let dst = pick_gpr(&mut rng);
        let mut r = Registers::default();
        let dval = rng.operand();
        set_reg(&mut r, dst, dval);
        // Preserve incoming CF to verify INC/DEC don't touch it.
        let cf_in = rng.below(2) == 1;
        if cf_in {
            r.rflags |= flags::bits::CF;
        }

        let mut code = size_prefix(size);
        if let Some(rex) = rex_byte(size, true) {
            code.push(rex);
        }
        let byte = size == Size::B8;
        let name;
        match u {
            U::Inc => {
                code.push(if byte { 0xFE } else { 0xFF });
                code.push(modrm(0b11, 0, dst));
                name = "inc";
            }
            U::Dec => {
                code.push(if byte { 0xFE } else { 0xFF });
                code.push(modrm(0b11, 1, dst));
                name = "dec";
            }
            U::Not => {
                code.push(if byte { 0xF6 } else { 0xF7 });
                code.push(modrm(0b11, 2, dst));
                name = "not";
            }
            U::Neg => {
                code.push(if byte { 0xF6 } else { 0xF7 });
                code.push(modrm(0b11, 3, dst));
                name = "neg";
            }
            U::Test => {
                // group F6/F7 /0 with immediate.
                let imm = rng.operand();
                code.push(if byte { 0xF6 } else { 0xF7 });
                code.push(modrm(0b11, 0, dst));
                match size {
                    Size::B8 => code.push(imm as u8),
                    Size::B16 => code.extend_from_slice(&(imm as u16).to_le_bytes()),
                    _ => code.extend_from_slice(&(imm as u32).to_le_bytes()),
                }
                name = "test";
            }
        }
        code.push(HLT);

        let inputs = format!("{} {} {} (cf_in={}); dst={:#x}", name, size.name(), reg_name(dst), cf_in, dval);
        if !stats.check("smir_unary", &code, r, [0u8; 64], CompareOpts::default(), inputs) {
            break;
        }
    }
    stats.finish("unary");
}

// SMIR validation: MOVZX/MOVSX/MOVSXD/BSWAP — zero/sign extension widths and the
// sub-register merge interaction. Mirrors fuzz_movext_bswap's generation exactly.
#[test]
fn smir_movext() {
    const CASES: usize = 300;
    let mut rng = Rng::new(0x1A2B_3C4D_5E6F_7081);
    let mut stats = SmirStats::new();

    for _ in 0..CASES {
        let kind = rng.below(5); // 0=movzxb 1=movsxb 2=movzxw 3=movsxw 4=movsxd
        let dst = pick_gpr(&mut rng);
        let mut src = pick_gpr(&mut rng);
        while src == dst {
            src = pick_gpr(&mut rng);
        }
        // Destination 64-bit (REX.W) so we see the full extension.
        let mut r = Registers::default();
        let sval = rng.operand();
        set_reg(&mut r, src, sval);
        // Preload dst to detect partial-write bugs.
        set_reg(&mut r, dst, 0xCCCC_CCCC_CCCC_CCCC);

        let mut code = vec![0x48]; // REX.W
        let name;
        match kind {
            0 => {
                code.extend_from_slice(&[0x0F, 0xB6, modrm(0b11, dst, src)]);
                name = "movzx_b";
            }
            1 => {
                code.extend_from_slice(&[0x0F, 0xBE, modrm(0b11, dst, src)]);
                name = "movsx_b";
            }
            2 => {
                code.extend_from_slice(&[0x0F, 0xB7, modrm(0b11, dst, src)]);
                name = "movzx_w";
            }
            3 => {
                code.extend_from_slice(&[0x0F, 0xBF, modrm(0b11, dst, src)]);
                name = "movsx_w";
            }
            _ => {
                // MOVSXD r64, r/m32 = REX.W 63 /r.
                code.extend_from_slice(&[0x63, modrm(0b11, dst, src)]);
                name = "movsxd";
            }
        }
        code.push(HLT);

        let inputs = format!("{} {}, {} ; src={:#x}", name, reg_name(dst), reg_name(src), sval);
        // mov-extend ops don't touch flags -> compare all (they should be unchanged).
        if !stats.check("smir_movext", &code, r, [0u8; 64], CompareOpts::default(), inputs) {
            break;
        }
    }
    stats.finish("movext");
}

// SMIR validation: SETcc / CMOVcc across all 16 condition codes. Mirrors
// fuzz_setcc_cmovcc's generation EXACTLY (same opcodes/encodings/operands), but
// drives the SMIR backend. Exercises SMIR's condition evaluation against the
// materialized RFLAGS produced by a preceding CMP.
#[test]
fn smir_setcc_cmov() {
    const CASES: usize = 400;
    let mut rng = Rng::new(0x9988_7766_5544_3322);
    let mut stats = SmirStats::new();

    for _ in 0..CASES {
        // First establish a random flag state via CMP of two random values, then
        // run SETcc or CMOVcc and compare. The flag state is fully defined so we
        // compare all status flags and the destination.
        let cc = (rng.below(16)) as u8; // condition 0..15 -> opcode 0x90+cc / 0x40+cc
        let is_cmov = rng.below(2) == 0;

        let a = rng.operand();
        let b = rng.operand();
        let mut r = Registers::default();
        r.rax = a;
        r.rbx = b;

        // cmp rax, rbx (REX.W 39 /r): reg=rbx(3), rm=rax(0).
        let mut code = vec![0x48, 0x39, modrm(0b11, 3, 0)];
        if is_cmov {
            // cmovcc rax, rcx : REX.W 0F (40+cc) /r, reg=rax(0), rm=rcx(1).
            let cval = rng.operand();
            r.rcx = cval;
            // sentinel already in rax via `a`; CMOV may or may not overwrite.
            code.extend_from_slice(&[0x48, 0x0F, 0x40 + cc, modrm(0b11, 0, 1)]);
            code.push(HLT);
            let inputs = format!("cmp+cmov cc={:#x} ; a={:#x} b={:#x} c={:#x}", cc, a, b, cval);
            if !stats.check("smir_cmov", &code, r, [0u8; 64], CompareOpts::default(), inputs) {
                break;
            }
        } else {
            // setcc al : 0F (90+cc) /0, then movzx eax, al for a clean 0/1.
            code.extend_from_slice(&[0x0F, 0x90 + cc, modrm(0b11, 0, 0)]);
            code.extend_from_slice(&[0x0F, 0xB6, 0xC0]); // movzx eax, al
            code.push(HLT);
            let inputs = format!("cmp+setcc cc={:#x} ; a={:#x} b={:#x}", cc, a, b);
            if !stats.check("smir_setcc", &code, r, [0u8; 64], CompareOpts::default(), inputs) {
                break;
            }
        }
    }
    stats.finish("setcc_cmov");
}

// SMIR validation: MOV loads/stores across all ModRM/SIB/disp/RIP addressing
// forms. Exercises the SMIR memory path + effective-address computation +
// scratch compare. Mirrors fuzz_mem_addressing's generation EXACTLY.
#[test]
fn smir_memaddr() {
    const CASES: usize = 700;
    let mut rng = Rng::new(0xADD4_E55F_0FF5_E701);
    let mut stats = SmirStats::new();
    let sizes = [Size::B8, Size::B16, Size::B32, Size::B64];
    let forms = [
        AddrForm::Base,
        AddrForm::BaseDisp8,
        AddrForm::BaseDisp32,
        AddrForm::Sib,
        AddrForm::SibDisp8,
        AddrForm::SibDisp32,
        AddrForm::SibNoIndex,
        AddrForm::SibNoBase,
        AddrForm::RipRel,
    ];

    const REG: u8 = 0; // rax, the moved register (reg field)
    const BASE: u8 = 3; // rbx
    const INDEX: u8 = 6; // rsi

    for _ in 0..CASES {
        let size = *rng.pick(&sizes);
        let bytes = (size.bits() / 8) as u64;
        let form = *rng.pick(&forms);
        let is_store = rng.below(2) == 0;

        // Effective address: keep [EA, EA+bytes) inside the 64-byte scratch.
        let target_off = rng.below(64 - bytes + 1);
        let ea = DATA_ADDR + target_off;

        let scale_bits = rng.below(4) as u8; // 0..3 -> *1,*2,*4,*8
        let scale = 1u64 << scale_bits;
        let idxv = rng.below(8); // small index value

        let mut r = Registers::default();
        let sval = rng.operand(); // source value for stores
        set_reg(&mut r, REG, sval);

        let mut code = size_prefix(size);
        if let Some(rex) = rex_byte(size, true) {
            code.push(rex);
        }
        let opcode = match (is_store, size == Size::B8) {
            (true, true) => 0x88,
            (true, false) => 0x89,
            (false, true) => 0x8A,
            (false, false) => 0x8B,
        };
        code.push(opcode);

        match form {
            AddrForm::Base => {
                code.push(modrm(0b00, REG, BASE));
                set_reg(&mut r, BASE, ea);
            }
            AddrForm::BaseDisp8 => {
                let d8 = (rng.next_u32() as i8) as i64;
                code.push(modrm(0b01, REG, BASE));
                set_reg(&mut r, BASE, ea.wrapping_sub(d8 as u64));
                code.push(d8 as u8);
            }
            AddrForm::BaseDisp32 => {
                let d32 = rng.next_u32() as i32 as i64;
                code.push(modrm(0b10, REG, BASE));
                set_reg(&mut r, BASE, ea.wrapping_sub(d32 as u64));
                code.extend_from_slice(&(d32 as i32).to_le_bytes());
            }
            AddrForm::Sib => {
                code.push(modrm(0b00, REG, 4));
                code.push((scale_bits << 6) | (INDEX << 3) | BASE);
                set_reg(&mut r, INDEX, idxv);
                set_reg(&mut r, BASE, ea.wrapping_sub(idxv.wrapping_mul(scale)));
            }
            AddrForm::SibDisp8 => {
                let d8 = (rng.next_u32() as i8) as i64;
                code.push(modrm(0b01, REG, 4));
                code.push((scale_bits << 6) | (INDEX << 3) | BASE);
                set_reg(&mut r, INDEX, idxv);
                set_reg(
                    &mut r,
                    BASE,
                    ea.wrapping_sub(idxv.wrapping_mul(scale)).wrapping_sub(d8 as u64),
                );
                code.push(d8 as u8);
            }
            AddrForm::SibDisp32 => {
                let d32 = rng.next_u32() as i32 as i64;
                code.push(modrm(0b10, REG, 4));
                code.push((scale_bits << 6) | (INDEX << 3) | BASE);
                set_reg(&mut r, INDEX, idxv);
                set_reg(
                    &mut r,
                    BASE,
                    ea.wrapping_sub(idxv.wrapping_mul(scale)).wrapping_sub(d32 as u64),
                );
                code.extend_from_slice(&(d32 as i32).to_le_bytes());
            }
            AddrForm::SibNoIndex => {
                // index=4 in SIB encodes "no index". EA = base.
                code.push(modrm(0b00, REG, 4));
                code.push((scale_bits << 6) | (4 << 3) | BASE);
                set_reg(&mut r, BASE, ea);
            }
            AddrForm::SibNoBase => {
                // mod=00, SIB base=5 => no base register, disp32 follows.
                // EA = index*scale + disp32.
                code.push(modrm(0b00, REG, 4));
                code.push((scale_bits << 6) | (INDEX << 3) | 5);
                set_reg(&mut r, INDEX, idxv);
                let disp = ea.wrapping_sub(idxv.wrapping_mul(scale)) as i64 as i32;
                code.extend_from_slice(&disp.to_le_bytes());
            }
            AddrForm::RipRel => {
                // mod=00, rm=5 => [rip + disp32], rip = address of NEXT insn.
                code.push(modrm(0b00, REG, 5));
                let rip_after = CODE_ADDR + code.len() as u64 + 4;
                let disp = ea.wrapping_sub(rip_after) as i64 as i32;
                code.extend_from_slice(&disp.to_le_bytes());
            }
        }
        code.push(HLT);

        // Random scratch contents (the load source / store target window).
        let mut scratch = [0u8; 64];
        for b in scratch.iter_mut() {
            *b = rng.next_u32() as u8;
        }

        let dir = if is_store { "store" } else { "load" };
        let inputs = format!(
            "mov.{} {} ea={:#x} off={} scale={} idxv={}",
            size.name(),
            dir,
            ea,
            target_off,
            scale,
            idxv
        );
        // MOV does not affect flags; compare scratch (stores) + all GPRs (loads).
        let opts = CompareOpts {
            flag_mask: 0,
            scratch: true,
            ..CompareOpts::default()
        };
        if !stats.check("smir_memaddr", &code, r, scratch, opts, inputs) {
            break;
        }
    }
    stats.finish("memaddr");
}
