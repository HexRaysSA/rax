//! End-to-end M4 integration test: the SMIR native hot-block JIT tier executing
//! through the real `X86_64Vcpu` state, validated against the interpreter.
//!
//! Run with: `cargo test --features smir-jit --test smir_jit_vcpu -- --nocapture`
#![cfg(all(feature = "smir-jit", target_arch = "x86_64"))]

use std::sync::Arc;
use std::time::Instant;

use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap, GuestRegionMmap, MmapRegion};

use rax::backend::emulator::x86_64::X86_64Vcpu;
use rax::cpu::{Registers, SystemRegisters, VCpu, VcpuExit};

const LOAD_ADDR: u64 = 0x10_0000;
const MEM_SIZE: u64 = 16 * 1024 * 1024;

/// Build a vcpu loaded with the `bench_loop` hot loop for `iters` iterations.
//   xor eax,eax ; mov ecx,iters ; loop: add eax,3 ; xor edx,edx ; sub eax,1 ;
//   dec ecx ; jnz loop ; hlt
fn make_vcpu(iters: u32) -> X86_64Vcpu {
    let mut code: Vec<u8> = vec![0x31, 0xC0]; // xor eax,eax
    code.push(0xB9); // mov ecx, imm32
    code.extend_from_slice(&iters.to_le_bytes());
    code.extend_from_slice(&[0x83, 0xC0, 0x03]); // add eax,3
    code.extend_from_slice(&[0x31, 0xD2]); // xor edx,edx
    code.extend_from_slice(&[0x83, 0xE8, 0x01]); // sub eax,1
    code.extend_from_slice(&[0xFF, 0xC9]); // dec ecx
    code.extend_from_slice(&[0x75, 0xF4]); // jnz loop
    code.push(0xF4); // hlt

    let region = MmapRegion::new(MEM_SIZE as usize).unwrap();
    let guest_region = GuestRegionMmap::new(region, GuestAddress(0)).unwrap();
    let memory = Arc::new(GuestMemoryMmap::from_regions(vec![guest_region]).unwrap());
    memory.write_slice(&code, GuestAddress(LOAD_ADDR)).unwrap();

    let mut regs = Registers::default();
    regs.rip = LOAD_ADDR;
    regs.rsp = 0x11_0000;
    regs.rflags = 0x2;

    let mut sregs = SystemRegisters::default();
    sregs.cr0 = 0x21;
    sregs.cr4 = 0x20;
    sregs.efer = 0x500;
    sregs.cs.base = 0;
    sregs.cs.limit = 0xFFFFFFFF;
    sregs.cs.selector = 0x8;
    sregs.cs.type_ = 0xB;
    sregs.cs.present = true;
    sregs.cs.s = true;
    sregs.cs.l = true;
    sregs.cs.g = true;
    sregs.ds.base = 0;
    sregs.ds.limit = 0xFFFFFFFF;
    sregs.ds.selector = 0x10;
    sregs.ds.type_ = 0x3;
    sregs.ds.present = true;
    sregs.ds.db = true;
    sregs.ds.s = true;
    sregs.ds.g = true;
    sregs.es = sregs.ds.clone();
    sregs.fs = sregs.ds.clone();
    sregs.gs = sregs.ds.clone();
    sregs.ss = sregs.ds.clone();

    let mut vcpu = X86_64Vcpu::new(0, memory);
    vcpu.set_regs(&regs).unwrap();
    vcpu.set_sregs(&sregs).unwrap();
    vcpu
}

/// Build a vcpu loaded with arbitrary guest `code` at LOAD_ADDR.
fn make_vcpu_code(code: &[u8]) -> X86_64Vcpu {
    let region = MmapRegion::new(MEM_SIZE as usize).unwrap();
    let guest_region = GuestRegionMmap::new(region, GuestAddress(0)).unwrap();
    let memory = Arc::new(GuestMemoryMmap::from_regions(vec![guest_region]).unwrap());
    memory.write_slice(code, GuestAddress(LOAD_ADDR)).unwrap();

    let mut regs = Registers::default();
    regs.rip = LOAD_ADDR;
    regs.rsp = 0x11_0000;
    regs.rflags = 0x2;

    let mut sregs = SystemRegisters::default();
    sregs.cr0 = 0x21;
    sregs.cr4 = 0x20;
    sregs.efer = 0x500;
    sregs.cs.limit = 0xFFFFFFFF;
    sregs.cs.selector = 0x8;
    sregs.cs.type_ = 0xB;
    sregs.cs.present = true;
    sregs.cs.s = true;
    sregs.cs.l = true;
    sregs.cs.g = true;
    sregs.ds.limit = 0xFFFFFFFF;
    sregs.ds.selector = 0x10;
    sregs.ds.type_ = 0x3;
    sregs.ds.present = true;
    sregs.ds.db = true;
    sregs.ds.s = true;
    sregs.ds.g = true;
    sregs.es = sregs.ds.clone();
    sregs.fs = sregs.ds.clone();
    sregs.gs = sregs.ds.clone();
    sregs.ss = sregs.ds.clone();

    let mut vcpu = X86_64Vcpu::new(0, memory);
    vcpu.set_regs(&regs).unwrap();
    vcpu.set_sregs(&sregs).unwrap();
    vcpu
}

/// The eligibility/clobber checks must DECLINE ineligible regions (returning
/// None so a caller falls back to the interpreter) rather than mis-compile —
/// the safety net for a future automatic `run()` integration.
#[test]
fn jit_bails_on_ineligible() {
    // (a) A region with a CALL terminator — not a self-contained HALT region.
    //     call $+5 ; hlt
    let mut v = make_vcpu_code(&[0xE8, 0x00, 0x00, 0x00, 0x00, 0xF4]);
    assert!(
        !v.jit_try_block().expect("jit_try_block"),
        "a CALL region (entry block is a frontier) must bail to the interpreter"
    );

    // (b) A straight-line block ending in RET — entry block is a frontier exit,
    //     so there is no internal native work; must bail.
    let mut v = make_vcpu_code(&[0xB8, 0x05, 0x00, 0x00, 0x00, 0xC3]);
    assert!(
        !v.jit_try_block().expect("jit_try_block"),
        "an entry-is-frontier region must bail"
    );

    // (c) A frontier-less spin loop `jmp $` (EB FE) — running it natively would
    //     loop forever with no way back; must bail (and must NOT hang).
    let mut v = make_vcpu_code(&[0xEB, 0xFE]);
    assert!(
        !v.jit_try_block().expect("jit_try_block"),
        "a frontier-less infinite loop must bail (no native exit)"
    );

    // (d) A loop whose body READS MEMORY (mov eax,[rbx]; dec ecx; jnz) — memory
    //     ops are not on the JIT whitelist (they would access wrong host
    //     addresses under native exec); the region MUST bail to the interpreter
    //     and never execute natively. This is the kernel-safety gate.
    let mut v = make_vcpu_code(&[0x8B, 0x03, 0xFF, 0xC9, 0x75, 0xFA, 0xF4]);
    let mut r = v.get_regs().unwrap();
    r.rcx = 5;
    r.rbx = LOAD_ADDR;
    v.set_regs(&r).unwrap();
    assert!(
        !v.jit_try_block().expect("jit_try_block"),
        "a memory-touching loop must bail (not JIT-safe)"
    );
}

fn run_interp(vcpu: &mut X86_64Vcpu) {
    loop {
        match vcpu.step() {
            Ok(Some(VcpuExit::Hlt)) => break,
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(e) => panic!("interp error: {e:?}"),
        }
    }
}

/// The JIT-tier final state must equal the interpreter's, register for register.
#[test]
fn jit_matches_interpreter() {
    let iters = 1000u32;

    let mut jit = make_vcpu(iters);
    assert!(
        jit.jit_try_block().expect("jit_try_block"),
        "the loop region should JIT and advance to its exit"
    );
    // The JIT ran the loop natively and parked RIP at the HLT (the frontier
    // exit, not yet executed). Step it so both vcpus end at the same point.
    run_interp(&mut jit);
    let jr = jit.get_regs().unwrap();

    let mut interp = make_vcpu(iters);
    run_interp(&mut interp);
    let ir = interp.get_regs().unwrap();

    // Whole-loop native execution must reproduce the interpreter's GPR state.
    assert_eq!(jr.rax, ir.rax, "rax");
    assert_eq!(jr.rcx, ir.rcx, "rcx");
    assert_eq!(jr.rdx, ir.rdx, "rdx");
    assert_eq!(jr.rbx, ir.rbx, "rbx");
    assert_eq!(jr.rsi, ir.rsi, "rsi");
    assert_eq!(jr.rdi, ir.rdi, "rdi");
    assert_eq!(jr.r8, ir.r8, "r8");
    assert_eq!(jr.r15, ir.r15, "r15");
    // Sanity vs the closed-form result: eax = 2*iters, ecx = 0.
    assert_eq!(jr.rax & 0xffff_ffff, (2 * iters as u64) & 0xffff_ffff);
    assert_eq!(jr.rcx & 0xffff_ffff, 0);
}

/// Register-only LEA (address arithmetic, no dereference) + BSF (bit-scan) in a
/// hot loop must JIT bit-exactly vs the interpreter — verifies the whitelist
/// additions (Lea/Bsf/Bsr) lower correctly under the native runtime.
#[test]
fn jit_lea_sib_matches_interpreter() {
    // xor eax,eax; mov ecx,300
    // loop: lea edx,[rax+rax*2+5]  (SIB base+index*scale+disp); add eax,1;
    //       dec ecx; jnz loop; hlt
    let code: &[u8] = &[
        0x31, 0xC0, // xor eax,eax
        0xB9, 0x2C, 0x01, 0x00, 0x00, // mov ecx,300
        0x8D, 0x54, 0x40, 0x05, // loop: lea edx,[rax+rax*2+5]
        0x83, 0xC0, 0x01, // add eax,1
        0xFF, 0xC9, // dec ecx
        0x75, 0xF5, // jnz loop
        0xF4, // hlt
    ];

    let mut jit = make_vcpu_code(code);
    assert!(
        jit.jit_try_block().expect("jit_try_block"),
        "LEA-SIB loop should JIT and advance to its exit"
    );
    run_interp(&mut jit);
    let jr = jit.get_regs().unwrap();

    let mut interp = make_vcpu_code(code);
    run_interp(&mut interp);
    let ir = interp.get_regs().unwrap();

    assert_eq!(jr.rax, ir.rax, "rax");
    assert_eq!(jr.rcx, ir.rcx, "rcx");
    assert_eq!(jr.rdx, ir.rdx, "rdx (lea base+index*scale+disp)");
    assert_eq!(jr.rax & 0xffff_ffff, 300, "closed form: eax == iters");
    // Last iter rax==299: edx = 299*3 + 5 = 902.
    assert_eq!(jr.rdx & 0xffff_ffff, 902, "lea result of last iteration");
}

/// Variable shift by CL (`shl edx,cl`) in a hot loop — the pattern the kernel's
/// __free_pages_memory bootmem loop uses. Must JIT bit-exactly vs the interpreter.
#[test]
fn jit_shl_cl_matches_interpreter() {
    // mov ecx,5; xor eax,eax
    // loop: mov edx,1; shl edx,cl; add eax,edx; dec ecx; jns loop; hlt
    let code: &[u8] = &[
        0xB9, 0x05, 0x00, 0x00, 0x00, // mov ecx,5
        0x31, 0xC0, // xor eax,eax
        0xBA, 0x01, 0x00, 0x00, 0x00, // loop: mov edx,1
        0xD3, 0xE2, // shl edx,cl
        0x01, 0xD0, // add eax,edx
        0xFF, 0xC9, // dec ecx
        0x79, 0xF3, // jns loop
        0xF4, // hlt
    ];

    let mut jit = make_vcpu_code(code);
    assert!(
        jit.jit_try_block().expect("jit_try_block"),
        "SHL-by-CL loop should JIT and advance to its exit"
    );
    run_interp(&mut jit);
    let jr = jit.get_regs().unwrap();

    let mut interp = make_vcpu_code(code);
    run_interp(&mut interp);
    let ir = interp.get_regs().unwrap();

    assert_eq!(jr.rax, ir.rax, "rax (sum of 1<<cl for cl=5..0)");
    assert_eq!(jr.rdx, ir.rdx, "rdx (last shl result)");
    // Sum 32+16+8+4+2+1 = 63.
    assert_eq!(jr.rax & 0xffff_ffff, 63, "closed form sum");
}

/// A realistic hot loop with an INTERNAL conditional (if-inside-loop): multiple
/// internal blocks, a forward branch + a join, two back-edges to the head, and a
/// HLT frontier — all run natively by `jit_try_block`. JIT final state must equal
/// the interpreter's (self-validating regardless of the exact arithmetic).
//   loop: add eax,1 ; cmp eax,10 ; jl skip ; add ebx,10 ; skip: dec ecx ; jnz loop ; hlt
#[test]
fn jit_loop_with_internal_if_matches_interp() {
    let code: Vec<u8> = vec![
        0x83, 0xC0, 0x01, // add eax,1
        0x83, 0xF8, 0x0A, // cmp eax,10
        0x7C, 0x03, // jl skip (+3 -> skip)   (eax<10 -> skip the add)
        0x83, 0xC3, 0x0A, // add ebx,10  (only when eax>=10)
        0xFF, 0xC9, // skip: dec ecx
        0x75, 0xF1, // jnz loop (-15 -> head)
        0xF4, // hlt
    ];
    let setup = |v: &mut X86_64Vcpu| {
        let mut r = v.get_regs().unwrap();
        r.rax = 0;
        r.rcx = 20;
        r.rbx = 0;
        v.set_regs(&r).unwrap();
    };

    let mut jit = make_vcpu_code(&code);
    setup(&mut jit);
    assert!(
        jit.jit_try_block().expect("jit_try_block"),
        "a loop with an internal if should JIT natively"
    );
    run_interp(&mut jit); // execute the parked HLT
    let jr = jit.get_regs().unwrap();

    let mut interp = make_vcpu_code(&code);
    setup(&mut interp);
    run_interp(&mut interp);
    let ir = interp.get_regs().unwrap();

    assert_eq!(jr.rax & 0xffff_ffff, ir.rax & 0xffff_ffff, "eax");
    assert_eq!(jr.rbx & 0xffff_ffff, ir.rbx & 0xffff_ffff, "ebx (conditional accumulation)");
    assert_eq!(jr.rcx & 0xffff_ffff, ir.rcx & 0xffff_ffff, "ecx");
    assert_eq!(jr.rax & 0xffff_ffff, 20, "ran all 20 iterations");
    assert_eq!(jr.rbx & 0xffff_ffff, 110, "ebx += 10 for each eax>=10 (iterations 10..=20)");
}

/// General-exit lowering: a hot loop that exits to a NON-HLT continuation runs
/// natively (back-edge internal) and hands control back to the interpreter at
/// the loop-exit address via an exit stub recording `exit_pc`. The native
/// result + resume PC must match the interpreter stepped to the same point.
#[test]
fn jit_general_exit_matches_interp_at_handoff() {
    use rax::smir::ir::Terminator;
    use rax::smir::lift::x86_64::X86_64Lifter;
    use rax::smir::lift::{LiftContext, MemoryReader, SmirLifter};
    use rax::smir::lower::runtime::{is_native_clobber_safe, ExecMem, GuestRegs};
    use rax::smir::lower::x86_64::X86_64Lowerer;
    use rax::smir::lower::SmirLowerer;
    use rax::smir::memory::MemoryError;
    use rax::smir::types::SourceArch;
    use std::collections::HashMap;

    // loop: add eax,2 ; dec ecx ; jnz loop      (exits to a continuation)
    // cont: mov ebx,0x7777 ; hlt
    let code: Vec<u8> = vec![
        0x83, 0xC0, 0x02, // add eax,2
        0xFF, 0xC9, // dec ecx
        0x75, 0xF9, // jnz loop (rel8 -7)
        0xBB, 0x77, 0x77, 0x00, 0x00, // mov ebx,0x7777  (continuation)
        0xF4, // hlt
    ];
    let cont_addr = LOAD_ADDR + 7;

    // --- JIT general-exit path ---
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
    let reader = Win { base: LOAD_ADDR, bytes: code.clone() };
    let mut lifter = X86_64Lifter::strict();
    let mut lctx = LiftContext::new(SourceArch::X86_64);
    let func = lifter.lift_function(LOAD_ADDR, &reader, &mut lctx).expect("lift_function");

    // Mark every "frontier" terminal (the JIT can't continue through it) as a
    // native-exit recording the block's guest_pc — the JIT runs up to but NOT
    // through it, so the interpreter resumes there and re-executes the block.
    let mut exits: HashMap<_, u64> = HashMap::new();
    for b in &func.blocks {
        let frontier = matches!(
            b.terminator,
            Terminator::Trap { .. }
                | Terminator::Return { .. }
                | Terminator::Call { .. }
                | Terminator::TailCall { .. }
                | Terminator::IndirectBranch { .. }
                | Terminator::IndirectBranchMem { .. }
                | Terminator::Switch { .. }
        );
        if frontier {
            exits.insert(b.id, b.guest_pc);
        }
    }
    assert!(!exits.is_empty(), "expected a frontier exit block");
    assert!(is_native_clobber_safe(&func), "loop must be clobber-safe");

    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_native_exits(exits);
    let res = lowerer.lower_function(&func).expect("lower (native_exit)");
    assert!(res.relocations.is_empty());
    let bytes = lowerer.finalize().expect("finalize");
    let mem = ExecMem::new(&bytes).expect("ExecMem");

    let mut gr = GuestRegs::default();
    gr.gpr[0] = 0; // eax
    gr.gpr[1] = 10; // ecx (trip)
    gr.gpr[3] = 0x1111; // ebx (must NOT become 0x7777 — cont not executed)
    gr.rflags = 0x2;
    mem.run(res.entry_offset, &mut gr);

    // --- Interpreter, stepped to the same hand-off point ---
    let mut interp = make_vcpu_code(&code);
    let mut r = interp.get_regs().unwrap();
    r.rax = 0;
    r.rcx = 10;
    r.rbx = 0x1111;
    interp.set_regs(&r).unwrap();
    loop {
        if interp.get_regs().unwrap().rip == cont_addr {
            break;
        }
        match interp.step() {
            Ok(Some(VcpuExit::Hlt)) => panic!("interp hit HLT before the cont hand-off"),
            Ok(_) => {}
            Err(e) => panic!("interp error: {e:?}"),
        }
    }
    let ir = interp.get_regs().unwrap();

    assert_eq!(gr.exit_pc, cont_addr, "exit stub recorded the loop-exit PC");
    assert_eq!(gr.gpr[0] & 0xffff_ffff, ir.rax & 0xffff_ffff, "eax");
    assert_eq!(gr.gpr[1] & 0xffff_ffff, ir.rcx & 0xffff_ffff, "ecx");
    assert_eq!(gr.gpr[3] & 0xffff_ffff, ir.rbx & 0xffff_ffff, "ebx (continuation NOT run)");
    assert_eq!(gr.gpr[0] & 0xffff_ffff, 20, "eax = 2*10");
    assert_eq!(gr.gpr[3] & 0xffff_ffff, 0x1111, "ebx unchanged — exit block skipped");
}

/// THE M5c GOAL: `run()` itself auto-detects the hot loop, compiles it, and
/// executes it natively — with no manual `jit_try_block` call — and produces the
/// correct architectural result. Proves the auto-trigger + cache + back-edge
/// hotness path end-to-end through the real run loop.
#[test]
fn run_auto_jits_hot_loop() {
    let n = 5000u32;
    let mut vcpu = make_vcpu(n);
    // run() services ~1ms slices and returns Hlt on the timer as well as on a
    // real guest HALT, so loop until the guest loop has actually drained
    // (ecx==0), bounded so a bug can't hang the test.
    let mut slices = 0;
    loop {
        let _ = vcpu.run().expect("run");
        slices += 1;
        if vcpu.get_regs().unwrap().rcx & 0xffff_ffff == 0 || slices > 10_000 {
            break;
        }
    }
    let r = vcpu.get_regs().unwrap();
    assert_eq!(r.rcx & 0xffff_ffff, 0, "the hot loop drained under run()");
    assert_eq!(r.rax & 0xffff_ffff, (2 * n as u64) & 0xffff_ffff, "eax = 2*n (correct result)");
    // The auto-trigger must have fired: at least one region was compiled.
    assert!(
        vcpu.jit_region_count() >= 1,
        "run() should have auto-compiled the hot loop, got {} regions",
        vcpu.jit_region_count()
    );
}

/// SMC safety: a guest store to a code page that has a cached JIT region must
/// EVICT that region (so stale native code never runs) — essential for a kernel
/// that patches/loads code. Control case confirms the region would otherwise
/// stay cached.
#[test]
fn run_smc_evicts_jit_region() {
    // add eax,1 ; dec ecx ; jnz loop   (back-edge to LOAD_ADDR)
    let loop_bytes = [0x83, 0xC0, 0x01, 0xFF, 0xC9, 0x75, 0xF9];
    let mk = |store: bool| -> X86_64Vcpu {
        let mut code = loop_bytes.to_vec();
        if store {
            // mov rbx, LOAD_ADDR ; mov byte [rbx], 0x90   (self-modify code page)
            code.extend_from_slice(&[0x48, 0xBB]);
            code.extend_from_slice(&LOAD_ADDR.to_le_bytes());
            code.extend_from_slice(&[0xC6, 0x03, 0x90]);
        }
        code.push(0xF4); // hlt
        let mut v = make_vcpu_code(&code);
        let mut r = v.get_regs().unwrap();
        r.rcx = 500; // well past the 64-hit JIT threshold
        v.set_regs(&r).unwrap();
        v
    };
    let drive = |v: &mut X86_64Vcpu| {
        for _ in 0..10_000 {
            let _ = v.run().expect("run");
            if v.get_regs().unwrap().rcx & 0xffff_ffff == 0 {
                let _ = v.run().expect("run"); // let the continuation (store+hlt) finish
                break;
            }
        }
    };

    // Control: no self-modifying write — the compiled region remains cached.
    let mut a = mk(false);
    drive(&mut a);
    assert!(
        a.jit_region_count() >= 1,
        "control: the hot loop should compile and stay cached (got {})",
        a.jit_region_count()
    );

    // SMC: the guest store to the loop's code page must evict the region.
    let mut b = mk(true);
    drive(&mut b);
    assert_eq!(
        b.jit_region_count(),
        0,
        "a self-modifying store must evict the cached JIT region"
    );
}

/// Report JIT vs interpreter throughput on the same loop (informational).
#[test]
fn jit_throughput() {
    // Large count: the whole loop runs in ONE native call (internal back-edge).
    let big = 200_000_000u32;
    let mut jit = make_vcpu(big);
    let t = Instant::now();
    let ran = jit.jit_try_block().expect("jit_try_block");
    let dt = t.elapsed();
    assert!(ran, "the loop region should JIT");
    let executed = (big as u64) * 5 + 3; // matches bench_loop accounting
    let mips = executed as f64 / dt.as_secs_f64() / 1e6;
    let r = jit.get_regs().unwrap();
    println!(
        "[jit-vcpu] {} insns in {:.4}s => {:.1} MIPS  (final eax={:#x} ecx={:#x})",
        executed,
        dt.as_secs_f64(),
        mips,
        r.rax & 0xffff_ffff,
        r.rcx & 0xffff_ffff
    );
    assert_eq!(r.rax & 0xffff_ffff, (2 * big as u64) & 0xffff_ffff);
}
