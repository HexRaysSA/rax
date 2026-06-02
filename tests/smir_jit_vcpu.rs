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
        v.jit_try_block().expect("jit_try_block").is_none(),
        "a CALL region must bail to the interpreter"
    );

    // (b) A region with no HALT exit — `mov eax,5 ; ret`.
    let mut v = make_vcpu_code(&[0xB8, 0x05, 0x00, 0x00, 0x00, 0xC3]);
    assert!(
        v.jit_try_block().expect("jit_try_block").is_none(),
        "a region without a HALT exit must bail"
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
    let exit = jit.jit_try_block().expect("jit_try_block");
    assert!(
        matches!(exit, Some(VcpuExit::Hlt)),
        "the loop region should JIT and run to HLT, got {exit:?}"
    );
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

/// Report JIT vs interpreter throughput on the same loop (informational).
#[test]
fn jit_throughput() {
    // Large count: the whole loop runs in ONE native call (internal back-edge).
    let big = 200_000_000u32;
    let mut jit = make_vcpu(big);
    let t = Instant::now();
    let exit = jit.jit_try_block().expect("jit_try_block");
    let dt = t.elapsed();
    assert!(matches!(exit, Some(VcpuExit::Hlt)));
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
