//! Real CPU/helper handoff for partially completed native VSIB stores.

use super::*;
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

fn scatter_code_page_progress(verified: bool) {
    if !std::is_x86_feature_detected!("avx512f") {
        eprintln!("skipping CPU native VSIB SMC: host lacks AVX512F state bridge");
        return;
    }
    // VPSCATTERDD [RAX+ZMM2]{K3},ZMM1; HLT. Lane 0 writes ordinary
    // data; lane 1 targets the already marked instruction page itself.
    let instruction = [0x62, 0xF2, 0x7D, 0x4B, 0xA0, 0x0C, 0x10];
    let memory =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    memory.write_slice(&instruction, GuestAddress(0)).unwrap();
    memory
        .write_obj(0xF4u8, GuestAddress(instruction.len() as u64))
        .unwrap();
    let mut vcpu = X86_64Vcpu::new(0, memory.clone());
    vcpu.sregs.cr0 = 1;
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.regs.rip = 0;
    vcpu.regs.rax = 0;
    vcpu.regs.rsp = 0x3000;
    vcpu.regs.rflags = 0xCD7;
    vcpu.mxcsr = 0x3FA1;
    vcpu.regs.xmm[1][0] = 0x9090_9090_1122_3344;
    vcpu.regs.xmm[2][0] = 0x0000_0000_0000_2000;
    vcpu.regs.k[3] = 0xFEDC_0000_0000_0003;
    vcpu.set_jit_mem(true);
    vcpu.set_jit_call(false);

    let region = vcpu
        .jit_compile_region()
        .unwrap()
        .expect("VSIB must be natively admitted");
    assert!(region.uses_vector);
    assert!(region.narrow_vector_opmasks);
    assert!(vcpu.mmu.is_code_page(0));
    if verified {
        vcpu.jit_run_region_verified(&region);
    } else {
        vcpu.jit_run_region_native(&region);
    }

    assert_eq!(
        vcpu.regs.rip, 0,
        "code-page helper exits at the scatter instruction"
    );
    assert_eq!(
        vcpu.regs.k[3], 0xFEDC_0000_0000_0002,
        "only completed lane 0 clears"
    );
    assert_eq!(
        memory.read_obj::<u32>(GuestAddress(0x2000)).unwrap(),
        0x1122_3344
    );
    let mut original = [0; 7];
    memory.read_slice(&mut original, GuestAddress(0)).unwrap();
    assert_eq!(
        original, instruction,
        "native helper must not yet modify code"
    );
    assert_eq!(vcpu.regs.rflags, 0xCD7);
    assert_eq!(vcpu.mxcsr, 0x3FA1);

    // Deliberately change the already completed source lane. Restarting the
    // instruction must not repeat that store, but must complete lane 1.
    vcpu.regs.xmm[1][0] = 0x9090_9090_AABB_CCDD;
    assert!(vcpu.step().unwrap().is_none());
    assert_eq!(vcpu.regs.rip, instruction.len() as u64);
    assert_eq!(vcpu.regs.k[3], 0);
    assert_eq!(
        memory.read_obj::<u32>(GuestAddress(0x2000)).unwrap(),
        0x1122_3344
    );
    assert_eq!(
        memory.read_obj::<u32>(GuestAddress(0)).unwrap(),
        0x9090_9090
    );
    assert!(
        vcpu.mmu.has_smc_dirty(),
        "direct fallback records the code-page write"
    );
    vcpu.drain_smc();
    assert!(!vcpu.mmu.has_smc_dirty());
    // The next fetch at the old address executes one replacement NOP, not
    // the formerly cached seven-byte VSIB instruction.
    vcpu.regs.rip = 0;
    assert!(vcpu.step().unwrap().is_none());
    assert_eq!(vcpu.regs.rip, 1);
    assert_eq!(vcpu.regs.k[3], 0);
}

#[test]
fn jit_vsib_scatter_to_its_code_page_preserves_progress_then_redecodes_modified_bytes() {
    scatter_code_page_progress(false);
}

#[test]
fn jit_vsib_verified_scatter_code_page_handoff_compares_the_exact_partial_prefix() {
    scatter_code_page_progress(true);
}

#[test]
fn jit_vsib_verified_late_memory_failure_preserves_partial_gather_and_scatter() {
    if !std::is_x86_feature_detected!("avx512f") {
        eprintln!("skipping verified native VSIB fault: host lacks AVX512F state bridge");
        return;
    }
    for scatter in [false, true] {
        let memory =
            Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x3000)]).unwrap());
        // MOV EBX,22334455h; VPGATHERDD/VPSCATTERDD; HLT. The VSIB
        // frontier is deliberately later than the region entry, so verified
        // replay must execute both the earlier instruction and lane 0.
        let code = [
            0xBB,
            0x55,
            0x44,
            0x33,
            0x22,
            0x62,
            0xF2,
            0x7D,
            0x4B,
            if scatter { 0xA0 } else { 0x90 },
            0x0C,
            0x10,
            0xF4,
        ];
        memory.write_slice(&code, GuestAddress(0)).unwrap();
        memory
            .write_obj(0x1122_3344u32, GuestAddress(0x2000))
            .unwrap();
        let mut vcpu = X86_64Vcpu::new(0, memory.clone());
        vcpu.sregs.cr0 = 1;
        vcpu.sregs.efer = 1 << 10;
        vcpu.sregs.cs.l = true;
        vcpu.regs.rip = 0;
        vcpu.regs.rax = 0;
        vcpu.regs.rbx = 0xBAD0_BAD0_BAD0_BAD0;
        vcpu.regs.rsp = 0x2800;
        vcpu.regs.rflags = 0xCD7;
        vcpu.mxcsr = 0x3FA1;
        vcpu.regs.xmm[1] = [0x5555_6666_7788_99AA, 0xA1B2_C3D4_E5F6_0718];
        vcpu.regs.ymm_high[1] = [0x1234_5678_90AB_CDEF; 2];
        vcpu.regs.zmm_high[1] = [0xF0F1_F2F3_F4F5_F6F7; 4];
        vcpu.regs.xmm[2][0] = 0x0000_4000_0000_2000;
        vcpu.regs.k[3] = 0xFEDC_0000_0000_0003;
        vcpu.set_jit_mem(true);
        vcpu.set_jit_call(false);
        let before = vcpu.regs.clone();
        let region = vcpu
            .jit_compile_region()
            .unwrap()
            .expect("VSIB late-fault region native admission");
        vcpu.jit_run_region_verified(&region);
        assert_eq!(vcpu.regs.rip, 5, "failed lane remains at the VSIB PC");
        assert_eq!(
            vcpu.regs.rbx, 0x2233_4455,
            "pre-VSIB instruction was verified"
        );
        assert_eq!(vcpu.regs.k[3], 0xFEDC_0000_0000_0002);
        assert_eq!(
            vcpu.regs.xmm[1][0],
            if scatter {
                before.xmm[1][0]
            } else {
                0x5555_6666_1122_3344
            }
        );
        assert_eq!(vcpu.regs.xmm[1][1], before.xmm[1][1]);
        assert_eq!(vcpu.regs.ymm_high[1], before.ymm_high[1]);
        assert_eq!(vcpu.regs.zmm_high[1], before.zmm_high[1]);
        assert_eq!(vcpu.regs.xmm[2], before.xmm[2]);
        assert_eq!(vcpu.regs.rflags, before.rflags);
        assert_eq!(vcpu.mxcsr, 0x3FA1);
        assert_eq!(
            memory.read_obj::<u32>(GuestAddress(0x2000)).unwrap(),
            if scatter { 0x7788_99AA } else { 0x1122_3344 }
        );
    }
}

#[test]
fn jit_vsib_verified_loop_replays_the_second_visit_to_the_same_faulting_pc() {
    // The mixed VMOVQ/KMOVW region currently selects the general full-opmask
    // bridge. Pure VSIB regions themselves require only AVX512F.
    if !std::is_x86_feature_detected!("avx512f") || !std::is_x86_feature_detected!("avx512bw") {
        eprintln!("skipping verified VSIB loop: mixed-region AVX512F/BW bridge unavailable");
        return;
    }
    let memory =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x3000)]).unwrap());
    // KMOVW K3,ESI; VMOVQ XMM2,RCX; VPGATHERDD ZMM1{K3},[RAX+ZMM2];
    // MOV RCX,0000400000002000h; DEC RBX; JNZ entry; HLT.
    // The first visit reads 2000h/2004h. The next updates XMM2 and K3,
    // re-reads 2000h, then faults at 4000h while still at guest PC 9.
    let code = [
        0xC5, 0xF8, 0x92, 0xDE, 0xC4, 0xE1, 0xF9, 0x6E, 0xD1, 0x62, 0xF2, 0x7D, 0x4B, 0x90, 0x0C,
        0x10, 0x48, 0xB9, 0x00, 0x20, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x48, 0xFF, 0xCB, 0x75,
        0xE1, 0xF4,
    ];
    memory.write_slice(&code, GuestAddress(0)).unwrap();
    memory
        .write_obj(0x5566_7788_1122_3344u64, GuestAddress(0x2000))
        .unwrap();
    let mut vcpu = X86_64Vcpu::new(0, memory.clone());
    vcpu.sregs.cr0 = 1;
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.regs.rip = 0;
    vcpu.regs.rax = 0;
    vcpu.regs.rcx = 0x0000_2004_0000_2000;
    vcpu.regs.rbx = 2;
    vcpu.regs.rsi = 3;
    vcpu.regs.rsp = 0x2800;
    vcpu.regs.rflags = 0xCD7;
    vcpu.mxcsr = 0x3FA1;
    vcpu.regs.xmm[1] = [u64::MAX; 2];
    vcpu.set_jit_mem(true);
    vcpu.set_jit_call(false);
    // Explicit compile keeps native backedges, unlike hot-loop promotion's
    // instruction-boundary yield. This is the dynamic-ordinal regression.
    let region = vcpu
        .jit_compile_region()
        .unwrap()
        .expect("native VSIB loop");
    assert!(region.yielded_backward_exit_pcs.is_empty());
    vcpu.jit_run_region_verified(&region);
    assert_eq!(vcpu.regs.rip, 9);
    assert_eq!(
        vcpu.regs.rbx, 1,
        "one loop iteration completed before the fault"
    );
    assert_eq!(vcpu.regs.rcx, 0x0000_4000_0000_2000);
    assert_eq!(vcpu.regs.xmm[2][0], 0x0000_4000_0000_2000);
    assert_eq!(vcpu.regs.xmm[1][0], 0x5566_7788_1122_3344);
    assert_eq!(vcpu.regs.k[3], 2);
    assert_eq!(vcpu.regs.rflags, 0x403);
    assert_eq!(vcpu.mxcsr, 0x3FA1);
}

/// `run()` also returns Hlt for a scheduling yield. Only `halted` proves that
/// the guest executed HLT. Eight bounded run calls tolerate those yields while
/// making a repeated native same-PC frontier fail instead of spinning forever.
/// Each individual run has its existing 1 ms/1024-iteration housekeeping check;
/// this test does not assert elapsed wall time or a machine-dependent throughput.
fn run_to_architectural_halt(vcpu: &mut X86_64Vcpu, context: &str) {
    for _ in 0..8 {
        let exit = vcpu
            .run()
            .unwrap_or_else(|error| panic!("{context}: {error}"));
        assert!(matches!(exit, VcpuExit::Hlt), "{context}: {exit:?}");
        if vcpu.halted {
            return;
        }
    }
    panic!(
        "{context}: eight scheduling yields without architectural HLT; RIP={:#x}, K3={:#x}",
        vcpu.regs.rip, vcpu.regs.k[3]
    );
}

#[test]
fn jit_vsib_cached_run_scatter_smc_completes_once_and_executes_replacement_bytes() {
    if !std::is_x86_feature_detected!("avx512f") {
        eprintln!("skipping cached CPU native VSIB SMC: host lacks AVX512F state bridge");
        return;
    }
    // VPSCATTERDD [RAX+ZMM2]{K3},ZMM1; HLT. The second active lane
    // replaces the original instruction's first four bytes with HLT; NOP*3.
    let instruction = [0x62, 0xF2, 0x7D, 0x4B, 0xA0, 0x0C, 0x10];
    let memory =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    memory.write_slice(&instruction, GuestAddress(0)).unwrap();
    memory.write_obj(0xF4u8, GuestAddress(7)).unwrap();
    let mut vcpu = X86_64Vcpu::new(0, memory.clone());
    vcpu.sregs.cr0 = 1;
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.regs.rip = 0;
    vcpu.regs.rax = 0;
    vcpu.regs.rsp = 0x3000;
    vcpu.regs.rflags = 0xCD7;
    vcpu.mxcsr = 0x3FA1;
    vcpu.regs.xmm[1][0] = 0x9090_90F4_1122_3344;
    vcpu.regs.xmm[2][0] = 0x0000_0000_0000_2000;
    vcpu.regs.k[3] = 0xFEDC_0000_0000_0003;
    vcpu.set_jit_mem(true);
    vcpu.set_jit_call(false);

    let region = vcpu
        .jit_compile_region()
        .unwrap()
        .expect("cached-run scatter must be natively admitted");
    assert!(region.uses_vector && region.narrow_vector_opmasks);
    let cache_key = (0, vcpu.jit_mode_tag());
    vcpu.jit_cache.insert(cache_key, Some(Arc::new(region)));
    assert!(vcpu.mmu.is_code_page(0));

    // No manual jit_run_region/step handoff: the production cache-hit loop
    // must run lane 0 natively, defer lane 1, and consume the one-shot fallback.
    run_to_architectural_halt(&mut vcpu, "cached scatter SMC");
    assert_eq!(vcpu.regs.rip, 8);
    assert_eq!(vcpu.regs.k[3], 0);
    assert_eq!(vcpu.regs.rflags, 0xCD7);
    assert_eq!(vcpu.mxcsr, 0x3FA1);
    assert_eq!(
        memory.read_obj::<u32>(GuestAddress(0x2000)).unwrap(),
        0x1122_3344
    );
    assert_eq!(
        memory.read_obj::<u32>(GuestAddress(0)).unwrap(),
        0x9090_90F4
    );
    assert!(!vcpu.mmu.has_smc_dirty(), "run must drain the SMC journal");
    assert!(
        !vcpu.jit_cache.contains_key(&cache_key),
        "the modified source page must evict its cached native region"
    );

    // Re-enter via the real run loop. A stale decode/native region would
    // execute the old seven-byte scatter and stop at RIP 8 instead of RIP 1.
    vcpu.halted = false;
    vcpu.regs.rip = 0;
    vcpu.regs.k[3] = 1;
    vcpu.regs.xmm[1][0] = 0xAABB_CCDD;
    run_to_architectural_halt(&mut vcpu, "replacement HLT fetch");
    assert_eq!(vcpu.regs.rip, 1);
    assert_eq!(vcpu.regs.k[3], 1, "replacement HLT must not execute VSIB");
    assert_eq!(
        memory.read_obj::<u32>(GuestAddress(0x2000)).unwrap(),
        0x1122_3344,
        "the completed scatter lane must not execute after SMC"
    );
}

#[test]
fn jit_vsib_cached_run_late_page_fault_delivers_guest_frame_or_triple_fault() {
    if !std::is_x86_feature_detected!("avx512f") {
        eprintln!("skipping cached CPU native VSIB #PF: host lacks AVX512F state bridge");
        return;
    }
    for scatter in [false, true] {
        for valid_idt in [false, true] {
            let memory = Arc::new(
                GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
            );
            let instruction = [
                0x62,
                0xF2,
                0x7D,
                0x4B,
                if scatter { 0xA0 } else { 0x90 },
                0x0C,
                0x10,
                0xF4,
            ];
            memory.write_slice(&instruction, GuestAddress(0)).unwrap();
            memory
                .write_obj(0x1122_3344u32, GuestAddress(0x2000))
                .unwrap();
            // Identity-map code, handler, data, IDT, GDT and exception stack.
            // Linear page 0x3000 is deliberately absent from the final table.
            for (address, value) in [(0x8000, 0x9007u64), (0x9000, 0xA007), (0xA000, 0xB007)] {
                memory.write_obj(value, GuestAddress(address)).unwrap();
            }
            for page in [0u64, 1, 2, 4, 5, 6] {
                memory
                    .write_obj((page << 12) | 7, GuestAddress(0xB000 + page * 8))
                    .unwrap();
            }
            let mut vcpu = X86_64Vcpu::new(0, memory.clone());
            vcpu.sregs.cr0 = 0x8005_0033;
            vcpu.sregs.cr3 = 0x8000;
            vcpu.sregs.cr4 = 1 << 5;
            vcpu.sregs.efer = (1 << 8) | (1 << 10);
            vcpu.sregs.cs.l = true;
            vcpu.sregs.cs.db = false;
            vcpu.sregs.cs.selector = 8;
            vcpu.sregs.ss.selector = 16;
            vcpu.sregs.idt.base = 0x4000;
            vcpu.sregs.idt.limit = 0xFFF;
            vcpu.sregs.gdt.base = 0x5000;
            vcpu.sregs.gdt.limit = 23;
            if valid_idt {
                // Present ring-0 64-bit code, accessed bit set; flat data.
                memory
                    .write_obj(0x00AF_9B00_0000_FFFFu64, GuestAddress(0x5008))
                    .unwrap();
                memory
                    .write_obj(0x00CF_9300_0000_FFFFu64, GuestAddress(0x5010))
                    .unwrap();
                let mut gate = [0u8; 16];
                gate[..2].copy_from_slice(&0x1000u16.to_le_bytes());
                gate[2..4].copy_from_slice(&8u16.to_le_bytes());
                gate[5] = 0x8E; // present ring-0 interrupt gate, IST=0.
                memory
                    .write_slice(&gate, GuestAddress(0x4000 + 14 * 16))
                    .unwrap();
                // MOV R15D,DEADBEEFh; HLT: observable guest #PF handler.
                memory
                    .write_slice(
                        &[0x41, 0xBF, 0xEF, 0xBE, 0xAD, 0xDE, 0xF4],
                        GuestAddress(0x1000),
                    )
                    .unwrap();
            }
            vcpu.regs.rip = 0;
            vcpu.regs.rax = 0;
            vcpu.regs.rsp = 0x7000;
            vcpu.regs.rflags = 0xCD7;
            vcpu.regs.r15 = 0;
            vcpu.mxcsr = 0x3FA1;
            vcpu.regs.xmm[1] = [0x5555_6666_7788_99AA, 0xA1B2_C3D4_E5F6_0718];
            vcpu.regs.ymm_high[1] = [0x1234_5678_90AB_CDEF; 2];
            vcpu.regs.zmm_high[1] = [0xF0F1_F2F3_F4F5_F6F7; 4];
            vcpu.regs.xmm[2][0] = 0x0000_3000_0000_2000;
            vcpu.regs.k[3] = 0xFEDC_0000_0000_0003;
            vcpu.set_jit_mem(true);
            vcpu.set_jit_call(false);
            let before = vcpu.regs.clone();
            let region = vcpu
                .jit_compile_region()
                .unwrap()
                .expect("cached-run late-fault VSIB must be natively admitted");
            assert!(region.uses_vector && region.narrow_vector_opmasks);
            let cache_key = (0, vcpu.jit_mode_tag());
            vcpu.jit_cache.insert(cache_key, Some(Arc::new(region)));

            if valid_idt {
                run_to_architectural_halt(&mut vcpu, "cached VSIB guest #PF handler");
                assert_eq!(vcpu.regs.rip, 0x1007);
                assert_eq!(vcpu.regs.r15, 0xDEAD_BEEF);
                assert_eq!(vcpu.regs.rsp, 0x7000 - 6 * 8);
                // Frame = error, fault RIP, CS, RFLAGS, prior RSP, SS.
                let expected = [u64::from(scatter) << 1, 0, 8, 0xCD7, 0x7000, 16];
                for (slot, value) in expected.into_iter().enumerate() {
                    let actual = memory
                        .read_obj::<u64>(GuestAddress(vcpu.regs.rsp + slot as u64 * 8))
                        .unwrap();
                    // Saved RF insertion is owned by generic exception
                    // delivery, not this VSIB restart test. Intel SDM 086,
                    // Vol. 3B 19.3.1.1 requires RF=1 for a #PF; the current
                    // exception path preserves its incoming value instead.
                    let mask = if slot == 3 {
                        !flags::bits::RF
                    } else {
                        u64::MAX
                    };
                    assert_eq!(
                        actual & mask,
                        value & mask,
                        "scatter={scatter}: #PF frame slot {slot}"
                    );
                }
            } else {
                let mut delivery_error = None;
                for _ in 0..8 {
                    match vcpu.run() {
                        Err(error) => {
                            delivery_error = Some(error.to_string());
                            break;
                        }
                        Ok(exit) => {
                            assert!(matches!(exit, VcpuExit::Hlt), "{exit:?}");
                            assert!(!vcpu.halted, "faulting VSIB must not reach trailing HLT");
                        }
                    }
                }
                let error = delivery_error.expect("cached late #PF must not spin natively");
                assert!(error.contains("triple fault"), "{error}");
                assert!(error.contains("vector 14"), "{error}");
                assert_eq!(vcpu.regs.rip, 0);
                assert_eq!(vcpu.regs.rsp, before.rsp);
            }
            assert_eq!(vcpu.sregs.cr2, 0x3000);
            assert_eq!(vcpu.regs.k[3], 0xFEDC_0000_0000_0002);
            assert_eq!(
                vcpu.regs.xmm[1][0],
                if scatter {
                    before.xmm[1][0]
                } else {
                    0x5555_6666_1122_3344
                }
            );
            assert_eq!(vcpu.regs.xmm[1][1], before.xmm[1][1]);
            assert_eq!(vcpu.regs.ymm_high[1], before.ymm_high[1]);
            assert_eq!(vcpu.regs.zmm_high[1], before.zmm_high[1]);
            assert_eq!(vcpu.regs.xmm[2], before.xmm[2]);
            assert_eq!(vcpu.mxcsr, 0x3FA1);
            assert_eq!(
                memory.read_obj::<u32>(GuestAddress(0x2000)).unwrap(),
                if scatter { 0x7788_99AA } else { 0x1122_3344 }
            );
        }
    }
}

#[test]
fn jit_vsib_cached_run_compatibility_guard_uses_32_bit_effective_addresses() {
    if !std::is_x86_feature_detected!("avx512f") {
        eprintln!("skipping cached CPU native VSIB CS.L guard: host lacks AVX512F state bridge");
        return;
    }
    for scatter in [false, true] {
        // Both candidate addresses are mapped and contain different payloads:
        // an omitted CS.L guard must produce a wrong result, not an incidental
        // helper fault that independently causes the correct direct fallback.
        let memory = Arc::new(
            GuestMemoryMmap::<()>::from_ranges(&[
                (GuestAddress(0), 0x4000),
                (GuestAddress(0x1_0000_2000), 0x1000),
            ])
            .unwrap(),
        );
        let instruction = [
            0x62,
            0xF2,
            0x7D,
            0x4B,
            if scatter { 0xA0 } else { 0x90 },
            0x0C,
            0x10,
            0xF4,
        ];
        memory.write_slice(&instruction, GuestAddress(0)).unwrap();
        memory
            .write_obj(0x1122_3344u32, GuestAddress(0x2000))
            .unwrap();
        memory
            .write_obj(0xAABB_CCDDu32, GuestAddress(0x1_0000_2000))
            .unwrap();
        let mut vcpu = X86_64Vcpu::new(0, memory.clone());
        vcpu.sregs.cr0 = 1;
        vcpu.sregs.efer = 1 << 10;
        vcpu.sregs.cs.l = false;
        vcpu.sregs.cs.db = true;
        vcpu.sregs.cs.base = 0;
        vcpu.sregs.ds.base = 0;
        vcpu.regs.rip = 0;
        vcpu.regs.rax = 0x1_0000_2000;
        vcpu.regs.rsp = 0x3000;
        vcpu.regs.rflags = 0xCD7;
        vcpu.mxcsr = 0x3FA1;
        vcpu.regs.xmm[1] = [0x5555_6666_7788_99AA, 0xA1B2_C3D4_E5F6_0718];
        vcpu.regs.ymm_high[1] = [0x1234_5678_90AB_CDEF; 2];
        vcpu.regs.zmm_high[1] = [0xF0F1_F2F3_F4F5_F6F7; 4];
        vcpu.regs.xmm[2] = [0; 2];
        vcpu.regs.k[3] = 0xFEDC_0000_0000_0001;
        vcpu.set_jit_mem(true);
        vcpu.set_jit_call(false);
        let before = vcpu.regs.clone();

        // Compile and cache under the actual compatibility-mode key. Moving a
        // long-mode region into an unrelated cache key would not exercise a
        // reachable production cache hit.
        let region = vcpu
            .jit_compile_region()
            .unwrap()
            .expect("compatibility-mode VSIB region retains its dynamic CS.L guard");
        assert!(region.uses_vector && region.narrow_vector_opmasks);
        assert_eq!(region.vsib_instructions.len(), 1);
        let cache_key = (0, vcpu.jit_mode_tag());
        vcpu.jit_cache.insert(cache_key, Some(Arc::new(region)));
        run_to_architectural_halt(&mut vcpu, "cached VSIB compatibility guard");

        assert_eq!(vcpu.regs.rip, 8);
        assert_eq!(vcpu.regs.rax, before.rax);
        assert_eq!(vcpu.regs.rsp, before.rsp);
        assert_eq!(vcpu.regs.rflags, before.rflags);
        assert_eq!(vcpu.mxcsr, 0x3FA1);
        assert_eq!(vcpu.regs.k[3], 0);
        assert_eq!(
            vcpu.regs.xmm[1][0],
            if scatter {
                before.xmm[1][0]
            } else {
                0x5555_6666_1122_3344
            }
        );
        assert_eq!(vcpu.regs.xmm[1][1], before.xmm[1][1]);
        assert_eq!(vcpu.regs.ymm_high[1], before.ymm_high[1]);
        assert_eq!(vcpu.regs.zmm_high[1], before.zmm_high[1]);
        assert_eq!(vcpu.regs.xmm[2], before.xmm[2]);
        assert_eq!(
            memory.read_obj::<u32>(GuestAddress(0x2000)).unwrap(),
            if scatter { 0x7788_99AA } else { 0x1122_3344 }
        );
        assert_eq!(
            memory.read_obj::<u32>(GuestAddress(0x1_0000_2000)).unwrap(),
            0xAABB_CCDD,
            "a compatibility-mode VSIB must never access the untruncated address"
        );
        assert!(
            vcpu.jit_vsib_resume_pc.is_none(),
            "one-shot guard handoff consumed"
        );
    }
}

#[test]
fn jit_vsib_cached_run_disabled_apx_base_reaches_direct_ud_without_lane_effects() {
    if !std::is_x86_feature_detected!("avx512f") {
        eprintln!("skipping cached CPU native VSIB APX guard: host lacks AVX512F state bridge");
        return;
    }
    for scatter in [false, true] {
        for active_mask in [0, 1] {
            let memory =
                Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
            // B4 selects R16. APX disablement is checked even with no active
            // lanes; the interpreted #UD delivery sees an empty guest IDT.
            let instruction = [
                0x62,
                0xFA,
                0x7D,
                0x4B,
                if scatter { 0xA0 } else { 0x90 },
                0x0C,
                0x10,
                0xF4,
            ];
            memory.write_slice(&instruction, GuestAddress(0)).unwrap();
            memory
                .write_obj(0x1122_3344u32, GuestAddress(0x2000))
                .unwrap();
            let mut vcpu = X86_64Vcpu::new(0, memory.clone());
            vcpu.sregs.cr0 = 1;
            vcpu.sregs.efer = 1 << 10;
            vcpu.sregs.cs.l = true;
            vcpu.sregs.idt.base = 0x1000;
            vcpu.sregs.idt.limit = 0xFFF;
            vcpu.regs.rip = 0;
            vcpu.regs.rax = 0x2400;
            vcpu.regs.r16 = 0x2000;
            vcpu.regs.rsp = 0x3000;
            vcpu.regs.rflags = 0xCD7;
            vcpu.mxcsr = 0x3FA1;
            vcpu.regs.xmm[1] = [0x5555_6666_7788_99AA, 0xA1B2_C3D4_E5F6_0718];
            vcpu.regs.ymm_high[1] = [0x1234_5678_90AB_CDEF; 2];
            vcpu.regs.zmm_high[1] = [0xF0F1_F2F3_F4F5_F6F7; 4];
            vcpu.regs.xmm[2] = [0; 2];
            vcpu.regs.k[3] = 0xFEDC_0000_0000_0000 | active_mask;
            vcpu.set_apx_enabled(true);
            vcpu.set_jit_mem(true);
            vcpu.set_jit_call(false);
            let before = vcpu.regs.clone();
            let before_gprs: Vec<_> = (0..32).map(|index| vcpu.get_reg(index, 8)).collect();
            let region = vcpu
                .jit_compile_region()
                .unwrap()
                .expect("APX-base VSIB region must be natively admitted before disablement");
            assert!(region.uses_vector && region.narrow_vector_opmasks);
            assert_eq!(region.vsib_instructions.len(), 1);
            let cache_key = (0, vcpu.jit_mode_tag());
            vcpu.jit_cache.insert(cache_key, Some(Arc::new(region)));
            vcpu.set_apx_enabled(false);
            assert_eq!(
                (vcpu.regs.rip, vcpu.jit_mode_tag()),
                cache_key,
                "APX profile changes retain the cached region and use its dynamic guard"
            );

            let mut delivery_error = None;
            for _ in 0..8 {
                match vcpu.run() {
                    Err(error) => {
                        delivery_error = Some(error.to_string());
                        break;
                    }
                    Ok(exit) => {
                        assert!(matches!(exit, VcpuExit::Hlt), "{exit:?}");
                        assert!(!vcpu.halted, "disabled APX must not reach trailing HLT");
                    }
                }
            }
            let error = delivery_error.expect("cached APX guard must not spin natively");
            assert!(
                error.contains("triple fault while delivering vector 6"),
                "{error}"
            );
            assert_eq!(vcpu.regs.rip, 0);
            let after_gprs: Vec<_> = (0..32).map(|index| vcpu.get_reg(index, 8)).collect();
            assert_eq!(after_gprs, before_gprs);
            assert_eq!(vcpu.regs.xmm, before.xmm);
            assert_eq!(vcpu.regs.ymm_high, before.ymm_high);
            assert_eq!(vcpu.regs.zmm_high, before.zmm_high);
            assert_eq!(vcpu.regs.zmm_ext, before.zmm_ext);
            assert_eq!(vcpu.regs.k, before.k);
            assert_eq!(vcpu.regs.rflags, before.rflags);
            assert_eq!(vcpu.mxcsr, 0x3FA1);
            assert_eq!(
                memory.read_obj::<u32>(GuestAddress(0x2000)).unwrap(),
                0x1122_3344
            );
            assert!(
                vcpu.jit_vsib_resume_pc.is_none(),
                "one-shot APX handoff consumed"
            );
        }
    }
}
