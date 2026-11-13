//! CPU-level native x86-64 JIT verification for approximate FP estimates.

use super::*;
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

fn long_mode_vcpu(memory: Arc<GuestMemoryMmap>) -> X86_64Vcpu {
    let mut vcpu = X86_64Vcpu::new(0, memory);
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.regs.rflags = 0x8D7;
    vcpu.mxcsr = 0xDFE1;
    vcpu.set_jit_mem(false);
    vcpu.set_jit_call(false);
    vcpu
}

fn set_f32_lane(vcpu: &mut X86_64Vcpu, register: usize, lane: usize, value: u32) {
    let word = lane / 2;
    let shift = (lane & 1) * 32;
    vcpu.regs.xmm[register][word] = (vcpu.regs.xmm[register][word]
        & !(u64::from(u32::MAX) << shift))
        | (u64::from(value) << shift);
}

fn seed_architectural_state(vcpu: &mut X86_64Vcpu) {
    vcpu.regs.xmm = std::array::from_fn(|register| {
        [
            0x0123_4567_89AB_CDEFu64.rotate_left((register * 7) as u32),
            0xFEDC_BA98_7654_3210u64.rotate_right((register * 11) as u32),
        ]
    });
    vcpu.regs.ymm_high = std::array::from_fn(|register| {
        [
            0x1111_2222_3333_4444u64.rotate_left((register * 5) as u32),
            0xAAAA_BBBB_CCCC_DDDDu64.rotate_right((register * 3) as u32),
        ]
    });
    vcpu.regs.zmm_high = std::array::from_fn(|register| {
        std::array::from_fn(|word| {
            0xF0E1_D2C3_B4A5_9687u64.rotate_left((register * 13 + word * 17) as u32)
        })
    });
    vcpu.regs.zmm_ext = std::array::from_fn(|register| {
        std::array::from_fn(|word| {
            0x6996_F00F_3CC3_A55Au64.rotate_right((register * 19 + word * 23) as u32)
        })
    });
    vcpu.regs.k = [
        0x6996_F00F_3CC3_A55A,
        0,
        1,
        0x0123_4567_89AB_CDEF,
        0x5555_AAAA_3333_CCCC,
        0x8000_0000_0000_0000,
        0xF0F0_0F0F_A5A5_5A5A,
        u64::MAX,
    ];

    for (lane, value) in [7.0f32.to_bits(), 0, 0x7FC1_2345, (-4.0f32).to_bits()]
        .into_iter()
        .enumerate()
    {
        set_f32_lane(vcpu, 3, lane, value);
    }
    set_f32_lane(vcpu, 11, 0, 3.0f32.to_bits());
    for (lane, value) in [
        4.0f32.to_bits(),
        f32::INFINITY.to_bits(),
        1,
        (-0.5f32).to_bits(),
        f32::MAX.to_bits(),
        f32::MIN_POSITIVE.to_bits(),
        0xFF81_2345,
        0x8000_0000,
    ]
    .into_iter()
    .enumerate()
    {
        if lane < 4 {
            set_f32_lane(vcpu, 15, lane, value);
        } else {
            let word = (lane - 4) / 2;
            let shift = ((lane - 4) & 1) * 32;
            vcpu.regs.ymm_high[15][word] = (vcpu.regs.ymm_high[15][word]
                & !(u64::from(u32::MAX) << shift))
                | (u64::from(value) << shift);
        }
    }
}

fn check_verified_estimate_state(mxcsr: u32) {
    let memory =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
    // rcpps xmm1,xmm3
    // rsqrtss xmm8,xmm11
    // vrcpss xmm9,xmm10,xmm11 (VEX.L=1, VEX.W/X ignored)
    // vrsqrtps ymm14,ymm15 (VEX.W/X ignored)
    // jmp next; hlt
    let code = [
        0x0F, 0x53, 0xCB, 0xF3, 0x45, 0x0F, 0x52, 0xC3, 0xC4, 0x41, 0xAE, 0x53, 0xCB, 0xC4, 0x01,
        0xFC, 0x52, 0xF7, 0xEB, 0x00, 0xF4,
    ];
    memory.write_slice(&code, GuestAddress(0)).unwrap();

    let mut direct = long_mode_vcpu(memory.clone());
    let mut verified = long_mode_vcpu(memory);
    direct.mxcsr = mxcsr;
    verified.mxcsr = mxcsr;
    seed_architectural_state(&mut direct);
    seed_architectural_state(&mut verified);

    let frontier = code.len() as u64 - 1;
    let mut direct_steps = 0usize;
    while direct.regs.rip != frontier {
        assert!(direct.step().unwrap().is_none());
        direct_steps += 1;
        assert!(direct_steps <= 5, "direct execution missed HLT frontier");
    }
    assert_eq!(direct_steps, 5);

    let region = verified
        .jit_compile_region()
        .expect("compile legacy/VEX reciprocal-estimate region")
        .expect("register-only reciprocal estimates must be native eligible");
    assert!(region.uses_vector);
    assert!(region.avx_ymm16_vector_state);
    assert!(!region.uses_xmm_state);
    assert!(!region.narrow_vector_opmasks);

    // Verification re-executes the direct x86 handlers. Those handlers use
    // the same host estimate instructions, so implementation-dependent result
    // bits are exactly reproducible on one host even though the ISA specifies
    // only a relative-error bound across hosts.
    verified.jit_run_region_verified(&region);

    assert_eq!(verified.regs.xmm, direct.regs.xmm);
    assert_eq!(verified.regs.ymm_high, direct.regs.ymm_high);
    assert_eq!(verified.regs.zmm_high, direct.regs.zmm_high);
    assert_eq!(verified.regs.zmm_ext, direct.regs.zmm_ext);
    assert_eq!(verified.regs.k, direct.regs.k);
    assert_eq!(verified.mxcsr, direct.mxcsr);
    assert_eq!(verified.regs.rflags, direct.regs.rflags);
    assert_eq!(verified.regs.rip, direct.regs.rip);
    assert_eq!(verified.regs.rip, frontier);
}

fn host_mxcsr() -> u32 {
    let mut value = 0;
    unsafe {
        core::arch::asm!("stmxcsr [{value}]", value = in(reg) &mut value,
                         options(nostack, preserves_flags));
    }
    value
}

fn set_host_mxcsr(value: u32) {
    unsafe {
        core::arch::asm!("ldmxcsr [{value}]", value = in(reg) &value,
                         options(nostack, preserves_flags));
    }
}

struct RestoreHostMxcsr(u32);

impl Drop for RestoreHostMxcsr {
    fn drop(&mut self) {
        set_host_mxcsr(self.0);
    }
}

#[test]
fn jit_verify_replays_same_host_estimates_and_adopts_exact_full_vector_state() {
    if !std::is_x86_feature_detected!("avx") {
        eprintln!("skipping CPU JIT estimate verification: host lacks AVX");
        return;
    }
    let restore = RestoreHostMxcsr(host_mxcsr());
    let mut checked = 0;
    for ambient in [
        0x1F80, 0x3FA1, 0x5FA1, 0x7FA1, 0x9F80, 0xBFA1, 0xDFA1, 0xFFA1,
    ] {
        for guest in [
            0x1F80, 0x3FE1, 0x5FE1, 0x7FE1, 0x9F80, 0xBFE1, 0xDFE1, 0xFFE1,
        ] {
            set_host_mxcsr(ambient);
            check_verified_estimate_state(guest);
            let after = host_mxcsr();
            set_host_mxcsr(restore.0);
            assert_eq!(after, ambient, "guest={guest:#x}");
            checked += 1;
        }
    }
    assert_eq!(checked, 64);
}
