//! Configured Armv6T2 guest admission across standalone VM checkpoints.
use super::*;
use crate::config::Aarch32Isa;
use crate::vm::vcpu::state::Aarch32Registers;

fn step(vm: &mut Vmm, raw: u32, thumb: bool, admitted: bool) -> Aarch32Registers {
    let word = if thumb { raw.rotate_left(16) } else { raw };
    vm.guest_mem
        .memory()
        .write_slice(&word.to_le_bytes(), GuestAddress(CODE))
        .unwrap();
    let cpu = &mut vm.vcpus[0];
    let CpuState::Aarch32(mut state) = cpu.get_state().unwrap() else {
        panic!("expected a standalone AArch32 vCPU");
    };
    state.regs.pc = CODE as u32;
    state.regs.cpsr = 0xd3 | (u32::from(thumb) << 5);
    state.regs.r[2] = u32::MAX;
    state.regs.r[3] = 1 << 30;
    state.regs.r[7] = 0xc0f0_0000;
    state.regs.s[..6].copy_from_slice(&[0, 0, 0, 0x3ff0_0000, 0, 0x4000_0000]);
    state.regs.d_high[0] = 0x1234_5678_9abc_def0;
    let seed = state.regs.clone();
    cpu.set_state(&CpuState::Aarch32(state)).unwrap();
    let retired = cpu.instruction_count();
    assert!(cpu.step_insn().unwrap().is_none());
    let label = format_args!("{raw:#010x} Thumb={thumb}");
    assert_eq!(
        cpu.current_pc(),
        if admitted { CODE + 4 } else { 4 },
        "{label}"
    );
    assert_eq!(
        cpu.instruction_count(),
        retired + u64::from(admitted),
        "{label}"
    );
    let CpuState::Aarch32(observed) = cpu.get_state().unwrap() else {
        panic!("expected a standalone AArch32 vCPU");
    };
    if !admitted {
        assert_eq!(observed.regs.cpsr & 0x3f, 0x1b, "{label}");
        assert_eq!(observed.regs.r, seed.r, "{label}");
        assert_eq!(observed.regs.s, seed.s, "{label}");
        assert_eq!(observed.regs.d_high, seed.d_high, "{label}");
        assert_eq!(observed.regs.fpscr, seed.fpscr, "{label}");
    }
    observed.regs
}

fn check_profile(vm: &mut Vmm) {
    for thumb in [false, true] {
        let mvfr0 = step(vm, 0xeef7_2a10, thumb, true).r[2];
        assert_eq!(mvfr0 & 0xfff, 0x111, "VFPv2 D16 profile");
        assert_eq!(step(vm, 0xeef6_2a10, thumb, true).r[2] & 0x00ff_ffff, 0);
        let result = step(vm, 0xee31_0b02, thumb, true); // VADD.F64 D0,D1,D2
        assert_eq!(result.s[..2], [0, 0x4008_0000]);
        for raw in [
            0xeeb7_0a00,                                   // VFPv3 VMOV.F32 S0,#1.0
            0xee71_0b02,                                   // VADD.F64 D16,D1,D2
            0xeef5_2a10,                                   // VMRS R2,MVFR2
            if thumb { 0xef22_0844 } else { 0xf222_0844 }, // VADD.I32 Q0,Q1,Q2
        ] {
            step(vm, raw, thumb, false);
        }
    }
}

fn check_older_profile_rejection(vm: &mut Vmm, mut bundle: SnapshotBundle) {
    let mut contexts = bundle.take_backend_contexts().unwrap().entries().to_vec();
    let first = contexts[0].as_mut().unwrap();
    let (id, mut imported, end) = profile_cpu(first);
    let former = crate::isa::arm::Armv7Cpu::new();
    imported.vfp.fpsid = former.vfp.fpsid;
    imported.vfp.mvfr0 = former.vfp.mvfr0;
    imported.vfp.mvfr1 = former.vfp.mvfr1;
    imported.vfp.mvfr2 = former.vfp.mvfr2;
    imported.cp15.id_pfr0 = former.cp15.id_pfr0;
    imported.cp15.id_pfr1 = former.cp15.id_pfr1;
    first
        .data
        .splice(8..end, crate::codec::serialize(&(id, imported)).unwrap());
    let legacy = bundle.with_backend_contexts(contexts).unwrap();
    let config = VmConfig::from_checkpoint_bundle(&legacy, CliConfig::default()).unwrap();
    let before = crate::codec::serialize(&vm.vcpus[0].get_state().unwrap()).unwrap();
    let retired = vm.vcpus[0].instruction_count();
    for result in [
        vm.restore_snapshot_bundle(&legacy),
        Vmm::new_resume_bundle(config, &legacy).map(drop),
    ] {
        assert!(matches!(result, Err(Error::InvalidConfig(reason))
            if reason.contains("Armv6T2 checkpoint requires its configured VFPv2 D16 profile")));
    }
    assert_eq!(
        before,
        crate::codec::serialize(&vm.vcpus[0].get_state().unwrap()).unwrap()
    );
    assert_eq!(vm.vcpus[0].instruction_count(), retired);
}

#[test]
fn configured_armv6t2_admits_thumb_vfpv2_but_rejects_later_fp_features() {
    let fixture = Fixture::new();
    let mut config = fixture.config(1);
    config.aarch32_isa = Aarch32Isa::V6T2;
    let mut source = Vmm::new_resume(config).unwrap();
    let reset_cpacr = step(&mut source, 0xee11_2f50, false, true).r[2];
    assert_eq!(reset_cpacr & 0xc0f0_0000, 0);
    step(&mut source, 0xee01_7f50, false, true); // MCR CPACR, R7
    assert_eq!(
        step(&mut source, 0xee11_2f50, false, true).r[2],
        0x00f0_0000
    );
    assert_eq!(
        (step(&mut source, 0xee10_2f11, false, true).r[2] >> 4) & 0xf,
        3
    );
    assert_eq!(
        step(&mut source, 0xeef8_2a10, true, true).r[2] & (1 << 30),
        0
    );
    step(&mut source, 0xee31_0b02, true, false); // VADD before FPEXC.EN.
    step(&mut source, 0xeee8_3a10, true, true); // VMSR FPEXC,R3
    check_profile(&mut source);

    let bundle = source
        .take_snapshot_bundle(source.vcpus[0].instruction_count())
        .unwrap();
    bundle.save(&fixture.checkpoint).unwrap();
    source.restore_snapshot_bundle(&bundle).unwrap();
    check_profile(&mut source);
    check_older_profile_rejection(&mut source, bundle);
    drop(source);
    std::fs::remove_file(&fixture.kernel).unwrap();
    let file = SnapshotBundle::load(&fixture.checkpoint).unwrap();
    let config = VmConfig::from_checkpoint_bundle(&file, CliConfig::default()).unwrap();
    assert_eq!(config.aarch32_isa, Aarch32Isa::V6T2);
    let mut restored = Vmm::new_resume_bundle(config, &file).unwrap();
    check_profile(&mut restored);
}
