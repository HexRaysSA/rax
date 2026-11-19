//! Feature-register declarations for the implemented default FP instruction set.
use rax::isa::arm::aarch32::cpu::ProcessorMode;
use rax::isa::arm::aarch64::{AArch64Config, AArch64Cpu};
use rax::isa::arm::common::cpu::{ArmCpu, CpuExit};
use rax::isa::arm::common::features::ArmFeatures;
use rax::isa::arm::common::memory::FlatMemory as MixedMemory;
use rax::isa::arm::common::sysreg::{Aarch64SysRegEncoding, Cp15Encoding};
use rax::isa::arm::decoder::{Aarch32Decoder, ThumbDecoder};
use rax::isa::arm::execution::FlatMemory;
use rax::isa::arm::{Armv7Cpu, ExecResult, Executor};

fn execute(cpu: &mut Armv7Cpu, memory: &mut FlatMemory, raw: u32) -> ExecResult {
    let insn = if cpu.cpsr.t {
        ThumbDecoder::decode_32bit(raw)
    } else {
        Aarch32Decoder::decode(raw)
    }
    .unwrap();
    Executor::new(cpu, memory).execute(&insn)
}

#[test]
fn default_feature_fields_describe_half_data_processing_and_miscellaneous_fp() {
    let cpu = Armv7Cpu::new();
    assert_eq!(cpu.vfp.mvfr0, 0x1011_0222);
    assert_eq!(cpu.vfp.mvfr1, 0x1321_1111);
    assert_eq!(cpu.vfp.mvfr2, 0x43);
    assert_eq!((cpu.vfp.mvfr0 >> 12) & 15, 0); // No FP traps.
    assert_eq!((cpu.vfp.mvfr0 >> 24) & 15, 0); // No short vectors.
    assert_eq!((cpu.vfp.mvfr1 >> 24) & 15, 3); // Scalar half conversion + data processing.
    assert_eq!((cpu.vfp.mvfr1 >> 20) & 15, 2); // AdvSIMD half conversion + data processing.
    assert_eq!(cpu.vfp.mvfr2 >> 4, 4); // Scalar select, directed conversion, rounding, number min/max.
    assert_eq!(cpu.vfp.mvfr2 & 15, 3); // AdvSIMD directed conversion, rounding, number min/max.
}

#[test]
fn privileged_feature_reads_work_with_fp_disabled_and_preserve_control_and_data() {
    let mut memory = FlatMemory::new(4096, 0);
    for thumb in [false, true] {
        let mut cpu = Armv7Cpu::new();
        cpu.cpsr.t = thumb;
        cpu.vfp.fpexc = 0;
        cpu.vfp.dregs.fill(0x7ff1_2345_89ab_cdef);
        let cpsr = cpu.cpsr.to_u32();
        let dregs = cpu.vfp.dregs;
        for (raw, expected) in [
            (0xeef7_0a10, 0x1011_0222),
            (0xeef6_0a10, 0x1321_1111),
            (0xeef5_0a10, 0x43),
        ] {
            assert!(matches!(
                execute(&mut cpu, &mut memory, raw),
                ExecResult::Continue
            ));
            assert_eq!(cpu.regs[0], expected);
            assert_eq!(cpu.cpsr.to_u32(), cpsr);
            assert_eq!(cpu.vfp.dregs, dregs);
            assert_eq!(cpu.vfp.fpexc, 0);
        }
    }
}

#[test]
fn mvfr_register_writes_reject_without_modifying_features_or_fp_state() {
    let mut memory = FlatMemory::new(4096, 0);
    for thumb in [false, true] {
        for raw in [0xeee5_0a10, 0xeee6_0a10, 0xeee7_0a10] {
            let mut cpu = Armv7Cpu::new();
            cpu.cpsr.t = thumb;
            cpu.regs[0] = u32::MAX;
            let features = (cpu.vfp.mvfr0, cpu.vfp.mvfr1, cpu.vfp.mvfr2);
            let regs = cpu.regs;
            let dregs = cpu.vfp.dregs;
            let cpsr = cpu.cpsr.to_u32();
            assert!(matches!(
                execute(&mut cpu, &mut memory, raw),
                ExecResult::Undefined
            ));
            assert_eq!((cpu.vfp.mvfr0, cpu.vfp.mvfr1, cpu.vfp.mvfr2), features);
            assert_eq!(cpu.regs, regs);
            assert_eq!(cpu.vfp.dregs, dregs);
            assert_eq!(cpu.cpsr.to_u32(), cpsr);
        }
    }
}

#[test]
fn id_isar6_exposes_only_implemented_fhm_and_remains_read_only() {
    let mut memory = FlatMemory::new(4096, 0);
    let encoding = Cp15Encoding::new(0, 0, 2, 7);
    for thumb in [false, true] {
        let mut cpu = Armv7Cpu::new();
        cpu.cpsr.t = thumb;
        assert_eq!(cpu.cp15.read(encoding), Some(0x100));
        assert!(!cpu.cp15.write(encoding, u32::MAX));
        assert_eq!(cpu.cp15.read(encoding), Some(0x100));
        let old_ids = cpu.cp15.id_isar;
        let cpsr = cpu.cpsr.to_u32();
        assert!(matches!(
            execute(&mut cpu, &mut memory, 0xee10_0ff2),
            ExecResult::Continue
        ));
        assert_eq!(cpu.regs[0], 0x100);
        cpu.regs[0] = u32::MAX;
        // Existing CP15 instruction policy accepts writes to read-only ID space as no-ops.
        assert!(matches!(
            execute(&mut cpu, &mut memory, 0xee00_0ff2),
            ExecResult::Continue
        ));
        assert!(matches!(
            execute(&mut cpu, &mut memory, 0xee10_0ff2),
            ExecResult::Continue
        ));
        assert_eq!(cpu.regs[0], 0x100);
        assert_eq!(cpu.cp15.id_isar, old_ids);
        assert_eq!(cpu.cpsr.to_u32(), cpsr);
    }
}

#[test]
fn standalone_id_reads_hide_unsupported_advsimd_fields_after_state_roundtrip() {
    let mut memory = FlatMemory::new(4096, 0);
    // Set every bit in each absent field. Keep nearby RDM, FHM, and JSCVT set.
    let raw_isar5 = 0xf100_0000;
    let raw_isar6 = 0x0ff0_01f1;
    for thumb in [false, true] {
        let mut cpu = Armv7Cpu::new();
        cpu.cpsr.t = thumb;
        cpu.cp15.id_isar[5] = raw_isar5;
        cpu.cp15.id_isar6 = raw_isar6;
        cpu.cp15 = serde_json::from_slice(&serde_json::to_vec(&cpu.cp15).unwrap()).unwrap();

        for (op2, mrc, expected) in [(5, 0xee10_0fb2, 0x0100_0000), (7, 0xee10_0ff2, 0x101)] {
            assert_eq!(cpu.cp15.read(Cp15Encoding::new(0, 0, 2, op2)), Some(expected));
            assert!(matches!(execute(&mut cpu, &mut memory, mrc), ExecResult::Continue));
            assert_eq!(cpu.regs[0], expected);
        }
        assert_eq!(cpu.cp15.id_isar[5], raw_isar5);
        assert_eq!(cpu.cp15.id_isar6, raw_isar6);
    }
}

#[test]
fn mixed_id_reads_agree_without_masking_native_aarch64_features() {
    let mut config = AArch64Config::v8_2();
    config.initial_el = 3;
    config.gic_config = None;
    config.features |= ArmFeatures::FCMA
        | ArmFeatures::DOTPROD
        | ArmFeatures::BF16
        | ArmFeatures::I8MM
        | ArmFeatures::FHM
        | ArmFeatures::JSCVT;
    let mut cpu = AArch64Cpu::new(config, Box::new(MixedMemory::new(0, 0x4000)));
    let mut state = cpu.export_sregs();
    let sys = &mut state.execution.as_mut().unwrap().sysregs;
    sys.scr_el3 = 0;
    sys.hcr_el2 = 0;
    let isar5 = Aarch64SysRegEncoding::new(3, 0, 0, 2, 5);
    let isar6 = Aarch64SysRegEncoding::new(3, 0, 0, 2, 7);
    let raw_isar5 = 0xf000_0001;
    let raw_isar6 = 0x0ff0_00f0;
    sys.impl_defined.insert(isar5.encode(), raw_isar5);
    sys.impl_defined.insert(isar6.encode(), raw_isar6);
    cpu.import_sregs(&state).unwrap();

    let restored = cpu.export_sregs();
    let sys = &restored.execution.as_ref().unwrap().sysregs;
    assert_eq!(sys.impl_defined.get(&isar5.encode()), Some(&raw_isar5));
    assert_eq!(sys.impl_defined.get(&isar6.encode()), Some(&raw_isar6));
    assert_eq!((sys.id_aa64isar0_el1 >> 44) & 0xff, 0x11); // DP and FHM.
    assert_eq!((sys.id_aa64isar1_el1 >> 12) & 0xff, 0x11); // JSCVT and FCMA.
    assert_eq!((sys.id_aa64isar1_el1 >> 44) & 0xf, 1); // BF16.
    assert_eq!((sys.id_aa64isar1_el1 >> 52) & 0xf, 1); // I8MM.

    for (encoding, mrs, mrc, expected) in [
        (isar5, 0xd538_02a0u32, 0xee10_0fb2u32, 0x0100_0001),
        (isar6, 0xd538_02e0, 0xee10_0ff2, 0x101),
    ] {
        assert_eq!(sys.read(encoding, 3), Some(expected));
        cpu.set_pstate_bits(0x3cd).unwrap(); // AArch64 EL3h.
        cpu.set_pc(0x100);
        cpu.write_memory(0x100, &mrs.to_le_bytes()).unwrap();
        assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
        assert_eq!(cpu.get_gpr(0), expected);

        for thumb in [false, true] {
            cpu.set_pstate_bits(0x1d3 | if thumb { 32 } else { 0 }).unwrap();
            let bytes = if thumb { mrc.rotate_left(16) } else { mrc }.to_le_bytes();
            cpu.set_pc(0x100);
            cpu.write_memory(0x100, &bytes).unwrap();
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
            assert_eq!(cpu.get_gpr(0), expected);
        }
    }
}

#[test]
fn feature_register_reads_remain_privileged() {
    let mut memory = FlatMemory::new(4096, 0);
    for thumb in [false, true] {
        for raw in [0xeef5_0a10, 0xeef6_0a10, 0xeef7_0a10, 0xee10_0ff2] {
            let mut cpu = Armv7Cpu::new();
            cpu.cpsr.t = thumb;
            cpu.cpsr.mode = ProcessorMode::User as u8;
            cpu.regs[0] = 0x1234_5678;
            let regs = cpu.regs;
            let cpsr = cpu.cpsr.to_u32();
            assert!(matches!(
                execute(&mut cpu, &mut memory, raw),
                ExecResult::Undefined
            ));
            assert_eq!(cpu.regs, regs);
            assert_eq!(cpu.cpsr.to_u32(), cpsr);
        }
    }
}

#[path = "fp_admission.rs"]
mod fp_admission;

#[path = "fp_misc_admission.rs"]
mod fp_misc_admission;
