//! NEON shifts: by an immediate (shifting right, accumulating, inserting,
//! saturating left), narrowing, and by a register (VSHL, VRSHL, VQSHL,
//! VQRSHL), against the Arm ARM's A32 pseudocode (`aarch32_VSHL_r_A`,
//! `aarch32_VRSHL_A`, `aarch32_VQSHL_r_A`, `aarch32_VQRSHL_A`, and the
//! immediate forms).

use super::exec_one;
use rax::isa::arm::decoder::{Aarch32Decoder, DecodedInsn, Mnemonic};
use rax::isa::arm::execution::FlatMemory;
use rax::isa::arm::{Armv7Cpu, ExecResult, ExecutionState, Executor};

#[test]
fn neon_shift_right_immediate_handles_signed_unsigned_rounding_and_q_forms() {
    let mut cpu = Armv7Cpu::new();
    let mut mem = FlatMemory::new(0x1000, 0);

    assert_eq!(
        Aarch32Decoder::decode(0xF38D_4015).unwrap().mnemonic,
        Mnemonic::VSHR
    );
    assert_eq!(
        Aarch32Decoder::decode(0xF29C_6017).unwrap().mnemonic,
        Mnemonic::VSHR
    );
    assert_eq!(
        Aarch32Decoder::decode(0xF38D_8219).unwrap().mnemonic,
        Mnemonic::VRSHR
    );
    assert_eq!(
        Aarch32Decoder::decode(0xF3AF_4058).unwrap().mnemonic,
        Mnemonic::VSHR
    );
    assert_eq!(
        Aarch32Decoder::decode(0xF3AF_5058).unwrap().mnemonic,
        Mnemonic::UNDEFINED
    );

    cpu.vfp.write_d_bits(5, 0x0003_0407_087f_80ff);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF38D_4015),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(4), 0x0000_0000_010f_101f);

    cpu.vfp.write_d_bits(7, 0x0010_7fff_ffff_8000);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF29C_6017),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(6), 0x0001_07ff_ffff_f800);

    cpu.vfp.write_d_bits(9, 0x0003_0407_087f_80ff);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF38D_8219),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(8), 0x0000_0101_0110_1020);

    cpu.vfp.write_d_bits(11, 0x0017_7fff_ffff_8000);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF29C_A21B),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(10), 0x0001_0800_0000_f800);

    cpu.vfp.write_d_bits(8, 0x8000_0000_ffff_ffff);
    cpu.vfp.write_d_bits(9, 0x0001_ffff_0002_0000);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF3AF_4058),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(4), 0x0000_4000_0000_7fff);
    assert_eq!(cpu.vfp.read_d_bits(5), 0x0000_0000_0000_0001);

    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF3AF_5058),
        ExecResult::Undefined
    ));
    let invalid_imm = DecodedInsn::new(Mnemonic::VSHR, ExecutionState::Aarch32, 0xF307_4015, 4);
    assert!(matches!(
        Executor::new(&mut cpu, &mut mem).execute(&invalid_imm),
        ExecResult::Undefined
    ));
}

#[test]
fn neon_shift_accumulate_immediate_adds_shifted_lanes_to_destination() {
    let mut cpu = Armv7Cpu::new();
    let mut mem = FlatMemory::new(0x1000, 0);

    assert_eq!(
        Aarch32Decoder::decode(0xF28F_0111).unwrap().mnemonic,
        Mnemonic::VSRA
    );
    assert_eq!(
        Aarch32Decoder::decode(0xF39C_0152).unwrap().mnemonic,
        Mnemonic::VSRA
    );
    assert_eq!(
        Aarch32Decoder::decode(0xF2B8_2313).unwrap().mnemonic,
        Mnemonic::VRSRA
    );
    assert_eq!(
        Aarch32Decoder::decode(0xF38D_4358).unwrap().mnemonic,
        Mnemonic::VRSRA
    );

    cpu.vfp.write_d_bits(0, 0x0a00_80ff_0403_0201);
    cpu.vfp.write_d_bits(1, 0x8104_fe01_7f80_ff02);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF28F_0111),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(0), 0xca02_7fff_43c3_0102);

    cpu.vfp.write_d_bits(0, 0xffff_ff00_0002_0001);
    cpu.vfp.write_d_bits(1, 0xff00_000f_1000_0000);
    cpu.vfp.write_d_bits(2, 0x0001_8000_ffff_0010);
    cpu.vfp.write_d_bits(3, 0x00f0_fff0_000f_1000);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF39C_0152),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(0), 0xffff_0700_1001_0002);
    assert_eq!(cpu.vfp.read_d_bits(1), 0xff0f_100e_1000_0100);

    cpu.vfp.write_d_bits(2, 0x8000_0000_0000_0001);
    cpu.vfp.write_d_bits(3, 0xffff_ff00_0000_0180);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF2B8_2313),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(2), 0x7fff_ffff_0000_0003);

    cpu.vfp.write_d_bits(4, 0x0706_0504_0302_0100);
    cpu.vfp.write_d_bits(5, 0x6050_4030_2010_00ff);
    cpu.vfp.write_d_bits(8, 0x80ff_0807_0403_0100);
    cpu.vfp.write_d_bits(9, 0x0120_407f_fe12_1110);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF38D_4358),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(4), 0x1726_0605_0402_0100);
    assert_eq!(cpu.vfp.read_d_bits(5), 0x6054_4840_4012_0201);

    assert_eq!(
        Aarch32Decoder::decode(0xF39C_1152).unwrap().mnemonic,
        Mnemonic::UNDEFINED
    );
    let invalid_imm = DecodedInsn::new(Mnemonic::VSRA, ExecutionState::Aarch32, 0xF307_0111, 4);
    assert!(matches!(
        Executor::new(&mut cpu, &mut mem).execute(&invalid_imm),
        ExecResult::Undefined
    ));
}

#[test]
fn neon_saturating_shift_left_immediate_saturates_and_sets_qc() {
    let mut cpu = Armv7Cpu::new();
    let mut mem = FlatMemory::new(0x1000, 0);

    assert_eq!(
        Aarch32Decoder::decode(0xF289_0711).unwrap().mnemonic,
        Mnemonic::VQSHL
    );
    assert_eq!(
        Aarch32Decoder::decode(0xF394_0752).unwrap().mnemonic,
        Mnemonic::VQSHL
    );
    assert_eq!(
        Aarch32Decoder::decode(0xF2A8_2713).unwrap().mnemonic,
        Mnemonic::VQSHL
    );
    assert_eq!(
        Aarch32Decoder::decode(0xF38A_4615).unwrap().mnemonic,
        Mnemonic::VQSHLU
    );
    assert_eq!(
        Aarch32Decoder::decode(0xF393_865A).unwrap().mnemonic,
        Mnemonic::VQSHLU
    );

    cpu.vfp.fpscr.set_qc(false);
    cpu.vfp.write_d_bits(1, 0x8120_ffc0_807f_4001);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF289_0711),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(0), 0x8040_fe80_807f_7f02);
    assert!(cpu.vfp.fpscr.qc());

    cpu.vfp.fpscr.set_qc(false);
    cpu.vfp.write_d_bits(2, 0x8000_ffff_1000_0001);
    cpu.vfp.write_d_bits(3, 0xf000_0fff_0100_000f);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF394_0752),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(0), 0xffff_ffff_ffff_0010);
    assert_eq!(cpu.vfp.read_d_bits(1), 0xffff_fff0_1000_00f0);
    assert!(cpu.vfp.fpscr.qc());

    cpu.vfp.fpscr.set_qc(false);
    cpu.vfp.write_d_bits(3, 0x0080_0000_0000_0001);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF2A8_2713),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(2), 0x7fff_ffff_0000_0100);
    assert!(cpu.vfp.fpscr.qc());

    cpu.vfp.fpscr.set_qc(false);
    cpu.vfp.write_d_bits(5, 0x1000_80ff_7f40_2001);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF38A_4615),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(4), 0x4000_0000_ffff_8004);
    assert!(cpu.vfp.fpscr.qc());

    cpu.vfp.fpscr.set_qc(false);
    cpu.vfp.write_d_bits(10, 0x8000_7fff_1000_0001);
    cpu.vfp.write_d_bits(11, 0x4000_2000_0002_ffff);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF393_865A),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(8), 0x0000_ffff_8000_0008);
    assert_eq!(cpu.vfp.read_d_bits(9), 0xffff_ffff_0010_0000);
    assert!(cpu.vfp.fpscr.qc());

    assert_eq!(
        Aarch32Decoder::decode(0xF394_1752).unwrap().mnemonic,
        Mnemonic::UNDEFINED
    );
    let invalid_imm = DecodedInsn::new(Mnemonic::VQSHL, ExecutionState::Aarch32, 0xF207_0711, 4);
    assert!(matches!(
        Executor::new(&mut cpu, &mut mem).execute(&invalid_imm),
        ExecResult::Undefined
    ));
}

#[test]
fn neon_shift_left_and_insert_immediate_update_expected_bits() {
    let mut cpu = Armv7Cpu::new();
    let mut mem = FlatMemory::new(0x1000, 0);

    assert_eq!(
        Aarch32Decoder::decode(0xF289_0511).unwrap().mnemonic,
        Mnemonic::VSHL
    );
    assert_eq!(
        Aarch32Decoder::decode(0xF38A_C51D).unwrap().mnemonic,
        Mnemonic::VSLI
    );
    assert_eq!(
        Aarch32Decoder::decode(0xF39B_E41F).unwrap().mnemonic,
        Mnemonic::VSRI
    );
    assert_eq!(
        Aarch32Decoder::decode(0xF2AC_1552).unwrap().mnemonic,
        Mnemonic::UNDEFINED
    );

    cpu.vfp.write_d_bits(1, 0x11aa_55ff_807f_0201);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF289_0511),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(0), 0x2254_aafe_00fe_0402);

    cpu.vfp.write_d_bits(3, 0xffff_8000_1234_0001);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF295_2513),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(2), 0xffe0_0000_4680_0020);

    cpu.vfp.write_d_bits(2, 0x000f_ffff_0000_0001);
    cpu.vfp.write_d_bits(3, 0xffff_ffff_8000_0000);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF2AC_0552),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(0), 0xffff_f000_0000_1000);
    assert_eq!(cpu.vfp.read_d_bits(1), 0xffff_f000_0000_0000);

    cpu.vfp.write_d_bits(12, 0xcc33_f00f_5aa5_00ff);
    cpu.vfp.write_d_bits(13, 0x11aa_55ff_807f_0201);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF38A_C51D),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(12), 0x44ab_54ff_02fd_0807);

    cpu.vfp.write_d_bits(14, 0x5555_aaaa_0000_ffff);
    cpu.vfp.write_d_bits(15, 0x8000_0001_ffff_1234);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF39B_E41F),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(14), 0x5400_a800_07ff_f891);

    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF2AC_1552),
        ExecResult::Undefined
    ));
    let invalid_zero_shift =
        DecodedInsn::new(Mnemonic::VSHL, ExecutionState::Aarch32, 0xF288_0511, 4);
    assert!(matches!(
        Executor::new(&mut cpu, &mut mem).execute(&invalid_zero_shift),
        ExecResult::Undefined
    ));
}

#[test]
fn neon_shift_narrow_immediate_keeps_shifted_low_half() {
    let mut cpu = Armv7Cpu::new();
    let mut mem = FlatMemory::new(0x1000, 0);

    assert_eq!(
        Aarch32Decoder::decode(0xF28D_0812).unwrap().mnemonic,
        Mnemonic::VSHRN
    );
    assert_eq!(
        Aarch32Decoder::decode(0xF28D_7878).unwrap().mnemonic,
        Mnemonic::VRSHRN
    );

    cpu.vfp.write_d_bits(2, 0x7fff_8000_ff00_00ff);
    cpu.vfp.write_d_bits(3, 0x00f0_0100_ffff_1234);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF28D_0812),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(0), 0x1e20_ff46_ff00_e01f);

    cpu.vfp.write_d_bits(8, 0xffff_0000_0000_ffff);
    cpu.vfp.write_d_bits(9, 0x7fff_ffff_8000_0000);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF294_3818),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(3), 0xffff_0000_fff0_000f);

    cpu.vfp.write_d_bits(16, 0x0000_0001_0000_0000);
    cpu.vfp.write_d_bits(17, 0xffff_ffff_ffff_ffff);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF2A0_6830),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(6), 0xffff_ffff_0000_0001);

    cpu.vfp.write_d_bits(24, 0x0008_0007_0004_0003);
    cpu.vfp.write_d_bits(25, 0x7fff_8000_ff00_00ff);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF28D_7878),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(7), 0x0000_e020_0101_0100);

    let invalid_odd_source =
        DecodedInsn::new(Mnemonic::VSHRN, ExecutionState::Aarch32, 0xF28D_0813, 4);
    assert!(matches!(
        Executor::new(&mut cpu, &mut mem).execute(&invalid_odd_source),
        ExecResult::Undefined
    ));
    let invalid_imm = DecodedInsn::new(Mnemonic::VSHRN, ExecutionState::Aarch32, 0xF207_0812, 4);
    assert!(matches!(
        Executor::new(&mut cpu, &mut mem).execute(&invalid_imm),
        ExecResult::Undefined
    ));
}

#[test]
fn neon_saturating_shift_narrow_immediate_saturates_and_sets_qc() {
    let mut cpu = Armv7Cpu::new();
    let mut mem = FlatMemory::new(0x1000, 0);

    assert_eq!(
        Aarch32Decoder::decode(0xF28C_8932).unwrap().mnemonic,
        Mnemonic::VQSHRN
    );
    assert_eq!(
        Aarch32Decoder::decode(0xF38C_9934).unwrap().mnemonic,
        Mnemonic::VQSHRN
    );
    assert_eq!(
        Aarch32Decoder::decode(0xF28B_C97A).unwrap().mnemonic,
        Mnemonic::VQRSHRN
    );
    assert_eq!(
        Aarch32Decoder::decode(0xF38C_1814).unwrap().mnemonic,
        Mnemonic::VQSHRUN
    );
    assert_eq!(
        Aarch32Decoder::decode(0xF393_4870).unwrap().mnemonic,
        Mnemonic::VQRSHRUN
    );

    cpu.vfp.fpscr.set_qc(false);
    cpu.vfp.write_d_bits(18, 0x8000_f800_0800_07f0);
    cpu.vfp.write_d_bits(19, 0x0010_000f_ffff_7fff);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF28C_8932),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(8), 0x0100_ff7f_8080_7f7f);
    assert!(cpu.vfp.fpscr.qc());

    cpu.vfp.fpscr.set_qc(false);
    cpu.vfp.write_d_bits(20, 0x000f_ffff_1000_0ff0);
    cpu.vfp.write_d_bits(21, 0x0100_00f0_8000_0010);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF38C_9934),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(9), 0x100f_ff01_00ff_ffff);
    assert!(cpu.vfp.fpscr.qc());

    cpu.vfp.fpscr.set_qc(false);
    cpu.vfp.write_d_bits(26, 0xf800_f801_07f0_07ef);
    cpu.vfp.write_d_bits(27, 0x0010_000f_8000_7fff);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF28B_C97A),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(12), 0x0100_807f_c0c0_403f);
    assert!(cpu.vfp.fpscr.qc());

    cpu.vfp.fpscr.set_qc(false);
    cpu.vfp.write_d_bits(4, 0xf800_ffff_0800_07f0);
    cpu.vfp.write_d_bits(5, 0x8000_7fff_0010_000f);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF38C_1814),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(1), 0x00ff_0100_0000_807f);
    assert!(cpu.vfp.fpscr.qc());

    cpu.vfp.fpscr.set_qc(false);
    cpu.vfp.write_d_bits(16, 0x0010_0000_000f_fff0);
    cpu.vfp.write_d_bits(17, 0);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF393_4870),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(4), 0x0000_0000_0080_0080);
    assert!(!cpu.vfp.fpscr.qc());

    let invalid_odd_source =
        DecodedInsn::new(Mnemonic::VQSHRN, ExecutionState::Aarch32, 0xF28C_8933, 4);
    assert!(matches!(
        Executor::new(&mut cpu, &mut mem).execute(&invalid_odd_source),
        ExecResult::Undefined
    ));
}

#[test]
fn neon_shift_register_handles_signed_counts_rounding_and_q_forms() {
    let mut cpu = Armv7Cpu::new();
    let mut mem = FlatMemory::new(0x1000, 0);

    assert_eq!(
        Aarch32Decoder::decode(0xF202_0401).unwrap().mnemonic,
        Mnemonic::VSHL
    );
    assert_eq!(
        Aarch32Decoder::decode(0xF20A_6508).unwrap().mnemonic,
        Mnemonic::VRSHL
    );
    assert_eq!(
        Aarch32Decoder::decode(0xF31C_4548).unwrap().mnemonic,
        Mnemonic::VRSHL
    );
    assert_eq!(
        Aarch32Decoder::decode(0xF224_1452).unwrap().mnemonic,
        Mnemonic::UNDEFINED
    );

    cpu.vfp.write_d_bits(1, 0x7f80_0302_ff7f_8001);
    cpu.vfp.write_d_bits(2, 0x80f8_0807_fe02_ff01);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF202_0401),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(0), 0x00ff_0000_fffc_c002);

    cpu.vfp.write_d_bits(4, 0xffff_00ff_8000_0001);
    cpu.vfp.write_d_bits(5, 0xfffc_0004_ffff_0001);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF315_3404),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(3), 0x0fff_0ff0_4000_0002);

    cpu.vfp.write_d_bits(8, 0x0302_80ff_8007_0707);
    cpu.vfp.write_d_bits(10, 0x0807_80f8_01fd_feff);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF20A_6508),
        ExecResult::Continue
    ));
    // A rounded right shift past the element is 0, a negative value's too:
    // (-128 + 2^127) >> 128.
    assert_eq!(cpu.vfp.read_d_bits(6), 0x0000_0000_0001_0204);

    cpu.vfp.write_d_bits(8, 0x0001_8000_0007_0007);
    cpu.vfp.write_d_bits(9, 0x8000_1234_4000_ffff);
    cpu.vfp.write_d_bits(12, 0x0010_0001_fffe_ffff);
    cpu.vfp.write_d_bits(13, 0xfffd_0000_0002_fff0);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF31C_4548),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(4), 0x0000_0000_0002_0004);
    assert_eq!(cpu.vfp.read_d_bits(5), 0x1000_1234_0000_0001);

    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF224_1452),
        ExecResult::Undefined
    ));
}

#[test]
fn neon_saturating_shift_register_saturates_left_shifts_and_sets_qc() {
    let mut cpu = Armv7Cpu::new();
    let mut mem = FlatMemory::new(0x1000, 0);

    assert_eq!(
        Aarch32Decoder::decode(0xF202_0411).unwrap().mnemonic,
        Mnemonic::VQSHL
    );
    assert_eq!(
        Aarch32Decoder::decode(0xF302_0411).unwrap().mnemonic,
        Mnemonic::VQSHL
    );
    assert_eq!(
        Aarch32Decoder::decode(0xF20A_6518).unwrap().mnemonic,
        Mnemonic::VQRSHL
    );
    assert_eq!(
        Aarch32Decoder::decode(0xF31C_4558).unwrap().mnemonic,
        Mnemonic::VQRSHL
    );

    cpu.vfp.fpscr.set_qc(false);
    cpu.vfp.write_d_bits(1, 0);
    cpu.vfp.write_d_bits(2, 0x0808_0808_0808_0808);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF202_0411),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(0), 0);
    assert!(!cpu.vfp.fpscr.qc());

    cpu.vfp.fpscr.set_qc(false);
    cpu.vfp.write_d_bits(1, 0);
    cpu.vfp.write_d_bits(2, 0x0808_0808_0808_0808);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF302_0411),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(0), 0);
    assert!(!cpu.vfp.fpscr.qc());

    cpu.vfp.fpscr.set_qc(false);
    cpu.vfp.write_d_bits(1, 0x7f80_7f80_0102_4040);
    cpu.vfp.write_d_bits(2, 0x0080_feff_0807_0201);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF202_0411),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(0), 0x7fff_1fc0_7f7f_7f7f);
    assert!(cpu.vfp.fpscr.qc());

    cpu.vfp.fpscr.set_qc(false);
    cpu.vfp.write_d_bits(4, 0x0001_0002_1000_8000);
    cpu.vfp.write_d_bits(5, 0x0010_000f_0004_0001);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF315_3414),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(3), 0xffff_ffff_ffff_ffff);
    assert!(cpu.vfp.fpscr.qc());

    cpu.vfp.fpscr.set_qc(false);
    cpu.vfp.write_d_bits(8, 0x7f80_8001_0240_0707);
    cpu.vfp.write_d_bits(10, 0x00fd_8008_0701_feff);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF20A_6518),
        ExecResult::Continue
    ));
    // As for VRSHL, -128 rounded right by 128 is 0.
    assert_eq!(cpu.vfp.read_d_bits(6), 0x7ff0_007f_7f7f_0204);
    assert!(cpu.vfp.fpscr.qc());

    cpu.vfp.fpscr.set_qc(false);
    cpu.vfp.write_d_bits(8, 0x0001_8000_0007_0007);
    cpu.vfp.write_d_bits(9, 0x8000_1234_4000_ffff);
    cpu.vfp.write_d_bits(12, 0x0010_0001_fffe_ffff);
    cpu.vfp.write_d_bits(13, 0xfffd_0000_0002_fff0);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, 0xF31C_4558),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.read_d_bits(4), 0xffff_ffff_0002_0004);
    assert_eq!(cpu.vfp.read_d_bits(5), 0x1000_1234_ffff_0001);
    assert!(cpu.vfp.fpscr.qc());
}

/// An A32 shift by a register: VSHL (`op` 0b0100) or VRSHL (0b0101),
/// saturating (VQSHL, VQRSHL) when `sat`, of `size` (0b11: 64-bit lanes);
/// the values in `m`, the counts in `n` (D0-D15 only).
#[allow(clippy::too_many_arguments)]
fn shift_reg(u: u32, size: u32, op: u32, sat: u32, q: u32, d: u32, m: u32, n: u32) -> u32 {
    0xF200_0000 | u << 24 | size << 20 | n << 16 | d << 12 | op << 8 | q << 6 | sat << 4 | m
}

/// Runs `raw` on D1 (values) and D2 (counts): D0 and FPSCR.QC.
fn run_d(cpu: &mut Armv7Cpu, raw: u32, value: u64, count: u64) -> (u64, bool) {
    let mut mem = FlatMemory::new(0x1000, 0);
    cpu.vfp.fpscr.set_qc(false);
    cpu.vfp.write_d_bits(1, value);
    cpu.vfp.write_d_bits(2, count);
    assert!(matches!(exec_one(cpu, &mut mem, raw), ExecResult::Continue));
    (cpu.vfp.read_d_bits(0), cpu.vfp.fpscr.qc())
}

#[test]
fn register_shifts_take_64_bit_lanes() {
    // size 0b11 is esize 64 for all four (the pseudocode has no
    // UNDEFINED for it); a count is the signed low byte of its element;
    // the arithmetic is on integers, then truncated or saturated. The
    // expected values follow aarch32_VSHL_r_A, aarch32_VRSHL_A,
    // aarch32_VQSHL_r_A, and aarch32_VQRSHL_A.
    for (op, sat, mnemonic) in [
        (0b0100, 0, Mnemonic::VSHL),
        (0b0101, 0, Mnemonic::VRSHL),
        (0b0100, 1, Mnemonic::VQSHL),
        (0b0101, 1, Mnemonic::VQRSHL),
    ] {
        let raw = shift_reg(0, 0b11, op, sat, 0, 0, 1, 2);
        assert_eq!(Aarch32Decoder::decode(raw).unwrap().mnemonic, mnemonic);
        let odd = shift_reg(0, 0b11, op, sat, 1, 1, 2, 4);
        assert_eq!(
            Aarch32Decoder::decode(odd).unwrap().mnemonic,
            Mnemonic::UNDEFINED
        );
    }
    let mut cpu = Armv7Cpu::new();
    let (vshl, vrshl) = (0b0100, 0b0101);
    let s64 = |op, sat| shift_reg(0, 0b11, op, sat, 0, 0, 1, 2);
    let u64_ = |op, sat| shift_reg(1, 0b11, op, sat, 0, 0, 1, 2);
    let max = u64::MAX;
    // VSHL: wrapping left, flooring right (-128 is past the element).
    assert_eq!(
        run_d(&mut cpu, s64(vshl, 0), 0x8000_0000_0000_0001, 1),
        (2, false)
    );
    assert_eq!(
        run_d(
            &mut cpu,
            u64_(vshl, 0),
            0x4000_0000_0000_0000,
            0xAAAA_AAAA_AAAA_AA01
        ),
        (0x8000_0000_0000_0000, false)
    );
    assert_eq!(
        run_d(&mut cpu, s64(vshl, 0), max - 2, 0xFF),
        (max - 1, false)
    );
    assert_eq!(run_d(&mut cpu, u64_(vshl, 0), 1 << 63, 0x81), (0, false));
    assert_eq!(run_d(&mut cpu, s64(vshl, 0), max - 2, 0x80), (max, false));
    // VRSHL: (value + 2^(count-1)) >> count, without overflowing.
    assert_eq!(run_d(&mut cpu, s64(vrshl, 0), max - 2, 0xFF), (max, false));
    assert_eq!(run_d(&mut cpu, s64(vrshl, 0), max, 0x80), (0, false));
    assert_eq!(run_d(&mut cpu, u64_(vrshl, 0), max, 0xFF), (1 << 63, false));
    // VQSHL: saturating, setting QC.
    assert_eq!(
        run_d(&mut cpu, s64(vshl, 1), 1 << 62, 1),
        (0x7FFF_FFFF_FFFF_FFFF, true)
    );
    assert_eq!(run_d(&mut cpu, s64(vshl, 1), max, 63), (1 << 63, false));
    assert_eq!(
        run_d(&mut cpu, s64(vshl, 1), 1, 64),
        (0x7FFF_FFFF_FFFF_FFFF, true)
    );
    assert_eq!(run_d(&mut cpu, s64(vshl, 1), 0, 127), (0, false));
    assert_eq!(run_d(&mut cpu, u64_(vshl, 1), max, 1), (max, true));
    // VQRSHL.
    assert_eq!(
        run_d(&mut cpu, s64(vrshl, 1), 0x7FFF_FFFF_FFFF_FFFF, 0xFF),
        (1 << 62, false)
    );
    assert_eq!(run_d(&mut cpu, u64_(vrshl, 1), max, 0xFF), (1 << 63, false));
    // The Q form: two lanes.
    let mut mem = FlatMemory::new(0x1000, 0);
    cpu.vfp.write_d_bits(2, 1);
    cpu.vfp.write_d_bits(3, 0x10);
    cpu.vfp.write_d_bits(4, 4);
    cpu.vfp.write_d_bits(5, 0xFC);
    let q = shift_reg(1, 0b11, vshl, 0, 1, 0, 2, 4);
    assert!(matches!(
        exec_one(&mut cpu, &mut mem, q),
        ExecResult::Continue
    ));
    assert_eq!((cpu.vfp.read_d_bits(0), cpu.vfp.read_d_bits(1)), (0x10, 1));
}

#[test]
fn register_shift_counts_are_the_low_byte_of_each_element() {
    // Elem[D[n+r],e,esize]<7:0>: the bits above a count's low byte do not
    // count; and a rounded right shift past the element rounds a negative
    // value to zero.
    let mut cpu = Armv7Cpu::new();
    let vshl_u16 = shift_reg(1, 0b01, 0b0100, 0, 0, 0, 1, 2);
    assert_eq!(
        run_d(
            &mut cpu,
            vshl_u16,
            0x0001_0002_0003_8000,
            0xFF00_7F02_01FF_0100
        ),
        (0x0001_0008_0001_8000, false)
    );
    let vshl_s32 = shift_reg(0, 0b10, 0b0100, 0, 0, 0, 1, 2);
    assert_eq!(
        run_d(
            &mut cpu,
            vshl_s32,
            0xFFFF_FFF0_0000_0100,
            0x1234_5602_0000_01FF
        ),
        (0xFFFF_FFC0_0000_0080, false)
    );
    let vrshl_s8 = shift_reg(0, 0b00, 0b0101, 0, 0, 0, 1, 2);
    assert_eq!(run_d(&mut cpu, vrshl_s8, 0xFF, 0xF7), (0, false));
    let vrshl_u8 = shift_reg(1, 0b00, 0b0101, 0, 0, 0, 1, 2);
    assert_eq!(run_d(&mut cpu, vrshl_u8, 0xFF, 0xF8), (1, false));
    let vqrshl_s16 = shift_reg(0, 0b01, 0b0101, 1, 0, 0, 1, 2);
    assert_eq!(run_d(&mut cpu, vqrshl_s16, 0x7FFF, 0x80F1), (1, false));
}
