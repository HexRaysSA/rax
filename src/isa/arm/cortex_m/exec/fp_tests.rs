//! The Floating-point Extension subset of the Cortex-M7: access control
//! (CPACR, NOCP), loads, stores and transfers, VMOV, VMRS/VMSR, and the
//! frame with the FP state on exception entry and return. Expected
//! behaviour follows the Armv7-M ARM (DDI 0403E.e) A7.7 and B1.5 pseudocode.

use crate::isa::arm::common::cpu::{ArmCpu, CpuExit};
use crate::isa::arm::common::memory::{ArmMemory, FlatMemory};
use crate::isa::arm::cortex_m::cpu::CortexMCpu;
use crate::isa::arm::cortex_m::exec::Fault;
use crate::isa::arm::cortex_m::scb::CortexMVariant;

const CODE: u32 = 0x100;
const DATA: u32 = 0x4000;
const STACK: u32 = 0x8000;
/// CPACR with full access to CP10 and CP11.
const CPACR_FULL: u32 = 0x00F0_0000;

fn m7(code: &[u8], fpu: bool) -> CortexMCpu {
    let mut memory = FlatMemory::new(0, 0x1_0000);
    memory.write(u64::from(CODE), code).unwrap();
    let mut cpu = CortexMCpu::new(CortexMVariant::CortexM7, Box::new(memory));
    cpu.set_floating_point(fpu);
    cpu.ppb.cpacr = if fpu { CPACR_FULL } else { 0 };
    cpu.pc = CODE;
    cpu.sp_main = STACK;
    cpu
}

fn word(cpu: &CortexMCpu, address: u32) -> u32 {
    let mut b = [0u8; 4];
    cpu.memory.read(u64::from(address), &mut b).unwrap();
    u32::from_le_bytes(b)
}

fn set_word(cpu: &mut CortexMCpu, address: u32, value: u32) {
    cpu.memory
        .write(u64::from(address), &value.to_le_bytes())
        .unwrap();
}

// vldr d0, [pc, #8] (ED9F 0B02)
const VLDR_LITERAL: [u8; 4] = [0x9F, 0xED, 0x02, 0x0B];

#[test]
fn fp_instructions_need_the_fpu_and_cpacr() {
    let mut none = m7(&VLDR_LITERAL, false);
    assert!(matches!(none.execute_one(), Err(Fault::NoCoprocessor(_))));
    let mut denied = m7(&VLDR_LITERAL, true);
    denied.ppb.cpacr = 0;
    assert!(matches!(denied.execute_one(), Err(Fault::NoCoprocessor(_))));
    // privileged access only: Thread mode with CONTROL.nPRIV set is refused
    let mut unprivileged = m7(&VLDR_LITERAL, true);
    unprivileged.ppb.cpacr = 0x0050_0000;
    unprivileged.control = 1;
    assert!(matches!(
        unprivileged.execute_one(),
        Err(Fault::NoCoprocessor(_))
    ));
    unprivileged.control = 0;
    assert!(unprivileged.execute_one().is_ok());
}

#[test]
fn vldr_literal_reads_from_the_aligned_pc() {
    let mut cpu = m7(&VLDR_LITERAL, true);
    // Align(PC, 4) = CODE + 4, plus 8
    set_word(&mut cpu, CODE + 12, 0x5555_6666);
    set_word(&mut cpu, CODE + 16, 0x7777_8888);
    cpu.execute_one().unwrap();
    assert_eq!(cpu.d(0), 0x7777_8888_5555_6666);
    // the first FP instruction makes the FP context active
    assert_ne!(cpu.control & 4, 0);
}

#[test]
fn vpush_and_vpop_keep_the_low_word_first() {
    // vpush {d8} (ED2D 8B02) ; vpop {d8} (ECBD 8B02)
    let mut cpu = m7(&[0x2D, 0xED, 0x02, 0x8B, 0xBD, 0xEC, 0x02, 0x8B], true);
    cpu.set_d(8, 0x1122_3344_5566_7788);
    cpu.execute_one().unwrap();
    assert_eq!(cpu.sp_main, STACK - 8);
    assert_eq!(word(&cpu, STACK - 8), 0x5566_7788);
    assert_eq!(word(&cpu, STACK - 4), 0x1122_3344);
    cpu.set_d(8, 0);
    cpu.execute_one().unwrap();
    assert_eq!((cpu.d(8), cpu.sp_main), (0x1122_3344_5566_7788, STACK));
}

#[test]
fn vldm_and_vstm_write_back_and_fault_atomically() {
    // vldmia r0!, {s0-s3} (ECB0 0A04) ; vstmdb r1!, {d1-d2} (ED21 1B04)
    let mut cpu = m7(&[0xB0, 0xEC, 0x04, 0x0A, 0x21, 0xED, 0x04, 0x1B], true);
    for i in 0..4 {
        set_word(&mut cpu, DATA + 4 * i, 0xA0 + i);
    }
    cpu.set_r(0, DATA);
    cpu.set_r(1, DATA + 0x100);
    cpu.execute_one().unwrap();
    assert_eq!(
        (0..4).map(|i| cpu.s(i)).collect::<Vec<_>>(),
        [0xA0, 0xA1, 0xA2, 0xA3]
    );
    assert_eq!(cpu.r(0), DATA + 16);
    cpu.execute_one().unwrap();
    // d1 = s3:s2, d2 = s5:s4
    assert_eq!(cpu.r(1), DATA + 0x100 - 16);
    assert_eq!(word(&cpu, DATA + 0x100 - 16), 0xA2);
    assert_eq!(word(&cpu, DATA + 0x100 - 12), 0xA3);

    // the last word beyond memory: no register changes
    let mut cpu = m7(&[0xB0, 0xEC, 0x04, 0x0A], true);
    cpu.set_r(0, 0x1_0000 - 12);
    assert!(matches!(cpu.execute_one(), Err(Fault::Bus { .. })));
    assert_eq!((cpu.s(0), cpu.r(0)), (0, 0x1_0000 - 12));
}

#[test]
fn vmov_between_core_and_extension_registers() {
    // vmov d8, r0, r1 (EC41 0B18) ; vmov r8, fp, d8 (EC5B 8B18) ;
    // vmov s3, r2 (EE01 2A90) ; vmov r4, s3 (EE11 4A90) ;
    // vmov.32 d2[1], r5 (EE22 5B10) ; vmov.32 r6, d2[1] (EE32 6B10)
    let code = [
        0x41, 0xEC, 0x18, 0x0B, 0x5B, 0xEC, 0x18, 0x8B, 0x01, 0xEE, 0x90, 0x2A, 0x11, 0xEE, 0x90,
        0x4A, 0x22, 0xEE, 0x10, 0x5B, 0x32, 0xEE, 0x10, 0x6B,
    ];
    let mut cpu = m7(&code, true);
    cpu.set_r(0, 0x0000_1111);
    cpu.set_r(1, 0x2222_0000);
    cpu.set_r(2, 0x3F80_0000);
    cpu.set_r(5, 0xCAFE_F00D);
    for _ in 0..6 {
        cpu.execute_one().unwrap();
    }
    assert_eq!(cpu.d(8), 0x2222_0000_0000_1111);
    assert_eq!((cpu.r(8), cpu.r(11)), (0x0000_1111, 0x2222_0000));
    assert_eq!((cpu.s(3), cpu.r(4)), (0x3F80_0000, 0x3F80_0000));
    assert_eq!((cpu.d(2) >> 32, cpu.r(6)), (0xCAFE_F00D, 0xCAFE_F00D));
}

#[test]
fn vmov_register_and_immediate() {
    // vmov.f32 s0, s16 (EEB0 0A48) ; vmov.f32 s1, #1.0 (EEF7 0A00) ;
    // vmov.f64 d1, #-2.0 (EEB8 1B00)
    let code = [
        0xB0, 0xEE, 0x48, 0x0A, 0xF7, 0xEE, 0x00, 0x0A, 0xB8, 0xEE, 0x00, 0x1B,
    ];
    let mut cpu = m7(&code, true);
    cpu.set_s(16, 0x4049_0FDB);
    for _ in 0..3 {
        cpu.execute_one().unwrap();
    }
    assert_eq!(cpu.s(0), 0x4049_0FDB);
    assert_eq!(cpu.s(1), 1.0f32.to_bits());
    assert_eq!(cpu.d(1), (-2.0f64).to_bits());
}

#[test]
fn vmsr_masks_fpscr_and_vmrs_sets_the_flags() {
    // vmsr fpscr, r0 (EEE1 0A10) ; vmrs r1, fpscr (EEF1 1A10) ;
    // vmrs APSR_nzcv, fpscr (EEF1 FA10)
    let code = [
        0xE1, 0xEE, 0x10, 0x0A, 0xF1, 0xEE, 0x10, 0x1A, 0xF1, 0xEE, 0x10, 0xFA,
    ];
    let mut cpu = m7(&code, true);
    cpu.set_r(0, u32::MAX);
    for _ in 0..3 {
        cpu.execute_one().unwrap();
    }
    assert_eq!(cpu.r(1), 0xF7C0_009F);
    assert_eq!(cpu.xpsr >> 28, 0xF);
}

#[test]
fn unimplemented_fp_data_processing_is_undefined() {
    // vadd.f32 s0, s1, s2 (EE30 0A81)
    let mut cpu = m7(&[0x30, 0xEE, 0x81, 0x0A], true);
    assert!(matches!(cpu.execute_one(), Err(Fault::Undefined(_))));
}

#[test]
fn exceptions_stack_and_restore_the_fp_state() {
    // Thread: vmov.f32 s0, s16 (sets CONTROL.FPCA). Handler of IRQ 0 at
    // 0x200: vmov.f32 s0, #1.0 (EEB7 0A00) ; bx lr (4770).
    let mut cpu = m7(&[0xB0, 0xEE, 0x48, 0x0A, 0x00, 0xBF], true);
    cpu.memory
        .write(0x200, &[0xB7, 0xEE, 0x00, 0x0A, 0x70, 0x47])
        .unwrap();
    set_word(&mut cpu, 4 * 16, 0x201);
    cpu.set_s(16, 0x1234_5678);
    cpu.execute_one().unwrap();

    cpu.nvic_mut().enable(0);
    cpu.nvic_mut().set_pending(0);
    assert!(matches!(cpu.step(), Ok(CpuExit::ExceptionTaken(_))));
    let frame = STACK - 0x68;
    assert_eq!(cpu.sp_main, frame);
    assert_eq!(cpu.lr, 0xFFFF_FFE9);
    assert_eq!(word(&cpu, frame + 0x20), 0x1234_5678);
    assert_eq!(cpu.control & 4, 0);

    cpu.step().unwrap();
    assert_eq!(cpu.s(0), 1.0f32.to_bits());
    cpu.step().unwrap();
    assert_eq!(cpu.s(0), 0x1234_5678);
    assert_eq!(cpu.sp_main, STACK);
    assert_ne!(cpu.control & 4, 0);
    assert_eq!(cpu.pc, CODE + 4);
}
