//! Execution rules the QEMU oracle does not exercise: the Armv6-M subset,
//! the IT-block restrictions, privilege, and the event register. Expected
//! behaviour follows the Armv7-M ARM (DDI 0403E.e) A5/A7/B5 pseudocode.

use super::*;
use crate::isa::arm::common::memory::{ArmMemory, FlatMemory};
use crate::isa::arm::cortex_m::scb::CortexMVariant;

const CODE: u32 = 0x100;

fn cpu(variant: CortexMVariant, code: &[u8]) -> CortexMCpu {
    let mut memory = FlatMemory::new(0, 0x1_0000);
    memory.write(u64::from(CODE), code).unwrap();
    let mut cpu = CortexMCpu::new(variant, Box::new(memory));
    cpu.pc = CODE;
    cpu.sp_main = 0x8000;
    cpu
}

fn m4(code: &[u8]) -> CortexMCpu {
    cpu(CortexMVariant::CortexM4, code)
}

#[test]
fn armv6m_executes_only_its_thumb_subset() {
    // cbz r0,#4 ; it eq ; add.w r0,r0,#1 ; bl #0 (hw1 0xF000, hw2 0xF800)
    let cases: [&[u8]; 3] = [&[0x10, 0xB1], &[0x08, 0xBF], &[0x00, 0xF1, 0x01, 0x00]];
    for code in cases {
        let mut m0 = cpu(CortexMVariant::CortexM0, code);
        assert!(
            matches!(m0.execute_one(), Err(Fault::Undefined(_))),
            "{code:x?}"
        );
        let mut m3 = cpu(CortexMVariant::CortexM3, code);
        assert!(m3.execute_one().is_ok(), "{code:x?}");
    }
    let mut m0 = cpu(CortexMVariant::CortexM0, &[0x00, 0xF0, 0x00, 0xF8]);
    m0.execute_one().unwrap();
    assert_eq!((m0.pc, m0.lr), (CODE + 4, (CODE + 4) | 1));
}

#[test]
fn dsp_instructions_need_armv7e_m() {
    // qadd r3,r1,r2 ; uadd8 r3,r1,r2
    for code in [[0x82, 0xFA, 0x81, 0xF3], [0x81, 0xFA, 0x42, 0xF3]] {
        let mut m3 = cpu(CortexMVariant::CortexM3, &code);
        assert!(matches!(m3.execute_one(), Err(Fault::Undefined(_))));
        assert!(m4(&code).execute_one().is_ok());
    }
}

#[test]
fn it_blocks_reject_unpredictable_members() {
    // itt eq, then: cpsid i / beq #0 (16-bit) / mov pc,r1 (not last).
    for member in [[0x72, 0xB6], [0x00, 0xD0], [0x8F, 0x46]] {
        let mut cpu = m4(&[0x04, 0xBF, member[0], member[1], 0x00, 0xBF]);
        cpu.set_z(true);
        cpu.execute_one().unwrap();
        assert!(cpu.in_it_block());
        let before = (cpu.pc, cpu.it_state());
        assert!(
            matches!(cpu.execute_one(), Err(Fault::Undefined(_))),
            "{member:x?}"
        );
        assert_eq!(
            (cpu.pc, cpu.it_state()),
            before,
            "the fault changes nothing"
        );
    }
    // As the last member MOV PC is permitted.
    let mut cpu = m4(&[0x08, 0xBF, 0x8F, 0x46]); // it eq ; moveq pc,r1
    cpu.set_z(true);
    cpu.regs[1] = 0x201;
    cpu.execute_one().unwrap();
    cpu.execute_one().unwrap();
    assert_eq!((cpu.pc, cpu.it_state()), (0x200, 0));
}

#[test]
fn unprivileged_code_cannot_change_masks_or_read_stack_pointers() {
    // msr primask,r0 ; cpsid i ; mrs r2,msp
    let mut cpu = m4(&[0x80, 0xF3, 0x10, 0x88, 0x72, 0xB6, 0xEF, 0xF3, 0x08, 0x82]);
    cpu.control = 1; // nPRIV
    cpu.regs[0] = 1;
    cpu.regs[2] = 7;
    for _ in 0..3 {
        cpu.execute_one().unwrap();
    }
    assert!(!cpu.primask);
    assert_eq!(cpu.regs[2], 0);
}

#[test]
fn handler_mode_cannot_select_the_process_stack() {
    // msr control,r0 with SPSEL and nPRIV set.
    let mut cpu = m4(&[0x80, 0xF3, 0x14, 0x88]);
    cpu.thread_mode = false;
    cpu.current_exception = 11;
    cpu.xpsr |= 11;
    cpu.regs[0] = 0b11;
    cpu.execute_one().unwrap();
    assert_eq!(cpu.control, 0b01);
}

#[test]
fn stack_pointer_writes_ignore_bits_1_0() {
    let mut cpu = m4(&[0x85, 0x46]); // mov sp,r0
    cpu.regs[0] = 0x1003;
    cpu.execute_one().unwrap();
    assert_eq!(cpu.sp_main, 0x1000);
}

#[test]
fn wfe_consumes_a_pending_event() {
    // sev ; wfe ; wfe
    let mut cpu = m4(&[0x40, 0xBF, 0x20, 0xBF, 0x20, 0xBF]);
    assert_eq!(cpu.execute_one(), Ok(CpuExit::Continue));
    assert_eq!(cpu.execute_one(), Ok(CpuExit::Continue));
    assert!(!cpu.is_sleeping());
    assert_eq!(cpu.execute_one(), Ok(CpuExit::Wfe));
    assert!(cpu.is_sleeping());
}

#[test]
fn clear_epsr_t_faults_on_the_next_instruction() {
    let mut cpu = m4(&[0x00, 0x47]); // bx r0
    cpu.regs[0] = 0x200;
    cpu.execute_one().unwrap();
    assert_eq!(cpu.pc, 0x200);
    assert_eq!(cpu.execute_one(), Err(Fault::InvalidState));
    assert_eq!(cpu.pc, 0x200);
}
