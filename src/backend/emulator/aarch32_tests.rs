//! Instruction-level AArch32 execution for embedders.

use std::sync::Arc;

use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use super::*;

const CODE: u64 = 0x1000;
const DATA: u64 = 0x2000;

const MOV_R0_42: u32 = 0xE3A0_002A; // mov r0, #42
const STR_R0_R1: u32 = 0xE581_0000; // str r0, [r1]
const LDR_R0_R1: u32 = 0xE591_0000; // ldr r0, [r1]
const SVC_0: u32 = 0xEF00_0000; // svc #0
const WFI: u32 = 0xE320_F003;
const NOP: u32 = 0xE320_F000;
const USER_MODE: u32 = 0x10;
const SVC_MODE: u32 = 0x13;

/// Guest memory at 0 (16 KiB) with `insns` at [`CODE`]; nothing is mapped at
/// or above 0x4000.
fn new_vcpu(insns: &[u32]) -> (Aarch32Vcpu, Arc<GuestMemoryMmap>) {
    let mem = Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    for (i, insn) in insns.iter().enumerate() {
        mem.write_slice(&insn.to_le_bytes(), GuestAddress(CODE + 4 * i as u64))
            .unwrap();
    }
    let mut vcpu = Aarch32Vcpu::new(0, mem.clone());
    vcpu.set_current_pc(CODE).unwrap();
    (vcpu, mem)
}

/// A vCPU in Thumb state with `code` at [`CODE`].
fn thumb_vcpu(code: &[u8]) -> (Aarch32Vcpu, Arc<GuestMemoryMmap>) {
    let (mut vcpu, mem) = new_vcpu(&[]);
    mem.write_slice(code, GuestAddress(CODE)).unwrap();
    let mut st = state(&vcpu);
    st.regs.cpsr |= 1 << 5; // T
    st.regs.pc = CODE as u32;
    vcpu.set_state(&CpuState::Aarch32(st)).unwrap();
    (vcpu, mem)
}

fn state(vcpu: &Aarch32Vcpu) -> Aarch32CpuState {
    match vcpu.get_state().unwrap() {
        CpuState::Aarch32(state) => state,
        other => panic!("expected AArch32 state, got {other:?}"),
    }
}

fn set_r(vcpu: &mut Aarch32Vcpu, reg: usize, value: u32) {
    let mut st = state(vcpu);
    st.regs.r[reg] = value;
    vcpu.set_state(&CpuState::Aarch32(st)).unwrap();
}

fn fault(result: Result<Option<VcpuExit>>) -> GuestMemoryFault {
    match result {
        Err(Error::GuestAccess(fault)) => fault,
        other => panic!("expected a guest access fault, got {other:?}"),
    }
}

#[test]
fn code_and_data_anywhere_in_guest_memory_are_used() {
    // The S3C64xx machine vCPU treats addresses outside its RAM window as
    // open bus; this vCPU has no such window.
    let (mut vcpu, mem) = new_vcpu(&[MOV_R0_42, STR_R0_R1]);
    set_r(&mut vcpu, 1, DATA as u32);
    assert!(vcpu.supports_stepping());
    assert!(vcpu.step_insn().unwrap().is_none());
    assert_eq!(vcpu.current_pc(), CODE + 4);
    assert_eq!(vcpu.instruction_count(), 1);
    assert!(vcpu.step_insn().unwrap().is_none());
    assert_eq!(state(&vcpu).regs.r[0], 42);
    let mut stored = [0u8; 4];
    mem.read_slice(&mut stored, GuestAddress(DATA)).unwrap();
    assert_eq!(u32::from_le_bytes(stored), 42);
    assert_eq!(vcpu.instruction_count(), 2);
}

#[test]
fn unmapped_accesses_fault_at_the_first_missing_byte_without_retiring() {
    let (mut vcpu, _) = new_vcpu(&[LDR_R0_R1]);
    set_r(&mut vcpu, 0, 7);
    set_r(&mut vcpu, 1, 0x8000);
    let f = fault(vcpu.step_insn());
    assert_eq!(f.kind, MemoryFaultKind::Unmapped);
    assert_eq!(f.access, MemoryAccessKind::Read);
    assert_eq!(f.address, 0x8000);
    assert_eq!(vcpu.current_pc(), CODE);
    assert_eq!(state(&vcpu).regs.r[0], 7);
    assert_eq!(vcpu.instruction_count(), 0);

    // A word store straddling the end of memory publishes nothing.
    let (mut vcpu, mem) = new_vcpu(&[STR_R0_R1]);
    set_r(&mut vcpu, 0, 0x1122_3344);
    set_r(&mut vcpu, 1, 0x3FFE);
    let f = fault(vcpu.step_insn());
    assert_eq!(
        (f.kind, f.access, f.address),
        (MemoryFaultKind::Unmapped, MemoryAccessKind::Write, 0x4000)
    );
    let mut tail = [0xAAu8; 2];
    mem.read_slice(&mut tail, GuestAddress(0x3FFE)).unwrap();
    assert_eq!(tail, [0, 0]);

    // An instruction fetch from missing memory.
    let (mut vcpu, _) = new_vcpu(&[]);
    vcpu.set_current_pc(0x5000).unwrap();
    let f = fault(vcpu.step_insn());
    assert_eq!(
        (f.kind, f.access, f.address),
        (MemoryFaultKind::Unmapped, MemoryAccessKind::Fetch, 0x5000)
    );
}

#[test]
fn undefined_instructions_are_returned_without_retiring() {
    // Thumb `udf #0` (T1). (The ARM-state decoder does not yet recognize
    // `udf`, 0xE7F000F0.)
    let (mut vcpu, _) = thumb_vcpu(&[0x00, 0xDE]);
    match vcpu.step_insn() {
        Err(Error::InvalidInstruction { pc, .. }) => assert_eq!(pc, CODE),
        other => panic!("expected an invalid instruction, got {other:?}"),
    }
    assert_eq!(vcpu.current_pc(), CODE);
    assert_eq!(vcpu.instruction_count(), 0);
}

#[test]
fn svc_is_taken_through_the_vector_table() {
    let (mut vcpu, _) = new_vcpu(&[SVC_0]);
    let mut st = state(&vcpu);
    st.regs.cpsr = USER_MODE;
    st.regs.pc = CODE as u32;
    vcpu.set_state(&CpuState::Aarch32(st)).unwrap();
    assert!(vcpu.step_insn().unwrap().is_none());
    let st = state(&vcpu);
    assert_eq!(st.regs.pc, 0x08, "the SVC vector");
    assert_eq!(st.regs.cpsr & 0x1F, SVC_MODE);
    assert_eq!(st.regs.lr, CODE as u32 + 4, "preferred return address");
    assert_eq!(st.regs.spsr & 0x1F, USER_MODE);
    assert_eq!(vcpu.instruction_count(), 1);
}

#[test]
fn thumb_instructions_advance_by_their_length() {
    // movs r0,#5 ; nop (T1)
    let (mut vcpu, _) = thumb_vcpu(&[0x05, 0x20, 0x00, 0xBF]);
    assert!(vcpu.step_insn().unwrap().is_none());
    assert_eq!(vcpu.current_pc(), CODE + 2);
    assert_eq!(state(&vcpu).regs.r[0], 5);
    assert!(vcpu.step_insn().unwrap().is_none());
    assert_eq!(vcpu.current_pc(), CODE + 4);
}

#[test]
fn wfi_halts_until_woken() {
    let (mut vcpu, _) = new_vcpu(&[WFI, MOV_R0_42]);
    assert!(matches!(vcpu.run().unwrap(), VcpuExit::Hlt));
    assert_eq!(vcpu.current_pc(), CODE + 4);
    assert!(matches!(vcpu.step_insn().unwrap(), Some(VcpuExit::Hlt)));
    assert_eq!(state(&vcpu).regs.r[0], 0, "a halted vCPU executes nothing");
    vcpu.wake();
    assert!(vcpu.step_insn().unwrap().is_none());
    assert_eq!(state(&vcpu).regs.r[0], 42);
}

#[test]
fn state_round_trips_banked_and_system_registers() {
    let (mut vcpu, _) = new_vcpu(&[NOP]);
    let mut st = state(&vcpu);
    st.regs.cpsr = SVC_MODE | (1 << 7);
    st.regs.sp = 0x3F00;
    st.regs.lr = 0x1234;
    st.regs.spsr = USER_MODE | (1 << 29);
    st.regs.d_high[3] = 0x0123_4567_89AB_CDEF;
    st.sregs.dacr = 0x5555_5555;
    st.sregs.ttbr0 = 0x0000_4000;
    st.sregs.contextidr = 0x42;
    vcpu.set_state(&CpuState::Aarch32(st.clone())).unwrap();
    let back = state(&vcpu);
    assert_eq!(back.regs.cpsr & 0x1FF, st.regs.cpsr & 0x1FF);
    assert_eq!(
        (back.regs.sp, back.regs.lr, back.regs.spsr),
        (0x3F00, 0x1234, st.regs.spsr)
    );
    assert_eq!(back.regs.d_high[3], 0x0123_4567_89AB_CDEF);
    assert_eq!(
        (back.sregs.dacr, back.sregs.ttbr0, back.sregs.contextidr),
        (0x5555_5555, 0x4000, 0x42)
    );
}

#[test]
fn thumb_wait_hints_halt() {
    // movw r0,#40000 ; subs r0,r0,#1 ; bne -6 ; wfi (Thumb): 80 002
    // instructions ending in the wait, not in the memory after it.
    let (mut vcpu, _) = thumb_vcpu(&[0x49, 0xF6, 0x40, 0x40, 0x40, 0x1E, 0xFD, 0xD1, 0x30, 0xBF]);
    assert!(matches!(vcpu.run().unwrap(), VcpuExit::Hlt));
    assert_eq!(
        (vcpu.current_pc(), vcpu.instruction_count()),
        (CODE + 10, 80_002)
    );

    // wfe also waits; yield and sev do not.
    for (hint, waits) in [
        ([0x20, 0xBF], true),
        ([0x10, 0xBF], false),
        ([0x40, 0xBF], false),
    ] {
        let (mut vcpu, _) = thumb_vcpu(&hint);
        let exit = vcpu.step_insn().unwrap();
        assert_eq!(matches!(exit, Some(VcpuExit::Hlt)), waits, "{hint:x?}");
    }
}
