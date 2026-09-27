//! User-mode (U-mode) execution of [`RiscVVcpu::new_user`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use super::*;
use crate::error::{GuestMemoryFault, MemoryAccessKind, MemoryFaultKind};
use crate::isa::riscv::RiscVConfig;
use crate::isa::riscv::cpu::{Priv, cause};
use crate::vm::memory::FlatTranslation;
use crate::vm::vcpu::{CpuState, MemAccess, VCpu, VcpuExit};

const R: u8 = 1;
const W: u8 = 2;
const X: u8 = 4;

/// Identity translation with per-page permissions.
#[derive(Default)]
struct Pages(Mutex<HashMap<u64, u8>>);

impl FlatTranslation for Pages {
    fn translate(
        &self,
        linear: u64,
        access: MemoryAccessKind,
    ) -> std::result::Result<u64, GuestMemoryFault> {
        let Some(&perms) = self.0.lock().unwrap().get(&(linear & !0xFFF)) else {
            return Err(GuestMemoryFault::unmapped(linear, 1, access));
        };
        let need = match access {
            MemoryAccessKind::Read => R,
            MemoryAccessKind::Write => W,
            MemoryAccessKind::Fetch => X,
        };
        if perms & need == 0 {
            return Err(GuestMemoryFault {
                address: linear,
                size: 1,
                access,
                kind: MemoryFaultKind::Permission,
            });
        }
        Ok(linear)
    }
}

const CODE: u64 = 0x1000;
const DATA: u64 = 0x2000;
const RODATA: u64 = 0x3000;
const NOEXEC: u64 = 0x4000;

const LI_A7_93: u32 = 0x05D0_0893; // addi a7, zero, 93
const ECALL: u32 = 0x0000_0073;
const EBREAK: u32 = 0x0010_0073;
const ILLEGAL: u32 = 0x0000_0000;
const LD_A0_A1: u32 = 0x0005_B503; // ld a0, 0(a1)
const SD_A0_A1: u32 = 0x00A5_B023; // sd a0, 0(a1)
const CSRR_A0_MSTATUS: u32 = 0x3000_2573;
const RDCYCLE_A0: u32 = 0xC000_2573;

/// A user-mode hart with `insns` at [`CODE`] (R|X), a R|W page at [`DATA`], a
/// read-only page at [`RODATA`], and a R|W page at [`NOEXEC`]; 0x5000 and up
/// are unmapped.
fn user_vcpu(insns: &[u32]) -> (RiscVVcpu, Arc<GuestMemoryMmap>) {
    let mem = Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x8000)]).unwrap());
    for (i, insn) in insns.iter().enumerate() {
        mem.write_slice(&insn.to_le_bytes(), GuestAddress(CODE + 4 * i as u64))
            .unwrap();
    }
    let pages = Pages::default();
    for (page, perms) in [(CODE, R | X), (DATA, R | W), (RODATA, R), (NOEXEC, R | W)] {
        pages.0.lock().unwrap().insert(page, perms);
    }
    let mut vcpu = RiscVVcpu::new_user(0, mem.clone(), RiscVConfig::rv64gc(), Arc::new(pages));
    vcpu.set_current_pc(CODE).unwrap();
    (vcpu, mem)
}

fn set_x(vcpu: &mut RiscVVcpu, reg: usize, value: u64) {
    let CpuState::RiscV(mut state) = vcpu.get_state().unwrap() else {
        panic!("expected RISC-V state");
    };
    state.regs.x[reg] = value;
    vcpu.update_state(&CpuState::RiscV(state)).unwrap();
}

fn expect_event(vcpu: &mut RiscVVcpu, want: u64) -> RvUserTrap {
    match vcpu.step_insn() {
        Err(Error::GuestEvent { vector }) => assert_eq!(u64::from(vector), want),
        other => panic!("expected event {want}, got {other:?}"),
    }
    vcpu.take_user_trap().expect("the event records a trap")
}

fn expect_fault(vcpu: &mut RiscVVcpu) -> GuestMemoryFault {
    match vcpu.step_insn() {
        Err(Error::GuestAccess(fault)) => fault,
        other => panic!("expected a guest access fault, got {other:?}"),
    }
}

#[test]
fn ecall_reports_a_system_call_and_resumes_after_it() {
    let (mut vcpu, _) = user_vcpu(&[LI_A7_93, ECALL]);
    assert!(vcpu.step_insn().unwrap().is_none());
    assert!(matches!(
        vcpu.step_insn().unwrap(),
        Some(VcpuExit::SystemCall)
    ));
    assert_eq!(
        vcpu.take_user_trap(),
        Some(RvUserTrap::Ecall { pc: CODE + 4 })
    );
    assert_eq!(vcpu.current_pc(), CODE + 8);
    assert_eq!(vcpu.cpu.privilege(), Priv::User);
    assert_eq!(vcpu.cpu.x(17), 93);
    // The completed call counts as an executed instruction.
    assert_eq!(vcpu.instruction_count(), 2);
}

#[test]
fn run_stops_at_the_system_call() {
    let (mut vcpu, _) = user_vcpu(&[LI_A7_93, ECALL]);
    assert!(matches!(vcpu.run().unwrap(), VcpuExit::SystemCall));
    assert_eq!(vcpu.current_pc(), CODE + 8);
}

#[test]
fn ebreak_reports_a_breakpoint_without_retiring() {
    let (mut vcpu, _) = user_vcpu(&[EBREAK]);
    assert_eq!(
        expect_event(&mut vcpu, cause::BREAKPOINT),
        RvUserTrap::Exception {
            cause: cause::BREAKPOINT,
            tval: CODE,
            pc: CODE
        }
    );
    assert_eq!(vcpu.current_pc(), CODE);
    assert_eq!(vcpu.instruction_count(), 0);
}

#[test]
fn illegal_and_privileged_instructions_stay_in_u_mode() {
    for insn in [ILLEGAL, CSRR_A0_MSTATUS, RDCYCLE_A0] {
        let (mut vcpu, _) = user_vcpu(&[insn]);
        let trap = expect_event(&mut vcpu, cause::ILLEGAL_INSTR);
        let RvUserTrap::Exception { cause, pc, .. } = trap else {
            panic!("{insn:#010x}: expected an exception, got {trap:?}");
        };
        assert_eq!((cause, pc), (cause::ILLEGAL_INSTR, CODE), "{insn:#010x}");
        assert_eq!(vcpu.current_pc(), CODE, "{insn:#010x}");
        assert_eq!(vcpu.cpu.privilege(), Priv::User, "{insn:#010x}");
    }
}

#[test]
fn page_permissions_are_enforced_with_the_exact_address() {
    let (mut vcpu, _) = user_vcpu(&[SD_A0_A1]);
    set_x(&mut vcpu, 11, RODATA + 16);
    let fault = expect_fault(&mut vcpu);
    assert_eq!(fault.kind, MemoryFaultKind::Permission);
    assert_eq!(fault.access, MemoryAccessKind::Write);
    assert_eq!(fault.address, RODATA + 16);
    assert_eq!(vcpu.current_pc(), CODE, "the store does not retire");
    assert_eq!(vcpu.cpu.privilege(), Priv::User);

    // A load from an unmapped page.
    let (mut vcpu, _) = user_vcpu(&[LD_A0_A1]);
    set_x(&mut vcpu, 11, 0x6000);
    let fault = expect_fault(&mut vcpu);
    assert_eq!(fault.kind, MemoryFaultKind::Unmapped);
    assert_eq!(fault.access, MemoryAccessKind::Read);
    assert_eq!(fault.address, 0x6000);

    // A load crossing from the R|W page at NOEXEC into the unmapped page at
    // 0x5000 reports its first inaccessible byte.
    let (mut vcpu, _) = user_vcpu(&[LD_A0_A1]);
    set_x(&mut vcpu, 11, 0x5000 - 4);
    let fault = expect_fault(&mut vcpu);
    assert_eq!(fault.kind, MemoryFaultKind::Unmapped);
    assert_eq!(fault.address, 0x5000);

    let (mut vcpu, _) = user_vcpu(&[]);
    vcpu.set_current_pc(NOEXEC).unwrap();
    let fault = expect_fault(&mut vcpu);
    assert_eq!(fault.kind, MemoryFaultKind::Permission);
    assert_eq!(fault.access, MemoryAccessKind::Fetch);
    assert_eq!(fault.address, NOEXEC);
}

#[test]
fn a_crossing_store_that_faults_publishes_nothing() {
    let (mut vcpu, mem) = user_vcpu(&[SD_A0_A1]);
    set_x(&mut vcpu, 10, 0x1122_3344_5566_7788);
    set_x(&mut vcpu, 11, RODATA - 4);
    let fault = expect_fault(&mut vcpu);
    assert_eq!(fault.kind, MemoryFaultKind::Permission);
    assert_eq!(fault.address, RODATA);
    let mut bytes = [0xAAu8; 4];
    mem.read_slice(&mut bytes, GuestAddress(RODATA - 4))
        .unwrap();
    assert_eq!(bytes, [0; 4]);
}

#[test]
fn user_mode_has_no_device_windows() {
    // 0x1000_0000 is the system hart's UART window; in user mode it is
    // ordinary (here unmapped) memory.
    let (mut vcpu, _) = user_vcpu(&[LD_A0_A1]);
    set_x(&mut vcpu, 11, 0x1000_0005);
    let fault = expect_fault(&mut vcpu);
    assert_eq!(fault.kind, MemoryFaultKind::Unmapped);
    assert_eq!(fault.address, 0x1000_0005);
}

#[test]
fn translate_addr_applies_the_user_translation() {
    let (mut vcpu, _) = user_vcpu(&[]);
    assert_eq!(
        vcpu.translate_addr(DATA + 1, MemAccess::Write).unwrap(),
        DATA + 1
    );
    assert!(vcpu.translate_addr(RODATA, MemAccess::Write).is_err());
    assert!(vcpu.translate_addr(DATA, MemAccess::Exec).is_err());
}
