//! User-mode (EL0) execution of [`Aarch64Vcpu::new_user`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use super::*;
use crate::error::{GuestMemoryFault, MemoryAccessKind, MemoryFaultKind};
use crate::vm::memory::FlatTranslation;
use crate::vm::vcpu::{CpuState, MemAccess, VCpu, VcpuExit};

const R: u8 = 1;
const W: u8 = 2;
const X: u8 = 4;

/// Identity translation with per-page permissions.
#[derive(Default)]
struct Pages(Mutex<HashMap<u64, u8>>);

impl Pages {
    fn map(&self, page: u64, perms: u8) {
        self.0.lock().unwrap().insert(page, perms);
    }
}

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

/// A user-mode vCPU with `insns` at [`CODE`] (R|X), a R|W page at [`DATA`], a
/// read-only page at [`RODATA`], and a R|W page at [`NOEXEC`]; 0x5000 and up
/// are unmapped.
fn user_vcpu(insns: &[u32]) -> (Aarch64Vcpu, Arc<GuestMemoryMmap>) {
    let mem = Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x8000)]).unwrap());
    for (i, insn) in insns.iter().enumerate() {
        mem.write_slice(&insn.to_le_bytes(), GuestAddress(CODE + 4 * i as u64))
            .unwrap();
    }
    let pages = Arc::new(Pages::default());
    pages.map(CODE, R | X);
    pages.map(DATA, R | W);
    pages.map(RODATA, R);
    pages.map(NOEXEC, R | W);
    let mut vcpu = Aarch64Vcpu::new_user(0, mem.clone(), pages);
    vcpu.set_current_pc(CODE).unwrap();
    (vcpu, mem)
}

fn state(vcpu: &Aarch64Vcpu) -> crate::vm::vcpu::Aarch64CpuState {
    match vcpu.get_state().unwrap() {
        CpuState::Aarch64(state) => state,
        other => panic!("expected AArch64 state, got {other:?}"),
    }
}

fn set_x(vcpu: &mut Aarch64Vcpu, reg: usize, value: u64) {
    let mut st = state(vcpu);
    st.regs.x[reg] = value;
    vcpu.update_state(&CpuState::Aarch64(st)).unwrap();
}

const MOVZ_X8_64: u32 = 0xD280_0808; // MOVZ X8, #64
const SVC_1234: u32 = 0xD402_4681; // SVC #0x1234
const BRK_10: u32 = 0xD420_0200; // BRK #0x10
const UDF_0: u32 = 0x0000_0000; // UDF #0
const MRS_X0_SCTLR_EL1: u32 = 0xD538_1000;
const LDR_X0_X1: u32 = 0xF940_0020;
const STR_X0_X1: u32 = 0xF900_0020;
const FMOV_D0_1: u32 = 0x1E6E_1000; // FMOV D0, #1.0
const HLT_0: u32 = 0xD440_0000;
const HVC_0: u32 = 0xD400_0002;

#[test]
fn new_user_executes_at_el0t() {
    let (vcpu, _) = user_vcpu(&[]);
    assert!(vcpu.user_mode_enabled());
    // PSTATE.M[3:0] = EL0t.
    assert_eq!(state(&vcpu).regs.pstate & 0xF, 0);
}

#[test]
fn svc_retires_and_reports_a_system_call_with_the_pc_past_it() {
    let (mut vcpu, _) = user_vcpu(&[MOVZ_X8_64, SVC_1234]);
    assert!(vcpu.step_insn().unwrap().is_none());
    assert!(matches!(
        vcpu.step_insn().unwrap(),
        Some(VcpuExit::SystemCall)
    ));
    assert_eq!(
        vcpu.take_user_trap(),
        Some(A64UserTrap::Svc {
            imm: 0x1234,
            pc: CODE + 4
        })
    );
    assert_eq!(vcpu.take_user_trap(), None, "the trap is taken once");
    assert_eq!(vcpu.current_pc(), CODE + 8);
    assert_eq!(state(&vcpu).regs.x[8], 64);
    assert_eq!(vcpu.instruction_count(), 2);
}

#[test]
fn run_stops_at_the_system_call() {
    let (mut vcpu, _) = user_vcpu(&[MOVZ_X8_64, SVC_1234]);
    assert!(matches!(vcpu.run().unwrap(), VcpuExit::SystemCall));
    assert_eq!(vcpu.current_pc(), CODE + 8);
}

#[test]
fn brk_reports_a_breakpoint_exception_without_retiring() {
    let (mut vcpu, _) = user_vcpu(&[BRK_10]);
    match vcpu.step_insn() {
        Err(Error::GuestEvent { vector }) => assert_eq!(vector, A64_EC_BRK),
        other => panic!("expected a BRK event, got {other:?}"),
    }
    assert_eq!(
        vcpu.take_user_trap(),
        Some(A64UserTrap::Exception {
            ec: A64_EC_BRK,
            iss: 0x10,
            pc: CODE
        })
    );
    assert_eq!(vcpu.current_pc(), CODE);
    assert_eq!(vcpu.instruction_count(), 0);
}

#[test]
fn undefined_encodings_report_an_unknown_reason_exception() {
    for insn in [UDF_0, MRS_X0_SCTLR_EL1, HLT_0, HVC_0] {
        let (mut vcpu, _) = user_vcpu(&[insn]);
        match vcpu.step_insn() {
            Err(Error::GuestEvent { vector }) => assert_eq!(vector, A64_EC_UNKNOWN),
            other => panic!("{insn:#010x}: expected an UNDEFINED event, got {other:?}"),
        }
        assert_eq!(
            vcpu.take_user_trap(),
            Some(A64UserTrap::Exception {
                ec: A64_EC_UNKNOWN,
                iss: 0,
                pc: CODE
            }),
            "{insn:#010x}"
        );
        assert_eq!(vcpu.current_pc(), CODE, "{insn:#010x}");
        assert_eq!(vcpu.instruction_count(), 0, "{insn:#010x}");
    }
}

#[test]
fn floating_point_is_enabled_at_el0() {
    let (mut vcpu, _) = user_vcpu(&[FMOV_D0_1]);
    assert!(vcpu.step_insn().unwrap().is_none());
    assert_eq!(state(&vcpu).regs.v[0][0], 1.0f64.to_bits());
}

fn expect_fault(result: Result<Option<VcpuExit>>) -> GuestMemoryFault {
    match result {
        Err(Error::GuestAccess(fault)) => fault,
        other => panic!("expected a guest access fault, got {other:?}"),
    }
}

#[test]
fn page_permissions_are_enforced_with_the_exact_address() {
    // A store to a read-only page.
    let (mut vcpu, _) = user_vcpu(&[STR_X0_X1]);
    set_x(&mut vcpu, 1, RODATA + 8);
    let fault = expect_fault(vcpu.step_insn());
    assert_eq!(fault.kind, MemoryFaultKind::Permission);
    assert_eq!(fault.access, MemoryAccessKind::Write);
    assert_eq!(fault.address, RODATA + 8);
    assert_eq!(vcpu.current_pc(), CODE, "the store does not retire");

    // A load from an unmapped page.
    let (mut vcpu, _) = user_vcpu(&[LDR_X0_X1]);
    set_x(&mut vcpu, 1, 0x6000);
    let fault = expect_fault(vcpu.step_insn());
    assert_eq!(fault.kind, MemoryFaultKind::Unmapped);
    assert_eq!(fault.access, MemoryAccessKind::Read);
    assert_eq!(fault.address, 0x6000);

    // An instruction fetch from a page without execute permission.
    let (mut vcpu, _) = user_vcpu(&[]);
    vcpu.set_current_pc(NOEXEC).unwrap();
    let fault = expect_fault(vcpu.step_insn());
    assert_eq!(fault.kind, MemoryFaultKind::Permission);
    assert_eq!(fault.access, MemoryAccessKind::Fetch);
    assert_eq!(fault.address, NOEXEC);
}

#[test]
fn a_crossing_store_that_faults_publishes_nothing() {
    // DATA is writable; RODATA, the next page, is not.
    let (mut vcpu, mem) = user_vcpu(&[STR_X0_X1]);
    set_x(&mut vcpu, 0, 0x1122_3344_5566_7788);
    set_x(&mut vcpu, 1, RODATA - 4);
    let fault = expect_fault(vcpu.step_insn());
    assert_eq!(fault.kind, MemoryFaultKind::Permission);
    assert_eq!(fault.address, RODATA, "first inaccessible byte");
    let mut bytes = [0xAAu8; 4];
    mem.read_slice(&mut bytes, GuestAddress(RODATA - 4))
        .unwrap();
    assert_eq!(bytes, [0; 4], "no byte of the faulting store was written");
}

#[test]
fn translate_addr_applies_the_user_translation() {
    let (mut vcpu, _) = user_vcpu(&[]);
    assert_eq!(
        vcpu.translate_addr(DATA + 3, MemAccess::Write).unwrap(),
        DATA + 3
    );
    assert!(vcpu.translate_addr(RODATA, MemAccess::Write).is_err());
    assert!(vcpu.translate_addr(0x6000, MemAccess::Read).is_err());
}

#[test]
fn memory_recording_reports_user_accesses() {
    let (mut vcpu, mem) = user_vcpu(&[LDR_X0_X1]);
    mem.write_slice(&0x0123_4567_89AB_CDEFu64.to_le_bytes(), GuestAddress(DATA))
        .unwrap();
    set_x(&mut vcpu, 1, DATA);
    vcpu.set_mem_recording(true);
    assert!(vcpu.step_insn().unwrap().is_none());
    let mut records = Vec::new();
    vcpu.drain_mem_records(&mut records);
    assert!(
        records
            .iter()
            .any(|r| r.access == MemAccess::Exec && r.addr == CODE)
    );
    assert!(records.iter().any(|r| r.access == MemAccess::Read
        && r.addr == DATA
        && r.size == 8
        && r.value == 0x0123_4567_89AB_CDEF));
}
