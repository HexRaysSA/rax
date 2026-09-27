//! `VCpu` state transfer: an injected RFLAGS value is architectural and must
//! not be overridden by flags still derived lazily from an earlier ALU result.

use super::*;
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use crate::error::{GuestMemoryFault, MemoryAccessKind};
use crate::vm::memory::FlatTranslation;

/// Identity translation granting every access.
struct Flat;

impl FlatTranslation for Flat {
    fn translate(
        &self,
        linear: u64,
        _access: MemoryAccessKind,
    ) -> std::result::Result<u64, GuestMemoryFault> {
        Ok(linear)
    }
}

const CODE: u64 = 0x1000;
const ZF_PF: u64 = (1 << 6) | (1 << 2);
const CF: u64 = 1;

/// A 64-bit vCPU (user mode supplies a flat long-mode environment) with
/// `code` at [`CODE`].
fn vcpu(code: &[u8]) -> X86_64Vcpu {
    let memory =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
    memory.write_slice(code, GuestAddress(CODE)).unwrap();
    let mut vcpu = X86_64Vcpu::new(0, memory);
    vcpu.enable_user_mode(Arc::new(Flat));
    vcpu.set_current_pc(CODE).unwrap();
    vcpu
}

fn rflags(vcpu: &X86_64Vcpu) -> u64 {
    match vcpu.get_state().unwrap() {
        CpuState::X86_64(state) => state.regs.rflags,
        other => panic!("expected x86-64 state, got {other:?}"),
    }
}

#[test]
fn set_state_replaces_lazily_derived_flags() {
    // xor eax,eax (ZF=PF=1, CF=0 pending lazily) ; setc al
    let mut vcpu = vcpu(&[0x31, 0xC0, 0x0F, 0x92, 0xC0]);
    assert!(vcpu.step_insn().unwrap().is_none());
    assert_eq!(rflags(&vcpu) & (ZF_PF | CF), ZF_PF);

    let CpuState::X86_64(mut state) = vcpu.get_state().unwrap() else {
        unreachable!()
    };
    state.regs.rflags = 0x202 | CF;
    vcpu.set_state(&CpuState::X86_64(state)).unwrap();
    assert_eq!(rflags(&vcpu), 0x202 | CF);

    // The written CF is what the next instruction observes.
    assert!(vcpu.step_insn().unwrap().is_none());
    assert_eq!(vcpu.user_regs().rax & 0xFF, 1);
}

#[test]
fn snapshot_restore_reinstates_the_saved_lazy_flags() {
    let mut source = vcpu(&[0x31, 0xC0]);
    assert!(source.step_insn().unwrap().is_none());
    let state = source.get_state().unwrap();
    let emulator = source.get_emulator_state().unwrap();

    let mut restored = vcpu(&[]);
    restored.set_state(&state).unwrap();
    restored.set_emulator_state(&emulator).unwrap();
    assert_eq!(rflags(&restored), rflags(&source));
    assert_eq!(rflags(&restored) & (ZF_PF | CF), ZF_PF);
}
