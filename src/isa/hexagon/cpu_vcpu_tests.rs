//! Batched runs, packet stepping, and the packet count of the Hexagon vCPU.

use super::*;
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

/// `{ r0 = ##200000 }`, a two-packet countdown loop, then `{ r1 = #42 }`
/// (LLVM 23 `llvm-mc -triple=hexagon`).
const LOOP: [u32; 5] = [
    0x0000_4C35,
    0x7800_C000,
    0xBFE0_FFE0,
    0x1070_E0FE,
    0x7800_C541,
];

fn vcpu() -> HexagonVcpu {
    let mem = Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
    for (i, word) in LOOP.iter().enumerate() {
        mem.write_slice(&word.to_le_bytes(), GuestAddress(0x1000 + 4 * i as u64))
            .unwrap();
    }
    let mut vcpu = HexagonVcpu::new(0, mem, HexagonIsa::default(), Endianness::Little);
    vcpu.set_current_pc(0x1000).unwrap();
    vcpu
}

#[test]
fn a_long_run_yields_between_batches_instead_of_failing() {
    let mut vcpu = vcpu();
    // `{ r1 = #42 }` is packet 400 002; one batch is 100 000 packets.
    assert!(matches!(vcpu.run().unwrap(), VcpuExit::Hlt));
    assert_eq!(vcpu.instruction_count(), RUN_BATCH_PACKETS);
    let pc = vcpu.current_pc();
    assert!(
        (0x1008..0x1010).contains(&pc),
        "still in the loop at {pc:#x}"
    );
    // Later batches continue where the first stopped.
    for _ in 0..3 {
        assert!(matches!(vcpu.run().unwrap(), VcpuExit::Hlt));
    }
    assert_eq!(vcpu.instruction_count(), 4 * RUN_BATCH_PACKETS);
    for _ in 0..2 {
        assert!(vcpu.step_insn().unwrap().is_none());
    }
    assert_eq!(vcpu.current_pc(), 0x1014);
    let CpuState::Hexagon(state) = vcpu.get_state().unwrap() else {
        unreachable!()
    };
    assert_eq!(state.regs.r[0], 0);
    assert_eq!(state.regs.r[1], 42);
}

#[test]
fn step_insn_executes_and_counts_one_packet() {
    let mut vcpu = vcpu();
    assert!(vcpu.supports_stepping());
    assert!(vcpu.step_insn().unwrap().is_none());
    assert_eq!(vcpu.current_pc(), 0x1008, "immext + transfer is one packet");
    assert_eq!(vcpu.instruction_count(), 1);
    assert!(vcpu.step_insn().unwrap().is_none());
    assert_eq!(vcpu.current_pc(), 0x100C);
    assert_eq!(vcpu.instruction_count(), 2);
}
