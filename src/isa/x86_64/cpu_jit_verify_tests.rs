//! Partial-frontier validation without executing any host vector instruction.

use super::*;
use crate::smir::ir::X86InstructionBytes;
use crate::smir::lower::runtime::ExecMem;
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

const BYTES: [u8; 7] = [0x62, 0xF2, 0x7D, 0x0B, 0x90, 0x0C, 0x10];

fn fixture() -> (X86_64Vcpu, JitRegion, Arc<GuestMemoryMmap>) {
    let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x3000)]).unwrap());
    memory.write_slice(&BYTES, GuestAddress(0)).unwrap();
    memory
        .write_obj(0x1122_3344u32, GuestAddress(0x2000))
        .unwrap();
    let mut cpu = X86_64Vcpu::new(0, memory.clone());
    cpu.sregs.cr0 = 1;
    cpu.sregs.efer = 1 << 10;
    cpu.sregs.cs.l = true;
    cpu.regs.rip = 0;
    cpu.regs.rax = 0;
    cpu.regs.rflags = 0xCD7;
    cpu.regs.k[3] = 0xF000_0000_0000_0003;
    cpu.regs.xmm[1] = [u64::MAX; 2];
    cpu.regs.ymm_high[1] = [u64::MAX; 2];
    cpu.regs.zmm_high[1] = [u64::MAX; 4];
    cpu.regs.xmm[2][0] = 0x0000_4000_0000_2000;
    cpu.jit_mem_trace = Some(Vec::new());
    let region = JitRegion {
        exec: ExecMem::new(&[0xC3]).unwrap(),
        entry_offset: 0,
        source_pages: vec![0],
        uses_vector: true,
        uses_xmm_state: false,
        uses_mxcsr_state: false,
        avx_ymm16_vector_state: false,
        narrow_vector_opmasks: true,
        uses_mmx: false,
        uses_x87_tag_state: false,
        uses_x87_environment_state: false,
        uses_timestamp: false,
        uses_io: false,
        yielded_backward_exit_pcs: Vec::new(),
        callout_boundaries: Vec::new(),
        vsib_instructions: vec![(0, X86InstructionBytes::new(&BYTES).unwrap())],
    };
    (cpu, region, memory)
}

#[test]
fn vsib_frontier_metadata_rejects_invalid_source_mode_lane_and_missing_trace_before_execution() {
    for case in 0..12 {
        let (mut cpu, mut region, memory) = fixture();
        let mut marker = 1;
        let mut trace = Some(&[][..]);
        match case {
            0 => marker = 0,
            1 => marker = 17,
            2 => marker = u64::MAX,
            3 => region.vsib_instructions.clear(),
            4 => region.vsib_instructions[0].1 = X86InstructionBytes::new(&[0x90]).unwrap(),
            5 => memory.write_obj(0x90u8, GuestAddress(0)).unwrap(),
            6 => cpu.regs.k[3] = 0,
            7 => marker = 5, // VL=128, DD has only four lanes.
            8 => cpu.sregs.cs.l = false,
            9 => {
                let mut apx = BYTES;
                apx[1] |= 8; // B4 selects the R16 VSIB base.
                memory.write_slice(&apx, GuestAddress(0)).unwrap();
                region.vsib_instructions[0].1 = X86InstructionBytes::new(&apx).unwrap();
                cpu.set_apx_enabled(false);
            }
            10 => cpu.jit_mem_trace = None,
            11 => trace = None,
            _ => unreachable!(),
        }
        let old = cpu.regs.clone();
        assert!(
            cpu.jit_verify_vsib_frontier(&region, marker, trace)
                .is_err(),
            "case {case}"
        );
        assert_eq!(cpu.regs.rip, old.rip, "case {case}");
        assert_eq!(cpu.regs.rflags, old.rflags, "case {case}");
        assert_eq!(cpu.regs.k, old.k, "case {case}");
        assert_eq!(cpu.regs.xmm, old.xmm, "case {case}");
        assert_eq!(cpu.jit_verify_vsib_stop, None, "case {case}");
        assert!(
            cpu.jit_mem_trace.as_ref().is_none_or(Vec::is_empty),
            "case {case}"
        );
    }
}

#[test]
fn vsib_frontier_replay_stops_before_first_or_later_active_lane_and_checks_prefix_values() {
    let (mut first, first_region, _) = fixture();
    let initial = first.regs.clone();
    first
        .jit_verify_vsib_frontier(&first_region, 1, Some(&[]))
        .unwrap();
    assert_eq!(first.regs.k, initial.k);
    assert_eq!(first.regs.xmm, initial.xmm);
    assert_eq!(first.regs.rip, 0);
    assert_eq!(first.jit_mem_trace, Some(Vec::new()));

    let (mut later, later_region, _) = fixture();
    let native = [(0, 0x2000, 4, 0x1122_3344)];
    later
        .jit_verify_vsib_frontier(&later_region, 2, Some(&native))
        .unwrap();
    assert_eq!(later.regs.xmm[1][0], 0xFFFF_FFFF_1122_3344);
    assert_eq!(later.regs.ymm_high[1], [u64::MAX; 2]);
    assert_eq!(later.regs.zmm_high[1], [u64::MAX; 4]);
    assert_eq!(later.regs.k[3], 0xF000_0000_0000_0002);
    assert_eq!(later.regs.rip, 0);
    assert_eq!(later.jit_mem_trace, Some(native.to_vec()));
    assert_eq!(later.jit_verify_vsib_stop, None);

    let (mut wrong, wrong_region, _) = fixture();
    assert!(
        wrong
            .jit_verify_vsib_frontier(&wrong_region, 2, Some(&[(0, 0x2000, 4, 0x1122_3345)]))
            .is_err()
    );
    assert_eq!(wrong.jit_verify_vsib_stop, None);
}
