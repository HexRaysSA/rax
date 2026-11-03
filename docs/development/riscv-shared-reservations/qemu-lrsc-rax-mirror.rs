//! Execute the retained bare-metal instruction bytes through two actual RAX
//! system backends. The host interleaves single instructions; this witness does
//! not qualify VMM secondary startup or its interrupt/controller machinery.
use rax::backend::emulator::riscv::RiscVVcpu;
use rax::vm::vcpu::{CpuState, VCpu, VcpuExit};
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

#[test]
fn observed_peer_stores_fail_sc_for_all_four_retained_program_cases() {
    let code = std::fs::read(std::env::var("RAX_LRSC_TEXT_IMAGE").unwrap()).unwrap();
    let memory = Arc::new(
        GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0x100000), 4096),
            (GuestAddress(0x80000000), 0x4000),
        ])
        .unwrap(),
    );
    memory.write_slice(&code, GuestAddress(0x80000000)).unwrap();
    let mut harts: Vec<_> = (0..2)
        .map(|id| {
            let mut hart = RiscVVcpu::new(id, memory.clone());
            let CpuState::RiscV(mut state) = hart.get_state().unwrap() else {
                panic!()
            };
            state.regs.pc = 0x80000000;
            hart.set_state(&CpuState::RiscV(state)).unwrap();
            hart
        })
        .collect();
    let mut output = Vec::new();
    let mut completed = false;
    for _ in 0..100_000 {
        for hart in &mut harts {
            match hart.step_insn().unwrap() {
                None => {}
                Some(VcpuExit::MmioWrite {
                    addr: 0x10000000,
                    data,
                }) => output.extend(data),
                other => panic!("unexpected instruction exit: {other:?}"),
            }
        }
        if memory.read_obj::<u32>(GuestAddress(0x100000)).unwrap() == 0x5555 {
            completed = true;
            break;
        }
    }
    println!("observed_status_bytes={}", String::from_utf8_lossy(&output));
    assert!(
        completed,
        "the actual two-hart instruction program must finish"
    );
    assert_eq!(
        output, b"1111\n",
        "changed, same-value, ABA, same-value doubleword stores all invalidate LR"
    );
}
