//! CMOVcc memory reads on an Intel Hypervisor.framework vCPU.
use super::*;

const REPLY: u64 = 0x1020_3040_5060_7080;

fn check_read(cpu: &mut dyn VCpu, width: usize) {
    let pending = event(cpu);
    assert!(
        matches!(pending, VcpuExit::MmioRead { addr: MMIO, size } if usize::from(size) == width),
        "unexpected CMOVcc exit: {pending:?}"
    );
    assert!(cpu.get_state().is_err());
    assert!(cpu.io_completion_result().is_err());
}

fn transaction(code: &[u8], width: usize, expected_rax: u64, restore: bool) {
    let memory = guest_memory(code);
    let (mut vm, mut cpu) = machine(&memory);
    check_read(cpu.as_mut(), width);
    if restore {
        let boundary = vm.checkpoint_boundary().unwrap();
        let (saved, context) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
        assert_eq!(saved.state.pc(), CODE);
        let context = context.unwrap();
        drop(boundary);
        drop(cpu);
        drop(vm);
        (vm, cpu) = machine(&guest_memory(code));
        cpu.restore_checkpoint_context(&saved.state, &saved.emulator, Some(&context))
            .unwrap();
    }
    check_read(cpu.as_mut(), width);
    cpu.complete_io_in(&REPLY.to_le_bytes()[..width]);
    cpu.io_completion_result().unwrap();
    let regs = state(cpu.as_ref()).regs;
    assert_eq!(regs.rip, CODE + code.len() as u64);
    assert_eq!(regs.rax, expected_rax);
    assert_eq!(regs.rflags, 2);
    halted(cpu.as_mut(), code.len(), expected_rax);
    drop(cpu);
    drop(vm);
}

pub(super) fn run(output: &Path) {
    assert!(!output.exists(), "observations must be new");
    let mut case = 0;
    // The fixture starts with ZF clear, so CMOVNE selects the value and CMOVE keeps the low bits.
    for (prefix, width, selected, unselected) in [
        (&[0x66][..], 2, 0x1122_3344_5566_7080, SEED),
        (&[][..], 4, 0x5060_7080, 0x5566_7788),
        (&[0x48][..], 8, REPLY, SEED),
    ] {
        for (opcode, expected) in [(0x44, unselected), (0x45, selected)] {
            let code = [prefix, &[0x0f, opcode, 0x07]].concat();
            for restore in [false, true] {
                transaction(&code, width, expected, restore);
                let name = match (opcode, restore) {
                    (0x44, false) => "cmove-false",
                    (0x44, true) => "cmove-false-restored",
                    (_, false) => "cmovne-true",
                    (_, true) => "cmovne-true-restored",
                };
                record(output, case, name, width, expected);
                case += 1;
            }
        }
    }
    assert_eq!(case, 12);
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}
