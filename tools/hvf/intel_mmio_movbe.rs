//! MOVBE device effects on a real Intel Hypervisor.framework vCPU.
use super::*;

const REPLY: [u8; 8] = [0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x12, 0x13, 0x14];

fn transaction(code: &[u8], width: usize, store: Option<&[u8]>, expected_rax: u64, restore: bool) {
    let memory = guest_memory(code);
    let (mut vm, mut cpu) = machine(&memory);
    let pending = event(cpu.as_mut());
    match (&pending, store) {
        (VcpuExit::MmioRead { addr, size }, None) => {
            assert_eq!((*addr, usize::from(*size)), (MMIO, width));
        }
        (VcpuExit::MmioWrite { addr, data }, Some(expected)) => {
            assert_eq!((*addr, data.as_slice()), (MMIO, expected));
        }
        _ => panic!("unexpected MOVBE device exit: {pending:?}"),
    }
    assert!(cpu.get_state().is_err());
    assert!(cpu.io_completion_result().is_err());
    if restore {
        let boundary = vm.checkpoint_boundary().unwrap();
        let (saved, context) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
        let context = context.unwrap();
        assert_eq!(saved.state.pc(), CODE);
        drop(boundary);
        drop(cpu);
        drop(vm);
        let fresh_memory = guest_memory(code);
        (vm, cpu) = machine(&fresh_memory);
        cpu.restore_checkpoint_context(&saved.state, &saved.emulator, Some(&context))
            .unwrap();
        assert!(cpu.get_state().is_err());
    }

    // Re-entry before dispatch must offer the original request. The post-MMIO
    // marker and register checks below require exactly one retirement.
    assert_eq!(format!("{:?}", event(cpu.as_mut())), format!("{pending:?}"));
    if store.is_some() {
        cpu.complete_io_out().unwrap();
    } else {
        cpu.complete_io_in(&REPLY[..width]);
        cpu.io_completion_result().unwrap();
    }
    assert_eq!(state(cpu.as_ref()).regs.rip, CODE + code.len() as u64);
    halted(cpu.as_mut(), code.len(), expected_rax);
    drop(cpu);
    drop(vm);
}

pub(super) fn run(output: &Path) {
    assert!(!output.exists(), "observations must be new");
    let mut case = 0;
    for (width, load, store, expected_rax, expected_bytes) in [
        (
            2,
            &[0x66, 0x0f, 0x38, 0xf0, 0x07][..],
            &[0x66, 0x0f, 0x38, 0xf1, 0x07][..],
            0x1122_3344_5566_aabb,
            &[0x77, 0x88][..],
        ),
        (
            4,
            &[0x0f, 0x38, 0xf0, 0x07],
            &[0x0f, 0x38, 0xf1, 0x07],
            0x0000_0000_aabb_ccdd,
            &[0x55, 0x66, 0x77, 0x88],
        ),
        (
            8,
            &[0x48, 0x0f, 0x38, 0xf0, 0x07],
            &[0x48, 0x0f, 0x38, 0xf1, 0x07],
            0xaabb_ccdd_1112_1314,
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        ),
    ] {
        for (restore, load_name, store_name) in [
            (false, "movbe-load", "movbe-store"),
            (true, "movbe-load-restored", "movbe-store-restored"),
        ] {
            transaction(load, width, None, expected_rax, restore);
            record(output, case, load_name, width, expected_rax);
            case += 1;
            transaction(store, width, Some(expected_bytes), SEED, restore);
            record(output, case, store_name, width, SEED);
            case += 1;
        }
    }
    assert_eq!(case, 12);
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}
