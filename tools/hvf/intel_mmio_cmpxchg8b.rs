//! Paired-register completion on a real Intel Hypervisor.framework vCPU.
use super::*;
use rax::devices::bus::MmioRmwOp;

const COMPARE: u64 = 0xabcd_1234_1234_5678;
const REPLACE: u64 = 0x5555_7777_8765_4321;
const DIFFERENT: u64 = 0x8899_aabb_ccdd_eeff;
const RAX: u64 = 0xfeed_face_1234_5678;
const RDX: u64 = 0xd00d_f00d_abcd_1234;
const RBX: u64 = 0xcccc_dddd_8765_4321;
const RCX: u64 = 0x8765_1234_5555_7777;
const FLAGS: u64 = 0x897;
const ZF: u64 = 1 << 6;

fn trial(output: &Path, case: usize, prefix: &str, code: &[u8], equal: bool, restore: bool) {
    let memory = guest_memory(code);
    let (mut vm, mut cpu) = machine(&memory);
    let mut state_before = state(cpu.as_ref());
    state_before.regs.rax = RAX;
    state_before.regs.rdx = RDX;
    state_before.regs.rbx = RBX;
    state_before.regs.rcx = RCX;
    state_before.regs.rflags = if equal { FLAGS } else { FLAGS | ZF };
    cpu.set_state(&CpuState::X86_64(state_before)).unwrap();
    let pending = event(cpu.as_mut());
    let VcpuExit::MmioRmw {
        addr: MMIO,
        size: 8,
        operation,
    } = pending
    else {
        panic!("case {case}: unexpected CMPXCHG8B exit: {pending:?}");
    };
    assert_eq!(
        operation,
        MmioRmwOp::CompareExchange {
            expected: COMPARE,
            replacement: REPLACE,
        }
    );
    assert!(cpu.io_completion_result().is_err());
    if restore {
        let boundary = vm.checkpoint_boundary().unwrap();
        let (saved, private) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
        let private = private.expect("native pending CMPXCHG8B context");
        assert_eq!(saved.state.pc(), CODE);
        drop(boundary);
        drop(cpu);
        drop(vm);
        (vm, cpu) = machine(&guest_memory(code));
        cpu.restore_checkpoint_context(&saved.state, &saved.emulator, Some(&private))
            .unwrap();
    }
    let repeated = event(cpu.as_mut());
    assert!(matches!(repeated, VcpuExit::MmioRmw {
        addr: MMIO, size: 8, operation: repeated_op,
    } if operation == repeated_op));
    let old = if equal { COMPARE } else { DIFFERENT };
    let mut device = old.to_le_bytes();
    operation.apply(&mut device).unwrap();
    let device = u64::from_le_bytes(device);
    assert_eq!(device, if equal { REPLACE } else { DIFFERENT });
    cpu.complete_io_in(&old.to_le_bytes());
    cpu.io_completion_result().unwrap();
    assert_eq!(state(cpu.as_ref()).regs.rip, CODE + code.len() as u64);
    assert!(matches!(event(cpu.as_mut()), VcpuExit::Hlt));
    let regs = state(cpu.as_ref()).regs;
    assert_eq!(regs.rip, CODE + code.len() as u64 + 11);
    assert_eq!(regs.r10, MARKER);
    assert_eq!(regs.rdi, MMIO);
    assert_eq!(regs.rbx, RBX);
    assert_eq!(regs.rcx, RCX);
    assert_eq!(regs.rax, if equal { RAX } else { DIFFERENT & 0xffff_ffff });
    assert_eq!(regs.rdx, if equal { RDX } else { DIFFERENT >> 32 });
    assert_eq!(regs.rflags, if equal { FLAGS | ZF } else { FLAGS });
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(output)
        .unwrap();
    writeln!(file, "{{\"case\":{case},\"name\":\"cmpxchg8b\",\"prefix\":\"{prefix}\",\"equal\":{equal},\"restored\":{restore},\"rax\":{},\"rdx\":{},\"rflags\":{},\"device\":{device},\"rip\":{},\"passed\":true}}", regs.rax, regs.rdx, regs.rflags, regs.rip).unwrap();
    drop(cpu);
    drop(vm);
}

pub(super) fn run(output: &Path) {
    assert!(!output.exists(), "observations must be new");
    let mut case = 0;
    for (prefix, code) in [
        ("plain", &[0x0f, 0xc7, 0x0f][..]),
        ("lock", &[0xf0, 0x0f, 0xc7, 0x0f]),
        ("operand-size", &[0x66, 0x0f, 0xc7, 0x0f]),
    ] {
        for equal in [false, true] {
            for restore in [false, true] {
                trial(output, case, prefix, code, equal, restore);
                case += 1;
            }
        }
    }
    assert_eq!(case, 12);
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}
