//! Wide MMIO compare-exchange on the native Intel exit and completion paths.
use super::guest_debug::{IDT, OBSERVATIONS, debug_memory};
use super::*;
use rax::devices::bus::{MmioBus, MmioDevice, MmioRange, MmioRmwOp, SharedMmioDevice};
use std::sync::Mutex;

const COMPARE: u128 = 0xffee_ddcc_bbaa_9988_1122_3344_5566_7788;
const REPLACE: u128 = 0x0102_0304_0506_0708_a5a5_a5a5_b6b6_b6b6;
const FLAGS: u64 = 0x897;
const ZF: u64 = 1 << 6;

struct Register {
    bytes: [u8; 16],
    reads: usize,
    writes: usize,
}
impl MmioDevice for Register {
    fn read(&mut self, address: u64, data: &mut [u8]) {
        assert_eq!(address, MMIO);
        self.reads += 1;
        data.copy_from_slice(&self.bytes);
    }
    fn write(&mut self, address: u64, data: &[u8]) {
        assert_eq!(address, MMIO);
        self.writes += 1;
        self.bytes.copy_from_slice(data);
    }
}

fn trial(
    output: &Path,
    case: usize,
    prefix: &str,
    code: &[u8],
    equal: bool,
    restore: bool,
    watched: bool,
) {
    let memory = if watched {
        debug_memory(code, false)
    } else {
        guest_memory(code)
    };
    let (mut vm, mut cpu) = machine(&memory);
    let mut before = state(cpu.as_ref());
    before.regs.rax = COMPARE as u64;
    before.regs.rdx = (COMPARE >> 64) as u64;
    before.regs.rbx = REPLACE as u64;
    before.regs.rcx = (REPLACE >> 64) as u64;
    before.regs.rflags = if equal { FLAGS } else { FLAGS | ZF };
    if watched {
        before.sregs.idt.base = IDT;
        before.sregs.idt.limit = 4095;
        before.sregs.dr0 = MMIO + 15;
        before.sregs.dr1 = MMIO + 16;
        before.sregs.dr7 = 0x33_0405;
    }
    cpu.set_state(&CpuState::X86_64(before)).unwrap();

    let pending = event(cpu.as_mut());
    let VcpuExit::MmioRmw {
        addr: MMIO,
        size: 16,
        operation,
    } = pending
    else {
        panic!("case {case}: unexpected CMPXCHG16B exit: {pending:?}");
    };
    assert_eq!(
        operation,
        MmioRmwOp::CompareExchange16B {
            expected: COMPARE,
            replacement: REPLACE,
        }
    );
    assert!(cpu.io_completion_result().is_err());
    if restore {
        let boundary = vm.checkpoint_boundary().unwrap();
        let (saved, private) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
        let private = private.expect("native pending CMPXCHG16B context");
        assert_eq!(saved.state.pc(), CODE);
        drop(boundary);
        drop(cpu);
        drop(vm);
        (vm, cpu) = machine(&memory);
        cpu.restore_checkpoint_context(&saved.state, &saved.emulator, Some(&private))
            .unwrap();
    }
    let repeated = event(cpu.as_mut());
    assert!(matches!(repeated, VcpuExit::MmioRmw {
        addr: MMIO, size: 16, operation: repeated_op,
    } if operation == repeated_op));

    // A mismatch in only one half still returns the whole pre-write operand.
    let old = if equal {
        COMPARE
    } else {
        COMPARE ^ if prefix == "lock" { 1 << 96 } else { 1 << 32 }
    };
    let model = Arc::new(Mutex::new(Register {
        bytes: old.to_le_bytes(),
        reads: 0,
        writes: 0,
    }));
    let mut bus = MmioBus::new();
    bus.register(
        MmioRange {
            base: MMIO,
            len: 16,
        },
        Box::new(SharedMmioDevice::new(model.clone())),
    )
    .unwrap();
    let reply = bus.read_modify_write(MMIO, 16, operation).unwrap();
    assert_eq!(reply, old.to_le_bytes());
    let device = {
        let register = model.lock().unwrap();
        assert_eq!((register.reads, register.writes), (1, 1));
        u128::from_le_bytes(register.bytes)
    };
    assert_eq!(device, if equal { REPLACE } else { old });
    cpu.complete_io_in(&reply);
    cpu.io_completion_result().unwrap();

    assert_eq!(state(cpu.as_ref()).regs.rip, CODE + code.len() as u64);
    assert!(matches!(event(cpu.as_mut()), VcpuExit::Hlt));
    let regs = state(cpu.as_ref()).regs;
    assert_eq!(regs.rip, CODE + code.len() as u64 + 11);
    assert_eq!(regs.r10, MARKER);
    assert_eq!(regs.rdi, MMIO);
    assert_eq!(regs.rbx, REPLACE as u64);
    assert_eq!(regs.rcx, (REPLACE >> 64) as u64);
    assert_eq!(regs.rax, old as u64);
    assert_eq!(regs.rdx, (old >> 64) as u64);
    assert_eq!(regs.rflags, if equal { FLAGS | ZF } else { FLAGS });

    let observed = |offset| {
        memory
            .memory()
            .read_obj::<u64>(GuestAddress(OBSERVATIONS + offset))
            .unwrap()
    };
    let traps = observed(0);
    let dr6 = observed(32);
    assert_eq!(traps, u64::from(watched));
    if watched {
        assert_eq!(observed(8), CODE + code.len() as u64);
        assert_eq!(observed(24), 0, "#DB must precede the following marker");
        assert_eq!(
            dr6 & 15,
            1,
            "only the watch on the last operand byte may hit"
        );
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(output)
        .unwrap();
    writeln!(file, "{{\"case\":{case},\"name\":\"cmpxchg16b\",\"prefix\":\"{prefix}\",\"equal\":{equal},\"restored\":{restore},\"rax\":{},\"rdx\":{},\"rflags\":{},\"device\":\"{device:032x}\",\"rip\":{},\"reads\":1,\"writes\":1,\"watched\":{watched},\"traps\":{traps},\"dr6\":{dr6},\"passed\":true}}",
        regs.rax, regs.rdx, regs.rflags, regs.rip).unwrap();
    drop(cpu);
    drop(vm);
}

pub(super) fn run(output: &Path) {
    assert!(!output.exists(), "observations must be new");
    let mut case = 0;
    for watched in [false, true] {
        for (prefix, code) in [
            ("plain", &[0x48, 0x0f, 0xc7, 0x0f][..]),
            ("lock", &[0xf0, 0x48, 0x0f, 0xc7, 0x0f]),
        ] {
            for equal in [false, true] {
                for restore in [false, true] {
                    trial(output, case, prefix, code, equal, restore, watched);
                    case += 1;
                }
            }
        }
    }
    assert_eq!(case, 16);
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}
