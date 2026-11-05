//! Actual RAX Intel HVF guest execution; no SDK binding replacements.
use rax::backend::{
    Backend, Vm,
    hvf::{HvfBackend, HvfVm},
};
use rax::vm::memory::GuestMemoryWrapper;
use rax::vm::vcpu::{CpuState, Segment, VCpu, VcpuExit, X86_64CpuState};
use std::{fs::OpenOptions, io::Write, path::Path, sync::Arc, time::Duration};
use vm_memory::{Bytes, GuestAddress};

const RAM: u64 = 0x20_0000;
const CODE: u64 = 0x1_0000;
const MMIO: u64 = 0x4000_0080;
const SEED: u64 = 0x1122_3344_5566_7788;
const MARKER: u64 = 0xa1b2_c3d4_e5f6_0718;

fn word(memory: &GuestMemoryWrapper, address: u64, value: u64) {
    memory
        .memory()
        .write_slice(&value.to_le_bytes(), GuestAddress(address))
        .unwrap();
}

fn guest_memory(instruction: &[u8]) -> GuestMemoryWrapper {
    let memory = GuestMemoryWrapper::new(RAM).unwrap();
    // Four-level identity translation for RAM and the unmapped MMIO address.
    word(&memory, 0x1000, 0x2003);
    for gigabyte in 0..2 {
        let directory = 0x3000 + gigabyte * 0x1000;
        word(&memory, 0x2000 + gigabyte * 8, directory | 3);
        for page in 0..512 {
            word(
                &memory,
                directory + page * 8,
                (gigabyte << 30) | (page << 21) | 0x83,
            );
        }
    }
    word(&memory, 0x9008, 0x00af_9b00_0000_ffff);
    word(&memory, 0x9010, 0x00cf_9300_0000_ffff);
    word(&memory, 0x9018, 0x0000_8b00_8000_0067);
    word(&memory, 0x8004, RAM - 0x1000);
    memory
        .memory()
        .write_slice(&0x68u16.to_le_bytes(), GuestAddress(0x8066))
        .unwrap();
    let mut code = instruction.to_vec();
    code.extend([0x49, 0xba]); // MOV R10, imm64: executed after MMIO completion.
    code.extend(MARKER.to_le_bytes());
    code.push(0xf4); // HLT
    memory
        .memory()
        .write_slice(&code, GuestAddress(CODE))
        .unwrap();
    memory
}

fn initial() -> CpuState {
    let mut state = X86_64CpuState::default();
    state.regs.rip = CODE;
    state.regs.rsp = RAM - 0x1000;
    state.regs.rflags = 2;
    state.regs.rax = SEED;
    state.regs.rdi = MMIO;
    state.sregs.cs = Segment {
        selector: 8,
        limit: u32::MAX,
        type_: 11,
        present: true,
        s: true,
        l: true,
        g: true,
        ..Default::default()
    };
    let data = Segment {
        selector: 16,
        limit: u32::MAX,
        type_: 3,
        present: true,
        s: true,
        db: true,
        g: true,
        ..Default::default()
    };
    state.sregs.ds = data.clone();
    state.sregs.es = data.clone();
    state.sregs.ss = data.clone();
    state.sregs.fs = data.clone();
    state.sregs.gs = data;
    state.sregs.tr = Segment {
        selector: 24,
        base: 0x8000,
        limit: 0x67,
        type_: 11,
        present: true,
        ..Default::default()
    };
    state.sregs.ldt.unusable = true;
    state.sregs.gdt.base = 0x9000;
    state.sregs.gdt.limit = 47;
    state.sregs.cr0 = 0x8001_0033;
    state.sregs.cr3 = 0x1000;
    state.sregs.cr4 = 0x220;
    state.sregs.efer = 0x500;
    state.sregs.dr6 = 0xffff_0ff0;
    state.sregs.dr7 = 0x400;
    CpuState::X86_64(state)
}

fn machine(memory: &GuestMemoryWrapper) -> (Box<dyn Vm>, Box<dyn VCpu>) {
    let backend = HvfBackend::new().unwrap();
    let vm = backend.create_vm().unwrap();
    vm.as_any()
        .downcast_ref::<HvfVm>()
        .unwrap()
        .register_memory(memory)
        .unwrap();
    vm.configure_cpu_topology(1, RAM).unwrap();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    cpu.set_state(&initial()).unwrap();
    (vm, cpu)
}

fn state(cpu: &dyn VCpu) -> X86_64CpuState {
    let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
        panic!("non-x86 state")
    };
    state
}

fn event(cpu: &mut dyn VCpu) -> VcpuExit {
    for _ in 0..100 {
        if let Some(exit) = cpu.run_host_slice(Duration::from_millis(100)).unwrap() {
            return exit;
        }
    }
    panic!(
        "no guest exit after 100 bounded entries; state={:#x?}",
        cpu.get_state()
    );
}

fn halted(cpu: &mut dyn VCpu, instruction_length: usize, expected_rax: u64) {
    let exit = event(cpu);
    assert!(
        matches!(exit, VcpuExit::Hlt),
        "guest did not reach HLT: {exit:?}; state={:#x?}",
        cpu.get_state()
    );
    let state = state(cpu);
    assert_eq!(state.regs.rip, CODE + instruction_length as u64 + 11);
    assert_eq!(state.regs.r10, MARKER, "post-transaction guest marker");
    assert_eq!(state.regs.rax, expected_rax);
    assert_eq!(state.regs.rdi, MMIO);
    assert_eq!(state.regs.rflags, 2);
}

fn record(output: &Path, case: usize, name: &str, width: usize, value: u64) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(output)
        .unwrap();
    writeln!(file, "{{\"case\":{case},\"name\":\"{name}\",\"width\":{width},\"value\":{value},\"passed\":true}}").unwrap();
}

fn patterns(width: usize) -> [u64; 6] {
    let mask = u64::MAX >> (64 - width * 8);
    let sign = 1u64 << (width * 8 - 1);
    [0, 1, mask, sign, sign - 1, 0x8877_6655_4433_2211 & mask]
}

fn read_case(instruction: &[u8], width: usize, value: u64, expected: u64) {
    let memory = guest_memory(instruction);
    let (vm, mut cpu) = machine(&memory);
    let pending = event(&mut *cpu);
    assert!(
        matches!(pending, VcpuExit::MmioRead { addr: MMIO, size } if usize::from(size) == width),
        "unexpected read exit: {pending:?}"
    );
    assert!(
        cpu.get_state().is_err(),
        "pending input must block public state projection"
    );
    assert!(cpu.io_completion_result().is_err());
    assert_eq!(format!("{:?}", event(&mut *cpu)), format!("{pending:?}"));
    let payload = value.to_le_bytes();
    cpu.complete_io_in(&payload[..width]);
    cpu.io_completion_result().unwrap();
    assert_eq!(state(&*cpu).regs.rip, CODE + instruction.len() as u64);
    assert_eq!(state(&*cpu).regs.rax, expected);
    halted(&mut *cpu, instruction.len(), expected);
    drop(cpu);
    drop(vm);
}

fn main() {
    let output = std::path::PathBuf::from(std::env::args_os().nth(1).expect("observations path"));
    assert!(!output.exists(), "observations must be new");
    let mut case = 0;
    // This independent RAM-only entry distinguishes invalid setup from MMIO defects.
    let memory = guest_memory(&[]);
    let (vm, mut cpu) = machine(&memory);
    halted(&mut *cpu, 0, SEED);
    drop(cpu);
    drop(vm);
    record(&output, case, "ram-control", 0, MARKER);
    case += 1;
    for (width, load, store) in [
        (1, &b"\x8a\x07"[..], &b"\x88\x07"[..]),
        (2, &b"\x66\x8b\x07"[..], &b"\x66\x89\x07"[..]),
        (4, &b"\x8b\x07"[..], &b"\x89\x07"[..]),
        (8, &b"\x48\x8b\x07"[..], &b"\x48\x89\x07"[..]),
    ] {
        for value in patterns(width) {
            let mask = u64::MAX >> (64 - width * 8);
            let expected = if width < 4 {
                (SEED & !mask) | value
            } else {
                value
            };
            read_case(load, width, value, expected);
            record(&output, case, "mov-load", width, value);
            case += 1;
            let memory = guest_memory(store);
            let (vm, mut cpu) = machine(&memory);
            let mut input = initial();
            let CpuState::X86_64(ref mut input_state) = input else {
                unreachable!()
            };
            input_state.regs.rax = value;
            cpu.set_state(&input).unwrap();
            let pending = event(&mut *cpu);
            assert!(
                matches!(&pending, VcpuExit::MmioWrite { addr: MMIO, data } if data == &value.to_le_bytes()[..width]),
                "unexpected write exit: {pending:?}"
            );
            assert!(
                cpu.get_state().is_err(),
                "pending output must block public state projection"
            );
            assert!(cpu.io_completion_result().is_err());
            assert_eq!(format!("{:?}", event(&mut *cpu)), format!("{pending:?}"));
            cpu.complete_io_out().unwrap();
            assert_eq!(state(&*cpu).regs.rip, CODE + store.len() as u64);
            halted(&mut *cpu, store.len(), value);
            drop(cpu);
            drop(vm);
            record(&output, case, "mov-store", width, value);
            case += 1;
        }
    }
    for (name, instruction, width, signed, wide) in [
        ("movzx32-byte", &b"\x0f\xb6\x07"[..], 1, false, false),
        ("movzx32-word", &b"\x0f\xb7\x07"[..], 2, false, false),
        ("movzx64-byte", &b"\x48\x0f\xb6\x07"[..], 1, false, true),
        ("movzx64-word", &b"\x48\x0f\xb7\x07"[..], 2, false, true),
        ("movsx32-byte", &b"\x0f\xbe\x07"[..], 1, true, false),
        ("movsx32-word", &b"\x0f\xbf\x07"[..], 2, true, false),
        ("movsx64-byte", &b"\x48\x0f\xbe\x07"[..], 1, true, true),
        ("movsx64-word", &b"\x48\x0f\xbf\x07"[..], 2, true, true),
        ("movsxd64", &b"\x48\x63\x07"[..], 4, true, true),
    ] {
        for value in patterns(width) {
            let mut expected = value;
            if signed && value & (1 << (width * 8 - 1)) != 0 {
                expected |= u64::MAX << (width * 8);
            }
            if !wide {
                expected &= u64::from(u32::MAX);
            }
            read_case(instruction, width, value, expected);
            record(&output, case, name, width, value);
            case += 1;
        }
    }
    for (width, instruction) in [
        (1, &b"\x8a\x07"[..]),
        (2, &b"\x66\x8b\x07"[..]),
        (4, &b"\x8b\x07"[..]),
        (8, &b"\x48\x8b\x07"[..]),
    ] {
        let mut lengths = vec![0, width - 1, width + 2];
        lengths.sort_unstable();
        lengths.dedup();
        for length in lengths {
            let memory = guest_memory(instruction);
            let (vm, mut cpu) = machine(&memory);
            let pending = event(&mut *cpu);
            assert!(
                matches!(pending, VcpuExit::MmioRead { addr: MMIO, size } if usize::from(size) == width)
            );
            cpu.complete_io_in(&vec![0xa5; length]);
            assert!(
                cpu.io_completion_result().is_err(),
                "malformed reply must fail"
            );
            assert!(cpu.get_state().is_err());
            assert!(cpu.run_host_slice(Duration::from_millis(100)).is_err());
            cpu.complete_io_in(&vec![0; width]);
            assert!(
                cpu.io_completion_result().is_err(),
                "completion failure must remain latched"
            );
            assert!(cpu.run_host_slice(Duration::from_millis(100)).is_err());
            drop(cpu);
            drop(vm);
            record(&output, case, "invalid-reply-denied", width, length as u64);
            case += 1;
        }
    }
    assert_eq!(case, 114);
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}
