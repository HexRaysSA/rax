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

fn read_word(memory: &GuestMemoryWrapper, address: u64) -> u64 {
    let mut bytes = [0; 8];
    memory
        .memory()
        .read_slice(&mut bytes, GuestAddress(address))
        .unwrap();
    u64::from_le_bytes(bytes)
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

fn pat_case(pat: u64, restore: bool) {
    let mut instruction = vec![0xb9]; // MOV ECX, IA32_PAT.
    instruction.extend(0x277u32.to_le_bytes());
    instruction.push(0xb8); // MOV EAX, low32.
    instruction.extend((pat as u32).to_le_bytes());
    instruction.push(0xba); // MOV EDX, high32.
    instruction.extend(((pat >> 32) as u32).to_le_bytes());
    instruction.extend([0x0f, 0x30]); // WRMSR.
    if restore {
        instruction.push(0xf4); // Private CPU checkpoint before RDMSR.
    }
    instruction.extend([0x0f, 0x32]); // RDMSR.
    let memory = guest_memory(&instruction);
    let (mut vm, mut cpu) = machine(&memory);
    if restore {
        assert!(matches!(event(cpu.as_mut()), VcpuExit::Hlt));
        assert_eq!(state(cpu.as_ref()).regs.rip, CODE + 18);
        let boundary = vm.checkpoint_boundary().unwrap();
        let (saved, private) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
        assert_eq!(saved.emulator.pat, pat);
        drop(boundary);
        drop(cpu);
        drop(vm);
        (vm, cpu) = machine(&memory);
        cpu.restore_checkpoint_context(&saved.state, &saved.emulator, private.as_ref())
            .unwrap();
        cpu.wake();
    }
    halted(cpu.as_mut(), instruction.len(), pat & 0xffff_ffff);
    assert_eq!(state(cpu.as_ref()).regs.rdx, pat >> 32);
    assert_eq!(cpu.get_emulator_state().unwrap().pat, pat);
    drop(cpu);
    drop(vm);
}

fn msr_fault_handler(observations: u32) -> Vec<u8> {
    let mut handler = vec![0x50, 0x48, 0xff, 0x04, 0x25]; // PUSH RAX; INC qword [abs32].
    handler.extend(observations.to_le_bytes());
    // After PUSH RAX: saved RAX at RSP, error code at RSP+8, fault RIP at RSP+16.
    for (offset, address) in [
        (8, observations + 8),
        (16, observations + 16),
        (0, observations + 24),
    ] {
        handler.extend([0x48, 0x8b, 0x44, 0x24, offset]); // MOV RAX,[RSP+disp8].
        handler.extend([0x48, 0x89, 0x04, 0x25]); // MOV [abs32],RAX.
        handler.extend(address.to_le_bytes());
    }
    handler.extend([0x48, 0x89, 0x14, 0x25]); // MOV [abs32],RDX.
    handler.extend((observations + 32).to_le_bytes());
    handler.extend([
        0x48, 0x83, 0x44, 0x24, 0x10, 2,    // ADD qword [RSP+16],2: skip the faulting MSR.
        0x58, // POP RAX.
        0x48, 0x83, 0xc4, 8, // Discard the error code.
        0x48, 0xcf, // IRETQ.
    ]);
    handler
}

fn reserved_msr_case(msr: u32, write: bool) -> [u64; 5] {
    const OBSERVATIONS: u64 = 0xa000;
    const HANDLER: u64 = 0xb000;
    const IDT: u64 = 0xc000;
    const RDX: u64 = 0x8877_6655_4433_2211;
    let instruction = [0x0f, if write { 0x30 } else { 0x32 }];
    let memory = guest_memory(&instruction);
    // #GP gate: 64-bit interrupt gate, selector8, IST0, reserved fields zero.
    let gate = (HANDLER & 0xffff) | (8 << 16) | (0x8e << 40) | (((HANDLER >> 16) & 0xffff) << 48);
    word(&memory, IDT + 13 * 16, gate);
    word(&memory, IDT + 13 * 16 + 8, HANDLER >> 32);
    let handler = msr_fault_handler(OBSERVATIONS as u32);
    memory
        .memory()
        .write_slice(&handler, GuestAddress(HANDLER))
        .unwrap();
    let (vm, mut cpu) = machine(&memory);
    let mut input = initial();
    let CpuState::X86_64(ref mut input_state) = input else {
        unreachable!()
    };
    input_state.regs.rcx = u64::from(msr);
    input_state.regs.rdx = RDX;
    input_state.sregs.idt.base = IDT;
    input_state.sregs.idt.limit = 4095;
    cpu.set_state(&input).unwrap();
    halted(cpu.as_mut(), instruction.len(), SEED);
    assert_eq!(state(cpu.as_ref()).regs.rdx, RDX);
    let observed = std::array::from_fn(|index| read_word(&memory, OBSERVATIONS + index as u64 * 8));
    assert_eq!(observed, [1, 0, CODE, SEED, RDX]);
    drop(cpu);
    drop(vm);
    observed
}

fn record_msr_fault(output: &Path, case: usize, msr: u32, write: bool, observed: [u64; 5]) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(output)
        .unwrap();
    writeln!(file, "{{\"case\":{case},\"name\":\"reserved-msr-gp\",\"msr\":{msr},\"write\":{write},\"fault_count\":{},\"error\":{},\"fault_rip\":{},\"saved_rax\":{},\"saved_rdx\":{},\"passed\":true}}", observed[0], observed[1], observed[2], observed[3], observed[4]).unwrap();
}

mod deadline {
    use super::*;
    use rax::devices::bus::MmioDevice;
    use rax::devices::lapic::{LAPIC_BASE, LAPIC_SIZE, LapicDevice, LocalApic};
    use std::sync::Mutex;

    const OBS: u64 = 0xa000;
    const IDT: u64 = 0xb000;
    const HANDLER: u64 = 0xc000;
    const VECTOR: u8 = 0x51;

    fn store_register(code: &mut Vec<u8>, register: u8, address: u64) {
        code.extend([0x89, 0x04 | (register << 3), 0x25]);
        code.extend((address as u32).to_le_bytes());
    }

    fn store_pair(code: &mut Vec<u8>, address: u64) {
        store_register(code, 0, address); // MOV [abs32],EAX.
        store_register(code, 2, address + 4); // MOV [abs32+4],EDX.
    }

    fn write_msr(code: &mut Vec<u8>, index: u32, value: u64) {
        code.push(0xb9);
        code.extend(index.to_le_bytes());
        code.push(0xb8);
        code.extend((value as u32).to_le_bytes());
        code.push(0xba);
        code.extend(((value >> 32) as u32).to_le_bytes());
        code.extend([0x0f, 0x30]);
    }

    fn read_msr(code: &mut Vec<u8>, index: u32, address: u64) {
        code.push(0xb9);
        code.extend(index.to_le_bytes());
        code.extend([0x0f, 0x32]);
        store_pair(code, address);
    }

    fn write_apic(code: &mut Vec<u8>, offset: u64, value: u32) {
        code.extend([0x48, 0xbf]); // MOV RDI,absolute APIC register.
        code.extend((LAPIC_BASE + offset).to_le_bytes());
        code.extend([0xc7, 0x07]); // MOV dword [RDI],imm32.
        code.extend(value.to_le_bytes());
        code.extend([0x0f, 0xae, 0xf0]); // MFENCE orders xAPIC before WRMSR.
    }

    fn memory(code: &[u8]) -> GuestMemoryWrapper {
        let memory = guest_memory(code);
        // Also translate the high MMIO gigabytes containing the xAPIC page.
        for gigabyte in 2..4 {
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
        memory
    }

    fn attach(cpu: &mut dyn VCpu) -> (Arc<Mutex<LocalApic>>, LapicDevice) {
        let model = Arc::new(Mutex::new(LocalApic::new(0)));
        cpu.attach_local_apic(model.clone());
        (model.clone(), LapicDevice::new(model))
    }

    /// Service the actual public exits, without holding a model lock across
    /// a CPU call. Clock sampling precedes each observed MMIO state change.
    fn halt(cpu: &mut dyn VCpu, bus: &mut LapicDevice) {
        for _ in 0..128 {
            cpu.poll_vm_clock().unwrap();
            let exit = event(cpu);
            cpu.poll_vm_clock().unwrap();
            match exit {
                VcpuExit::MmioWrite { addr, data }
                    if (LAPIC_BASE..LAPIC_BASE + LAPIC_SIZE).contains(&addr) =>
                {
                    bus.write(addr, &data);
                    cpu.complete_io_out().unwrap();
                }
                VcpuExit::MmioRead { addr, size }
                    if (LAPIC_BASE..LAPIC_BASE + LAPIC_SIZE).contains(&addr) =>
                {
                    let mut bytes = vec![0; usize::from(size)];
                    bus.read(addr, &mut bytes);
                    cpu.complete_io_in(&bytes);
                    cpu.io_completion_result().unwrap();
                }
                VcpuExit::Hlt => return,
                other => panic!(
                    "deadline guest exit: {other:?}; state={:?}",
                    cpu.get_state()
                ),
            }
        }
        panic!("deadline guest exceeded its bounded exit inventory");
    }

    fn complete(cpu: &dyn VCpu, length: usize) {
        let final_state = state(cpu);
        assert_eq!(final_state.regs.r10, MARKER);
        assert_eq!(final_state.regs.rip, CODE + length as u64 + 11);
    }

    pub(super) fn scenario(scenario: u32) {
        let mut code = vec![0xb8, 1, 0, 0, 0, 0x31, 0xc9, 0x0f, 0xa2];
        store_register(&mut code, 1, OBS + 32); // Actual guest CPUID.1:ECX.
        let lvt = match scenario {
            0 => 0x51,
            1 => 0x20051,
            9 | 10 => 0x50051,
            _ => 0x40051,
        };
        write_apic(&mut code, 0x320, lvt);
        write_msr(&mut code, 0x6e0, if scenario >= 8 { 1 } else { u64::MAX });
        match scenario {
            3 => write_msr(&mut code, 0x6e0, 0),
            4 => write_apic(&mut code, 0x320, 0x51),
            5 => write_apic(&mut code, 0x320, 0x20051),
            6 => write_apic(&mut code, 0x380, 0x1234_5678),
            7 => write_apic(&mut code, 0x320, 0x50061),
            _ => (),
        }
        read_msr(&mut code, 0x6e0, OBS);
        code.extend([0x48, 0xbf]);
        code.extend((LAPIC_BASE + 0x390).to_le_bytes());
        code.extend([0x8b, 0x07]); // Current count must remain zero in deadline mode.
        store_register(&mut code, 0, OBS + 8);
        code.extend([0x0f, 0x31]);
        store_pair(&mut code, OBS + 16);
        if scenario == 10 {
            write_apic(&mut code, 0x320, 0x40051);
        }
        read_msr(&mut code, 0x6e0, OBS + 24);
        let memory = memory(&code);
        let (vm, mut cpu) = machine(&memory);
        let (model, mut bus) = attach(cpu.as_mut());
        halt(cpu.as_mut(), &mut bus);
        complete(cpu.as_ref(), code.len());
        let expected = if matches!(scenario, 2 | 6 | 7) {
            u64::MAX
        } else {
            0
        };
        assert_eq!(read_word(&memory, OBS), expected, "scenario {scenario}");
        assert_eq!(read_word(&memory, OBS + 24), expected);
        assert_eq!(read_word(&memory, OBS + 8) as u32, 0);
        assert_ne!(read_word(&memory, OBS + 32) as u32 & (1 << 24), 0);
        assert!(read_word(&memory, OBS + 16) > 1);
        assert_eq!(
            model.lock().unwrap().get_pending_vector(),
            (scenario == 8).then_some(VECTOR)
        );
        if scenario == 6 {
            let mut initial = [0; 4];
            bus.read(LAPIC_BASE + 0x380, &mut initial);
            assert_eq!(
                u32::from_le_bytes(initial),
                0,
                "initial-count write was ignored"
            );
        }
        drop(cpu);
        drop(vm);
    }

    pub(super) fn restore_armed(value: u64) {
        let mut code = Vec::new();
        write_apic(&mut code, 0x320, 0x40051);
        write_msr(&mut code, 0x6e0, value);
        code.push(0xf4);
        let boundary_pc = CODE + code.len() as u64;
        read_msr(&mut code, 0x6e0, OBS);
        let memory = memory(&code);
        let (vm, mut cpu) = machine(&memory);
        let (_, mut bus) = attach(cpu.as_mut());
        halt(cpu.as_mut(), &mut bus);
        assert_eq!(state(cpu.as_ref()).regs.rip, boundary_pc);
        let boundary = vm.checkpoint_boundary().unwrap();
        let (public, private) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
        drop(boundary);
        drop(cpu);
        drop(vm);
        let (vm, mut cpu) = machine(&memory);
        let (_, mut bus) = attach(cpu.as_mut());
        cpu.restore_checkpoint_context(&public.state, &public.emulator, private.as_ref())
            .unwrap();
        let mut lvt = [0; 4];
        bus.read(LAPIC_BASE + 0x320, &mut lvt);
        assert_eq!(
            u32::from_le_bytes(lvt),
            0x40051,
            "restored controller binding"
        );
        cpu.wake();
        halt(cpu.as_mut(), &mut bus);
        complete(cpu.as_ref(), code.len());
        assert_eq!(read_word(&memory, OBS), value);
        drop(cpu);
        drop(vm);
    }

    pub(super) fn wake(restore: bool) {
        let mut code = Vec::new();
        write_apic(&mut code, 0x320, 0x40051);
        write_msr(&mut code, 0x6e0, 1);
        code.extend([0xfb, 0xf4]); // STI; HLT: IRQ injection must wake this owner.
        let first_pc = CODE + code.len() as u64;
        read_msr(&mut code, 0x6e0, OBS);
        let memory = memory(&code);
        let gate =
            (HANDLER & 0xffff) | (8 << 16) | (0x8e << 40) | (((HANDLER >> 16) & 0xffff) << 48);
        word(&memory, IDT + u64::from(VECTOR) * 16, gate);
        word(&memory, IDT + u64::from(VECTOR) * 16 + 8, HANDLER >> 32);
        let mut handler = vec![0x50, 0x57, 0xff, 0x04, 0x25]; // PUSH RAX/RDI; INC dword [abs32].
        handler.extend(((OBS + 64) as u32).to_le_bytes());
        write_apic(&mut handler, 0xb0, 0); // Guest EOI through the same controller.
        handler.extend([0x5f, 0x58, 0x48, 0xcf]); // POP RDI/RAX; IRETQ.
        memory
            .memory()
            .write_slice(&handler, GuestAddress(HANDLER))
            .unwrap();
        let (mut vm, mut cpu) = machine(&memory);
        let mut input = initial();
        if let CpuState::X86_64(state) = &mut input {
            state.sregs.idt.base = IDT;
            state.sregs.idt.limit = 4095;
        }
        cpu.set_state(&input).unwrap();
        let (mut model, mut bus) = attach(cpu.as_mut());
        halt(cpu.as_mut(), &mut bus);
        assert_eq!(state(cpu.as_ref()).regs.rip, first_pc);
        assert_eq!(model.lock().unwrap().get_pending_vector(), Some(VECTOR));
        if restore {
            let saved_model = model.lock().unwrap().clone();
            let boundary = vm.checkpoint_boundary().unwrap();
            let (public, private) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
            drop(boundary);
            drop(cpu);
            drop(vm);
            (vm, cpu) = machine(&memory);
            model = Arc::new(Mutex::new(saved_model));
            cpu.attach_local_apic(model.clone());
            bus = LapicDevice::new(model.clone());
            cpu.restore_checkpoint_context(&public.state, &public.emulator, private.as_ref())
                .unwrap();
        }
        assert!(cpu.can_inject_interrupt());
        assert!(cpu.inject_interrupt(VECTOR).unwrap());
        model.lock().unwrap().ack_interrupt(VECTOR);
        halt(cpu.as_mut(), &mut bus);
        complete(cpu.as_ref(), code.len());
        assert_eq!(read_word(&memory, OBS), 0);
        assert_eq!(
            read_word(&memory, OBS + 64),
            1,
            "one guest IRQ handler execution"
        );
        assert_eq!(model.lock().unwrap().get_pending_vector(), None);
        let mut isr = [0; 4];
        bus.read(LAPIC_BASE + 0x120, &mut isr);
        assert_eq!(
            u32::from_le_bytes(isr),
            0,
            "guest EOI retires the in-service timer"
        );
        drop(cpu);
        drop(vm);
    }

    pub(super) fn tsc_domain() {
        let mut code = Vec::new();
        write_msr(&mut code, 0x10, 1_000_000);
        code.extend([0x0f, 0xae, 0xe8, 0x0f, 0x31, 0x0f, 0xae, 0xe8]); // LFENCE; RDTSC; LFENCE.
        store_pair(&mut code, OBS);
        read_msr(&mut code, 0x10, OBS + 8);
        code.extend([0x0f, 0xae, 0xe8, 0x0f, 0x31, 0x0f, 0xae, 0xe8]);
        store_pair(&mut code, OBS + 16);
        let memory = memory(&code);
        let (vm, mut cpu) = machine(&memory);
        let (_, mut bus) = attach(cpu.as_mut());
        halt(cpu.as_mut(), &mut bus);
        complete(cpu.as_ref(), code.len());
        let first = read_word(&memory, OBS);
        let middle = read_word(&memory, OBS + 8);
        let last = read_word(&memory, OBS + 16);
        assert!(
            1_000_000 <= first && first <= middle && middle <= last,
            "guest RDTSC/RDMSR/RDTSC domains differ: {first:#x}, {middle:#x}, {last:#x}"
        );
        drop(cpu);
        drop(vm);
    }
}

mod startup {
    use super::*;
    use rax::config::{ArchKind, BackendKind, CliConfig, MemorySize, VmConfig};
    use rax::vm::Vmm;
    use std::path::PathBuf;

    // GNU as2.42; 64-bit BSP, real-mode AP trampoline then protected-mode payload.
    // INIT/SIPI vector0x20 selects0x20000, away from the PC loader's page tables.
    const BSP: &[u8] = &[
        0xfa, 0xfc, 0xbe, 0x00, 0x12, 0x00, 0x01, 0xbf, 0x00, 0x00, 0x02, 0x00, 0xb9, 0x00, 0x01,
        0x00, 0x00, 0xf3, 0xa4, 0x48, 0xb8, 0xff, 0xff, 0x00, 0x00, 0x00, 0x9a, 0xcf, 0x00, 0x48,
        0x89, 0x04, 0x25, 0x08, 0x73, 0x00, 0x00, 0x48, 0xb8, 0xff, 0xff, 0x00, 0x00, 0x00, 0x92,
        0xcf, 0x00, 0x48, 0x89, 0x04, 0x25, 0x10, 0x73, 0x00, 0x00, 0x66, 0xc7, 0x04, 0x25, 0x00,
        0x72, 0x00, 0x00, 0x17, 0x00, 0xc7, 0x04, 0x25, 0x02, 0x72, 0x00, 0x00, 0x00, 0x73, 0x00,
        0x00, 0xb8, 0xaa, 0x00, 0x02, 0x00, 0x89, 0xc3, 0x81, 0xe3, 0xff, 0xff, 0x00, 0x00, 0x81,
        0xcb, 0x00, 0x00, 0x08, 0x00, 0x89, 0x1c, 0x25, 0x08, 0x02, 0x24, 0x00, 0x25, 0x00, 0x00,
        0xff, 0xff, 0x0d, 0x00, 0x8e, 0x00, 0x00, 0x89, 0x04, 0x25, 0x0c, 0x02, 0x24, 0x00, 0x66,
        0xc7, 0x04, 0x25, 0x10, 0x74, 0x00, 0x00, 0x0f, 0x02, 0xc7, 0x04, 0x25, 0x12, 0x74, 0x00,
        0x00, 0x00, 0x00, 0x24, 0x00, 0x31, 0xc0, 0x0f, 0xa2, 0x89, 0x04, 0x25, 0x00, 0x00, 0x23,
        0x00, 0xb8, 0x0b, 0x00, 0x00, 0x00, 0x31, 0xc9, 0x0f, 0xa2, 0x89, 0x14, 0x25, 0x04, 0x00,
        0x23, 0x00, 0x89, 0x1c, 0x25, 0x0c, 0x00, 0x23, 0x00, 0xb8, 0x1f, 0x00, 0x00, 0x00, 0x31,
        0xc9, 0x0f, 0xa2, 0x89, 0x14, 0x25, 0x08, 0x00, 0x23, 0x00, 0x89, 0x1c, 0x25, 0x10, 0x00,
        0x23, 0x00, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0xa2, 0xc1, 0xeb, 0x18, 0x89, 0x1c, 0x25,
        0x00, 0x00, 0x22, 0x00, 0xba, 0x00, 0x00, 0xe0, 0xfe, 0xc7, 0x82, 0xf0, 0x00, 0x00, 0x00,
        0xff, 0x01, 0x00, 0x00, 0xc7, 0x04, 0x25, 0x00, 0x00, 0x20, 0x00, 0x5a, 0x5a, 0xa5, 0xa5,
        0xc7, 0x82, 0x00, 0x03, 0x00, 0x00, 0x00, 0x45, 0x0c, 0x00, 0xe6, 0x80, 0xc7, 0x82, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x85, 0x0c, 0x00, 0xe6, 0x80, 0xc7, 0x82, 0x00, 0x03, 0x00, 0x00,
        0x20, 0x06, 0x0c, 0x00, 0xe6, 0x80, 0xbd, 0xe8, 0x03, 0x00, 0x00, 0x8b, 0x0c, 0x25, 0x00,
        0x00, 0x21, 0x00, 0x31, 0xdb, 0x81, 0x3c, 0xdd, 0x00, 0x00, 0x20, 0x00, 0x5a, 0x5a, 0xa5,
        0xa5, 0x75, 0x60, 0xff, 0xc3, 0x39, 0xcb, 0x72, 0xed, 0xbf, 0x01, 0x00, 0x00, 0x00, 0xc7,
        0x82, 0x00, 0x03, 0x00, 0x00, 0x41, 0x00, 0x0c, 0x00, 0xe6, 0x80, 0xbd, 0xe8, 0x03, 0x00,
        0x00, 0x8b, 0x0c, 0x25, 0x00, 0x00, 0x21, 0x00, 0xbb, 0x01, 0x00, 0x00, 0x00, 0x39, 0xcb,
        0x73, 0x20, 0x39, 0x3c, 0xdd, 0x04, 0x00, 0x20, 0x00, 0x75, 0x04, 0xff, 0xc3, 0xeb, 0xef,
        0xe6, 0x80, 0xff, 0xcd, 0x75, 0xdd, 0xc7, 0x04, 0x25, 0x04, 0x00, 0x21, 0x00, 0xd1, 0xba,
        0xd1, 0xba, 0xeb, 0x25, 0xff, 0xc7, 0x83, 0xff, 0x03, 0x72, 0xb8, 0xc7, 0x04, 0x25, 0x04,
        0x00, 0x21, 0x00, 0x0d, 0x60, 0x0d, 0x60, 0xeb, 0x11, 0xe6, 0x80, 0xff, 0xcd, 0x75, 0x84,
        0xc7, 0x04, 0x25, 0x04, 0x00, 0x21, 0x00, 0xd0, 0xba, 0xd0, 0xba, 0xba, 0x04, 0x06, 0x00,
        0x00, 0xb8, 0x00, 0x20, 0x00, 0x00, 0x66, 0xef, 0xf4,
    ];
    const AP: &[u8] = &[
        0xfa, 0x31, 0xc0, 0x8e, 0xd8, 0x8e, 0xc0, 0x8e, 0xd0, 0x66, 0x0f, 0x01, 0x16, 0x00, 0x72,
        0x0f, 0x20, 0xc0, 0x66, 0x83, 0xc8, 0x01, 0x0f, 0x22, 0xc0, 0x66, 0xea, 0x21, 0x00, 0x02,
        0x00, 0x08, 0x00, 0x66, 0xb8, 0x10, 0x00, 0x8e, 0xd8, 0x8e, 0xc0, 0x8e, 0xd0, 0x8b, 0x2d,
        0x20, 0x00, 0xe0, 0xfe, 0xc1, 0xed, 0x18, 0x89, 0xef, 0xc1, 0xe7, 0x05, 0x31, 0xc0, 0x0f,
        0xa2, 0x89, 0x87, 0x00, 0x00, 0x23, 0x00, 0xb8, 0x0b, 0x00, 0x00, 0x00, 0x31, 0xc9, 0x0f,
        0xa2, 0x89, 0x97, 0x04, 0x00, 0x23, 0x00, 0x89, 0x9f, 0x0c, 0x00, 0x23, 0x00, 0xb8, 0x1f,
        0x00, 0x00, 0x00, 0x31, 0xc9, 0x0f, 0xa2, 0x89, 0x97, 0x08, 0x00, 0x23, 0x00, 0x89, 0x9f,
        0x10, 0x00, 0x23, 0x00, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0xa2, 0xc1, 0xeb, 0x18, 0x89,
        0x1c, 0xad, 0x00, 0x00, 0x22, 0x00, 0xbc, 0x00, 0x00, 0x40, 0x00, 0x89, 0xe8, 0xc1, 0xe0,
        0x0c, 0x29, 0xc4, 0x0f, 0x01, 0x1d, 0x10, 0x74, 0x00, 0x00, 0xc7, 0x05, 0xf0, 0x00, 0xe0,
        0xfe, 0xff, 0x01, 0x00, 0x00, 0xc7, 0x04, 0xed, 0x00, 0x00, 0x20, 0x00, 0x5a, 0x5a, 0xa5,
        0xa5, 0xfb, 0xf4, 0xeb, 0xfd, 0x60, 0xff, 0x04, 0xed, 0x04, 0x00, 0x20, 0x00, 0xc7, 0x05,
        0xb0, 0x00, 0xe0, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x61, 0xcf,
    ];

    // LLVM23, docs/development/hvf-native-file-continuation/phase2.S.
    const PHASE2: &[u8] = &[
        0xba, 0x00, 0x00, 0xe0, 0xfe, 0xbf, 0x03, 0x00, 0x00, 0x00, 0xc7, 0x82, 0x00, 0x03, 0x00,
        0x00, 0x41, 0x00, 0x0c, 0x00, 0x0f, 0xae, 0xf0, 0xe6, 0x80, 0xbd, 0xe8, 0x03, 0x00, 0x00,
        0x8b, 0x0c, 0x25, 0x00, 0x00, 0x21, 0x00, 0xbb, 0x01, 0x00, 0x00, 0x00, 0x39, 0xcb, 0x73,
        0x20, 0x39, 0x3c, 0xdd, 0x04, 0x00, 0x20, 0x00, 0x75, 0x04, 0xff, 0xc3, 0xeb, 0xef, 0xe6,
        0x80, 0xff, 0xcd, 0x75, 0xdd, 0xc7, 0x04, 0x25, 0x04, 0x00, 0x21, 0x00, 0xd2, 0xba, 0xd2,
        0xba, 0xeb, 0x12, 0xff, 0xc7, 0x83, 0xff, 0x05, 0x72, 0xb5, 0xc7, 0x04, 0x25, 0x04, 0x00,
        0x21, 0x00, 0x0d, 0x70, 0x0d, 0x70, 0xba, 0x04, 0x06, 0x00, 0x00, 0xb8, 0x00, 0x20, 0x00,
        0x00, 0x66, 0xef, 0xf4,
    ];

    struct Kernel(PathBuf);
    impl Drop for Kernel {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn boot(count: u8) -> (Vmm, Kernel) {
        let path = std::env::temp_dir().join(format!(
            "rax-hvf-native-startup-{}-{count}",
            std::process::id()
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let kernel = Kernel(path);
        // Use the same guest bytes as the native Linux KVM VMM startup control.
        // The BSP copies the real-mode trampoline into the SIPI vector window.
        let mut image = vec![0; 0x200];
        image.extend_from_slice(BSP);
        image.resize(0x1200, 0);
        image.extend_from_slice(AP);
        image.resize(0x1300, 0);
        file.write_all(&image).unwrap();
        drop(file);
        let config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::X86_64),
                backend: Some(BackendKind::Hvf),
                vcpus: Some(count),
                memory: Some(MemorySize(128 * 1024 * 1024)),
                kernel: Some(kernel.0.clone()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        let mut vm = Vmm::new(config).unwrap();
        let read = |vm: &Vmm, address| -> u32 {
            vm.guest_mem()
                .memory()
                .read_obj(GuestAddress(address))
                .unwrap()
        };
        vm.guest_mem()
            .memory()
            .write_obj(u32::from(count), GuestAddress(0x210000))
            .unwrap();
        vm.run().unwrap();
        let marker = read(&vm, 0x210004);
        let flags: Vec<u32> = (0..count)
            .map(|id| read(&vm, 0x200000 + u64::from(id) * 8))
            .collect();
        let ipi_counts: Vec<u32> = (0..count)
            .map(|id| read(&vm, 0x200004 + u64::from(id) * 8))
            .collect();
        let ids: Vec<u32> = (0..count)
            .map(|id| read(&vm, 0x220000 + u64::from(id) * 4))
            .collect();
        println!(
            "native_vmm_cpus={count} marker={marker:#x} flags={flags:x?} ipi_counts={ipi_counts:?} cpuid_ids={ids:?}"
        );
        assert_eq!(
            marker, 0x600d600d,
            "BSP exhausted its guest wait for AP execution"
        );
        assert!(flags.iter().all(|flag| *flag == 0xa5a55a5a));
        assert_eq!(ipi_counts[0], 0);
        assert!(
            ipi_counts.iter().skip(1).all(|count| *count == 2),
            "each AP must wake, handle and EOI both fixed IPIs"
        );
        assert_eq!(ids, (0..u32::from(count)).collect::<Vec<_>>());
        for id in 0..count {
            let words: [u32; 5] = std::array::from_fn(|word| {
                read(&vm, 0x230000 + u64::from(id) * 32 + word as u64 * 4)
            });
            println!("native_vmm_cpu={id} topology_words={words:x?}");
            for (leaf, initial_id, logical_count) in
                [(0xb, words[1], words[3]), (0x1f, words[2], words[4])]
            {
                if words[0] >= leaf && logical_count & 0xffff != 0 {
                    assert_eq!(
                        initial_id,
                        u32::from(id),
                        "foreign APIC identity at leaf {leaf:#x}"
                    );
                }
            }
        }
        let states = vm.capture_cpu_states().unwrap();
        assert_eq!(states.len(), usize::from(count));
        for (id, state) in states.iter().enumerate() {
            println!("native_vmm_cpu={id} final_pc={:#x}", state.state.pc());
        }
        (vm, kernel)
    }

    pub(super) fn run(count: u8) {
        drop(boot(count));
    }

    pub(super) fn file_resume(count: u8, directory: &Path) {
        use rax::vm::snapshot::{HVF_INTEL_CONTEXT, SnapshotBundle};

        let (vm, kernel) = boot(count);
        let states = vm.capture_cpu_states().unwrap();
        let pc = states[0].state.pc();
        // The source has returned from ACPI output, before its next instruction.
        // Place new work at that saved PC before capture; restoration changes no
        // PC, counter, interrupt request or guest register in the host harness.
        vm.guest_mem()
            .memory()
            .write_slice(PHASE2, GuestAddress(pc))
            .unwrap();
        let saved = vm.take_snapshot_bundle(0).unwrap();
        for (id, cpu) in saved.cpus().unwrap().entries().iter().enumerate().skip(1) {
            assert!(
                cpu.emulator.halted,
                "{count}-CPU source AP{id} is active at PC={:#x}",
                cpu.state.pc()
            );
        }
        assert_eq!(
            saved.execution().unwrap().online(),
            vec![true; usize::from(count)]
        );
        assert!(saved.physical_memory().is_some() && saved.vm_context().is_some());
        let private = saved.backend_contexts().unwrap().entries();
        assert_eq!(private.len(), usize::from(count));
        for context in private {
            let context = context.as_ref().expect("missing native CPU record");
            assert_eq!(context.kind, HVF_INTEL_CONTEXT);
            assert_eq!(&context.data[..8], b"RAXHVI03");
        }
        let before = saved
            .cpus()
            .unwrap()
            .entries()
            .iter()
            .map(|cpu| rax::codec::serialize(&cpu.state).unwrap())
            .collect::<Vec<_>>();
        let checkpoint = directory.join(format!("native-vmm-continuation-{count}.rxc"));
        assert!(!checkpoint.exists(), "checkpoint path must be new");
        // Preserve the file on failure so the execution artifact retains it.
        saved.save(&checkpoint).unwrap();
        println!(
            "native_checkpoint_cpus={count} bytes={}",
            std::fs::metadata(&checkpoint).unwrap().len()
        );
        drop(saved);
        drop(states);
        drop(vm);
        let source_path = kernel.0.clone();
        drop(kernel);
        assert!(
            !source_path.exists(),
            "source kernel must be absent during restore"
        );
        let loaded = SnapshotBundle::load(&checkpoint).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
        let mut resumed = Vmm::new_resume_bundle(config, &loaded).unwrap();
        let after = resumed
            .capture_cpu_states()
            .unwrap()
            .iter()
            .map(|cpu| rax::codec::serialize(&cpu.state).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            after, before,
            "fresh native owners changed the captured CPU projections"
        );
        resumed.run().unwrap();
        let read = |address| -> u32 {
            resumed
                .guest_mem()
                .memory()
                .read_obj(GuestAddress(address))
                .unwrap()
        };
        let marker = read(0x210004);
        let counts = (0..count)
            .map(|id| read(0x200004 + u64::from(id) * 8))
            .collect::<Vec<_>>();
        println!(
            "native_restored_vmm_cpus={count} marker={marker:#x} ipi_counts={counts:?} source_kernel_absent={}",
            !source_path.exists()
        );
        assert_eq!(
            marker, 0x700d700d,
            "restored BSP exhausted its wait for new AP work"
        );
        assert_eq!(counts[0], 0);
        assert!(
            counts.iter().skip(1).all(|value| *value == 4),
            "every restored AP must handle two new IPIs and EOI them"
        );
        assert!(!source_path.exists());
        drop(resumed);
        drop(loaded);
        std::fs::remove_file(&checkpoint).unwrap();
    }
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
    for restore in [false, true] {
        for pat in [
            0,
            0x0101_0101_0101_0101,
            0x0405_0607_0001_0406,
            0x0007_0406_0007_0406,
        ] {
            pat_case(pat, restore);
            record(
                &output,
                case,
                if restore {
                    "pat-private-restore"
                } else {
                    "pat-guest-write-read"
                },
                8,
                pat,
            );
            case += 1;
        }
    }
    for msr in [0xffff_ffff, 0xffff_fffe, 0xdead_beef, 0x2000_0000] {
        for write in [false, true] {
            let observed = reserved_msr_case(msr, write);
            record_msr_fault(&output, case, msr, write, observed);
            case += 1;
        }
    }
    for scenario in 0..11 {
        deadline::scenario(scenario);
        record(
            &output,
            case,
            "deadline-mode-expiry",
            8,
            u64::from(scenario),
        );
        case += 1;
    }
    for value in [u64::MAX, u64::MAX - 1] {
        deadline::restore_armed(value);
        record(&output, case, "deadline-private-restore", 8, value);
        case += 1;
    }
    for restore in [false, true] {
        deadline::wake(restore);
        record(&output, case, "deadline-halt-irq", 8, u64::from(restore));
        case += 1;
    }
    deadline::tsc_domain();
    record(&output, case, "deadline-tsc-domain", 8, 1_000_000);
    case += 1;
    for count in [1, 2, 4] {
        startup::run(count);
        record(&output, case, "native-vmm-startup-ipi", 0, u64::from(count));
        case += 1;
    }
    for count in [1, 2, 4] {
        startup::file_resume(count, output.parent().expect("observations directory"));
        record(
            &output,
            case,
            "native-vmm-file-continuation",
            0,
            u64::from(count),
        );
        case += 1;
    }
    assert_eq!(case, 152);
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}
