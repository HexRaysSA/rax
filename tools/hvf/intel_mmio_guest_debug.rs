//! Actual guest #DB delivery after scalar EPT completion, including new owners.
use super::*;

const OBSERVATIONS: u64 = 0xa000;
const DEBUG_HANDLER: u64 = 0xb000;
const ASYNC_HANDLER: u64 = 0xb100;
const IDT: u64 = 0xc000;

fn store_rax(code: &mut Vec<u8>, address: u64) {
    code.extend([0x48, 0x89, 0x04, 0x25]); // MOV [abs32],RAX.
    code.extend((address as u32).to_le_bytes());
}

fn handler() -> Vec<u8> {
    let mut code = vec![0x50, 0x48, 0xff, 0x04, 0x25]; // PUSH RAX; INC [abs32].
    code.extend((OBSERVATIONS as u32).to_le_bytes());
    // After PUSH RAX the interrupted RIP and RFLAGS are at RSP+8 and RSP+24.
    for (offset, address) in [(8, OBSERVATIONS + 8), (24, OBSERVATIONS + 16)] {
        code.extend([0x48, 0x8b, 0x44, 0x24, offset]);
        store_rax(&mut code, address);
    }
    code.extend([0x4c, 0x89, 0x14, 0x25]); // MOV [abs32],R10: next instruction not run.
    code.extend(((OBSERVATIONS + 24) as u32).to_le_bytes());
    code.extend([0x0f, 0x21, 0xf0]); // MOV RAX,DR6.
    store_rax(&mut code, OBSERVATIONS + 32);
    code.extend([
        0x48, 0x81, 0x64, 0x24, 24, 0xff, 0xfe, 0xff, 0xff, // Clear saved TF.
        0x58, // POP RAX.
        0x48, 0xcf, // IRETQ.
    ]);
    code
}

fn async_handler() -> Vec<u8> {
    let mut code = vec![0x48, 0xff, 0x04, 0x25]; // INC count.
    code.extend(((OBSERVATIONS + 40) as u32).to_le_bytes());
    code.extend([0x48, 0x8b, 0x04, 0x25]); // Observe that #DB already ran.
    code.extend((OBSERVATIONS as u32).to_le_bytes());
    store_rax(&mut code, OBSERVATIONS + 48);
    code.push(0xf4);
    code
}

fn gate(memory: &GuestMemoryWrapper, vector: u64, address: u64) {
    let descriptor =
        (address & 0xffff) | (8 << 16) | (0x8e << 40) | (((address >> 16) & 0xffff) << 48);
    word(memory, IDT + vector * 16, descriptor);
    word(memory, IDT + vector * 16 + 8, address >> 32);
}

fn restored_owner(
    vm: Box<dyn Vm>,
    cpu: Box<dyn VCpu>,
    memory: &GuestMemoryWrapper,
    host_step: bool,
) -> (Box<dyn Vm>, Box<dyn VCpu>) {
    let boundary = vm.checkpoint_boundary().unwrap();
    let (saved, private) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
    let private = private.expect("native private record");
    let encoded =
        rax::codec::serialize(&(saved.state, saved.emulator, private.kind, private.data)).unwrap();
    drop(boundary);
    drop(cpu);
    drop(vm);
    let (vm, mut cpu) = machine(memory);
    cpu.set_single_step(host_step);
    let (state, emulator, kind, data): (CpuState, rax::vm::snapshot::EmulatorState, u32, Vec<u8>) =
        rax::codec::deserialize_strict(&encoded).unwrap();
    let private = rax::vm::snapshot::BackendContext { kind, data };
    cpu.restore_checkpoint_context(&state, &emulator, Some(&private))
        .unwrap();
    (vm, cpu)
}

fn scenario(code: &[u8], action: usize, host_step: bool, restore: usize, nmi: bool) -> [u64; 7] {
    let memory = guest_memory(code);
    gate(&memory, 1, DEBUG_HANDLER);
    gate(&memory, if nmi { 2 } else { 0x51 }, ASYNC_HANDLER);
    memory
        .memory()
        .write_slice(&handler(), GuestAddress(DEBUG_HANDLER))
        .unwrap();
    memory
        .memory()
        .write_slice(&async_handler(), GuestAddress(ASYNC_HANDLER))
        .unwrap();
    let (mut vm, mut cpu) = machine(&memory);
    let mut input = initial();
    let CpuState::X86_64(ref mut guest) = input else {
        unreachable!()
    };
    guest.regs.rax = 2;
    guest.regs.rflags = 0x1_0302; // Guest TF/IF and RF; no host TF control.
    guest.sregs.idt.base = IDT;
    guest.sregs.idt.limit = 4095;
    cpu.set_state(&input).unwrap();
    cpu.set_single_step(host_step);
    let exit = event(cpu.as_mut());
    assert!(
        matches!(
            exit,
            VcpuExit::MmioRead {
                addr: MMIO,
                size: 8
            } | VcpuExit::MmioWrite { addr: MMIO, .. }
                | VcpuExit::MmioRmw {
                    addr: MMIO,
                    size: 8,
                    ..
                }
        ),
        "{exit:?}"
    );
    assert_eq!(read_word(&memory, OBSERVATIONS), 0);
    assert!(
        cpu.get_state().is_err(),
        "pending device effect exposes no retired state"
    );
    assert!(!cpu.inject_interrupt(0x51).unwrap());
    assert!(!cpu.inject_nmi().unwrap());
    if restore == 1 {
        (vm, cpu) = restored_owner(vm, cpu, &memory, host_step);
        assert_eq!(format!("{:?}", event(cpu.as_mut())), format!("{exit:?}"));
    }
    match &exit {
        VcpuExit::MmioWrite { data, .. } => {
            assert_eq!(data, &2u64.to_le_bytes());
            cpu.complete_io_out().unwrap();
        }
        VcpuExit::MmioRead { .. } => cpu.complete_io_in(&5u64.to_le_bytes()),
        VcpuExit::MmioRmw { operation, .. } => {
            let mut value = 5u64.to_le_bytes();
            operation.apply(&mut value).unwrap();
            assert_eq!(u64::from_le_bytes(value), if action == 4 { 7 } else { 10 });
            cpu.complete_io_in(&5u64.to_le_bytes());
        }
        _ => unreachable!(),
    }
    cpu.io_completion_result().unwrap();
    if restore == 2 {
        (vm, cpu) = restored_owner(vm, cpu, &memory, host_step);
    }
    assert_eq!(state(cpu.as_ref()).regs.rip, CODE + code.len() as u64);
    assert_eq!(state(cpu.as_ref()).regs.rflags & 0x1_0300, 0x300);
    assert!(!cpu.can_inject_interrupt());
    assert!(!cpu.inject_interrupt(0x51).unwrap());
    assert!(!cpu.inject_nmi().unwrap());
    if host_step {
        assert!(matches!(event(cpu.as_mut()), VcpuExit::GdbStep));
        assert_eq!(read_word(&memory, OBSERVATIONS), 0);
        assert_eq!(state(cpu.as_ref()).regs.rip, CODE + code.len() as u64);
        cpu.set_single_step(false);
        assert!(!cpu.inject_nmi().unwrap());
    }
    assert!(matches!(event(cpu.as_mut()), VcpuExit::Hlt));
    let observed: [u64; 7] =
        std::array::from_fn(|i| read_word(&memory, OBSERVATIONS + i as u64 * 8));
    assert_eq!(observed[0], 1, "one actual guest #DB");
    assert_eq!(
        observed[1],
        CODE + code.len() as u64,
        "trap follows the MMIO instruction"
    );
    assert_eq!(observed[2] & 0x1_0300, 0x300, "saved TF/IF, cleared RF");
    assert_eq!(
        observed[3], 0,
        "post-MMIO marker has not executed before #DB"
    );
    assert_eq!(
        observed[4] & 0x400f,
        0x4000,
        "DR6.BS without data breakpoint causes"
    );
    assert_eq!(
        (observed[5], observed[6]),
        (0, 0),
        "caller still owns the deferred asynchronous event"
    );
    let retired = state(cpu.as_ref());
    assert_eq!(
        retired.regs.rax,
        if action == 0 {
            5
        } else if action == 2 {
            7
        } else {
            2
        }
    );
    assert_eq!(retired.regs.r10, MARKER);
    assert_eq!(retired.regs.rflags & 0x100, 0);
    assert!(if nmi {
        cpu.inject_nmi().unwrap()
    } else {
        cpu.inject_interrupt(0x51).unwrap()
    });
    assert!(matches!(event(cpu.as_mut()), VcpuExit::Hlt));
    assert_eq!(read_word(&memory, OBSERVATIONS + 40), 1);
    assert_eq!(
        read_word(&memory, OBSERVATIONS + 48),
        1,
        "#DB precedes IRQ/NMI delivery"
    );
    drop(cpu);
    drop(vm);
    observed
}

pub(super) fn run(output: &Path, case: &mut usize) {
    let encodings: &[&[u8]] = &[
        &[0x48, 0x8b, 0x07],          // MOV RAX,[RDI].
        &[0x48, 0x89, 0x07],          // MOV [RDI],RAX.
        &[0x48, 0x03, 0x07],          // ADD RAX,[RDI].
        &[0x48, 0x3b, 0x07],          // CMP RAX,[RDI].
        &[0x48, 0x01, 0x07],          // ADD [RDI],RAX.
        &[0x48, 0xc1, 0x27, 1],       // SHL qword [RDI],1.
        &[0x48, 0x0f, 0xa4, 0x07, 1], // SHLD qword [RDI],RAX,1.
    ];
    for (action, code) in encodings.iter().enumerate() {
        for host_step in [false, true] {
            for restore in 0..3 {
                for nmi in [false, true] {
                    let observed = scenario(code, action, host_step, restore, nmi);
                    let mut file = OpenOptions::new().append(true).open(output).unwrap();
                    writeln!(file, "{{\"case\":{},\"name\":\"mmio-guest-debug-priority\",\"action\":{action},\"host_step\":{host_step},\"restore_phase\":{restore},\"nmi\":{nmi},\"guest_debug\":{observed:?},\"passed\":true}}", *case).unwrap();
                    *case += 1;
                }
            }
        }
    }
}
