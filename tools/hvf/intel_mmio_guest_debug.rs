//! Actual guest #DB after scalar EPT/port completion, including new owners.
use super::*;

const OBSERVATIONS: u64 = 0xa000;
const DEBUG_HANDLER: u64 = 0xb000;
const ASYNC_HANDLER: u64 = 0xb100;
const IDT: u64 = 0xc000;
const PORT: u16 = 0x3f8;
const PORT_RAX: u64 = 0x1234_5678_9abc_def0;

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
    code.extend([0x0f, 0x20, 0xe0]); // MOV RAX,CR4: actual guest-visible DE.
    store_rax(&mut code, OBSERVATIONS + 56);
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
    restored_owner_with_record(vm, cpu, memory, host_step, false, None)
}

fn old_record_tag(data: &mut [u8]) {
    let old = match &data[..8] {
        b"RAXHVI04" => *b"RAXHVI02",
        b"RAXHVI05" => *b"RAXHVI03",
        tag => panic!("unexpected current native producer: {tag:?}"),
    };
    data[..8].copy_from_slice(&old);
}

fn clear_pending_cause(data: &mut [u8], causes: u64) {
    // Register { id: u32, value: u64 } uses the legacy sequential codec.
    let field = rax::codec::serialize(&(0x6822u32, causes)).unwrap();
    assert_eq!(field.len(), 12);
    let matches: Vec<_> = data
        .windows(field.len())
        .enumerate()
        .filter(|(_, value)| *value == field.as_slice())
        .map(|(offset, _)| offset)
        .collect();
    assert_eq!(matches.len(), 1, "unique pending-debug VMCS field");
    let offset = matches[0] + 4;
    data[offset..offset + 8].copy_from_slice(&0u64.to_le_bytes());
}

fn restored_owner_with_record(
    vm: Box<dyn Vm>,
    cpu: Box<dyn VCpu>,
    memory: &GuestMemoryWrapper,
    host_step: bool,
    legacy: bool,
    missing_causes: Option<u64>,
) -> (Box<dyn Vm>, Box<dyn VCpu>) {
    let boundary = vm.checkpoint_boundary().unwrap();
    let (saved, private) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
    let mut private = private.expect("native private record");
    if let Some(causes) = missing_causes {
        // Simulate a pre-fix producer's omitted pending port cause. The legacy
        // codec stores Register { id: u32, value: u64 } sequentially. Require a
        // unique exact field; do not change the public projection or other state.
        clear_pending_cause(&mut private.data, causes);
    }
    if legacy {
        old_record_tag(&mut private.data);
    }
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

struct DebugCase {
    host_step: bool,
    restore: usize,
    nmi: bool,
    tf: bool,
    data: bool,
    port: Option<PortAccess>,
}

#[derive(Clone, Copy)]
struct PortAccess {
    input: bool,
    size: u8,
    port: u16,
    condition: u64,
    de: bool,
    enabled: bool,
}

fn debug_memory(code: &[u8], nmi: bool) -> GuestMemoryWrapper {
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
    memory
}

fn debug_state(tf: bool, data: bool, port: Option<PortAccess>) -> CpuState {
    let mut input = initial();
    let CpuState::X86_64(ref mut guest) = input else {
        unreachable!()
    };
    guest.regs.rax = if port.is_some() { PORT_RAX } else { 2 };
    guest.regs.rflags = 0x1_0202 | if tf { 0x100 } else { 0 }; // IF/RF; independent guest TF.
    if data && port.is_none() {
        guest.sregs.dr0 = MMIO;
        guest.sregs.dr1 = MMIO + 1;
        guest.sregs.dr2 = MMIO + 7;
        guest.sregs.dr3 = MMIO + 8;
        guest.sregs.dr7 = 0x479 | (3 << 16) | (1 << 20) | (3 << 24) | (3 << 28);
    }
    if let Some(access) = port {
        guest.regs.rdx = u64::from(PORT);
        guest.sregs.cr4 = (guest.sregs.cr4 & !8) | if access.de { 8 } else { 0 };
        guest.sregs.dr0 = u64::from(access.port);
        guest.sregs.dr1 = u64::from(access.port) + 1;
        guest.sregs.dr2 = u64::from(access.port) + 3;
        guest.sregs.dr3 = u64::from(access.port) + 4;
        guest.sregs.dr7 = 0x400 | if access.enabled { 0x79 } else { 0 };
        for slot in 0..4 {
            guest.sregs.dr7 |= access.condition << (16 + slot * 4);
        }
    }
    guest.sregs.idt.base = IDT;
    guest.sregs.idt.limit = 4095;
    input
}

fn scenario(code: &[u8], action: usize, case: DebugCase) -> ([u64; 7], u64) {
    let DebugCase {
        host_step,
        restore,
        nmi,
        tf,
        data,
        port,
    } = case;
    let memory = debug_memory(code, nmi);
    let (mut vm, mut cpu) = machine(&memory);
    let input = debug_state(tf, data, port);
    let data_causes = if let Some(access) = port {
        if access.de && access.enabled && access.condition == 2 {
            match access.size {
                1 => 1,
                2 => 3,
                4 => 7,
                _ => unreachable!(),
            }
        } else {
            0
        }
    } else if data {
        if matches!(action, 0 | 2 | 3) { 5 } else { 7 }
    } else {
        0
    };
    let trap = tf || data_causes != 0;
    cpu.set_state(&input).unwrap();
    cpu.set_single_step(host_step);
    let exit = event(cpu.as_mut());
    if let Some(access) = port {
        assert!(
            match &exit {
                VcpuExit::IoIn { port, size } =>
                    access.input && *port == access.port && *size == access.size,
                VcpuExit::IoOut { port, data } =>
                    !access.input && *port == access.port && data.len() == usize::from(access.size),
                _ => false,
            },
            "{exit:?}"
        );
    } else {
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
    }
    assert_eq!(read_word(&memory, OBSERVATIONS), 0);
    assert!(
        cpu.get_state().is_err(),
        "pending device effect exposes no retired state"
    );
    assert!(!cpu.inject_interrupt(0x51).unwrap());
    assert!(!cpu.inject_nmi().unwrap());
    if matches!(restore, 1 | 3 | 4) {
        let missing = (restore == 3).then_some(data_causes | 0x1000);
        assert!(restore != 3 || port.is_some());
        (vm, cpu) = restored_owner_with_record(vm, cpu, &memory, host_step, restore >= 3, missing);
        assert_eq!(format!("{:?}", event(cpu.as_mut())), format!("{exit:?}"));
    }
    match &exit {
        VcpuExit::IoIn { size, .. } => cpu.complete_io_in(&[5, 0, 0, 0][..usize::from(*size)]),
        VcpuExit::IoOut { data, .. } => {
            let size = usize::from(port.unwrap().size);
            assert_eq!(data.as_slice(), &PORT_RAX.to_le_bytes()[..size]);
            cpu.complete_io_out().unwrap();
        }
        VcpuExit::MmioWrite { data, .. } => {
            assert_eq!(data, &2u64.to_le_bytes());
            cpu.complete_io_out().unwrap();
        }
        VcpuExit::MmioRead { .. } => cpu.complete_io_in(&5u64.to_le_bytes()),
        VcpuExit::MmioRmw { operation, .. } => {
            let mut value = 5u64.to_le_bytes();
            operation.apply(&mut value).unwrap();
            assert_eq!(
                u64::from_le_bytes(value),
                if action == 4 {
                    7
                } else if action == 7 {
                    5
                } else {
                    10
                }
            );
            cpu.complete_io_in(&5u64.to_le_bytes());
        }
        _ => unreachable!(),
    }
    cpu.io_completion_result().unwrap();
    if restore == 2 {
        (vm, cpu) = restored_owner(vm, cpu, &memory, host_step);
    }
    assert_eq!(state(cpu.as_ref()).regs.rip, CODE + code.len() as u64);
    let expected_tf_if = 0x200 | if tf { 0x100 } else { 0 };
    assert_eq!(state(cpu.as_ref()).regs.rflags & 0x1_0300, expected_tf_if);
    assert_eq!(cpu.can_inject_interrupt(), !trap);
    if trap {
        assert!(!cpu.inject_interrupt(0x51).unwrap());
        assert!(!cpu.inject_nmi().unwrap());
    }
    if host_step {
        assert!(matches!(event(cpu.as_mut()), VcpuExit::GdbStep));
        assert_eq!(read_word(&memory, OBSERVATIONS), 0);
        assert_eq!(state(cpu.as_ref()).regs.rip, CODE + code.len() as u64);
        cpu.set_single_step(false);
        if trap {
            assert!(!cpu.inject_nmi().unwrap());
        }
    }
    assert!(matches!(event(cpu.as_mut()), VcpuExit::Hlt));
    let observed: [u64; 7] =
        std::array::from_fn(|i| read_word(&memory, OBSERVATIONS + i as u64 * 8));
    assert_eq!(observed[0], u64::from(trap), "actual guest #DB count");
    if trap {
        assert_eq!(
            observed[1],
            CODE + code.len() as u64,
            "trap follows the completed I/O instruction"
        );
        assert_eq!(
            observed[2] & 0x1_0300,
            expected_tf_if,
            "saved TF/IF, cleared RF"
        );
        assert_eq!(
            observed[3], 0,
            "next guest marker has not executed before #DB"
        );
        assert_eq!(
            observed[4] & 0x400f,
            data_causes | if tf { 0x4000 } else { 0 },
            "DR6 contains enabled memory/I/O matches and independent BS"
        );
    } else {
        assert_eq!(&observed[1..5], &[0; 4]);
    }
    assert_eq!(
        (observed[5], observed[6]),
        (0, 0),
        "caller still owns the deferred asynchronous event"
    );
    let retired = state(cpu.as_ref());
    assert_eq!(
        retired.regs.rax,
        if let Some(access) = port {
            if access.input {
                match access.size {
                    1 => (PORT_RAX & !0xff) | 5,
                    2 => (PORT_RAX & !0xffff) | 5,
                    4 => 5,
                    _ => unreachable!(),
                }
            } else {
                PORT_RAX
            }
        } else if action == 0 {
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
        u64::from(trap),
        "IRQ/NMI records the expected prior #DB count"
    );
    let guest_cr4 = read_word(&memory, OBSERVATIONS + 56);
    if let Some(access) = port {
        if trap {
            assert_eq!(guest_cr4 & 8, if access.de { 8 } else { 0 });
        }
    }
    drop(cpu);
    drop(vm);
    (observed, guest_cr4)
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
                    let (observed, _) = scenario(
                        code,
                        action,
                        DebugCase {
                            host_step,
                            restore,
                            nmi,
                            tf: true,
                            data: false,
                            port: None,
                        },
                    );
                    let mut file = OpenOptions::new().append(true).open(output).unwrap();
                    writeln!(file, "{{\"case\":{},\"name\":\"mmio-guest-debug-priority\",\"action\":{action},\"host_step\":{host_step},\"restore_phase\":{restore},\"nmi\":{nmi},\"guest_debug\":{observed:?},\"passed\":true}}", *case).unwrap();
                    *case += 1;
                }
            }
        }
    }
    let data_encodings = [
        encodings[0],
        encodings[1],
        encodings[2],
        encodings[3],
        encodings[4],
        encodings[5],
        encodings[6],
        &[0x48, 0xc1, 0x27, 0],
    ];
    for (action, code) in data_encodings.iter().enumerate() {
        for tf in [false, true] {
            for host_step in [false, true] {
                for restore in 0..3 {
                    for nmi in [false, true] {
                        let (observed, _) = scenario(
                            code,
                            action,
                            DebugCase {
                                host_step,
                                restore,
                                nmi,
                                tf,
                                data: true,
                                port: None,
                            },
                        );
                        let mut file = OpenOptions::new().append(true).open(output).unwrap();
                        writeln!(file, "{{\"case\":{},\"name\":\"mmio-data-debug-priority\",\"action\":{action},\"tf\":{tf},\"host_step\":{host_step},\"restore_phase\":{restore},\"nmi\":{nmi},\"guest_debug\":{observed:?},\"passed\":true}}", *case).unwrap();
                        *case += 1;
                    }
                }
            }
        }
    }
    run_ports(output, case);
    run_legacy_mmio(&data_encodings, output, case);
}

fn run_legacy_mmio(encodings: &[&[u8]], output: &Path, case: &mut usize) {
    for (action, code) in encodings.iter().enumerate() {
        for clear in [false, true] {
            let memory = debug_memory(code, false);
            let (vm, mut cpu) = machine(&memory);
            cpu.set_state(&debug_state(false, true, None)).unwrap();
            assert!(matches!(
                event(cpu.as_mut()),
                VcpuExit::MmioRead { .. } | VcpuExit::MmioWrite { .. } | VcpuExit::MmioRmw { .. }
            ));
            let boundary = vm.checkpoint_boundary().unwrap();
            let (saved, private) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
            let mut private = private.unwrap();
            if clear {
                clear_pending_cause(
                    &mut private.data,
                    0x1000 | if matches!(action, 0 | 2 | 3) { 5 } else { 7 },
                );
            }
            old_record_tag(&mut private.data);
            drop(boundary);
            drop(cpu);
            drop(vm);
            let (vm, mut cpu) = machine(&memory);
            cpu.set_state(&debug_state(false, false, None)).unwrap();
            let before = rax::codec::serialize(&cpu.get_state().unwrap()).unwrap();
            let error = cpu
                .restore_checkpoint_context(&saved.state, &saved.emulator, Some(&private))
                .unwrap_err()
                .to_string();
            assert!(error.contains("legacy pending MMIO"), "{error}");
            assert_eq!(
                rax::codec::serialize(&cpu.get_state().unwrap()).unwrap(),
                before
            );
            let mut file = OpenOptions::new().append(true).open(output).unwrap();
            writeln!(file, "{{\"case\":{},\"name\":\"mmio-legacy-debug-rejected\",\"action\":{action},\"cleared_cause\":{clear},\"destination_unchanged\":true,\"passed\":true}}", *case).unwrap();
            *case += 1;
            drop(cpu);
            drop(vm);
        }
        let (observed, _) = scenario(
            code,
            action,
            DebugCase {
                host_step: false,
                restore: 4,
                nmi: false,
                tf: true,
                data: false,
                port: None,
            },
        );
        let mut file = OpenOptions::new().append(true).open(output).unwrap();
        writeln!(file, "{{\"case\":{},\"name\":\"mmio-legacy-unwatched\",\"action\":{action},\"guest_debug\":{observed:?},\"passed\":true}}", *case).unwrap();
        *case += 1;
    }
}

fn run_ports(output: &Path, case: &mut usize) {
    let encodings: &[(bool, u8, u16, &[u8])] = &[
        (true, 1, PORT, &[0xec]),
        (true, 2, PORT, &[0x66, 0xed]),
        (true, 4, PORT, &[0xed]),
        (false, 1, PORT, &[0xee]),
        (false, 2, PORT, &[0x66, 0xef]),
        (false, 4, PORT, &[0xef]),
        (true, 1, 0xf8, &[0xe4, 0xf8]),
        (true, 2, 0xf8, &[0x66, 0xe5, 0xf8]),
        (true, 4, 0xf8, &[0xe5, 0xf8]),
        (false, 1, 0xf8, &[0xe6, 0xf8]),
        (false, 2, 0xf8, &[0x66, 0xe7, 0xf8]),
        (false, 4, 0xf8, &[0xe7, 0xf8]),
    ];
    for (action, &(input, size, port, code)) in encodings.iter().enumerate() {
        let access = PortAccess {
            input,
            size,
            port,
            condition: 2,
            de: true,
            enabled: true,
        };
        for tf in [false, true] {
            for host_step in [false, true] {
                for restore in 0..4 {
                    for nmi in [false, true] {
                        let (observed, guest_cr4) = scenario(
                            code,
                            action,
                            DebugCase {
                                host_step,
                                restore,
                                nmi,
                                tf,
                                data: true,
                                port: Some(access),
                            },
                        );
                        let mut file = OpenOptions::new().append(true).open(output).unwrap();
                        writeln!(file, "{{\"case\":{},\"name\":\"port-io-debug-priority\",\"action\":{action},\"input\":{input},\"size\":{size},\"port\":{port},\"tf\":{tf},\"host_step\":{host_step},\"restore_phase\":{restore},\"nmi\":{nmi},\"guest_cr4\":{guest_cr4},\"guest_debug\":{observed:?},\"passed\":true}}", *case).unwrap();
                        *case += 1;
                    }
                }
            }
        }
        for (control, (condition, de, enabled)) in [
            (2, false, true),
            (0, true, true),
            (3, true, true),
            (2, true, false),
        ]
        .into_iter()
        .enumerate()
        {
            let (observed, guest_cr4) = scenario(
                code,
                action,
                DebugCase {
                    host_step: false,
                    restore: 0,
                    nmi: false,
                    tf: false,
                    data: true,
                    port: Some(PortAccess {
                        input,
                        size,
                        port,
                        condition,
                        de,
                        enabled,
                    }),
                },
            );
            let mut file = OpenOptions::new().append(true).open(output).unwrap();
            writeln!(file, "{{\"case\":{},\"name\":\"port-io-debug-control\",\"action\":{action},\"input\":{input},\"size\":{size},\"port\":{port},\"control\":{control},\"condition\":{condition},\"de\":{de},\"enabled\":{enabled},\"guest_cr4\":{guest_cr4},\"guest_debug\":{observed:?},\"passed\":true}}", *case).unwrap();
            *case += 1;
        }
        if input {
            for received in 0..usize::from(size) {
                let invalid = invalid_port_reply(code, access, received);
                let mut file = OpenOptions::new().append(true).open(output).unwrap();
                writeln!(file, "{{\"case\":{},\"name\":\"port-io-debug-invalid-reply\",\"action\":{action},\"size\":{size},\"port\":{port},\"received\":{received},\"frontier\":{invalid:?},\"restored_fenced\":true,\"passed\":true}}", *case).unwrap();
                *case += 1;
            }
        }
    }
}

fn invalid_port_reply(code: &[u8], access: PortAccess, received: usize) -> [u64; 4] {
    let memory = debug_memory(code, false);
    let (vm, mut cpu) = machine(&memory);
    cpu.set_state(&debug_state(false, true, Some(access)))
        .unwrap();
    assert!(matches!(event(cpu.as_mut()), VcpuExit::IoIn { port, size }
        if port == access.port && size == access.size));
    cpu.complete_io_in(&vec![5; received]);
    assert!(cpu.io_completion_result().is_err());
    let error = cpu.run().unwrap_err().to_string();
    assert!(
        error.contains("expected") && error.contains("received"),
        "{error}"
    );
    let (vm, mut cpu) = restored_owner(vm, cpu, &memory, false);
    // Even a later correctly sized reply cannot erase the retained failure.
    cpu.complete_io_in(&vec![5; usize::from(access.size)]);
    for _ in 0..3 {
        let error = cpu.run().unwrap_err().to_string();
        assert!(
            error.contains("expected") && error.contains("received"),
            "{error}"
        );
        assert!(!cpu.can_inject_interrupt());
        assert!(!cpu.inject_interrupt(0x51).unwrap());
        assert!(!cpu.inject_nmi().unwrap());
    }
    let boundary = vm.checkpoint_boundary().unwrap();
    let (saved, _) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
    let CpuState::X86_64(guest) = saved.state else {
        unreachable!()
    };
    let observed = [
        guest.regs.rip,
        guest.regs.rax,
        guest.regs.r10,
        read_word(&memory, OBSERVATIONS),
    ];
    assert_eq!(observed, [CODE, PORT_RAX, 0, 0]);
    assert_eq!(read_word(&memory, OBSERVATIONS + 24), 0);
    drop(boundary);
    drop(cpu);
    drop(vm);
    observed
}
