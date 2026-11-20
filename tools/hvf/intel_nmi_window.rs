//! Native VM-entry NMI delivery, IRET, and stopped CPU record restoration.
use super::*;

const IDT: u64 = 0xc000;
const HANDLER: u64 = 0xb000;
const PORT: u16 = 0x80;
const START_PORT: u16 = 0x81;

#[derive(Clone, Copy)]
enum Watch {
    Unarmed,
    Direct,
    Restored,
}

fn complete_handler_exit(cpu: &mut dyn VCpu, exit: VcpuExit, visits: u64) {
    assert!(
        matches!(exit, VcpuExit::IoOut { port: PORT, .. }),
        "expected an NMI handler port exit: {exit:?}"
    );
    cpu.complete_io_out().unwrap();
    let regs = state(cpu).regs;
    assert_eq!((regs.rip, regs.r11, regs.r10), (HANDLER + 5, visits, 0));
    assert_eq!(regs.rflags & 0x200, 0);
}

fn install_handler(memory: &GuestMemoryWrapper) {
    let gate = HANDLER | (8 << 16) | (0x8e << 40);
    word(memory, IDT + 2 * 16, gate);
    word(memory, IDT + 2 * 16 + 8, 0);
    // INC R11; OUT 80h, AL; IRETQ. The port exit precedes the unblock.
    memory
        .memory()
        .write_slice(
            &[0x49, 0xff, 0xc3, 0xe6, 0x80, 0x48, 0xcf],
            GuestAddress(HANDLER),
        )
        .unwrap();
}

fn set_handler_state(cpu: &mut dyn VCpu, mut input: X86_64CpuState) {
    input.sregs.idt.base = IDT;
    input.sregs.idt.limit = 3 * 16 - 1;
    cpu.set_state(&CpuState::X86_64(input)).unwrap();
}

fn window_machine(memory: &GuestMemoryWrapper) -> (Box<dyn Vm>, Box<dyn VCpu>) {
    install_handler(memory);
    let (vm, mut cpu) = machine(memory);
    let input = state(cpu.as_ref());
    set_handler_state(cpu.as_mut(), input);
    (vm, cpu)
}

pub(super) fn run_baseline(output: &Path) {
    assert!(!output.exists(), "observations must be new");
    let memory = guest_memory(&[]);
    let (_vm, mut cpu) = window_machine(&memory);
    eprintln!("nmi-baseline entering the initialized guest without an event");
    halted(cpu.as_mut(), 0, SEED);
    let visits = state(cpu.as_ref()).regs.r11;
    assert_eq!(visits, 0, "NMI handler ran without an injected event");
    record(output, 0, "nmi-baseline-hlt", 8, visits);
    println!("{{\"cases\":1,\"failed\":0,\"guest_execution_performed\":true}}");
}

/// Isolate event admission after a known-good non-NMI guest entry.
pub(super) fn run_hot_entry(output: &Path) {
    assert!(!output.exists(), "observations must be new");
    let code = [0xe6, START_PORT as u8];
    let memory = guest_memory(&code);
    let (_vm, mut cpu) = window_machine(&memory);
    eprintln!("nmi-hot-entry: entering without an event");
    let exit = event(cpu.as_mut());
    assert!(
        matches!(
            exit,
            VcpuExit::IoOut {
                port: START_PORT,
                ..
            }
        ),
        "initial guest entry must reach its port marker: {exit:?}",
    );
    cpu.complete_io_out().unwrap();
    cpu.io_completion_result().unwrap();
    let before = state(cpu.as_ref()).regs;
    assert_eq!((before.rip, before.rflags, before.r11), (CODE + 2, 2, 0));
    eprintln!("nmi-hot-entry: publishing NMI with IF clear after the completed marker");
    assert!(cpu.inject_nmi().unwrap());
    eprintln!("nmi-hot-entry: NMI accepted; entering the guest");
    let handler = event(cpu.as_mut());
    eprintln!("nmi-hot-entry: handler entry returned {handler:?}");
    complete_handler_exit(cpu.as_mut(), handler, 1);
    assert!(!cpu.inject_nmi().unwrap(), "NMI admitted before IRET");
    eprintln!("nmi-hot-entry: resuming through IRET");
    halted(cpu.as_mut(), code.len(), SEED);
    let visits = state(cpu.as_ref()).regs.r11;
    assert_eq!(visits, 1);
    record(output, 0, "nmi-hot-entry", 8, visits);
    println!("{{\"cases\":1,\"failed\":0,\"guest_execution_performed\":true}}");
}

/// Split a failed first entry into controls that change one input each.
/// These diagnostic exits do not count toward successful NMI observations.
fn diagnose_first_entry() {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Control {
        NoNmi,
        ExplicitState,
        PriorPortExit,
        InterruptFlagSet,
    }
    for control in [
        Control::NoNmi,
        Control::ExplicitState,
        Control::PriorPortExit,
        Control::InterruptFlagSet,
    ] {
        eprintln!("nmi-window {control:?}: initializing fresh VM");
        let code: &[u8] = if control == Control::PriorPortExit {
            &[0xe6, START_PORT as u8]
        } else {
            &[]
        };
        let memory = guest_memory(code);
        install_handler(&memory);
        let (_vm, mut cpu) = machine(&memory);
        let mut input = if control == Control::ExplicitState {
            let CpuState::X86_64(input) = initial() else {
                unreachable!();
            };
            input
        } else {
            state(cpu.as_ref())
        };
        if control == Control::InterruptFlagSet {
            input.regs.rflags |= 1 << 9;
        }
        set_handler_state(cpu.as_mut(), input);
        if control == Control::PriorPortExit {
            let exit = event(cpu.as_mut());
            eprintln!("nmi-window {control:?} initial exit: {exit:?}");
            if !matches!(
                exit,
                VcpuExit::IoOut {
                    port: START_PORT,
                    ..
                }
            ) {
                continue;
            }
            cpu.complete_io_out().unwrap();
        }
        let before = state(cpu.as_ref());
        let accepted = (control != Control::NoNmi).then(|| cpu.inject_nmi());
        eprintln!("nmi-window {control:?} starting entry: request={accepted:?}");
        let exit = event(cpu.as_mut());
        eprintln!(
            "nmi-window {control:?}: request={accepted:?} exit={exit:?} rip={:#x} rflags={:#x}",
            before.regs.rip, before.regs.rflags
        );
    }
}

fn observe(watch: Watch) -> u64 {
    let memory = guest_memory(&[]);
    let (mut vm, mut cpu) = window_machine(&memory);
    assert!(cpu.inject_nmi().unwrap());
    let first_exit = event(cpu.as_mut());
    if !matches!(first_exit, VcpuExit::IoOut { port: PORT, .. }) {
        eprintln!("nmi-window first handler entry failed: {first_exit:?}");
        drop(cpu);
        drop(vm);
        diagnose_first_entry();
        panic!("expected an NMI handler port exit: {first_exit:?}");
    }
    complete_handler_exit(cpu.as_mut(), first_exit, 1);
    assert!(!cpu.inject_nmi().unwrap(), "NMI admitted before IRET");

    if matches!(watch, Watch::Restored) {
        let boundary = vm.checkpoint_boundary().unwrap();
        let (saved, private) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
        let private = private.expect("native vCPU record");
        drop(boundary);
        drop(cpu);
        drop(vm);
        (vm, cpu) = machine(&memory);
        cpu.restore_checkpoint_context(&saved.state, &saved.emulator, Some(&private))
            .unwrap();
        assert!(
            !cpu.inject_nmi().unwrap(),
            "restore lost the handler's NMI block"
        );
    }

    let watched = !matches!(watch, Watch::Unarmed);
    if watched {
        let mut reached_window = false;
        for _ in 0..100 {
            let exit = cpu
                .run_coordinated_host_slice_with_events(Duration::from_millis(100), false, true)
                .unwrap();
            assert!(exit.is_none(), "guest ran past the NMI window: {exit:?}");
            let regs = state(cpu.as_ref()).regs;
            assert_eq!((regs.r11, regs.r10), (1, 0));
            if regs.rip == CODE {
                reached_window = true;
                break;
            }
            assert_eq!(regs.rip, HANDLER + 5);
        }
        assert!(reached_window, "no window at the IRET return address");
        assert!(cpu.inject_nmi().unwrap());
        let exit = event(cpu.as_mut());
        complete_handler_exit(cpu.as_mut(), exit, 2);
    }
    assert!(matches!(event(cpu.as_mut()), VcpuExit::Hlt));
    let regs = state(cpu.as_ref()).regs;
    assert_eq!(
        (regs.rip, regs.r10, regs.rflags & 0x200),
        (CODE + 11, MARKER, 0)
    );
    assert_eq!(regs.r11, 1 + u64::from(watched));
    drop(cpu);
    drop(vm);
    regs.r11
}

pub(super) fn run(output: &Path) {
    assert!(!output.exists(), "observations must be new");
    for (case, (watch, name)) in [
        (Watch::Unarmed, "nmi-window-unarmed"),
        (Watch::Direct, "nmi-window-direct"),
        (Watch::Restored, "nmi-window-restored"),
    ]
    .into_iter()
    .enumerate()
    {
        record(output, case, name, 8, observe(watch));
    }
    println!("{{\"cases\":3,\"failed\":0,\"guest_execution_performed\":true}}");
}
