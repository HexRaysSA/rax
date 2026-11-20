//! Native VM-entry NMI delivery, IRET, and stopped CPU record restoration.
use super::*;

const IDT: u64 = 0xc000;
const HANDLER: u64 = 0xb000;
const PORT: u16 = 0x80;

#[derive(Clone, Copy)]
enum Watch {
    Unarmed,
    Direct,
    Restored,
}

fn handler_exit(cpu: &mut dyn VCpu, visits: u64) {
    let exit = event(cpu);
    assert!(
        matches!(exit, VcpuExit::IoOut { port: PORT, .. }),
        "expected an NMI handler port exit: {exit:?}"
    );
    cpu.complete_io_out().unwrap();
    let regs = state(cpu).regs;
    assert_eq!((regs.rip, regs.r11, regs.r10), (HANDLER + 5, visits, 0));
    assert_eq!(regs.rflags & 0x200, 0);
}

fn observe(watch: Watch) -> u64 {
    let memory = guest_memory(&[]);
    let gate = HANDLER | (8 << 16) | (0x8e << 40);
    word(&memory, IDT + 2 * 16, gate);
    word(&memory, IDT + 2 * 16 + 8, 0);
    // INC R11; OUT 80h, AL; IRETQ. The port exit precedes the unblock.
    memory
        .memory()
        .write_slice(
            &[0x49, 0xff, 0xc3, 0xe6, 0x80, 0x48, 0xcf],
            GuestAddress(HANDLER),
        )
        .unwrap();
    let (mut vm, mut cpu) = machine(&memory);
    let mut initial = state(cpu.as_ref());
    initial.sregs.idt.base = IDT;
    initial.sregs.idt.limit = 3 * 16 - 1;
    cpu.set_state(&CpuState::X86_64(initial)).unwrap();
    assert!(cpu.inject_nmi().unwrap());
    handler_exit(cpu.as_mut(), 1);
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
        handler_exit(cpu.as_mut(), 2);
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
