//! Compare Intel HVF MMIO completion with the same instruction using guest RAM.
use super::*;

const IDT: u64 = 0xc000;
const HANDLER: u64 = 0xb000;
const DIVISOR: u64 = 0xa000;
const STATUS_FLAGS: u64 = 0x8d5;

#[derive(Clone, Copy, Debug)]
enum Restore {
    None,
    ReadPending,
    FaultQueued,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Observation {
    rax: u64,
    rdx: u64,
    flags: u64,
    saved_rip: u64,
    dr6: u64,
}

fn recreate(
    memory: &GuestMemoryWrapper,
    vm: Box<dyn Vm>,
    cpu: Box<dyn VCpu>,
) -> (Box<dyn Vm>, Box<dyn VCpu>) {
    let boundary = vm.checkpoint_boundary().unwrap();
    let (saved, private) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
    let private = private.expect("private divide frontier");
    assert_eq!(saved.state.pc(), CODE);
    drop(boundary);
    drop(cpu);
    drop(vm);
    let (vm, mut cpu) = machine(memory);
    cpu.restore_checkpoint_context(&saved.state, &saved.emulator, Some(&private))
        .unwrap();
    (vm, cpu)
}

fn observe(
    code: &[u8],
    divisor: u64,
    size: usize,
    (rax, rdx): (u64, u64),
    fault: bool,
    device: bool,
    restore: Restore,
) -> Observation {
    let memory = guest_memory(code);
    word(&memory, DIVISOR, divisor);
    // Vector 0 has no error code. Vector 1 at a distinct address catches
    // an incorrectly published data or single-step breakpoint.
    for (vector, handler) in [(0, HANDLER), (1, HANDLER + 16)] {
        let gate = handler | (8 << 16) | (0x8e << 40);
        word(&memory, IDT + vector * 16, gate);
        word(&memory, IDT + vector * 16 + 8, 0);
        memory
            .memory()
            .write_slice(&[0xf4], GuestAddress(handler))
            .unwrap();
    }
    let (mut vm, mut cpu) = machine(&memory);
    let address = if device { MMIO } else { DIVISOR };
    let mut before = state(cpu.as_ref());
    before.regs.rax = rax;
    before.regs.rdx = rdx;
    before.regs.rdi = address;
    before.regs.rflags = if fault { 0x302 } else { 0x202 };
    before.sregs.idt.base = IDT;
    before.sregs.idt.limit = 31;
    if fault {
        before.sregs.dr0 = address;
        before.sregs.dr7 = 0x30401; // Local read/write watch, one byte.
    }
    cpu.set_state(&CpuState::X86_64(before)).unwrap();
    if device {
        let read = |cpu: &mut dyn VCpu| {
            let exit = event(cpu);
            assert!(
                matches!(exit, VcpuExit::MmioRead { addr: MMIO, size: observed } if usize::from(observed) == size),
                "expected MMIO divide read: {exit:?}"
            );
        };
        read(cpu.as_mut());
        if matches!(restore, Restore::ReadPending) {
            (vm, cpu) = recreate(&memory, vm, cpu);
            read(cpu.as_mut());
        }
        cpu.complete_io_in(&divisor.to_le_bytes()[..size]);
        cpu.io_completion_result().unwrap();
        if fault {
            let regs = state(cpu.as_ref()).regs;
            assert_eq!((regs.rax, regs.rdx, regs.rip), (rax, rdx, CODE));
            if matches!(restore, Restore::FaultQueued) {
                (vm, cpu) = recreate(&memory, vm, cpu);
            }
            assert!(!cpu.inject_interrupt(0x31).unwrap());
            assert!(!cpu.inject_nmi().unwrap());
        }
    }
    let exit = event(cpu.as_mut());
    assert!(matches!(exit, VcpuExit::Hlt), "{exit:?}");
    let after = state(cpu.as_ref());
    if fault {
        assert_eq!(after.regs.rip, HANDLER + 1);
        assert_eq!((after.regs.rax, after.regs.rdx), (rax, rdx));
        assert_eq!(after.regs.r10, 0);
        assert_eq!(read_word(&memory, after.regs.rsp), CODE);
        assert_eq!(read_word(&memory, after.regs.rsp + 8), 8);
    } else {
        assert_eq!(after.regs.rip, CODE + code.len() as u64 + 11);
        assert_eq!(after.regs.r10, MARKER);
    }
    Observation {
        rax: after.regs.rax,
        rdx: after.regs.rdx,
        flags: if fault {
            read_word(&memory, after.regs.rsp + 16)
        } else {
            after.regs.rflags & !STATUS_FLAGS
        },
        saved_rip: if fault { CODE } else { 0 },
        dr6: after.sregs.dr6,
    }
}

pub(super) fn run(output: &Path) {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output)
        .unwrap();
    let mut case = 0;
    for (size, prefix) in [
        (1, &[0xf6][..]),
        (2, &[0x66, 0xf7]),
        (4, &[0xf7]),
        (8, &[0x48, 0xf7]),
    ] {
        let width = size * 8;
        let mask = u64::MAX >> (64 - width);
        let sign = 1 << (width - 1);
        for signed in [false, true] {
            let code = [prefix, &[if signed { 0x3f } else { 0x37 }]].concat();
            let (low, high) = if signed { (mask - 16, mask) } else { (17, 0) };
            let (wide_low, wide_high, wide_divisor) =
                if signed { (sign - 1, 0, 1) } else { (1, 1, 2) };
            for (kind, low, high, divisor, fault) in [
                ("nonzero-remainder", low, high, 5, false),
                ("large-quotient", wide_low, wide_high, wide_divisor, false),
                ("zero-divisor", 17, 0, 0, true),
                ("quotient-overflow", 0, 1, 1, true),
            ] {
                let rax = if size == 1 {
                    (SEED & !0xffff) | (high << 8) | low
                } else {
                    (SEED & !mask) | low
                };
                let rdx = (MARKER & !mask) | high;
                let reference = observe(
                    &code,
                    divisor,
                    size,
                    (rax, rdx),
                    fault,
                    false,
                    Restore::None,
                );
                let phases = [Restore::None, Restore::ReadPending, Restore::FaultQueued];
                for &restore in &phases[..if fault { 3 } else { 2 }] {
                    let observed = observe(&code, divisor, size, (rax, rdx), fault, true, restore);
                    assert_eq!(
                        observed, reference,
                        "size={size} signed={signed} {kind} {restore:?}"
                    );
                    writeln!(
                        file,
                        "{{\"case\":{case},\"name\":\"implicit-divide\",\"width\":{size},\"signed\":{signed},\"kind\":\"{kind}\",\"restore\":\"{restore:?}\",\"fault\":{fault},\"saved_rip\":{},\"flags\":{},\"rax\":{},\"rdx\":{},\"dr6\":{},\"passed\":true}}",
                        observed.saved_rip, observed.flags, observed.rax, observed.rdx, observed.dr6,
                    ).unwrap();
                    case += 1;
                }
            }
        }
    }
    assert_eq!(case, 80);
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}
