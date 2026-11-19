//! Read-only device operands for the implicit-register MUL and IMUL forms.
use super::*;
use std::arch::asm;

const CARRY_OVERFLOW: u64 = 1 | (1 << 11);
const FLAGS: u64 = 0x96;
const RDX: u64 = 0x7856_3412_fedc_ba98;

fn hardware(signed: bool, width: usize, mut rax: u64, source: u64) -> (u64, u64, u64) {
    let mut rdx = RDX;
    let flags: u64;
    macro_rules! multiply {
        ($instruction:literal) => {
            // SAFETY: The operand is a live stack value, the instruction
            // only reads it, and both result registers are declared.
            unsafe {
                asm!(
                    concat!($instruction, " [{source}]"),
                    "pushfq",
                    "pop {flags}",
                    source = in(reg) &source,
                    inout("rax") rax,
                    inout("rdx") rdx,
                    flags = lateout(reg) flags,
                );
            }
        };
    }
    match (signed, width) {
        (false, 1) => multiply!("mul byte ptr"),
        (false, 2) => multiply!("mul word ptr"),
        (false, 4) => multiply!("mul dword ptr"),
        (false, 8) => multiply!("mul qword ptr"),
        (true, 1) => multiply!("imul byte ptr"),
        (true, 2) => multiply!("imul word ptr"),
        (true, 4) => multiply!("imul dword ptr"),
        (true, 8) => multiply!("imul qword ptr"),
        _ => unreachable!(),
    }
    (rax, rdx, flags & CARRY_OVERFLOW)
}

fn trial(code: &[u8], reply: &[u8], accumulator: u64, expected: (u64, u64, u64), restore: bool) {
    let memory = guest_memory(code);
    let (mut vm, mut cpu) = machine(&memory);
    let (rax, rdx, flags) = expected;
    let mut before = state(cpu.as_ref());
    before.regs.rax = accumulator;
    before.regs.rdx = RDX;
    before.regs.rflags = FLAGS | (flags ^ CARRY_OVERFLOW);
    cpu.set_state(&CpuState::X86_64(before)).unwrap();

    let check_pending = |cpu: &mut dyn VCpu| {
        let pending = event(cpu);
        assert!(
            matches!(pending, VcpuExit::MmioRead { addr: MMIO, size }
            if usize::from(size) == reply.len()),
            "unexpected multiply exit: {pending:?}"
        );
        assert!(cpu.io_completion_result().is_err());
    };
    check_pending(cpu.as_mut());
    if restore {
        let boundary = vm.checkpoint_boundary().unwrap();
        let (saved, private) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
        let private = private.expect("native pending multiply context");
        assert_eq!(saved.state.pc(), CODE);
        drop(boundary);
        drop(cpu);
        drop(vm);
        (vm, cpu) = machine(&guest_memory(code));
        cpu.restore_checkpoint_context(&saved.state, &saved.emulator, Some(&private))
            .unwrap();
    }
    check_pending(cpu.as_mut());
    cpu.complete_io_in(reply);
    cpu.io_completion_result().unwrap();
    let regs = state(cpu.as_ref()).regs;
    assert_eq!((regs.rax, regs.rdx, regs.rflags), (rax, rdx, FLAGS | flags));
    assert_eq!(regs.rip, CODE + code.len() as u64);
    halted_with_flags(cpu.as_mut(), code.len(), rax, FLAGS | flags);
    assert_eq!(state(cpu.as_ref()).regs.rdx, rdx);
    drop(cpu);
    drop(vm);
}

pub(super) fn run(output: &Path) {
    assert!(!output.exists(), "observations must be new");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output)
        .unwrap();
    let mut case = 0;
    for (width, prefix) in [
        (1, &[0xf6][..]),
        (2, &[0x66, 0xf7]),
        (4, &[0xf7]),
        (8, &[0x48, 0xf7]),
    ] {
        let mask = u64::MAX >> (64 - width * 8);
        let sign = 1 << (width * 8 - 1);
        for (signed, factor, source, overflow) in [
            (false, 2, 3, false),
            (false, mask, 2, true),
            (true, mask - 2, 2, false),
            (true, sign, mask, true),
        ] {
            let accumulator = (0xaabb_ccdd_5566_8800 & !mask) | factor;
            let code = [prefix, &[if signed { 0x2f } else { 0x27 }]].concat();
            let (rax, rdx, flags) = hardware(signed, width, accumulator, source);
            assert_eq!(flags, if overflow { CARRY_OVERFLOW } else { 0 });
            for restore in [false, true] {
                trial(
                    &code,
                    &source.to_le_bytes()[..width],
                    accumulator,
                    (rax, rdx, flags),
                    restore,
                );
                writeln!(file, "{{\"case\":{case},\"name\":\"implicit-multiply\",\"width\":{width},\"signed\":{signed},\"overflow\":{overflow},\"restored\":{restore},\"rax\":{rax},\"rdx\":{rdx},\"flags\":{flags},\"passed\":true}}").unwrap();
                case += 1;
            }
        }
    }
    assert_eq!(case, 32);
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}
