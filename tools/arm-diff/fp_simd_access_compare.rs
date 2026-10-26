use rax::isa::arm::aarch32::cp15::Cpacr;
use rax::isa::arm::aarch32::cpu::ProcessorMode;
use rax::isa::arm::decoder::{Aarch32Decoder, ThumbDecoder};
use rax::isa::arm::execution::FlatMemory;
use rax::isa::arm::{Armv7Cpu, ExceptionType, ExecResult, Executor};
fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn main() {
    let mut args = std::env::args_os().skip(1);
    let cases = std::fs::read(args.next().expect("cases path")).unwrap();
    assert!(args.next().is_none());
    assert_eq!(cases.len(), 336 * 24);
    let mut memory = FlatMemory::new(4096, 0);
    let mut failed = 0;
    let mut denied_cases = 0;
    let mut reference_differences = 0;
    let mut unexpected_reference_differences = 0;
    for (index, case) in cases.chunks_exact(24).enumerate() {
        let thumb = word(case, 0) != 0;
        let user = word(case, 4) != 0;
        let asedis = word(case, 8) != 0;
        let enabled = word(case, 12) != 0;
        let raw = word(case, 16);
        let reference_undefined = word(case, 20) != 0;
        // Corpus order is 11 Advanced SIMD then 10 VFP operations per access cell.
        // The reference assembler fixes this classification independently of RAX.
        let simd = index % 21 < 11;
        let expected_undefined = !enabled || (asedis && simd);
        if reference_undefined != expected_undefined {
            reference_differences += 1;
            unexpected_reference_differences +=
                usize::from(!(asedis && enabled && simd && !reference_undefined));
        }
        denied_cases += usize::from(expected_undefined);
        let mut cpu = Armv7Cpu::new();
        cpu.cpsr.t = thumb;
        if user {
            cpu.cpsr.mode = ProcessorMode::User as u8;
        }
        cpu.cp15.cpacr = Cpacr::from_bits(0x00f0_0000 | (u32::from(asedis) << 31));
        cpu.vfp.fpexc = u32::from(enabled) << 30;
        cpu.regs[0] = 0x100;
        cpu.regs[1] = 0x1234_5678;
        cpu.regs[2] = 0;
        let regs = cpu.regs;
        let cpsr = cpu.cpsr.to_u32();
        let dregs = cpu.vfp.dregs;
        let fpscr = cpu.vfp.fpscr.bits();
        let fpexc = cpu.vfp.fpexc;
        let insn = if thumb {
            ThumbDecoder::decode_32bit(raw)
        } else {
            Aarch32Decoder::decode(raw)
        }
        .unwrap();
        let result = Executor::new(&mut cpu, &mut memory).execute(&insn);
        let undefined = matches!(
            result,
            ExecResult::Undefined | ExecResult::Exception(ExceptionType::UndefinedInstruction)
        );
        let passed = if expected_undefined {
            undefined
                && cpu.regs == regs
                && cpu.cpsr.to_u32() == cpsr
                && cpu.vfp.dregs == dregs
                && cpu.vfp.fpscr.bits() == fpscr
                && cpu.vfp.fpexc == fpexc
        } else {
            matches!(result, ExecResult::Continue)
        };
        if !passed {
            failed += 1;
            eprintln!(
                "raw={raw:08x} Thumb={thumb} User={user} ASEDIS={asedis} FPEXC.EN={enabled} expected_undefined={expected_undefined} result={result:?}"
            );
        }
    }
    assert_eq!(denied_cases, 212);
    println!(
        "{{\"cases\":336,\"primary_denied\":212,\"primary_allowed\":124,\"reference_differences\":{reference_differences},\"unexpected_reference_differences\":{unexpected_reference_differences},\"failed\":{failed}}}"
    );
    if failed != 0 {
        std::process::exit(1);
    }
}
