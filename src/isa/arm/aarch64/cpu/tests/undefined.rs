//! Precise state at the shared Undefined instruction frontier.
use super::*;

const ENTRY: u64 = 0x1000;
const VBAR: u64 = 0x2000;

fn words() -> Vec<u32> {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/development/a64-undefined-retirement/corpus.json"
    )))
    .unwrap();
    corpus["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| record["word"].as_u64().unwrap() as u32)
        .collect()
}

fn cpu(word: u32, el: u8, btype: u8) -> AArch64Cpu {
    let mut config = AArch64Config {
        initial_el: el,
        gic_config: None,
        ..Default::default()
    };
    config.features |= ArmFeatures::FP16
        | ArmFeatures::FHM
        | ArmFeatures::JSCVT
        | ArmFeatures::FCMA
        | ArmFeatures::FRINTTS
        | ArmFeatures::BF16
        | ArmFeatures::I8MM
        | ArmFeatures::DOTPROD;
    let mut cpu = AArch64Cpu::new(config, Box::new(FlatMemory::new(0, 0x8000)));
    cpu.pc = ENTRY;
    cpu.btype = btype;
    cpu.nzcv = 10;
    cpu.x = std::array::from_fn(|i| 0x1234_0000_0000_0000 | i as u64);
    cpu.v = std::array::from_fn(|i| (u128::from(i as u64) << 96) | 0x7fc0_dead);
    cpu.fpcr = 0x0400_0000;
    cpu.fpsr = 0x0800_0011;
    cpu.insn_count = 17;
    cpu.cycle_count = 29;
    cpu.sysregs.el1.cpacr = 3 << 20;
    cpu.sysregs.el1.vbar = VBAR;
    cpu.sysregs.el1.elr = 0xfeed;
    cpu.sysregs.el1.esr = 0xbeef;
    cpu.execution.disabled = true;
    cpu.write_memory(ENTRY, &word.to_le_bytes()).unwrap();
    cpu.write_memory(0x4000, &[0xa5; 256]).unwrap();
    cpu
}

#[test]
fn direct_undefined_preserves_complete_private_state_and_memory_without_retirement() {
    let mut failures = Vec::new();
    for word in words() {
        for el in [0, 1] {
            for btype in 0..4 {
                let mut cpu = cpu(word, el, btype);
                let before = CoreCheckpoint::capture(&cpu).unwrap();
                let memory = cpu.read_memory(0, 0x8000).unwrap();
                let result = cpu.step();
                let after = CoreCheckpoint::capture(&cpu).unwrap();
                if result != Ok(CpuExit::Undefined(word)) || after != before {
                    failures.push(format!(
                        "word={word:08x} EL{el} BTYPE={btype}: {result:?}, pc={:x}, retired={}, cycles={}, btype={}",
                        cpu.pc, cpu.insn_count, cpu.cycle_count, cpu.btype
                    ));
                }
                assert_eq!(cpu.read_memory(0, 0x8000).unwrap(), memory);
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures: {failures:?}",
        failures.len()
    );
}

#[test]
fn undefined_retry_preserves_saturated_counters_and_executes_a_replacement_once() {
    for word in words() {
        let mut cpu = cpu(word, 1, 2);
        cpu.insn_count = u64::MAX;
        cpu.cycle_count = u64::MAX;
        let before = CoreCheckpoint::capture(&cpu).unwrap();
        for _ in 0..2 {
            assert_eq!(cpu.step().unwrap(), CpuExit::Undefined(word));
            assert_eq!(CoreCheckpoint::capture(&cpu).unwrap(), before);
        }
        cpu.insn_count = 17;
        cpu.cycle_count = 29;
        let x9 = cpu.x[9];
        cpu.write_memory(ENTRY, &0x9100_0529u32.to_le_bytes())
            .unwrap();
        assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
        assert_eq!(
            (cpu.pc, cpu.insn_count, cpu.cycle_count),
            (ENTRY + 4, 18, 30)
        );
        assert_eq!((cpu.x[9], cpu.btype), (x9 + 1, 0));
    }
}

#[test]
fn system_undefined_delivery_preserves_fault_spsr_and_diagnostic_frontier() {
    for word in words() {
        for el in [0, 1] {
            for diagnostic in [false, true] {
                let mut cpu = cpu(word, el, 2);
                let pstate = cpu.pstate_bits();
                let registers = (cpu.x, cpu.v, cpu.fpcr, cpu.fpsr);
                let ticks = cpu.sysregs.cntpct_el0;
                let result = cpu.step_system_interpreted(diagnostic);
                if diagnostic {
                    assert_eq!(result, Err(ArmError::UndefinedInstruction(word)));
                    assert_eq!((cpu.pc, cpu.pstate_bits()), (ENTRY, pstate));
                    assert_eq!((cpu.sysregs.el1.elr, cpu.sysregs.el1.esr), (0xfeed, 0xbeef));
                } else {
                    assert_eq!(result.unwrap(), CpuExit::Continue);
                    assert_eq!(cpu.pc, VBAR + if el == 0 { 0x400 } else { 0x200 });
                    assert_eq!(cpu.sysregs.el1.elr, ENTRY);
                    assert_eq!(cpu.sysregs.el1.esr, 1 << 25);
                    assert_eq!(cpu.sysregs.el1.spsr, pstate);
                }
                assert_eq!((cpu.insn_count, cpu.cycle_count), (17, 29), "{word:08x}");
                assert_eq!((cpu.x, cpu.v, cpu.fpcr, cpu.fpsr), registers);
                assert_eq!(cpu.sysregs.cntpct_el0, ticks + 16);
            }
        }
    }
}

#[test]
fn saved_pending_undefined_completes_once_without_an_extra_attempt_or_retirement() {
    let word = 0xce02_9420;
    let mut source = cpu(word, 0, 2);
    source.sysregs.cntpct_el0 = 1234;
    source.execution.native_fault = Some(ArmError::UndefinedInstruction(word));
    let saved = CoreCheckpoint::capture(&source).unwrap();
    let bytes = crate::codec::serialize(&saved).unwrap();
    let decoded: CoreCheckpoint = crate::codec::deserialize_strict(&bytes).unwrap();
    let mut target = cpu(word, 0, 0);
    target
        .write_memory(VBAR + 0x400, &0x9100_0529u32.to_le_bytes())
        .unwrap();
    decoded.install_in_prepared(&mut target).unwrap();
    let x9 = target.x[9];
    assert_eq!(target.step_system().unwrap(), CpuExit::Continue);
    assert_eq!((target.pc, target.sysregs.el1.elr), (VBAR + 0x400, ENTRY));
    assert_eq!(target.sysregs.el1.esr, 1 << 25);
    assert_eq!((target.insn_count, target.cycle_count), (17, 29));
    assert_eq!(target.sysregs.cntpct_el0, 1234);
    assert!(target.execution.native_fault.is_none());
    assert_eq!(target.step_system().unwrap(), CpuExit::Continue);
    assert_eq!((target.pc, target.x[9]), (VBAR + 0x404, x9 + 1));
    assert_eq!((target.insn_count, target.cycle_count), (18, 30));
    assert_eq!(target.sysregs.cntpct_el0, 1250);
}
