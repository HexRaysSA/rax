//! Admitted private counters retain the scheduler's modulo-2^64 contract.
use super::*;

const ENTRY: u64 = 0x100;
const TICKS: u64 = u64::MAX - 7;

#[derive(Clone, Copy, Debug)]
enum Isa {
    A64,
    Arm,
    Thumb16,
    Thumb32,
}

impl Isa {
    const ALL: [Self; 4] = [Self::A64, Self::Arm, Self::Thumb16, Self::Thumb32];

    fn bytes(self) -> &'static [u8] {
        match self {
            Self::A64 => &[0x00, 0x04, 0x00, 0x91],     // ADD X0,X0,#1
            Self::Arm => &[0x01, 0x00, 0x80, 0xe2],     // ADD R0,R0,#1
            Self::Thumb16 => &[0x01, 0x30],             // ADDS R0,#1
            Self::Thumb32 => &[0x00, 0xf1, 0x01, 0x00], // ADD.W R0,R0,#1
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Entry {
    Direct,
    System,
    Diagnostic,
}

fn machine(isa: Isa, enabled: bool) -> AArch64Cpu {
    let mut cpu = AArch64Cpu::new(
        AArch64Config {
            gic_config: None,
            ..AArch64Config::default()
        },
        Box::new(crate::isa::arm::common::memory::FlatMemory::new(0, 0x4000)),
    );
    let mut controls = cpu.pauth_controls();
    controls.scr_el3 |= 1 | (1 << 10);
    controls.hcr_el2 |= 1 << 31;
    cpu.set_pauth_controls(controls).unwrap();
    if !matches!(isa, Isa::A64) {
        let thumb = matches!(isa, Isa::Thumb16 | Isa::Thumb32);
        cpu.set_pstate_bits(0x10 | (u64::from(thumb) << 5)).unwrap();
    }
    cpu.write_memory(ENTRY, isa.bytes()).unwrap();
    cpu.set_pc(ENTRY);
    #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
    cpu.set_jit_enabled(enabled);
    #[cfg(not(all(feature = "smir-jit", target_arch = "aarch64")))]
    let _ = enabled;
    cpu.sysregs.cntpct_el0 = TICKS;
    cpu
}

fn restored(isa: Isa, instructions: u64, cycles: u64, value: u64, native: bool) -> AArch64Cpu {
    let mut source = machine(isa, native);
    source.insn_count = instructions;
    source.cycle_count = cycles;
    source.x[0] = value;
    source.x[1] = 0x9876_5432_10fe_dcba;
    let bytes = crate::codec::serialize(&CoreCheckpoint::capture(&source).unwrap()).unwrap();
    let saved: CoreCheckpoint = crate::codec::deserialize_strict(&bytes).unwrap();
    let mut target = machine(isa, native);
    saved.install_in_prepared(&mut target).unwrap();
    assert_eq!(CoreCheckpoint::capture(&target).unwrap(), saved);
    target
}

fn step(cpu: &mut AArch64Cpu, entry: Entry) -> Result<CpuExit, ArmError> {
    match entry {
        Entry::Direct => cpu.step(),
        Entry::System => cpu.step_system(),
        Entry::Diagnostic => cpu.step_system_with_fault_exit(),
    }
}

fn successful_case(isa: Isa, entry: Entry, instructions: u64, cycles: u64, value: u64) {
    let mut cpu = restored(isa, instructions, cycles, value, false);
    assert!(matches!(step(&mut cpu, entry).unwrap(), CpuExit::Continue));
    assert_eq!(cpu.insn_count, instructions.wrapping_add(1));
    assert_eq!(cpu.cycle_count, cycles.wrapping_add(1));
    let expected = if matches!(isa, Isa::A64) {
        value.wrapping_add(1)
    } else {
        (value & 0xffff_ffff_0000_0000) | u64::from((value as u32).wrapping_add(1))
    };
    assert_eq!(cpu.x[0], expected, "{isa:?} {entry:?}");
    assert_eq!(cpu.x[1], 0x9876_5432_10fe_dcba);
    assert_eq!(cpu.pc, ENTRY + isa.bytes().len() as u64);
    assert_eq!(cpu.last_instruction_size as usize, isa.bytes().len());
    assert_eq!(
        cpu.sysregs.cntpct_el0,
        TICKS.wrapping_add(if matches!(entry, Entry::Direct) {
            0
        } else {
            16
        })
    );
}

macro_rules! overflow_case {
    ($name:ident, $isa:ident, $instructions:expr, $cycles:expr) => {
        #[test]
        fn $name() {
            successful_case(Isa::$isa, Entry::Diagnostic, $instructions, $cycles, 1);
        }
    };
}

overflow_case!(cold_a64_instruction_counter_wraps, A64, u64::MAX, 0);
overflow_case!(cold_a64_cycle_counter_wraps, A64, 0, u64::MAX);
overflow_case!(cold_arm_instruction_counter_wraps, Arm, u64::MAX, 0);
overflow_case!(cold_arm_cycle_counter_wraps, Arm, 0, u64::MAX);
overflow_case!(cold_thumb16_instruction_counter_wraps, Thumb16, u64::MAX, 0);
overflow_case!(cold_thumb16_cycle_counter_wraps, Thumb16, 0, u64::MAX);
overflow_case!(cold_thumb32_instruction_counter_wraps, Thumb32, u64::MAX, 0);
overflow_case!(cold_thumb32_cycle_counter_wraps, Thumb32, 0, u64::MAX);

#[test]
fn zero_count_control_admits_and_executes_every_width_and_entry() {
    for isa in Isa::ALL {
        for entry in [Entry::Direct, Entry::System, Entry::Diagnostic] {
            successful_case(isa, entry, 0, 0, 1);
        }
    }
}

#[test]
fn restored_cold_counters_cover_independent_boundary_partitions_and_operands() {
    for isa in Isa::ALL {
        for entry in [Entry::Direct, Entry::System, Entry::Diagnostic] {
            for instructions in [0, u64::MAX - 1, u64::MAX] {
                for cycles in [0, u64::MAX - 1, u64::MAX] {
                    for value in [0, 0x7fff_ffff, u64::MAX] {
                        successful_case(isa, entry, instructions, cycles, value);
                    }
                }
            }
        }
    }
}

#[test]
fn restored_maximum_counters_do_not_charge_a_faulting_fetch() {
    for isa in Isa::ALL {
        for entry in [Entry::Direct, Entry::Diagnostic] {
            let mut cpu = restored(isa, u64::MAX, u64::MAX, 0x1234, false);
            cpu.set_pc(0x5000);
            assert!(matches!(
                step(&mut cpu, entry),
                Err(ArmError::MemoryError(_))
            ));
            assert_eq!((cpu.insn_count, cpu.cycle_count), (u64::MAX, u64::MAX));
            assert_eq!((cpu.pc, cpu.x[0]), (0x5000, 0x1234));
        }
    }
}

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[test]
fn restored_hot_a64_counters_use_actual_native_entries_at_every_boundary() {
    for instructions in [0, u64::MAX - 1, u64::MAX] {
        for cycles in [0, u64::MAX - 1, u64::MAX] {
            let mut cpu = restored(Isa::A64, instructions, cycles, u64::MAX, true);
            assert_eq!(
                cpu.jit.bounded_runs, 0,
                "restoration retains no native cache"
            );
            cpu.jit
                .hot
                .insert(ENTRY, super::super::A64_JIT_HOT_THRESHOLD - 1);
            assert!(matches!(cpu.step_system().unwrap(), CpuExit::Continue));
            assert_eq!(
                cpu.jit.bounded_runs, 1,
                "must execute the sampled instruction natively"
            );
            assert_eq!((cpu.pc, cpu.x[0]), (ENTRY + 4, 0));
            assert_eq!(cpu.insn_count, instructions.wrapping_add(1));
            assert_eq!(cpu.cycle_count, cycles.wrapping_add(1));
            assert_eq!(cpu.sysregs.cntpct_el0, TICKS.wrapping_add(16));
        }
    }
}

// Typed test-only construction of valid private records for adapter tests.
// Production exposes no counter setter and keeps the existing wire fields.
impl CoreCheckpoint {
    pub(crate) fn with_test_retirement_counters(mut self, instructions: u64, cycles: u64) -> Self {
        self.insn_count = instructions;
        self.cycle_count = cycles;
        self
    }
}
