//! Guest support-code entry and complete private-context continuation.
use super::*;
use crate::vm::timing::{ClockMode, TimingContext};
use crate::vm::vcpu::{RetirementRun, RetirementStop};

const ENTRY: u32 = 0x100;
const FRAME: u32 = 0x800;
const STANDARD: u32 = 3 << 24;

fn word(name: &str) -> u32 {
    let cases: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/development/a32-restricted-fp/cases.json"
    )))
    .unwrap();
    cases["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap()["arm"]
        .as_u64()
        .unwrap() as u32
}

fn fixture(thumb: bool, variant: u32) -> (Aarch32Vcpu, Arc<GuestMemoryMmap>, u32) {
    let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    let mut cpu = Aarch32Vcpu::new(0, memory.clone());
    cpu.cpu.cpsr.t = thumb;
    cpu.cpu.regs[15] = ENTRY;
    cpu.cpu.regs[4] = FRAME;
    cpu.cpu.regs[5] = STANDARD;
    cpu.cpu.vfp.write_s_bits(0, 0xdead_beef);
    let (control, lhs, rhs, expected) = match variant {
        0 => {
            cpu.cpu.vfp.mvfr0 &= !(15 << 28);
            (1 << 22, 0x3f80_0000, 0x3380_0000, 0x3f80_0000)
        }
        1 => {
            cpu.cpu.vfp.mvfr1 &= !0xf0;
            (0, 0x7fc1_2345, 0x3f80_0000, 0x7fc0_0000)
        }
        2 => {
            cpu.cpu.vfp.mvfr1 &= !15;
            (0, 1, 0, 0)
        }
        _ => panic!("unknown fixture variant"),
    };
    cpu.cpu.vfp.fpscr = Fpscr::from_bits(control);
    cpu.cpu.vfp.write_s_bits(2, lhs);
    cpu.cpu.vfp.write_s_bits(4, rhs);
    let saved_cpsr = cpu.cpu.cpsr.to_u32();
    let add = word("vadd_f32");
    let bytes = if thumb {
        [
            ((add >> 16) as u16).to_le_bytes(),
            (add as u16).to_le_bytes(),
        ]
        .concat()
    } else {
        add.to_le_bytes().to_vec()
    };
    memory
        .write_slice(&bytes, GuestAddress(u64::from(ENTRY)))
        .unwrap();
    let wfi = if thumb {
        0xbf30u16.to_le_bytes().to_vec()
    } else {
        0xe320_f003u32.to_le_bytes().to_vec()
    };
    memory
        .write_slice(&wfi, GuestAddress(u64::from(ENTRY + 4)))
        .unwrap();
    for (address, value) in [
        (4, word("vmsr_handler")),
        (8, word("rfeia_handler")),
        (FRAME, ENTRY),
        (FRAME + 4, saved_cpsr),
    ] {
        memory
            .write_slice(&value.to_le_bytes(), GuestAddress(u64::from(address)))
            .unwrap();
    }
    (cpu, memory, expected)
}

fn turn(cpu: &mut Aarch32Vcpu, clock: &Arc<TimingContext>) -> RetirementRun {
    let _binding = clock.enter();
    cpu.run_retirement_budget(1).unwrap()
}

#[test]
fn restricted_modes_enter_the_guest_without_retirement_or_data_effects() {
    for thumb in [false, true] {
        for variant in 0..3 {
            let (mut cpu, _, _) = fixture(thumb, variant);
            let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
            let before = (
                cpu.cpu.vfp.dregs,
                cpu.cpu.vfp.fpscr.bits(),
                cpu.cpu.cpsr.to_u32(),
            );
            let outcome = turn(&mut cpu, &clock);
            assert_eq!(outcome.retired, 0);
            assert!(matches!(outcome.stop, RetirementStop::StateChange));
            assert_eq!(
                (
                    cpu.instruction_count(),
                    clock.checkpoint_state().retired_units
                ),
                (0, 0)
            );
            assert_eq!(cpu.current_pc(), 4);
            assert_eq!(cpu.cpu.cpsr.mode, ProcessorMode::Undefined as u8);
            assert!(!cpu.cpu.cpsr.t);
            assert_eq!(cpu.cpu.regs[14], ENTRY + if thumb { 2 } else { 4 });
            assert_eq!(
                (
                    cpu.cpu.vfp.dregs,
                    cpu.cpu.vfp.fpscr.bits(),
                    cpu.cpu.spsr_und.to_u32()
                ),
                before
            );
        }
    }
}

#[test]
fn pre_and_post_bounce_private_contexts_resume_the_same_guest_handler_and_retry() {
    for thumb in [false, true] {
        for variant in 0..3 {
            for delivered in [false, true] {
                let (mut source, memory, expected) = fixture(thumb, variant);
                let source_clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
                if delivered {
                    assert_eq!(turn(&mut source, &source_clock).retired, 0);
                }
                let public = source.get_state().unwrap();
                let emulator = source.get_emulator_state().unwrap_or_default();
                let private = source.capture_backend_context().unwrap();
                let mut restored = Aarch32Vcpu::new(0, memory);
                restored
                    .restore_checkpoint_context(&public, &emulator, private.as_ref())
                    .unwrap();
                assert_eq!(
                    restored.save_context().unwrap(),
                    source.save_context().unwrap()
                );
                let restored_clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
                if !delivered {
                    for (cpu, clock) in [
                        (&mut source, &source_clock),
                        (&mut restored, &restored_clock),
                    ] {
                        assert_eq!(turn(cpu, clock).retired, 0);
                    }
                }
                assert_eq!(
                    restored.save_context().unwrap(),
                    source.save_context().unwrap()
                );
                // VMSR establishes supported controls; RFE retries the original
                // word with its original ARM/Thumb state; VADD and WFI retire.
                for index in 0..4 {
                    let actual = turn(&mut source, &source_clock);
                    let resumed = turn(&mut restored, &restored_clock);
                    assert_eq!(
                        (actual.retired, resumed.retired),
                        (1, 1),
                        "thumb={thumb} variant={variant} delivered={delivered} step={index}"
                    );
                    if index == 3 {
                        assert!(matches!(actual.stop, RetirementStop::Exit(VcpuExit::Hlt)));
                        assert!(matches!(resumed.stop, RetirementStop::Exit(VcpuExit::Hlt)));
                    } else {
                        assert!(matches!(actual.stop, RetirementStop::BudgetExhausted));
                        assert!(matches!(resumed.stop, RetirementStop::BudgetExhausted));
                    }
                    assert_eq!(
                        restored.save_context().unwrap(),
                        source.save_context().unwrap()
                    );
                }
                for (cpu, clock) in [(&source, &source_clock), (&restored, &restored_clock)] {
                    assert_eq!(
                        (
                            cpu.instruction_count(),
                            clock.checkpoint_state().retired_units
                        ),
                        (4, 4)
                    );
                    assert_eq!(
                        cpu.current_pc(),
                        u64::from(ENTRY + if thumb { 6 } else { 8 })
                    );
                    assert_eq!(cpu.cpu.cpsr.t, thumb);
                    assert_eq!(cpu.cpu.vfp.read_s_bits(0), expected);
                    assert_eq!(cpu.cpu.vfp.fpscr.bits() & !0x9f, STANDARD);
                }
            }
        }
    }
}
