//! Execute native debug-control and retirement policies without a host VM.
//! These are SDK fault-injection traces, not physical Intel qualification.
#[path = "hvf_native_debug/data_breakpoints.rs"]
mod data_breakpoint_tests;
#[path = "../../../src/backend/hvf/data_breakpoints.rs"]
mod data_breakpoints;
#[path = "../../../src/backend/hvf/interrupt_shadow.rs"]
mod interrupt_shadow;
#[path = "../../../src/backend/hvf/native_step.rs"]
mod native_step;
#[path = "../../../src/backend/hvf/output.rs"]
mod output;
#[path = "hvf_native_debug/port_breakpoints.rs"]
mod port_breakpoint_tests;
#[path = "../../../src/backend/hvf/retirement.rs"]
mod retirement;

use native_step::{Access, MONITOR_TRAP, State};
use std::collections::BTreeMap;

#[path = "hvf_native_debug/sdk_adapter.rs"]
mod sdk_adapter;

#[derive(Clone, Copy, Debug)]
enum Fault {
    Before,
    After,
    WrongRead,
}

struct Host {
    capability: u64,
    control: u64,
    trace: Vec<(&'static str, u64)>,
    faults: BTreeMap<usize, Fault>,
}

impl Default for Host {
    fn default() -> Self {
        Self {
            capability: u64::from(u32::MAX) << 32,
            control: (1 << 7) | (1 << 24) | (1 << 31),
            trace: vec![],
            faults: BTreeMap::new(),
        }
    }
}

impl Host {
    fn call(&mut self, name: &'static str, value: u64) -> Result<Option<Fault>, String> {
        let fault = self.faults.get(&self.trace.len()).copied();
        self.trace.push((name, value));
        if matches!(fault, Some(Fault::Before)) {
            Err(format!("{name} failed before mutation"))
        } else {
            Ok(fault)
        }
    }
}

impl Access for Host {
    fn capability(&mut self) -> Result<u64, String> {
        self.call("capability", self.capability)?;
        Ok(self.capability)
    }
    fn read_control(&mut self) -> Result<u64, String> {
        let fault = self.call("read", self.control)?;
        Ok(if matches!(fault, Some(Fault::WrongRead)) {
            self.control ^ 1
        } else {
            self.control
        })
    }
    fn write_control(&mut self, value: u64) -> Result<(), String> {
        let fault = self.call("write", value)?;
        self.control = value;
        if matches!(fault, Some(Fault::After)) {
            Err("write failed after mutation".into())
        } else {
            Ok(())
        }
    }
}

#[test]
fn host_transitions_preserve_every_unrelated_processor_control() {
    for bit in 0..32 {
        if bit == 27 {
            continue;
        }
        for initial in [0, 1u64 << bit, u64::from(u32::MAX) & !MONITOR_TRAP] {
            let state = State::default();
            let mut host = Host {
                control: initial,
                ..Host::default()
            };
            for enabled in [false, true, true, false, false] {
                state.configure(&mut host, enabled).unwrap();
                assert_eq!(state.enabled(), enabled);
                assert_eq!(host.control & !MONITOR_TRAP, initial);
                assert_eq!(host.control & MONITOR_TRAP != 0, enabled);
            }
        }
    }
}

#[test]
fn every_required_and_allowed_capability_bit_is_checked() {
    for bit in 0..32 {
        for required in [false, true] {
            for allowed in [false, true] {
                let mask = 1u64 << bit;
                let mut host = Host::default();
                let permit = u64::from(u32::MAX) & if allowed { u64::MAX } else { !mask };
                host.capability = (permit << 32) | if required { mask } else { 0 };
                host.control = if required { mask } else { 0 };
                let state = State::default();
                let result = state.configure(&mut host, false);
                let valid = (!required || allowed) && !(required && bit == 27);
                assert_eq!(
                    result.is_ok(),
                    valid,
                    "bit={bit}, required={required}, allowed={allowed}"
                );
                assert_eq!(state.ready().is_ok(), valid);
                assert!(host.trace.iter().all(|(name, _)| *name != "write"));
            }
        }
    }
}

#[test]
fn unsupported_enable_does_not_poison_ordinary_execution() {
    let state = State::default();
    let mut host = Host::default();
    host.capability &= !(MONITOR_TRAP << 32);
    assert!(state.configure(&mut host, true).is_err());
    assert!(state.ready().is_ok());
    assert!(!state.enabled());
    assert_eq!(host.trace.len(), 1);
    state.configure(&mut host, false).unwrap();
}

#[test]
fn invalid_or_unowned_current_controls_fence_the_owner() {
    for control in [1u64 << 32, MONITOR_TRAP, u64::MAX] {
        let state = State::default();
        let mut host = Host {
            control,
            ..Host::default()
        };
        assert!(state.configure(&mut host, true).is_err());
        assert!(state.ready().is_err());
        let calls = host.trace.len();
        assert!(state.configure(&mut host, false).is_err());
        assert_eq!(host.trace.len(), calls);
        assert!(state.take_completion().is_err());
    }
    for (capability, control) in [(3u64 << 32, 4), ((3u64 << 32) | 1, 0)] {
        let state = State::default();
        let mut host = Host {
            capability,
            control,
            ..Host::default()
        };
        assert!(state.configure(&mut host, false).is_err());
        assert!(state.ready().is_err());
    }
}

#[test]
fn capability_or_initial_control_read_failure_is_terminal() {
    for at in [0, 1] {
        let state = State::default();
        let mut host = Host::default();
        host.faults.insert(at, Fault::Before);
        assert!(state.configure(&mut host, true).is_err());
        assert!(state.ready().is_err());
        assert!(!state.enabled());
        assert_eq!(host.trace.len(), at + 1);
    }
}

#[test]
fn failed_updates_restore_the_full_word_before_allowing_reuse() {
    for initial_step in [false, true] {
        for (at, fault) in [
            (2, Fault::Before),
            (2, Fault::After),
            (3, Fault::Before),
            (3, Fault::WrongRead),
        ] {
            let state = State::default();
            let mut host = Host::default();
            if initial_step {
                state.configure(&mut host, true).unwrap();
                state.complete_instruction();
            }
            let before = host.control;
            host.trace.clear();
            host.faults.insert(at, fault);
            assert!(state.configure(&mut host, !initial_step).is_err());
            assert_eq!(host.control, before);
            assert_eq!(state.enabled(), initial_step);
            assert!(state.ready().is_ok());
            assert_eq!(state.take_completion().unwrap(), initial_step);
            assert_eq!(host.trace.last(), Some(&("read", before)));
        }
    }
}

#[test]
fn unverified_compensation_fences_entry_completion_and_further_sdk_calls() {
    for (first_at, first_fault, rollback_at) in [(2, Fault::After, 3), (3, Fault::WrongRead, 4)] {
        for (offset, fault) in [
            (0, Fault::Before),
            (0, Fault::After),
            (1, Fault::Before),
            (1, Fault::WrongRead),
        ] {
            let state = State::default();
            let mut host = Host::default();
            host.faults.insert(first_at, first_fault);
            host.faults.insert(rollback_at + offset, fault);
            assert!(state.configure(&mut host, true).is_err());
            assert!(state.ready().is_err());
            assert!(state.take_completion().is_err());
            let calls = host.trace.len();
            assert!(state.configure(&mut host, false).is_err());
            assert_eq!(host.trace.len(), calls);
        }
    }
}

#[test]
fn emulated_completion_is_one_shot_and_new_requests_discard_old_completions() {
    let state = State::default();
    let mut host = Host::default();
    state.complete_instruction();
    assert!(!state.take_completion().unwrap());
    for enabled in [true, false, true] {
        state.configure(&mut host, enabled).unwrap();
        assert!(!state.take_completion().unwrap());
        state.complete_instruction();
        assert_eq!(state.take_completion().unwrap(), enabled);
        assert!(!state.take_completion().unwrap());
        state.complete_instruction();
        state.configure(&mut host, enabled).unwrap();
        assert!(!state.take_completion().unwrap());
    }
    state.complete_instruction();
    state.discard_completion();
    assert!(!state.take_completion().unwrap());
}

#[test]
fn monitor_trap_is_a_debug_boundary_without_retirement_credit() {
    let state = State::default();
    let mut host = Host::default();
    state.configure(&mut host, true).unwrap();
    state.monitor_trap().unwrap();
    assert!(!state.take_completion().unwrap());
    assert!(state.enabled());
    state.configure(&mut host, false).unwrap();
    assert!(state.monitor_trap().is_err());
    assert!(state.ready().is_err());
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    Flags,
    Control,
    Pending,
    Shadow,
    Advance,
    WriteFlags(u64),
    WritePending(u64),
    WriteShadow(u64),
}

struct Instruction {
    flags: u64,
    control: u64,
    pending: u64,
    shadow: u64,
    rip: u64,
    trace: Vec<Call>,
    fail_at: Option<usize>,
}

impl Instruction {
    fn call(&mut self, call: Call) -> Result<(), usize> {
        let index = self.trace.len();
        self.trace.push(call);
        if self.fail_at == Some(index) {
            Err(index)
        } else {
            Ok(())
        }
    }
}

impl retirement::Access for Instruction {
    type Error = usize;
    fn rflags(&mut self) -> Result<u64, usize> {
        self.call(Call::Flags)?;
        Ok(self.flags)
    }
    fn debug_control(&mut self) -> Result<u64, usize> {
        self.call(Call::Control)?;
        Ok(self.control)
    }
    fn pending_debug(&mut self) -> Result<u64, usize> {
        self.call(Call::Pending)?;
        Ok(self.pending)
    }
    fn interruptibility(&mut self) -> Result<u64, usize> {
        self.call(Call::Shadow)?;
        Ok(self.shadow)
    }
    fn advance_ip(&mut self) -> Result<(), usize> {
        self.call(Call::Advance)?;
        self.rip += 1;
        Ok(())
    }
    fn write_rflags(&mut self, value: u64) -> Result<(), usize> {
        self.call(Call::WriteFlags(value))?;
        self.flags = value;
        Ok(())
    }
    fn write_pending_debug(&mut self, value: u64) -> Result<(), usize> {
        self.call(Call::WritePending(value))?;
        self.pending = value;
        Ok(())
    }
    fn write_interruptibility(&mut self, value: u64) -> Result<(), usize> {
        self.call(Call::WriteShadow(value))?;
        self.shadow = value;
        Ok(())
    }
}

fn instruction() -> Instruction {
    Instruction {
        flags: 0x1_0303,
        control: 0,
        pending: 0x1001,
        shadow: 0xb,
        rip: 0x1000,
        trace: vec![],
        fail_at: None,
    }
}

#[test]
fn guest_step_traps_and_resume_flags_are_independent_of_host_requests() {
    for tf in [false, true] {
        for rf in [false, true] {
            for btf in [false, true] {
                for pending in [0, 1, 0x100f, 0x4000, 0x500f] {
                    for shadow in 0..16 {
                        let mut cpu = instruction();
                        cpu.flags =
                            0x203 | if tf { 1 << 8 } else { 0 } | if rf { 1 << 16 } else { 0 };
                        cpu.control = if btf { 2 } else { 0 };
                        cpu.pending = pending;
                        cpu.shadow = shadow;
                        let flags = cpu.flags;
                        retirement::complete(&mut cpu).unwrap();
                        assert_eq!(cpu.flags, flags & !(1 << 16));
                        assert_eq!(cpu.pending, pending | if tf && !btf { 1 << 14 } else { 0 });
                        assert_eq!(cpu.shadow, shadow & !3);
                        assert_eq!(cpu.rip, 0x1001);
                        assert_eq!(
                            &cpu.trace[..5],
                            &[
                                Call::Flags,
                                Call::Control,
                                Call::Pending,
                                Call::Shadow,
                                Call::Advance
                            ]
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn each_retirement_failure_stops_before_later_writes_and_host_completion() {
    let mut success = instruction();
    retirement::complete(&mut success).unwrap();
    assert_eq!(success.trace.len(), 8);
    for failed in 0..success.trace.len() {
        let state = State::default();
        let mut host = Host::default();
        state.configure(&mut host, true).unwrap();
        let mut cpu = instruction();
        cpu.fail_at = Some(failed);
        let result = retirement::complete(&mut cpu);
        assert_eq!(result, Err(failed));
        assert_eq!(cpu.trace, success.trace[..=failed]);
        assert!(!state.take_completion().unwrap());
        state.poison(format!("retirement failed at {failed}"));
        assert!(state.ready().is_err());
        assert!(state.take_completion().is_err());
        if failed <= 4 {
            assert_eq!(cpu.rip, 0x1000);
        }
    }
}

#[test]
fn pending_guest_traps_wake_halt_without_charging_a_guest_instruction() {
    for shadow in 0..32 {
        for pending in [0, 1, 0xf, 1 << 12, 1 << 14, 0x500f] {
            assert_eq!(
                retirement::pending_trap(pending, shadow),
                pending & 0x5000 != 0 && shadow & 2 == 0,
            );
        }
    }
}

#[test]
fn outputs_reemit_identical_operands_until_acknowledged_then_complete_once() {
    for length in [1, 2, 15] {
        for data in [vec![0], vec![0xff; 8], vec![0xa5, 0x5a]] {
            let mut output = output::State::default();
            let state = State::default();
            let mut host = Host::default();
            state.configure(&mut host, true).unwrap();
            let request = (0xffff_ffff_ffff_fff0u64, data);
            assert_eq!(output.begin(request.clone(), length).unwrap(), request);
            for _ in 0..3 {
                assert_eq!(output.pending().unwrap(), Some(request.clone()));
                assert!(output.ready().is_err());
                assert!(!state.take_completion().unwrap());
            }
            let mut completions = 0;
            output
                .acknowledge(|got| {
                    assert_eq!(got, length);
                    completions += 1;
                    state.complete_instruction();
                    Ok(())
                })
                .unwrap();
            assert_eq!(completions, 1);
            assert!(output.ready().is_ok());
            assert_eq!(output.pending().unwrap(), None);
            assert!(state.take_completion().unwrap());
            assert!(!state.take_completion().unwrap());
            assert!(
                output
                    .acknowledge(|_| panic!("duplicate retirement"))
                    .is_err()
            );
            assert!(output.ready().is_err());
        }
    }
}

#[test]
fn output_completion_failure_never_repeats_an_acknowledged_device_effect() {
    let mut output = output::State::default();
    output.begin(vec![0x5a], 3).unwrap();
    assert!(output.begin(vec![0], 1).is_err());
    assert_eq!(output.pending().unwrap(), Some(vec![0x5a]));
    let error = output
        .acknowledge(|length| {
            assert_eq!(length, 3);
            Err("SDK failed after device commit".into())
        })
        .unwrap_err();
    assert!(output.ready().is_err());
    assert_eq!(output.pending(), Err(error.clone()));
    assert_eq!(
        output.acknowledge(|_| panic!("retrying acknowledged output")),
        Err(error)
    );
}

#[test]
fn malformed_output_length_and_unexpected_acknowledgment_have_no_effects() {
    for length in [0, 16, u64::MAX] {
        let mut output = output::State::default();
        assert!(output.begin(19, length).is_err());
        assert!(output.ready().is_ok());
        assert_eq!(output.pending().unwrap(), None);
    }
    let mut output = output::State::<u32>::default();
    assert!(output.acknowledge(|_| panic!("no pending output")).is_err());
    assert!(output.pending().is_err());
}
