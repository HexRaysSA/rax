//! A device reply/acknowledgment reaches the shared guest debug boundary once.
use super::*;
use mmio::Plan;

struct Host {
    registers: [u64; 16],
    flags: u64,
    control: u64,
    pending: u64,
    shadow: u64,
    rip: u64,
    length: u64,
    step: native_step::State,
    calls: Vec<&'static str>,
    fail: Option<usize>,
}

impl Host {
    fn access(&mut self, name: &'static str) -> Result<(), String> {
        self.calls.push(name);
        if self.fail == Some(self.calls.len() - 1) {
            Err(name.into())
        } else {
            Ok(())
        }
    }
    fn finish(&mut self, length: u64) -> Result<(), String> {
        self.length = length;
        if let Err(error) = retirement::complete(self) {
            return Err(self.step.poison(error));
        }
        self.step.complete_instruction();
        Ok(())
    }
}

impl retirement::Access for Host {
    type Error = String;
    fn rflags(&mut self) -> Result<u64, String> {
        self.access("flags")?;
        Ok(self.flags)
    }
    fn debug_control(&mut self) -> Result<u64, String> {
        self.access("control")?;
        Ok(self.control)
    }
    fn pending_debug(&mut self) -> Result<u64, String> {
        self.access("pending")?;
        Ok(self.pending)
    }
    fn interruptibility(&mut self) -> Result<u64, String> {
        self.access("shadow")?;
        Ok(self.shadow)
    }
    fn advance_ip(&mut self) -> Result<(), String> {
        self.access("advance")?;
        self.rip += self.length;
        Ok(())
    }
    fn write_rflags(&mut self, flags: u64) -> Result<(), String> {
        self.access("writeflags")?;
        self.flags = flags;
        Ok(())
    }
    fn write_pending_debug(&mut self, pending: u64) -> Result<(), String> {
        self.access("writepending")?;
        self.pending = pending;
        Ok(())
    }
    fn write_interruptibility(&mut self, shadow: u64) -> Result<(), String> {
        self.access("writeshadow")?;
        self.shadow = shadow;
        Ok(())
    }
}

impl mmio::CompletionAccess for Host {
    type Error = String;
    fn write_gpr(&mut self, index: usize, value: u64) -> Result<(), String> {
        self.access("gpr")?;
        self.registers[index] = value;
        Ok(())
    }
    fn write_rflags(&mut self, flags: u64) -> Result<(), String> {
        self.access("alu-flags")?;
        self.flags = flags;
        Ok(())
    }
    fn finish_instruction(&mut self, length: u64) -> Result<(), String> {
        self.finish(length)
    }
}

const CASES: &[(&[u8], u64)] = &[
    (&[0x8b, 0x07], 0x181),          // MOV EAX,[RDI].
    (&[0x89, 0x07], 0x182),          // MOV [RDI],EAX.
    (&[0x03, 0x07], 0x181),          // ADD EAX,[RDI].
    (&[0x3b, 0x07], 0x181),          // CMP EAX,[RDI].
    (&[0x0f, 0xba, 0x27, 1], 0x181), // BT dword [RDI],1.
    (&[0x01, 0x07], 0x183),          // ADD [RDI],EAX.
    (&[0xc1, 0x27, 1], 0x182),       // SHL dword [RDI],1.
    (&[0x0f, 0xa4, 0x07, 1], 0x183), // SHLD dword [RDI],EAX,1.
];

#[test]
fn guest_tf_admits_all_scalar_transfer_widths_and_legacy_code_modes() {
    for bits in [16, 32, 64] {
        for size in [1, 2, 4, 8] {
            if size == 8 && bits != 64 {
                continue;
            }
            for (opcode, qualification) in [
                (if size == 1 { 0x8a } else { 0x8b }, 0x181),
                (if size == 1 { 0x88 } else { 0x89 }, 0x182),
                (if size == 1 { 0x02 } else { 0x03 }, 0x181),
                (if size == 1 { 0x3a } else { 0x3b }, 0x181),
                (if size == 1 { 0x00 } else { 0x01 }, 0x183),
            ] {
                let mut code = vec![];
                if (size == 2 && bits != 16) || (size == 4 && bits == 16) {
                    code.push(0x66);
                }
                if size == 8 {
                    code.push(0x48);
                }
                code.extend([opcode, 0x07]);
                let (mut context, mut memory, mut record) = fixture(&code);
                context.code_bits = bits;
                context.rflags = 0x1_0302;
                if bits == 16 {
                    context.registers[3] = 0; // BX addresses the operand.
                    context.segments[3] = record.linear;
                }
                record.qualification = qualification;
                let plan = prepare(&context, &mut memory, record).unwrap();
                assert_eq!(plan.length, code.len() as u64);
                assert!(!memory.reads.iter().any(|&(a, _)| a == record.physical));
            }
        }
    }
}

fn prepared(code: &[u8], qualification: u64, flags: u64) -> (Plan, Context) {
    let (mut context, mut memory, mut record) = fixture(code);
    context.rflags = flags;
    record.qualification = qualification;
    let plan = prepare(&context, &mut memory, record).unwrap();
    assert!(
        !memory
            .reads
            .iter()
            .any(|&(addr, _)| addr == record.physical)
    );
    (plan, context)
}

fn host(context: Context, control: u64, shadow: u64, enabled: bool) -> Host {
    Host {
        registers: context.registers,
        flags: context.rflags,
        control,
        pending: 3, // Disabled breakpoint status remains independent of BS.
        shadow,
        rip: context.rip,
        length: 0,
        step: native_step::State::from_checkpoint(enabled, false, None).unwrap(),
        calls: vec![],
        fail: None,
    }
}

fn pending(action: Action) -> mmio::InputState {
    let mut state = mmio::InputState::default();
    match action {
        Action::Read(input) => state.begin(input).unwrap(),
        Action::Rmw(input) => state.begin_rmw(input).unwrap(),
        Action::AluRead(input) => state.begin_alu_read(input).unwrap(),
        Action::Write(_) => panic!("write has an output acknowledgment"),
    }
    state
}

#[test]
fn scalar_mmio_tf_rf_btf_shadow_and_host_step_survive_pending_codec_roundtrips() {
    for &(code, qualification) in CASES {
        for flags in [2, 0x102, 0x1_0002, 0x1_0102] {
            for control in [0, 2] {
                for shadow in 0..16 {
                    for enabled in [false, true] {
                        let (plan, context) = prepared(code, qualification, flags);
                        let expected_pending = 3 | if flags & 0x100 != 0 && control == 0 {
                            1 << 14
                        } else {
                            0
                        };
                        if let Action::Write(data) = plan.action {
                            let mut state = output::State::default();
                            state.begin(data, plan.length).unwrap();
                            let binary = rax::codec::serialize(&state.checkpoint()).unwrap();
                            drop(state);
                            let (pending, failure) =
                                rax::codec::deserialize_strict(&binary).unwrap();
                            let mut restored =
                                output::State::<Vec<u8>>::from_checkpoint(pending, failure)
                                    .unwrap();
                            let mut cpu = host(context, control, shadow, enabled);
                            assert!(!cpu.step.take_completion().unwrap());
                            restored.acknowledge(|length| cpu.finish(length)).unwrap();
                            assert!(restored.ready().is_ok());
                            assert_eq!(cpu.registers, context.registers);
                            assert_eq!(cpu.flags, flags & !0x1_0000);
                            assert_eq!(cpu.pending, expected_pending);
                            assert_eq!(cpu.shadow, shadow & !3);
                            assert_eq!(cpu.rip, context.rip + plan.length);
                            assert_eq!(cpu.step.take_completion().unwrap(), enabled);
                            assert!(!cpu.step.take_completion().unwrap());
                            continue;
                        }
                        let state = pending(plan.action);
                        let binary = rax::codec::serialize(&state).unwrap();
                        let json = serde_json::to_vec(&state).unwrap();
                        drop(state);
                        for mut restored in [
                            rax::codec::deserialize_strict::<mmio::InputState>(&binary).unwrap(),
                            serde_json::from_slice::<mmio::InputState>(&json).unwrap(),
                        ] {
                            restored.validate_checkpoint().unwrap();
                            let mut cpu = host(context, control, shadow, enabled);
                            assert!(!cpu.step.take_completion().unwrap());
                            restored.complete(&mut cpu, &1u32.to_le_bytes());
                            assert!(restored.ready().is_ok());
                            assert_eq!(cpu.flags & !0x8d5, flags & !0x1_0000);
                            assert_eq!(cpu.pending, expected_pending);
                            assert_eq!(cpu.shadow, shadow & !3);
                            assert_eq!(cpu.rip, context.rip + plan.length);
                            assert_eq!(cpu.step.take_completion().unwrap(), enabled);
                            assert!(!cpu.step.take_completion().unwrap());
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn every_mmio_publication_failure_retains_reply_and_prevents_debug_completion() {
    for &(code, qualification) in CASES.iter().filter(|(_, q)| *q != 0x182) {
        let (plan, context) = prepared(code, qualification, 0x1_0102);
        let mut success = host(context, 0, 3, true);
        pending(plan.action.clone()).complete(&mut success, &1u32.to_le_bytes());
        assert!(success.step.take_completion().unwrap());
        for fail in 0..success.calls.len() {
            let mut cpu = host(context, 0, 3, true);
            cpu.fail = Some(fail);
            let mut state = pending(plan.action.clone());
            state.complete(&mut cpu, &1u32.to_le_bytes());
            assert!(state.failure().is_some());
            assert!(state.pending());
            state.validate_checkpoint().unwrap();
            let binary = rax::codec::serialize(&state).unwrap();
            let mut restored: mmio::InputState = rax::codec::deserialize_strict(&binary).unwrap();
            let before = cpu.calls.clone();
            cpu.fail = None;
            restored.complete(&mut cpu, &1u32.to_le_bytes());
            assert_eq!(cpu.calls, before);
            assert!(!cpu.step.take_completion().unwrap_or(false));
        }
    }
}

#[test]
fn acknowledged_output_retirement_errors_remain_terminal_across_checkpoints() {
    let (plan, context) = prepared(&[0x89, 0x07], 0x182, 0x1_0102);
    let Action::Write(data) = plan.action else {
        panic!("expected store")
    };
    let mut success = host(context, 0, 3, true);
    success.finish(plan.length).unwrap();
    for fail in 0..success.calls.len() {
        let mut cpu = host(context, 0, 3, true);
        cpu.fail = Some(fail);
        let mut state = output::State::default();
        state.begin(data.clone(), plan.length).unwrap();
        assert!(state.acknowledge(|length| cpu.finish(length)).is_err());
        assert!(!cpu.step.take_completion().unwrap_or(false));
        let binary = rax::codec::serialize(&state.checkpoint()).unwrap();
        drop(state);
        let (pending, failure) = rax::codec::deserialize_strict(&binary).unwrap();
        let mut restored = output::State::<Vec<u8>>::from_checkpoint(pending, failure).unwrap();
        assert!(restored.ready().is_err());
        assert!(
            restored.pending().is_err(),
            "an acknowledged write cannot dispatch again"
        );
        assert!(
            restored
                .acknowledge(|_| panic!("duplicate retirement"))
                .is_err()
        );
    }
}
