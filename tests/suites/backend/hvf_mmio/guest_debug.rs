//! A device reply/acknowledgment reaches the shared guest debug boundary once.
use super::*;
use mmio::{CompletionAccess, Plan};

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
    fn finish_string_iteration(&mut self) -> Result<(), String> {
        retirement::complete_string_iteration(self)?;
        self.step.complete_instruction();
        Ok(())
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
        Action::Divide(input) => state.begin_divide(input, 0).unwrap(),
        Action::XmmRead { input, zero_upper } => state.begin_xmm(input, zero_upper).unwrap(),
        Action::YmmRead(input) => state.begin_ymm(input).unwrap(),
        Action::StringLoad(input) => state.begin_string_load(input).unwrap(),
        Action::Write(_)
        | Action::XmmWrite(_)
        | Action::XmmLaneRead { .. }
        | Action::XmmLaneWrite(_)
        | Action::VectorLogic { .. }
        | Action::YmmWrite(_)
        | Action::StringStore { .. } => {
            panic!("write has an output acknowledgment")
        }
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
                            restored
                                .acknowledge(|_, length| cpu.finish(length))
                                .unwrap();
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
        assert!(state.acknowledge(|_, length| cpu.finish(length)).is_err());
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
                .acknowledge(|_, _| panic!("duplicate retirement"))
                .is_err()
        );
    }
}

#[test]
fn setcc_pending_output_keeps_the_byte_until_restored_retirement() {
    use isa::x86_64::flags::bits::ZF;
    for (flags, expected) in [(2, 0), (2 | ZF, 1)] {
        let (plan, context) = prepared(&[0x0f, 0x94, 0x07], 0x182, flags);
        let Action::Write(data) = plan.action else {
            panic!("expected a SETE write");
        };
        let mut state = output::State::default();
        state.begin(data, plan.length).unwrap();
        let bytes = rax::codec::serialize(&state.checkpoint()).unwrap();
        drop(state);
        let (pending, failure) = rax::codec::deserialize_strict(&bytes).unwrap();
        let mut restored = output::State::<Vec<u8>>::from_checkpoint(pending, failure).unwrap();
        let mut cpu = host(context, 0, 0, true);
        assert_eq!(restored.pending().unwrap(), Some(vec![expected]));
        assert_eq!(cpu.rip, context.rip);
        assert!(!cpu.step.take_completion().unwrap());
        restored
            .acknowledge(|_, length| cpu.finish(length))
            .unwrap();
        assert_eq!(restored.pending().unwrap(), None);
        assert_eq!(cpu.rip, context.rip + 3);
        assert_eq!(cpu.registers, context.registers);
        assert_eq!(cpu.flags, flags);
        assert!(cpu.step.take_completion().unwrap());
        assert!(!cpu.step.take_completion().unwrap());
    }
}

#[test]
fn rep_lods_completes_each_read_at_its_restart_boundary_after_restore() {
    let code = [0xf3, 0x67, 0xad]; // REP LODSD with ESI and ECX.
    let (mut context, mut memory, mut record) = fixture(&code);
    context.registers[6] = (0x7654_3210 << 32) | record.linear;
    context.registers[1] = 0x8765_4321_0000_0002;
    context.rflags = retirement::SINGLE_STEP | retirement::RESUME | (1 << 10) | 2;
    let mut cpu = host(context, 0, 1, true);
    for (value, count) in [(0x1111_2222u32, 1), (0x3333_4444, 0)] {
        let plan = prepare(&context, &mut memory, record).unwrap();
        assert_eq!(plan.physical, record.physical);
        let binary = rax::codec::serialize(&pending(plan.action)).unwrap();
        let mut restored: mmio::InputState = rax::codec::deserialize_strict(&binary).unwrap();
        restored.validate_checkpoint().unwrap();
        assert_eq!(restored.descriptor(), Some((4, None)));
        restored.complete(&mut cpu, &value.to_le_bytes());
        assert!(restored.ready().is_ok());
        assert_eq!(cpu.registers[0], u64::from(value));
        assert_eq!(cpu.registers[1], count);
        assert_eq!(cpu.registers[6], record.linear - 4);
        assert_eq!(
            cpu.rip,
            context.rip + if count == 0 { code.len() as u64 } else { 0 }
        );
        assert_eq!(cpu.pending, 3 | retirement::PENDING_STEP);
        assert_eq!(cpu.shadow, 0);
        assert_eq!(cpu.flags & retirement::RESUME != 0, count != 0);
        assert!(cpu.step.take_completion().unwrap());
        assert!(!cpu.step.take_completion().unwrap());
        context.registers = cpu.registers;
        record.linear -= 4;
        record.physical -= 4;
    }
}

#[test]
fn rep_stos_roundtrips_pending_data_and_wraps_word_index_on_acknowledgment() {
    let code = [0x64, 0xf3, 0xaa]; // FS override is ignored for STOS.
    let (mut context, mut memory, mut record) = fixture(&code);
    context.code_bits = 16;
    context.paging.cr0 = 0;
    context.paging.cr4 = 0;
    context.paging.efer = 0;
    context.registers[7] = 0x1234_5678_9abc_ffff;
    context.registers[1] = 0x8765_4321_4321_0001;
    context.segments[0] = 0x9000;
    context.segments[4] = 0x3000;
    record.linear = 0x18fff;
    record.physical = record.linear;
    record.qualification = 0x182;
    let plan = prepare(&context, &mut memory, record).unwrap();
    let Action::StringStore { data, progress } = plan.action else {
        panic!("expected STOS output");
    };
    assert_eq!(data, [0xf0]);
    let mut state = output::State::default();
    state.begin((data, progress), plan.length).unwrap();
    let binary = rax::codec::serialize(&state.checkpoint()).unwrap();
    let (pending, failure) = rax::codec::deserialize_strict(&binary).unwrap();
    let mut restored =
        output::State::<(Vec<u8>, mmio::StringProgress)>::from_checkpoint(pending, failure)
            .unwrap();
    let mut cpu = host(context, 0, 0, false);
    assert_eq!(cpu.registers, context.registers);
    restored
        .acknowledge(|(data, progress), length| {
            assert_eq!(data, &[0xf0]);
            assert_eq!(progress.length, length);
            let (updates, next) = progress.updates(data.len() as u8, false);
            for (index, value) in updates.into_iter().flatten() {
                cpu.write_gpr(index, value)?;
            }
            assert_eq!(next, Some(length));
            cpu.finish(length)
        })
        .unwrap();
    assert_eq!(cpu.registers[7], 0x1234_5678_9abc_0000);
    assert_eq!(cpu.registers[1], 0x8765_4321_4321_0000);
    assert_eq!(cpu.registers[0], context.registers[0]);
    assert_eq!(cpu.rip, context.rip + code.len() as u64);
    assert!(restored.pending().unwrap().is_none());
}

#[test]
fn string_planner_checks_segment_direction_and_nonzero_repeat_count() {
    let (mut context, mut memory, mut record) = fixture(&[0x64, 0xf3, 0xac]);
    context.registers[6] = record.linear - 0x4000;
    context.registers[1] = 1;
    context.segments[4] = 0x4000;
    assert!(prepare(&context, &mut memory, record).is_ok());
    record.qualification = 0x182;
    assert!(prepare(&context, &mut memory, record).is_err());
    record.qualification = 0x181;
    context.registers[1] = 0;
    assert!(prepare(&context, &mut memory, record).is_err());
    context.registers[1] = 1;
    context.segments[4] = 0;
    assert!(prepare(&context, &mut memory, record).is_err());
}

#[test]
fn scalar_scas_retires_a_single_read_and_preserves_rax_and_rcx_after_restore() {
    use isa::x86_64::flags::bits::{AF, CF, OF, PF, SF, ZF};

    let status = CF | PF | AF | ZF | SF | OF;
    for (code, size, device, expected) in [
        (&[0xae][..], 1, 0x80u64, CF | PF | SF | OF),
        (&[0x66, 0xaf][..], 2, 1, CF | PF | AF | SF),
        (&[0xaf][..], 4, 0x8000_0000, PF | ZF),
        (
            &[0x48, 0xaf][..],
            8,
            0x8000_0000_0000_0000,
            CF | PF | SF | OF,
        ),
        (&[0x67, 0xae][..], 1, 0x80, CF | PF | SF | OF),
    ] {
        for backwards in [false, true] {
            let (mut context, mut memory, record) = fixture(code);
            context.registers[0] = match size {
                1 => 0x1234_abcd_1234_007f,
                2 => 0x1234_abcd_1234_0000,
                4 => 0x1234_abcd_8000_0000,
                8 => 0,
                _ => unreachable!(),
            };
            context.registers[1] = 0x5678_1234_9abc_0000;
            context.registers[7] = record.linear | (u64::from(code[0] == 0x67) * (0x1234 << 32));
            let direction = u64::from(backwards) << 10;
            context.rflags = status | direction | retirement::SINGLE_STEP | retirement::RESUME | 2;
            let plan = prepare(&context, &mut memory, record)
                .expect("scalar SCAS needs a translated device read");
            assert_eq!(plan.physical, record.physical);
            let bytes = rax::codec::serialize(&pending(plan.action)).unwrap();
            let mut restored: mmio::InputState = rax::codec::deserialize_strict(&bytes).unwrap();
            restored.validate_checkpoint().unwrap();
            assert_eq!(restored.descriptor(), Some((size, None)));
            let mut cpu = host(context, 0, 1, true);
            restored.complete(&mut cpu, &device.to_le_bytes()[..usize::from(size)]);
            assert!(restored.ready().is_ok());
            let expected_di = if backwards {
                record.linear - u64::from(size)
            } else {
                record.linear + u64::from(size)
            };
            let mut expected_gprs = context.registers;
            expected_gprs[7] = expected_di;
            assert_eq!(cpu.registers, expected_gprs);
            assert_eq!(
                cpu.flags,
                direction | retirement::SINGLE_STEP | expected | 2
            );
            assert_eq!(cpu.rip, context.rip + code.len() as u64);
            assert_eq!(cpu.shadow, 0);
            assert!(cpu.step.take_completion().unwrap());
            assert!(!cpu.step.take_completion().unwrap());
        }
    }
}

#[test]
fn scalar_scas_uses_es_and_wraps_di_and_refuses_write_and_exhausted_repeat_exits() {
    let (mut context, mut memory, mut record) = fixture(&[0x64, 0xae]);
    context.code_bits = 16;
    context.paging.cr0 = 0;
    context.paging.cr4 = 0;
    context.paging.efer = 0;
    context.registers[7] = 0x1234_5678_9abc_ffff;
    context.segments[0] = 0x9000;
    context.segments[4] = 0x3000;
    record.linear = 0x18fff;
    record.physical = record.linear;
    let plan = prepare(&context, &mut memory, record).unwrap();
    let mut cpu = host(context, 0, 0, false);
    let mut state = pending(plan.action);
    state.complete(&mut cpu, &[context.registers[0] as u8]);
    assert!(state.ready().is_ok());
    assert_eq!(cpu.registers[7], 0x1234_5678_9abc_0000);
    assert_eq!(cpu.rip, context.rip + 2);
    record.qualification = 0x182;
    assert!(prepare(&context, &mut memory, record).is_err());
    record.qualification = 0x181;
    context.registers[1] = 0x7654_3210_aaaa_0000;
    for prefix in [0xf2, 0xf3] {
        memory.bytes(context.rip, &[prefix, 0xae]);
        assert!(prepare(&context, &mut memory, record).is_err());
    }
}

#[test]
fn repeated_scas_preserves_restart_flags_and_commits_only_the_ending_comparison() {
    use isa::x86_64::flags::bits::{AF, CF, PF, SF, ZF};

    for (prefix, first, different, stop) in
        [(0xf3, 0u8, 1u8, CF | PF | AF | SF), (0xf2, 1, 0, PF | ZF)]
    {
        for (suffix, size) in [
            (&[0xae][..], 1),
            (&[0x66, 0xaf][..], 2),
            (&[0xaf][..], 4),
            (&[0x48, 0xaf][..], 8),
        ] {
            for address32 in [false, true] {
                for backwards in [false, true] {
                    let mut code = vec![prefix];
                    if address32 {
                        code.push(0x67);
                    }
                    code.extend_from_slice(suffix);
                    let (mut context, mut memory, mut record) = fixture(&code);
                    let high = if address32 { 0xaaaa_bbbb_0000_0000 } else { 0 };
                    let direction = u64::from(backwards) << 10;
                    let movement = if backwards {
                        -(size as i64)
                    } else {
                        size as i64
                    };
                    let restart = 2 | direction | CF | if prefix == 0xf2 { ZF } else { 0 };
                    context.rflags = restart | retirement::RESUME;
                    context.registers[0] = if size == 8 { 0 } else { 0x1234_0000_0000_0000 };
                    context.registers[1] = high | 3;
                    context.registers[7] = high | record.linear;

                    let mut cpu = host(context, 0, 1, true);
                    for (iteration, reply) in [first, different].into_iter().enumerate() {
                        let plan = prepare(&context, &mut memory, record)
                            .expect("repeated SCAS needs a translated device read");
                        let mut state = pending(plan.action);
                        let packed = rax::codec::serialize(&state).unwrap();
                        state = rax::codec::deserialize_strict(&packed).unwrap();
                        state.validate_checkpoint().unwrap();
                        assert_eq!(state.descriptor(), Some((size as u8, None)));
                        let scan = state.string_scan().unwrap();
                        let [rax, rcx, ..] = context.registers;
                        let rdi = context.registers[7];
                        assert!(scan.matches_scan_frontier(rax, rcx, rdi, context.rflags, 64));
                        assert!(!scan.matches_scan_frontier(rax, rcx + 1, rdi, context.rflags, 64));
                        state.complete(&mut cpu, &u64::from(reply).to_le_bytes()[..size]);
                        assert!(state.ready().is_ok());
                        let done = iteration == 1;
                        assert_eq!(cpu.registers[0], context.registers[0]);
                        assert_eq!(cpu.registers[1], 2 - iteration as u64);
                        assert_eq!(
                            cpu.registers[7],
                            record.linear.wrapping_add_signed(movement)
                        );
                        assert_eq!(
                            cpu.rip,
                            context.rip + if done { code.len() as u64 } else { 0 }
                        );
                        assert_eq!(
                            cpu.flags,
                            if done {
                                2 | direction | stop
                            } else {
                                context.rflags
                            }
                        );
                        assert_eq!(cpu.shadow, 0);
                        assert!(cpu.step.take_completion().unwrap());
                        assert!(!cpu.step.take_completion().unwrap());

                        context.registers = cpu.registers;
                        context.rflags = cpu.flags;
                        record.linear = cpu.registers[7];
                        record.physical = record.linear;
                    }
                }
            }
        }
    }
}

#[test]
fn repeated_scas_uses_cx_and_di_and_retires_when_the_count_is_exhausted() {
    let code = [0xf3, 0x64, 0xae];
    let (mut context, mut memory, mut record) = fixture(&code);
    let upper_count = 0x7654_3210_aaaa_0000;
    let upper_index = 0x1234_5678_9abc_0000;
    context.code_bits = 16;
    context.paging.cr0 = 0;
    context.paging.cr4 = 0;
    context.paging.efer = 0;
    context.registers[0] = 0;
    context.registers[1] = upper_count | 1;
    context.registers[7] = upper_index | 0xffff;
    context.segments[0] = 0x9000;
    context.segments[4] = 0x3000;
    record.linear = 0x18fff;
    record.physical = record.linear;
    let plan = prepare(&context, &mut memory, record).unwrap();
    let mut cpu = host(context, 0, 0, false);
    let mut state = pending(plan.action);
    state.complete(&mut cpu, &[0]);
    assert!(state.ready().is_ok());
    assert_eq!(cpu.registers[1], upper_count);
    assert_eq!(cpu.registers[7], upper_index);
    assert_eq!(cpu.rip, context.rip + code.len() as u64);
    assert_eq!(
        cpu.flags,
        2 | isa::x86_64::flags::bits::PF | isa::x86_64::flags::bits::ZF
    );
}
