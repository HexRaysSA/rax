//! Actual packet continuation and admission, including private forwarding state.
use super::*;

fn cpu(words: &[u32], isa: HexagonIsa, endian: Endianness) -> HexagonVcpu {
    let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
    for (i, word) in words.iter().enumerate() {
        let bytes = match endian {
            Endianness::Little => word.to_le_bytes(),
            Endianness::Big => word.to_be_bytes(),
        };
        mem.write_slice(&bytes, GuestAddress(0x1000 + 4 * i as u64))
            .unwrap();
    }
    let mut cpu = HexagonVcpu::new(2, mem, isa, endian);
    cpu.set_pc(0x1000);
    cpu
}
fn m(words: &[u32]) -> HexagonVcpu {
    cpu(words, HexagonIsa::V68, Endianness::Little)
}
fn restore(source: &HexagonVcpu, target: &mut HexagonVcpu) {
    target
        .restore_private(
            &source.get_state().unwrap(),
            &EmulatorState::default(),
            &source.capture_private(false).unwrap(),
        )
        .unwrap();
}
fn read(cpu: &HexagonVcpu, at: u64) -> u32 {
    let mut b = [0; 4];
    cpu.mem.read_slice(&mut b, GuestAddress(at)).unwrap();
    u32::from_le_bytes(b)
}

#[test]
fn all_isa_and_endian_profiles_preserve_retirement_without_replacing_target_memory() {
    use HexagonIsa::*;
    for isa in [V4, V5, V55, V60, V62, V65, V66, V67, V68, V69] {
        for endian in [Endianness::Little, Endianness::Big] {
            let mut source = cpu(&[0x7800_c540, 0x7800_c540], isa, endian);
            source.step_insn().unwrap();
            let mut target = cpu(&[0x7800_c540, 0x7800_c540], isa, endian);
            let owner = target.mem.clone();
            restore(&source, &mut target);
            assert!(Arc::ptr_eq(&owner, &target.mem));
            assert_eq!(
                target.capture_private(false).unwrap().data,
                source.capture_private(false).unwrap().data
            );
            target.step_insn().unwrap();
            assert_eq!(target.instruction_count(), 2);
            assert_eq!(target.regs.r[0], 42);
        }
    }
}
#[test]
fn pending_input_retains_earlier_gpr_forwarding_until_packet_commit() {
    // LLVM 23 hexagonv68: {r24=#1; r1=memw(r2)}.
    let words = [0x7800_4038, 0x9182_c001];
    let mut source = m(&words);
    source.regs.r[2] = 0xf000_0000;
    assert!(matches!(
        source.step_insn().unwrap(),
        Some(VcpuExit::MmioRead { size: 4, .. })
    ));
    assert_eq!(source.old_regs().r[24], 0);
    let mut target = m(&words);
    restore(&source, &mut target);
    for c in [&mut source, &mut target] {
        c.complete_io_in(&0x1122_3344u32.to_le_bytes());
        assert!(c.step_insn().unwrap().is_none());
        assert_eq!(c.regs.r[24], 1);
        assert_eq!(c.regs.r[1], 0x1122_3344);
        assert_eq!(c.packets, 1);
    }
}
#[test]
fn pending_duplex_uses_its_original_word_after_guest_code_changes() {
    // LLVM 23 hexagonv68: {r0=memb(r2); r1=memb(r3)}.
    let word = 0x3020_1031;
    let mut source = m(&[word]);
    source.regs.r[2] = 0xf000_0000;
    source.regs.r[3] = 0x2000;
    source
        .mem
        .write_slice(&[0x7f], GuestAddress(0x2000))
        .unwrap();
    assert!(matches!(
        source.step_insn().unwrap(),
        Some(VcpuExit::MmioRead { size: 1, .. })
    ));
    assert_eq!(
        source.pending_packet.as_ref().unwrap().pending_duplex,
        Some(word)
    );
    let raw = source.capture_private(false).unwrap();
    let state = source.get_state().unwrap();
    let mut target = m(&[word]);
    target
        .mem
        .write_slice(&[0x7f], GuestAddress(0x2000))
        .unwrap();
    for c in [&source, &target] {
        c.mem
            .write_slice(&0xffff_ffffu32.to_le_bytes(), GuestAddress(0x1000))
            .unwrap();
    }
    target
        .restore_private(&state, &EmulatorState::default(), &raw)
        .unwrap();
    for c in [&mut source, &mut target] {
        c.complete_io_in(&[42]);
        assert!(c.step_insn().unwrap().is_none());
        assert_eq!((c.regs.r[0], c.regs.r[1], c.packets), (42, 127, 1));
    }
}
#[test]
fn hvx_result_survives_a_later_suspended_scalar_input() {
    // LLVM 23 hexagonv68,+hvx,+hvx-length128b: {v7.w=vadd(v1.w,v2.w); r0=memb(r2)}.
    let words = [0x1c42_4107, 0x9102_c000];
    let mut source = m(&words);
    source.regs.r[2] = 0xf000_0000;
    source.regs.v[1] = std::array::from_fn(|i| i as u32);
    source.regs.v[2] = [2; 32];
    source.regs.v[7] = [0x7777_7777; 32];
    assert!(matches!(
        source.step_insn().unwrap(),
        Some(VcpuExit::MmioRead { .. })
    ));
    assert_eq!(source.old_regs().v[7], [0x7777_7777; 32]);
    let mut target = m(&words);
    restore(&source, &mut target);
    for c in [&mut source, &mut target] {
        c.complete_io_in(&[42]);
        assert!(c.step_insn().unwrap().is_none());
        assert_eq!(c.regs.v[7], std::array::from_fn(|i| i as u32 + 2));
        assert_eq!(c.packets, 1);
    }
}
#[test]
fn returned_mmio_outputs_are_not_replayed_by_restoration() {
    // LLVM 23 hexagonv68: {memw(r2)=r3; memw(r4)=r5}.
    let words = [0xa023_0045];
    let mut source = m(&words);
    source.regs.r[2] = 0xf000_0000;
    source.regs.r[3] = 0x1122_3344;
    source.regs.r[4] = 0xf000_0004;
    source.regs.r[5] = 0x5566_7788;
    let first = source.step_insn().unwrap();
    assert!(matches!(
        first,
        Some(VcpuExit::MmioWrite {
            addr: 0xf000_0000,
            ..
        })
    ));
    assert_eq!(source.packets, 0);
    let mut target = m(&words);
    restore(&source, &mut target);
    for c in [&mut source, &mut target] {
        let Some(VcpuExit::MmioWrite { addr, data }) = c.step_insn().unwrap() else {
            panic!()
        };
        assert_eq!(addr, 0xf000_0004);
        assert_eq!(data, 0x5566_7788u32.to_le_bytes());
        assert!(c.step_insn().unwrap().is_none());
        assert_eq!(c.packets, 1);
    }
}
#[test]
fn deferred_ram_publishes_after_the_already_returned_output_without_replay() {
    let words = [0xa023_0045];
    let mut source = m(&words);
    source.regs.r[2] = 0x2000;
    source.regs.r[3] = 0x1122_3344;
    source.regs.r[4] = 0xf000_0004;
    source.regs.r[5] = 0x5566_7788;
    assert!(matches!(
        source.step_insn().unwrap(),
        Some(VcpuExit::MmioWrite {
            addr: 0xf000_0004,
            ..
        })
    ));
    assert_eq!(read(&source, 0x2000), 0);
    let mut target = m(&words);
    restore(&source, &mut target);
    assert_eq!(read(&target, 0x2000), 0);
    for c in [&mut source, &mut target] {
        assert!(c.step_insn().unwrap().is_none());
        assert_eq!(read(c, 0x2000), 0x1122_3344);
        assert_eq!(c.packets, 1);
    }
}
#[test]
fn cancellation_and_foreign_scope_cannot_enable_candidate_entry() {
    let mut source = m(&[0x7800_c540, 0x7800_c540]);
    source.step_insn().unwrap();
    let target = m(&[0x7800_c540, 0x7800_c540]);
    let before = target.capture_private(false).unwrap().data;
    let mut candidate = target
        .prepare_private(
            &source.get_state().unwrap(),
            &EmulatorState::default(),
            &source.capture_private(false).unwrap(),
        )
        .unwrap();
    assert!(candidate.capture_private(false).is_err());
    assert!(candidate.step_insn().is_err());
    assert!(candidate.run_retirement_budget(0).is_ok());
    {
        let bindings = CheckpointBindings::new(&source.mem, vec![]);
        let scope = bindings.enter().unwrap();
        assert!(candidate.publication(&scope).is_err());
    }
    {
        let bindings = CheckpointBindings::new(&target.mem, vec![]);
        let scope = bindings.enter().unwrap();
        drop(candidate.publication(&scope).unwrap());
    }
    assert!(candidate.step_insn().is_err());
    assert_eq!(target.capture_private(false).unwrap().data, before);
    {
        let bindings = CheckpointBindings::new(&target.mem, vec![]);
        let scope = bindings.enter().unwrap();
        candidate.publication(&scope).unwrap().commit();
    }
    candidate.step_insn().unwrap();
    assert_eq!(candidate.packets, 2);
}
#[test]
fn private_projection_profile_and_phase_conflicts_reject_without_mutation() {
    let source = m(&[0x7800_c540]);
    let mut target = m(&[0x7800_c540]);
    let before = target.capture_private(false).unwrap().data;
    let state = source.get_state().unwrap();
    let raw = source.capture_private(false).unwrap();
    for mutation in 0..5 {
        let mut bad = raw.clone();
        if mutation == 0 {
            bad.data[0] ^= 1;
        } else {
            let mut image: Image = crate::codec::deserialize(&bad.data[8..]).unwrap();
            match mutation {
                1 => image.id += 1,
                2 => image.isa = HexagonIsa::V4,
                3 => image.producers.push(255),
                4 => image.finished = Some(Finished::Continue),
                _ => unreachable!(),
            }
            bad.data.truncate(8);
            bad.data.extend(crate::codec::serialize(&image).unwrap());
        }
        assert!(
            target
                .restore_private(&state, &EmulatorState::default(), &bad)
                .is_err()
        );
        assert_eq!(target.capture_private(false).unwrap().data, before);
    }
    let mut state = state;
    let CpuState::Hexagon(ref mut h) = state else {
        unreachable!()
    };
    h.regs.r[0] ^= 1;
    assert!(
        target
            .restore_private(&state, &EmulatorState::default(), &raw)
            .is_err()
    );
    assert_eq!(target.capture_private(false).unwrap().data, before);
}

#[test]
fn oversized_packet_collection_counts_reject_before_reading_elements() {
    for which in 0..3 {
        let source = m(&[0x7800_c540]);
        let mut image = Image::capture(&source).unwrap();
        match which {
            0 => {
                image.writes = (0..=MAX_WRITES)
                    .map(|_| WriteImage {
                        address: 0,
                        data: vec![],
                    })
                    .collect()
            }
            1 => {
                image.outputs = (0..=MAX_OUTPUTS)
                    .map(|_| OutputImage {
                        address: 0xf000_0000,
                        data: vec![],
                    })
                    .collect()
            }
            2 => image.producers = vec![0; 9],
            _ => unreachable!(),
        }
        let raw = crate::codec::serialize(&image).unwrap();
        let error = crate::codec::deserialize_limited::<Image, MAX_PAYLOAD>(&raw)
            .err()
            .expect("oversized field decoded")
            .to_string();
        assert!(error.contains("collection count exceeds bound"), "{error}");
    }
}

#[test]
fn non_duplex_parse_bits_reject_before_any_target_mutation() {
    let mut source = m(&[0x3020_1031]);
    source.regs.r[2] = 0xf000_0000;
    source.regs.r[3] = 0x2000;
    assert!(matches!(
        source.step_insn().unwrap(),
        Some(VcpuExit::MmioRead { size: 1, .. })
    ));
    let state = source.get_state().unwrap();
    let raw = source.capture_private(false).unwrap();
    let mut target = m(&[0x3020_1031]);
    let before = target.capture_private(false).unwrap().data;
    for parse in [1u32, 2, 3] {
        let mut image: Image = crate::codec::deserialize(&raw.data[8..]).unwrap();
        image.packet.as_mut().unwrap().pending_duplex = Some(0x3020_1031 | (parse << 14));
        let mut bad = raw.clone();
        bad.data.truncate(8);
        bad.data.extend(crate::codec::serialize(&image).unwrap());
        let error = target
            .restore_private(&state, &EmulatorState::default(), &bad)
            .err()
            .expect("a normal-word classification was accepted as retained duplex")
            .to_string();
        assert!(error.contains("not duplex"), "{error}");
        assert_eq!(target.capture_private(false).unwrap().data, before);
    }
}

#[test]
fn host_register_and_pc_overlays_preserve_idle_local_rights() {
    let mut source = m(&[0x9202_c001, 0xa0a2_c300]);
    source.regs.r[2] = 0x2000;
    source.regs.r[3] = 0x5566_7788;
    source.step_insn().unwrap();
    let mut state = source.get_state().unwrap();
    let CpuState::Hexagon(ref mut h) = state else {
        unreachable!()
    };
    h.regs.r[10] = 7;
    source.update_state(&state).unwrap();
    source.set_current_pc(0x1004).unwrap();
    assert!(source.step_insn().unwrap().is_none());
    assert_eq!(source.regs.p[0], 255);
    assert_eq!(source.regs.r[10], 7);
    assert_eq!(source.packets, 2);
    assert_eq!(read(&source, 0x2000), 0x5566_7788);
}
#[test]
fn pending_host_edits_reject_and_identical_controls_preserve_saved_work() {
    let mut source = m(&[0x7800_4038, 0x9182_c001]);
    source.regs.r[2] = 0xf000_0000;
    source.step_insn().unwrap();
    let before = source.capture_private(false).unwrap().data;
    let state = source.get_state().unwrap();
    source.update_state(&state).unwrap();
    source.set_current_pc(0x1000).unwrap();
    assert_eq!(source.capture_private(false).unwrap().data, before);
    assert!(source.set_current_pc(0x1004).is_err());
    assert_eq!(source.capture_private(false).unwrap().data, before);
    let mut state = state;
    let CpuState::Hexagon(ref mut h) = state else {
        unreachable!()
    };
    h.regs.r[10] = 7;
    assert!(source.update_state(&state).is_err());
    assert_eq!(source.capture_private(false).unwrap().data, before);
    source.complete_io_in(&0x1122_3344u32.to_le_bytes());
    source.step_insn().unwrap();
    assert_eq!(source.regs.r[24], 1);
    assert_eq!(source.regs.r[1], 0x1122_3344);
    assert_eq!(source.packets, 1);
}
