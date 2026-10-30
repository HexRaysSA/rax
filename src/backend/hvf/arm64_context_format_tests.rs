use super::*;

#[test]
fn terminal_state_roundtrips_and_cannot_carry_unfinished_io() {
    let mut stopped = fixture(false, false);
    stopped.pending_read = None;
    stopped.pending_reply = None;
    stopped.completion_error = None;
    for shutdown in [false, true] {
        stopped.shutdown = shutdown;
        assert_eq!(
            Context::decode(&stopped.encode().unwrap()).unwrap(),
            stopped
        );
    }
    let mut old_schema = stopped.encode().unwrap();
    old_schema[..8].copy_from_slice(b"RAXHVA03");
    assert!(Context::decode(&old_schema).is_err());

    let mut read = fixture(false, false);
    read.shutdown = true;
    let mut write = stopped.clone();
    write.pending_write = Some(PendingWrite {
        address: 0x0900_0030,
        data: vec![0xa5],
    });
    let mut unserviced_read = read.clone();
    unserviced_read.pending_reply = None;
    unserviced_read.completion_error = None;
    for invalid in [read, write, unserviced_read] {
        let mut raw = TAG.to_vec();
        raw.extend(crate::codec::serialize_limited(&invalid, LIMIT).unwrap());
        assert!(Context::decode(&raw).is_err());
    }
}

#[test]
fn undispatched_scalar_outputs_roundtrip_without_an_input_transaction() {
    for width in [1, 2, 4, 8] {
        let mut context = fixture(false, false);
        context.pending_read = None;
        context.pending_reply = None;
        context.completion_error = None;
        context.pending_write = Some(PendingWrite {
            address: 0x0900_0030,
            data: (0..width).map(|index| 0xa5 ^ index).collect(),
        });
        assert_eq!(
            Context::decode(&context.encode().unwrap()).unwrap(),
            context
        );
        for length in [0, 3, 16] {
            let mut bad = context.clone();
            bad.pending_write.as_mut().unwrap().data.resize(length, 0);
            assert!(bad.encode().is_err(), "invalid output width {length}");
        }
        let mut bad = context.clone();
        bad.pending_write.as_mut().unwrap().address = u64::MAX;
        if width > 1 {
            assert!(bad.encode().is_err(), "wrapped output width {width}");
        }
        context.pending_read = fixture(false, false).pending_read;
        assert!(
            context.encode().is_err(),
            "input and output cannot both be pending"
        );
    }
}

#[test]
fn deferred_completion_error_requires_the_original_complete_device_reply() {
    let mut context = fixture(false, false);
    context.pending_reply = None;
    let mut raw = TAG.to_vec();
    raw.extend(crate::codec::serialize_limited(&context, LIMIT).unwrap());
    assert!(
        Context::decode(&raw).is_err(),
        "a failed destination write must retain the consumed device reply"
    );
}

#[test]
fn staged_device_reply_requires_its_request_and_exact_width() {
    for width in [1, 2, 4, 8] {
        let mut context = fixture(false, false);
        context.pending_read.as_mut().unwrap().size = width;
        context.pending_reply = Some(vec![0xa5; usize::from(width)]);
        assert_eq!(
            Context::decode(&context.encode().unwrap()).unwrap(),
            context
        );
        for length in [0, usize::from(width) - 1, usize::from(width) + 1] {
            let mut invalid = context.clone();
            invalid.pending_reply = Some(vec![0xa5; length]);
            assert!(invalid.encode().is_err(), "request {width}, reply {length}");
        }
        context.pending_read = None;
        assert!(context.encode().is_err());
    }
    let mut context = fixture(false, false);
    context.completion_error = None;
    context.pending_reply = None;
    assert!(
        context.encode().is_ok(),
        "an unserviced read needs no reply"
    );
}

#[test]
fn active_sme2_cannot_omit_zt0_storage() {
    let mut context = fixture(false, true);
    for register in context
        .system
        .iter_mut()
        .chain(context.profile.feature_values.iter_mut())
    {
        if register.id == 0xc025 {
            register.value = 1 << 56;
        }
    }
    context.sme.zt = None;
    let mut raw = TAG.to_vec();
    raw.extend(crate::codec::serialize_limited(&context, LIMIT).unwrap());
    assert!(
        Context::decode(&raw).is_err(),
        "active SME2 requires its ZT0 storage"
    );
}

#[test]
fn sme_without_sme2_cannot_carry_zt0_storage() {
    let mut context = fixture(false, true);
    for register in context
        .system
        .iter_mut()
        .chain(context.profile.feature_values.iter_mut())
    {
        if register.id == 0xc025 {
            register.value = 0;
        }
    }
    let mut raw = TAG.to_vec();
    raw.extend(crate::codec::serialize_limited(&context, LIMIT).unwrap());
    assert!(
        Context::decode(&raw).is_err(),
        "SME without SME2 has no ZT0 storage"
    );
}
fn fixture(streaming: bool, za_enabled: bool) -> Context {
    // Synthetic storage values exercise framing and coherence. This fixture
    // does not claim native SDK support or architectural execution semantics.
    let mut system: Vec<Register> = SYSTEM_IDS
        .iter()
        .map(|&id| Register {
            id,
            value: if id == 0xc025 { 1 << 56 } else { u64::from(id) },
        })
        .collect();
    let id = 7;
    system.iter_mut().find(|r| r.id == 0xc005).unwrap().value =
        crate::isa::arm::aarch64::AArch64Cpu::mpidr_for_cpu_id(id);
    let maximum_svl = 64;
    let profile = Profile {
        system_ids: system.iter().map(|r| r.id).collect(),
        feature_values: system
            .iter()
            .filter(|r| FEATURE_IDS.binary_search(&r.id).is_ok())
            .cloned()
            .collect(),
        maximum_svl,
    };
    let pattern = |length| {
        (0..length)
            .map(|i| (i as u8).wrapping_mul(17).wrapping_add(0x35))
            .collect()
    };
    let sme = Sme {
        streaming,
        za_enabled,
        z: pattern(if streaming { 32 * 64 } else { 0 }),
        p: pattern(if streaming { 2 * 64 } else { 0 }),
        za: pattern(if za_enabled { 64 * 64 } else { 0 }),
        zt: za_enabled.then(|| pattern(64)),
    };
    let mut public = Aarch64CpuState::default();
    for (index, value) in public.regs.x.iter_mut().enumerate() {
        *value = 0xfedcba9800000000 | index as u64;
    }
    public.regs.pc = 0x40001234;
    public.regs.fpcr = 0x01800000;
    public.regs.fpsr = 0x0800009f;
    for (index, pair) in public.regs.v.iter_mut().enumerate() {
        *pair = [index as u64, !(index as u64)];
    }
    if streaming {
        for (index, z) in sme.z.chunks_exact(64).enumerate() {
            public.regs.v[index] = [
                u64::from_le_bytes(z[..8].try_into().unwrap()),
                u64::from_le_bytes(z[8..16].try_into().unwrap()),
            ];
        }
    }
    let mut context = Context {
        id,
        profile,
        public,
        system,
        gic_cpu: ICC_IDS
            .iter()
            .map(|&id| Register {
                id,
                value: u64::from(id),
            })
            .collect(),
        running_priority: 0x70,
        controls: Controls {
            vtimer_masked: true,
            vtimer_offset: 0x123456789abcdef0,
            trap_debug_exceptions: true,
            trap_debug_registers: false,
            pending_serror: true,
        },
        sme,
        shutdown: false,
        pending_read: Some(PendingRead {
            address: 0x09000000,
            register: 0,
            size: 8,
            sign_extend: false,
            sixty_four: true,
        }),
        completion_error: Some("Failed to write register 0: native test failure".into()),
        pending_reply: Some(vec![0xa5; 8]),
        pending_write: None,
    };
    context.project_system().unwrap();
    context.validate().unwrap();
    context
}
#[test]
fn all_streaming_and_za_modes_roundtrip_every_private_field_and_admit_exact_target() {
    for sm in [false, true] {
        for za in [false, true] {
            let context = fixture(sm, za);
            let raw = context.encode().unwrap();
            let restored = Context::decode(&raw).unwrap();
            assert_eq!(restored, context);
            let public = CpuState::Aarch64(context.public.clone());
            restored.admit(7, &context.profile, &public).unwrap();
            assert!(restored.admit(8, &context.profile, &public).is_err());
            let mut changed = context.profile.clone();
            changed.maximum_svl = 32;
            assert!(restored.admit(7, &changed, &public).is_err());
            let mut changed = context.public.clone();
            changed.regs.pc += 4;
            assert!(
                restored
                    .admit(7, &context.profile, &CpuState::Aarch64(changed))
                    .is_err()
            );
        }
    }
}
#[test]
fn rejects_every_truncation_trailing_data_unknown_version_and_oversized_count() {
    let raw = fixture(true, true).encode().unwrap();
    for end in 0..raw.len() {
        assert!(Context::decode(&raw[..end]).is_err(), "prefix {end}");
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(Context::decode(&trailing).is_err());
    let mut wrong = raw.clone();
    wrong[7] = b'?';
    assert!(Context::decode(&wrong).is_err());
    let mut count = raw.clone();
    count[12..20].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(Context::decode(&count).is_err());
    assert!(Context::decode(&vec![0; LIMIT + TAG.len() + 1]).is_err());
}
#[test]
fn rejects_projection_identity_alias_and_pending_request_inconsistencies() {
    let context = fixture(true, true);
    let mut cases = Vec::new();
    let mut bad = context.clone();
    bad.public.sregs.esr_el1 ^= 1;
    cases.push(bad);
    let mut bad = context.clone();
    bad.public.regs.sp ^= 16;
    cases.push(bad);
    let mut bad = context.clone();
    bad.public.regs.v[19][1] ^= 1;
    cases.push(bad);
    let mut bad = context.clone();
    bad.system
        .iter_mut()
        .find(|r| r.id == 0xc005)
        .unwrap()
        .value ^= 1;
    cases.push(bad);
    let mut bad = context.clone();
    bad.system.swap(0, 1);
    cases.push(bad);
    let mut bad = context.clone();
    bad.system[1].id = bad.system[0].id;
    cases.push(bad);
    let mut bad = context.clone();
    bad.pending_read.as_mut().unwrap().register = 32;
    cases.push(bad);
    let mut bad = context.clone();
    bad.pending_read.as_mut().unwrap().size = 3;
    cases.push(bad);
    let mut bad = context.clone();
    bad.pending_read = None;
    cases.push(bad);
    let mut bad = context.clone();
    bad.completion_error = Some("x".repeat(4097));
    cases.push(bad);
    let mut bad = context.clone();
    bad.gic_cpu.remove(0);
    cases.push(bad);
    let mut bad = context.clone();
    bad.running_priority = 256;
    cases.push(bad);
    let mut bad = context.clone();
    bad.sme.z.pop();
    cases.push(bad);
    let mut bad = context.clone();
    bad.sme.p.pop();
    cases.push(bad);
    let mut bad = context.clone();
    bad.sme.za_enabled = false;
    cases.push(bad);
    let mut bad = context.clone();
    bad.sme.zt.as_mut().unwrap().pop();
    cases.push(bad);
    for (index, bad) in cases.iter().enumerate() {
        assert!(bad.encode().is_err(), "case {index}");
    }
}
#[test]
fn missing_private_register_cannot_pass_target_profile_admission() {
    let context = fixture(false, false);
    let mut changed = context.clone();
    changed.system.retain(|r| r.id != 0xc082);
    changed.profile.system_ids.retain(|&id| id != 0xc082);
    // Format-level optionality cannot weaken the independently supplied native
    // target profile, even when a forged record edits its own inventory too.
    let raw = changed.encode().unwrap();
    let decoded = Context::decode(&raw).unwrap();
    assert!(
        decoded
            .admit(
                context.id,
                &context.profile,
                &CpuState::Aarch64(context.public)
            )
            .is_err()
    );
}
