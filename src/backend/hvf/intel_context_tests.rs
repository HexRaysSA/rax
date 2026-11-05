//! Portable admission tests; these fixtures do not establish SDK execution.
use super::*;
use crate::backend::intel_hvf_xsave::{Component, Layout};

#[test]
fn deadline_cpu_record_preserves_lvt_arm_and_queued_vectors_without_changing_old_records() {
    use crate::devices::lapic::tsc_deadline::Image;
    let old = context();
    let legacy = old.encode().unwrap();
    assert!(legacy.starts_with(b"RAXHVI02"));
    let loaded = Context::decode(&legacy).unwrap();
    assert!(loaded.deadline.is_none());
    assert_eq!(loaded.encode().unwrap(), legacy);
    let mut current = old;
    current.deadline = Some(Image {
        lvt: 0x40051,
        deadline: u64::MAX,
        pending: [0, 1 << 17, 0, 0],
    });
    let raw = current.encode().unwrap();
    assert!(raw.starts_with(b"RAXHVI03"));
    let decoded = Context::decode(&raw).unwrap();
    assert_eq!(decoded.deadline, current.deadline);
    assert_eq!(decoded.encode().unwrap(), raw);
    for end in 0..raw.len() {
        assert!(Context::decode(&raw[..end]).is_err(), "prefix {end}");
    }
    let mut bad = raw.clone();
    let image = bad.len() - Image::BYTES;
    bad[image..image + 4].copy_from_slice(&0x51u32.to_le_bytes());
    assert!(Context::decode(&bad).is_err());
    let mut trailing = raw;
    trailing.push(0);
    assert!(Context::decode(&trailing).is_err());
}

pub(crate) fn context() -> Context {
    let layout = Layout {
        mask: 7,
        size: 832,
        components: vec![Component {
            bit: 2,
            size: 256,
            offset: 576,
            align64: false,
        }],
        mxcsr_mask: 0xffbf,
    };
    let mut fp = vec![0; 832];
    fp[..2].copy_from_slice(&0x037fu16.to_le_bytes());
    fp[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
    fp[512..520].copy_from_slice(&3u64.to_le_bytes());
    let profile = Profile {
        identity: Identity {
            maximum_basic: 0x0d,
            maximum_extended: 0x8000_0008,
            vendor: *b"GenuineIntel",
            brand: vec![b' '; 48],
        },
        host: vec![Cpuid {
            leaf: 0,
            subleaf: 0,
            words: [0x0d, 0, 0, 0],
        }],
        xsave: layout,
        capabilities: Capabilities {
            pin: 0xffff_ffff_0000_0000,
            primary: 0xffff_ffff_0000_0000,
            secondary: 0xffff_ffff_0000_0000,
            entry: 0xffff_ffff_0000_0000,
            misc: 0,
        },
        fields: vmcs_candidates(),
        controls: policy_fields()
            .into_iter()
            .map(|id| Register { id, value: 0 })
            .collect(),
        tsc_hz: None,
    };
    let mut context = Context {
        deadline: None,
        id: 0,
        registers: register_ids()
            .into_iter()
            .map(|id| Register {
                id,
                value: if id == R::HV_X86_XCR0 as u32 {
                    1
                } else if id == R::HV_X86_RFLAGS as u32 {
                    2
                } else {
                    0
                },
            })
            .collect(),
        vmcs: profile
            .fields
            .iter()
            .map(|&id| Register { id, value: 0 })
            .collect(),
        msrs: MSRS.iter().map(|&id| Register { id, value: 0 }).collect(),
        profile,
        public: X86_64CpuState {
            regs: Default::default(),
            sregs: Default::default(),
        },
        emulator: EmulatorState::default(),
        fp,
        tpr: 0,
        priority_failure: None,
        apic_base: 0xfee0_0900,
        halted: false,
        shutdown: false,
        anchor: 1000,
        guest_tsc: u64::MAX - 10,
        clock: ClockBinding {
            offset: -1011,
            pending: None,
            epoch: None,
        },
        port_input: Default::default(),
        mmio_input: Default::default(),
        request: None,
        output: None,
        output_failure: None,
        execution_failure: None,
        restore_failure: None,
        debug: DebugState {
            enabled: false,
            completed: false,
            failure: None,
        },
    };
    refresh(&mut context);
    context
}
fn refresh(context: &mut Context) {
    let (public, emulator) = context.projection().unwrap();
    context.public = public;
    context.emulator = emulator;
}

#[test]
fn bounded_cpu_codec_rejects_every_truncation_and_trailing_byte() {
    let saved = context();
    let encoded = saved.encode().unwrap();
    assert_eq!(
        Context::decode(&encoded).unwrap().encode().unwrap(),
        encoded
    );
    for length in 0..encoded.len() {
        assert!(
            Context::decode(&encoded[..length]).is_err(),
            "prefix {length}"
        );
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(Context::decode(&trailing).is_err());
    let mut tag = encoded;
    tag[7] = b'9';
    assert!(Context::decode(&tag).is_err());
    assert!(Context::decode(&vec![0; CPU_LIMIT + 9]).is_err());
}

#[test]
fn software_owned_pat_roundtrips_without_sdk_private_vmcs_fields() {
    for pat in [0, 0x0101_0101_0101_0101, 0x0405_0607_0001_0406] {
        let mut saved = context();
        saved.emulator.pat = pat;
        refresh(&mut saved);
        let raw = saved.encode().unwrap();
        assert_eq!(&raw[..8], b"RAXHVI02");
        let loaded = Context::decode(&raw).unwrap();
        assert_eq!(loaded.emulator.pat, pat);
        assert_eq!(loaded.encode().unwrap(), raw);
        for id in [V::VMCS_GUEST_LINK_POINTER, V::VMCS_GUEST_IA32_PAT] {
            assert!(!loaded.profile.fields.contains(&(id as u32)));
        }
    }
    for entry in 0..8 {
        for invalid in [2, 3, 8, 0x80, 0xff] {
            let mut saved = context();
            saved.emulator.pat = u64::from(invalid as u8) << (entry * 8);
            assert!(saved.projection().is_err());
            assert!(saved.encode().is_err());
        }
    }
}

fn legacy_cpu_record(saved: &Context) -> Vec<u8> {
    let mut raw = b"RAXHVI01".to_vec();
    raw.extend(crate::codec::serialize_limited(saved, CPU_LIMIT).unwrap());
    raw
}

fn legacy_cpu_context() -> Context {
    let mut saved = context();
    for (id, value) in [
        (V::VMCS_GUEST_LINK_POINTER, u64::MAX),
        (V::VMCS_GUEST_IA32_PAT, 0),
    ] {
        saved.profile.fields.push(id as u32);
        saved.vmcs.push(Register {
            id: id as u32,
            value,
        });
    }
    saved.profile.fields.sort_unstable();
    saved.vmcs.sort_unstable_by_key(|field| field.id);
    saved
}

#[test]
fn legacy_fixed_pat_migration_preserves_the_architectural_reset_value() {
    let saved = legacy_cpu_context();
    let migrated = Context::decode(&legacy_cpu_record(&saved)).unwrap();
    assert_eq!(
        migrated.emulator.pat,
        crate::isa::x86_64::execute::system::IA32_PAT_RESET
    );
    assert_eq!(migrated.encode().unwrap(), context().encode().unwrap());
    for corruption in 0..6 {
        let mut saved = saved.clone();
        match corruption {
            0 => {
                saved
                    .vmcs
                    .iter_mut()
                    .find(|field| field.id == 0x2800)
                    .unwrap()
                    .value = 0
            }
            1 => {
                saved
                    .vmcs
                    .iter_mut()
                    .find(|field| field.id == 0x2804)
                    .unwrap()
                    .value = 2
            }
            2 => saved.emulator.pat = 0,
            3 => saved.profile.fields.retain(|id| *id != 0x2800),
            4 => saved.vmcs.retain(|field| field.id != 0x2804),
            5 => saved.profile.fields.swap(0, 1),
            _ => unreachable!(),
        }
        assert!(
            Context::decode(&legacy_cpu_record(&saved)).is_err(),
            "corruption {corruption}"
        );
    }
}

#[test]
fn missing_duplicate_reordered_and_foreign_registers_reject() {
    for bank_index in 0..3 {
        for corruption in 0..4 {
            let mut saved = context();
            let bank = match bank_index {
                0 => &mut saved.registers,
                1 => &mut saved.vmcs,
                _ => &mut saved.msrs,
            };
            match corruption {
                0 => {
                    bank.pop();
                }
                1 => bank[1].id = bank[0].id,
                2 => bank.swap(0, 1),
                3 => bank[0].id = u32::MAX,
                _ => unreachable!(),
            }
            assert!(
                saved.validate().is_err(),
                "bank {bank_index} corruption {corruption}"
            );
        }
    }
}

#[test]
fn guest_xcr0_and_public_projection_are_admitted_together() {
    for xcr0 in [0, 2, 4, 5, 8, u64::MAX] {
        let mut saved = context();
        saved
            .registers
            .iter_mut()
            .find(|r| r.id == R::HV_X86_XCR0 as u32)
            .unwrap()
            .value = xcr0;
        assert!(saved.validate().is_err(), "XCR0={xcr0:#x}");
    }
    for xcr0 in [1, 3, 7] {
        let mut saved = context();
        saved
            .registers
            .iter_mut()
            .find(|r| r.id == R::HV_X86_XCR0 as u32)
            .unwrap()
            .value = xcr0;
        assert!(saved.validate().is_ok());
    }
    let mut saved = context();
    saved.public.regs.xmm[15][1] ^= 1;
    assert!(saved.validate().is_err());
    let mut saved = context();
    saved.emulator.fpu.st[7][9] ^= 1;
    assert!(saved.validate().is_err());
    let saved = context();
    let mut profile = saved.profile.clone();
    profile.identity.brand[47] ^= 1;
    assert!(
        saved
            .admit(
                0,
                &profile,
                &CpuState::X86_64(saved.public.clone()),
                &saved.emulator
            )
            .is_err()
    );
    assert!(
        saved
            .admit(
                1,
                &saved.profile,
                &CpuState::X86_64(saved.public.clone()),
                &saved.emulator
            )
            .is_err()
    );
}

#[test]
fn pending_input_and_retained_failure_require_the_exported_request() {
    let mut saved = context();
    saved
        .port_input
        .begin(port_io::PendingInput {
            io: port_io::ScalarIo {
                port: 0x3f8,
                size: 1,
                direction: port_io::Direction::In,
            },
            original_rax: 0x1234,
            length: 3,
        })
        .unwrap();
    assert!(saved.validate().is_err());
    saved.request = Some(Packet::PortRead {
        port: 0x3f8,
        size: 1,
    });
    saved.validate().unwrap();
    saved
        .port_input
        .hold_failure(&[0xa5], "post-reply SDK failure".into());
    let roundtrip = Context::decode(&saved.encode().unwrap()).unwrap();
    assert_eq!(
        roundtrip.port_input.failure(),
        Some("post-reply SDK failure")
    );
    assert_eq!(
        crate::codec::serialize(&roundtrip.port_input).unwrap(),
        crate::codec::serialize(&saved.port_input).unwrap()
    );
    saved.request = Some(Packet::PortRead {
        port: 0x3f9,
        size: 1,
    });
    assert!(saved.validate().is_err());
}

#[test]
fn untrusted_mmio_register_parts_and_output_continuations_reject() {
    for part in [
        mmio::RegisterPart {
            index: 16,
            bits: 64,
            shift: 0,
        },
        mmio::RegisterPart {
            index: 4,
            bits: 8,
            shift: 8,
        },
        mmio::RegisterPart {
            index: 0,
            bits: 32,
            shift: 8,
        },
        mmio::RegisterPart {
            index: 0,
            bits: 0,
            shift: 0,
        },
    ] {
        assert!(!part.valid());
    }
    for (packet, length) in [
        (
            Packet::PortWrite {
                port: 1,
                data: vec![0; 8],
            },
            1,
        ),
        (
            Packet::Write {
                address: u64::MAX,
                data: vec![1],
            },
            1,
        ),
        (Packet::PortRead { port: 1, size: 1 }, 1),
        (
            Packet::PortWrite {
                port: 1,
                data: vec![1],
            },
            16,
        ),
    ] {
        let mut saved = context();
        saved.output = Some((packet, length));
        assert!(saved.validate().is_err());
    }
}

#[test]
fn shared_codec_preserves_irq_order_and_rejects_ambiguous_mappings() {
    let saved = GlobalContext {
        cpus: 4,
        ram_size: 4096,
        regions: vec![(0, 4096), (0x8000, 4096)],
        fixed_holes: vec![(0xfee0_0000, 4096)],
        pending_irqs: vec![33, 17, 44],
        resume_clock: None,
        anchor: 0,
    };
    let raw = saved.encode().unwrap();
    let loaded = GlobalContext::decode(&raw).unwrap();
    assert_eq!(loaded.pending_irqs, [33, 17, 44]);
    assert!(loaded.require_controller_owned_irqs().is_err());
    let mut controller_owned = loaded.clone();
    controller_owned.pending_irqs.clear();
    assert!(controller_owned.require_controller_owned_irqs().is_ok());
    let empty_raw = controller_owned.encode().unwrap();
    assert_eq!(
        GlobalContext::decode(&empty_raw).unwrap().encode().unwrap(),
        empty_raw
    );
    assert_eq!(loaded.regions, saved.regions);
    for corruption in 0..5 {
        let mut saved = saved.clone();
        match corruption {
            0 => saved.cpus = 0,
            1 => saved.regions[1] = (4095, 4096),
            2 => saved.regions[1] = (u64::MAX, 1),
            3 => saved.pending_irqs.push(33),
            4 => saved.fixed_holes[0].1 = 0,
            _ => unreachable!(),
        }
        assert!(saved.encode().is_err());
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(GlobalContext::decode(&trailing).is_err());
    for length in 0..raw.len() {
        assert!(GlobalContext::decode(&raw[..length]).is_err());
    }
}

#[test]
fn mmio_input_extension_must_match_the_encoded_transfer_and_destination() {
    for (size, bits, shift, extension, valid) in [
        (8, 8, 0, mmio::Extension::Plain, false),
        (1, 8, 0, mmio::Extension::Zero, false),
        (1, 16, 8, mmio::Extension::Signed, false),
        (8, 64, 0, mmio::Extension::Signed, false),
        (1, 8, 8, mmio::Extension::Plain, true),
        (4, 32, 0, mmio::Extension::Plain, true),
        (1, 64, 0, mmio::Extension::Signed, true),
        (2, 32, 0, mmio::Extension::Zero, true),
    ] {
        let input = mmio::Input {
            destination: mmio::RegisterPart {
                index: 0,
                bits,
                shift,
            },
            original: 0,
            size,
            extension,
            length: 3,
        };
        assert_eq!(
            input.validate().is_ok(),
            valid,
            "size={size} bits={bits} shift={shift} extension={extension:?}"
        );
        assert_eq!(mmio::InputState::default().begin(input).is_ok(), valid);
    }
}

#[test]
fn clock_binding_distinguishes_running_and_pending_domains_and_rejects_incoherent_points() {
    for (binding, anchor, expected) in [
        (
            ClockBinding {
                offset: -1,
                pending: None,
                epoch: None,
            },
            0,
            u64::MAX,
        ),
        (
            ClockBinding {
                offset: 9,
                pending: Some((7, false)),
                epoch: Some(10),
            },
            20,
            7,
        ),
        (
            ClockBinding {
                offset: 9,
                pending: Some((7, true)),
                epoch: None,
            },
            20,
            7,
        ),
        (
            ClockBinding {
                offset: 9,
                pending: Some((7, true)),
                epoch: Some(10),
            },
            20,
            17,
        ),
    ] {
        assert_eq!(binding.at(anchor), expected);
    }
    let mut saved = context();
    saved.clock.offset ^= 1;
    assert!(saved.validate().is_err());
}

#[test]
fn shared_ram_layout_version_preserves_legacy_low_memory_and_rejects_large_flat_records() {
    for bytes in [4096, 3 << 30, (3 << 30) + 4096, 4 << 30, 64 << 30] {
        let saved = GlobalContext {
            cpus: 1,
            ram_size: bytes,
            regions: vec![(0, bytes + (4 << 30))],
            fixed_holes: vec![],
            pending_irqs: vec![],
            resume_clock: None,
            anchor: 0,
        };
        let raw = saved.encode().unwrap();
        assert_eq!(&raw[..8], b"RAXHVG02");
        assert_eq!(GlobalContext::decode(&raw).unwrap().ram_size, bytes);
        let mut legacy = raw;
        legacy[..8].copy_from_slice(b"RAXHVG01");
        assert_eq!(GlobalContext::decode(&legacy).is_ok(), bytes <= 3 << 30);
    }
}
