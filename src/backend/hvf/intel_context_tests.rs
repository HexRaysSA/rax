//! Portable admission tests; these fixtures do not establish SDK execution.
use super::*;
use crate::backend::intel_hvf_xsave::{Component, Layout};

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
    tag[7] = b'2';
    assert!(Context::decode(&tag).is_err());
    assert!(Context::decode(&vec![0; CPU_LIMIT + 9]).is_err());
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
