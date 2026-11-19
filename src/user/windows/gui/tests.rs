use super::*;
use crate::user::mm::{AddressSpace, SpaceConfig};
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::object_namespace::data::DataRegion;

pub(crate) fn fixture(arch: WinArch) -> Arc<Inputs> {
    fixture_with_client_flags(arch, 0x2000_0008).unwrap()
}

fn fixture_with_client_flags(arch: WinArch, flags: u64) -> io::Result<Arc<Inputs>> {
    let gdi = View {
        base: 0x3000_0000,
        section: DataSection::private_readonly(
            0x181000,
            vec![DataRegion {
                offset: 0,
                size: 0x181000,
                bytes: Some(vec![0; 0x181000].into()),
            }],
        )
        .unwrap(),
    };
    let desktop = View {
        base: 0x3100_0000,
        section: DataSection::private_readonly(
            65536,
            vec![
                DataRegion {
                    offset: 0,
                    size: 8192,
                    bytes: Some(vec![0; 8192].into()),
                },
                DataRegion {
                    offset: 8192,
                    size: 57344,
                    bytes: None,
                },
            ],
        )
        .unwrap(),
    };
    let mut client = [0; 20];
    client[0] = flags;
    client[2] = 0xa00;
    client[4] = desktop.base + 0x1040;
    client[5] = desktop.base;
    client[12] = desktop.base + 0x1800;
    client[18] = 0x0409_0409;
    client[19] = 1252;
    Inputs::selected(
        arch,
        gdi,
        desktop,
        client,
        0,
        NonZeroU32::new(192),
        super::super::objects::Desktop::selected("Default".encode_utf16().collect(), 0xF00CF, 0)
            .unwrap(),
        Ok([0, 0]),
    )
}

fn memory() -> VirtualMemory {
    VirtualMemory::new(
        AddressSpace::new(SpaceConfig {
            va_limit: 1 << 32,
            arena_bytes: 16 << 20,
            reserved_phys: vec![],
        })
        .unwrap(),
        65536,
        1 << 32,
    )
}

#[test]
fn gui_threads_have_private_records_inside_one_owned_readonly_desktop_view() {
    for arch in [WinArch::Arm64, WinArch::X64] {
        let inputs = fixture(arch);
        assert_eq!(inputs.client[0], 0x2000_0000);
        let mut vm = memory();
        let mut state = State::new((6, 2));
        let first = state
            .prepare_thread(&mut vm, inputs.clone(), 8, 123)
            .unwrap();
        let second = state
            .prepare_thread(&mut vm, inputs.clone(), 12, 456)
            .unwrap();
        assert_ne!(first, second);
        for (address, tick) in [(first, 123), (second, 456)] {
            let region = vm.query(address).unwrap();
            assert_eq!(region.allocation_base, inputs.desktop.base);
            assert_eq!((region.kind, region.protect), (mem::MAPPED, prot::READONLY));
            assert_eq!(vm.space().u32(address + 20).unwrap(), tick);
            assert!(vm.space().w32(address + 20, 999).is_err());
        }
        assert_eq!(inputs.client_seed, [0; CLIENT_SEED_BYTES]);
        assert_eq!(
            state
                .prepare_thread(&mut vm, inputs.clone(), 8, 999)
                .unwrap(),
            first
        );
        assert_eq!(vm.space().u32(first + 20).unwrap(), 123);
        state.retire_thread(&mut vm, 8).unwrap();
        assert!(!state.threads.contains_key(&8));
        let reused = state.prepare_thread(&mut vm, inputs, 16, 789).unwrap();
        assert_eq!(reused, first);
        assert_eq!(vm.space().u32(reused + 20).unwrap(), 789);
        assert_eq!(vm.space().u32(second + 20).unwrap(), 456);
    }
}

#[test]
fn gui_input_mapping_collisions_and_replacements_do_not_acquire_foreign_memory() {
    let inputs = fixture(WinArch::Arm64);
    let mut vm = memory();
    vm.map_data_section(
        inputs.desktop.section.clone(),
        inputs.desktop.base,
        0,
        inputs.desktop.section.size,
        prot::READONLY,
    )
    .unwrap();
    let before = vm.committed_bytes();
    let mut state = State::default();
    assert_eq!(
        state.prepare_thread(&mut vm, inputs.clone(), 8, 0),
        Err(VmError::Conflicting)
    );
    assert_eq!(vm.committed_bytes(), before);
    assert!(vm.is_free(inputs.gdi.base, inputs.gdi.section.size));
    vm.release(inputs.desktop.base).unwrap();
    state.prepare_thread(&mut vm, inputs.clone(), 8, 0).unwrap();
    vm.release(inputs.desktop.base).unwrap();
    vm.map_data_section(
        inputs.desktop.section.clone(),
        inputs.desktop.base,
        0,
        inputs.desktop.section.size,
        prot::READONLY,
    )
    .unwrap();
    assert_eq!(
        state.prepare_thread(&mut vm, inputs.clone(), 12, 0),
        Err(VmError::InvalidAddress)
    );
    assert_eq!(vm.space().u8(inputs.desktop.base).unwrap(), 0);
}

#[test]
fn gui_inputs_accept_both_measured_client_flag_profiles() {
    for (captured, expected) in [(0x2000_0008, 0x2000_0000), (8, 0)] {
        let selected = fixture_with_client_flags(WinArch::Arm64, captured).unwrap();
        assert_eq!(selected.client[0], expected);
    }
    for unmeasured in [0x18, 0x4000_0008, (1 << 63) | 8] {
        assert!(fixture_with_client_flags(WinArch::Arm64, unmeasured).is_err());
    }
}

#[test]
fn gui_inputs_reject_unmeasured_pointer_words_and_native_wow64_aliasing() {
    for mutation in 0..3 {
        let inputs = fixture(WinArch::Arm64);
        let mut client = inputs.client;
        match mutation {
            0 => client[1] = 0x4141_4141,
            1 => client[12] = inputs.desktop.base + inputs.desktop.section.size - 8,
            _ => client[5] += 65536,
        }
        assert!(
            Inputs::selected(
                WinArch::Arm64,
                View {
                    base: inputs.gdi.base,
                    section: inputs.gdi.section.clone()
                },
                View {
                    base: inputs.desktop.base,
                    section: inputs.desktop.section.clone()
                },
                client,
                0,
                inputs.process_dpi,
                inputs.assigned_desktop.clone(),
                inputs.process_ui_context.clone()
            )
            .is_err()
        );
    }
    let inputs = fixture(WinArch::Arm64);
    assert!(
        Inputs::selected(
            WinArch::X86,
            View {
                base: inputs.gdi.base,
                section: inputs.gdi.section.clone()
            },
            View {
                base: inputs.desktop.base,
                section: inputs.desktop.section.clone()
            },
            inputs.client,
            0,
            inputs.process_dpi,
            inputs.assigned_desktop.clone(),
            inputs.process_ui_context.clone()
        )
        .is_err()
    );
}

#[test]
fn gui_inputs_validate_context_field_domains_without_requiring_query_availability() {
    for (context, valid) in [
        (Ok([3, 3]), true),
        (Ok([4, 0]), false),
        (Ok([0, u32::MAX]), false),
        (Err("controlled absent process context".into()), true),
    ] {
        let inputs = fixture(WinArch::Arm64);
        let selected = Inputs::selected(
            inputs.arch,
            View {
                base: inputs.gdi.base,
                section: inputs.gdi.section.clone(),
            },
            View {
                base: inputs.desktop.base,
                section: inputs.desktop.section.clone(),
            },
            inputs.client,
            inputs.remote_connect_state,
            inputs.process_dpi,
            inputs.assigned_desktop.clone(),
            context.clone(),
        );
        assert_eq!(selected.is_ok(), valid);
        if let Ok(selected) = selected {
            assert_eq!(selected.process_ui_context, context);
        }
    }
}
