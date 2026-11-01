//! File admission and producer coherence; opaque GIC bytes here are synthetic.
use super::*;
use crate::backend::arm64_hvf_context::{
    Context, Controls, FEATURE_IDS, GlobalContext, ICC_IDS, Profile, Register, SYSTEM_IDS, Sme,
};
use crate::config::{ArchKind, BackendKind};
use crate::vm::vcpu::Aarch64CpuState;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
fn physical(include_native_ram: bool) -> PhysicalMemorySnapshot {
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
    let mut ranges = vec![(GuestAddress(0), 4096)];
    if include_native_ram {
        ranges.push((
            GuestAddress(crate::machine::arm_virt::AARCH64_RAM_BASE),
            4096,
        ));
    }
    let memory = GuestMemoryMmap::from_ranges(&ranges).unwrap();
    for (address, _) in ranges {
        memory.write_slice(&[0x51; 4096], address).unwrap();
    }
    PhysicalMemorySnapshot::capture(&memory).unwrap()
}
fn complete_file(count: u8) -> SnapshotBundle {
    let saved = bundle(count);
    let execution = ExecutionSnapshot {
        cursor: 0,
        retired: 0,
        online: (0..count).map(|id| id == 0).collect(),
        local_apics: (0..count)
            .map(|id| {
                let apic = if id == 0 {
                    saved.base.devices.lapic.clone()
                } else {
                    crate::devices::lapic::LocalApic::new(u32::from(id))
                };
                apic.checkpoint_at(std::time::Instant::now())
            })
            .collect(),
        arm_cluster: None,
        pc: None,
        pl011: None,
    };
    let mut clock = crate::vm::timing::TimingContext::default().checkpoint_state();
    clock.elapsed_nanos = saved.base.elapsed_nanos;
    saved
        .with_execution(execution)
        .unwrap()
        .with_clock(clock)
        .unwrap()
        .with_physical_memory(physical(true))
        .unwrap()
}
struct TestPath(std::path::PathBuf);
impl TestPath {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "rax-native-bundle-{}-{}.rxc",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        Self(path)
    }
}
impl Drop for TestPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn context(id: u32) -> Context {
    let system: Vec<_> = SYSTEM_IDS
        .iter()
        .map(|&reg| Register {
            id: reg,
            value: if reg == 0xc005 {
                crate::isa::arm::aarch64::AArch64Cpu::mpidr_for_cpu_id(id)
            } else {
                u64::from(reg)
            },
        })
        .collect();
    let mut public = Aarch64CpuState::default();
    public.regs.pstate = 5;
    public.regs.pc = 0x4000_1000 + u64::from(id) * 4;
    let mut saved = Context {
        id,
        profile: Profile {
            system_ids: system.iter().map(|r| r.id).collect(),
            feature_values: system
                .iter()
                .filter(|r| FEATURE_IDS.contains(&r.id))
                .cloned()
                .collect(),
            maximum_svl: 0,
        },
        public,
        system,
        gic_cpu: ICC_IDS
            .iter()
            .map(|&id| Register { id, value: 0 })
            .collect(),
        running_priority: 255,
        controls: Controls {
            vtimer_masked: true,
            vtimer_offset: 123,
            trap_debug_exceptions: false,
            trap_debug_registers: true,
            pending_serror: false,
        },
        sme: Sme {
            streaming: false,
            za_enabled: false,
            z: vec![],
            p: vec![],
            za: vec![],
            zt: None,
        },
        pending_read: None,
        shutdown: false,
        completion_error: None,
        pending_reply: None,
        pending_write: None,
    };
    saved.project_system().unwrap();
    saved
}

fn shared(count: u8) -> BackendContext {
    BackendContext {
        kind: HVF_AARCH64_CONTEXT,
        data: GlobalContext {
            cpus: count,
            power: crate::backend::arm64_hvf_power::Power::new(count),
            ram_base: crate::machine::arm_virt::AARCH64_RAM_BASE,
            ram_size: 4096,
            distributor_base: crate::machine::arm_virt::AARCH64_GICD_BASE,
            redistributor_base: crate::machine::arm_virt::AARCH64_GICR_BASE,
            spi_base: 32,
            spi_count: 224,
            affinities: (0..u32::from(count))
                .map(crate::isa::arm::aarch64::AArch64Cpu::mpidr_for_cpu_id)
                .collect(),
            irq_levels: vec![(33, true)],
            gic: vec![0xa5; 127],
        }
        .encode()
        .unwrap(),
    }
}

fn bundle(count: u8) -> SnapshotBundle {
    let mut base = super::tests::snapshot_with_memory_metadata(4096, 4096);
    base.config.arch = ArchKind::Aarch64;
    base.config.backend = BackendKind::Hvf;
    base.config.vcpus = count;
    base.memory_data = zstd::encode_all(&[0x51u8; 4096][..], 3).unwrap();
    let contexts: Vec<_> = (0..u32::from(count)).map(context).collect();
    base.cpu_state = CpuState::Aarch64(contexts[0].public.clone());
    let cpus = contexts
        .iter()
        .map(|c| CpuSnapshot {
            state: CpuState::Aarch64(c.public.clone()),
            emulator: EmulatorState::default(),
        })
        .collect();
    let records = contexts
        .iter()
        .map(|c| {
            Some(BackendContext {
                kind: HVF_AARCH64_CONTEXT,
                data: c.encode().unwrap(),
            })
        })
        .collect();
    SnapshotBundle::new(base)
        .with_checkpoint_records(cpus, records, Some(shared(count)))
        .unwrap()
}

#[test]
fn complete_native_graph_survives_real_files_without_software_execution_state() {
    for count in [1, 2, 4] {
        let saved = complete_file(count);
        let path = TestPath::new();
        saved.save(&path.0).unwrap();
        let loaded = SnapshotBundle::load(&path.0).unwrap();
        assert_eq!(loaded.cpus().unwrap().entries().len(), usize::from(count));
        assert_eq!(loaded.vm_context(), saved.vm_context());
        assert_eq!(
            loaded.backend_contexts().unwrap().entries(),
            saved.backend_contexts().unwrap().entries()
        );
        assert!(
            loaded
                .base
                .cpu_state
                .as_aarch64()
                .unwrap()
                .sregs
                .execution
                .is_none()
        );
        assert_eq!(loaded.base.decompress_memory().unwrap(), vec![0x51; 4096]);
        assert!(Snapshot::load(&path.0).is_err());
        assert!(loaded.into_base().is_err());
    }
}

#[test]
fn native_graph_rejects_each_missing_record_and_legacy_downgrade() {
    for mutation in 0..7 {
        let mut saved = bundle(2);
        let mut records = saved.backend_contexts.as_ref().unwrap().entries().to_vec();
        match mutation {
            0 => {
                saved.take_cpus();
            }
            1 => {
                saved.take_backend_contexts();
            }
            2 => {
                saved.take_vm_context();
            }
            3 => {
                records[1] = None;
                saved.backend_contexts = Some(BackendContexts::capture(records, 2).unwrap());
            }
            4 => {
                records[1].as_mut().unwrap().kind = AARCH64_CONTEXT;
                saved.backend_contexts = Some(BackendContexts::capture(records, 2).unwrap());
            }
            5 => {
                saved.vm_context.as_mut().unwrap().kind = AARCH64_CONTEXT;
            }
            6 => {
                saved.base.config.backend = BackendKind::Emulator;
            }
            _ => unreachable!(),
        }
        assert!(saved.validate().is_err(), "mutation {mutation}");
        let path = TestPath::new();
        std::fs::write(&path.0, b"existing checkpoint").unwrap();
        assert!(saved.save(&path.0).is_err());
        assert_eq!(std::fs::read(&path.0).unwrap(), b"existing checkpoint");
    }
    assert!(bundle(1).into_parts().is_err());
}

#[test]
fn shared_file_section_is_mandatory_ordered_and_cannot_be_marked_optional() {
    let path = TestPath::new();
    complete_file(2).save(&path.0).unwrap();
    let raw = std::fs::read(&path.0).unwrap();
    let mut offset = 20;
    let mut sections = Vec::new();
    while offset < raw.len() {
        let length = u64::from_le_bytes(raw[offset + 8..offset + 16].try_into().unwrap()) as usize;
        sections.push(raw[offset..offset + 16 + length].to_vec());
        offset += 16 + length;
    }
    let shared = sections
        .iter()
        .position(|s| s[..4] == 16u32.to_le_bytes())
        .unwrap();
    let cpu = sections
        .iter()
        .position(|s| s[..4] == 11u32.to_le_bytes())
        .unwrap();
    for mutation in 0..7 {
        let mut parts = sections.clone();
        match mutation {
            0 => {
                parts.remove(shared);
            }
            1 => parts[shared][..4].copy_from_slice(&(16u32 | 1 << 31).to_le_bytes()),
            2 => parts[shared][4..8].copy_from_slice(&2u32.to_le_bytes()),
            3 => parts.swap(shared, cpu),
            4 => parts.push(parts[shared].clone()),
            5 => {
                let late = parts.remove(shared);
                parts.push(late);
            }
            6 => parts[shared][8..16].copy_from_slice(&u64::MAX.to_le_bytes()),
            _ => unreachable!(),
        }
        let mut mutated = raw[..16].to_vec();
        mutated.extend_from_slice(&(parts.len() as u32).to_le_bytes());
        mutated.extend(parts.concat());
        std::fs::write(&path.0, mutated).unwrap();
        assert!(
            SnapshotBundle::load(&path.0).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn native_graph_rejects_public_private_identity_topology_and_profile_disagreement() {
    for mutation in 0..9 {
        let mut saved = bundle(2);
        let contexts = saved.backend_contexts.take().unwrap();
        let mut records = contexts.entries().to_vec();
        let mut cpu = Context::decode(&records[1].as_ref().unwrap().data).unwrap();
        let mut global = GlobalContext::decode(&saved.vm_context.as_ref().unwrap().data).unwrap();
        match mutation {
            0 => cpu.public.regs.x[17] ^= 1,
            1 => {
                cpu.id = 0;
                cpu.system
                    .iter_mut()
                    .find(|r| r.id == 0xc005)
                    .unwrap()
                    .value = crate::isa::arm::aarch64::AArch64Cpu::mpidr_for_cpu_id(0);
            }
            2 => {
                cpu.system.retain(|r| r.id != 0xc082);
                cpu.profile.system_ids.retain(|&id| id != 0xc082);
            }
            3 => global.ram_base += 4096,
            4 => global.ram_size += 4096,
            5 => global.distributor_base += 4096,
            6 => global.redistributor_base += 4096,
            7 => {
                global.cpus = 1;
                global.affinities.truncate(1);
                global.power.states.truncate(1);
            }
            8 => {
                cpu.public.regs.pc += 4;
            }
            _ => unreachable!(),
        }
        cpu.project_system().unwrap();
        records[1].as_mut().unwrap().data = cpu.encode().unwrap();
        saved.backend_contexts = Some(BackendContexts::capture(records, 2).unwrap());
        saved.vm_context.as_mut().unwrap().data = global.encode().unwrap();
        assert!(saved.validate().is_err(), "mutation {mutation}");
    }
}

#[test]
fn shared_context_framing_rejects_all_truncations_and_unbounded_lengths() {
    let context = shared(2);
    let raw = vm_context::encode(&context).unwrap();
    assert_eq!(
        vm_context::read_from(&mut raw.as_slice(), raw.len() as u64).unwrap(),
        context
    );
    for end in 0..raw.len() {
        assert!(
            vm_context::read_from(&mut &raw[..end], end as u64).is_err(),
            "prefix {end}"
        );
    }
    for mutation in 0..4 {
        let mut bad = raw.clone();
        match mutation {
            0 => bad[7] ^= 1,
            1 => bad[8..12].fill(0),
            2 => bad[12..20].copy_from_slice(&u64::MAX.to_le_bytes()),
            3 => bad.push(0),
            _ => unreachable!(),
        }
        assert!(vm_context::read_from(&mut bad.as_slice(), bad.len() as u64).is_err());
    }
    assert!(vm_context::read_from(&mut &[][..], vm_context::MAX_SECTION + 1).is_err());
}

#[test]
fn native_backend_table_rejects_oversized_payload_before_reading_or_allocating_it() {
    let mut table = b"RAXBCK01".to_vec();
    table.extend_from_slice(&1u32.to_le_bytes());
    table.extend_from_slice(&HVF_AARCH64_CONTEXT.to_le_bytes());
    let length = crate::backend::arm64_hvf_context::MAX_CPU_CONTEXT + 1;
    table.extend_from_slice(&length.to_le_bytes());
    let error = BackendContexts::read_from(&mut table.as_slice(), 24 + length, 1).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("invalid context kind or record length")
    );
}

#[test]
fn native_files_require_the_actual_sdk_ram_window_before_publication() {
    for image in [None, Some(physical(false))] {
        let mut candidate = bundle(1);
        candidate.physical_memory = image;
        let path = TestPath::new();
        std::fs::write(&path.0, b"prior checkpoint").unwrap();
        assert!(candidate.save(&path.0).is_err());
        assert_eq!(std::fs::read(&path.0).unwrap(), b"prior checkpoint");
        assert!(
            crate::config::VmConfig::from_checkpoint_bundle(&candidate, Default::default())
                .is_err()
        );
    }
}

#[test]
fn native_complete_file_requires_clock_coordinator_and_coherent_power_graph() {
    for missing in 0..2 {
        let mut saved = complete_file(2);
        if missing == 0 {
            saved.take_clock();
        } else {
            saved.take_execution();
        }
        assert!(saved.save(&TestPath::new().0).is_err());
    }
    let mut saved = complete_file(2);
    saved.execution.as_mut().unwrap().online[1] = true;
    assert!(saved.validate_complete().is_err());
    let mut saved = complete_file(2);
    let raw = &mut saved.vm_context.as_mut().unwrap().data;
    raw[..8].copy_from_slice(b"RAXHVM01");
    assert!(saved.validate_complete().is_err());
}
#[test]
fn native_pending_power_graph_survives_real_file_without_losing_endianness() {
    let mut saved = complete_file(4);
    set_bigend_profile(&mut saved, 1);
    let mut global = GlobalContext::decode(&saved.vm_context.as_ref().unwrap().data).unwrap();
    assert_eq!(
        global.power.cpu_on(
            3,
            global.ram_base,
            0x1234,
            true,
            global.ram_base,
            global.ram_size
        ),
        0
    );
    assert_eq!(
        global.power.cpu_on(
            1,
            global.ram_base + 4,
            0x5678,
            false,
            global.ram_base,
            global.ram_size
        ),
        0
    );
    let expected = global.power.clone();
    saved.vm_context.as_mut().unwrap().data = global.encode().unwrap();
    let path = TestPath::new();
    saved.save(&path.0).unwrap();
    let loaded = SnapshotBundle::load(&path.0).unwrap();
    let global = GlobalContext::decode(&loaded.vm_context.as_ref().unwrap().data).unwrap();
    assert_eq!(global.power, expected);
    let mut bad = loaded;
    bad.execution.as_mut().unwrap().online[3] = true;
    assert!(bad.validate_complete().is_err());
}

#[test]
fn native_cpu_and_vm_terminal_state_must_agree() {
    let mut saved = complete_file(2);
    let mut records = saved.backend_contexts.take().unwrap().entries().to_vec();
    let mut cpu = Context::decode(&records[1].as_ref().unwrap().data).unwrap();
    cpu.shutdown = true;
    records[1].as_mut().unwrap().data = cpu.encode().unwrap();
    saved.backend_contexts = Some(BackendContexts::capture(records, 2).unwrap());
    assert!(saved.validate_complete().is_err());
}

#[test]
fn native_terminal_pending_transactions_survive_complete_file_admission() {
    use crate::backend::arm64_hvf_context::{PendingRead, PendingWrite};
    for phase in 0..4 {
        let mut saved = complete_file(2);
        saved.execution.as_mut().unwrap().online[1] = true;
        let mut global = GlobalContext::decode(&saved.vm_context.as_ref().unwrap().data).unwrap();
        global.power.states[1] = crate::backend::arm64_hvf_power::State::On;
        global.power.shutdown = true;
        saved.vm_context.as_mut().unwrap().data = global.encode().unwrap();
        let mut records = saved.backend_contexts.take().unwrap().entries().to_vec();
        for (id, record) in records.iter_mut().enumerate() {
            let mut context = Context::decode(&record.as_ref().unwrap().data).unwrap();
            context.shutdown = true;
            if id == 1 {
                if phase == 3 {
                    context.pending_write = Some(PendingWrite {
                        retirement: Some(crate::backend::arm64_hvf_context::Retirement {
                            next_pc: context.public.regs.pc.wrapping_add(4),
                            acknowledged: false,
                        }),
                        address: 0x09000030,
                        data: vec![0xab],
                    });
                } else {
                    context.pending_read = Some(PendingRead {
                        address: 0x09000000,
                        register: 0,
                        size: 1,
                        sign_extend: false,
                        sixty_four: false,
                        retire_pc: Some(context.public.regs.pc.wrapping_add(4)),
                    });
                    if phase > 0 {
                        context.pending_reply = Some(vec![0xab]);
                    }
                    if phase == 1 {
                        context.completion_error = Some("saved native writeback failure".into());
                    }
                }
            }
            record.as_mut().unwrap().data = context.encode().unwrap();
        }
        let expected = Context::decode(&records[1].as_ref().unwrap().data).unwrap();
        saved.backend_contexts = Some(BackendContexts::capture(records, 2).unwrap());
        let path = TestPath::new();
        saved.save(&path.0).unwrap();
        let mut loaded = SnapshotBundle::load(&path.0).unwrap();
        loaded.validate_complete().unwrap();
        let mut records = loaded.backend_contexts.take().unwrap().entries().to_vec();
        assert_eq!(
            Context::decode(&records[1].as_ref().unwrap().data).unwrap(),
            expected
        );
        // Relaxing terminal/IO admission must not weaken CPU/shared coherence.
        let mut bad = expected;
        bad.shutdown = false;
        records[1].as_mut().unwrap().data = bad.encode().unwrap();
        loaded.backend_contexts = Some(BackendContexts::capture(records, 2).unwrap());
        assert!(loaded.validate_complete().is_err());
    }
}

fn set_bigend_profile(saved: &mut SnapshotBundle, field: u64) {
    let mut records = saved.backend_contexts.take().unwrap().entries().to_vec();
    for record in records.iter_mut().flatten() {
        let mut cpu = Context::decode(&record.data).unwrap();
        for register in cpu
            .system
            .iter_mut()
            .chain(cpu.profile.feature_values.iter_mut())
        {
            if register.id == 0xc038 {
                register.value = (register.value & !(15 << 8)) | (field << 8);
            }
        }
        record.data = cpu.encode().unwrap();
    }
    saved.backend_contexts =
        Some(BackendContexts::capture(records, saved.base.config.vcpus).unwrap());
}

#[test]
fn native_pending_big_endian_start_requires_an_implemented_profile_field() {
    let mut saved = complete_file(2);
    let mut global = GlobalContext::decode(&saved.vm_context.as_ref().unwrap().data).unwrap();
    assert_eq!(
        global.power.cpu_on(
            1,
            global.ram_base,
            0x1234,
            true,
            global.ram_base,
            global.ram_size
        ),
        0
    );
    saved.vm_context.as_mut().unwrap().data = global.encode().unwrap();
    for field in 0..16 {
        set_bigend_profile(&mut saved, field);
        assert_eq!(
            saved.validate_complete().is_ok(),
            field == 1,
            "BigEnd={field}"
        );
    }
}
