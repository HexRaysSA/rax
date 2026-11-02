//! Source/target files at pre-control, pre-vector and completed-vector frontiers.
use super::*;
fn rows() -> serde_json::Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/development/a32-short-vectors/cases.json"
    )))
    .unwrap()
}
fn selected(all: &serde_json::Value, id: usize) -> &serde_json::Value {
    let names = [
        "vadd-binary-f32-vector-len8-stride1",
        "vadd-binary-f32-vector-len4-stride2",
        "vadd-binary-f64-vector-len4-stride1",
        "vadd-binary-f64-scalar_source-len2-stride2",
    ];
    all["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == names[id])
        .unwrap()
}
fn round(vm: &mut Vmm) {
    for cpu in &mut vm.vcpus {
        cpu.wake();
    }
    for id in 0..vm.vcpus.len() {
        let turn = vm.execute_turn().unwrap().unwrap();
        assert_eq!(turn.cpu_index, id);
        assert!(matches!(turn.exit, VcpuExit::Hlt));
    }
}
fn prepare(fixture: &Fixture, count: u8) -> Vmm {
    let all = rows();
    let mut vm = Vmm::new_resume(fixture.config(count)).unwrap();
    for id in 0..usize::from(count) {
        let row = selected(&all, id);
        let thumb = id & 1 != 0;
        let entry = CODE + 0x100 * id as u64;
        let CpuState::Aarch32(mut state) = vm.vcpus[id].get_state().unwrap() else {
            panic!()
        };
        state.regs.pc = entry as u32;
        state.regs.cpsr = (state.regs.cpsr & !32) | (u32::from(thumb) << 5);
        state.regs.r[0] = row["control"].as_u64().unwrap() as u32;
        state.regs.fpscr = 0;
        let initial = all["initials"][row["initial"].as_u64().unwrap() as usize]
            .as_array()
            .unwrap();
        for i in 0..16 {
            let d = initial[i].as_u64().unwrap();
            state.regs.s[i * 2] = d as u32;
            state.regs.s[i * 2 + 1] = (d >> 32) as u32;
            state.regs.d_high[i] = initial[i + 16].as_u64().unwrap();
        }
        vm.vcpus[id].set_state(&CpuState::Aarch32(state)).unwrap();
        let mut raw = vm.vcpus[id].capture_backend_context().unwrap().unwrap();
        let (cpu_id, mut cpu, end) = profile_cpu(&raw);
        cpu.vfp.mvfr0 |= 1 << 24;
        let mut data = b"RAXS3C02".to_vec();
        data.extend(crate::codec::serialize(&(cpu_id, cpu)).unwrap());
        data.extend_from_slice(&raw.data[end..]);
        raw.data = data;
        let public = vm.vcpus[id].get_state().unwrap();
        let emulator = vm.vcpus[id].get_emulator_state().unwrap_or_default();
        vm.vcpus[id]
            .restore_checkpoint_context(&public, &emulator, Some(&raw))
            .unwrap();
        let add = row[if thumb { "thumb" } else { "arm" }].as_u64().unwrap() as u32;
        let mut code = Vec::new();
        for word in [0xeee10a10u32, add] {
            if thumb {
                code.extend_from_slice(&((word >> 16) as u16).to_le_bytes());
                code.extend_from_slice(&(word as u16).to_le_bytes());
                code.extend_from_slice(&0xbf30u16.to_le_bytes());
            } else {
                code.extend_from_slice(&word.to_le_bytes());
                code.extend_from_slice(&0xe320f003u32.to_le_bytes());
            }
        }
        vm.guest_mem
            .memory()
            .write_slice(&code, GuestAddress(entry))
            .unwrap();
    }
    vm.coordinator.online.fill(true);
    vm
}
fn check(vm: &Vmm) {
    let all = rows();
    for (id, cpu) in vm.vcpus.iter().enumerate() {
        assert_eq!(cpu.instruction_count(), 4);
        let raw = cpu.capture_backend_context().unwrap().unwrap();
        let (_, core, _) = profile_cpu(&raw);
        let row = selected(&all, id);
        let initial = &all["initials"][row["initial"].as_u64().unwrap() as usize];
        let mut expected = [0u64; 32];
        for (i, x) in initial.as_array().unwrap().iter().enumerate() {
            expected[i] = x.as_u64().unwrap();
        }
        for c in row["changes"].as_array().unwrap() {
            expected[c[0].as_u64().unwrap() as usize] = c[1].as_u64().unwrap();
        }
        assert_eq!(core.vfp.dregs, expected, "CPU{id}");
        assert_eq!(
            core.vfp.fpscr.bits(),
            row["control"].as_u64().unwrap() as u32
        );
        assert_eq!((core.vfp.mvfr0 >> 24) & 15, 1);
    }
    assert_eq!(vm.coordinator.retired, 4 * vm.vcpus.len() as u64);
}
#[test]
fn one_two_four_cpu_files_resume_short_vectors_at_all_instruction_boundaries() {
    let fixture = Fixture::new();
    for count in [1, 2, 4] {
        for boundary in 0..=2 {
            let mut source = prepare(&fixture, count);
            for _ in 0..boundary {
                round(&mut source);
            }
            source
                .take_snapshot_bundle(source.coordinator.retired)
                .unwrap()
                .save(&fixture.checkpoint)
                .unwrap();
            let bundle = SnapshotBundle::load(&fixture.checkpoint).unwrap();
            let mut target = Vmm::new_resume_bundle(fixture.config(count), &bundle).unwrap();
            assert_eq!(contexts(&target), contexts(&source));
            assert_eq!(target.coordinator, source.coordinator);
            for _ in boundary..2 {
                round(&mut source);
                round(&mut target);
            }
            check(&source);
            check(&target);
            assert_eq!(contexts(&source), contexts(&target));
            assert_eq!(source.coordinator, target.coordinator);
        }
    }
}
