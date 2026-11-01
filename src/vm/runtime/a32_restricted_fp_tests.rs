//! Real S3C CPU scheduling and file continuation around a scalar FP bounce.
use super::*;

const STANDARD: u32 = 3 << 24;

fn word(name: &str) -> u32 {
    let cases: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/development/a32-restricted-fp/cases.json"
    )))
    .unwrap();
    cases["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap()["arm"]
        .as_u64()
        .unwrap() as u32
}

fn prepare(fixture: &Fixture, count: u8) -> Vmm {
    let mut vm = Vmm::new_resume(fixture.config(count)).unwrap();
    let ram = crate::machine::s3c64xx::runtime::S3C_RAM_BASE;
    let table = ram + 0x4000;
    // The board's low physical addresses are open bus. Map the low vector
    // section to real RAM and retain an identity section for code/data/table.
    // Section type=2, AP=3, domain=0, TEX=1/C=B=0 (Normal non-cacheable).
    // DACR below selects manager access; SCTLR.TRE is explicitly disabled.
    for index in [0, ram >> 20] {
        vm.guest_mem
            .memory()
            .write_slice(
                &(ram | 0x1c02).to_le_bytes(),
                GuestAddress(u64::from(table + index * 4)),
            )
            .unwrap();
    }
    for (address, instruction) in [(4, word("vmsr_handler")), (8, word("rfeia_handler"))] {
        vm.guest_mem
            .memory()
            .write_slice(
                &instruction.to_le_bytes(),
                GuestAddress(u64::from(ram) + address),
            )
            .unwrap();
    }
    for id in 0..usize::from(count) {
        let entry = CODE + 0x100 * id as u64;
        let frame = CODE + 0x1000 + 16 * id as u64;
        let thumb = id & 1 != 0;
        let (control, lhs, rhs) = match id {
            0 => (1 << 22, 0x3f80_0000, 0x3380_0000),
            1 => (0, 0x7fc1_2345, 0x3f80_0000),
            2 => (0, 1, 0),
            3 => (STANDARD, 0x3f80_0000, 0x3f80_0000),
            _ => panic!("fixture topology exceeds selected cases"),
        };
        let CpuState::Aarch32(mut public) = vm.vcpus[id].get_state().unwrap() else {
            panic!()
        };
        public.regs.pc = entry as u32;
        public.regs.cpsr = (public.regs.cpsr & !32) | (u32::from(thumb) << 5);
        public.regs.r[4] = frame as u32;
        public.regs.r[5] = STANDARD;
        public.regs.s[0] = 0xdead_beef;
        public.regs.s[2] = lhs;
        public.regs.s[4] = rhs;
        public.regs.fpscr = control;
        let saved_cpsr = public.regs.cpsr;
        vm.vcpus[id].set_state(&CpuState::Aarch32(public)).unwrap();
        let mut context = vm.vcpus[id].capture_backend_context().unwrap().unwrap();
        let (cpu_id, mut cpu, end) = profile_cpu(&context);
        cpu.vfp.mvfr1 = 0x1111_1111; // Conversion-only half profile, full base controls.
        cpu.vfp.mvfr2 = 0;
        cpu.cp15.id_isar6 = 0;
        cpu.cp15.cpacr = crate::isa::arm::cp15::Cpacr::from_bits(0x00f0_0000);
        cpu.vfp.fpexc = 1 << 30;
        cpu.cp15.ttbr0 = u64::from(table);
        cpu.cp15.ttbr1 = 0;
        cpu.cp15.ttbcr = 0;
        cpu.cp15.dacr = 3;
        cpu.cp15.sctlr =
            crate::isa::arm::cp15::Sctlr::from_bits((cpu.cp15.sctlr.bits() & !(1 << 28)) | 1);
        match id {
            0 => cpu.vfp.mvfr0 &= !(15 << 28),
            1 => cpu.vfp.mvfr1 &= !0xf0,
            2 => cpu.vfp.mvfr1 &= !15,
            _ => (),
        }
        let mut data = b"RAXS3C02".to_vec();
        data.extend(crate::codec::serialize(&(cpu_id, cpu)).unwrap());
        data.extend_from_slice(&context.data[end..]);
        context.data = data;
        let public = vm.vcpus[id].get_state().unwrap();
        let emulator = vm.vcpus[id].get_emulator_state().unwrap_or_default();
        vm.vcpus[id]
            .restore_checkpoint_context(&public, &emulator, Some(&context))
            .unwrap();
        let add = word("vadd_f32");
        let code = if thumb {
            [
                ((add >> 16) as u16).to_le_bytes(),
                (add as u16).to_le_bytes(),
            ]
            .concat()
        } else {
            add.to_le_bytes().to_vec()
        };
        let wfi = if thumb {
            0xbf30u16.to_le_bytes().to_vec()
        } else {
            0xe320_f003u32.to_le_bytes().to_vec()
        };
        for (address, bytes) in [
            (entry, code),
            (entry + 4, wfi),
            (frame, (entry as u32).to_le_bytes().to_vec()),
            (frame + 4, saved_cpsr.to_le_bytes().to_vec()),
        ] {
            vm.guest_mem
                .memory()
                .write_slice(&bytes, GuestAddress(address))
                .unwrap();
        }
    }
    // Explicit prepared contexts; this does not claim AP firmware startup.
    vm.coordinator.online.fill(true);
    vm
}

fn finish(vm: &mut Vmm) -> Vec<(usize, usize, Option<usize>, u64)> {
    let done = |vm: &Vmm| {
        vm.vcpus
            .iter()
            .enumerate()
            .all(|(id, cpu)| cpu.instruction_count() == if id < 3 { 4 } else { 2 })
    };
    let mut trace = Vec::new();
    for _ in 0..12 {
        if done(vm) {
            break;
        }
        let cursor = vm.coordinator.cursor;
        let exit = vm.execute_turn().unwrap();
        if let Some(exit) = &exit {
            assert!(matches!(exit.exit, VcpuExit::Hlt));
        }
        trace.push((
            cursor,
            vm.coordinator.cursor,
            exit.map(|exit| exit.cpu_index),
            vm.coordinator.retired,
        ));
    }
    assert!(
        done(vm),
        "coordinator did not complete all prepared CPUs: {trace:?}"
    );
    for (id, cpu) in vm.vcpus.iter().enumerate() {
        let CpuState::Aarch32(public) = cpu.get_state().unwrap() else {
            panic!()
        };
        let expected = [0x3f80_0000, 0x7fc0_0000, 0, 0x4000_0000][id];
        assert_eq!(public.regs.s[0], expected, "CPU{id}");
        assert_eq!(
            public.regs.pc,
            CODE as u32 + 0x100 * id as u32 + if id & 1 != 0 { 6 } else { 8 }
        );
        assert_eq!(public.regs.cpsr & 32 != 0, id & 1 != 0);
        assert_eq!(public.regs.fpscr & !0x9f, STANDARD);
    }
    assert_eq!(
        vm.coordinator.retired,
        if vm.vcpus.len() == 2 { 8 } else { 14 }
    );
    trace
}

#[test]
fn two_and_four_cpu_files_resume_before_and_after_restricted_mode_guest_entry() {
    let mut fixture = Fixture::new();
    fixture.checkpoint.set_extension("rxc");
    for count in [2, 4] {
        for attempted in [false, true] {
            let mut source = prepare(&fixture, count);
            if attempted {
                for id in 0..usize::from(count) {
                    let exit = source.execute_turn().unwrap();
                    if id < 3 {
                        assert!(exit.is_none());
                        assert_eq!(source.vcpus[id].instruction_count(), 0);
                        assert_eq!(source.vcpus[id].current_pc(), 4);
                    } else {
                        assert!(matches!(exit.unwrap().exit, VcpuExit::Hlt));
                    }
                }
            }
            let before = contexts(&source);
            let bundle = source
                .take_snapshot_bundle(source.coordinator.retired)
                .unwrap();
            bundle.save(&fixture.checkpoint).unwrap();
            let loaded = SnapshotBundle::load(&fixture.checkpoint).unwrap();
            assert_eq!(loaded.backend_contexts().unwrap().entries(), before);
            let mut restored = Vmm::new_resume_bundle(fixture.config(count), &loaded).unwrap();
            assert_eq!(contexts(&restored), before);
            assert_eq!(restored.coordinator, source.coordinator);
            assert_eq!(finish(&mut restored), finish(&mut source));
            assert_eq!(contexts(&restored), contexts(&source));
            std::fs::remove_file(&fixture.checkpoint).unwrap();
        }
    }
}
