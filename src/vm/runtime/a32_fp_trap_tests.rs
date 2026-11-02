//! Prepared 1/2/4-CPU S3C files before/after FP trap; actual guest handler and retry.
use super::*;

fn prepare(fixture: &Fixture, count: u8) -> Vmm {
    let mut vm = Vmm::new_resume(fixture.config(count)).unwrap();
    let ram = crate::machine::s3c64xx::runtime::S3C_RAM_BASE;
    let table = ram + 0x4000;
    for index in [0, ram >> 20] {
        vm.guest_mem
            .memory()
            .write_slice(
                &(ram | 0x1c02).to_le_bytes(),
                GuestAddress(u64::from(table + index * 4)),
            )
            .unwrap();
    }
    // Low vectors are mapped to RAM. Handler: clear enables; acknowledge
    // FPEXC.DEX/TFV; RFEIA R4 restores the original PC/CPSR from its frame.
    for (address, word) in [(4, 0xeee15a10u32), (8, 0xeee86a10), (12, 0xf8940a00)] {
        vm.guest_mem
            .memory()
            .write_slice(&word.to_le_bytes(), GuestAddress(u64::from(ram) + address))
            .unwrap();
    }
    for id in 0..usize::from(count) {
        let entry = CODE + 0x100 * id as u64;
        let frame = CODE + 0x1000 + 16 * id as u64;
        let thumb = id & 1 != 0;
        let CpuState::Aarch32(mut public) = vm.vcpus[id].get_state().unwrap() else {
            panic!()
        };
        public.regs.pc = entry as u32;
        public.regs.cpsr = (public.regs.cpsr & !32) | (u32::from(thumb) << 5);
        public.regs.r[4] = frame as u32;
        public.regs.r[5] = 0;
        public.regs.r[6] = 1 << 30;
        public.regs.s[0] = 0xdeadbeef;
        public.regs.s[2] = 0;
        public.regs.s[4] = 0;
        public.regs.fpscr = 0x100;
        let saved = public.regs.cpsr;
        vm.vcpus[id].set_state(&CpuState::Aarch32(public)).unwrap();
        let mut context = vm.vcpus[id].capture_backend_context().unwrap().unwrap();
        let (cpu_id, mut cpu, end) = profile_cpu(&context);
        cpu.vfp.mvfr0 |= 1 << 12;
        cpu.vfp.fpexc = 1 << 30;
        cpu.cp15.cpacr = crate::isa::arm::cp15::Cpacr::from_bits(0x00f00000);
        cpu.cp15.ttbr0 = u64::from(table);
        cpu.cp15.ttbr1 = 0;
        cpu.cp15.ttbcr = 0;
        cpu.cp15.dacr = 3;
        cpu.cp15.sctlr =
            crate::isa::arm::cp15::Sctlr::from_bits((cpu.cp15.sctlr.bits() & !(1 << 28)) | 1);
        let mut data = b"RAXS3C02".to_vec();
        data.extend(crate::codec::serialize(&(cpu_id, cpu)).unwrap());
        data.extend_from_slice(&context.data[end..]);
        context.data = data;
        let public = vm.vcpus[id].get_state().unwrap();
        let emulator = vm.vcpus[id].get_emulator_state().unwrap_or_default();
        vm.vcpus[id]
            .restore_checkpoint_context(&public, &emulator, Some(&context))
            .unwrap();
        let raw = 0xee810a02u32;
        let code = if thumb { raw.rotate_left(16) } else { raw }
            .to_le_bytes()
            .to_vec();
        let wfi = if thumb {
            0xbf30u16.to_le_bytes().to_vec()
        } else {
            0xe320f003u32.to_le_bytes().to_vec()
        };
        for (address, bytes) in [
            (entry, code),
            (entry + 4, wfi),
            (frame, (entry as u32).to_le_bytes().to_vec()),
            (frame + 4, saved.to_le_bytes().to_vec()),
        ] {
            vm.guest_mem
                .memory()
                .write_slice(&bytes, GuestAddress(address))
                .unwrap();
        }
    }
    vm.coordinator.online.fill(true);
    vm
}

fn finish(vm: &mut Vmm) -> Vec<(usize, usize, Option<usize>, u64)> {
    let mut trace = Vec::new();
    for _ in 0..20 {
        if vm.vcpus.iter().all(|cpu| cpu.instruction_count() == 5) {
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
    for (id, cpu) in vm.vcpus.iter().enumerate() {
        assert_eq!(cpu.instruction_count(), 5, "CPU{id} {trace:?}");
        let CpuState::Aarch32(public) = cpu.get_state().unwrap() else {
            panic!()
        };
        assert_eq!(
            public.regs.pc,
            CODE as u32 + 0x100 * id as u32 + if id & 1 != 0 { 6 } else { 8 }
        );
        assert_eq!(public.regs.s[0], 0x7fc00000);
        assert_eq!(public.regs.fpscr, 1);
        let context = cpu.capture_backend_context().unwrap().unwrap();
        assert_eq!(profile_cpu(&context).1.vfp.fpexc, 0x44000700);
    }
    assert_eq!(vm.coordinator.retired, 5 * vm.vcpus.len() as u64);
    trace
}

#[test]
fn one_two_four_prepared_cpu_files_preserve_fp_traps_guest_acknowledgment_and_retry() {
    let fixture = Fixture::new();
    for count in [1, 2, 4] {
        for delivered in [false, true] {
            let mut source = prepare(&fixture, count);
            if delivered {
                for id in 0..usize::from(count) {
                    assert!(source.execute_turn().unwrap().is_none());
                    assert_eq!(source.vcpus[id].current_pc(), 4);
                    assert_eq!(source.vcpus[id].instruction_count(), 0);
                    let context = source.vcpus[id].capture_backend_context().unwrap().unwrap();
                    assert_eq!(profile_cpu(&context).1.vfp.fpexc & 0x2400009f, 0x24000001);
                }
            }
            let before = contexts(&source);
            source
                .take_snapshot_bundle(0)
                .unwrap()
                .save(&fixture.checkpoint)
                .unwrap();
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
