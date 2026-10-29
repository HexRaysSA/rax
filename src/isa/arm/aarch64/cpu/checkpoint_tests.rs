use super::*;
use crate::isa::arm::common::memory::FlatMemory;

fn cpu() -> AArch64Cpu {
    AArch64Cpu::new(
        AArch64Config {
            gic_config: None,
            ..AArch64Config::default()
        },
        Box::new(FlatMemory::new(0, 0x4000)),
    )
}

#[test]
fn independently_decoded_core_maps_and_all_private_fields_roundtrip_semantically() {
    let mut source = cpu();
    source.x = std::array::from_fn(|i| 0x1234_0000_0000_0000 | i as u64);
    source.sp_el = [0x100, 0x200, 0x300, 0x400];
    source.pc = 0x1000;
    source.nzcv = 10;
    source.daif = 5;
    source.pan = true;
    source.uao = true;
    source.dit = true;
    source.ssbs = true;
    source.tco = true;
    source.btype = 3;
    source.il = true;
    source.ss = true;
    source.v = std::array::from_fn(|i| (u128::from(i as u64) << 96) | 0xfeed);
    source.fpcr = 0x1234;
    source.fpsr = 0x5678;
    source.sve_p = std::array::from_fn(|i| 0xaaaa_0000 | i as u32);
    source.sve_ffr = 0x5a5a;
    source.aarch32_monitor.address = Some(0x2000);
    source.aarch32_monitor.size = 8;
    source.timer_levels = (true, false);
    source.instruction_guarded.store(true, Ordering::Relaxed);
    source.last_fault_level.store(3, Ordering::Relaxed);
    source
        .tbi_tag
        .store(0xab00_0000_0000_0001, Ordering::Relaxed);
    source.fault_log_budget = 7;
    source.pc_ring = std::array::from_fn(|i| 0x8000 + i as u64 * 4);
    source.pc_ring_idx = 63;
    source.insn_count = u64::MAX - 1;
    source.cycle_count = u64::MAX - 2;
    source.last_instruction_size = 2;
    source.halted = true;
    source.wfi = true;
    source.wfe = true;
    source.set_event();
    source.pending_exceptions = vec![ArmException::SError(0x1234), ArmException::VIrq];
    source.breakpoints = [0x3000, 0x1000, 0x2000].into_iter().collect();
    source.watchpoints = vec![
        (0x2000, 8, WatchpointKind::ReadWrite),
        (0x2000, 0, WatchpointKind::Read),
        (u64::MAX, 8, WatchpointKind::Write),
    ];
    source.execution.native_fault = Some(ArmError::ArchitecturalException {
        ec: 0x1c,
        iss: 7,
        target_el: Some(1),
    });
    source.execution.pauth_native_runs = 11;
    source.execution.mem = true;
    source.execution.disabled = true;
    for key in 0..128u16 {
        source
            .sysregs
            .impl_defined
            .insert(key, u64::from(key) << 32);
    }
    let expected = CoreCheckpoint::capture(&source).unwrap();
    let bytes = crate::codec::serialize(&expected).unwrap();
    for _ in 0..32 {
        let decoded: CoreCheckpoint = crate::codec::deserialize_strict(&bytes).unwrap();
        assert_eq!(decoded, expected);
        let mut target = cpu();
        decoded.install_in_prepared(&mut target).unwrap();
        assert_eq!(CoreCheckpoint::capture(&target).unwrap(), expected);
        assert_eq!(target.native_pauth_entry_count(), 11);
    }
}

#[test]
fn invalid_core_fields_and_binding_fail_before_prepared_cpu_assignment() {
    let source = cpu();
    let valid = CoreCheckpoint::capture(&source).unwrap();
    for defect in 0..10 {
        let mut bad = valid.clone();
        match defect {
            0 => bad.pc_ring_idx = 64,
            1 => bad.last_instruction_size = 3,
            2 => bad.current_el = 4,
            3 => bad.mmu.pa_size = 49,
            4 => bad.gic_shared = true,
            5 => bad.breakpoints = vec![8, 8],
            6 => bad.sysregs.mpidr_el1 ^= 1,
            7..=9 => {
                bad.execution.native_fault = Some(ArmError::ArchitecturalException {
                    ec: if defect == 7 { 0x40 } else { 0x1c },
                    iss: if defect == 8 { 1 << 25 } else { 0 },
                    target_el: Some(if defect == 9 { 4 } else { 1 }),
                })
            }
            _ => unreachable!(),
        }
        let mut target = cpu();
        target.x[0] = 0xfeed;
        let before = CoreCheckpoint::capture(&target).unwrap();
        assert!(
            bad.install_in_prepared(&mut target).is_err(),
            "defect {defect}"
        );
        assert_eq!(CoreCheckpoint::capture(&target).unwrap(), before);
    }
}

#[test]
fn portable_checkpoint_delivers_pending_native_event_without_a_native_cache() {
    let mut source = cpu();
    let error = ArmError::ArchitecturalException {
        ec: 0x1c,
        iss: 3,
        target_el: Some(1),
    };
    source.execution.native_fault = Some(error.clone());
    source.execution.disabled = true;
    source.insn_count = 99;
    source.sysregs.cntpct_el0 = 1234;
    let raw = crate::codec::serialize(&CoreCheckpoint::capture(&source).unwrap()).unwrap();
    let saved: CoreCheckpoint = crate::codec::deserialize_strict(&raw).unwrap();
    let mut target = cpu();
    saved.install_in_prepared(&mut target).unwrap();
    assert_eq!(target.step().unwrap_err(), error);
    assert_eq!(target.insn_count, 99);
    assert_eq!(target.sysregs.cntpct_el0, 1234);
    assert!(target.execution.native_fault.is_none());
}
