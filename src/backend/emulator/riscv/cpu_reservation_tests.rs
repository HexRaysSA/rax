use crate::backend::emulator::riscv::RiscVVcpu;
use crate::isa::riscv::RiscVConfig;
use crate::vm::vcpu::{CpuState, VCpu};
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
fn check(value: u32) {
    let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap());
    mem.write_slice(
        &[0x100522afu32, 0x00852303, 0x0230000f, 0x185525af]
            .iter()
            .flat_map(|x| x.to_le_bytes())
            .collect::<Vec<_>>(),
        GuestAddress(0),
    )
    .unwrap();
    mem.write_slice(
        &[0x00c52023u32, 0x0110000f, 0x00d52423]
            .iter()
            .flat_map(|x| x.to_le_bytes())
            .collect::<Vec<_>>(),
        GuestAddress(0x100),
    )
    .unwrap();
    mem.write_obj(0x11111111u32, GuestAddress(0x800)).unwrap();
    let mut source = RiscVVcpu::new_embedded(0, mem.clone(), RiscVConfig::rv64gc());
    let mut writer = RiscVVcpu::new_embedded(1, mem.clone(), RiscVConfig::rv64gc());
    for (cpu, pc) in [(&mut source, 0), (&mut writer, 0x100)] {
        let CpuState::RiscV(mut state) = cpu.get_state().unwrap() else {
            panic!()
        };
        state.regs.pc = pc;
        state.regs.x[10] = 0x800;
        state.regs.x[12] = u64::from(value);
        state.regs.x[13] = 1;
        cpu.set_state(&CpuState::RiscV(state)).unwrap();
    }
    assert!(source.step_insn().unwrap().is_none());
    for _ in 0..3 {
        assert!(writer.step_insn().unwrap().is_none());
    }
    assert_eq!(mem.read_obj::<u32>(GuestAddress(0x800)).unwrap(), value);
    assert!(source.step_insn().unwrap().is_none());
    let CpuState::RiscV(observed) = source.get_state().unwrap() else {
        panic!()
    };
    assert_eq!(
        observed.regs.x[6], 1,
        "receiver must observe peer publication flag"
    );
    assert!(source.step_insn().unwrap().is_none());
    assert!(source.step_insn().unwrap().is_none());
    let CpuState::RiscV(state) = source.get_state().unwrap() else {
        panic!()
    };
    let actual: u32 = mem.read_obj(GuestAddress(0x800)).unwrap();
    assert_ne!(
        state.regs.x[11], 0,
        "peer store={value:#x}, SC succeeded and final memory={actual:#x}"
    );
    assert_eq!(actual, value);
}
#[test]
fn different_value_peer_store_invalidates_lr() {
    check(0x22222222)
}
#[test]
fn same_value_peer_store_invalidates_lr() {
    check(0x11111111)
}

struct Aliases;
impl crate::vm::memory::FlatTranslation for Aliases {
    fn translate(
        &self,
        address: u64,
        _access: crate::error::MemoryAccessKind,
    ) -> Result<u64, crate::error::GuestMemoryFault> {
        Ok(address & 0xfff)
    }
}

fn shared_hart(mem: Arc<GuestMemoryMmap>, id: u32, mode: u8, size: usize, rv32: bool) -> RiscVVcpu {
    let width: u32 = if size == 8 { 3 } else { 2 };
    let code = 0x100 + u64::from(id) * 0x100;
    // LR t0,(a0); SC a1,a2,(a0); SC a1,a2,(a0); SW/SD a2,(a0).
    let words = [
        0x1005_02af | width << 12,
        0x18c5_05af | width << 12,
        0x18c5_05af | width << 12,
        0x00c5_0023 | width << 12,
    ];
    for (index, word) in words.iter().enumerate() {
        mem.write_slice(&word.to_le_bytes(), GuestAddress(code + index as u64 * 4))
            .unwrap();
    }
    let cfg = if rv32 {
        crate::isa::riscv::RiscVConfig::rv32(crate::isa::riscv::Isa::rv64gc())
    } else {
        RiscVConfig::rv64gc()
    };
    let mut hart = match mode {
        0 => RiscVVcpu::new_with_config(id, mem, cfg),
        1 => RiscVVcpu::new_embedded(id, mem, cfg),
        2 => RiscVVcpu::new_user(id, mem, cfg, Arc::new(Aliases)),
        _ => unreachable!(),
    };
    hart.cpu.set_pc(code);
    hart.cpu
        .set_x(10, 0x800 + if mode == 2 && id == 1 { 0x1000 } else { 0 });
    hart.cpu.set_x(12, 0x2222_2222);
    hart
}

fn step(hart: &mut RiscVVcpu, native: bool, level: crate::smir::optimize::OptLevel) {
    #[cfg(all(
        feature = "smir-jit",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    if native {
        assert_eq!(
            hart.cpu.step_jit(level),
            crate::isa::riscv::RiscVExit::Continue
        );
        return;
    }
    assert!(
        !native,
        "native execution was requested on an unsupported build"
    );
    assert!(hart.step_insn().unwrap().is_none());
}

#[test]
fn reservation_width_modes_aliases_and_double_sc() {
    use crate::smir::optimize::OptLevel;
    for (rv32, size) in [(true, 4), (false, 4), (false, 8)] {
        for mode in 0..3 {
            for peer in [None, Some(0x1111_1111), Some(0x2222_2222)] {
                let mem =
                    Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x2000)]).unwrap());
                mem.write_obj(0x1111_1111u64, GuestAddress(0x800)).unwrap();
                let mut first = shared_hart(mem.clone(), 0, mode, size, rv32);
                let mut second = shared_hart(mem.clone(), 1, mode, size, rv32);
                step(&mut first, false, OptLevel::O0);
                if let Some(value) = peer {
                    second.cpu.set_x(12, value);
                    second.cpu.set_pc(0x20c);
                    step(&mut second, false, OptLevel::O0);
                }
                step(&mut first, false, OptLevel::O0);
                assert_eq!(
                    first.cpu.x(11) == 0,
                    peer.is_none(),
                    "rv32={rv32} size={size} mode={mode} peer={peer:?}"
                );
                step(&mut first, false, OptLevel::O0);
                assert_ne!(
                    first.cpu.x(11),
                    0,
                    "every SC consumes the most recent reservation"
                );
            }
        }
    }
}

#[cfg(all(
    feature = "smir-jit",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
#[test]
fn native_reservations_observe_direct_and_native_peer_stores() {
    use crate::smir::optimize::OptLevel;
    for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
        for mode in 0..3 {
            for size in [4, 8] {
                for peer_native in [false, true] {
                    let mem = Arc::new(
                        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x2000)]).unwrap(),
                    );
                    mem.write_obj(0x1111_1111u64, GuestAddress(0x800)).unwrap();
                    let mut first = shared_hart(mem.clone(), 0, mode, size, false);
                    let mut second = shared_hart(mem, 1, mode, size, false);
                    second.cpu.set_x(12, 0x1111_1111);
                    second.cpu.set_pc(0x20c);
                    step(&mut first, true, level);
                    step(&mut second, peer_native, level);
                    step(&mut first, true, level);
                    assert_ne!(first.cpu.x(11), 0, "{level:?}/{mode}/{size}/{peer_native}");
                    assert_eq!(
                        first.cpu.jit_stats().native_executions,
                        2,
                        "LR and SC must actually execute natively"
                    );
                    assert_eq!(
                        second.cpu.jit_stats().native_executions,
                        u64::from(peer_native)
                    );
                }
            }
        }
    }
}

#[test]
fn competing_same_value_store_conditionals_have_one_winner() {
    use crate::smir::optimize::OptLevel;
    let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x2000)]).unwrap());
    mem.write_obj(0x1111_1111u64, GuestAddress(0x800)).unwrap();
    let mut harts = [
        shared_hart(mem.clone(), 0, 1, 4, false),
        shared_hart(mem, 1, 1, 4, false),
    ];
    let barrier = Arc::new(std::sync::Barrier::new(2));
    for hart in &mut harts {
        hart.cpu.set_x(12, 0x1111_1111);
        step(hart, false, OptLevel::O0);
    }
    let joins: Vec<_> = harts
        .into_iter()
        .map(|mut hart| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                step(&mut hart, false, OptLevel::O0);
                hart.cpu.x(11)
            })
        })
        .collect();
    let successes = joins
        .into_iter()
        .map(|join| join.join().unwrap())
        .filter(|status| *status == 0)
        .count();
    assert_eq!(successes, 1);
}

#[test]
fn uart_exclusives_fault_without_publishing_events() {
    use crate::isa::riscv::Memory;
    let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x2000)]).unwrap());
    let mut cpu = shared_hart(mem.clone(), 0, 0, 4, false);
    cpu.cpu.set_x(10, super::UART_BASE);
    assert!(matches!(
        cpu.cpu.step(),
        crate::isa::riscv::RiscVExit::Trap(_)
    ));
    assert!(cpu.pending.lock().unwrap().is_empty());
    let mut bridge = super::GuestBridge {
        mem,
        exclusive: cpu.exclusive.clone(),
        pending: cpu.pending.clone(),
        tohost_addr: cpu.tohost_addr.clone(),
        devices_enabled: true,
    };
    assert!(
        bridge
            .store_conditional(super::UART_BASE, &[1; 4], false)
            .is_err()
    );
    assert!(cpu.pending.lock().unwrap().is_empty());
}

#[test]
fn aba_store_invalidates_reservation_but_another_granule_does_not() {
    use crate::smir::optimize::OptLevel;
    for aba in [false, true] {
        let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x2000)]).unwrap());
        mem.write_obj(0x1111_1111u64, GuestAddress(0x800)).unwrap();
        let mut first = shared_hart(mem.clone(), 0, 1, 4, false);
        let mut second = shared_hart(mem, 1, 1, 4, false);
        step(&mut first, false, OptLevel::O0);
        if !aba {
            second.cpu.set_x(10, 0x840);
        }
        second.cpu.set_pc(0x20c);
        step(&mut second, false, OptLevel::O0);
        second.cpu.set_pc(0x20c);
        second.cpu.set_x(12, 0x1111_1111);
        step(&mut second, false, OptLevel::O0);
        step(&mut first, false, OptLevel::O0);
        assert_eq!(first.cpu.x(11) != 0, aba);
    }
}

struct Permissions(std::sync::atomic::AtomicBool);
impl crate::vm::memory::FlatTranslation for Permissions {
    fn translate(
        &self,
        address: u64,
        access: crate::error::MemoryAccessKind,
    ) -> Result<u64, crate::error::GuestMemoryFault> {
        if address == 0x800
            && access == crate::error::MemoryAccessKind::Write
            && !self.0.load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(crate::error::GuestMemoryFault {
                address,
                size: 4,
                access,
                kind: crate::error::MemoryFaultKind::Permission,
            });
        }
        Ok(address)
    }
}

#[test]
fn translated_failed_sc_checks_permission_and_clears_live_reservation() {
    for active in [false, true] {
        let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x2000)]).unwrap());
        let _seed = shared_hart(mem.clone(), 0, 1, 4, false);
        let permission = Arc::new(Permissions(std::sync::atomic::AtomicBool::new(true)));
        let mut hart = RiscVVcpu::new_user(0, mem, RiscVConfig::rv64gc(), permission.clone());
        hart.cpu.set_x(10, 0x800);
        hart.cpu.set_pc(0x100);
        if active {
            assert!(hart.step_insn().unwrap().is_none());
        }
        hart.cpu.set_pc(0x104);
        permission
            .0
            .store(false, std::sync::atomic::Ordering::Release);
        let error = hart.step_insn().unwrap_err();
        let crate::error::Error::GuestAccess(fault) = error else {
            panic!("{error:?}")
        };
        assert_eq!(fault.address, 0x800);
        assert_eq!(fault.access, crate::error::MemoryAccessKind::Write);
        assert_eq!(hart.exclusive.get(), None);
    }
}

mod shared_view {
    use crate::backend::emulator::riscv::RiscVVcpu;
    use crate::isa::riscv::RiscVConfig;
    use crate::vm::vcpu::{CpuState, VCpu};
    use std::sync::Arc;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap, GuestRegionMmap};
    #[test]
    fn another_map_of_shared_backing_must_invalidate_lr() {
        let shared = Arc::new(GuestRegionMmap::from_range(GuestAddress(0), 4096, None).unwrap());
        let extra =
            Arc::new(GuestRegionMmap::from_range(GuestAddress(0x2000), 4096, None).unwrap());
        let first = Arc::new(GuestMemoryMmap::from_arc_regions(vec![shared.clone()]).unwrap());
        let second = Arc::new(GuestMemoryMmap::from_arc_regions(vec![shared, extra]).unwrap());
        first
            .write_slice(
                &[0x1005_22afu32, 0x1855_25af]
                    .iter()
                    .flat_map(|w| w.to_le_bytes())
                    .collect::<Vec<_>>(),
                GuestAddress(0),
            )
            .unwrap();
        second
            .write_slice(&0x00c5_2023u32.to_le_bytes(), GuestAddress(0x100))
            .unwrap();
        first
            .write_obj(0x1111_1111u32, GuestAddress(0x800))
            .unwrap();
        let mut reader = RiscVVcpu::new_embedded(0, first.clone(), RiscVConfig::rv64gc());
        let mut writer = RiscVVcpu::new_embedded(1, second, RiscVConfig::rv64gc());
        for (hart, pc) in [(&mut reader, 0), (&mut writer, 0x100)] {
            let CpuState::RiscV(mut state) = hart.get_state().unwrap() else {
                panic!()
            };
            state.regs.pc = pc;
            state.regs.x[10] = 0x800;
            state.regs.x[12] = 0x1111_1111;
            hart.set_state(&CpuState::RiscV(state)).unwrap();
        }
        assert!(reader.step_insn().unwrap().is_none());
        assert!(writer.step_insn().unwrap().is_none());
        assert!(reader.step_insn().unwrap().is_none());
        let CpuState::RiscV(state) = reader.get_state().unwrap() else {
            panic!()
        };
        assert_ne!(
            state.regs.x[11], 0,
            "a different view of the same RAM must invalidate the LR"
        );
    }
}
