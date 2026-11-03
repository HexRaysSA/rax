use super::*;
use crate::backend::emulator::riscv::platform::{BASE, LEN, Platform};
use crate::isa::riscv::memory::AtomicOp;
use crate::vm::timing::{ClockMode, TimingContext};

fn fixture() -> (Arc<GuestMemoryMmap>, Arc<Platform>) {
    let mem = Arc::new(
        GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), 0x2000),
            (GuestAddress(BASE), LEN as usize),
        ])
        .unwrap(),
    );
    mem.write_obj(0xa5a5a5a5u32, GuestAddress(BASE + 4))
        .unwrap();
    let platform = Arc::new(
        Platform::new(
            2,
            0x2000,
            Arc::new(TimingContext::with_mode(ClockMode::Retired)),
        )
        .unwrap(),
    );
    (mem, platform)
}
fn bridge(mem: Arc<GuestMemoryMmap>, platform: Option<Arc<Platform>>) -> GuestBridge {
    GuestBridge {
        exclusive: MemoryDomain::for_memory(&mem).register(),
        mem,
        pending: Arc::new(Mutex::new(VecDeque::new())),
        tohost_addr: Arc::new(Mutex::new(None)),
        devices_enabled: true,
        platform,
    }
}
#[test]
fn configured_harts_share_msip_without_writing_shadow_ram() {
    let (mem, platform) = fixture();
    mem.write_obj(0x00b52023u32.to_le(), GuestAddress(0x100))
        .unwrap();
    let mut sender =
        RiscVVcpu::new_in_platform(0, mem.clone(), RiscVConfig::rv64gc(), platform.clone())
            .unwrap();
    let mut receiver =
        RiscVVcpu::new_in_platform(1, mem.clone(), RiscVConfig::rv64gc(), platform.clone())
            .unwrap();
    sender.cpu.set_pc(0x100);
    sender.cpu.set_x(10, BASE + 4);
    sender.cpu.set_x(11, 3);
    sender.step_insn().unwrap();
    receiver.poll_vm_clock().unwrap();
    assert_eq!(receiver.cpu.csr_read(0x344).unwrap() & 8, 8);
    assert_eq!(
        mem.read_obj::<u32>(GuestAddress(BASE + 4)).unwrap(),
        0xa5a5a5a5
    );
    assert!(
        RiscVVcpu::new_in_platform(
            0,
            mem.clone(),
            RiscVConfig::rv32(crate::isa::riscv::Isa::rv64gc()),
            platform.clone()
        )
        .is_err()
    );
    assert!(RiscVVcpu::new_in_platform(2, mem, RiscVConfig::rv64gc(), platform).is_err());
}
#[test]
fn platform_interrupt_entry_retires_zero_and_cpu_mip_writes_do_not_own_inputs() {
    let (mem, platform) = fixture();
    mem.write_obj(0x00000013u32.to_le(), GuestAddress(0x100))
        .unwrap();
    let mut cpu =
        RiscVVcpu::new_in_platform(1, mem, RiscVConfig::rv64gc(), platform.clone()).unwrap();
    cpu.cpu.set_pc(0x100);
    cpu.cpu.csr_write(0x305, 0x200).unwrap();
    cpu.cpu.csr_write(0x304, 0x88).unwrap();
    cpu.cpu.csr_write(0x300, 8).unwrap();
    cpu.cpu.csr_write(0x344, 0x88).unwrap();
    cpu.poll_vm_clock().unwrap();
    assert_eq!(cpu.cpu.csr_read(0x344).unwrap() & 0x88, 0);
    platform.write(BASE + 4, &1u32.to_le_bytes()).unwrap();
    cpu.cpu.csr_write(0x344, 0).unwrap();
    let before = cpu.instruction_count();
    assert!(cpu.step_insn().unwrap().is_none());
    assert_eq!(cpu.instruction_count(), before);
    assert_eq!(cpu.cpu.pc(), 0x200);
    assert_eq!(cpu.cpu.csr_read(0x342).unwrap(), (1 << 63) | 3);
    assert_eq!(cpu.cpu.csr_read(0x341).unwrap(), 0x100);
}
#[test]
fn clint_atomics_and_crossing_transactions_reject_without_ram_or_device_effects() {
    let (mem, platform) = fixture();
    let mut memory = bridge(mem.clone(), Some(platform.clone()));
    let before = platform.checkpoint().unwrap();
    let operation = AtomicOp::Add(1);
    for (address, size) in [
        (BASE, 4u8),
        (BASE + 4, 4),
        (BASE + 0x4000, 8),
        (BASE - 4, 8),
    ] {
        assert!(memory.atomic(address, size, operation).is_err());
        let mut data = vec![0xa5; usize::from(size)];
        assert!(memory.load_reserved(address, &mut data).is_err());
        assert!(memory.store_conditional(address, &data, true).is_err());
    }
    let mut bytes = [0xa5; 8];
    assert!(memory.read(BASE - 4, &mut bytes).is_err());
    assert!(memory.write(BASE - 4, &[1; 8]).is_err());
    assert_eq!(bytes, [0xa5; 8]);
    assert_eq!(platform.checkpoint().unwrap(), before);
    assert_eq!(
        mem.read_obj::<u32>(GuestAddress(BASE + 4)).unwrap(),
        0xa5a5a5a5
    );
}
#[test]
fn standalone_and_disabled_platform_bridges_keep_clint_addresses_as_ram() {
    let (mem, platform) = fixture();
    for binding in [None, Some(platform.clone())] {
        platform.restore_with(None, || Ok(())).unwrap();
        let mut memory = bridge(mem.clone(), binding);
        memory
            .write(BASE + 4, &0x11223344u32.to_le_bytes())
            .unwrap();
        assert_eq!(memory.read_u32(BASE + 4).unwrap(), 0x11223344);
    }
}
#[test]
fn raw_hart_restore_requires_matching_shared_platform_profile() {
    let (mem, platform) = fixture();
    let mut configured =
        RiscVVcpu::new_in_platform(0, mem.clone(), RiscVConfig::rv64gc(), platform.clone())
            .unwrap();
    let mut standalone = RiscVVcpu::new(0, mem);
    let current = configured.save_context().unwrap();
    let legacy = standalone.save_context().unwrap();
    let before = configured.save_context().unwrap();
    assert!(configured.restore_context(&legacy).is_err());
    assert_eq!(configured.save_context().unwrap(), before);
    assert!(standalone.restore_context(&current).is_err());
    platform.restore_with(None, || Ok(())).unwrap();
    configured.restore_context(&legacy).unwrap();
}
