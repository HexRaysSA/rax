use super::*;
use crate::backend::emulator::riscv::platform::{BASE, FREQUENCY_HZ, LEN, Platform};
use crate::isa::riscv::memory::AtomicOp;
use crate::vm::timing::{ClockMode, RETIREMENT_FREQUENCY_HZ, TimingContext};
use crate::vm::vcpu::RetirementStop;

fn fixture(architectural_traps: bool) -> (Arc<GuestMemoryMmap>, Arc<Platform>) {
    fixture_with_clock(architectural_traps, ClockMode::Retired)
}

fn fixture_with_clock(
    architectural_traps: bool,
    clock: ClockMode,
) -> (Arc<GuestMemoryMmap>, Arc<Platform>) {
    fixture_with_timing(
        architectural_traps,
        Arc::new(TimingContext::with_mode(clock)),
    )
}

fn fixture_with_timing(
    architectural_traps: bool,
    clock: Arc<TimingContext>,
) -> (Arc<GuestMemoryMmap>, Arc<Platform>) {
    let mem = Arc::new(
        GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), 0x2000),
            (GuestAddress(BASE), LEN as usize),
        ])
        .unwrap(),
    );
    mem.write_obj(0xa5a5a5a5u32, GuestAddress(BASE + 4))
        .unwrap();
    let platform = Arc::new(Platform::new(2, 0x2000, clock, architectural_traps).unwrap());
    (mem, platform)
}

#[test]
fn retirement_budget_publishes_the_timer_at_halt_and_samples_it_before_the_next_instruction() {
    const PC: u64 = 0x100;
    const WFI: u64 = PC + 4;
    const VECTOR: u64 = 0x200;
    const MTIP: u64 = 1 << cause::INT_M_TIMER;
    const UNITS_PER_TICK: u64 = RETIREMENT_FREQUENCY_HZ / FREQUENCY_HZ;

    for wait_at_deadline in [false, true] {
        let timing = Arc::new(TimingContext::with_mode(ClockMode::RetiredWithIdle));
        let (mem, platform) = fixture_with_timing(true, timing.clone());
        mem.write_obj(0x0000_006fu32.to_le(), GuestAddress(PC))
            .unwrap(); // jal zero,0
        mem.write_obj(0x1050_0073u32.to_le(), GuestAddress(WFI))
            .unwrap(); // wfi
        platform.write(BASE + 0x4008, &1u64.to_le_bytes()).unwrap();
        let mut hart =
            RiscVVcpu::new_in_platform(1, mem, RiscVConfig::rv64gc(), platform.clone()).unwrap();
        hart.cpu.set_pc(PC);
        hart.cpu.csr_write(0x305, VECTOR).unwrap();
        hart.cpu.csr_write(0x304, MTIP).unwrap();
        hart.cpu.csr_write(0x300, 8).unwrap();
        let _timing = timing.enter();

        let before_tick = hart.run_retirement_budget(UNITS_PER_TICK - 1).unwrap();
        assert!(matches!(before_tick.stop, RetirementStop::BudgetExhausted));
        assert_eq!(before_tick.retired, UNITS_PER_TICK - 1);
        assert_eq!(hart.cpu.csr_read(0x344).unwrap() & MTIP, 0);

        let interrupted_pc = if wait_at_deadline {
            hart.cpu.set_pc(WFI);
            let halt = hart.run_retirement_budget(2).unwrap();
            assert!(matches!(halt.stop, RetirementStop::Exit(VcpuExit::Hlt)));
            assert_eq!(halt.retired, 1);
            assert_eq!(hart.cpu.csr_read(0x344).unwrap() & MTIP, MTIP);
            WFI + 4
        } else {
            PC
        };
        let interrupt = hart.run_retirement_budget(2).unwrap();
        assert!(matches!(interrupt.stop, RetirementStop::StateChange));
        assert_eq!(interrupt.retired, u64::from(!wait_at_deadline));
        assert_eq!(hart.instruction_count(), UNITS_PER_TICK);
        assert_eq!(timing.retirement_count(), Some(UNITS_PER_TICK));
        assert_eq!(hart.cpu.pc(), VECTOR);
        assert_eq!(hart.cpu.csr_read(0x341).unwrap(), interrupted_pc);
        assert_eq!(hart.cpu.csr_read(0x342).unwrap(), (1 << 63) | 7);
    }
}

#[test]
fn wall_clock_firmware_wait_survives_restore_and_wakes_on_a_local_interrupt() {
    const PC: u64 = 0x100;
    const DEADLINE: u64 = 1 << 62;
    for (enabled, register, data) in [
        (
            1 << cause::INT_M_SOFTWARE,
            BASE + 4,
            1u32.to_le_bytes().to_vec(),
        ),
        (
            1 << cause::INT_M_TIMER,
            BASE + 0xbff8,
            DEADLINE.to_le_bytes().to_vec(),
        ),
    ] {
        let (mem, platform) = fixture_with_clock(true, ClockMode::Wall);
        mem.write_obj(0x1050_0073u32.to_le(), GuestAddress(PC))
            .unwrap(); // wfi
        mem.write_obj(0x02b0_0393u32.to_le(), GuestAddress(PC + 4))
            .unwrap(); // addi t2,zero,43
        platform
            .write(BASE + 0x4008, &DEADLINE.to_le_bytes())
            .unwrap();
        let make_hart = || {
            RiscVVcpu::new_in_platform(1, mem.clone(), RiscVConfig::rv64gc(), platform.clone())
                .unwrap()
        };
        let mut original = make_hart();
        original.cpu.set_pc(PC);
        original.cpu.csr_write(0x304, enabled).unwrap();
        assert!(matches!(original.step_insn().unwrap(), Some(VcpuExit::Hlt)));
        assert_eq!(original.instruction_count(), 1);
        assert_eq!(original.cpu.pc(), PC + 4);

        let mut restored = make_hart();
        restored
            .restore_context(&original.save_context().unwrap())
            .unwrap();
        for hart in [&mut original, &mut restored] {
            assert!(matches!(hart.step_insn().unwrap(), Some(VcpuExit::Hlt)));
            assert_eq!(hart.instruction_count(), 1);
            assert_eq!(hart.cpu.x(7), 0);
        }

        platform.write(register, &data).unwrap();
        for hart in [&mut original, &mut restored] {
            assert!(hart.step_insn().unwrap().is_none());
            assert_eq!(hart.instruction_count(), 2);
            assert_eq!(hart.cpu.x(7), 43);
            assert_eq!(hart.cpu.csr_read(0x342).unwrap(), 0);
        }
    }
}

#[test]
fn machine_ecall_and_compressed_breakpoint_enter_the_selected_vector() {
    let (mem, platform) = fixture(true);
    let pc = 0x102;
    for (word, origin, vector, epc, cause, tval, expected_cause, expected_tval) in [
        (0x0000_0073u32, Priv::Machine, 0, 0x341, 0x342, 0x343, 11, 0),
        (0x0000_9002, Priv::User, 0x200, 0x141, 0x142, 0x143, 3, pc),
    ] {
        mem.write_slice(&word.to_le_bytes(), GuestAddress(pc))
            .unwrap();
        let mut hart =
            RiscVVcpu::new_in_platform(0, mem.clone(), RiscVConfig::rv64gc(), platform.clone())
                .unwrap();
        hart.cpu.set_pc(pc);
        hart.cpu.set_privilege(origin);
        hart.cpu.csr_write(0x302, (1 << 11) | (1 << 3)).unwrap();
        hart.cpu.csr_write(0x305, 1).unwrap();
        hart.cpu.csr_write(0x105, 0x201).unwrap();
        assert!(hart.step_insn().unwrap().is_none());
        assert_eq!(hart.instruction_count(), 0);
        assert_eq!(hart.cpu.pc(), vector);
        assert_eq!(hart.cpu.csr_read(epc).unwrap(), pc);
        assert_eq!(hart.cpu.csr_read(cause).unwrap(), expected_cause);
        assert_eq!(hart.cpu.csr_read(tval).unwrap(), expected_tval);
    }
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
    let (mem, platform) = fixture(false);
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
    let (mem, platform) = fixture(false);
    mem.write_obj(0x00000013u32.to_le(), GuestAddress(0x100))
        .unwrap();
    let mut cpu =
        RiscVVcpu::new_in_platform(1, mem, RiscVConfig::rv64gc(), platform.clone()).unwrap();
    cpu.cpu.set_pc(0x100);
    cpu.cpu.csr_write(0x305, 0x200).unwrap();
    cpu.cpu.csr_write(0x304, 0x88).unwrap();
    cpu.cpu.csr_write(0x300, 8).unwrap();
    cpu.cpu.set_interrupt_pending(0x88, true);
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
    let (mem, platform) = fixture(false);
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
    let (mem, platform) = fixture(false);
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
    let (mem, platform) = fixture(false);
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

#[test]
fn uart_reads_consume_input_without_fetch_or_invalid_access_side_effects() {
    use crate::backend::emulator::riscv::platform::PLIC_BASE;
    use crate::devices::bus::MmioDevice;
    use crate::devices::serial::Serial16550;

    let (mem, platform) = fixture(false);
    let mut uart = Serial16550::new_mmio(UART_BASE);
    uart.write(UART_BASE + 1, &[1]); // Receiver interrupt enable.
    platform.bind_serial(Arc::new(Mutex::new(uart))).unwrap();
    let mut memory = bridge(mem, Some(platform.clone()));
    memory.write(PLIC_BASE + 40, &3u32.to_le_bytes()).unwrap();
    memory
        .write(PLIC_BASE + 0x2080, &(1u32 << 10).to_le_bytes())
        .unwrap();
    assert!(platform.queue_uart_input(b"X").unwrap());
    assert_eq!(
        platform.signals(0).unwrap().unwrap().external,
        Some((false, true))
    );
    let claim = PLIC_BASE + 0x20_1004;
    assert_eq!(memory.read_u32(claim).unwrap(), 10);
    let before = platform.checkpoint().unwrap();
    assert!(memory.fetch_u16(UART_BASE).is_err());
    assert!(memory.read(UART_BASE - 1, &mut [0; 2]).is_err());
    assert!(memory.write(UART_BASE + 7, &[0; 2]).is_err());
    assert_eq!(platform.checkpoint().unwrap(), before);

    let mut byte = [0; 1];
    memory.read(UART_BASE, &mut byte).unwrap();
    assert_eq!(byte, *b"X");
    memory.write(claim, &10u32.to_le_bytes()).unwrap();
    assert_eq!(
        platform.signals(0).unwrap().unwrap().external,
        Some((false, false))
    );
    assert_eq!(memory.read_u32(claim).unwrap(), 0);
}
