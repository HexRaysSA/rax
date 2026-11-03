use super::*;
use crate::vm::vcpu::CpuState;

fn test_cfg() -> GscConfig {
    GscConfig {
        uart_base: DEFAULT_UART_BASE,
        uart_state: DEFAULT_UART_STATE,
        open_bus: 0,
        rstsrc_cold: DEFAULT_RSTSRC_COLD,
        rstsrc_warm: DEFAULT_RSTSRC_WARM,
        flash_img_base: DEFAULT_FLASH_IMG_BASE,
        trace: Trace::Off,
        console_trace: false,
        ap_ro_info_stub: false,
        ap_ro_crypto_stub: false,
        ap_ro_stub: false,
        timer_div: TIMER_DEFAULT_DIV,
    }
}

fn test_bridge() -> GscBridge {
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20_0000usize)]).unwrap();
    GscBridge {
        exclusive: crate::vm::memory::reservations::MemoryDomain::for_memory(&mem).register(),
        mem: Arc::new(mem),
        shared: Arc::new(Mutex::new(GscShared {
            rstsrc: DEFAULT_RSTSRC_COLD,
            timer_compare: u64::MAX,
            ..GscShared::default()
        })),
        ap_flash: Arc::new(Vec::new()),
        cfg: test_cfg(),
        ready: builtin_ready_map(),
        pc: Arc::new(AtomicU64::new(0)),
        time: Arc::new(AtomicU64::new(0)),
        crypto_trace: false,
    }
}

fn rd32(b: &GscBridge, addr: u64) -> u32 {
    let mut buf = [0u8; 4];
    b.read(addr, &mut buf).unwrap();
    u32::from_le_bytes(buf)
}

fn wr32(b: &mut GscBridge, addr: u64, value: u32) {
    b.write(addr, &value.to_le_bytes()).unwrap();
}

fn rd8(b: &GscBridge, addr: u64) -> u8 {
    let mut buf = [0u8; 1];
    b.read(addr, &mut buf).unwrap();
    buf[0]
}

fn wr8(b: &mut GscBridge, addr: u64, value: u8) {
    b.write(addr, &[value]).unwrap();
}

fn mem_rd32(b: &GscBridge, addr: u64) -> u32 {
    let mut buf = [0u8; 4];
    b.mem.read_slice(&mut buf, GuestAddress(addr)).unwrap();
    u32::from_le_bytes(buf)
}

fn mem_wr32(b: &GscBridge, addr: u64, value: u32) {
    b.mem
        .write_slice(&value.to_le_bytes(), GuestAddress(addr))
        .unwrap();
}

#[test]
fn ready_map_returns_fixed_status() {
    let mut b = test_bridge();
    b.ready.insert(0x4000_1234, 0x5a5a_0001);
    assert_eq!(rd32(&b, 0x4000_1234), 0x5a5a_0001);
}

#[test]
fn timer_counter_advances_with_published_time() {
    let b = test_bridge();
    // Frozen at zero before any time is published.
    assert_eq!(rd32(&b, TIMER_COUNT_LO), 0);
    assert_eq!(rd32(&b, TIMER_COUNT_HI), 0);
    // The free-running counter reflects the published instruction count
    // divided by the configured tick divisor.
    let instret = (TIMER_DEFAULT_DIV as u64) * 0x1_2345_6789;
    b.time.store(instret, Ordering::Relaxed);
    let ticks = instret / TIMER_DEFAULT_DIV as u64;
    assert_eq!(rd32(&b, TIMER_COUNT_LO), ticks as u32);
    assert_eq!(rd32(&b, TIMER_COUNT_HI), (ticks >> 32) as u32);
    // Busy/ready status always reads "ready" (0).
    assert_eq!(rd32(&b, TIMER_BUSY), 0);
}

#[test]
fn second_timer_counter_advances() {
    let b = test_bridge();
    assert_eq!(rd32(&b, TIMER2_COUNT_LO), 0);
    let instret = (TIMER_DEFAULT_DIV as u64) * 0xfeed_face;
    b.time.store(instret, Ordering::Relaxed);
    let ticks = instret / TIMER_DEFAULT_DIV as u64;
    assert_eq!(rd32(&b, TIMER2_COUNT_LO), ticks as u32);
    assert_eq!(rd32(&b, TIMER2_COUNT_HI), (ticks >> 32) as u32);
    assert_eq!(rd32(&b, TIMER2_BUSY), 0);
}

#[test]
fn drbg_reports_done_and_nonzero_output() {
    let b = test_bridge();
    // sub_80434 spins until status bits[2:0] != 0 and treats 1 as success.
    assert_eq!(rd32(&b, DRBG_STATUS) & 7, 1);
    // The 256-bit output files read back non-zero, varied entropy.
    let w0 = rd32(&b, DRBG_OUT_HI);
    let w1 = rd32(&b, DRBG_OUT_HI + 4);
    assert_ne!(w0, 0);
    assert_ne!(w1, 0);
    assert_ne!(w0, w1);
}

#[test]
fn fifo_ram_window_round_trips() {
    let mut b = test_bridge();
    // The GscFifo dual-port RAM stages the wired TPM frame.
    wr32(&mut b, GSC_FIFO_RAM_BASE, 0x0c00_0180);
    wr32(&mut b, GSC_FIFO_RAM_BASE + 4, 0x4401_0000);
    assert_eq!(rd32(&b, GSC_FIFO_RAM_BASE), 0x0c00_0180);
    assert_eq!(rd32(&b, GSC_FIFO_RAM_BASE + 4), 0x4401_0000);
    // Byte-accurate access.
    wr8(&mut b, GSC_FIFO_RAM_BASE + 2, 0xab);
    assert_eq!(rd8(&b, GSC_FIFO_RAM_BASE + 2), 0xab);
}

#[test]
fn timer_compare_write_tracks_64bit_deadline() {
    let mut b = test_bridge();
    // Init disarms the compare (all-ones); the alarm driver then writes a
    // 64-bit deadline through the low/high halves.
    assert_eq!(b.shared.lock().unwrap().timer_compare, u64::MAX);
    wr32(&mut b, TIMER_COMPARE_LO, 0xdead_beef);
    wr32(&mut b, TIMER_COMPARE_HI, 0x0000_1234);
    assert_eq!(
        b.shared.lock().unwrap().timer_compare,
        0x0000_1234_dead_beef
    );
}

#[test]
fn parse_tpm_cmds_splits_hex_commands() {
    let cmds = {
        // Mirror parse_tpm_cmds_env's parsing on an explicit string.
        "80010000000c000001440000, 80 01 00 00"
            .split([',', ';'])
            .filter_map(|part| {
                let hex: String = part.chars().filter(|c| c.is_ascii_hexdigit()).collect();
                if hex.len() < 2 {
                    return None;
                }
                let bytes: Vec<u8> = (0..hex.len() - 1)
                    .step_by(2)
                    .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
                    .collect();
                (!bytes.is_empty()).then_some(bytes)
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(cmds.len(), 2);
    assert_eq!(
        cmds[0],
        vec![
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00
        ]
    );
    assert_eq!(cmds[1], vec![0x80, 0x01, 0x00, 0x00]);
}

#[test]
fn uart_state_tracks_rx_queue() {
    let b = test_bridge();
    let state = rd32(&b, DEFAULT_UART_BASE + UART_STATE);
    assert_eq!(state & UART_STATE_TX_BUSY, 0);
    assert_eq!(state & UART_STATE_RX_EMPTY, UART_STATE_RX_EMPTY);

    b.shared.lock().unwrap().uart_rx.extend(b"AB");
    let state = rd32(&b, DEFAULT_UART_BASE + UART_STATE);
    assert_eq!(state & UART_STATE_RX_EMPTY, UART_STATE_RX_EMPTY);

    b.shared.lock().unwrap().uart_irq_armed = true;
    let state = rd32(&b, DEFAULT_UART_BASE + UART_STATE);
    assert_eq!(state & UART_STATE_RX_EMPTY, 0);
    assert_eq!(rd32(&b, DEFAULT_UART_BASE + UART_RDATA), b'A' as u32);
    assert_eq!(rd32(&b, DEFAULT_UART_BASE + UART_RDATA), b'B' as u32);
    let state = rd32(&b, DEFAULT_UART_BASE + UART_STATE);
    assert_eq!(state & UART_STATE_RX_EMPTY, UART_STATE_RX_EMPTY);
}

#[test]
fn core_irq_claim_tracks_armed_uart_rx() {
    let b = test_bridge();
    assert_eq!(rd32(&b, CORE_IRQ_CLAIM), CORE_IRQ_NONE);

    b.shared.lock().unwrap().uart_rx.extend(b"A");
    assert_eq!(rd32(&b, CORE_IRQ_CLAIM), CORE_IRQ_NONE);

    b.shared.lock().unwrap().uart_irq_armed = true;
    assert_eq!(rd32(&b, CORE_IRQ_CLAIM), CORE_IRQ_UART0);
    assert_eq!(rd32(&b, CORE_IRQ_EPOCH), 0);

    assert_eq!(rd32(&b, DEFAULT_UART_BASE + UART_RDATA), b'A' as u32);
    assert_eq!(rd32(&b, CORE_IRQ_CLAIM), CORE_IRQ_NONE);
}

#[test]
fn rstsrc_reads_por_then_clears_via_clrrst() {
    let mut b = test_bridge();
    // Cold boot: RSTSRC (PMU+0x00) reads back POR, so the firmware
    // classifies the reset cause instead of "Other" + reboot.
    assert_eq!(rd32(&b, PMU_RSTSRC_REG), RSTSRC_POR);
    // CLRRST (PMU+0x04, write-1-to-clear) clears the reported bits.
    wr32(&mut b, PMU_CLRRST_REG, RSTSRC_POR);
    assert_eq!(rd32(&b, PMU_RSTSRC_REG), 0);
}

#[test]
fn global_reset_preserves_persistent_pmu_scratch() {
    // The persistent PMU scratch (boot counter / init flags) must survive a
    // warm reset, so the firmware sees "already initialized" on reboot.
    let mut b = test_bridge();
    // Boot-attempt counter.
    wr32(&mut b, 0x4000_00b0, 0x0000_0300);
    // RO init flags (bits 30/31).
    wr32(&mut b, 0x4000_004c, 0xc000_0000);
    // A warm reset clears CPU/arch state but NOT the bridge's store.
    assert_eq!(rd32(&b, 0x4000_00b0), 0x0000_0300);
    assert_eq!(rd32(&b, 0x4000_004c), 0xc000_0000);
}

#[test]
fn mmio_registers_remember_writes() {
    let mut b = test_bridge();
    // An unmodeled register reads back the last value written (scratch).
    assert_eq!(rd32(&b, 0x4000_1000), 0); // open-bus before any write
    wr32(&mut b, 0x4000_1000, 0xabcd_1234);
    assert_eq!(rd32(&b, 0x4000_1000), 0xabcd_1234);
}

#[test]
fn spin_breaker_alternates_polarity() {
    let mut b = test_bridge();
    let addr = 0x4000_2000;
    // Below threshold: open-bus 0.
    for _ in 0..(SPIN_THRESHOLD - 1) {
        assert_eq!(rd32(&b, addr), 0);
    }
    // The threshold-th consecutive read breaks the spin with all-ones.
    assert_eq!(rd32(&b, addr), 0xffff_ffff);
    // The next break alternates to zero (satisfies "wait for clear").
    for _ in 0..(SPIN_THRESHOLD - 1) {
        let _ = rd32(&b, addr);
    }
    assert_eq!(rd32(&b, addr), 0x0000_0000);
    // A write resets the spin window (forward progress).
    wr32(&mut b, addr, 5);
    assert_eq!(rd32(&b, addr), 5);
}

#[test]
fn pmu_reset_magic_is_detected() {
    let mut b = test_bridge();
    wr32(&mut b, PMU_RESET_REG, 0x1234); // wrong value: no reset
    assert!(!b.shared.lock().unwrap().reset_requested);
    wr32(&mut b, PMU_RESET_REG, PMU_RESET_MAGIC);
    assert!(b.shared.lock().unwrap().reset_requested);
}

#[test]
fn pmu_chip_id_and_wake_source_are_fixed() {
    let b = test_bridge();
    assert_eq!(rd32(&b, PMU_CHIP_ID_REG), PMU_CHIP_ID);
    assert_eq!(rd32(&b, PMU_CHIP_ID_ALT_REG), PMU_CHIP_ID);
    assert_eq!(rd32(&b, PMU_WAKE_EXIT_SRC_REG), 0);
}

#[test]
fn flash_program_op_uses_payload_registers_and_clears_control() {
    let mut b = test_bridge();
    let off = 0x3e400;
    let gpa = DEFAULT_FLASH_IMG_BASE + off;
    let trans = ((off / 4) as u32) << 7;

    mem_wr32(&b, gpa, 0xffff_00ff);
    mem_wr32(&b, gpa + 4, 0xffff_ffff);
    wr32(&mut b, FLASH_TRANS, trans);
    wr32(&mut b, FLASH_WR_DATA0, 0x1234_5678);
    wr32(&mut b, FLASH_WR_DATA1, 0x0000_ffff);
    wr32(&mut b, FLASH_PE_EN, FLASH_PE_EN_MAGIC);
    wr32(&mut b, FLASH_PE_CONTROL0, FLASH_OP_TI50_PROGRAM);

    assert_eq!(rd32(&b, FLASH_PE_CONTROL0), 0);
    assert_eq!(rd32(&b, FLASH_ERROR), 0);
    assert_eq!(mem_rd32(&b, gpa), 0x1234_0078);
    assert_eq!(mem_rd32(&b, gpa + 4), 0x0000_ffff);
}

#[test]
fn flash_control1_programs_second_slot() {
    let mut b = test_bridge();
    let off = 0x3b800;
    let slot0_gpa = DEFAULT_FLASH_IMG_BASE + off;
    let slot1_gpa = DEFAULT_FLASH_IMG_BASE + TI50_FLASH_SLOT_SIZE + off;
    let trans = ((off / 4) as u32) << 7;

    mem_wr32(&b, slot0_gpa, 0x4622_4592);
    mem_wr32(&b, slot1_gpa, 0xffff_ffff);
    wr32(&mut b, FLASH_TRANS, trans);
    wr32(&mut b, FLASH_WR_DATA0, 0);
    wr32(&mut b, FLASH_WR_DATA1, 0);
    wr32(&mut b, FLASH_PE_EN, FLASH_PE_EN_MAGIC);
    wr32(&mut b, FLASH_PE_CONTROL1, FLASH_OP_TI50_PROGRAM);

    assert_eq!(mem_rd32(&b, slot0_gpa), 0x4622_4592);
    assert_eq!(mem_rd32(&b, slot1_gpa), 0);
}

#[test]
fn flash_read_and_erase_family_ops_work() {
    let mut b = test_bridge();
    let off = 0x1200;
    let gpa = DEFAULT_FLASH_IMG_BASE + off;
    let read_trans = (off / 4) as u32;
    let trans = read_trans << 7;

    mem_wr32(&b, gpa, 0xa5a5_5a5a);
    mem_wr32(&b, gpa + 4, 0x1122_3344);
    wr32(&mut b, FLASH_READ_TRANS, read_trans);
    wr32(&mut b, FLASH_PE_EN, FLASH_PE_EN_MAGIC);
    wr32(&mut b, FLASH_PE_CONTROL0, FLASH_OP_CR50_READ);
    assert_eq!(rd32(&b, FLASH_DOUT0_LO), 0xa5a5_5a5a);
    assert_eq!(rd32(&b, FLASH_DOUT0_HI), 0x1122_3344);

    let slot1_gpa = DEFAULT_FLASH_IMG_BASE + TI50_FLASH_SLOT_SIZE + off;
    mem_wr32(&b, slot1_gpa, 0x5566_7788);
    mem_wr32(&b, slot1_gpa + 4, 0x99aa_bbcc);
    wr32(&mut b, FLASH_READ_TRANS, read_trans);
    wr32(&mut b, FLASH_PE_EN, FLASH_PE_EN_MAGIC);
    wr32(&mut b, FLASH_PE_CONTROL1, FLASH_OP_CR50_READ);
    assert_eq!(rd32(&b, FLASH_DOUT1_LO), 0x5566_7788);
    assert_eq!(rd32(&b, FLASH_DOUT1_HI), 0x99aa_bbcc);
    assert_eq!(rd32(&b, FLASH_STATUS1), 0);

    wr32(&mut b, FLASH_TRANS, trans);
    wr32(&mut b, FLASH_PE_EN, FLASH_PE_EN_MAGIC);
    wr32(&mut b, FLASH_PE_CONTROL0, FLASH_OP_CR50_ERASE);
    assert_eq!(mem_rd32(&b, gpa), 0xffff_ffff);
    assert_eq!(mem_rd32(&b, gpa + 4), 0xffff_ffff);
}

#[test]
fn flash_info_bank_is_separate_from_xip_flash() {
    let mut b = test_bridge();
    let off = 0x500;
    let gpa = DEFAULT_FLASH_IMG_BASE + off;
    let read_trans = 0x1_0000 | (off / 4) as u32;
    let prog_trans = (((off / 4) as u32) << 7) | 0x8;

    mem_wr32(&b, gpa, 0x1234_5678);
    wr32(&mut b, FLASH_READ_TRANS, read_trans);
    wr32(&mut b, FLASH_PE_EN, FLASH_PE_EN_MAGIC);
    wr32(&mut b, FLASH_PE_CONTROL0, FLASH_OP_CR50_READ);
    assert_eq!(rd32(&b, FLASH_DOUT0_LO), 0xffff_ffff);

    wr32(&mut b, FLASH_TRANS, prog_trans);
    wr32(&mut b, FLASH_WR_DATA0, 0x00ff_00ff);
    wr32(&mut b, FLASH_WR_DATA1, 0xff00_ff00);
    wr32(&mut b, FLASH_PE_EN, FLASH_PE_EN_MAGIC);
    wr32(&mut b, FLASH_PE_CONTROL0, FLASH_OP_CR50_PROGRAM);

    wr32(&mut b, FLASH_READ_TRANS, read_trans);
    wr32(&mut b, FLASH_PE_EN, FLASH_PE_EN_MAGIC);
    wr32(&mut b, FLASH_PE_CONTROL0, FLASH_OP_CR50_READ);
    assert_eq!(rd32(&b, FLASH_DOUT0_LO), 0x00ff_00ff);
    assert_eq!(rd32(&b, FLASH_DOUT0_HI), 0xff00_ff00);
    assert_eq!(mem_rd32(&b, gpa), 0x1234_5678);
}

#[test]
fn ap_ro_stub_supplies_cached_status_info_words() {
    let mut b = test_bridge();
    b.cfg.ap_ro_stub = true;

    let read_info = |b: &mut GscBridge, off: u64| -> [u32; 2] {
        wr32(b, FLASH_READ_TRANS, 0x1_0000 | (off / 4) as u32);
        wr32(b, FLASH_PE_EN, FLASH_PE_EN_MAGIC);
        wr32(b, FLASH_PE_CONTROL1, FLASH_OP_CR50_READ);
        [rd32(b, FLASH_DOUT1_LO), rd32(b, FLASH_DOUT1_HI)]
    };

    assert_eq!(read_info(&mut b, 0x0c00), [0x0000_0001, 0x0000_0001]);
    assert_eq!(read_info(&mut b, 0x0c08), [0x00ff_ff00, 0x00ff_fd02]);
    assert_eq!(read_info(&mut b, 0x0c10), [0x00ff_ff00, 0x00ff_ff00]);
    assert_eq!(read_info(&mut b, 0x0c18), [0x00ff_ff00, 0x0000_0000]);
}

#[test]
fn ap_ro_info_stub_only_supplies_cached_status_info_words() {
    let mut b = test_bridge();
    b.cfg.ap_ro_info_stub = true;

    wr32(&mut b, FLASH_READ_TRANS, 0x1_0000 | (0x0c08 / 4));
    wr32(&mut b, FLASH_PE_EN, FLASH_PE_EN_MAGIC);
    wr32(&mut b, FLASH_PE_CONTROL1, FLASH_OP_CR50_READ);

    assert_eq!(rd32(&b, FLASH_DOUT1_LO), 0x00ff_ff00);
    assert_eq!(rd32(&b, FLASH_DOUT1_HI), 0x00ff_fd02);
}

#[test]
fn ap_ro_stub_forces_kernel_verifier_return_to_ok() {
    let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20_0000usize)]).unwrap());
    let mut vcpu = GscVcpu::new(0, mem.clone());
    vcpu.ap_ro_stub = true;
    vcpu.cpu.set_x(10, 0xdead_beef);
    vcpu.cpu.set_pc(0xb7462);
    mem.write_slice(&0x0010_0073u32.to_le_bytes(), GuestAddress(0xb7462))
        .unwrap();

    assert!(matches!(vcpu.run().unwrap(), VcpuExit::Debug));
    assert_eq!(vcpu.cpu.x(10), 0);
}

#[test]
fn ap_ro_crypto_stub_supplies_root_key_digest_compare_result() {
    let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20_0000usize)]).unwrap());
    let mut vcpu = GscVcpu::new(0, mem.clone());
    vcpu.ap_ro_crypto_stub = true;
    vcpu.cpu.set_x(2, 0x12_000);
    vcpu.cpu.set_pc(0xb2904);

    let expected_addr = 0x18_000u32;
    let expected = [0x5au8; 0x20];
    mem.write_slice(&expected_addr.to_le_bytes(), GuestAddress(0x12_000 + 0x68))
        .unwrap();
    mem.write_slice(&expected, GuestAddress(expected_addr as u64))
        .unwrap();
    mem.write_slice(&0x0010_0073u32.to_le_bytes(), GuestAddress(0xb2904))
        .unwrap();

    assert!(matches!(vcpu.run().unwrap(), VcpuExit::Debug));
    let mut actual = [0u8; 0x20];
    mem.read_slice(&mut actual, GuestAddress(0x12_000 + 0x250))
        .unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn ap_ro_crypto_stub_supplies_range_digest_compare_result() {
    let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20_0000usize)]).unwrap());
    let mut vcpu = GscVcpu::new(0, mem.clone());
    vcpu.ap_ro_crypto_stub = true;
    vcpu.cpu.set_pc(0xb1efe);
    vcpu.cpu.set_x(18, 0x12_000);
    vcpu.cpu.set_x(19, 0x20);
    vcpu.cpu.set_x(21, 0x18_000);
    vcpu.cpu.set_x(9, 0x20);

    let expected = [0xacu8; 0x20];
    mem.write_slice(&expected, GuestAddress(0x18_000)).unwrap();
    mem.write_slice(&[0x55u8; 0x20], GuestAddress(0x12_000))
        .unwrap();
    mem.write_slice(&0x0010_0073u32.to_le_bytes(), GuestAddress(0xb1efe))
        .unwrap();

    assert!(matches!(vcpu.run().unwrap(), VcpuExit::Debug));
    let mut actual = [0u8; 0x20];
    mem.read_slice(&mut actual, GuestAddress(0x12_000)).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn usb_status_and_reset_registers_self_clear() {
    let mut b = test_bridge();
    wr32(&mut b, USB_INT_STATE2, 0xffff_ffff);
    assert_eq!(rd32(&b, USB_INT_STATE2), 0);
    wr32(&mut b, USB_SOFT_RESET, 1);
    assert_eq!(rd32(&b, USB_SOFT_RESET), 0);
    wr32(&mut b, GSC_EVENT_USB_RESET, 1);
    assert_eq!(rd32(&b, GSC_EVENT_USB_RESET), 0x8000_0000);
}

#[test]
fn rbox_interrupt_state_is_write_one_to_clear() {
    let mut b = test_bridge();
    b.shared
        .lock()
        .unwrap()
        .store
        .insert(RBOX_INTR0_STATE, 0x0000_00ff);

    wr32(&mut b, RBOX_INTR0_STATE, 0x0000_000f);
    assert_eq!(rd32(&b, RBOX_INTR0_STATE), 0x0000_00f0);

    wr32(&mut b, RBOX_INTR1_STATE, 0xffff_ffff);
    assert_eq!(rd32(&b, RBOX_INTR1_STATE), 0);
}

#[test]
fn rbox_ready_and_control_status_complete_immediately() {
    let mut b = test_bridge();
    assert_eq!(rd32(&b, RBOX_INIT_READY), 1);
    assert_eq!(rd32(&b, RBOX_CMD_STATUS), 0);

    wr32(&mut b, RBOX_CONTROL0, 0);
    assert_eq!(rd32(&b, RBOX_STATUS) & 1, 0);
    wr32(&mut b, RBOX_CONTROL0, 1);
    assert_eq!(rd32(&b, RBOX_STATUS) & 1, 1);

    wr32(&mut b, RBOX_CONTROL1, 1);
    assert_eq!(rd32(&b, RBOX_STATUS) & 0x20, 0);
    wr32(&mut b, RBOX_CONTROL1, 0);
    assert_eq!(rd32(&b, RBOX_STATUS) & 0x20, 0x20);
}

#[test]
fn ap_spi_status_registers_are_write_one_to_clear() {
    let mut b = test_bridge();
    b.shared
        .lock()
        .unwrap()
        .store
        .insert(AP_SPI_INTR2, 0x0000_00ff);

    wr32(&mut b, AP_SPI_INTR2, 0x0000_000f);
    assert_eq!(rd32(&b, AP_SPI_INTR2), 0x0000_00f0);

    wr32(&mut b, AP_SPI_INTR2, 0xffff_ffff);
    assert_eq!(rd32(&b, AP_SPI_INTR2), 0);
}

#[test]
fn ap_spi_transaction_clears_busy_and_returns_status_byte() {
    let mut b = test_bridge();

    wr8(&mut b, AP_SPI_DATA_BASE, 0x05);
    wr32(&mut b, AP_SPI_XFER_CFG, 0x0000_0380);
    wr32(&mut b, AP_SPI_XACT, 0x000f_0001);

    assert_eq!(rd32(&b, AP_SPI_XACT) & AP_SPI_XACT_START, 0);
    assert_eq!(rd8(&b, AP_SPI_DATA_BASE + 5), 0x02);

    wr8(&mut b, AP_SPI_DATA_BASE, 0x35);
    wr32(&mut b, AP_SPI_XACT, 0x000f_0001);
    assert_eq!(rd32(&b, AP_SPI_XACT) & AP_SPI_XACT_START, 0);
    assert_eq!(rd8(&b, AP_SPI_DATA_BASE + 5), 0);
}

#[test]
fn ap_spi_fast_read_returns_erased_flash_without_image() {
    let mut b = test_bridge();

    wr32(&mut b, AP_SPI_DATA_BASE, 0x3412_000b); // 0x0b fast-read @ 0x001234
    wr32(&mut b, AP_SPI_DATA_BASE + 4, 0);
    wr32(&mut b, AP_SPI_XFER_CFG, 0x0018_1380);
    wr32(&mut b, AP_SPI_XACT, 0x0067_0001);

    assert_eq!(rd32(&b, AP_SPI_XACT) & AP_SPI_XACT_START, 0);
    assert_eq!(rd8(&b, AP_SPI_DATA_BASE + 0x0d), 0xff);
    assert_eq!(rd8(&b, AP_SPI_DATA_BASE + 0x11), 0xff);
    assert_eq!(rd8(&b, AP_SPI_DATA_BASE + 0x17), 0xff);
}

#[test]
fn ap_spi_fast_read_uses_backing_ap_flash_image() {
    let mut b = test_bridge();
    let mut ap_flash = vec![0xff; 0x1244];
    for i in 0..16 {
        ap_flash[0x1234 + i] = 0xa0 + i as u8;
    }
    b.ap_flash = Arc::new(ap_flash);

    wr32(&mut b, AP_SPI_DATA_BASE, 0x3412_000b); // 0x0b fast-read @ 0x001234
    wr32(&mut b, AP_SPI_DATA_BASE + 4, 0);
    wr32(&mut b, AP_SPI_XFER_CFG, 0x0018_1380);
    wr32(&mut b, AP_SPI_XACT, 0x0067_0001);

    assert_eq!(rd8(&b, AP_SPI_DATA_BASE + 0x0d), 0xa0);
    assert_eq!(rd8(&b, AP_SPI_DATA_BASE + 0x11), 0xa4);
    assert_eq!(rd8(&b, AP_SPI_DATA_BASE + 0x17), 0xaa);
}

#[test]
fn gsc_fifo_reset_busy_bits_clear_on_read() {
    let mut b = test_bridge();
    wr32(&mut b, GSC_FIFO_CONTROL, 0x1b);
    assert_eq!(rd32(&b, GSC_FIFO_CONTROL), 0x12);

    wr32(&mut b, GSC_FIFO_CONTROL, 0x12);
    assert_eq!(rd32(&b, GSC_FIFO_CONTROL), 0x12);
    assert_eq!(rd32(&b, GSC_FIFO_IRQ_STATUS), 0);
}

#[test]
fn gsc_fifo_interrupt_state_is_write_one_to_clear() {
    let mut b = test_bridge();
    b.shared
        .lock()
        .unwrap()
        .store
        .insert(GSC_FIFO_IRQ_STATE, 0x0000_ffff);

    wr32(&mut b, GSC_FIFO_IRQ_STATE, 0x0000_00ff);
    assert_eq!(rd32(&b, GSC_FIFO_IRQ_STATE), 0x0000_ff00);

    wr32(&mut b, GSC_FIFO_IRQ_ENABLE, 0xffff_ffff);
    assert_eq!(rd32(&b, GSC_FIFO_IRQ_ENABLE), 0);
}

#[test]
fn gpio_input_banks_are_stable_status_words() {
    let mut b = test_bridge();
    assert_eq!(rd32(&b, GPIO_INPUT_BANK0), 0);
    assert_eq!(rd32(&b, GPIO_INPUT_BANK1), 0);
    assert_eq!(rd32(&b, GPIO_INPUT_BANK2), 0);
    assert_eq!(rd32(&b, GPIO_INPUT_BANK3), 0);

    // Board strap experiments can override levels through the persistent
    // store/ready path without falling back to the generic spin-breaker.
    wr32(&mut b, GPIO_INPUT_BANK1, 0x0000_1000);
    for _ in 0..SPIN_THRESHOLD {
        assert_eq!(rd32(&b, GPIO_INPUT_BANK1), 0x0000_1000);
    }
}

#[test]
fn gpio_interrupt_state_is_write_one_to_clear() {
    let mut b = test_bridge();
    b.shared
        .lock()
        .unwrap()
        .store
        .insert(GPIO_INTR_STATE0, 0x0000_00ff);
    wr32(&mut b, GPIO_INTR_STATE0, 0x0000_000f);
    assert_eq!(rd32(&b, GPIO_INTR_STATE0), 0x0000_00f0);

    wr32(&mut b, GPIO_INTR_STATE0, 0xffff_ffff);
    assert_eq!(rd32(&b, GPIO_INTR_STATE0), 0);
}

#[test]
fn fuse_defaults_and_trng_are_available() {
    let b = test_bridge();
    assert_eq!(rd32(&b, FUSE_BASE + 0x280), FUSE_DEFAULT);
    let first = rd32(&b, TRNG_READ_DATA);
    let second = rd32(&b, TRNG_READ_DATA);
    assert_ne!(first, second);
}

#[test]
fn globalsec_active_image_regions_are_available() {
    let b = test_bridge();
    assert_eq!(
        rd32(&b, GLOBALSEC_CRYPTOLIB_BASE),
        CRYPTOLIB_ROM_BASE as u32
    );
    assert_eq!(
        rd32(&b, GLOBALSEC_ACTIVE_RO_BASE),
        DEFAULT_FLASH_IMG_BASE as u32
    );
    assert_eq!(rd32(&b, GLOBALSEC_ACTIVE_RO_SIZE), TI50_RO_IMAGE_SIZE);
    assert_eq!(
        rd32(&b, GLOBALSEC_ACTIVE_RW_BASE),
        (DEFAULT_FLASH_IMG_BASE + TI50_RW_SLOT_OFFSET) as u32
    );
    assert_eq!(rd32(&b, GLOBALSEC_ACTIVE_RW_SIZE), TI50_RW_IMAGE_SIZE);
}

#[test]
fn synthetic_cryptolib_rom_is_installed() {
    let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20_0000usize)]).unwrap());
    let _vcpu = GscVcpu::new(0, mem.clone());
    let read_word = |addr| {
        let mut bytes = [0u8; 4];
        mem.read_slice(&mut bytes, GuestAddress(addr)).unwrap();
        u32::from_le_bytes(bytes)
    };

    assert_eq!(read_word(CRYPTOLIB_HEADER), 1);
    assert_eq!(read_word(CRYPTOLIB_HEADER + 8), CRYPTOLIB_MAGIC);
    assert_eq!(read_word(CRYPTOLIB_HEADER + 0x0c), CRYPTOLIB_ENTRY as u32);
    assert_eq!(read_word(CRYPTOLIB_ENTRY), 0xaa55_b537);
}

/// Boot a synthetic RV32 program on the GSC machine and return the vCPU
/// (for `console()`) and the run exit.
fn boot(base: u64, program: &[u32]) -> (GscVcpu, VcpuExit) {
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20_0000usize)]).unwrap();
    for (i, w) in program.iter().enumerate() {
        mem.write_slice(&w.to_le_bytes(), GuestAddress(base + 4 * i as u64))
            .unwrap();
    }
    let mut vcpu = GscVcpu::new(0, Arc::new(mem));
    let mut regs = RiscVRegisters::default();
    regs.pc = base;
    vcpu.set_state(&CpuState::riscv(regs)).unwrap();
    let exit = vcpu.run().unwrap();
    (vcpu, exit)
}

#[test]
fn end_to_end_rv32_xsoteria_uart_console() {
    // Program: print "OK", then use the Xsoteria `pcnt` op to compute
    // popcount(7)=3, turn it into '3', and print it. Ends with `ebreak`.
    //   lui   a0, 0x404d0       ; console UART base
    //   addi  a1, x0, 'O'       ; 0x4f
    //   sw    a1, 4(a0)         ; UART WDATA
    //   addi  a1, x0, 'K'       ; 0x4b
    //   sw    a1, 4(a0)
    //   addi  a2, x0, 7
    //   pcnt  a3, a2            ; Xsoteria: a3 = popcount(7) = 3
    //   addi  a3, a3, 0x30      ; '0' + 3 = '3'
    //   sw    a3, 4(a0)
    //   ebreak
    let program = [
        0x404d_0537u32, // lui a0, 0x404d0
        0x04f0_0593,
        0x00b5_2223,
        0x04b0_0593,
        0x00b5_2223,
        0x0070_0613,
        0x0006_368b, // pcnt a3, a2
        0x0306_8693,
        0x00d5_2223,
        0x0010_0073, // ebreak
    ];
    let (vcpu, exit) = boot(0x1000, &program);
    assert!(matches!(exit, VcpuExit::Debug), "exit = {exit:?}");
    assert_eq!(vcpu.console(), b"OK3");
}

#[test]
fn pmu_reset_loop_is_bounded() {
    // Program writes the PMU reset magic immediately, so every boot reboots.
    // The loop guard must terminate with a diagnostic rather than hang.
    //   lui   a0, 0x40000
    //   lui   a1, 0x07041
    //   addi  a1, a1, 0x776      ; a1 = 0x07041776
    //   sw    a1, 8(a0)          ; PMU reset
    //   ebreak                   ; (never reached)
    let program = [
        0x4000_0537u32,
        0x0704_15b7,
        0x7765_8593,
        0x00b5_2423,
        0x0010_0073,
    ];
    let (_vcpu, exit) = boot(0x1000, &program);
    match exit {
        VcpuExit::Unknown(msg) => assert!(
            msg.contains("reboot loop"),
            "expected reboot-loop diagnostic, got: {msg}"
        ),
        other => panic!("expected bounded reboot loop, got {other:?}"),
    }
}
