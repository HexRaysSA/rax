//! Existing platform and DMA-bound tests, retaining original module/test names.
use super::*;

#[test]
fn platform_wfi_retires_arm_thumb_it_and_resumes_without_pc_repair() {
    for thumb in [false, true] {
        for condition_passes in [false, true] {
            let memory = Arc::new(
                GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(IBOOT_BASE as u64), 0x4000)])
                    .unwrap(),
            );
            let code = IBOOT_BASE + 0x100;
            let bytes = if thumb {
                [0xbf30u16, 0x202a, 0xbf30]
                    .into_iter()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>()
            } else {
                [0x0320_f003u32, 0xe3a0_002a, 0xe320_f003]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect::<Vec<_>>()
            };
            memory
                .write_slice(&bytes, GuestAddress(u64::from(code)))
                .unwrap();
            let mut cpu = S5L8900Vcpu::new(0, memory);
            cpu.cpu.regs[15] = code;
            cpu.cpu.cpsr.t = thumb;
            cpu.cpu.cpsr.z = condition_passes;
            if thumb {
                cpu.cpu.cpsr.set_it_state(0, 8);
            }
            let first = cpu.step();
            if condition_passes {
                assert!(matches!(first, StepOutcome::Idle));
                assert!(cpu.cpu.is_halted);
                cpu.wake();
                assert!(!cpu.cpu.is_halted);
            } else {
                assert!(matches!(first, StepOutcome::Progress));
                assert!(!cpu.cpu.is_halted);
            }
            let width = if thumb { 2 } else { 4 };
            assert_eq!(cpu.cpu.regs[15], code + width);
            assert!(!cpu.cpu.cpsr.in_it_block());
            assert!(matches!(cpu.step(), StepOutcome::Progress));
            assert_eq!(cpu.cpu.regs[0], 42);
            assert!(matches!(cpu.step(), StepOutcome::Idle));
            assert_eq!(cpu.cpu.regs[15], code + 3 * width);
            assert_eq!(cpu.insn_count, 3);
        }
    }
}

/// 16 KiB of guest RAM at physical 0.
fn small_vcpu() -> (S5L8900Vcpu, Arc<GuestMemoryMmap>) {
    let mem = Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    let vcpu = S5L8900Vcpu::new(0, mem.clone());
    (vcpu, mem)
}

fn unique_temp_path(name: &str) -> std::path::PathBuf {
    let now = crate::host::time::system_now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("rax-{name}-{}-{now}", std::process::id()))
}

#[test]
fn timer_speedup_defaults_to_reference_pace() {
    assert_eq!(parse_timer_speedup(None), 1);
    assert_eq!(parse_timer_speedup(Some("")), 1);
    assert_eq!(parse_timer_speedup(Some("invalid")), 1);
    assert_eq!(parse_timer_speedup(Some("0")), 1);
}

#[test]
fn timer_speedup_allows_explicit_diagnostic_override() {
    assert_eq!(parse_timer_speedup(Some("256")), 256);
}

#[test]
fn deterministic_timer_is_the_default() {
    assert_eq!(parse_det_timer(None), 32);
    assert_eq!(parse_det_timer(Some("invalid")), 32);
    assert_eq!(parse_det_timer(Some("128")), 128);
    assert_eq!(parse_det_timer(Some("0")), 0);
}

#[test]
fn dmadump_append_respects_cumulative_file_limit() {
    let path = unique_temp_path("s5l-dmadump-limit");
    let _ = std::fs::remove_file(&path);

    append_limited_dmadump(&path, b"hdr\n", b"abcdef", 8).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"hdr\nabcd");

    append_limited_dmadump(&path, b"next\n", b"zzzz", 8).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"hdr\nabcd");

    let _ = std::fs::remove_file(&path);
}

// issues #43 / #50: guest-controlled DMA sizes must be validated against
// guest RAM before any `vec![0u8; len]`, so a malicious size cannot drive a
// multi-GB host allocation.
#[test]
fn dma_range_in_bounds_rejects_oversized_sizes() {
    // 16 KiB of guest RAM at address zero.
    let (mem_start, mem_end) = (0, 0x4000);

    // Valid ranges within RAM are accepted (the bound must not over-reject).
    assert!(dma_range_in_bounds(mem_start, mem_end, 0, 0x1000));
    assert!(dma_range_in_bounds(mem_start, mem_end, 0x3000, 0x1000)); // exactly fills RAM
    assert!(dma_range_in_bounds(mem_start, mem_end, 0, 0)); // empty

    // Out-of-range / oversized requests are rejected (no allocation).
    assert!(!dma_range_in_bounds(mem_start, mem_end, 0x3001, 0x1000)); // one byte over
    assert!(!dma_range_in_bounds(mem_start, mem_end, 0, 0x8000_0000)); // ~2 GiB (issue #43)
    assert!(!dma_range_in_bounds(mem_start, mem_end, 0, 0xFFFF_FFF0)); // ~4 GiB (issue #50)
    assert!(!dma_range_in_bounds(mem_start, mem_end, u32::MAX, 16)); // base near top, no wrap
}

#[test]
fn dma_bound_uses_s5l_ram_base_and_excludes_padding() {
    let reported = 0x0800_0000u64; // 128 MiB
    let padded_end = reported + crate::vm::memory::GUEST_MEMORY_PADDING;
    let (mem_start, mem_end) = dma_ram_bounds_from_mmap_end(padded_end);

    assert_eq!((mem_start, mem_end), (0x0800_0000, 0x1000_0000));
    // iBoot's real kernelcache buffer must fit in 128 MiB S5L DRAM. This
    // regresses the address-zero bound that incorrectly rejected 0x0b000000.
    assert!(dma_range_in_bounds(
        mem_start,
        mem_end,
        0x0b00_0800,
        3_319_392,
    ));
    assert!(!dma_range_in_bounds(mem_start, mem_end, 0, 0x1000)); // below S5L DRAM
    assert!(!dma_range_in_bounds(
        mem_start,
        mem_end,
        0x0fff_f000,
        0x2000,
    )); // one page over
    assert!(!dma_range_in_bounds(
        mem_start,
        mem_end,
        S5L_RAM_BASE as u32,
        0xFFFF_FFF0,
    )); // ~4 GiB
    assert_eq!(dma_ram_bounds_from_mmap_end(0x4000), (0, 0x4000));
}

// issue #50: a crafted 8900 header advertising a huge data_len must be
// skipped (no multi-GB allocation, no decryption) rather than aborting.
#[test]
fn engine_8900_oversized_data_len_is_skipped() {
    let (mut vcpu, mem) = small_vcpu();
    let mut header = [0u8; S5L_8900_HEADER_LEN];
    header[..4].copy_from_slice(b"8900");
    header[7] = 0x03; // "encrypted" marker the engine requires
    header[12..16].copy_from_slice(&0x1000_0000u32.to_le_bytes()); // 256 MiB >> 16 KiB
    mem.write_slice(&header, GuestAddress(0)).unwrap();

    vcpu.decrypt_8900(0); // must return cleanly without a giant allocation

    // Nothing should have been decrypted into the (in-range) body slot.
    let mut probe = [0u8; 16];
    mem.read_slice(&mut probe, GuestAddress(S5L_8900_HEADER_LEN as u64))
        .unwrap();
    assert_eq!(
        probe, [0u8; 16],
        "an oversized 8900 request must not write a decrypted body",
    );
}

// issue #43: a huge AES insize must be rejected before allocation.
#[test]
fn aes_oversized_insize_is_skipped() {
    let (mut vcpu, _mem) = small_vcpu();
    {
        let mut inner = vcpu.bridge.inner.borrow_mut();
        inner.aes.keytype = AesKeyType::Custom; // 32-byte default key (AES-256)
        inner.aes.inaddr = 0;
        inner.aes.outaddr = 0;
        inner.aes.insize = 0x1000_0000; // 256 MiB, multiple of 16, >> 16 KiB
        inner.aes.pending_go = true;
    }
    vcpu.service_aes(); // must return cleanly without a giant allocation
    assert!(
        !vcpu.bridge.inner.borrow().aes.pending_go,
        "service_aes should consume the GO request",
    );
}

#[test]
fn adm_irq_propagates_to_daisy_synchronously() {
    let (vcpu, _mem) = small_vcpu();
    let mut inner = vcpu.bridge.inner.borrow_mut();
    let adm_mask = 1 << ADM_VIC1_LINE;
    let adm_vector = 0x8000_0025;

    inner.vic0.set_priority_mode(true);
    inner.vic1.set_priority_mode(true);
    inner.vic1.write(0x100 + ADM_VIC1_LINE * 4, adm_vector);
    inner.vic1.write(0x10, adm_mask);

    // QEMU propagates qemu_irq_raise() through both PL192s before the ADM
    // control-register write returns. No sync_irqs() call may be required.
    inner.set_adm_irq(true);
    assert!(inner.adm_irq);
    assert_eq!(inner.vic1.rawintr & adm_mask, adm_mask);
    assert_eq!(inner.vic1.irq_status & adm_mask, adm_mask);
    assert!(inner.vic0.daisy_input);
    assert_eq!(inner.vic0.debug_priority_state().1, 32);
    assert_eq!(inner.vic0.address, adm_vector);
    assert!(inner.vic0.irq_asserted());

    inner.set_adm_irq(false);
    assert!(!inner.adm_irq);
    assert_eq!(inner.vic1.rawintr & adm_mask, 0);
    assert_eq!(inner.vic1.irq_status & adm_mask, 0);
    assert!(!inner.vic0.daisy_input);
    assert!(!inner.vic0.irq_asserted());
}
