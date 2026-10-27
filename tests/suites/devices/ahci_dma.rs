//! Compile the owning AHCI controller with its existing shared bus/DMA contracts.
pub use rax::devices::{bus, virtio};
pub mod devices {
    pub use super::{bus, virtio};
}
#[path = "../../../src/devices/ahci.rs"]
pub mod ahci;

use ahci::*;
use devices::bus::MmioDevice;
use std::sync::{Arc, Mutex};
const BASE: u64 = 0x1000_0000;
const CLB: u64 = 0x1000;
const FB: u64 = 0x2000;
const CTBA: u64 = 0x3000;
const DATA: u64 = 0x8000;
const HBFS: u32 = 1 << 29;
const IFS: u32 = 1 << 27;
const OFS: u32 = 1 << 24;
const DPS: u32 = 1 << 5;
#[derive(Default)]
struct State {
    bytes: Vec<u8>,
    fault: Option<(bool, u64)>,
    partial: Option<(u64, usize)>,
    trace: Vec<(bool, u64, usize)>,
}
#[derive(Clone)]
struct Memory(Arc<Mutex<State>>);
impl Memory {
    fn new(size: usize) -> Self {
        Self(Arc::new(Mutex::new(State {
            bytes: vec![0; size],
            ..Default::default()
        })))
    }
    fn put(&self, address: u64, bytes: &[u8]) {
        self.0.lock().unwrap().bytes[address as usize..address as usize + bytes.len()]
            .copy_from_slice(bytes);
    }
    fn get(&self, address: u64, length: usize) -> Vec<u8> {
        self.0.lock().unwrap().bytes[address as usize..address as usize + length].to_vec()
    }
    fn word(&self, address: u64) -> u32 {
        u32::from_le_bytes(self.get(address, 4).try_into().unwrap())
    }
    fn fail(&self, write: bool, address: u64) {
        self.0.lock().unwrap().fault = Some((write, address));
    }
    fn clear_fault(&self) {
        self.0.lock().unwrap().fault = None;
    }
    fn trace(&self) -> Vec<(bool, u64, usize)> {
        self.0.lock().unwrap().trace.clone()
    }
    fn clear_trace(&self) {
        self.0.lock().unwrap().trace.clear();
    }
}
impl Mem for Memory {
    fn read(&self, address: u64, bytes: &mut [u8]) -> bool {
        let mut s = self.0.lock().unwrap();
        s.trace.push((false, address, bytes.len()));
        if s.fault.is_some_and(|(w, a)| {
            !w && a >= address && u128::from(a) < u128::from(address) + bytes.len() as u128
        }) {
            return false;
        }
        let Ok(start) = usize::try_from(address) else {
            return false;
        };
        let Some(end) = start.checked_add(bytes.len()) else {
            return false;
        };
        if end > s.bytes.len() {
            return false;
        }
        bytes.copy_from_slice(&s.bytes[start..end]);
        true
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> bool {
        let mut s = self.0.lock().unwrap();
        s.trace.push((true, address, bytes.len()));
        let Ok(start) = usize::try_from(address) else {
            return false;
        };
        let Some(end) = start.checked_add(bytes.len()) else {
            return false;
        };
        if end > s.bytes.len() {
            return false;
        }
        if let Some((at, length)) = s.partial {
            if at == address {
                let count = length.min(bytes.len());
                s.bytes[start..start + count].copy_from_slice(&bytes[..count]);
                return false;
            }
        }
        if s.fault.is_some_and(|(w, a)| {
            w && a >= address && u128::from(a) < u128::from(address) + bytes.len() as u128
        }) {
            return false;
        }
        s.bytes[start..end].copy_from_slice(bytes);
        true
    }
}
struct Host {
    memory: Memory,
    device: AhciController<Memory>,
}
impl Host {
    fn new() -> Self {
        Self::sizes(64, 0x80000)
    }
    fn sizes(sectors: u64, memory: usize) -> Self {
        let memory = Memory::new(memory);
        let disk = (0..sectors * 512)
            .map(|i| (i as u8).wrapping_mul(37) ^ 0xa5)
            .collect();
        let device = AhciController::new(BASE, memory.clone(), disk);
        let mut h = Self { memory, device };
        for (r, v) in [
            (REG_GHC, GHC_AE | GHC_IE),
            (PORT_BASE + PX_CLB, CLB as u32),
            (PORT_BASE + PX_FB, FB as u32),
            (PORT_BASE + PX_IE, u32::MAX),
            (PORT_BASE + PX_CMD, PXCMD_ST | PXCMD_FRE),
        ] {
            h.write(r, v);
        }
        h
    }
    fn write(&mut self, offset: u64, value: u32) {
        self.device.write(BASE + offset, &value.to_le_bytes());
    }
    fn read(&mut self, offset: u64) -> u32 {
        let mut b = [0; 4];
        self.device.read(BASE + offset, &mut b);
        u32::from_le_bytes(b)
    }
    fn command(&self, slot: u32, op: u8, lba: u64, blocks: u16, segments: &[(u64, u32, bool)]) {
        let mut header = [0; 32];
        let word = 5u32 | if op == 0x35 { 1 << 6 } else { 0 } | ((segments.len() as u32) << 16);
        header[..4].copy_from_slice(&word.to_le_bytes());
        header[8..16].copy_from_slice(&CTBA.to_le_bytes());
        self.memory.put(CLB + u64::from(slot) * 32, &header);
        let mut fis = [0; 20];
        fis[0] = 0x27;
        fis[1] = 0x80;
        fis[2] = op;
        fis[7] = 0x40;
        for (i, offset) in [4, 5, 6, 8, 9, 10].into_iter().enumerate() {
            fis[offset] = (lba >> (8 * i)) as u8;
        }
        fis[12..14].copy_from_slice(&blocks.to_le_bytes());
        self.memory.put(CTBA, &fis);
        for (i, (address, length, interrupt)) in segments.iter().enumerate() {
            let mut raw = [0; 16];
            raw[..8].copy_from_slice(&address.to_le_bytes());
            raw[12..16].copy_from_slice(
                &((length - 1) | if *interrupt { 1 << 31 } else { 0 }).to_le_bytes(),
            );
            self.memory.put(CTBA + 0x80 + i as u64 * 16, &raw);
        }
    }
    fn issue(&mut self, bits: u32) {
        self.write(PORT_BASE + PX_CI, bits);
    }
    fn restart(&mut self) {
        self.write(PORT_BASE + PX_CMD, PXCMD_FRE);
        self.write(PORT_BASE + PX_IS, u32::MAX);
        self.write(REG_IS, u32::MAX);
        self.write(PORT_BASE + PX_CMD, PXCMD_FRE | PXCMD_ST);
    }
    fn assert_host_fault(&mut self, bits: u32) {
        assert_ne!(self.read(PORT_BASE + PX_IS) & HBFS, 0);
        assert_eq!(self.read(PORT_BASE + PX_CI) & bits, bits);
        assert_eq!(self.read(PORT_BASE + PX_CMD) & PXCMD_CR, 0);
        let trace = self.memory.trace();
        self.issue(bits);
        assert_eq!(self.memory.trace(), trace, "no retry before port recovery");
    }
}
#[test]
fn late_write_source_failure_preserves_complete_media_and_retains_command() {
    let mut h = Host::new();
    let before = h.device.disk().to_vec();
    h.command(
        0,
        0x35,
        0,
        1,
        &[(DATA, 256, false), (DATA + 256, 256, false)],
    );
    h.memory.put(DATA, &[0x11; 512]);
    h.memory.fail(false, DATA + 256);
    h.issue(1);
    assert_eq!(h.device.disk(), before);
    h.assert_host_fault(1);
    assert_eq!(h.memory.word(CLB + 4), 0);
}
#[test]
fn missing_later_prd_is_not_successful_short_dma() {
    for op in [0x25, 0x35, 0xec] {
        let mut h = Host::new();
        let before = h.device.disk().to_vec();
        h.command(0, op, 0, 1, &[(DATA, 256, false), (DATA + 256, 256, false)]);
        h.memory.fail(false, CTBA + 0x90);
        h.memory.clear_trace();
        h.issue(1);
        h.assert_host_fault(1);
        assert_eq!(h.device.disk(), before);
        assert!(!h.memory.trace().iter().any(|(_, a, _)| *a == DATA));
    }
}
#[test]
fn host_header_fis_and_data_faults_do_not_fabricate_ata_errors() {
    for at in [CLB, CTBA, CTBA + 0x80, DATA] {
        let mut h = Host::new();
        h.command(0, 0x35, 0, 1, &[(DATA, 512, false)]);
        h.memory.fail(false, at);
        h.issue(1);
        h.assert_host_fault(1);
        assert_eq!(h.read(PORT_BASE + PX_TFD) & 1, 0);
        assert_eq!(h.read(PORT_BASE + PX_IS) & PXIS_TFES, 0);
    }
}
#[test]
fn prdbc_or_completion_dma_failure_never_retires_or_reexecutes_committed_write() {
    for at in [CLB + 4, FB + 0x40] {
        let mut h = Host::new();
        h.command(0, 0x35, 0, 1, &[(DATA, 512, false)]);
        h.memory.put(DATA, &[0x55; 512]);
        h.memory.fail(true, at);
        h.issue(1);
        assert_eq!(&h.device.disk()[..512], &[0x55; 512]);
        h.memory.put(DATA, &[0x99; 512]);
        h.assert_host_fault(1);
        assert_eq!(&h.device.disk()[..512], &[0x55; 512]);
        h.memory.clear_fault();
        h.restart();
        assert_eq!(h.read(PORT_BASE + PX_CI), 0);
        assert_eq!(&h.device.disk()[..512], &[0x55; 512]);
    }
}
#[test]
fn read_destination_failure_can_leave_prefix_but_cannot_publish_completion() {
    let mut h = Host::new();
    let expected = h.device.disk()[..512].to_vec();
    h.command(
        0,
        0x25,
        0,
        1,
        &[(DATA, 256, false), (DATA + 256, 256, false)],
    );
    h.memory.put(DATA, &[0xee; 512]);
    h.memory.fail(true, DATA + 256);
    h.issue(1);
    h.assert_host_fault(1);
    assert_eq!(h.memory.get(DATA, 256), expected[..256]);
    assert_eq!(h.memory.get(DATA + 256, 256), [0xee; 256]);
    assert_eq!(h.memory.word(CLB + 4), 0);
}
#[test]
fn partial_failed_dma_is_explicit_without_false_ci_clear() {
    let mut h = Host::new();
    h.command(0, 0x25, 0, 1, &[(DATA, 512, false)]);
    h.memory.0.lock().unwrap().partial = Some((DATA, 7));
    h.issue(1);
    h.assert_host_fault(1);
    assert_eq!(h.memory.get(DATA, 7), h.device.disk()[..7]);
    assert_eq!(h.memory.word(CLB + 4), 0);
}
#[test]
fn malformed_word_alignment_and_extent_overflow_fail_before_payload() {
    for (address, length) in [(DATA + 1, 512), (DATA, 511), (u64::MAX - 1, 512)] {
        let mut h = Host::new();
        h.command(0, 0x35, 0, 1, &[(address, length, false)]);
        h.memory.clear_trace();
        h.issue(1);
        h.assert_host_fault(1);
        assert!(!h.memory.trace().iter().any(|(_, a, _)| *a == address));
    }
}
#[test]
fn an_exclusive_extent_end_at_two_to_64_is_allowed_to_reach_memory_provider() {
    let mut h = Host::new();
    let address = u64::MAX - 511;
    h.command(0, 0x35, 0, 1, &[(address, 512, false)]);
    h.issue(1);
    assert!(h.memory.trace().contains(&(false, address, 512)));
    h.assert_host_fault(1);
}
#[test]
fn short_read_reports_overflow_and_actual_prdbc() {
    let mut h = Host::new();
    h.command(0, 0x25, 0, 1, &[(DATA, 256, false)]);
    h.memory.put(DATA, &[0xee; 512]);
    h.issue(1);
    assert_ne!(h.read(PORT_BASE + PX_IS) & OFS, 0);
    assert_eq!(h.memory.word(CLB + 4), 256);
    assert_eq!(h.memory.get(DATA, 256), h.device.disk()[..256]);
    assert_eq!(h.memory.get(DATA + 256, 256), [0xee; 256]);
}
#[test]
fn short_write_or_excess_write_buffer_aborts_before_media_change() {
    for length in [256, 1024] {
        let mut h = Host::new();
        let before = h.device.disk().to_vec();
        h.command(0, 0x35, 0, 1, &[(DATA, length, false)]);
        h.issue(1);
        assert_eq!(h.device.disk(), before);
        assert_ne!(h.read(PORT_BASE + PX_IS) & PXIS_TFES, 0);
        assert_eq!(h.read(PORT_BASE + PX_CI), 1);
        assert_eq!(h.read(PORT_BASE + PX_CMD) & PXCMD_CR, 0);
    }
}
#[test]
fn oversized_read_buffer_leaves_tail_and_does_not_exhaust_its_ioc() {
    let mut h = Host::new();
    h.command(0, 0x25, 0, 1, &[(DATA, 1024, true)]);
    h.memory.put(DATA, &[0xee; 1024]);
    h.issue(1);
    assert_eq!(h.memory.word(CLB + 4), 512);
    assert_eq!(h.memory.get(DATA + 512, 512), [0xee; 512]);
    assert_eq!(h.read(PORT_BASE + PX_IS) & (DPS | OFS), 0);
}
#[test]
fn exhausted_prd_ioc_sets_dps_and_only_enabled_sources_reach_irq() {
    for op in [0x25, 0x35, 0xec] {
        let mut h = Host::new();
        h.command(0, op, 0, 1, &[(DATA, 256, true), (DATA + 256, 256, false)]);
        h.write(PORT_BASE + PX_IE, DPS);
        h.issue(1);
        assert_ne!(h.read(PORT_BASE + PX_IS) & DPS, 0);
        assert!(h.device.interrupt_pending());
        assert_eq!(h.memory.word(CLB + 4), 512);
    }
}
#[test]
fn fatal_task_error_stops_later_queued_slot_and_reports_ccs() {
    let mut h = Host::new();
    h.command(0, 0xff, 0, 0, &[]);
    h.command(3, 0x25, 0, 1, &[(DATA, 512, false)]);
    h.memory.put(CTBA + 2, &[0xff]);
    h.issue(1 | 8);
    assert_eq!(h.read(PORT_BASE + PX_CI), 9);
    assert_ne!(h.read(PORT_BASE + PX_IS) & PXIS_TFES, 0);
    assert_eq!(h.read(PORT_BASE + PX_CMD) & PXCMD_CR, 0);
    assert_eq!((h.read(PORT_BASE + PX_CMD) >> 8) & 31, 0);
    assert_eq!(h.memory.word(CLB + 3 * 32 + 4), 0);
}
#[test]
fn fatal_slot_31_preserves_its_identity_until_stopping_port() {
    let mut h = Host::new();
    h.command(31, 0xff, 0, 0, &[]);
    h.issue(1 << 31);
    assert_eq!((h.read(PORT_BASE + PX_CMD) >> 8) & 31, 31);
    assert_eq!(h.read(PORT_BASE + PX_CI), 1 << 31);
    h.restart();
    assert_eq!(h.read(PORT_BASE + PX_CI), 0);
    assert_eq!((h.read(PORT_BASE + PX_CMD) >> 8) & 31, 0);
}
#[test]
fn clearing_error_status_alone_does_not_restart_fatal_engine() {
    let mut h = Host::new();
    h.command(0, 0xff, 0, 0, &[]);
    h.issue(1);
    h.write(PORT_BASE + PX_IS, u32::MAX);
    h.write(REG_IS, u32::MAX);
    h.command(0, 0x25, 0, 1, &[(DATA, 512, false)]);
    h.memory.clear_trace();
    h.issue(1);
    assert!(h.memory.trace().is_empty());
    h.restart();
    h.issue(1);
    assert_eq!(h.read(PORT_BASE + PX_CI), 0);
    assert_eq!(h.memory.word(CLB + 4), 512);
}
#[test]
fn hba_reset_preserves_media_and_clears_pending_engine_state() {
    let mut h = Host::new();
    h.command(0, 0x35, 0, 1, &[(DATA, 512, false)]);
    h.memory.put(DATA, &[0x6c; 512]);
    h.issue(1);
    h.write(REG_GHC, GHC_HR);
    assert_eq!(&h.device.disk()[..512], &[0x6c; 512]);
    assert_eq!(h.read(REG_GHC), GHC_AE);
    assert_eq!(h.read(PORT_BASE + PX_CI), 0);
    assert_eq!(h.read(PORT_BASE + PX_IS), 0);
    assert!(!h.device.interrupt_pending());
}
#[test]
fn ahci_only_mode_keeps_ae_readonly_one_before_after_reset() {
    let mut h = Host::new();
    assert_ne!(h.read(REG_CAP) & CAP_SAM, 0);
    for value in [0, GHC_IE, GHC_HR, u32::MAX] {
        h.write(REG_GHC, value);
        assert_ne!(h.read(REG_GHC) & GHC_AE, 0);
    }
}
#[test]
fn sticky_two_tier_interrupt_acknowledgement_and_late_enable_follow_virtual_wire() {
    let mut h = Host::new();
    h.write(PORT_BASE + PX_IE, 0);
    h.command(0, 0x25, 0, 1, &[(DATA, 512, false)]);
    h.issue(1);
    assert_eq!(h.read(REG_IS), 0);
    assert!(!h.device.interrupt_pending());
    h.write(PORT_BASE + PX_IE, PXIS_DHRS);
    assert_eq!(h.read(REG_IS), 1);
    assert!(h.device.interrupt_pending());
    h.device.clear_interrupt();
    assert!(h.device.interrupt_pending());
    h.write(REG_IS, 1);
    assert_eq!(h.read(REG_IS), 1);
    h.write(PORT_BASE + PX_IS, PXIS_DHRS);
    assert!(h.device.interrupt_pending());
    h.write(REG_IS, 1);
    assert!(!h.device.interrupt_pending());
}
#[test]
fn ghc_interrupt_mask_does_not_discard_port_status_or_sticky_is() {
    let mut h = Host::new();
    h.write(REG_GHC, 0);
    h.command(0, 0x25, 0, 1, &[(DATA, 512, false)]);
    h.issue(1);
    assert_eq!(h.read(REG_IS), 1);
    assert!(!h.device.interrupt_pending());
    h.write(REG_GHC, GHC_IE);
    assert!(h.device.interrupt_pending());
}
#[test]
fn base_addresses_mask_reserved_bits_and_cannot_change_while_engines_run() {
    let mut h = Host::new();
    h.write(PORT_BASE + PX_CLB, 0x4000);
    h.write(PORT_BASE + PX_FB, 0x5000);
    assert_eq!(h.read(PORT_BASE + PX_CLB), CLB as u32);
    assert_eq!(h.read(PORT_BASE + PX_FB), FB as u32);
    h.write(PORT_BASE + PX_CMD, 0);
    h.write(PORT_BASE + PX_CLB, 0x4fff);
    h.write(PORT_BASE + PX_FB, 0x5fff);
    assert_eq!(h.read(PORT_BASE + PX_CLB), 0x4c00);
    assert_eq!(h.read(PORT_BASE + PX_FB), 0x5f00);
}
#[test]
fn command_uses_only_declared_twenty_byte_fis() {
    let mut h = Host::new();
    h.command(0, 0x25, 0, 1, &[(DATA, 512, false)]);
    h.memory.fail(false, CTBA + 20);
    h.issue(1);
    assert_eq!(h.read(PORT_BASE + PX_CI), 0);
    assert_eq!(h.memory.word(CLB + 4), 512);
}
#[test]
fn malformed_command_admission_has_no_payload_dma() {
    for mode in 0..5 {
        let mut h = Host::new();
        h.command(0, 0x35, 0, 1, &[(DATA, 512, false)]);
        match mode {
            0 => h.memory.put(CLB, &[1]),
            1 => h.memory.put(CLB, &[6]),
            2 => h.memory.put(CTBA + 1, &[0]),
            3 => h.memory.put(CTBA, &[0]),
            _ => h.memory.put(CLB + 8, &0x3001u32.to_le_bytes()),
        }
        h.memory.clear_trace();
        h.issue(1);
        assert_ne!(h.read(PORT_BASE + PX_IS) & (HBFS | IFS), 0);
        assert!(!h.memory.trace().iter().any(|(_, a, _)| *a == DATA));
    }
}
#[test]
fn flush_opcodes_have_no_prdt_or_payload_dma() {
    for op in [0xe7, 0xea] {
        let mut h = Host::new();
        h.command(0, op, 0, 0, &[(u64::MAX, 1, false)]);
        h.memory.fail(false, CTBA + 0x80);
        h.memory.clear_trace();
        h.issue(1);
        assert_eq!(h.read(PORT_BASE + PX_CI), 0);
        assert_eq!(h.memory.word(CLB + 4), 0);
        assert!(!h.memory.trace().iter().any(|(_, a, _)| *a == CTBA + 0x80));
    }
}
#[test]
fn identify_uses_pio_setup_estatus_and_complete_block() {
    let mut h = Host::new();
    h.command(0, 0xec, 0, 0, &[(DATA, 512, false)]);
    h.issue(1);
    let fis = h.memory.get(FB + 0x20, 20);
    assert_eq!(&fis[..4], &[0x5f, 0x60, 0x48, 0]);
    assert_eq!(fis[15], 0x40);
    assert_eq!(&fis[16..18], &512u16.to_le_bytes());
    assert_ne!(h.read(PORT_BASE + PX_IS) & PXIS_PSS, 0);
    assert_eq!(h.read(PORT_BASE + PX_IS) & PXIS_DHRS, 0);
    assert_eq!(h.memory.word(CLB + 4), 512);
}
#[test]
fn pio_setup_dma_failure_precedes_data() {
    let mut h = Host::new();
    h.command(0, 0xec, 0, 0, &[(DATA, 512, false)]);
    h.memory.fail(true, FB + 0x20);
    h.memory.clear_trace();
    h.issue(1);
    h.assert_host_fault(1);
    assert!(!h.memory.trace().iter().any(|(_, a, _)| *a == DATA));
}
#[test]
fn comreset_retains_host_pending_bits_until_explicit_st_recovery() {
    let mut h = Host::new();
    let before = h.device.disk().to_vec();
    h.command(0, 0xff, 0, 0, &[]);
    h.issue(1);
    h.write(PORT_BASE + PX_SACT, 0x80);
    h.write(PORT_BASE + PX_SCTL, 1);
    assert_eq!(h.read(PORT_BASE + PX_CI), 1);
    assert_eq!(h.read(PORT_BASE + PX_SACT), 0x80);
    assert_eq!(h.read(PORT_BASE + PX_SSTS) & 15, 1);
    h.write(PORT_BASE + PX_SCTL, 0);
    assert_eq!(h.read(PORT_BASE + PX_SSTS) & 15, 3);
    assert_eq!(h.device.disk(), before);
    assert_eq!(h.read(PORT_BASE + PX_TFD) & 0x88, 0);
    let trace = h.memory.trace();
    h.issue(1);
    assert_eq!(h.memory.trace(), trace);
    h.restart();
    assert_eq!(h.read(PORT_BASE + PX_CI), 0);
    assert_eq!(h.read(PORT_BASE + PX_SACT), 0);
}
#[test]
fn command_posted_before_start_executes_when_port_starts() {
    let mut h = Host::new();
    h.write(PORT_BASE + PX_CMD, PXCMD_FRE);
    h.command(0, 0x35, 0, 1, &[(DATA, 512, false)]);
    h.memory.put(DATA, &[0x5a; 512]);
    h.issue(1);
    assert_eq!(h.read(PORT_BASE + PX_CI), 1);
    h.write(PORT_BASE + PX_CMD, PXCMD_ST | PXCMD_FRE);
    assert_eq!(h.read(PORT_BASE + PX_CI), 0);
    assert_eq!(&h.device.disk()[..512], &[0x5a; 512]);
}
#[test]
fn first_full_prdt_byte_limit_and_count_zero_transfer_all_thirty_two_mib() {
    let size = 32 * 1024 * 1024;
    let mut h = Host::sizes(65536, size + 0x10000);
    let segments = (0..8)
        .map(|i| (DATA + i * 4 * 1024 * 1024, 4 * 1024 * 1024, true))
        .collect::<Vec<_>>();
    h.command(0, 0x35, 0, 0, &segments);
    h.memory.put(DATA, &vec![0x6e; size]);
    h.issue(1);
    assert_eq!(h.memory.word(CLB + 4), size as u32);
    assert!(h.device.disk().iter().all(|b| *b == 0x6e));
    assert_ne!(h.read(PORT_BASE + PX_IS) & DPS, 0);
}

/// Replay the same retained byte inputs, preserving raw profile differences.
pub fn compare_reference(folder: &std::path::Path) {
    fn u32_at(b: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(b[offset..offset + 4].try_into().unwrap())
    }
    let mut cases = 0;
    let mut commands = 0;
    let mut payload = 0;
    let mut media_bytes = 0;
    let mut profile_records = 0;
    let mut identify_profile_bytes = 0;
    for index in 0..11 {
        let path = folder.join(format!("case-{index}"));
        let input = std::fs::read(path.join("input.bin")).unwrap();
        let reference = std::fs::read(path.join("records.bin")).unwrap();
        let disk = std::fs::read(path.join("initial.raw")).unwrap();
        let memory = Memory::new(0x0280_0000);
        let count = u32_at(&input, 0) as usize;
        let writes = u32_at(&input, 4) as usize;
        let outputs = u32_at(&input, 8) as usize;
        let mut product = reference[..20].to_vec();
        let mut at = 12 + 36 * count;
        for _ in 0..writes {
            let address = u32_at(&input, at);
            memory.put(u64::from(address), &input[at + 4..at + 8]);
            at += 8;
        }
        let mut h = Host {
            memory: memory.clone(),
            device: AhciController::new(BASE, memory, disk),
        };
        for (r, v) in [
            (REG_GHC, GHC_AE | GHC_IE),
            (PORT_BASE + PX_CLB, 0x0100_0000),
            (PORT_BASE + PX_FB, 0x0100_1000),
            (PORT_BASE + PX_IE, u32::MAX),
            (PORT_BASE + PX_CMD, PXCMD_FRE | PXCMD_ST),
        ] {
            h.write(r, v);
        }
        for step in 0..count {
            let p = 12 + step * 36;
            let slot = u32_at(&input, p);
            h.memory.put(0x0100_1000, &[0; 256]);
            h.write(PORT_BASE + PX_IS, u32::MAX);
            h.write(REG_IS, 1);
            h.memory
                .put(0x0100_0000 + u64::from(slot) * 32, &input[p + 4..p + 36]);
            h.issue(1 << slot);
            let actual = [
                h.read(PORT_BASE + PX_IS),
                h.read(REG_IS),
                h.read(PORT_BASE + PX_CI),
                h.read(PORT_BASE + PX_TFD),
                h.read(PORT_BASE + PX_CMD),
                h.read(PORT_BASE + PX_SSTS),
                h.memory.word(0x0100_0004 + u64::from(slot) * 32),
                h.read(PORT_BASE + PX_SERR),
            ];
            let offset = 20 + step * 288;
            let expected: Vec<u32> = (0..8).map(|i| u32_at(&reference, offset + i * 4)).collect();
            // Shared architectural result: command retirement, byte count,
            // global interrupt, ATA error/ready/busy/DRQ, and link presence.
            for field in [1, 2, 6, 7] {
                assert_eq!(
                    actual[field], expected[field],
                    "case {index} step {step} field {field}"
                );
            }
            assert_eq!(
                actual[3] & !0x10,
                expected[3] & !0x10,
                "ATA result case {index}/{step}"
            );
            assert_eq!(actual[5] & 0xf, expected[5] & 0xf);
            let reference_is = expected[0] & if index == 4 { !PXIS_DHRS } else { u32::MAX };
            assert_eq!(
                actual[0] & !DPS,
                reference_is,
                "shared PxIS case {index}/{step}"
            );
            let allowed_cmd = PXCMD_CR | (0x1f << 8);
            assert_eq!(actual[4] & !allowed_cmd, expected[4] & !allowed_cmd);
            assert_eq!(actual[5] & !0xf0, expected[5] & !0xf0);
            let fis = h.memory.get(0x0100_1000, 256);
            let rfis = &reference[offset + 32..offset + 288];
            for value in actual {
                product.extend_from_slice(&value.to_le_bytes());
            }
            product.extend_from_slice(&fis);
            if index != 4 {
                assert_eq!(&fis[64..66], &rfis[64..66]);
                assert_eq!(fis[66] & !0x10, rfis[66] & !0x10);
                assert_eq!(fis[67], rfis[67]);
                assert_eq!(
                    &fis[68..84],
                    &rfis[68..84],
                    "D2H task file case {index}/{step}"
                );
            } else {
                assert_eq!(fis[32], 0x5f);
                assert_eq!(rfis[32], 0x5f);
                assert_eq!(&fis[48..50], &rfis[48..50]);
            }
            if actual.as_slice() != expected || fis != rfis {
                profile_records += 1;
            }
            h.restart();
            commands += 1;
        }
        let mut output_at = 20 + 288 * count;
        for _ in 0..outputs {
            let address = u32_at(&input, at);
            let length = u32_at(&input, at + 4) as usize;
            at += 8;
            let got = h.memory.get(u64::from(address), length);
            let expected = &reference[output_at..output_at + length];
            if index == 4 {
                // IDENTIFY describes two intentionally different disk profiles.
                assert_eq!(u32_at(&got, 120), 64);
                assert_eq!(u32_at(expected, 120), 64);
                identify_profile_bytes += got.iter().zip(expected).filter(|(a, b)| a != b).count();
            } else {
                assert_eq!(got, expected, "payload case {index}");
                payload += length;
            }
            product.extend_from_slice(&got);
            output_at += length;
        }
        assert_eq!(at, input.len());
        assert_eq!(output_at + 8, reference.len());
        let expected = std::fs::read(path.join("disk.raw")).unwrap();
        assert_eq!(h.device.disk(), expected, "media case {index}");
        product.extend_from_slice(b"AHCIDONE");
        std::fs::write(path.join("product-records.bin"), product).unwrap();
        std::fs::write(path.join("product-disk.raw"), h.device.disk()).unwrap();
        media_bytes += expected.len();
        cases += 1;
    }
    println!(
        "{{\"cases\":{cases},\"commands\":{commands},\"shared_payload_bytes\":{payload},\"media_bytes\":{media_bytes},\"raw_profile_difference_records\":{profile_records},\"identify_profile_difference_bytes\":{identify_profile_bytes},\"failed\":0}}"
    );
}

#[test]
fn byte_status_acknowledgement_preserves_other_lanes_and_unwritten_bits() {
    let mut h = Host::new();
    h.command(0, 0x25, 0, 1, &[(DATA, 512, true)]);
    h.issue(1);
    h.command(1, 0xff, 0, 1, &[]);
    h.issue(2);
    assert_eq!(
        h.read(PORT_BASE + PX_IS) & (PXIS_DHRS | DPS | PXIS_TFES),
        PXIS_DHRS | DPS | PXIS_TFES
    );
    h.device.write(BASE + PORT_BASE + PX_IS, &[1]);
    assert_eq!(
        h.read(PORT_BASE + PX_IS) & (PXIS_DHRS | DPS | PXIS_TFES),
        DPS | PXIS_TFES
    );
    h.device.write(BASE + PORT_BASE + PX_IS + 3, &[0x40]);
    assert_eq!(h.read(PORT_BASE + PX_IS), DPS);
    h.device.write(BASE + PORT_BASE + PX_IS, &[]);
    assert_eq!(h.read(PORT_BASE + PX_IS), DPS);
}
#[test]
fn multiword_register_accesses_preserve_lanes_and_ignore_outside_aperture() {
    let mut h = Host::new();
    h.write(PORT_BASE + PX_CMD, 0);
    h.device.write(
        BASE + PORT_BASE + PX_CLB,
        &0x0000_0001_2345_6000u64.to_le_bytes(),
    );
    let mut b = [0; 8];
    h.device.read(BASE + PORT_BASE + PX_CLB, &mut b);
    assert_eq!(u64::from_le_bytes(b), 0x0000_0001_2345_6000);
    h.device.write(BASE - 1, &[0xff; 8]);
    h.device.read(BASE - 1, &mut b);
    assert_eq!(b, [0; 8]);
    h.device.write(BASE + ABAR_SIZE, &[0xff; 8]);
    h.device.read(BASE + ABAR_SIZE, &mut b);
    assert_eq!(b, [0; 8]);
    h.write(PORT_BASE + PX_SACT, 1);
    h.device.write(BASE + PORT_BASE + PX_SACT + 1, &[2]);
    assert_eq!(h.read(PORT_BASE + PX_SACT), 0x201);
}

#[test]
fn d2h_taskfile_retains_error_input_and_advances_completed_dma_lba() {
    let mut h = Host::new();
    h.command(0, 0x25, 3, 2, &[(DATA, 1024, false)]);
    h.issue(1);
    let fis = h.memory.get(FB + 0x40, 20);
    assert_eq!(fis[4], 5);
    assert_eq!(fis[7], 0x40);
    assert_eq!(&fis[12..14], &[0, 0]);
    h.command(1, 0x25, 64, 1, &[(DATA, 512, false)]);
    h.issue(2);
    let fis = h.memory.get(FB + 0x40, 20);
    assert_eq!(fis[4], 64);
    assert_eq!(&fis[12..14], &[1, 0]);
    assert_eq!(&fis[2..4], &[0x41, 4]);
}
