//! Endpoint-private state and explicit continuation; no whole-VM claim.
use rax::devices::bus::{IoDevice, MmioDevice};
use rax::devices::{ac97 as a, e1000 as e, uhci as u};
fn ew(d: &mut e::E1000, reg: u64, value: u32) {
    d.write(reg, &value.to_le_bytes());
}
fn er(d: &mut e::E1000, reg: u64) -> u32 {
    let mut b = [0; 4];
    d.read(reg, &mut b);
    u32::from_le_bytes(b)
}
fn desc(m: &mut e::VecMem, index: usize, address: u64, data: &[u8], end: bool) {
    let at = 0x100 + index * 16;
    m.bytes[at..at + 8].copy_from_slice(&address.to_le_bytes());
    m.bytes[at + 8..at + 10].copy_from_slice(&(data.len() as u16).to_le_bytes());
    m.bytes[at + 11] = 8 | u8::from(end);
    m.bytes[address as usize..address as usize + data.len()].copy_from_slice(data);
}
fn tx() -> (e::E1000, e::VecMem) {
    let mut d = e::E1000::default();
    let mut m = e::VecMem::new(0x4000);
    desc(&mut m, 0, 0x1000, b"first", true);
    desc(&mut m, 1, 0x1100, b"part", false);
    for (r, v) in [
        (e::TDBAL, 0x100),
        (e::TDLEN, 128),
        (e::TCTL, e::TCTL_EN),
        (e::IMS, e::ICR_TXDW),
    ] {
        ew(&mut d, r, v);
    }
    d.write_reg_mem(e::TDT, 2, &mut m);
    (d, m)
}
fn clock(d: &mut e::E1000, bit: bool) -> bool {
    let v = e::EECD_CS | if bit { e::EECD_DI } else { 0 };
    ew(d, e::EECD, v);
    ew(d, e::EECD, v | e::EECD_SK);
    er(d, e::EECD) & e::EECD_DO != 0
}
fn eeprom() -> e::E1000 {
    let mut d = e::E1000::new([2, 3, 4, 5, 6, 7]);
    for shift in (0..9).rev() {
        clock(&mut d, 0x180 & (1 << shift) != 0);
    }
    d
}
fn audio() -> (a::Ac97, a::VecMem) {
    let mut d = a::Ac97::new();
    let mut m = a::VecMem::new(0x3000);
    m.bytes[0x100..0x104].copy_from_slice(&0x1000u32.to_le_bytes());
    m.bytes[0x104..0x108].copy_from_slice(&0x80000004u32.to_le_bytes());
    m.bytes[0x1000..0x1008].copy_from_slice(b"samples!");
    for (i, v) in 0x100u32.to_le_bytes().into_iter().enumerate() {
        d.nabm_write_u8(a::NABM_PCM_OUT + i as u16, v);
    }
    d.nabm_write_u8(a::NABM_PCM_OUT + a::CH_LVI, 0);
    d.nabm_write_u8(a::NABM_PCM_OUT + a::CH_CR, 0x11);
    (d, m)
}
#[test]
fn all_default_endpoints_roundtrip() {
    let d = e::E1000::default();
    let c = d.checkpoint().unwrap();
    assert_eq!(c.state.len(), 751);
    let mut q = e::E1000::new([0; 6]);
    q.restore_checkpoint(c.clone()).unwrap();
    assert_eq!(q.checkpoint().unwrap(), c);
    let d = u::Uhci::new(0xc000);
    let c = d.checkpoint().unwrap();
    assert_eq!(c.state.len(), 39);
    let mut q = u::Uhci::new(0);
    q.restore_checkpoint(c.clone()).unwrap();
    assert_eq!(q.checkpoint().unwrap(), c);
    let d = a::Ac97::new();
    let c = d.checkpoint().unwrap();
    assert_eq!(c.state.len(), 316);
    let mut q = a::Ac97::new();
    q.restore_checkpoint(c.clone()).unwrap();
    assert_eq!(q.checkpoint().unwrap(), c);
}
#[test]
fn e1000_register_filter_mac_and_irq_state_survive() {
    let mut d = e::E1000::new([2, 3, 4, 5, 6, 7]);
    for (r, v) in [
        (e::RCTL, 0x1234),
        (e::TCTL, 2),
        (e::RDBAL, 0x1000),
        (e::RDBAH, 3),
        (e::RDLEN, 128),
        (e::RDH, 4),
        (e::RDT, 5),
        (e::MTA_BASE + 508, 0xdeadbeef),
        (e::IMS, e::ICR_LSC),
        (e::ICS, e::ICR_LSC),
    ] {
        ew(&mut d, r, v);
    }
    let mut q = e::E1000::default();
    q.restore_checkpoint(d.checkpoint().unwrap()).unwrap();
    assert_eq!(q.mac(), [2, 3, 4, 5, 6, 7]);
    assert!(q.interrupt_pending());
    assert_eq!(er(&mut q, e::MTA_BASE + 508), 0xdeadbeef);
    assert_eq!(er(&mut q, e::ICR), e::ICR_LSC);
    assert!(!q.interrupt_pending());
}
#[test]
fn e1000_partial_eeprom_command_continues() {
    let mut d = e::E1000::new([2, 3, 4, 5, 6, 7]);
    for shift in (5..9).rev() {
        clock(&mut d, 0x180 & (1 << shift) != 0);
    }
    let mut q = e::E1000::default();
    q.restore_checkpoint(d.checkpoint().unwrap()).unwrap();
    for shift in (0..5).rev() {
        clock(&mut q, 0x180 & (1 << shift) != 0);
    }
    let value = (0..16).fold(0u16, |v, _| (v << 1) | u16::from(clock(&mut q, false)));
    assert_eq!(value, 0x0302);
}
#[test]
fn e1000_partial_eeprom_output_continues_at_exact_bit() {
    let mut d = eeprom();
    let first = (0..5).fold(0u16, |v, _| (v << 1) | u16::from(clock(&mut d, false)));
    let mut q = e::E1000::default();
    q.restore_checkpoint(d.checkpoint().unwrap()).unwrap();
    let rest = (0..11).fold(0u16, |v, _| (v << 1) | u16::from(clock(&mut q, false)));
    assert_eq!((first << 11) | rest, 0x0302);
    assert_eq!(q.checkpoint().unwrap().state[158], 16);
}
#[test]
fn e1000_partial_frame_and_completed_queue_continue_without_replay() {
    let (d, mut m) = tx();
    let mut q = e::E1000::default();
    q.restore_checkpoint(d.checkpoint().unwrap()).unwrap();
    assert_eq!(q.tx_queue_len(), 1);
    assert!(q.interrupt_pending());
    m.bytes[0x1000..0x1005].copy_from_slice(b"xxxxx");
    desc(&mut m, 2, 0x1200, b"ial", true);
    q.write_reg_mem(e::TDT, 3, &mut m);
    assert_eq!(q.take_tx_frame().unwrap(), b"first");
    assert_eq!(q.take_tx_frame().unwrap(), b"partial");
    assert_eq!(q.take_tx_frame(), None);
    assert_eq!(m.bytes[0x100 + 2 * 16 + 12], 1);
}
#[test]
fn e1000_all_truncated_prefixes_and_trailing_input_are_atomic() {
    let (mut d, _) = tx();
    let before = d.checkpoint().unwrap();
    for end in 0..before.state.len() {
        assert!(
            d.restore_checkpoint(e::E1000Checkpoint {
                state: before.state[..end].to_vec()
            })
            .is_err()
        );
        assert_eq!(d.checkpoint().unwrap(), before);
    }
    let mut b = before.state.clone();
    b.push(0);
    assert!(
        d.restore_checkpoint(e::E1000Checkpoint { state: b })
            .is_err()
    );
    assert_eq!(d.checkpoint().unwrap(), before);
}
#[test]
fn e1000_invalid_phase_bool_frame_length_and_count_are_atomic() {
    let mut d = e::E1000::default();
    let before = d.checkpoint().unwrap();
    for (off, value) in [(154, 10), (155, 2), (158, 17), (159, 2), (160, 2)] {
        let mut b = before.state.clone();
        b[off] = value;
        assert!(
            d.restore_checkpoint(e::E1000Checkpoint { state: b })
                .is_err()
        );
        assert_eq!(d.checkpoint().unwrap(), before);
    }
    for off in [743, 747] {
        let mut b = before.state.clone();
        b[off..off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(
            d.restore_checkpoint(e::E1000Checkpoint { state: b })
                .is_err()
        );
        assert_eq!(d.checkpoint().unwrap(), before);
    }
}
#[test]
fn e1000_frame_count_limit_is_inclusive_and_lossless() {
    let mut d = e::E1000::default();
    let mut b = d.checkpoint().unwrap().state;
    b[747..751].copy_from_slice(&65536u32.to_le_bytes());
    for _ in 0..65536 {
        b.extend_from_slice(&[1, 0, 0, 0, 0xa5]);
    }
    d.restore_checkpoint(e::E1000Checkpoint { state: b.clone() })
        .unwrap();
    assert_eq!(d.tx_queue_len(), 65536);
    assert_eq!(d.checkpoint().unwrap().state, b);
    b[747..751].copy_from_slice(&65537u32.to_le_bytes());
    b.extend_from_slice(&[1, 0, 0, 0, 0xa5]);
    let before = d.checkpoint().unwrap();
    assert!(
        d.restore_checkpoint(e::E1000Checkpoint { state: b })
            .is_err()
    );
    assert_eq!(d.checkpoint().unwrap(), before);
}
#[test]
fn e1000_total_record_limit_rejects_before_decode() {
    let mut d = e::E1000::default();
    let before = d.checkpoint().unwrap();
    assert!(
        d.restore_checkpoint(e::E1000Checkpoint {
            state: vec![0; 64 * 1024 * 1024 + 1]
        })
        .is_err()
    );
    assert_eq!(d.checkpoint().unwrap(), before);
}
#[test]
fn uhci_ports_base_full_sofmod_and_running_frame_are_retained() {
    let mut d = u::Uhci::new(0xc000);
    d.attach_port_speed(0, true);
    d.attach_port(1);
    d.write(0xc00c, 0xff);
    d.write(0xc006, 0xff);
    d.write(0xc007, 7);
    d.write(0xc004, 15);
    d.write(0xc010, 4);
    d.write(0xc000, 1);
    let c = d.checkpoint().unwrap();
    let mut q = u::Uhci::new(0);
    q.restore_checkpoint(c.clone()).unwrap();
    assert_eq!(q.checkpoint().unwrap(), c);
    assert_eq!(q.base(), 0xc000);
    assert_eq!(q.read(0xc00c), 0xff);
    assert_eq!(q.frame_number(), 2047);
    let m = u::VecMem::new(0);
    q.process_frame(&m);
    assert_eq!(q.frame_number(), 0);
    assert!(q.port(0).unwrap().low_speed);
}
#[test]
fn uhci_pending_schedule_runs_only_on_explicit_frame() {
    let mut d = u::Uhci::new(0xc000);
    d.write(0xc009, 0x10);
    d.write(0xc000, 1);
    let mut q = u::Uhci::new(0);
    let before = d.checkpoint().unwrap();
    q.restore_checkpoint(before.clone()).unwrap();
    assert_eq!(q.checkpoint().unwrap(), before);
    let mut m = u::VecMem::new(0x2000);
    m.bytes[0x1000..0x1004].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(q.process_frame(&m), 0);
    assert_eq!(q.frame_number(), 1);
}
#[test]
fn uhci_all_prefixes_booleans_geometry_and_trailing_are_atomic() {
    let mut d = u::Uhci::new(0xc000);
    let before = d.checkpoint().unwrap();
    let mut bad: Vec<_> = (0..before.state.len())
        .map(|n| before.state[..n].to_vec())
        .collect();
    for off in 23..39 {
        let mut b = before.state.clone();
        b[off] = 2;
        bad.push(b);
    }
    for (off, value) in [(17, 8), (18, 1)] {
        let mut b = before.state.clone();
        b[off] = value;
        bad.push(b);
    }
    let mut b = before.state.clone();
    b.push(0);
    bad.push(b);
    for state in bad {
        assert!(d.restore_checkpoint(u::UhciCheckpoint { state }).is_err());
        assert_eq!(d.checkpoint().unwrap(), before);
    }
}
#[test]
fn ac97_all_mixer_channels_and_unmasked_lvi_are_preserved() {
    let mut d = a::Ac97::new();
    for off in (2..0x7c).step_by(2) {
        d.mixer_write(off, 0x1234 + off);
    }
    for base in [a::NABM_PCM_IN, a::NABM_PCM_OUT, a::NABM_MIC_IN] {
        d.nabm_write_u8(base + a::CH_BDBAR + 1, 0x10 + (base as u8));
        d.nabm_write_u8(base + a::CH_LVI, 0xff);
        d.nabm_write_u8(base + a::CH_CR, 0x10);
    }
    let c = d.checkpoint().unwrap();
    let mut q = a::Ac97::new();
    q.restore_checkpoint(c.clone()).unwrap();
    assert_eq!(q.checkpoint().unwrap(), c);
    for id in [
        a::ChannelId::PcmIn,
        a::ChannelId::PcmOut,
        a::ChannelId::MicIn,
    ] {
        assert_eq!(q.channel_state(id).lvi, 255);
    }
}
#[test]
fn ac97_pending_dma_runs_once_after_explicit_continuation() {
    let (d, mut m) = audio();
    let mut q = a::Ac97::new();
    q.restore_checkpoint(d.checkpoint().unwrap()).unwrap();
    assert_eq!(q.sink_bytes(), 0);
    assert!(!q.interrupt_pending());
    assert_eq!(q.run_pcm_out(&mut m), 1);
    assert_eq!(q.sink_bytes(), 8);
    assert!(q.interrupt_pending());
    let c = q.checkpoint().unwrap();
    let mut restored = a::Ac97::new();
    restored.restore_checkpoint(c.clone()).unwrap();
    assert_eq!(restored.sink_bytes(), 8);
    assert_eq!(restored.run_pcm_out(&mut m), 0);
    assert_eq!(restored.checkpoint().unwrap(), c);
}
#[test]
fn ac97_all_prefixes_indices_alignment_and_trailing_are_atomic() {
    let mut d = a::Ac97::new();
    let before = d.checkpoint().unwrap();
    let mut bad: Vec<_> = (0..before.state.len())
        .map(|n| before.state[..n].to_vec())
        .collect();
    for start in [264, 276, 288] {
        for (off, value) in [(start, 1), (start + 4, 32), (start + 10, 32)] {
            let mut b = before.state.clone();
            b[off] = value;
            bad.push(b);
        }
    }
    let mut b = before.state.clone();
    b.push(0);
    bad.push(b);
    for state in bad {
        assert!(d.restore_checkpoint(a::Ac97Checkpoint { state }).is_err());
        assert_eq!(d.checkpoint().unwrap(), before);
    }
}
#[test]
fn e1000_exact_total_byte_limit_roundtrips() {
    let mut d = e::E1000::default();
    let mut state = d.checkpoint().unwrap().state;
    let count = 4095;
    state[747..751].copy_from_slice(&(count as u32).to_le_bytes());
    let mut remaining = 64 * 1024 * 1024 - 751 - count * 4;
    for _ in 0..count {
        let length = remaining.min(16384);
        assert!(length > 0);
        state.extend_from_slice(&(length as u32).to_le_bytes());
        state.resize(state.len() + length, 0x93);
        remaining -= length;
    }
    assert_eq!(remaining, 0);
    assert_eq!(state.len(), 64 * 1024 * 1024);
    d.restore_checkpoint(e::E1000Checkpoint {
        state: state.clone(),
    })
    .unwrap();
    assert_eq!(d.checkpoint().unwrap().state, state);
}
/// Publish actual records/continuations for an independent field and RAM model.
pub fn emit_reference(directory: &std::path::Path) {
    std::fs::create_dir_all(directory).unwrap();
    for index in 0..9 {
        let case = directory.join(format!("case-{index}"));
        std::fs::create_dir_all(&case).unwrap();
        let mut event = Vec::new();
        let (before, after, ram_before, ram_after) = match index {
            0 => {
                let d = e::E1000::default();
                let c = d.checkpoint().unwrap();
                let mut q = e::E1000::new([0; 6]);
                q.restore_checkpoint(c.clone()).unwrap();
                (
                    c.state,
                    q.checkpoint().unwrap().state,
                    Vec::new(),
                    Vec::new(),
                )
            }
            1 => {
                let (d, mut m) = tx();
                let c = d.checkpoint().unwrap();
                let mut q = e::E1000::default();
                q.restore_checkpoint(c.clone()).unwrap();
                let before = m.bytes.clone();
                m.bytes[0x1000..0x1005].copy_from_slice(b"xxxxx");
                desc(&mut m, 2, 0x1200, b"ial", true);
                q.write_reg_mem(e::TDT, 3, &mut m);
                let after = q.checkpoint().unwrap();
                for _ in 0..2 {
                    let frame = q.take_tx_frame().unwrap();
                    event.extend_from_slice(&(frame.len() as u32).to_le_bytes());
                    event.extend_from_slice(&frame);
                }
                (c.state, after.state, before, m.bytes)
            }
            2 => {
                let mut d = eeprom();
                for _ in 0..5 {
                    clock(&mut d, false);
                }
                let c = d.checkpoint().unwrap();
                let mut q = e::E1000::default();
                q.restore_checkpoint(c.clone()).unwrap();
                let bits = (0..11).fold(0u16, |v, _| (v << 1) | u16::from(clock(&mut q, false)));
                event.extend_from_slice(&bits.to_le_bytes());
                (
                    c.state,
                    q.checkpoint().unwrap().state,
                    Vec::new(),
                    Vec::new(),
                )
            }
            3 => {
                let d = u::Uhci::new(0xc000);
                let c = d.checkpoint().unwrap();
                let mut q = u::Uhci::new(0);
                q.restore_checkpoint(c.clone()).unwrap();
                (
                    c.state,
                    q.checkpoint().unwrap().state,
                    Vec::new(),
                    Vec::new(),
                )
            }
            4 => {
                let mut d = u::Uhci::new(0xc000);
                d.attach_port_speed(0, true);
                d.attach_port(1);
                d.write(0xc00c, 0xff);
                d.write(0xc006, 0xff);
                d.write(0xc007, 7);
                d.write(0xc004, 15);
                d.write(0xc010, 4);
                d.write(0xc000, 1);
                let c = d.checkpoint().unwrap();
                let mut q = u::Uhci::new(0);
                q.restore_checkpoint(c.clone()).unwrap();
                q.process_frame(&u::VecMem::new(0));
                event.extend_from_slice(&q.frame_number().to_le_bytes());
                (
                    c.state,
                    q.checkpoint().unwrap().state,
                    Vec::new(),
                    Vec::new(),
                )
            }
            5 => {
                let mut d = u::Uhci::new(0xc000);
                d.write(0xc009, 0x10);
                d.write(0xc000, 1);
                let c = d.checkpoint().unwrap();
                let mut q = u::Uhci::new(0);
                q.restore_checkpoint(c.clone()).unwrap();
                let mut m = u::VecMem::new(0x2000);
                m.bytes[0x1000..0x1004].copy_from_slice(&1u32.to_le_bytes());
                let before = m.bytes.clone();
                let visits = q.process_frame(&m);
                event.extend_from_slice(&(visits as u64).to_le_bytes());
                event.extend_from_slice(&q.frame_number().to_le_bytes());
                (c.state, q.checkpoint().unwrap().state, before, m.bytes)
            }
            6 => {
                let d = a::Ac97::new();
                let c = d.checkpoint().unwrap();
                let mut q = a::Ac97::new();
                q.restore_checkpoint(c.clone()).unwrap();
                (
                    c.state,
                    q.checkpoint().unwrap().state,
                    Vec::new(),
                    Vec::new(),
                )
            }
            7 | 8 => {
                let (mut d, mut m) = audio();
                if index == 8 {
                    d.run_pcm_out(&mut m);
                }
                let c = d.checkpoint().unwrap();
                let mut q = a::Ac97::new();
                q.restore_checkpoint(c.clone()).unwrap();
                let before = m.bytes.clone();
                let processed = q.run_pcm_out(&mut m);
                event.extend_from_slice(&(processed as u64).to_le_bytes());
                event.extend_from_slice(&q.sink_bytes().to_le_bytes());
                event.push(u8::from(q.interrupt_pending()));
                (c.state, q.checkpoint().unwrap().state, before, m.bytes)
            }
            _ => unreachable!(),
        };
        for (name, bytes) in [
            ("control.bin", before),
            ("continued-control.bin", after),
            ("ram.raw", ram_before),
            ("continued-ram.raw", ram_after),
            ("event.bin", event),
        ] {
            std::fs::write(case.join(name), bytes).unwrap();
        }
    }
}
