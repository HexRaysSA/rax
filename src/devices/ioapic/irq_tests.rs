//! Source transitions and acceptance must preserve edge/level ownership.
use super::*;

fn program(io: &mut IoApic, pin: u8, low: u32) {
    io.write(IOAPIC_BASE, &[0x10 + 2 * pin]);
    io.write(IOAPIC_BASE + 0x10, &low.to_le_bytes());
}

#[test]
fn repeated_asserted_edge_inputs_do_not_create_duplicate_messages() {
    let mut io = IoApic::new();
    program(&mut io, 20, 0x51);
    for _ in 0..1000 {
        io.set_irq(20, true);
    }
    assert_eq!(io.pending().len(), 1);
    assert_eq!(io.take_pending().len(), 1);
    io.set_irq(20, true);
    assert!(!io.has_pending());
    io.set_irq(20, false);
    io.set_irq(20, true);
    assert_eq!(io.take_pending().len(), 1);
}

#[test]
fn accepted_level_input_sets_remote_irr_and_waits_for_eoi() {
    let mut io = IoApic::new();
    program(&mut io, 20, 0x8051);
    io.set_irq(20, true);
    assert_eq!(io.take_pending().len(), 1);
    assert_ne!(io.read_indexed(0x10 + 2 * 20) & (1 << 14), 0);
    for _ in 0..1000 {
        io.set_irq(20, true);
    }
    assert!(!io.has_pending());
}

#[test]
fn directed_eoi_reissues_an_asserted_level_but_not_a_deasserted_level() {
    let mut io = IoApic::new();
    program(&mut io, 20, 0x8051);
    io.set_irq(20, true);
    assert_eq!(io.take_pending().len(), 1);
    io.write(IOAPIC_BASE + 0x40, &0x51u32.to_le_bytes());
    assert_eq!(io.take_pending().len(), 1);
    io.set_irq(20, false);
    io.write(IOAPIC_BASE + 0x40, &0x51u32.to_le_bytes());
    assert_eq!(io.read_indexed(0x10 + 2 * 20) & (1 << 14), 0);
    assert!(!io.has_pending());
}

#[test]
fn a_masked_edge_needs_a_new_transition_after_unmasking() {
    let mut io = IoApic::new();
    io.set_irq(20, true);
    program(&mut io, 20, 0x51);
    assert!(!io.has_pending());
    io.set_irq(20, false);
    io.set_irq(20, true);
    assert_eq!(io.take_pending().len(), 1);
}

#[test]
fn masking_and_withdrawing_an_unaccepted_level_cancel_its_message() {
    let mut io = IoApic::new();
    program(&mut io, 20, 0x8051);
    io.set_irq(20, true);
    assert!(io.has_pending());
    io.set_irq(20, false);
    assert!(!io.has_pending());
    io.set_irq(20, true);
    program(&mut io, 20, 0x18051);
    assert!(!io.has_pending());
    program(&mut io, 20, 0x8051);
    assert_eq!(io.take_pending().len(), 1);
    // A mask does not acknowledge the already accepted level.
    program(&mut io, 20, 0x18051);
    assert_ne!(io.read_indexed(0x38) & (1 << 14), 0);
    io.end_of_interrupt(0x51);
    assert!(!io.has_pending());
    program(&mut io, 20, 0x8051);
    assert_eq!(io.take_pending().len(), 1);
}

#[test]
fn route_changes_refresh_an_unaccepted_message_without_creating_an_edge() {
    let mut io = IoApic::new();
    program(&mut io, 20, 0x51);
    io.set_irq(20, true);
    program(&mut io, 20, 0x61);
    io.write_indexed(0x39, 3 << 24);
    assert_eq!(io.pending().len(), 1);
    assert_eq!(
        (io.pending()[0].vector, io.pending()[0].destination),
        (0x61, 3)
    );
    io.take_pending();
    program(&mut io, 20, 0x71);
    assert!(!io.has_pending());
}

#[test]
fn source_ownership_is_transferred_only_by_the_current_complete_route() {
    let mut io = IoApic::new();
    program(&mut io, 20, 0x8051);
    io.set_irq(20, true);
    let original = io.pending_message(0).unwrap();
    assert_eq!(original.delivery_mode, 0);
    assert!(!original.logical_destination);
    io.write_indexed(0x39, 3 << 24);
    assert!(!io.accept_message(original));
    assert_eq!(io.pending().len(), 1);
    assert_eq!(io.read_indexed(0x38) & RTE_REMOTE_IRR as u32, 0);
    let current = io.pending_message(0).unwrap();
    assert_eq!(current.request.destination, 3);
    assert!(io.accept_message(current));
    assert!(!io.accept_message(current));
    assert!(io.pending().is_empty());
    assert_ne!(io.read_indexed(0x38) & RTE_REMOTE_IRR as u32, 0);
}

#[test]
fn a_matching_eoi_releases_every_in_service_pin_with_that_vector() {
    let mut io = IoApic::new();
    for pin in [18, 20, 23] {
        program(&mut io, pin, 0x8051);
        io.set_irq(pin, true);
    }
    assert_eq!(io.take_pending().len(), 3);
    io.end_of_interrupt(0x50);
    assert!(!io.has_pending());
    io.end_of_interrupt(0x51);
    assert_eq!(io.take_pending().len(), 3);
    for pin in [18, 20, 23] {
        io.set_irq(pin, false);
    }
    io.end_of_interrupt(0x51);
    assert!(!io.has_pending());
}

#[test]
fn controller_outputs_match_independent_kvm_guest_unmask_and_eoi_frontiers() {
    let reference: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/hvf/ioapic-transitions-v1/records.json"
    ))
    .unwrap();
    assert_eq!(reference["version"], 1);
    let records = reference["observations"].as_array().unwrap();
    assert_eq!(records.len(), 18);
    for level in [false, true] {
        let mut io = IoApic::new();
        program(&mut io, 20, 0x10051 | (u32::from(level) << 15));
        // This consumer latch represents only whether an output message was
        // accepted; the independent native records supply the expected state.
        // Actual VMM/LAPIC/guest-handler routing has its separate tests.
        let mut consumer_pending = false;
        let mut checked = 0;
        for record in records
            .iter()
            .filter(|record| record["level"] == u32::from(level))
        {
            let phase = record["phase"].as_str().unwrap();
            match phase {
                "initial" => (),
                "masked_assert" | "repeat_assert" | "new_assert" => io.set_irq(20, true),
                "native_unmask" => program(&mut io, 20, 0x51 | (u32::from(level) << 15)),
                "assert" => {
                    io.set_irq(20, false);
                    io.set_irq(20, true);
                }
                "deassert" => io.set_irq(20, false),
                "eoi_asserted" | "eoi_deasserted" => {
                    consumer_pending = false;
                    io.write(IOAPIC_BASE + EOI, &0x51u32.to_le_bytes());
                }
                _ => panic!("unknown native frontier {phase}"),
            }
            let messages = io.take_pending();
            if !messages.is_empty() {
                assert_eq!(messages.len(), 1);
                assert_eq!(messages[0].vector, 0x51);
                consumer_pending = true;
            }
            assert_eq!(
                u32::from(consumer_pending),
                record["pending"],
                "level={level},phase={phase}"
            );
            let remote_irr = io.read_indexed(0x38) & RTE_REMOTE_IRR as u32 != 0;
            assert_eq!(
                u32::from(remote_irr),
                record["remote_irr"],
                "level={level},phase={phase}"
            );
            checked += 1;
        }
        assert_eq!(checked, 9);
    }
}
