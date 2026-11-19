use super::*;

fn priority(source: u32) -> u64 {
    BASE + u64::from(source) * 4
}

fn context(index: u64) -> u64 {
    BASE + TARGET_BASE + index * TARGET_STRIDE
}

fn enable(index: u64, word: u64) -> u64 {
    BASE + ENABLE_BASE + index * ENABLE_STRIDE + word * 4
}

fn claim(plic: &mut Plic, index: u64) -> u32 {
    let address = context(index) + 4;
    plic.probe(address, 4).unwrap();
    plic.read(address).unwrap()
}

#[test]
fn priority_and_threshold_only_mask_notification() {
    let mut plic = Plic::new(1);
    for (source, priority_value) in [(5, 2), (10, 3), (11, 3), (12, 0), (95, 7)] {
        plic.write(priority(source), priority_value).unwrap();
        plic.set_level(source, true).unwrap();
    }
    plic.write(enable(0, 0), u32::MAX).unwrap();
    plic.write(enable(0, 2), 1 << 31).unwrap();
    plic.write(context(0), u32::MAX).unwrap();
    assert_eq!(plic.read(context(0)).unwrap(), 7);
    assert_eq!(plic.hart_lines(0), (false, false));
    assert_eq!(claim(&mut plic, 0), 95);
    assert_eq!(claim(&mut plic, 0), 10);
    assert_eq!(claim(&mut plic, 0), 11);
    assert_eq!(claim(&mut plic, 0), 5);
    assert_eq!(claim(&mut plic, 0), 0);
    assert_eq!(plic.read(BASE + PENDING_BASE).unwrap(), 1 << 12);
    plic.validate(1).unwrap();
}

#[test]
fn claims_are_global_but_completion_uses_the_writing_context_enable() {
    let mut plic = Plic::new(2);
    plic.write(priority(UART_SOURCE), 1).unwrap();
    plic.write(enable(0, 0), 1 << UART_SOURCE).unwrap();
    plic.write(enable(3, 0), 1 << UART_SOURCE).unwrap();
    plic.set_level(UART_SOURCE, true).unwrap();
    assert_eq!(plic.hart_lines(0), (true, false));
    assert_eq!(plic.hart_lines(1), (false, true));
    assert_eq!(claim(&mut plic, 3), UART_SOURCE);
    assert_eq!(claim(&mut plic, 0), 0);
    assert_eq!(plic.hart_lines(0), (false, false));
    assert_eq!(plic.hart_lines(1), (false, false));

    // Disabled context cannot complete. An enabled peer can complete
    // the claimed source, even though context 3 issued the claim.
    plic.write(context(1) + 4, UART_SOURCE).unwrap();
    assert_eq!(claim(&mut plic, 0), 0);
    plic.write(context(0) + 4, UART_SOURCE).unwrap();
    assert_eq!(plic.hart_lines(1), (false, true));
    assert_eq!(claim(&mut plic, 0), UART_SOURCE);

    // A second assertion while service is in flight coalesces. When service
    // completes, the live high level re-pends exactly one request.
    plic.set_level(UART_SOURCE, false).unwrap();
    plic.set_level(UART_SOURCE, true).unwrap();
    assert_eq!(claim(&mut plic, 0), 0);
    plic.write(context(3) + 4, UART_SOURCE).unwrap();
    plic.set_level(UART_SOURCE, false).unwrap();
    // Already-latched requests survive a falling level.
    assert_eq!(claim(&mut plic, 3), UART_SOURCE);
    plic.write(context(3) + 4, UART_SOURCE).unwrap();
    assert_eq!(claim(&mut plic, 0), 0);
    plic.validate(2).unwrap();
}

#[test]
fn last_bank_and_context_and_malformed_mmio_leave_unrelated_state_intact() {
    let mut plic = Plic::new(u8::MAX);
    let last = (MAX_CONTEXTS - 1) as u64;
    plic.write(priority(0), 7).unwrap();
    plic.write(priority(95), u32::MAX).unwrap();
    plic.write(enable(last, 2), 1 << 31).unwrap();
    plic.set_level(95, true).unwrap();
    assert_eq!(plic.read(priority(0)).unwrap(), 0);
    assert_eq!(plic.read(priority(95)).unwrap(), 7);
    assert_eq!(plic.read(BASE + PENDING_BASE + 8).unwrap(), 1 << 31);
    assert_eq!(plic.hart_lines(254), (false, true));
    let before = plic.clone();
    assert_eq!(plic.probe(context(last) + 4, 2), Err(AccessError::Range));
    assert_eq!(
        plic.probe(context(last) + 5, 4),
        Err(AccessError::Alignment)
    );
    assert_eq!(plic.probe(BASE - 2, 4), Err(AccessError::Range));
    assert_eq!(plic.probe(BASE + LEN, 4), Err(AccessError::Range));
    assert!(overlaps(BASE - 1, 2));
    assert!(overlaps(BASE + LEN - 1, 2));
    assert!(!overlaps(BASE - 4, 4));
    assert!(!overlaps(BASE + LEN, 4));
    assert!(!overlaps(u64::MAX, 4));
    assert_eq!(plic.set_level(0, true), Err("invalid interrupt source"));
    assert_eq!(plic.set_level(96, true), Err("invalid interrupt source"));
    plic.write(BASE + PENDING_BASE + 8, 0).unwrap();
    plic.write(enable(last, 3), u32::MAX).unwrap();
    assert_eq!(plic.read(enable(last, 3)).unwrap(), 0);
    assert_eq!(claim(&mut plic, last + 1), 0);
    assert_eq!(plic, before);
    assert_eq!(claim(&mut plic, last), 95);
    plic.validate(255).unwrap();
}

#[test]
fn every_invalid_checkpoint_relationship_is_detected() {
    let mut plic = Plic::new(1);
    for invalid_bit in [1, 1u128 << SOURCE_COUNT] {
        plic.pending = invalid_bit;
        assert!(plic.validate(1).is_err());
    }
    plic.pending = 1 << UART_SOURCE;
    plic.claimed = plic.pending;
    assert!(plic.validate(1).is_err());
    plic.pending = 0;
    plic.validate(1).unwrap();
    plic.levels = plic.claimed;
    plic.claimed = 0;
    assert!(plic.validate(1).is_err());
    plic.levels = 0;
    for count in [0, 2, 256, usize::MAX] {
        assert!(plic.validate(count).is_err());
    }
    plic.targets[0].threshold = 8;
    assert!(plic.validate(1).is_err());
    plic.targets[0].threshold = 7;
    plic.targets[0].enable |= 1;
    assert!(plic.validate(1).is_err());
}
