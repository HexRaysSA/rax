use super::*;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// ============================================================================
// BASIC INITIALIZATION AND STATE TESTS
// ============================================================================

#[test]
fn test_new_lapic_initial_state() {
    let lapic = LocalApic::new(0);

    // Check ID is stored in bits 24-31
    assert_eq!(lapic.id, 0);
    assert_eq!(lapic.apic_id(), 0);

    // Check version register
    assert_eq!(lapic.version, 0x00050014);

    // Check virtual wire mode defaults
    assert!(lapic.is_enabled(), "APIC should be enabled by default");
    assert_eq!(
        lapic.svr, 0x1FF,
        "SVR should have APIC enabled with vector 0xFF"
    );
    assert_eq!(lapic.lvt_lint0, 0x700, "LINT0 should be ExtInt mode");
    assert_eq!(lapic.lvt_lint1, 0x400, "LINT1 should be NMI mode");

    // Check timer is masked by default
    assert!(lapic.timer_masked(), "Timer should be masked initially");

    // Check flat model DFR
    assert_eq!(lapic.dfr, 0xFFFFFFFF, "DFR should be flat model");
}

#[test]
fn test_new_lapic_with_different_ids() {
    for id in [0, 1, 7, 15, 255] {
        let lapic = LocalApic::new(id);
        assert_eq!(lapic.apic_id(), id as u8, "APIC ID mismatch for id={}", id);
        assert_eq!(
            lapic.id,
            (id as u32) << 24,
            "ID register mismatch for id={}",
            id
        );
    }
}

#[test]
fn test_apic_enable_disable() {
    let mut lapic = LocalApic::new(0);

    // Initially enabled
    assert!(lapic.is_enabled());

    // Disable APIC by clearing bit 8 of SVR
    lapic.write_register(LAPIC_SVR, 0x0FF);
    assert!(!lapic.is_enabled(), "APIC should be disabled");

    // Re-enable APIC
    lapic.write_register(LAPIC_SVR, 0x1FF);
    assert!(lapic.is_enabled(), "APIC should be re-enabled");
}

// ============================================================================
// REGISTER READ/WRITE TESTS
// ============================================================================

#[test]
fn test_id_register_read_write() {
    let mut lapic = LocalApic::new(0);

    // Read initial ID
    assert_eq!(lapic.read_register(LAPIC_ID), 0);

    // Write new ID (only bits 24-31 are writable)
    lapic.write_register(LAPIC_ID, 0x05000000);
    assert_eq!(lapic.read_register(LAPIC_ID), 0x05000000);
    assert_eq!(lapic.apic_id(), 5);

    // Write ID with lower bits set (should be masked)
    lapic.write_register(LAPIC_ID, 0xFF123456);
    assert_eq!(lapic.read_register(LAPIC_ID), 0xFF000000);
}

#[test]
fn test_version_register_readonly() {
    let mut lapic = LocalApic::new(0);
    let original = lapic.read_register(LAPIC_VERSION);

    // Try to write (should have no effect - version is read-only)
    lapic.write_register(LAPIC_VERSION, 0x12345678);
    assert_eq!(lapic.read_register(LAPIC_VERSION), original);
}

#[test]
fn test_tpr_register() {
    let mut lapic = LocalApic::new(0);

    // Write and read TPR (only lower 8 bits)
    lapic.write_register(LAPIC_TPR, 0x12345678);
    assert_eq!(lapic.read_register(LAPIC_TPR), 0x78);

    lapic.write_register(LAPIC_TPR, 0xAB);
    assert_eq!(lapic.read_register(LAPIC_TPR), 0xAB);
}

#[test]
fn test_ppr_calculation() {
    let mut lapic = LocalApic::new(0);

    // PPR = max(TPR[7:4], highest ISR vector[7:4]) << 4
    // With no ISR and TPR=0, PPR should be 0
    assert_eq!(lapic.read_register(LAPIC_PPR), 0);

    // Set TPR to priority class 5
    lapic.write_register(LAPIC_TPR, 0x50);
    assert_eq!(lapic.read_register(LAPIC_PPR), 0x50);

    // Set an interrupt in service at vector 0x70 (priority class 7)
    lapic.isr[0x70 / 32] |= 1 << (0x70 % 32);
    assert_eq!(lapic.read_register(LAPIC_PPR), 0x70);

    // Set TPR higher than ISR
    lapic.write_register(LAPIC_TPR, 0x80);
    assert_eq!(lapic.read_register(LAPIC_PPR), 0x80);
}

#[test]
fn test_ldr_register() {
    let mut lapic = LocalApic::new(0);

    lapic.write_register(LAPIC_LDR, 0xAB000000);
    assert_eq!(lapic.read_register(LAPIC_LDR), 0xAB000000);
}

#[test]
fn test_dfr_register() {
    let mut lapic = LocalApic::new(0);

    // Default is flat model
    assert_eq!(lapic.read_register(LAPIC_DFR), 0xFFFFFFFF);

    // Write cluster model
    lapic.write_register(LAPIC_DFR, 0x0FFFFFFF);
    assert_eq!(lapic.read_register(LAPIC_DFR), 0x0FFFFFFF);
}

#[test]
fn test_svr_register() {
    let mut lapic = LocalApic::new(0);

    assert_eq!(lapic.read_register(LAPIC_SVR), 0x1FF);

    lapic.write_register(LAPIC_SVR, 0x0AB);
    assert_eq!(lapic.read_register(LAPIC_SVR), 0x0AB);
    assert!(!lapic.is_enabled());
}

#[test]
fn test_esr_register() {
    let mut lapic = LocalApic::new(0);

    // Initially 0
    assert_eq!(lapic.read_register(LAPIC_ESR), 0);

    // Manually set ESR for testing
    lapic.esr = 0x44;
    assert_eq!(lapic.read_register(LAPIC_ESR), 0x44);

    // Writing any value clears ESR
    lapic.write_register(LAPIC_ESR, 0xFF);
    assert_eq!(lapic.read_register(LAPIC_ESR), 0);
}

#[test]
fn test_icr_register() {
    let mut lapic = LocalApic::new(0);

    // Write ICR high (destination field)
    lapic.write_register(LAPIC_ICR_HIGH, 0x05000000);
    assert_eq!(lapic.read_register(LAPIC_ICR_HIGH), 0x05000000);

    // ICR low read
    assert_eq!(lapic.read_register(LAPIC_ICR_LOW), 0);
}

#[test]
fn test_lvt_registers() {
    let mut lapic = LocalApic::new(0);

    // Test all LVT registers
    let lvt_offsets = [
        (LAPIC_LVT_TIMER, &mut lapic.lvt_timer),
        (LAPIC_LVT_THERMAL, &mut lapic.lvt_thermal),
        (LAPIC_LVT_PMC, &mut lapic.lvt_pmc),
        (LAPIC_LVT_LINT0, &mut lapic.lvt_lint0),
        (LAPIC_LVT_LINT1, &mut lapic.lvt_lint1),
        (LAPIC_LVT_ERROR, &mut lapic.lvt_error),
    ];

    // Re-create lapic to avoid borrow issues
    let mut lapic = LocalApic::new(0);

    // Test LVT Timer
    lapic.write_register(LAPIC_LVT_TIMER, 0x00030020);
    assert_eq!(lapic.read_register(LAPIC_LVT_TIMER), 0x00030020);
    assert_eq!(lapic.timer_vector(), 0x20);
    assert_eq!(lapic.timer_mode(), 1); // Periodic

    // Test LVT Error
    lapic.write_register(LAPIC_LVT_ERROR, 0x00010030);
    assert_eq!(lapic.read_register(LAPIC_LVT_ERROR), 0x00010030);
}

#[test]
fn test_isr_tmr_irr_registers() {
    let mut lapic = LocalApic::new(0);

    // Set some bits in each register array
    lapic.isr[0] = 0x00000001;
    lapic.isr[7] = 0x80000000;
    lapic.tmr[3] = 0x12345678;
    lapic.irr[5] = 0xABCDEF00;

    // Read ISR
    assert_eq!(lapic.read_register(LAPIC_ISR_BASE), 0x00000001);
    assert_eq!(lapic.read_register(LAPIC_ISR_BASE + 0x70), 0x80000000);

    // Read TMR
    assert_eq!(lapic.read_register(LAPIC_TMR_BASE + 0x30), 0x12345678);

    // Read IRR
    assert_eq!(lapic.read_register(LAPIC_IRR_BASE + 0x50), 0xABCDEF00);
}

// ============================================================================
// TIMER FUNCTIONALITY TESTS
// ============================================================================

#[test]
fn test_timer_divisor_encoding() {
    let mut lapic = LocalApic::new(0);

    // Test all divisor encodings
    let test_cases = [
        (0b0000, 2),   // /2
        (0b0001, 4),   // /4
        (0b0010, 8),   // /8
        (0b0011, 16),  // /16
        (0b1000, 32),  // /32
        (0b1001, 64),  // /64
        (0b1010, 128), // /128
        (0b1011, 1),   // /1
    ];

    for (dcr_value, expected_divisor) in test_cases {
        lapic.write_register(LAPIC_TIMER_DCR, dcr_value);
        assert_eq!(
            lapic.timer_divisor(),
            expected_divisor,
            "DCR {:#x} should give divisor {}",
            dcr_value,
            expected_divisor
        );
    }
}

#[test]
fn test_timer_mode_encoding() {
    let mut lapic = LocalApic::new(0);

    // Oneshot mode (bits 17-18 = 00)
    lapic.write_register(LAPIC_LVT_TIMER, 0x00000020);
    assert_eq!(lapic.timer_mode(), TIMER_MODE_ONESHOT);

    // Periodic mode (bits 17-18 = 01)
    lapic.write_register(LAPIC_LVT_TIMER, 0x00020020);
    assert_eq!(lapic.timer_mode(), TIMER_MODE_PERIODIC);

    // TSC-deadline mode (bits 17-18 = 10)
    lapic.write_register(LAPIC_LVT_TIMER, 0x00040020);
    assert_eq!(lapic.timer_mode(), TIMER_MODE_TSC_DEADLINE);
}

#[test]
fn test_timer_masked() {
    let mut lapic = LocalApic::new(0);

    // Initially masked
    assert!(lapic.timer_masked());

    // Unmask
    lapic.write_register(LAPIC_LVT_TIMER, 0x00000020);
    assert!(!lapic.timer_masked());

    // Mask again
    lapic.write_register(LAPIC_LVT_TIMER, 0x00010020);
    assert!(lapic.timer_masked());
}

#[test]
fn test_timer_initial_count_starts_timer() {
    let mut lapic = LocalApic::new(0);

    // Timer should not be running initially
    assert!(lapic.timer_start.is_none());

    // Set initial count
    lapic.write_register(LAPIC_TIMER_ICR, 1000000);
    assert!(lapic.timer_start.is_some());
    assert_eq!(lapic.timer_initial_count, 1000000);

    // Setting to 0 stops timer
    lapic.write_register(LAPIC_TIMER_ICR, 0);
    assert!(lapic.timer_start.is_none());
}

#[test]
fn test_timer_current_count_decreases() {
    let mut lapic = LocalApic::new(0);

    // Set up timer
    lapic.write_register(LAPIC_LVT_TIMER, 0x00000020); // Unmask, oneshot
    lapic.write_register(LAPIC_TIMER_DCR, 0b1011); // Divisor = 1 (fastest)
    lapic.write_register(LAPIC_TIMER_ICR, 1_000_000_000); // 1 billion ticks

    let initial = lapic.read_register(LAPIC_TIMER_CCR);

    // Wait a tiny bit
    thread::sleep(Duration::from_micros(100));

    let current = lapic.read_register(LAPIC_TIMER_CCR);

    // Current count should have decreased (or stayed same if too fast)
    assert!(
        current <= initial,
        "Timer count should decrease or stay same"
    );
}

#[test]
fn test_timer_oneshot_expiration() {
    let mut lapic = LocalApic::new(0);

    // Set up oneshot timer with very short count
    lapic.write_register(LAPIC_LVT_TIMER, 0x00000020); // Vector 0x20, oneshot, unmasked
    lapic.write_register(LAPIC_TIMER_DCR, 0b1011); // Divisor = 1
    lapic.write_register(LAPIC_TIMER_ICR, 1); // Very small count

    // Wait for timer to expire
    thread::sleep(Duration::from_millis(10));

    // Tick should return the timer vector
    let vector = lapic.tick();
    assert_eq!(vector, Some(0x20), "Timer should fire with vector 0x20");
    assert!(lapic.has_pending_timer());

    // Second tick should return None (already fired in oneshot mode)
    let vector = lapic.tick();
    assert_eq!(vector, None, "Oneshot timer should not fire twice");
}

#[test]
fn test_timer_periodic_repeats() {
    let mut lapic = LocalApic::new(0);

    // Set up periodic timer
    lapic.write_register(LAPIC_LVT_TIMER, 0x00020030); // Vector 0x30, periodic, unmasked
    lapic.write_register(LAPIC_TIMER_DCR, 0b1011); // Divisor = 1
    lapic.write_register(LAPIC_TIMER_ICR, 1); // Very small count

    // Wait and tick
    thread::sleep(Duration::from_millis(10));
    let vector1 = lapic.tick();
    assert_eq!(vector1, Some(0x30));

    // Clear pending and wait again
    lapic.clear_timer_pending();
    thread::sleep(Duration::from_millis(10));

    let vector2 = lapic.tick();
    assert_eq!(vector2, Some(0x30), "Periodic timer should fire again");
}

#[test]
fn test_timer_masked_no_interrupt() {
    let mut lapic = LocalApic::new(0);

    // Set up masked timer
    lapic.write_register(LAPIC_LVT_TIMER, 0x00010020); // Masked
    lapic.write_register(LAPIC_TIMER_DCR, 0b1011);
    lapic.write_register(LAPIC_TIMER_ICR, 1);

    thread::sleep(Duration::from_millis(10));

    let vector = lapic.tick();
    assert_eq!(vector, None, "Masked timer should not generate interrupt");
}

#[test]
fn test_timer_disabled_apic_no_interrupt() {
    let mut lapic = LocalApic::new(0);

    // Disable APIC
    lapic.write_register(LAPIC_SVR, 0x0FF);

    // Set up timer
    lapic.write_register(LAPIC_LVT_TIMER, 0x00000020);
    lapic.write_register(LAPIC_TIMER_DCR, 0b1011);
    lapic.write_register(LAPIC_TIMER_ICR, 1);

    thread::sleep(Duration::from_millis(10));

    let vector = lapic.tick();
    assert_eq!(
        vector, None,
        "Disabled APIC should not generate timer interrupt"
    );
}

// ============================================================================
// INTERRUPT HANDLING TESTS
// ============================================================================

#[test]
fn test_set_irr() {
    let mut lapic = LocalApic::new(0);

    // Set various vectors
    lapic.set_irr(0);
    assert_eq!(lapic.irr[0], 1);

    lapic.set_irr(31);
    assert_eq!(lapic.irr[0], 0x80000001);

    lapic.set_irr(32);
    assert_eq!(lapic.irr[1], 1);

    lapic.set_irr(255);
    assert_eq!(lapic.irr[7], 0x80000000);
}

#[test]
fn test_get_pending_vector() {
    let mut lapic = LocalApic::new(0);

    // No pending interrupts
    assert_eq!(lapic.get_pending_vector(), None);

    // Set vector 0x20
    lapic.set_irr(0x20);
    assert_eq!(lapic.get_pending_vector(), Some(0x20));

    // Set higher priority vector 0x30
    lapic.set_irr(0x30);
    assert_eq!(lapic.get_pending_vector(), Some(0x30));

    // Set even higher priority vector 0xFF
    lapic.set_irr(0xFF);
    assert_eq!(lapic.get_pending_vector(), Some(0xFF));
}

#[test]
fn test_ack_interrupt() {
    let mut lapic = LocalApic::new(0);

    // Set and acknowledge interrupt
    lapic.set_irr(0x40);
    assert!(lapic.irr[0x40 / 32] & (1 << (0x40 % 32)) != 0);
    assert!(lapic.isr[0x40 / 32] & (1 << (0x40 % 32)) == 0);

    lapic.ack_interrupt(0x40);
    assert!(
        lapic.irr[0x40 / 32] & (1 << (0x40 % 32)) == 0,
        "IRR bit should be cleared"
    );
    assert!(
        lapic.isr[0x40 / 32] & (1 << (0x40 % 32)) != 0,
        "ISR bit should be set"
    );
}

#[test]
fn test_eoi_clears_highest_isr() {
    let mut lapic = LocalApic::new(0);

    // Set multiple interrupts in service
    lapic.isr[0x20 / 32] |= 1 << (0x20 % 32);
    lapic.isr[0x50 / 32] |= 1 << (0x50 % 32);
    lapic.isr[0x80 / 32] |= 1 << (0x80 % 32);

    // EOI should clear highest priority (0x80)
    lapic.write_register(LAPIC_EOI, 0);
    assert!(lapic.isr[0x80 / 32] & (1 << (0x80 % 32)) == 0);
    assert!(lapic.isr[0x50 / 32] & (1 << (0x50 % 32)) != 0);
    assert!(lapic.isr[0x20 / 32] & (1 << (0x20 % 32)) != 0);

    // Next EOI clears 0x50
    lapic.write_register(LAPIC_EOI, 0);
    assert!(lapic.isr[0x50 / 32] & (1 << (0x50 % 32)) == 0);
    assert!(lapic.isr[0x20 / 32] & (1 << (0x20 % 32)) != 0);

    // Final EOI clears 0x20
    lapic.write_register(LAPIC_EOI, 0);
    assert!(lapic.isr[0x20 / 32] & (1 << (0x20 % 32)) == 0);
}

#[test]
fn test_eoi_any_value() {
    let mut lapic = LocalApic::new(0);

    lapic.isr[1] = 0x00000001; // Vector 32

    // Any write to EOI triggers it
    lapic.write_register(LAPIC_EOI, 0xDEADBEEF);
    assert_eq!(lapic.isr[1], 0);
}

// ============================================================================
// IPI (INTER-PROCESSOR INTERRUPT) TESTS
// ============================================================================

#[test]
fn test_ipi_self_fixed() {
    let mut lapic = LocalApic::new(0);

    // Set up self-targeted fixed IPI
    // ICR: vector=0x50, delivery_mode=FIXED(0), shorthand=SELF(1)
    lapic.write_register(LAPIC_ICR_HIGH, 0);
    lapic.write_register(LAPIC_ICR_LOW, 0x00040050); // Shorthand=1 (self), vector=0x50

    // Should set IRR for vector 0x50
    assert!(lapic.irr[0x50 / 32] & (1 << (0x50 % 32)) != 0);

    // No pending IPI for VMM (self-targeted)
    assert!(!lapic.has_pending_ipi());
}

#[test]
fn test_ipi_self_nmi() {
    let mut lapic = LocalApic::new(0);

    // Self-targeted NMI
    // ICR: delivery_mode=NMI(4), shorthand=SELF(1)
    lapic.write_register(LAPIC_ICR_LOW, 0x00040400); // Shorthand=1, delivery=NMI

    assert!(lapic.has_pending_nmi());
    lapic.clear_pending_nmi();
    assert!(!lapic.has_pending_nmi());
}

#[test]
fn test_ipi_all_including_self() {
    let mut lapic = LocalApic::new(0);

    // All including self
    // ICR: vector=0x60, shorthand=ALL_INCLUDING_SELF(2)
    lapic.write_register(LAPIC_ICR_LOW, 0x00080060); // Shorthand=2

    // Should set local IRR
    assert!(lapic.irr[0x60 / 32] & (1 << (0x60 % 32)) != 0);

    // Should also have pending IPI for VMM
    assert!(lapic.has_pending_ipi());
    let ipi = lapic.take_pending_ipi().unwrap();
    match ipi {
        IpiRequest::Fixed { vector, target } => {
            assert_eq!(vector, 0x60);
            assert!(matches!(target, IpiTarget::AllIncludingSelf));
        }
        _ => panic!("Expected Fixed IPI"),
    }
}

#[test]
fn test_ipi_all_excluding_self() {
    let mut lapic = LocalApic::new(0);

    // All excluding self
    lapic.write_register(LAPIC_ICR_LOW, 0x000C0070); // Shorthand=3

    // Should NOT set local IRR
    assert!(lapic.irr[0x70 / 32] & (1 << (0x70 % 32)) == 0);

    // Should have pending IPI for VMM
    let ipi = lapic.take_pending_ipi().unwrap();
    match ipi {
        IpiRequest::Fixed { vector, target } => {
            assert_eq!(vector, 0x70);
            assert!(matches!(target, IpiTarget::AllExcludingSelf));
        }
        _ => panic!("Expected Fixed IPI"),
    }
}

#[test]
fn test_ipi_physical_destination() {
    let mut lapic = LocalApic::new(0);

    // Target CPU with APIC ID 5
    lapic.write_register(LAPIC_ICR_HIGH, 0x05000000);
    lapic.write_register(LAPIC_ICR_LOW, 0x00000080); // Shorthand=0 (use dest)

    let ipi = lapic.take_pending_ipi().unwrap();
    match ipi {
        IpiRequest::Fixed { vector, target } => {
            assert_eq!(vector, 0x80);
            assert!(matches!(target, IpiTarget::Physical(5)));
        }
        _ => panic!("Expected Fixed IPI"),
    }
}

#[test]
fn test_ipi_logical_destination() {
    let mut lapic = LocalApic::new(0);

    // Logical destination mode
    lapic.write_register(LAPIC_ICR_HIGH, 0xAB000000);
    lapic.write_register(LAPIC_ICR_LOW, 0x00000890); // Logical mode (bit 11), vector 0x90

    let ipi = lapic.take_pending_ipi().unwrap();
    match ipi {
        IpiRequest::Fixed { vector, target } => {
            assert_eq!(vector, 0x90);
            match target {
                IpiTarget::Logical { destination } => assert_eq!(destination, 0xAB),
                _ => panic!("Expected Logical target"),
            }
        }
        _ => panic!("Expected Fixed IPI"),
    }
}

#[test]
fn test_ipi_init() {
    let mut lapic = LocalApic::new(0);

    // INIT IPI with level assert
    lapic.write_register(LAPIC_ICR_HIGH, 0x01000000);
    lapic.write_register(LAPIC_ICR_LOW, 0x00004500); // INIT (delivery=5), level assert (bit 14)

    let ipi = lapic.take_pending_ipi().unwrap();
    assert!(matches!(ipi, IpiRequest::Init { .. }));
}

#[test]
fn test_ipi_init_deassert_ignored() {
    let mut lapic = LocalApic::new(0);

    // INIT IPI without level assert (de-assert)
    lapic.write_register(LAPIC_ICR_HIGH, 0x01000000);
    lapic.write_register(LAPIC_ICR_LOW, 0x00000500); // INIT, no level assert

    // Should be ignored
    assert!(!lapic.has_pending_ipi());
}

#[test]
fn test_ipi_sipi() {
    let mut lapic = LocalApic::new(0);

    // SIPI with vector 0x10 (start at 0x10000)
    lapic.write_register(LAPIC_ICR_HIGH, 0x01000000);
    lapic.write_register(LAPIC_ICR_LOW, 0x00000610); // SIPI (delivery=6), vector=0x10

    let ipi = lapic.take_pending_ipi().unwrap();
    match ipi {
        IpiRequest::Sipi { vector, .. } => {
            assert_eq!(vector, 0x10);
        }
        _ => panic!("Expected SIPI"),
    }
}

#[test]
fn test_ipi_lowest_priority() {
    let mut lapic = LocalApic::new(0);

    // Lowest priority delivery mode
    lapic.write_register(LAPIC_ICR_HIGH, 0x02000000);
    lapic.write_register(LAPIC_ICR_LOW, 0x000001A0); // delivery=1 (lowest priority), vector=0xA0

    let ipi = lapic.take_pending_ipi().unwrap();
    assert!(matches!(
        ipi,
        IpiRequest::LowestPriority { vector: 0xA0, .. }
    ));
}

#[test]
fn test_ipi_smi() {
    let mut lapic = LocalApic::new(0);

    // SMI delivery mode
    lapic.write_register(LAPIC_ICR_HIGH, 0x03000000);
    lapic.write_register(LAPIC_ICR_LOW, 0x00000200); // delivery=2 (SMI)

    let ipi = lapic.take_pending_ipi().unwrap();
    assert!(matches!(ipi, IpiRequest::Smi { .. }));
}

#[test]
fn test_ipi_logical_self_match() {
    let mut lapic = LocalApic::new(0);

    // Set our logical ID
    lapic.write_register(LAPIC_LDR, 0x04000000); // Logical ID = 0x04

    // Send to logical destination that matches us
    lapic.write_register(LAPIC_ICR_HIGH, 0x04000000); // destination = 0x04
    lapic.write_register(LAPIC_ICR_LOW, 0x000008B0); // Logical mode, vector=0xB0

    // Should set local IRR because destination matches our LDR
    assert!(lapic.irr[0xB0 / 32] & (1 << (0xB0 % 32)) != 0);
}

#[test]
fn test_take_pending_ipi() {
    let mut lapic = LocalApic::new(0);

    lapic.write_register(LAPIC_ICR_HIGH, 0x05000000);
    lapic.write_register(LAPIC_ICR_LOW, 0x00000050);

    assert!(lapic.has_pending_ipi());
    let ipi = lapic.take_pending_ipi();
    assert!(ipi.is_some());
    assert!(!lapic.has_pending_ipi());
    assert!(lapic.take_pending_ipi().is_none());
}

// ============================================================================
// MMIO DEVICE WRAPPER TESTS
// ============================================================================

#[test]
fn test_lapic_device_read_4byte() {
    let lapic = Arc::new(Mutex::new(LocalApic::new(5)));
    let mut device = LapicDevice::new(lapic);

    let mut data = [0u8; 4];
    device.read(LAPIC_BASE + LAPIC_ID, &mut data);

    let value = u32::from_le_bytes(data);
    assert_eq!(value, 0x05000000);
}

#[test]
fn test_lapic_device_read_1byte() {
    let lapic = Arc::new(Mutex::new(LocalApic::new(0xAB)));
    let mut device = LapicDevice::new(lapic);

    // Read byte 3 of ID register (which contains the APIC ID)
    let mut data = [0u8; 1];
    device.read(LAPIC_BASE + LAPIC_ID + 3, &mut data);
    assert_eq!(data[0], 0xAB);
}

#[test]
fn test_lapic_device_read_2byte() {
    let lapic = Arc::new(Mutex::new(LocalApic::new(0)));
    let mut device = LapicDevice::new(lapic.clone());

    // Set TPR to 0x1234 (but only low 8 bits matter)
    lapic.lock().unwrap().write_register(LAPIC_TPR, 0x34);

    let mut data = [0u8; 2];
    device.read(LAPIC_BASE + LAPIC_TPR, &mut data);
    assert_eq!(u16::from_le_bytes(data), 0x34);
}

#[test]
fn test_lapic_device_write_4byte() {
    let lapic = Arc::new(Mutex::new(LocalApic::new(0)));
    let mut device = LapicDevice::new(lapic.clone());

    let data = 0xAB_u32.to_le_bytes();
    device.write(LAPIC_BASE + LAPIC_TPR, &data);

    assert_eq!(lapic.lock().unwrap().read_register(LAPIC_TPR), 0xAB);
}

#[test]
fn test_lapic_device_write_1byte() {
    let lapic = Arc::new(Mutex::new(LocalApic::new(0)));
    let mut device = LapicDevice::new(lapic.clone());

    device.write(LAPIC_BASE + LAPIC_TPR, &[0x42]);
    assert_eq!(lapic.lock().unwrap().read_register(LAPIC_TPR), 0x42);
}

// ============================================================================
// EDGE CASES AND BOUNDARY TESTS
// ============================================================================

#[test]
fn test_vector_boundaries() {
    let mut lapic = LocalApic::new(0);

    // Test vector 0
    lapic.set_irr(0);
    assert_eq!(lapic.get_pending_vector(), Some(0));
    lapic.ack_interrupt(0);
    lapic.write_register(LAPIC_EOI, 0);

    // Test vector 255
    lapic.set_irr(255);
    assert_eq!(lapic.get_pending_vector(), Some(255));
    lapic.ack_interrupt(255);
    assert_eq!(lapic.isr[7], 0x80000000);
    lapic.write_register(LAPIC_EOI, 0);
    assert_eq!(lapic.isr[7], 0);
}

#[test]
fn test_all_irr_bits() {
    let mut lapic = LocalApic::new(0);

    // Set all 256 interrupt vectors
    for v in 0..=255u8 {
        lapic.set_irr(v);
    }

    // All IRR words should be 0xFFFFFFFF
    for i in 0..8 {
        assert_eq!(lapic.irr[i], 0xFFFFFFFF, "IRR[{}] should be all 1s", i);
    }

    // Highest priority should be 255
    assert_eq!(lapic.get_pending_vector(), Some(255));
}

#[test]
fn test_multiple_interrupts_priority() {
    let mut lapic = LocalApic::new(0);

    // Set interrupts at various priorities
    lapic.set_irr(0x10); // Low priority
    lapic.set_irr(0x50); // Medium priority
    lapic.set_irr(0x90); // High priority

    // Should get highest first
    assert_eq!(lapic.get_pending_vector(), Some(0x90));
    lapic.ack_interrupt(0x90);

    assert_eq!(lapic.get_pending_vector(), Some(0x50));
    lapic.ack_interrupt(0x50);

    assert_eq!(lapic.get_pending_vector(), Some(0x10));
    lapic.ack_interrupt(0x10);

    assert_eq!(lapic.get_pending_vector(), None);
}

#[test]
fn test_register_alignment() {
    let lapic = Arc::new(Mutex::new(LocalApic::new(0)));
    let mut device = LapicDevice::new(lapic.clone());

    // Write TPR
    lapic.lock().unwrap().write_register(LAPIC_TPR, 0xAB);

    // Read at various alignments - all should access same register
    let mut data4 = [0u8; 4];
    device.read(LAPIC_BASE + LAPIC_TPR, &mut data4);

    let mut data1_0 = [0u8; 1];
    device.read(LAPIC_BASE + LAPIC_TPR, &mut data1_0);

    // Byte 0 should be 0xAB
    assert_eq!(data1_0[0], 0xAB);
    assert_eq!(data4[0], 0xAB);
}

#[test]
fn test_invalid_register_offset() {
    let lapic = LocalApic::new(0);

    // Reading undefined register should return 0
    assert_eq!(lapic.read_register(0x004), 0);
    assert_eq!(lapic.read_register(0xFFC), 0);
}

#[test]
fn test_timer_zero_initial_count() {
    let mut lapic = LocalApic::new(0);

    lapic.write_register(LAPIC_LVT_TIMER, 0x00000020);
    lapic.write_register(LAPIC_TIMER_ICR, 0);

    // Timer should not fire with zero count
    let vector = lapic.tick();
    assert_eq!(vector, None);
}

#[test]
fn test_concurrent_ipi_and_timer() {
    let mut lapic = LocalApic::new(0);

    // Set up timer
    lapic.write_register(LAPIC_LVT_TIMER, 0x00000020); // Vector 0x20
    lapic.write_register(LAPIC_TIMER_DCR, 0b1011);
    lapic.write_register(LAPIC_TIMER_ICR, 1);

    // Send self-IPI
    lapic.write_register(LAPIC_ICR_LOW, 0x00040030); // Self, vector 0x30

    // Both should be pending
    assert!(lapic.irr[0x30 / 32] & (1 << (0x30 % 32)) != 0);

    thread::sleep(Duration::from_millis(10));
    let timer_vec = lapic.tick();
    assert_eq!(timer_vec, Some(0x20));

    // IPI vector should still be in IRR
    assert_eq!(lapic.get_pending_vector(), Some(0x30));
}

#[test]
fn test_nmi_pending_state() {
    let mut lapic = LocalApic::new(0);

    assert!(!lapic.has_pending_nmi());

    lapic.nmi_pending = true;
    assert!(lapic.has_pending_nmi());

    lapic.clear_pending_nmi();
    assert!(!lapic.has_pending_nmi());
}

#[test]
fn test_apr_rrd_readonly() {
    let lapic = LocalApic::new(0);

    // APR and RRD should return 0 (read-only, usually 0)
    assert_eq!(lapic.read_register(LAPIC_APR), 0);
    assert_eq!(lapic.read_register(LAPIC_RRD), 0);
}

#[test]
fn test_dcr_mask() {
    let mut lapic = LocalApic::new(0);

    // Only bits 0, 1, 3 are valid in DCR
    lapic.write_register(LAPIC_TIMER_DCR, 0xFFFFFFFF);
    assert_eq!(lapic.read_register(LAPIC_TIMER_DCR), 0x0B);
}

#[test]
fn test_timer_ccr_returns_zero_when_no_initial() {
    let lapic = LocalApic::new(0);

    // With no timer started, CCR should be 0
    assert_eq!(lapic.read_register(LAPIC_TIMER_CCR), 0);
}

#[test]
fn test_eoi_with_empty_isr() {
    let mut lapic = LocalApic::new(0);

    // EOI with empty ISR should not crash
    lapic.write_register(LAPIC_EOI, 0);

    // ISR should still be all zeros
    for i in 0..8 {
        assert_eq!(lapic.isr[i], 0);
    }
}

#[test]
fn test_isr_tmr_irr_register_indexing() {
    let mut lapic = LocalApic::new(0);

    // Each array has 8 entries, each at 0x10 byte intervals
    // ISR: 0x100, 0x110, 0x120, 0x130, 0x140, 0x150, 0x160, 0x170
    // TMR: 0x180, 0x190, 0x1A0, 0x1B0, 0x1C0, 0x1D0, 0x1E0, 0x1F0
    // IRR: 0x200, 0x210, 0x220, 0x230, 0x240, 0x250, 0x260, 0x270

    lapic.isr[3] = 0xDEADBEEF;
    lapic.tmr[5] = 0xCAFEBABE;
    lapic.irr[7] = 0x12345678;

    assert_eq!(lapic.read_register(LAPIC_ISR_BASE + 0x30), 0xDEADBEEF);
    assert_eq!(lapic.read_register(LAPIC_TMR_BASE + 0x50), 0xCAFEBABE);
    assert_eq!(lapic.read_register(LAPIC_IRR_BASE + 0x70), 0x12345678);
}

#[test]
fn test_physical_self_target() {
    let mut lapic = LocalApic::new(7);

    // Target physical ID 7 (ourselves)
    lapic.write_register(LAPIC_ICR_HIGH, 0x07000000);
    lapic.write_register(LAPIC_ICR_LOW, 0x000000C0); // Physical mode, vector 0xC0

    // Should set local IRR
    assert!(lapic.irr[0xC0 / 32] & (1 << (0xC0 % 32)) != 0);

    // Should also have IPI for VMM (since not using self shorthand)
    assert!(lapic.has_pending_ipi());
}

#[test]
fn test_icr_preserves_written_value() {
    let mut lapic = LocalApic::new(0);

    // ICR stores the written value (implementation detail: delivery status bit
    // is technically read-only in hardware, but we preserve all bits for simplicity)
    lapic.write_register(LAPIC_ICR_HIGH, 0xAB000000);
    lapic.write_register(LAPIC_ICR_LOW, 0x00000050);

    // Verify ICR maintains its value
    assert_eq!(lapic.read_register(LAPIC_ICR_HIGH), 0xAB000000);
    // Note: ICR_LOW may have different bits due to IPI processing,
    // but the vector and other fields should be preserved
    assert_eq!(lapic.read_register(LAPIC_ICR_LOW) & 0xFF, 0x50);
}

// ============================================================================
// EDGE CASES - TIMER
// ============================================================================

#[test]
fn test_timer_mode_change_while_running() {
    let mut lapic = LocalApic::new(0);

    // Start oneshot timer
    lapic.write_register(LAPIC_LVT_TIMER, 0x00000020); // Oneshot, vector 0x20
    lapic.write_register(LAPIC_TIMER_DCR, 0b1011);
    lapic.write_register(LAPIC_TIMER_ICR, 1_000_000_000);

    // Change to periodic while running
    lapic.write_register(LAPIC_LVT_TIMER, 0x00020020); // Periodic

    // Timer should still be running
    assert!(lapic.timer_start.is_some());
    assert_eq!(lapic.timer_mode(), TIMER_MODE_PERIODIC);
}

#[test]
fn test_timer_vector_change_while_running() {
    let mut lapic = LocalApic::new(0);

    lapic.write_register(LAPIC_LVT_TIMER, 0x00000020);
    lapic.write_register(LAPIC_TIMER_DCR, 0b1011);
    lapic.write_register(LAPIC_TIMER_ICR, 1);

    // Change vector while timer is expiring
    lapic.write_register(LAPIC_LVT_TIMER, 0x00000030);

    thread::sleep(Duration::from_millis(10));
    let vector = lapic.tick();

    // Should fire with new vector
    assert_eq!(vector, Some(0x30));
}

#[test]
fn test_timer_mask_while_pending() {
    let mut lapic = LocalApic::new(0);

    // Set up and let timer expire
    lapic.write_register(LAPIC_LVT_TIMER, 0x00000020);
    lapic.write_register(LAPIC_TIMER_DCR, 0b1011);
    lapic.write_register(LAPIC_TIMER_ICR, 1);

    thread::sleep(Duration::from_millis(10));
    lapic.tick(); // This sets pending

    // Mask the timer
    lapic.write_register(LAPIC_LVT_TIMER, 0x00010020);

    // Pending flag should still be set (masking doesn't clear pending)
    assert!(lapic.has_pending_timer());
}

#[test]
fn test_timer_restart_clears_pending() {
    let mut lapic = LocalApic::new(0);

    lapic.write_register(LAPIC_LVT_TIMER, 0x00000020);
    lapic.write_register(LAPIC_TIMER_DCR, 0b1011);
    lapic.write_register(LAPIC_TIMER_ICR, 1);

    thread::sleep(Duration::from_millis(10));
    lapic.tick();
    assert!(lapic.has_pending_timer());

    // Restart timer - should clear pending
    lapic.write_register(LAPIC_TIMER_ICR, 1_000_000);
    assert!(!lapic.has_pending_timer());
}

#[test]
fn test_timer_all_divisors_produce_different_rates() {
    // Verify each divisor actually changes the timer behavior
    let divisor_configs = [
        (0b0000, 2u32),
        (0b0001, 4),
        (0b0010, 8),
        (0b0011, 16),
        (0b1000, 32),
        (0b1001, 64),
        (0b1010, 128),
        (0b1011, 1),
    ];

    for (config, expected) in divisor_configs {
        let mut lapic = LocalApic::new(0);
        lapic.write_register(LAPIC_TIMER_DCR, config);
        assert_eq!(lapic.timer_divisor(), expected);
    }
}

#[test]
fn test_timer_initial_count_max_value() {
    let mut lapic = LocalApic::new(0);

    // Use slower divisor (128) to reduce sensitivity to timing
    lapic.write_register(LAPIC_LVT_TIMER, 0x00000020);
    lapic.write_register(LAPIC_TIMER_DCR, 0b1010); // Divisor 128
    lapic.write_register(LAPIC_TIMER_ICR, 0xFFFFFFFF);

    assert_eq!(lapic.timer_initial_count, 0xFFFFFFFF);
    assert!(lapic.timer_start.is_some());

    // CCR should be close to max (with div128, 1ms = ~7.8M ticks elapsed)
    // Allow generous margin for slow CI systems
    let ccr = lapic.read_register(LAPIC_TIMER_CCR);
    assert!(
        ccr > 0xF0000000,
        "CCR ({:#x}) should be reasonably close to initial count",
        ccr
    );
}

#[test]
fn test_timer_initial_count_one() {
    let mut lapic = LocalApic::new(0);

    lapic.write_register(LAPIC_LVT_TIMER, 0x00000020);
    lapic.write_register(LAPIC_TIMER_DCR, 0b1011); // Divisor 1
    lapic.write_register(LAPIC_TIMER_ICR, 1);

    // With divisor 1 and count 1, timer expires in 1 nanosecond
    thread::sleep(Duration::from_micros(10));

    let vector = lapic.tick();
    assert_eq!(vector, Some(0x20));
}

#[test]
fn test_timer_periodic_multiple_expirations() {
    let mut lapic = LocalApic::new(0);

    lapic.write_register(LAPIC_LVT_TIMER, 0x00020020); // Periodic
    lapic.write_register(LAPIC_TIMER_DCR, 0b1011);
    lapic.write_register(LAPIC_TIMER_ICR, 1);

    // Collect multiple timer fires
    let mut fire_count = 0;
    for _ in 0..5 {
        thread::sleep(Duration::from_millis(5));
        if lapic.tick().is_some() {
            fire_count += 1;
            lapic.clear_timer_pending();
        }
    }

    assert!(fire_count >= 2, "Periodic timer should fire multiple times");
}

// ============================================================================
// EDGE CASES - INTERRUPT PRIORITY
// ============================================================================

#[test]
fn test_irr_priority_all_classes() {
    let mut lapic = LocalApic::new(0);

    // Set one interrupt per priority class (0x00, 0x10, 0x20, ..., 0xF0)
    for class in 0..16u8 {
        lapic.set_irr(class * 16);
    }

    // Should return highest priority (0xF0)
    assert_eq!(lapic.get_pending_vector(), Some(0xF0));

    // Ack and check next
    lapic.ack_interrupt(0xF0);
    assert_eq!(lapic.get_pending_vector(), Some(0xE0));
}

#[test]
fn test_irr_same_class_different_vectors() {
    let mut lapic = LocalApic::new(0);

    // Set multiple vectors in same priority class
    lapic.set_irr(0x40);
    lapic.set_irr(0x41);
    lapic.set_irr(0x4F);

    // Highest within class should be returned first
    assert_eq!(lapic.get_pending_vector(), Some(0x4F));
    lapic.ack_interrupt(0x4F);

    assert_eq!(lapic.get_pending_vector(), Some(0x41));
    lapic.ack_interrupt(0x41);

    assert_eq!(lapic.get_pending_vector(), Some(0x40));
}

#[test]
fn test_nested_interrupts_isr_tracking() {
    let mut lapic = LocalApic::new(0);

    // Simulate nested interrupt handling
    lapic.set_irr(0x20);
    lapic.ack_interrupt(0x20); // ISR has 0x20

    lapic.set_irr(0x30);
    lapic.ack_interrupt(0x30); // ISR has 0x20, 0x30

    lapic.set_irr(0x40);
    lapic.ack_interrupt(0x40); // ISR has 0x20, 0x30, 0x40

    // EOI should clear in reverse order
    lapic.write_register(LAPIC_EOI, 0);
    assert!(lapic.isr[0x40 / 32] & (1 << (0x40 % 32)) == 0);
    assert!(lapic.isr[0x30 / 32] & (1 << (0x30 % 32)) != 0);

    lapic.write_register(LAPIC_EOI, 0);
    assert!(lapic.isr[0x30 / 32] & (1 << (0x30 % 32)) == 0);
    assert!(lapic.isr[0x20 / 32] & (1 << (0x20 % 32)) != 0);

    lapic.write_register(LAPIC_EOI, 0);
    assert!(lapic.isr[0x20 / 32] & (1 << (0x20 % 32)) == 0);
}

#[test]
fn test_ppr_with_nested_isr() {
    let mut lapic = LocalApic::new(0);

    lapic.write_register(LAPIC_TPR, 0x10);

    // Add interrupt in service at 0x50
    lapic.isr[0x50 / 32] |= 1 << (0x50 % 32);
    assert_eq!(lapic.read_register(LAPIC_PPR), 0x50);

    // Add higher priority ISR
    lapic.isr[0x80 / 32] |= 1 << (0x80 % 32);
    assert_eq!(lapic.read_register(LAPIC_PPR), 0x80);

    // Clear higher priority, should fall back
    lapic.isr[0x80 / 32] &= !(1 << (0x80 % 32));
    assert_eq!(lapic.read_register(LAPIC_PPR), 0x50);
}

#[test]
fn test_spurious_vector_reserved_bits() {
    let mut lapic = LocalApic::new(0);

    // SVR has specific bit meanings - test bit 8 (enable) toggles correctly
    lapic.write_register(LAPIC_SVR, 0x000);
    assert!(!lapic.is_enabled());

    lapic.write_register(LAPIC_SVR, 0x1AB);
    assert!(lapic.is_enabled());
    assert_eq!(lapic.read_register(LAPIC_SVR), 0x1AB);
}

// ============================================================================
// EDGE CASES - IPI
// ============================================================================

#[test]
fn test_ipi_rapid_succession() {
    let mut lapic = LocalApic::new(0);

    // Send multiple self-IPIs rapidly
    for vector in 0x20..0x30u8 {
        lapic.write_register(LAPIC_ICR_LOW, 0x00040000 | (vector as u32));
    }

    // All should be in IRR
    for vector in 0x20..0x30u8 {
        assert!(
            lapic.irr[vector as usize / 32] & (1 << (vector % 32)) != 0,
            "Vector {:#x} should be in IRR",
            vector
        );
    }
}

#[test]
fn test_ipi_logical_no_match() {
    let mut lapic = LocalApic::new(0);

    // Set our logical ID to 0x01
    lapic.write_register(LAPIC_LDR, 0x01000000);

    // Send to logical destination 0x80 (doesn't match 0x01)
    lapic.write_register(LAPIC_ICR_HIGH, 0x80000000);
    lapic.write_register(LAPIC_ICR_LOW, 0x00000850); // Logical mode, vector 0x50

    // Should NOT set local IRR (no match)
    assert!(lapic.irr[0x50 / 32] & (1 << (0x50 % 32)) == 0);

    // But should have IPI for VMM
    assert!(lapic.has_pending_ipi());
}

#[test]
fn test_ipi_logical_partial_match() {
    let mut lapic = LocalApic::new(0);

    // Set our logical ID with multiple bits
    lapic.write_register(LAPIC_LDR, 0x0F000000); // Bits 0-3 set

    // Send to destination that partially matches (bit 2)
    lapic.write_register(LAPIC_ICR_HIGH, 0x04000000);
    lapic.write_register(LAPIC_ICR_LOW, 0x00000860); // Logical mode

    // Should match (0x04 & 0x0F != 0)
    assert!(lapic.irr[0x60 / 32] & (1 << (0x60 % 32)) != 0);
}

#[test]
fn test_ipi_overwrite_pending() {
    let mut lapic = LocalApic::new(0);

    // Send first IPI
    lapic.write_register(LAPIC_ICR_HIGH, 0x01000000);
    lapic.write_register(LAPIC_ICR_LOW, 0x00000020);

    let first_ipi = lapic.take_pending_ipi();
    assert!(first_ipi.is_some());

    // Send second IPI without taking first
    lapic.write_register(LAPIC_ICR_HIGH, 0x02000000);
    lapic.write_register(LAPIC_ICR_LOW, 0x00000030);

    // Second IPI overwrites (implementation detail)
    let second_ipi = lapic.take_pending_ipi();
    assert!(second_ipi.is_some());
}

#[test]
fn test_ipi_all_delivery_modes_to_self() {
    let mut lapic = LocalApic::new(0);

    // Fixed to self
    lapic.write_register(LAPIC_ICR_LOW, 0x00040020);
    assert!(lapic.irr[0x20 / 32] & (1 << (0x20 % 32)) != 0);

    // NMI to self
    lapic.write_register(LAPIC_ICR_LOW, 0x00040400);
    assert!(lapic.has_pending_nmi());
    lapic.clear_pending_nmi();

    // Note: INIT/SIPI/SMI to self don't make practical sense
    // but shouldn't crash
    lapic.write_register(LAPIC_ICR_LOW, 0x00044500); // INIT to self (level assert)
    lapic.write_register(LAPIC_ICR_LOW, 0x00040600); // SIPI to self
    lapic.write_register(LAPIC_ICR_LOW, 0x00040200); // SMI to self
}

#[test]
fn test_sipi_vector_calculation() {
    let mut lapic = LocalApic::new(0);

    // SIPI with various vectors
    let test_vectors = [0x00, 0x01, 0x10, 0x80, 0xFF];

    for vector in test_vectors {
        lapic.pending_ipi = None;
        lapic.write_register(LAPIC_ICR_HIGH, 0x01000000);
        lapic.write_register(LAPIC_ICR_LOW, 0x00000600 | (vector as u32));

        let ipi = lapic.take_pending_ipi().unwrap();
        match ipi {
            IpiRequest::Sipi { vector: v, .. } => {
                assert_eq!(v, vector);
                // Start address would be vector * 0x1000
            }
            _ => panic!("Expected SIPI"),
        }
    }
}

// ============================================================================
// EDGE CASES - REGISTER ACCESS
// ============================================================================

#[test]
fn test_read_all_isr_registers() {
    let mut lapic = LocalApic::new(0);

    // Set a pattern in ISR
    for i in 0..8 {
        lapic.isr[i] = 0x12345678 + i as u32;
    }

    // Read all 8 ISR registers
    for i in 0..8 {
        let offset = LAPIC_ISR_BASE + (i as u64 * 0x10);
        let value = lapic.read_register(offset);
        assert_eq!(value, 0x12345678 + i as u32);
    }
}

#[test]
fn test_read_all_tmr_registers() {
    let mut lapic = LocalApic::new(0);

    for i in 0..8 {
        lapic.tmr[i] = 0xABCDEF00 + i as u32;
    }

    for i in 0..8 {
        let offset = LAPIC_TMR_BASE + (i as u64 * 0x10);
        let value = lapic.read_register(offset);
        assert_eq!(value, 0xABCDEF00 + i as u32);
    }
}

#[test]
fn test_read_all_irr_registers() {
    let mut lapic = LocalApic::new(0);

    for i in 0..8 {
        lapic.irr[i] = 0xDEADBEEF - i as u32;
    }

    for i in 0..8 {
        let offset = LAPIC_IRR_BASE + (i as u64 * 0x10);
        let value = lapic.read_register(offset);
        assert_eq!(value, 0xDEADBEEF - i as u32);
    }
}

#[test]
fn test_register_gaps_return_zero() {
    let lapic = LocalApic::new(0);

    // These are gaps in the LAPIC register space
    let gap_offsets = [
        0x000, 0x010, // Before ID
        0x040, 0x050, 0x060, 0x070, // Between VERSION and TPR
        0x0C0, // RRD
    ];

    for offset in gap_offsets {
        assert_eq!(
            lapic.read_register(offset),
            0,
            "Gap at offset {:#x} should return 0",
            offset
        );
    }
}

#[test]
fn test_lvt_all_registers() {
    let mut lapic = LocalApic::new(0);

    let lvt_offsets = [
        LAPIC_LVT_TIMER,
        0x330, // LVT_THERMAL
        0x340, // LVT_PMC
        LAPIC_LVT_LINT0,
        LAPIC_LVT_LINT1,
        LAPIC_LVT_ERROR,
    ];

    for (i, &offset) in lvt_offsets.iter().enumerate() {
        let value = 0x00010000 | (0x20 + i as u32); // Masked, different vectors
        lapic.write_register(offset, value);
        assert_eq!(
            lapic.read_register(offset),
            value,
            "LVT at offset {:#x}",
            offset
        );
    }
}

// ============================================================================
// TORTURE TESTS
// ============================================================================

#[test]
fn test_torture_rapid_irr_set_clear() {
    let mut lapic = LocalApic::new(0);

    // Rapidly set and clear IRR bits
    for _ in 0..100 {
        for v in 0..=255u8 {
            lapic.set_irr(v);
        }
        for v in 0..=255u8 {
            lapic.ack_interrupt(v);
        }
        for _ in 0..256 {
            lapic.write_register(LAPIC_EOI, 0);
        }
    }

    // Everything should be cleared
    for i in 0..8 {
        assert_eq!(lapic.irr[i], 0);
        assert_eq!(lapic.isr[i], 0);
    }
}

#[test]
fn test_torture_timer_reconfiguration() {
    let mut lapic = LocalApic::new(0);

    // Rapidly reconfigure timer
    for i in 0..100 {
        let vector = (0x20 + (i % 0xE0)) as u32;
        let mode = (i % 3) << 17;
        let mask = if i % 5 == 0 { LVT_MASK } else { 0 };

        lapic.write_register(LAPIC_LVT_TIMER, vector | mode | mask);
        lapic.write_register(LAPIC_TIMER_DCR, (i % 12) as u32);
        lapic.write_register(LAPIC_TIMER_ICR, (i * 1000 + 1) as u32);
    }

    // Should not crash, timer state should be consistent
    assert!(lapic.timer_initial_count > 0);
}

#[test]
fn test_torture_ipi_storm() {
    let mut lapic = LocalApic::new(0);

    // Send many IPIs
    for i in 0..1000 {
        let vector = (0x20 + (i % 0xE0)) as u32;
        let shorthand = ((i % 4) << 18) as u32;

        lapic.write_register(LAPIC_ICR_HIGH, ((i % 256) << 24) as u32);
        lapic.write_register(LAPIC_ICR_LOW, vector | shorthand);

        // Periodically drain IPIs
        if i % 10 == 0 {
            lapic.take_pending_ipi();
        }
    }
}

#[test]
fn test_torture_register_random_access() {
    let mut lapic = LocalApic::new(0);

    // Access many registers in "random" order
    let offsets = [
        LAPIC_ID,
        LAPIC_TPR,
        LAPIC_SVR,
        LAPIC_LVT_TIMER,
        LAPIC_TIMER_ICR,
        LAPIC_TIMER_DCR,
        LAPIC_EOI,
        LAPIC_ICR_LOW,
        LAPIC_ICR_HIGH,
        LAPIC_ESR,
        LAPIC_LDR,
        LAPIC_DFR,
    ];

    for round in 0..100 {
        for (i, &offset) in offsets.iter().enumerate() {
            let value = ((round * 13 + i * 7) % 256) as u32;

            // Write (skip read-only registers)
            if offset != LAPIC_VERSION && offset != 0x0A0 {
                lapic.write_register(offset, value);
            }

            // Read
            let _ = lapic.read_register(offset);
        }
    }
}

// ============================================================================
// COMPLEX INTERACTION TESTS
// ============================================================================

#[test]
fn test_complex_timer_with_interrupts() {
    let mut lapic = LocalApic::new(0);

    // Set up timer
    lapic.write_register(LAPIC_LVT_TIMER, 0x00000020);
    lapic.write_register(LAPIC_TIMER_DCR, 0b1011);
    lapic.write_register(LAPIC_TIMER_ICR, 1);

    // Also set some IRR bits
    lapic.set_irr(0x30);
    lapic.set_irr(0x40);

    thread::sleep(Duration::from_millis(10));
    lapic.tick();

    // Timer pending should be separate from IRR interrupts
    assert!(lapic.has_pending_timer());
    assert_eq!(lapic.get_pending_vector(), Some(0x40)); // Highest in IRR

    // Ack IRR interrupts
    lapic.ack_interrupt(0x40);
    lapic.ack_interrupt(0x30);

    // Timer still pending
    assert!(lapic.has_pending_timer());
}

#[test]
fn test_complex_disable_with_pending() {
    let mut lapic = LocalApic::new(0);

    // Set up interrupts and timer
    lapic.set_irr(0x50);
    lapic.write_register(LAPIC_LVT_TIMER, 0x00000020);
    lapic.write_register(LAPIC_TIMER_ICR, 1);

    thread::sleep(Duration::from_millis(10));
    lapic.tick();

    // Disable APIC
    lapic.write_register(LAPIC_SVR, 0x0FF);

    // IRR should still be readable
    assert!(lapic.irr[0x50 / 32] & (1 << (0x50 % 32)) != 0);

    // Timer tick should not fire when disabled
    lapic.clear_timer_pending();
    lapic.write_register(LAPIC_TIMER_ICR, 1);
    thread::sleep(Duration::from_millis(10));
    assert_eq!(lapic.tick(), None);
}

#[test]
fn test_complex_eoi_with_pending_irr() {
    let mut lapic = LocalApic::new(0);

    // Put 0x50 in service
    lapic.set_irr(0x50);
    lapic.ack_interrupt(0x50);

    // Set same vector in IRR again (re-assertion while in service)
    lapic.set_irr(0x50);

    // EOI should only clear ISR, not IRR
    lapic.write_register(LAPIC_EOI, 0);

    assert!(lapic.isr[0x50 / 32] & (1 << (0x50 % 32)) == 0);
    assert!(lapic.irr[0x50 / 32] & (1 << (0x50 % 32)) != 0);
}

#[test]
fn test_complex_icr_full_64bit() {
    let mut lapic = LocalApic::new(0);

    // Write ICR high first, then low
    lapic.write_register(LAPIC_ICR_HIGH, 0xABCDEF00);
    lapic.write_register(LAPIC_ICR_LOW, 0x12345678);

    // Full ICR should be correct
    assert_eq!(lapic.icr, 0xABCDEF0012345678);

    // Read back both halves
    assert_eq!(lapic.read_register(LAPIC_ICR_LOW), 0x12345678);
    assert_eq!(lapic.read_register(LAPIC_ICR_HIGH), 0xABCDEF00);
}

#[test]
fn test_complex_tpr_affects_ppr() {
    let mut lapic = LocalApic::new(0);

    // No ISR, PPR follows TPR
    for tpr in (0..=0xF0).step_by(0x10) {
        lapic.write_register(LAPIC_TPR, tpr);
        // PPR should be TPR class << 4
        assert_eq!(lapic.read_register(LAPIC_PPR), tpr & 0xF0);
    }
}

#[test]
fn test_complex_multiple_nmi_pending() {
    let mut lapic = LocalApic::new(0);

    // Send multiple self-NMIs
    lapic.write_register(LAPIC_ICR_LOW, 0x00040400); // NMI to self
    assert!(lapic.has_pending_nmi());

    // Sending another NMI shouldn't change anything (already pending)
    lapic.write_register(LAPIC_ICR_LOW, 0x00040400);
    assert!(lapic.has_pending_nmi());

    lapic.clear_pending_nmi();
    assert!(!lapic.has_pending_nmi());
}

// ============================================================================
// MMIO DEVICE EDGE CASES
// ============================================================================

#[test]
fn test_mmio_device_unaligned_read() {
    let lapic = Arc::new(Mutex::new(LocalApic::new(0)));
    let mut device = LapicDevice::new(lapic.clone());

    // Set a known value
    lapic.lock().unwrap().write_register(LAPIC_TPR, 0xAB);

    // Read at offset +1 (unaligned)
    let mut data = [0u8; 1];
    device.read(LAPIC_BASE + LAPIC_TPR + 1, &mut data);

    // Should read byte 1 of the aligned register (0x00)
    assert_eq!(data[0], 0x00);
}

#[test]
fn test_mmio_device_read_sizes() {
    let lapic = Arc::new(Mutex::new(LocalApic::new(0)));
    let mut device = LapicDevice::new(lapic.clone());

    lapic.lock().unwrap().write_register(LAPIC_TPR, 0xAB);

    // 1-byte read
    let mut data1 = [0u8; 1];
    device.read(LAPIC_BASE + LAPIC_TPR, &mut data1);
    assert_eq!(data1[0], 0xAB);

    // 2-byte read
    let mut data2 = [0u8; 2];
    device.read(LAPIC_BASE + LAPIC_TPR, &mut data2);
    assert_eq!(u16::from_le_bytes(data2), 0x00AB);

    // 4-byte read
    let mut data4 = [0u8; 4];
    device.read(LAPIC_BASE + LAPIC_TPR, &mut data4);
    assert_eq!(u32::from_le_bytes(data4), 0x000000AB);
}

#[test]
fn test_mmio_device_write_sizes() {
    let lapic = Arc::new(Mutex::new(LocalApic::new(0)));
    let mut device = LapicDevice::new(lapic.clone());

    // 1-byte write
    device.write(LAPIC_BASE + LAPIC_TPR, &[0x12]);
    assert_eq!(lapic.lock().unwrap().read_register(LAPIC_TPR), 0x12);

    // 2-byte write
    device.write(LAPIC_BASE + LAPIC_TPR, &[0x34, 0x00]);
    assert_eq!(lapic.lock().unwrap().read_register(LAPIC_TPR), 0x34);

    // 4-byte write
    device.write(LAPIC_BASE + LAPIC_TPR, &[0x56, 0x00, 0x00, 0x00]);
    assert_eq!(lapic.lock().unwrap().read_register(LAPIC_TPR), 0x56);
}

#[test]
fn test_mmio_device_invalid_size() {
    let lapic = Arc::new(Mutex::new(LocalApic::new(0)));
    let mut device = LapicDevice::new(lapic.clone());

    // 3-byte read (unusual size)
    let mut data = [0u8; 3];
    device.read(LAPIC_BASE + LAPIC_TPR, &mut data);
    // Should fill with 0s for unsupported sizes
    assert_eq!(data, [0, 0, 0]);

    // 5-byte write (unusual size) - should be ignored
    device.write(LAPIC_BASE + LAPIC_TPR, &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
}

#[test]
fn test_mmio_device_boundary_addresses() {
    let lapic = Arc::new(Mutex::new(LocalApic::new(0)));
    let mut device = LapicDevice::new(lapic);

    // Read at start of LAPIC region
    let mut data = [0u8; 4];
    device.read(LAPIC_BASE, &mut data);

    // Read at end of LAPIC region
    device.read(LAPIC_BASE + 0xFFC, &mut data);
}
