//! Local APIC (Local Advanced Programmable Interrupt Controller) emulation.
//!
//! The x86-64 Local APIC provides:
//! - Per-CPU interrupt handling
//! - Timer functionality (one-shot, periodic, TSC-deadline modes)
//! - Inter-Processor Interrupts (IPI)
//! - Local interrupt sources (LINT0, LINT1, error, thermal, PMC)
//!
//! MMIO region: 0xFEE00000 - 0xFEE00FFF (4KB)

use super::bus::MmioDevice;
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// LAPIC base address (fixed for x86-64)
pub const LAPIC_BASE: u64 = 0xFEE00000;
/// LAPIC region size
pub const LAPIC_SIZE: u64 = 0x1000;

// Register offsets (byte offsets from LAPIC_BASE)
const LAPIC_ID: u64 = 0x020;
const LAPIC_VERSION: u64 = 0x030;
const LAPIC_TPR: u64 = 0x080; // Task Priority Register
const LAPIC_APR: u64 = 0x090; // Arbitration Priority Register
const LAPIC_PPR: u64 = 0x0A0; // Processor Priority Register
const LAPIC_EOI: u64 = 0x0B0; // End of Interrupt
const LAPIC_RRD: u64 = 0x0C0; // Remote Read Register
const LAPIC_LDR: u64 = 0x0D0; // Logical Destination Register
const LAPIC_DFR: u64 = 0x0E0; // Destination Format Register
const LAPIC_SVR: u64 = 0x0F0; // Spurious Interrupt Vector Register
const LAPIC_ISR_BASE: u64 = 0x100; // In-Service Register (8 x 32-bit)
const LAPIC_TMR_BASE: u64 = 0x180; // Trigger Mode Register (8 x 32-bit)
const LAPIC_IRR_BASE: u64 = 0x200; // Interrupt Request Register (8 x 32-bit)
const LAPIC_ESR: u64 = 0x280; // Error Status Register
const LAPIC_ICR_LOW: u64 = 0x300; // Interrupt Command Register (low)
const LAPIC_ICR_HIGH: u64 = 0x310; // Interrupt Command Register (high)
const LAPIC_LVT_TIMER: u64 = 0x320; // LVT Timer Register
const LAPIC_LVT_THERMAL: u64 = 0x330; // LVT Thermal Sensor Register
const LAPIC_LVT_PMC: u64 = 0x340; // LVT Performance Counter Register
const LAPIC_LVT_LINT0: u64 = 0x350; // LVT LINT0 Register
const LAPIC_LVT_LINT1: u64 = 0x360; // LVT LINT1 Register
const LAPIC_LVT_ERROR: u64 = 0x370; // LVT Error Register
const LAPIC_TIMER_ICR: u64 = 0x380; // Timer Initial Count Register
const LAPIC_TIMER_CCR: u64 = 0x390; // Timer Current Count Register
const LAPIC_TIMER_DCR: u64 = 0x3E0; // Timer Divide Configuration Register

// LVT entry bits
const LVT_MASK: u32 = 1 << 16; // Interrupt masked
const LVT_TIMER_MODE_SHIFT: u32 = 17;
const LVT_TIMER_MODE_MASK: u32 = 0x3 << LVT_TIMER_MODE_SHIFT;

// Timer modes
const TIMER_MODE_ONESHOT: u32 = 0;
const TIMER_MODE_PERIODIC: u32 = 1;
const TIMER_MODE_TSC_DEADLINE: u32 = 2;

// SVR bits
const SVR_APIC_ENABLED: u32 = 1 << 8;

// ICR (Interrupt Command Register) field definitions
const ICR_VECTOR_MASK: u64 = 0xFF;
const ICR_DELIVERY_MODE_SHIFT: u64 = 8;
const ICR_DELIVERY_MODE_MASK: u64 = 0x7 << ICR_DELIVERY_MODE_SHIFT;
const ICR_DEST_MODE_LOGICAL: u64 = 1 << 11;
const ICR_DELIVERY_STATUS: u64 = 1 << 12; // Read-only, 0 = idle, 1 = pending
const ICR_LEVEL_ASSERT: u64 = 1 << 14;
const ICR_TRIGGER_LEVEL: u64 = 1 << 15;
const ICR_DEST_SHORTHAND_SHIFT: u64 = 18;
const ICR_DEST_SHORTHAND_MASK: u64 = 0x3 << ICR_DEST_SHORTHAND_SHIFT;
const ICR_DEST_FIELD_SHIFT: u64 = 56; // Bits 56-63 (in full 64-bit ICR)

// ICR Delivery Modes
const DELIVERY_MODE_FIXED: u64 = 0;
const DELIVERY_MODE_LOWEST_PRIORITY: u64 = 1;
const DELIVERY_MODE_SMI: u64 = 2;
const DELIVERY_MODE_NMI: u64 = 4;
const DELIVERY_MODE_INIT: u64 = 5;
const DELIVERY_MODE_SIPI: u64 = 6; // Start-up IPI

// ICR Destination Shorthands
const DEST_SHORTHAND_NONE: u64 = 0;
const DEST_SHORTHAND_SELF: u64 = 1;
const DEST_SHORTHAND_ALL_INCLUDING_SELF: u64 = 2;
const DEST_SHORTHAND_ALL_EXCLUDING_SELF: u64 = 3;

/// LAPIC timer frequency (approximate - 1 GHz bus clock / 16 = ~62.5 MHz base)
/// We'll use a simulated frequency based on real time
const LAPIC_TIMER_FREQ_HZ: u64 = 1_000_000_000; // 1 GHz base frequency

/// Represents an IPI request that needs to be delivered
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpiRequest {
    /// Fixed interrupt delivery - deliver vector to target CPU(s)
    Fixed { vector: u8, target: IpiTarget },
    /// Lowest priority - deliver to CPU with lowest priority (treated as Fixed for single CPU)
    LowestPriority { vector: u8, target: IpiTarget },
    /// Non-maskable interrupt
    Nmi { target: IpiTarget },
    /// System management interrupt
    Smi { target: IpiTarget },
    /// INIT - reset target CPU to wait-for-SIPI state
    Init { target: IpiTarget },
    /// Start-up IPI - start target CPU at specified vector * 0x1000
    Sipi { vector: u8, target: IpiTarget },
}

/// Target specification for an IPI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpiTarget {
    /// Send to self only
    ToSelf,
    /// Send to all CPUs including self
    AllIncludingSelf,
    /// Send to all CPUs excluding self
    AllExcludingSelf,
    /// Send to specific CPU by physical APIC ID
    Physical(u8),
    /// Send to CPUs matching logical destination
    Logical { destination: u8 },
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LocalApic {
    /// LAPIC ID (usually matches CPU ID)
    id: u32,
    /// LAPIC Version register
    version: u32,
    /// Task Priority Register
    tpr: u32,
    /// Logical Destination Register
    ldr: u32,
    /// Destination Format Register
    dfr: u32,
    /// Spurious Interrupt Vector Register
    svr: u32,
    /// In-Service Register (256 bits = 8 x 32-bit words)
    isr: [u32; 8],
    /// Trigger Mode Register (256 bits = 8 x 32-bit words)
    tmr: [u32; 8],
    /// Interrupt Request Register (256 bits = 8 x 32-bit words)
    irr: [u32; 8],
    /// Error Status Register
    esr: u32,
    /// Interrupt Command Register (64-bit)
    icr: u64,
    /// LVT Timer Register
    lvt_timer: u32,
    /// LVT Thermal Sensor Register
    lvt_thermal: u32,
    /// LVT Performance Counter Register
    lvt_pmc: u32,
    /// LVT LINT0 Register
    lvt_lint0: u32,
    /// LVT LINT1 Register
    lvt_lint1: u32,
    /// LVT Error Register
    lvt_error: u32,
    /// Timer Initial Count Register
    timer_initial_count: u32,
    /// Timer Current Count (computed dynamically)
    timer_current_count: u32,
    /// Timer Divide Configuration Register
    timer_divide_config: u32,
    /// Timestamp when timer was started. Transient host wall-clock state — not
    /// part of the persisted device state; re-armed lazily after restore.
    #[serde(skip)]
    timer_start: Option<Instant>,
    #[serde(skip)]
    timer_elapsed_base_nanos: u128,
    /// Pending timer interrupt
    timer_pending: bool,
    /// Pending IPI request (for VMM to process)
    pending_ipi: Option<IpiRequest>,
    /// Coordinator-owned outgoing messages. Base legacy codecs remain stable;
    /// the execution checkpoint section carries this complete FIFO explicitly.
    #[serde(skip)]
    pending_ipis: std::collections::VecDeque<IpiRequest>,
    #[serde(skip)]
    coordinated_ipis: bool,
    /// Pending NMI to deliver
    nmi_pending: bool,
}

impl LocalApic {
    pub fn new(apic_id: u32) -> Self {
        // Configure for virtual wire mode (what BIOS would normally do):
        // - APIC enabled (SVR bit 8 = 1)
        // - LINT0 configured for ExtInt mode (delivery mode 7 = external interrupt)
        // - LINT1 configured for NMI (delivery mode 4)
        //
        // LINT0 value: delivery_mode=7 (ExtInt), not masked = 0x700
        // LINT1 value: delivery_mode=4 (NMI), not masked = 0x400
        LocalApic {
            id: apic_id << 24, // ID is in bits 24-31
            // Version: bits 0-7 = version (0x14 = modern APIC)
            // bits 16-23 = max LVT entry (6 entries = 0x05)
            version: 0x00050014,
            tpr: 0,
            ldr: 0,
            dfr: 0xFFFFFFFF, // Flat model
            svr: 0x1FF,      // APIC enabled (bit 8), spurious vector 0xFF
            isr: [0; 8],
            tmr: [0; 8],
            irr: [0; 8],
            esr: 0,
            icr: 0,
            lvt_timer: LVT_MASK, // Masked initially
            lvt_thermal: LVT_MASK,
            lvt_pmc: LVT_MASK,
            lvt_lint0: 0x700, // ExtInt mode, not masked - virtual wire mode
            lvt_lint1: 0x400, // NMI mode, not masked
            lvt_error: LVT_MASK,
            timer_initial_count: 0,
            timer_current_count: 0,
            timer_divide_config: 0,
            timer_start: None,
            timer_elapsed_base_nanos: 0,
            timer_pending: false,
            pending_ipi: None,
            pending_ipis: Default::default(),
            coordinated_ipis: false,
            nmi_pending: false,
        }
    }

    /// Check if APIC is enabled
    pub fn is_enabled(&self) -> bool {
        (self.svr & SVR_APIC_ENABLED) != 0
    }

    /// Get the timer divisor from the divide configuration register
    fn timer_divisor(&self) -> u32 {
        // DCR bits 0-1 and bit 3 encode the divisor
        // 0b0000 = /2, 0b0001 = /4, 0b0010 = /8, 0b0011 = /16
        // 0b1000 = /32, 0b1001 = /64, 0b1010 = /128, 0b1011 = /1
        let bits = (self.timer_divide_config & 0x3) | ((self.timer_divide_config >> 1) & 0x4);
        match bits {
            0b000 => 2,
            0b001 => 4,
            0b010 => 8,
            0b011 => 16,
            0b100 => 32,
            0b101 => 64,
            0b110 => 128,
            0b111 => 1,
            _ => 1,
        }
    }

    /// Get the timer mode from LVT timer register
    fn timer_mode(&self) -> u32 {
        (self.lvt_timer & LVT_TIMER_MODE_MASK) >> LVT_TIMER_MODE_SHIFT
    }

    /// Check if timer is masked
    fn timer_masked(&self) -> bool {
        (self.lvt_timer & LVT_MASK) != 0
    }

    /// Get the timer vector
    pub fn timer_vector(&self) -> u8 {
        (self.lvt_timer & 0xFF) as u8
    }

    // floor(elapsed_ns * frequency_hz / 1e9) without a potentially
    // overflowing product. The modeled frequency is at most1GHz, so both
    // the whole-second product and its fractional addition fit in u128.
    fn elapsed_timer_ticks(elapsed_nanos: u128, divisor: u64) -> u128 {
        const NANOS_PER_SECOND: u128 = 1_000_000_000;
        let frequency = u128::from(LAPIC_TIMER_FREQ_HZ / divisor);
        (elapsed_nanos / NANOS_PER_SECOND) * frequency
            + (elapsed_nanos % NANOS_PER_SECOND) * frequency / NANOS_PER_SECOND
    }

    /// Tick the timer and return pending interrupt vector if any
    pub fn tick(&mut self) -> Option<u8> {
        self.tick_at(Instant::now())
    }

    fn tick_at(&mut self, now: Instant) -> Option<u8> {
        if !self.is_enabled() || self.timer_initial_count == 0 || self.timer_masked() {
            return None;
        }

        let Some(start) = self.timer_start else {
            return None;
        };

        let elapsed_nanos = self
            .timer_elapsed_base_nanos
            .saturating_add(now.saturating_duration_since(start).as_nanos());
        let divisor = self.timer_divisor() as u64;

        // Calculate how many timer ticks have elapsed
        let elapsed_ticks = Self::elapsed_timer_ticks(elapsed_nanos, divisor);

        let initial = u128::from(self.timer_initial_count);
        let mode = self.timer_mode();

        match mode {
            TIMER_MODE_ONESHOT => {
                if elapsed_ticks >= initial {
                    // Timer expired
                    self.timer_current_count = 0;
                    self.timer_start = None; // Stop the timer
                    if !self.timer_pending {
                        self.timer_pending = true;
                        return Some(self.timer_vector());
                    }
                } else {
                    self.timer_current_count = (initial - elapsed_ticks) as u32;
                }
            }
            TIMER_MODE_PERIODIC => {
                // In periodic mode, timer restarts automatically
                let periods = elapsed_ticks / initial;
                let remainder = elapsed_ticks % initial;
                self.timer_current_count = (initial - remainder) as u32;

                // Advance the phase even when a previous expiry remains
                // pending. Coalesced periods must not be delivered again after
                // that pending latch is accepted or transferred to IRR.
                if periods > 0 {
                    let period_nanos = initial * u128::from(divisor);
                    self.timer_elapsed_base_nanos = elapsed_nanos % period_nanos;
                    self.timer_start = Some(now);
                    if !self.timer_pending {
                        self.timer_pending = true;
                        return Some(self.timer_vector());
                    }
                }
            }
            TIMER_MODE_TSC_DEADLINE => {
                // TSC-deadline mode uses MSR, not implemented yet
            }
            _ => {}
        }

        None
    }

    /// Clear pending timer interrupt (called after injection)
    pub fn clear_timer_pending(&mut self) {
        self.timer_pending = false;
    }

    /// Check if there's a pending timer interrupt
    pub fn has_pending_timer(&self) -> bool {
        self.timer_pending
    }

    /// Get the APIC ID (bits 24-31 of the ID register)
    pub fn apic_id(&self) -> u8 {
        (self.id >> 24) as u8
    }

    /// Check if there's a pending NMI
    pub fn has_pending_nmi(&self) -> bool {
        self.nmi_pending
    }

    /// Clear pending NMI (called after delivery)
    pub fn clear_pending_nmi(&mut self) {
        self.nmi_pending = false;
    }

    /// Take pending IPI request (returns and clears it)
    pub fn take_pending_ipi(&mut self) -> Option<IpiRequest> {
        self.pending_ipi
            .take()
            .or_else(|| self.pending_ipis.pop_front())
    }

    /// Check if there's a pending IPI
    pub fn has_pending_ipi(&self) -> bool {
        self.pending_ipi.is_some() || !self.pending_ipis.is_empty()
    }

    pub(crate) fn enable_coordinated_delivery(&mut self) {
        self.coordinated_ipis = true;
        if let Some(request) = self.pending_ipi.take() {
            self.pending_ipis.push_front(request);
        }
    }

    fn enqueue_ipi(&mut self, request: IpiRequest) {
        if self.coordinated_ipis {
            self.pending_ipis.push_back(request);
        } else {
            self.pending_ipi = Some(request);
        }
    }

    pub(crate) fn set_pending_nmi(&mut self) {
        self.nmi_pending = true;
    }

    /// Intel SDM086 Vol.3A12.4.7.1/3: INIT clears controller registers,
    /// masks every LVT and disables the APIC, preserving its assigned ID.
    pub(crate) fn reset_for_init(&mut self) {
        let id = self.id;
        let version = self.version;
        let pending = self.pending_ipi.take();
        let pending_ipis = std::mem::take(&mut self.pending_ipis);
        let coordinated = self.coordinated_ipis;
        *self = Self::new(u32::from(self.apic_id()));
        self.id = id;
        self.version = version;
        self.svr = 0xff;
        self.lvt_lint0 = LVT_MASK;
        self.lvt_lint1 = LVT_MASK;
        self.pending_ipi = pending;
        self.pending_ipis = pending_ipis;
        self.coordinated_ipis = coordinated;
    }

    fn record_error(&mut self, bits: u32) {
        self.esr |= bits;
        if self.is_enabled() && self.lvt_error & LVT_MASK == 0 {
            let vector = (self.lvt_error & 0xff) as u8;
            if vector >= 16 {
                self.set_irr(vector);
            } else {
                // An invalid error-LVT vector cannot recursively raise itself.
                self.esr |= 1 << 6;
            }
        }
    }

    pub(crate) fn receive_fixed_interrupt(&mut self, vector: u8) {
        if vector >= 16 {
            self.set_irr(vector);
        } else {
            self.record_error(1 << 6);
        }
    }

    /// Handle IPI delivery when ICR is written.
    /// For self-targeted IPIs, this updates local state (IRR/NMI).
    /// For other CPUs, returns an IpiRequest for the VMM to handle.
    fn handle_ipi(&mut self) {
        let icr = self.icr;
        let vector = (icr & ICR_VECTOR_MASK) as u8;
        let delivery_mode = (icr & ICR_DELIVERY_MODE_MASK) >> ICR_DELIVERY_MODE_SHIFT;
        let dest_mode_logical = (icr & ICR_DEST_MODE_LOGICAL) != 0;
        let level_assert = (icr & ICR_LEVEL_ASSERT) != 0;
        let shorthand = (icr & ICR_DEST_SHORTHAND_MASK) >> ICR_DEST_SHORTHAND_SHIFT;
        let dest_field = ((icr >> ICR_DEST_FIELD_SHIFT) & 0xFF) as u8;

        // Intel SDM086 Vol.3A12.5.3: vectors0..15 are illegal for
        // fixed/lowest-priority delivery; they never enter a recipient's IRR.
        if matches!(
            delivery_mode,
            DELIVERY_MODE_FIXED | DELIVERY_MODE_LOWEST_PRIORITY
        ) && vector < 16
        {
            self.record_error(1 << 5);
            return;
        }

        tracing::debug!(
            "LAPIC IPI: vector={:#x}, delivery_mode={}, dest_mode={}, shorthand={}, dest={:#x}, level_assert={}",
            vector,
            delivery_mode,
            if dest_mode_logical {
                "logical"
            } else {
                "physical"
            },
            shorthand,
            dest_field,
            level_assert
        );

        // Determine target
        let target = match shorthand {
            DEST_SHORTHAND_SELF => IpiTarget::ToSelf,
            DEST_SHORTHAND_ALL_INCLUDING_SELF => IpiTarget::AllIncludingSelf,
            DEST_SHORTHAND_ALL_EXCLUDING_SELF => IpiTarget::AllExcludingSelf,
            DEST_SHORTHAND_NONE => {
                if dest_mode_logical {
                    IpiTarget::Logical {
                        destination: dest_field,
                    }
                } else {
                    IpiTarget::Physical(dest_field)
                }
            }
            _ => return, // Invalid shorthand
        };

        // A standalone APIC keeps its existing immediate local-delivery
        // interface. A coordinated fabric resolves the full destination set,
        // including cluster mode and lowest-priority arbitration, exactly once.
        if self.coordinated_ipis && !matches!(target, IpiTarget::ToSelf) {
            let request = match delivery_mode {
                DELIVERY_MODE_FIXED => Some(IpiRequest::Fixed { vector, target }),
                DELIVERY_MODE_LOWEST_PRIORITY => {
                    Some(IpiRequest::LowestPriority { vector, target })
                }
                DELIVERY_MODE_NMI => Some(IpiRequest::Nmi { target }),
                DELIVERY_MODE_SMI => Some(IpiRequest::Smi { target }),
                DELIVERY_MODE_INIT if level_assert => Some(IpiRequest::Init { target }),
                DELIVERY_MODE_SIPI => Some(IpiRequest::Sipi { vector, target }),
                _ => None,
            };
            if let Some(request) = request {
                self.enqueue_ipi(request);
            }
            return;
        }

        // Check if this IPI targets self
        let targets_self = match &target {
            IpiTarget::ToSelf => true,
            IpiTarget::AllIncludingSelf => true,
            IpiTarget::AllExcludingSelf => false,
            IpiTarget::Physical(id) => *id == self.apic_id(),
            IpiTarget::Logical { destination } => {
                // Check if our logical ID matches
                // In flat model (DFR = 0xFFFFFFFF), LDR bits 24-31 are the logical ID
                // Match if any bit in destination matches any bit in our logical ID
                let our_logical_id = (self.ldr >> 24) as u8;
                (destination & our_logical_id) != 0
            }
        };

        // Handle delivery based on mode
        match delivery_mode {
            DELIVERY_MODE_FIXED | DELIVERY_MODE_LOWEST_PRIORITY => {
                if targets_self {
                    // Deliver to self immediately by setting IRR
                    self.set_irr(vector);
                    tracing::debug!("LAPIC: Self-IPI vector {:#x} delivered to IRR", vector);
                }
                // Store IPI request for VMM to deliver to other CPUs
                if !matches!(target, IpiTarget::ToSelf) {
                    self.enqueue_ipi(if delivery_mode == DELIVERY_MODE_FIXED {
                        IpiRequest::Fixed { vector, target }
                    } else {
                        IpiRequest::LowestPriority { vector, target }
                    });
                }
            }
            DELIVERY_MODE_NMI => {
                if targets_self {
                    self.nmi_pending = true;
                    tracing::debug!("LAPIC: Self-NMI pending");
                }
                if !matches!(target, IpiTarget::ToSelf) {
                    self.enqueue_ipi(IpiRequest::Nmi { target });
                }
            }
            DELIVERY_MODE_SMI => {
                // SMI is system-level, store for VMM
                self.enqueue_ipi(IpiRequest::Smi { target });
                tracing::debug!("LAPIC: SMI requested");
            }
            DELIVERY_MODE_INIT => {
                // INIT resets target CPU to wait-for-SIPI state
                // Level de-assert (level=0) is used for INIT synchronization, ignore it
                if level_assert {
                    self.enqueue_ipi(IpiRequest::Init {
                        target: target.clone(),
                    });
                    tracing::debug!("LAPIC: INIT IPI requested");
                } else {
                    tracing::debug!("LAPIC: INIT level de-assert (ignored)");
                }
            }
            DELIVERY_MODE_SIPI => {
                // Start-up IPI - vector specifies start address (vector * 0x1000)
                self.enqueue_ipi(IpiRequest::Sipi { vector, target });
                tracing::debug!(
                    "LAPIC: SIPI vector={:#x} (start addr={:#x})",
                    vector,
                    (vector as u32) * 0x1000
                );
            }
            _ => {
                tracing::warn!("LAPIC: Unknown delivery mode {}", delivery_mode);
            }
        }
    }

    /// Get pending interrupt vector (highest priority)
    pub fn get_pending_vector(&self) -> Option<u8> {
        // Check IRR for pending interrupts
        for i in (0..8).rev() {
            if self.irr[i] != 0 {
                for bit in (0..32).rev() {
                    if self.irr[i] & (1 << bit) != 0 {
                        return Some((i * 32 + bit) as u8);
                    }
                }
            }
        }
        None
    }

    /// Set an interrupt as pending in IRR
    pub fn set_irr(&mut self, vector: u8) {
        let idx = (vector / 32) as usize;
        let bit = vector % 32;
        self.irr[idx] |= 1 << bit;
    }

    /// Acknowledge interrupt (move from IRR to ISR)
    pub fn ack_interrupt(&mut self, vector: u8) {
        let idx = (vector / 32) as usize;
        let bit = vector % 32;
        self.irr[idx] &= !(1 << bit);
        self.isr[idx] |= 1 << bit;
    }

    /// End of interrupt - clear highest priority ISR bit
    fn eoi(&mut self) {
        // Find highest priority in-service interrupt and clear it
        for i in (0..8).rev() {
            if self.isr[i] != 0 {
                for bit in (0..32).rev() {
                    if self.isr[i] & (1 << bit) != 0 {
                        self.isr[i] &= !(1 << bit);
                        return;
                    }
                }
            }
        }
    }

    pub(crate) fn read_register(&self, offset: u64) -> u32 {
        match offset {
            LAPIC_ID => self.id,
            LAPIC_VERSION => self.version,
            LAPIC_TPR => self.tpr,
            LAPIC_APR => 0, // Arbitration priority (read-only, usually 0)
            LAPIC_PPR => {
                // Processor priority = max(TPR, highest ISR priority)
                let tpr_class = (self.tpr >> 4) & 0xF;
                let mut max_isr = 0u32;
                for i in (0..8).rev() {
                    if self.isr[i] != 0 {
                        for bit in (0..32).rev() {
                            if self.isr[i] & (1 << bit) != 0 {
                                max_isr = ((i * 32 + bit) >> 4) as u32;
                                break;
                            }
                        }
                        break;
                    }
                }
                std::cmp::max(tpr_class, max_isr) << 4
            }
            LAPIC_RRD => 0,
            LAPIC_LDR => self.ldr,
            LAPIC_DFR => self.dfr,
            LAPIC_SVR => self.svr,
            o if o >= LAPIC_ISR_BASE && o < LAPIC_ISR_BASE + 0x80 => {
                let idx = ((o - LAPIC_ISR_BASE) / 0x10) as usize;
                if idx < 8 { self.isr[idx] } else { 0 }
            }
            o if o >= LAPIC_TMR_BASE && o < LAPIC_TMR_BASE + 0x80 => {
                let idx = ((o - LAPIC_TMR_BASE) / 0x10) as usize;
                if idx < 8 { self.tmr[idx] } else { 0 }
            }
            o if o >= LAPIC_IRR_BASE && o < LAPIC_IRR_BASE + 0x80 => {
                let idx = ((o - LAPIC_IRR_BASE) / 0x10) as usize;
                if idx < 8 { self.irr[idx] } else { 0 }
            }
            LAPIC_ESR => self.esr,
            LAPIC_ICR_LOW => self.icr as u32,
            LAPIC_ICR_HIGH => (self.icr >> 32) as u32,
            LAPIC_LVT_TIMER => self.lvt_timer,
            LAPIC_LVT_THERMAL => self.lvt_thermal,
            LAPIC_LVT_PMC => self.lvt_pmc,
            LAPIC_LVT_LINT0 => self.lvt_lint0,
            LAPIC_LVT_LINT1 => self.lvt_lint1,
            LAPIC_LVT_ERROR => self.lvt_error,
            LAPIC_TIMER_ICR => self.timer_initial_count,
            LAPIC_TIMER_CCR => {
                // Current count must be computed dynamically on every read
                // The kernel uses this for timer calibration
                if self.timer_initial_count == 0 {
                    0
                } else if let Some(start) = self.timer_start {
                    let now = Instant::now();
                    let elapsed_nanos = self
                        .timer_elapsed_base_nanos
                        .saturating_add(now.saturating_duration_since(start).as_nanos());
                    let divisor = self.timer_divisor() as u64;

                    // Calculate how many timer ticks have elapsed
                    let elapsed_ticks = Self::elapsed_timer_ticks(elapsed_nanos, divisor);
                    let initial = u128::from(self.timer_initial_count);

                    let mode = self.timer_mode();
                    match mode {
                        TIMER_MODE_ONESHOT => {
                            if elapsed_ticks >= initial {
                                0
                            } else {
                                (initial - elapsed_ticks) as u32
                            }
                        }
                        TIMER_MODE_PERIODIC => {
                            // In periodic mode, wrap around
                            let remainder = elapsed_ticks % initial;
                            (initial - remainder) as u32
                        }
                        _ => 0, // TSC-deadline mode returns 0
                    }
                } else {
                    self.timer_current_count
                }
            }
            LAPIC_TIMER_DCR => self.timer_divide_config,
            _ => 0,
        }
    }

    pub(crate) fn write_register(&mut self, offset: u64, value: u32) {
        match offset {
            LAPIC_ID => {
                // ID is in bits 24-31
                self.id = value & 0xFF000000;
            }
            LAPIC_TPR => {
                self.tpr = value & 0xFF;
            }
            LAPIC_EOI => {
                // Any write triggers EOI
                self.eoi();
            }
            LAPIC_LDR => {
                self.ldr = value;
            }
            LAPIC_DFR => {
                self.dfr = value;
            }
            LAPIC_SVR => {
                let was_enabled = self.is_enabled();
                self.svr = value;
                if !was_enabled && self.is_enabled() {
                    // APIC just got enabled
                    tracing::debug!("LAPIC enabled, SVR={:#x}", value);
                }
            }
            LAPIC_ESR => {
                // Writing clears the ESR
                self.esr = 0;
            }
            LAPIC_ICR_LOW => {
                self.icr = (self.icr & 0xFFFFFFFF00000000) | (value as u64);
                // Writing to ICR_LOW triggers IPI delivery
                self.handle_ipi();
            }
            LAPIC_ICR_HIGH => {
                self.icr = (self.icr & 0x00000000FFFFFFFF) | ((value as u64) << 32);
            }
            LAPIC_LVT_TIMER => {
                self.lvt_timer = value;
                tracing::debug!(
                    "LVT Timer set: vector={:#x}, mode={}, masked={}",
                    value & 0xFF,
                    (value >> 17) & 0x3,
                    (value & LVT_MASK) != 0
                );
            }
            LAPIC_LVT_THERMAL => {
                self.lvt_thermal = value;
            }
            LAPIC_LVT_PMC => {
                self.lvt_pmc = value;
            }
            LAPIC_LVT_LINT0 => {
                self.lvt_lint0 = value;
            }
            LAPIC_LVT_LINT1 => {
                self.lvt_lint1 = value;
            }
            LAPIC_LVT_ERROR => {
                self.lvt_error = value;
            }
            LAPIC_TIMER_ICR => {
                self.timer_initial_count = value;
                self.timer_current_count = value;
                if value > 0 {
                    self.timer_start = Some(Instant::now());
                    self.timer_elapsed_base_nanos = 0;
                    self.timer_pending = false;
                    tracing::debug!(
                        "LAPIC timer started: initial_count={}, divisor={}, mode={}",
                        value,
                        self.timer_divisor(),
                        self.timer_mode()
                    );
                } else {
                    self.timer_start = None;
                }
            }
            LAPIC_TIMER_DCR => {
                self.timer_divide_config = value & 0xB; // Only bits 0,1,3 are valid
                tracing::debug!("LAPIC timer divisor set to {}", self.timer_divisor());
            }
            _ => {}
        }
    }
}

/// LAPIC MMIO device wrapper
pub struct LapicDevice {
    lapic: std::sync::Arc<std::sync::Mutex<LocalApic>>,
}

impl LapicDevice {
    pub fn new(lapic: std::sync::Arc<std::sync::Mutex<LocalApic>>) -> Self {
        LapicDevice { lapic }
    }
}

impl MmioDevice for LapicDevice {
    fn read(&mut self, addr: u64, data: &mut [u8]) {
        let offset = addr - LAPIC_BASE;
        // LAPIC registers are 32-bit aligned
        let aligned_offset = offset & !0x3;

        if let Ok(lapic) = self.lapic.lock() {
            let value = lapic.read_register(aligned_offset);
            // Handle different read sizes
            match data.len() {
                1 => {
                    let byte_offset = (offset & 0x3) as usize;
                    data[0] = ((value >> (byte_offset * 8)) & 0xFF) as u8;
                }
                2 => {
                    let byte_offset = (offset & 0x2) as usize;
                    let word = ((value >> (byte_offset * 8)) & 0xFFFF) as u16;
                    data[0] = (word & 0xFF) as u8;
                    data[1] = ((word >> 8) & 0xFF) as u8;
                }
                4 => {
                    data[0] = (value & 0xFF) as u8;
                    data[1] = ((value >> 8) & 0xFF) as u8;
                    data[2] = ((value >> 16) & 0xFF) as u8;
                    data[3] = ((value >> 24) & 0xFF) as u8;
                }
                _ => {
                    for byte in data.iter_mut() {
                        *byte = 0;
                    }
                }
            }
        } else {
            for byte in data.iter_mut() {
                *byte = 0xFF;
            }
        }
    }

    fn write(&mut self, addr: u64, data: &[u8]) {
        let offset = addr - LAPIC_BASE;
        let aligned_offset = offset & !0x3;

        // Reconstruct 32-bit value from data
        let value = match data.len() {
            1 => data[0] as u32,
            2 => (data[0] as u32) | ((data[1] as u32) << 8),
            4 => {
                (data[0] as u32)
                    | ((data[1] as u32) << 8)
                    | ((data[2] as u32) << 16)
                    | ((data[3] as u32) << 24)
            }
            _ => return,
        };

        if let Ok(mut lapic) = self.lapic.lock() {
            lapic.write_register(aligned_offset, value);
        }
    }
}

#[cfg(test)]
#[path = "lapic/tests.rs"]
mod tests;

mod checkpoint;
pub(crate) use checkpoint::LapicCheckpoint;
