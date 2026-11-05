//! Complete local-controller state for the required execution checkpoint section.
use super::*;

#[derive(Clone)]
pub(crate) struct LapicCheckpoint {
    pub(crate) registers: LocalApic,
    pub(crate) queued: std::collections::VecDeque<IpiRequest>,
    pub(crate) eois: std::collections::VecDeque<u8>,
    pub(crate) timer_age_nanos: Option<u128>,
}

impl LocalApic {
    /// Detach runtime clock identity from captured register images.
    pub(crate) fn checkpoint_registers(&self) -> Self {
        let mut registers = self.clone();
        registers.timer_clock = TimerClock::default();
        registers.pending_eois.clear();
        registers
    }

    pub(crate) fn resume_timer_at(&mut self, now: Instant) {
        if self.timer_start.is_some() {
            self.timer_start = Some(now);
        }
    }

    pub(crate) fn checkpoint_at(&self, now: Instant) -> LapicCheckpoint {
        let timer_age_nanos = self.timer_start.map(|start| {
            self.timer_elapsed_base_nanos
                .saturating_add(self.timer_clock.sample(start, now).elapsed_nanos)
        });
        let mut registers = self.checkpoint_registers();
        registers.pending_ipis.clear();
        registers.pending_eois.clear();
        LapicCheckpoint {
            registers,
            queued: self.pending_ipis.clone(),
            eois: self.pending_eois.clone(),
            timer_age_nanos,
        }
    }
}

impl LapicCheckpoint {
    pub(crate) fn prepare_for_clock(
        &self,
        now: Instant,
        clock: &std::sync::Arc<crate::vm::timing::TimingContext>,
        incoming_nanos: u64,
    ) -> LocalApic {
        let mut apic = self.prepare(now);
        apic.timer_clock = TimerClock::prepared(clock.clone(), incoming_nanos);
        apic
    }

    pub(crate) fn prepare(&self, now: Instant) -> LocalApic {
        let mut apic = self.registers.clone();
        apic.pending_ipis = self.queued.clone();
        apic.pending_eois = self.eois.clone();
        apic.coordinated_ipis = true;
        apic.timer_start = self.timer_age_nanos.map(|_| now);
        apic.timer_elapsed_base_nanos = self.timer_age_nanos.unwrap_or(0);
        apic
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_eoi_broadcasts_retain_trigger_mode_and_respect_suppression() {
        for suppressed in [false, true] {
            let mut apic = LocalApic::new(0);
            apic.write_register(LAPIC_SVR, 0x1ff | (u32::from(suppressed) << 12));
            apic.receive_external_interrupt(0x51, true);
            assert_eq!(apic.read_register(0x1a0), 1 << 17);
            apic.ack_interrupt(0x51);
            apic.write_register(LAPIC_EOI, 0);
            assert_eq!(apic.read_register(0x120), 0);
            assert_eq!(apic.read_register(0x1a0), 1 << 17);
            assert_eq!(apic.take_pending_eoi(), (!suppressed).then_some(0x51));
            apic.write_register(LAPIC_EOI, 0);
            assert_eq!(apic.take_pending_eoi(), None);
            // A subsequent edge replaces that vector's trigger-mode bit.
            apic.receive_external_interrupt(0x51, false);
            assert_eq!(apic.read_register(0x1a0), 0);
            apic.ack_interrupt(0x51);
            apic.write_register(LAPIC_EOI, 0);
            assert_eq!(apic.take_pending_eoi(), None);
        }
    }

    #[test]
    fn completed_eoi_broadcast_fifo_survives_source_free_checkpoint_and_init() {
        let mut source = LocalApic::new(3);
        for vector in [0x51, 0x61, 0x51] {
            source.receive_external_interrupt(vector, true);
            source.ack_interrupt(vector);
            source.write_register(LAPIC_EOI, 0);
        }
        let saved = source.checkpoint_at(Instant::now());
        assert_eq!(saved.eois, [0x51, 0x61, 0x51]);
        assert!(saved.registers.pending_eois.is_empty());
        drop(source);
        let mut restored = saved.prepare(Instant::now());
        restored.reset_for_init();
        for vector in [0x51, 0x61, 0x51] {
            assert_eq!(restored.take_pending_eoi(), Some(vector));
        }
        assert_eq!(restored.take_pending_eoi(), None);
    }

    #[test]
    fn forty_second_timer_age_does_not_wrap_the_nanosecond_frequency_product() {
        let mut apic = LocalApic::new(0);
        apic.write_register(LAPIC_LVT_TIMER, 0x41);
        apic.write_register(LAPIC_TIMER_DCR, 0b1011);
        apic.write_register(LAPIC_TIMER_ICR, u32::MAX);
        apic.timer_elapsed_base_nanos = 40_000_000_000;
        assert_eq!(apic.tick(), Some(0x41));
        assert_eq!(apic.read_register(LAPIC_TIMER_CCR), 0);
        assert!(apic.has_pending_timer());
    }

    #[test]
    fn checkpoint_restores_timer_age_and_an_independent_fifo() {
        let now = Instant::now();
        let mut apic = LocalApic::new(0);
        apic.enable_coordinated_delivery();
        apic.write_register(LAPIC_ICR_HIGH, 1 << 24);
        for vector in [0x41, 0x42] {
            apic.write_register(LAPIC_ICR_LOW, vector);
        }
        apic.write_register(LAPIC_LVT_TIMER, 0x0002_0041);
        apic.write_register(LAPIC_TIMER_DCR, 0b1011);
        apic.write_register(LAPIC_TIMER_ICR, 1_000_000);
        apic.timer_start = Some(now);
        apic.timer_elapsed_base_nanos = 1_250_000;
        let saved = apic.checkpoint_at(now);
        assert_eq!(saved.timer_age_nanos, Some(1_250_000));
        apic.take_pending_ipi().unwrap();
        assert_eq!(
            saved.queued.len(),
            2,
            "snapshot does not share the live FIFO"
        );
        let resume = now + std::time::Duration::from_secs(86400);
        let mut restored = saved.prepare(resume);
        assert_eq!(
            restored.checkpoint_at(resume).timer_age_nanos,
            Some(1_250_000)
        );
        for vector in [0x41, 0x42] {
            assert!(matches!(restored.take_pending_ipi(),
                Some(IpiRequest::Fixed { vector: actual, target: IpiTarget::Physical(1) }) if actual == vector));
        }
        assert!(!restored.has_pending_ipi());
    }

    #[test]
    fn required_execution_fields_do_not_change_the_legacy_lapic_wire() {
        let apic = LocalApic::new(3);
        let mut transient = apic.clone();
        transient.enable_coordinated_delivery();
        transient.timer_start = Some(Instant::now());
        transient.timer_elapsed_base_nanos = 1234567;
        transient.pending_ipis.push_back(IpiRequest::Sipi {
            vector: 9,
            target: IpiTarget::Physical(1),
        });
        assert_eq!(
            crate::codec::serialize(&apic).unwrap(),
            crate::codec::serialize(&transient).unwrap()
        );
    }

    #[test]
    fn coalesced_periods_do_not_reappear_after_the_pending_latch_is_cleared() {
        let now = Instant::now();
        let mut apic = LocalApic::new(0);
        apic.write_register(LAPIC_LVT_TIMER, 0x0002_0041);
        apic.write_register(LAPIC_TIMER_DCR, 0b1011);
        apic.write_register(LAPIC_TIMER_ICR, 1_000_000);
        apic.timer_start = Some(now);
        apic.timer_elapsed_base_nanos = 2_250_000;
        apic.timer_pending = true;
        assert_eq!(apic.tick_at(now), None);
        apic.clear_timer_pending();
        assert_eq!(
            apic.tick_at(now + std::time::Duration::from_nanos(1)),
            None,
            "two old, coalesced periods cannot become a new interrupt"
        );
        assert_eq!(
            apic.tick_at(now + std::time::Duration::from_nanos(750_000)),
            Some(0x41)
        );
    }

    #[test]
    fn maximum_u64_age_plus_one_retains_full_elapsed_history() {
        let now = Instant::now();
        let mut apic = LocalApic::new(0);
        apic.write_register(LAPIC_LVT_TIMER, 0x0002_0041);
        apic.write_register(LAPIC_TIMER_DCR, 0b1011);
        apic.write_register(LAPIC_TIMER_ICR, 1_000_000);
        apic.timer_start = Some(now);
        apic.timer_elapsed_base_nanos = u128::from(u64::MAX);
        let saved = apic.checkpoint_at(now + std::time::Duration::from_nanos(1));
        assert_eq!(saved.timer_age_nanos, Some(u128::from(u64::MAX) + 1));
        let resumed = saved.prepare(now);
        assert_eq!(
            resumed.checkpoint_at(now).timer_age_nanos,
            saved.timer_age_nanos
        );
    }

    #[test]
    fn every_divisor_counts_wide_nanosecond_values_without_overflow() {
        for nanos in [
            0,
            1,
            u128::from(u64::MAX),
            u128::from(u64::MAX) + 1,
            u128::MAX,
        ] {
            for divisor in [1, 2, 4, 8, 16, 32, 64, 128] {
                // The1GHz modeled source emits exactly one tick per ns before
                // division; the reference needs no potentially wide product.
                assert_eq!(
                    LocalApic::elapsed_timer_ticks(nanos, divisor),
                    nanos / u128::from(divisor)
                );
            }
        }
    }
}
