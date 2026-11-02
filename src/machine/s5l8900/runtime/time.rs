//! Logical elapsed anchors and wrapping 64-bit modeled timer arithmetic.
use super::S5L8900Vcpu;
use crate::error::{Error, Result};
use crate::host::time::{Duration, Instant};
use crate::vm::timing::ClockEpoch;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub(super) struct ElapsedImage {
    seconds: u64,
    nanos: u32,
}
impl ElapsedImage {
    pub(super) fn zero() -> Self {
        Self {
            seconds: 0,
            nanos: 0,
        }
    }
    fn duration(self) -> Result<Duration> {
        if self.nanos >= 1_000_000_000 {
            return Err(Error::InvalidConfig(
                "S5L elapsed nanosecond fraction is invalid".into(),
            ));
        }
        Ok(Duration::new(self.seconds, self.nanos))
    }
}

pub(super) struct ElapsedClock {
    base: Duration,
    source: ClockEpoch,
    anchor: Option<ClockEpoch>,
    resume_epoch: Option<Arc<OnceLock<ClockEpoch>>>,
}
impl ElapsedClock {
    pub(super) fn new() -> Self {
        let now = ClockEpoch::selected_at(Instant::now());
        Self {
            base: Duration::ZERO,
            source: now.clone(),
            anchor: Some(now),
            resume_epoch: None,
        }
    }
    pub(super) fn suspended(image: ElapsedImage) -> Result<Self> {
        Ok(Self {
            base: image.duration()?,
            source: ClockEpoch::selected_at(Instant::now()),
            anchor: None,
            resume_epoch: None,
        })
    }
    pub(super) fn capture_time(&self) -> ClockEpoch {
        self.source.sample()
    }
    pub(super) fn validate_domain(&self, now: &ClockEpoch) -> Result<()> {
        if !self.source.same_domain(now) {
            return Err(Error::InvalidConfig(
                "S5L elapsed clock domain differs".into(),
            ));
        }
        Ok(())
    }
    pub(super) fn capture_at(&self, now: impl Into<ClockEpoch>) -> Result<ElapsedImage> {
        let now = now.into();
        self.validate_domain(&now)?;
        let anchor = self
            .anchor
            .as_ref()
            .or_else(|| self.resume_epoch.as_ref().and_then(|epoch| epoch.get()));
        let elapsed = match anchor {
            Some(anchor) => self.base.saturating_add(now.duration_since(anchor)?),
            None => self.base,
        };
        Ok(ElapsedImage {
            seconds: elapsed.as_secs(),
            nanos: elapsed.subsec_nanos(),
        })
    }
    pub(super) fn elapsed(&self) -> Duration {
        // Samples come from this retained owner. Restore rebinds suspended clocks
        // to the target, and publication validates their domain before activation.
        // ClockEpoch is runtime-only and cannot be forged by serialized images.
        let image = self
            .capture_at(self.capture_time())
            .expect("elapsed source and activation domain admitted together");
        Duration::new(image.seconds, image.nanos)
    }
    pub(super) fn reset(&mut self) {
        self.base = Duration::ZERO;
        self.anchor = Some(self.capture_time());
        self.resume_epoch = None;
    }
    pub(super) fn rebind_suspended_to(&mut self, target: &Self) -> Result<()> {
        if self.anchor.is_some() || self.resume_epoch.is_some() {
            return Err(Error::InvalidConfig(
                "S5L elapsed clock must be suspended before rebinding".into(),
            ));
        }
        self.source = target.source.clone();
        Ok(())
    }
    pub(super) fn bind_publication_epoch(
        &mut self,
        epoch: Arc<OnceLock<ClockEpoch>>,
    ) -> Result<()> {
        if epoch.get().is_some() {
            return Err(Error::InvalidConfig(
                "S5L clock activated before publication".into(),
            ));
        }
        self.anchor = None;
        self.resume_epoch = Some(epoch);
        Ok(())
    }
    pub(super) fn resume_at(&mut self, now: impl Into<ClockEpoch>) -> Result<()> {
        let now = now.into();
        self.validate_domain(&now)?;
        if self.anchor.is_none() {
            let anchor = match &self.resume_epoch {
                Some(epoch) => epoch.get().cloned(),
                None => Some(now),
            };
            if let Some(anchor) = &anchor {
                self.validate_domain(anchor)?;
            }
            self.anchor = anchor;
        }
        Ok(())
    }
}

impl S5L8900Vcpu {
    pub(super) fn timer_ticks(&self) -> u64 {
        let micros = if self.det_timer != 0 {
            self.timer_irq_clock / self.det_timer
        } else {
            (self.boot_clock.elapsed().as_micros() as u64).wrapping_mul(self.timer_speedup)
        };
        // The model exposes a 64-bit counter. Preserve release-mode modulo
        // arithmetic on checked builds and in restored diagnostic profiles.
        micros.wrapping_mul(self.timer_mul)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn suspended_elapsed_clock_excludes_preparation_and_resumes_once() {
        let image = ElapsedImage {
            seconds: 7,
            nanos: 123_456_789,
        };
        let mut clock = ElapsedClock::suspended(image).unwrap();
        let start = Instant::now();
        let later = start + Duration::from_secs(100);
        assert_eq!(
            clock.capture_at(later).unwrap().duration().unwrap(),
            image.duration().unwrap()
        );
        clock.resume_at(start).unwrap();
        assert_eq!(
            clock
                .capture_at(start + Duration::from_nanos(11))
                .unwrap()
                .duration()
                .unwrap(),
            Duration::new(7, 123_456_800)
        );
        clock.resume_at(later).unwrap();
        assert_eq!(
            clock
                .capture_at(start + Duration::from_nanos(11))
                .unwrap()
                .duration()
                .unwrap(),
            Duration::new(7, 123_456_800)
        );
    }
    #[test]
    fn elapsed_image_rejects_noncanonical_fraction_and_saturates_at_duration_max() {
        assert!(
            ElapsedClock::suspended(ElapsedImage {
                seconds: 0,
                nanos: 1_000_000_000
            })
            .is_err()
        );
        let start = Instant::now();
        let mut clock = ElapsedClock::suspended(ElapsedImage {
            seconds: u64::MAX,
            nanos: 999_999_999,
        })
        .unwrap();
        clock.resume_at(start).unwrap();
        assert_eq!(
            clock
                .capture_at(start + Duration::from_secs(1))
                .unwrap()
                .duration()
                .unwrap(),
            Duration::MAX
        );
    }
}

#[cfg(test)]
mod publication_tests {
    use super::*;
    #[test]
    fn host_diagnostic_timer_scaling_covers_full_u64_factors() {
        use crate::machine::s5l8900::runtime::S5L8900Vcpu;
        use vm_memory::{GuestAddress, GuestMemoryMmap};
        let memory =
            Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
        let mut cpu = S5L8900Vcpu::new(0, memory);
        cpu.det_timer = 0;
        cpu.boot_clock = ElapsedClock::suspended(ElapsedImage {
            seconds: 2,
            nanos: 0,
        })
        .unwrap();
        for speed in [0, 1, 1 << 63, u64::MAX] {
            for multiplier in [0, 1, 1 << 63, u64::MAX] {
                cpu.timer_speedup = speed;
                cpu.timer_mul = multiplier;
                let first = (2_000_000u128 * u128::from(speed)) & u128::from(u64::MAX);
                let expected = (first * u128::from(multiplier)) as u64;
                assert_eq!(
                    cpu.timer_ticks(),
                    expected,
                    "speed={speed} multiplier={multiplier}"
                );
            }
        }
    }
    #[test]
    fn elapsed_starts_at_publication_even_before_first_cpu_entry() {
        let mut clock = ElapsedClock::suspended(ElapsedImage {
            seconds: 7,
            nanos: 0,
        })
        .unwrap();
        let epoch = Arc::new(OnceLock::new());
        clock.bind_publication_epoch(epoch.clone()).unwrap();
        let start = Instant::now();
        assert_eq!(
            clock
                .capture_at(start + Duration::from_secs(100))
                .unwrap()
                .duration()
                .unwrap(),
            Duration::from_secs(7)
        );
        epoch.set(start.into()).unwrap();
        assert_eq!(
            clock
                .capture_at(start + Duration::from_secs(3))
                .unwrap()
                .duration()
                .unwrap(),
            Duration::from_secs(10)
        );
        clock.resume_at(start + Duration::from_secs(100)).unwrap();
        assert_eq!(
            clock
                .capture_at(start + Duration::from_secs(3))
                .unwrap()
                .duration()
                .unwrap(),
            Duration::from_secs(10)
        );
    }
}

#[cfg(test)]
#[path = "time/selected_tests.rs"]
mod selected_tests;
