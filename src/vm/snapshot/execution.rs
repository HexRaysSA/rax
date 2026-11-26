//! Required scheduler/local-controller extension; the base v8 wire stays stable.
use super::Snapshot;
use crate::devices::lapic::{IpiRequest, LapicCheckpoint, LocalApic};
use crate::error::{Error, Result};
use std::collections::VecDeque;

const TAG: &[u8; 8] = b"RAXEXE01";
const RISCV_TAG: &[u8; 8] = b"RAXEXE09";
const ARM_TAG: &[u8; 8] = b"RAXEXE02";
const PC_TAG: &[u8; 8] = b"RAXEXE04";
const UART_TAG: &[u8; 8] = b"RAXEXE03";
const SOURCE_ARM_TAG: &[u8; 8] = b"RAXEXE07";
const PREVIOUS_SOURCE_ARM_TAG: &[u8; 8] = b"RAXEXE05";
const SOURCE_UART_TAG: &[u8; 8] = b"RAXEXE08";
const PREVIOUS_SOURCE_UART_TAG: &[u8; 8] = b"RAXEXE06";
const PRE_APR_POWER_TAG: &[u8; 8] = b"RAXEXE13";
const PRE_APR_POWER_UART_TAG: &[u8; 8] = b"RAXEXE14";
const ARM_POWER_TAG: &[u8; 8] = b"RAXEXE15";
const ARM_POWER_UART_TAG: &[u8; 8] = b"RAXEXE16";
const SNAPSHOT_SCHEDULE_TAG: &[u8; 8] = b"RAXSCH01";
pub(super) const MAX_SECTION: u64 = 64 * 1024 * 1024;
const MAX_CONTROL: usize = 4096;
// The 255-hart RV64 controller package needs at most 11,150 bytes.
const MAX_RISCV_CONTROL: usize = 16 * 1024;
const MAX_REQUESTS: usize = 1_048_576;

#[path = "execution_eoi.rs"]
mod eoi;

#[path = "execution_deadline.rs"]
mod deadline;

#[path = "execution_ipi.rs"]
mod ipi;
pub(crate) use ipi::PendingIpiDelivery;

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::Emulator(format!("execution checkpoint: {message}"))
}

fn validate_snapshot_schedule(retired: u64, last_snapshot_insn: Option<u64>) -> Result<()> {
    if last_snapshot_insn.is_some_and(|count| count > retired) {
        return Err(invalid(
            "automatic checkpoint count exceeds retirement count",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        ExecutionSnapshot {
            cursor: 0,
            retired: 53,
            last_snapshot_insn: None,
            online: vec![true],
            pending_ipi: None,
            arm_cluster: None,
            riscv_platform: None,
            pc: None,
            pl011: None,
            local_apics: vec![LapicCheckpoint {
                registers: LocalApic::new(0),
                timer_age_nanos: None,
                queued: VecDeque::from([IpiRequest::Fixed {
                    vector: 0x41,
                    target: crate::devices::lapic::IpiTarget::Physical(1),
                }]),
                eois: VecDeque::new(),
            }],
        }
        .encoded()
        .unwrap()
    }

    #[test]
    fn framed_execution_state_preserves_cursor_retirement_and_typed_ipis() {
        let raw = fixture();
        let state = ExecutionSnapshot::decode(&raw, 1).unwrap();
        assert_eq!(state.cursor(), 0);
        assert_eq!(state.retired(), 53);
        assert_eq!(state.online(), &[true]);
        assert!(matches!(
            state.local_apics[0].queued.front(),
            Some(IpiRequest::Fixed {
                vector: 0x41,
                target: crate::devices::lapic::IpiTarget::Physical(1)
            })
        ));
        assert_eq!(state.encoded().unwrap(), raw);
    }

    #[test]
    fn every_truncated_prefix_and_trailing_byte_is_rejected() {
        let raw = fixture();
        for end in 0..raw.len() {
            assert!(
                ExecutionSnapshot::decode(&raw[..end], 1).is_err(),
                "prefix {end}"
            );
        }
        let mut trailing = raw;
        trailing.push(0);
        assert!(ExecutionSnapshot::decode(&trailing, 1).is_err());
    }

    #[test]
    fn automatic_checkpoint_schedule_frame_preserves_the_legacy_prefix_and_bounds() {
        let legacy = fixture();
        let mut state = ExecutionSnapshot::decode(&legacy, 1).unwrap();
        assert_eq!(state.last_snapshot_insn, None);
        for count in [0, 19, state.retired] {
            state.last_snapshot_insn = Some(count);
            let frame = state.encoded().unwrap();
            assert_eq!(&frame[..legacy.len()], legacy);
            assert_eq!(
                &frame[legacy.len()..legacy.len() + 8],
                SNAPSHOT_SCHEDULE_TAG
            );
            assert_eq!(&frame[legacy.len() + 8..], &count.to_le_bytes());
            assert_eq!(
                ExecutionSnapshot::decode(&frame, 1)
                    .unwrap()
                    .last_snapshot_insn,
                Some(count)
            );
            for end in legacy.len() + 1..frame.len() {
                assert!(
                    ExecutionSnapshot::decode(&frame[..end], 1).is_err(),
                    "{end}"
                );
            }
            let mut repeat = frame.clone();
            repeat.extend_from_slice(&frame[legacy.len()..]);
            assert!(ExecutionSnapshot::decode(&repeat, 1).is_err());
            let mut future = frame;
            future[legacy.len() + 8..].copy_from_slice(&(state.retired + 1).to_le_bytes());
            assert!(ExecutionSnapshot::decode(&future, 1).is_err());
        }
        state.last_snapshot_insn = Some(state.retired + 1);
        assert!(state.encoded().is_err());
    }

    #[test]
    fn arm_controller_frame_is_required_bounded_and_retains_legacy_encoding() {
        let legacy = fixture();
        let mut state = ExecutionSnapshot::decode(&legacy, 1).unwrap();
        state.arm_cluster = Some(
            crate::backend::emulator::aarch64::cluster::ArmCluster::new(1, 0x8000)
                .unwrap()
                .checkpoint()
                .unwrap(),
        );
        let raw = state.encoded().unwrap();
        assert_eq!(&raw[..8], ARM_POWER_TAG);
        // The frozen old aggregate layout is accepted only when each
        // physical source has a unique inactive interpretation.
        let controller = state.arm_cluster.as_ref().unwrap().legacy_bytes_for_test();
        let mut old = legacy.clone();
        old[..8].copy_from_slice(ARM_TAG);
        old.extend_from_slice(&(controller.len() as u32).to_le_bytes());
        old.extend_from_slice(&controller);
        assert_eq!(
            ExecutionSnapshot::decode(&old, 1)
                .unwrap()
                .encoded()
                .unwrap(),
            raw
        );
        let ambiguous =
            crate::backend::emulator::aarch64::cluster::ArmCluster::new(1, 0x8000).unwrap();
        ambiguous.set_irq_line(40, true).unwrap();
        let controller = ambiguous.checkpoint().unwrap().legacy_bytes_for_test();
        let mut old = legacy.clone();
        old[..8].copy_from_slice(ARM_TAG);
        old.extend_from_slice(&(controller.len() as u32).to_le_bytes());
        old.extend_from_slice(&controller);
        assert!(
            ExecutionSnapshot::decode(&old, 1)
                .err()
                .unwrap()
                .to_string()
                .contains("ambiguous")
        );
        assert_eq!(
            ExecutionSnapshot::decode(&raw, 1)
                .unwrap()
                .encoded()
                .unwrap(),
            raw
        );
        for end in 0..raw.len() {
            assert!(
                ExecutionSnapshot::decode(&raw[..end], 1).is_err(),
                "prefix {end}"
            );
        }
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(ExecutionSnapshot::decode(&trailing, 1).is_err());
        let mut missing = raw;
        missing[..8].copy_from_slice(TAG);
        assert!(ExecutionSnapshot::decode(&missing, 1).is_err());
        assert_eq!(
            ExecutionSnapshot::decode(&legacy, 1)
                .unwrap()
                .encoded()
                .unwrap(),
            legacy
        );
    }

    #[test]
    fn source_bearing_shared_frames_migrate_with_and_without_uart() {
        for uart in [false, true] {
            let mut state = ExecutionSnapshot::decode(&fixture(), 1).unwrap();
            let cluster =
                crate::backend::emulator::aarch64::cluster::ArmCluster::new(1, 0x8000).unwrap();
            state.arm_cluster = Some(cluster.checkpoint().unwrap());
            if uart {
                state.pl011 = Some(crate::devices::pl011::Pl011::new().checkpoint().unwrap());
            }
            let expected = state.encoded().unwrap();
            let platform = state
                .arm_cluster
                .as_ref()
                .unwrap()
                .previous_source_bytes_for_test();
            let mut old = fixture();
            old[..8].copy_from_slice(if uart {
                PREVIOUS_SOURCE_UART_TAG
            } else {
                PREVIOUS_SOURCE_ARM_TAG
            });
            old.extend_from_slice(&(platform.len() as u32).to_le_bytes());
            old.extend_from_slice(&platform);
            if let Some(uart) = &state.pl011 {
                let bytes = crate::codec::serialize(uart).unwrap();
                old.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                old.extend_from_slice(&bytes);
            }
            let migrated = ExecutionSnapshot::decode(&old, 1).unwrap();
            assert_eq!(migrated.encoded().unwrap(), expected);
            for end in 0..old.len() {
                assert!(
                    ExecutionSnapshot::decode(&old[..end], 1).is_err(),
                    "uart={uart} prefix={end}"
                );
            }
            old.push(0);
            assert!(ExecutionSnapshot::decode(&old, 1).is_err());
        }
    }

    #[test]
    fn arm_power_frames_distinguish_legacy_and_terminal_records() {
        for uart in [false, true] {
            let mut state = ExecutionSnapshot::decode(&fixture(), 1).unwrap();
            let cluster =
                crate::backend::emulator::aarch64::cluster::ArmCluster::new(1, 0x8000).unwrap();
            state.arm_cluster = Some(cluster.checkpoint().unwrap());
            if uart {
                state.pl011 = Some(crate::devices::pl011::Pl011::new().checkpoint().unwrap());
            }
            let platform = state
                .arm_cluster
                .as_ref()
                .unwrap()
                .without_terminal_bytes_for_test();
            let mut old = fixture();
            old[..8].copy_from_slice(if uart {
                SOURCE_UART_TAG
            } else {
                SOURCE_ARM_TAG
            });
            old.extend_from_slice(&(platform.len() as u32).to_le_bytes());
            old.extend_from_slice(&platform);
            if let Some(uart) = &state.pl011 {
                let bytes = crate::codec::serialize(uart).unwrap();
                old.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                old.extend_from_slice(&bytes);
            }
            let migrated = ExecutionSnapshot::decode(&old, 1).unwrap();
            assert!(!migrated.arm_cluster.as_ref().unwrap().shutdown);
            assert_eq!(migrated.encoded().unwrap(), state.encoded().unwrap());

            state.arm_cluster.as_mut().unwrap().shutdown = true;
            let terminal = state.encoded().unwrap();
            assert_eq!(
                &terminal[..8],
                if uart {
                    ARM_POWER_UART_TAG
                } else {
                    ARM_POWER_TAG
                }
            );
            let restored = ExecutionSnapshot::decode(&terminal, 1).unwrap();
            assert!(restored.arm_cluster.as_ref().unwrap().shutdown);

            let platform = state.arm_cluster.as_ref().unwrap().pre_apr_bytes_for_test();
            let mut previous = fixture();
            previous[..8].copy_from_slice(if uart {
                PRE_APR_POWER_UART_TAG
            } else {
                PRE_APR_POWER_TAG
            });
            previous.extend_from_slice(&(platform.len() as u32).to_le_bytes());
            previous.extend_from_slice(&platform);
            if let Some(uart) = &state.pl011 {
                let bytes = crate::codec::serialize(uart).unwrap();
                previous.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                previous.extend_from_slice(&bytes);
            }
            let previous = ExecutionSnapshot::decode(&previous, 1).unwrap();
            assert!(previous.arm_cluster.as_ref().unwrap().shutdown);
            assert_eq!(previous.encoded().unwrap(), terminal);

            // An extended tag cannot silently admit a record missing the bool.
            old[..8].copy_from_slice(&terminal[..8]);
            assert!(ExecutionSnapshot::decode(&old, 1).is_err());
        }
    }

    #[test]
    fn malformed_counts_flags_lengths_and_enum_tags_are_rejected() {
        let raw = fixture();
        let control_len = u32::from_le_bytes(raw[42..46].try_into().unwrap()) as usize;
        let request = 50 + control_len;
        for (offset, replacement) in [
            (8, 0u32.to_le_bytes().to_vec()),
            (8, u32::MAX.to_le_bytes().to_vec()),
            (12, 1u32.to_le_bytes().to_vec()),
            (24, vec![2]),
            (25, vec![2]),
            (26, 1u128.to_le_bytes().to_vec()),
            (42, 0u32.to_le_bytes().to_vec()),
            (42, 4097u32.to_le_bytes().to_vec()),
            (46, u32::MAX.to_le_bytes().to_vec()),
            (request, vec![0]),
            (request, vec![33]),
            (request + 1, u32::MAX.to_le_bytes().to_vec()),
        ] {
            let mut mutated = raw.clone();
            mutated[offset..offset + replacement.len()].copy_from_slice(&replacement);
            assert!(
                ExecutionSnapshot::decode(&mutated, 1).is_err(),
                "offset {offset}"
            );
        }
        assert!(ExecutionSnapshot::decode(&raw, 2).is_err());
    }
}

fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    crate::codec::serialize_limited(value, MAX_CONTROL).map_err(invalid)
}

fn decode<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T> {
    crate::codec::deserialize_limited::<T, MAX_CONTROL>(raw).map_err(invalid)
}

/// Coordinator cursor, online/startup states, all local controllers and outgoing
/// IPIs. This supplements CPU contexts; it does not replace backend-private state.
#[derive(Clone)]
pub struct ExecutionSnapshot {
    pub(crate) cursor: usize,
    pub(crate) retired: u64,
    /// Last successful automatic write, present when the source had a schedule.
    pub(crate) last_snapshot_insn: Option<u64>,
    pub(crate) online: Vec<bool>,
    pub(crate) local_apics: Vec<LapicCheckpoint>,
    pub(crate) pending_ipi: Option<PendingIpiDelivery>,
    pub(crate) pc: Option<crate::machine::pc::PcCheckpoint>,
    pub(crate) pl011: Option<crate::devices::pl011::Pl011Checkpoint>,
    pub(crate) riscv_platform:
        Option<crate::backend::emulator::riscv::platform::PlatformCheckpoint>,
    pub(crate) arm_cluster:
        Option<crate::backend::emulator::aarch64::cluster::ArmClusterCheckpoint>,
}

impl ExecutionSnapshot {
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn retired(&self) -> u64 {
        self.retired
    }

    pub fn online(&self) -> &[bool] {
        &self.online
    }

    pub(crate) fn validate(&self, base: &Snapshot) -> Result<()> {
        validate_snapshot_schedule(self.retired, self.last_snapshot_insn)?;
        base.validate_base_lapic_projection()?;
        let count = usize::from(base.config.vcpus);
        if count == 0
            || self.online.len() != count
            || self.local_apics.len() != count
            || self.cursor >= count
        {
            return Err(invalid("CPU count or cursor disagrees with configuration"));
        }
        if let Some(delivery) = &self.pending_ipi {
            if base.config.arch != crate::config::ArchKind::X86_64 {
                return Err(invalid("pending IPI on another architecture"));
            }
            delivery.validate(count)?;
        }
        if let Some(platform) = &self.riscv_platform {
            if base.config.arch != crate::config::ArchKind::Riscv64
                || base.config.backend != crate::config::BackendKind::Emulator
                || self.pc.is_some()
                || self.arm_cluster.is_some()
                || self.pl011.is_some()
            {
                return Err(invalid("RISC-V platform on another machine"));
            }
            // CLINT can wake an online WFI hart. It cannot change scheduler
            // eligibility, and this platform has no hart-start transition.
            if !self.online.contains(&true) {
                return Err(invalid("CLINT checkpoint requires an online hart"));
            }
            platform.validate(count, base.memory_size)?;
        }
        if let Some(pc) = &self.pc {
            if base.config.arch != crate::config::ArchKind::X86_64
                || self.arm_cluster.is_some()
                || self.pl011.is_some()
            {
                return Err(invalid("PC state on another platform"));
            }
            pc.validate_com1(base.devices.serial.has_pending_interrupt())?;
        }
        if let Some(uart) = &self.pl011 {
            if base.config.arch != crate::config::ArchKind::Aarch64 {
                return Err(invalid("PL011 state on another architecture"));
            }
            uart.validate()?;
        }
        if let Some(cluster) = &self.arm_cluster {
            if base.config.arch != crate::config::ArchKind::Aarch64 {
                return Err(invalid("ARM platform state on another architecture"));
            }
            cluster.validate(&self.online)?;
            if let Some(uart) = &self.pl011 {
                cluster.validate_uart_irq(uart.irq_pending())?;
            }
        }
        let first = self
            .local_apics
            .first()
            .ok_or_else(|| invalid("empty controller set"))?;
        if encode(&first.registers)? != encode(&base.devices.lapic)? {
            return Err(invalid("BSP controller disagrees with base checkpoint"));
        }
        if self.local_apics.iter().any(|apic| {
            apic.queued.len() > MAX_REQUESTS
                || apic.eois.len() > MAX_REQUESTS
                || apic.eois.iter().any(|vector| *vector < 16)
                || apic.registers.has_pending_eoi()
                || apic.registers.has_queued_ipis()
        }) {
            return Err(invalid("IPI queue exceeds format limit"));
        }
        Ok(())
    }

    pub(super) fn encoded(&self) -> Result<Vec<u8>> {
        if self
            .local_apics
            .iter()
            .any(|apic| apic.registers.has_pending_eoi() || apic.registers.has_queued_ipis())
        {
            return Err(invalid(
                "controller projection contains hidden IPI or EOI messages",
            ));
        }
        let base = self.encoded_base()?;
        let base = self.encode_eois(base)?;
        let base = self.encode_deadlines(base)?;
        self.encode_pending_ipi(base)
    }

    fn encoded_base(&self) -> Result<Vec<u8>> {
        let mut raw = Vec::new();
        if self.riscv_platform.is_some()
            && (self.pc.is_some() || self.pl011.is_some() || self.arm_cluster.is_some())
        {
            return Err(invalid("mixed RISC-V platform frame"));
        }
        raw.extend_from_slice(if self.riscv_platform.is_some() {
            RISCV_TAG
        } else if self.pc.is_some() {
            PC_TAG
        } else if self.pl011.is_some() {
            if self.arm_cluster.is_some() {
                ARM_POWER_UART_TAG
            } else {
                UART_TAG
            }
        } else if self.arm_cluster.is_some() {
            ARM_POWER_TAG
        } else {
            TAG
        });
        raw.extend_from_slice(&(self.online.len() as u32).to_le_bytes());
        raw.extend_from_slice(&(self.cursor as u32).to_le_bytes());
        raw.extend_from_slice(&self.retired.to_le_bytes());
        for ((online, apic), index) in self.online.iter().zip(&self.local_apics).zip(0..) {
            if index >= usize::from(u8::MAX) || apic.queued.len() > MAX_REQUESTS {
                return Err(invalid("controller count or queue exceeds format limit"));
            }
            let control = encode(&apic.registers)?;
            if control.len() > MAX_CONTROL {
                return Err(invalid("controller record exceeds format limit"));
            }
            raw.push(u8::from(*online));
            raw.push(u8::from(apic.timer_age_nanos.is_some()));
            raw.extend_from_slice(&apic.timer_age_nanos.unwrap_or(0).to_le_bytes());
            raw.extend_from_slice(&(control.len() as u32).to_le_bytes());
            raw.extend_from_slice(&(apic.queued.len() as u32).to_le_bytes());
            raw.extend_from_slice(&control);
            for request in &apic.queued {
                let request = encode(request)?;
                if request.is_empty() || request.len() > 32 {
                    return Err(invalid("IPI record exceeds format limit"));
                }
                raw.push(request.len() as u8);
                raw.extend_from_slice(&request);
            }
            if raw.len() as u64 > MAX_SECTION {
                return Err(invalid("execution section exceeds format limit"));
            }
        }
        if let Some(cluster) = &self.arm_cluster {
            cluster.validate(&self.online)?;
            let control =
                crate::codec::serialize_limited(cluster, MAX_SECTION as usize).map_err(invalid)?;
            if raw.len() as u64 + 4 + control.len() as u64 > MAX_SECTION {
                return Err(invalid(
                    "ARM platform state exceeds execution section limit",
                ));
            }
            raw.extend_from_slice(&(control.len() as u32).to_le_bytes());
            raw.extend_from_slice(&control);
        }
        if self.pl011.is_some() && self.arm_cluster.is_none() {
            raw.extend_from_slice(&0u32.to_le_bytes());
        }
        if let Some(uart) = &self.pl011 {
            uart.validate()?;
            let control =
                crate::codec::serialize_limited(uart, MAX_SECTION as usize).map_err(invalid)?;
            if raw.len() as u64 + 4 + control.len() as u64 > MAX_SECTION {
                return Err(invalid("UART state exceeds execution section limit"));
            }
            raw.extend_from_slice(&(control.len() as u32).to_le_bytes());
            raw.extend_from_slice(&control);
        }
        if let Some(pc) = &self.pc {
            let control = pc.encoded()?;
            if raw.len() as u64 + 4 + control.len() as u64 > MAX_SECTION {
                return Err(invalid("PC control state exceeds section limit"));
            }
            raw.extend_from_slice(&(control.len() as u32).to_le_bytes());
            raw.extend_from_slice(&control);
        }
        if let Some(platform) = &self.riscv_platform {
            let control = platform.encode(MAX_RISCV_CONTROL)?;
            raw.extend_from_slice(&(control.len() as u32).to_le_bytes());
            raw.extend_from_slice(&control);
        }
        if let Some(count) = self.last_snapshot_insn {
            validate_snapshot_schedule(self.retired, Some(count))?;
            if raw.len() as u64 + 16 > MAX_SECTION {
                return Err(invalid(
                    "automatic checkpoint schedule exceeds section limit",
                ));
            }
            raw.extend_from_slice(SNAPSHOT_SCHEDULE_TAG);
            raw.extend_from_slice(&count.to_le_bytes());
        }
        Ok(raw)
    }

    pub(super) fn decode(raw: &[u8], expected_count: u8) -> Result<Self> {
        if raw.len() as u64 > MAX_SECTION {
            return Err(invalid("execution section exceeds format limit"));
        }
        if let Some(restored) = Self::decode_pending_ipi(raw, expected_count)? {
            return Ok(restored);
        }
        if let Some(restored) = Self::decode_deadlines(raw, expected_count)? {
            return Ok(restored);
        }
        if let Some(restored) = Self::decode_eois(raw, expected_count)? {
            return Ok(restored);
        }
        struct Reader<'a>(&'a [u8]);
        impl<'a> Reader<'a> {
            fn take(&mut self, count: usize) -> Result<&'a [u8]> {
                let (part, rest) = self
                    .0
                    .split_at_checked(count)
                    .ok_or_else(|| invalid("truncated execution record"))?;
                self.0 = rest;
                Ok(part)
            }
            fn u8(&mut self) -> Result<u8> {
                Ok(self.take(1)?[0])
            }
            fn u32(&mut self) -> Result<u32> {
                Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
            }
            fn u128(&mut self) -> Result<u128> {
                Ok(u128::from_le_bytes(self.take(16)?.try_into().unwrap()))
            }
            fn u64(&mut self) -> Result<u64> {
                Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
            }
        }
        let mut reader = Reader(raw);
        let tag = reader.take(8)?;
        if ![
            TAG,
            ARM_TAG,
            UART_TAG,
            PC_TAG,
            RISCV_TAG,
            SOURCE_ARM_TAG,
            SOURCE_UART_TAG,
            PREVIOUS_SOURCE_ARM_TAG,
            PREVIOUS_SOURCE_UART_TAG,
            PRE_APR_POWER_TAG,
            PRE_APR_POWER_UART_TAG,
            ARM_POWER_TAG,
            ARM_POWER_UART_TAG,
        ]
        .contains(&tag.try_into().unwrap())
        {
            return Err(invalid("bad execution section tag"));
        }
        let count = reader.u32()? as usize;
        let cursor = reader.u32()? as usize;
        let retired = reader.u64()?;
        if count == 0 || count != usize::from(expected_count) || cursor >= count {
            return Err(invalid("invalid CPU count or scheduler cursor"));
        }
        let mut online = Vec::with_capacity(count);
        let mut local_apics = Vec::with_capacity(count);
        for _ in 0..count {
            let runnable = reader.u8()?;
            let armed = reader.u8()?;
            let age = reader.u128()?;
            let control_len = reader.u32()? as usize;
            let queue_len = reader.u32()? as usize;
            if runnable > 1
                || armed > 1
                || (armed == 0 && age != 0)
                || control_len == 0
                || control_len > MAX_CONTROL
                || queue_len > MAX_REQUESTS
            {
                return Err(invalid("invalid controller flags or lengths"));
            }
            let registers: LocalApic = decode(reader.take(control_len)?)?;
            // Each event needs a length byte and a nonempty payload. Admit that
            // lower bound before reserving memory for an untrusted count.
            if queue_len > reader.0.len() / 2 {
                return Err(invalid("IPI count exceeds remaining payload"));
            }
            let mut queued = VecDeque::new();
            queued.try_reserve_exact(queue_len).map_err(invalid)?;
            for _ in 0..queue_len {
                let length = usize::from(reader.u8()?);
                if length == 0 || length > 32 {
                    return Err(invalid("invalid IPI length"));
                }
                let request: IpiRequest = decode(reader.take(length)?)?;
                queued.push_back(request);
            }
            online.push(runnable != 0);
            local_apics.push(LapicCheckpoint {
                registers,
                queued,
                eois: VecDeque::new(),
                timer_age_nanos: (armed != 0).then_some(age),
            });
        }
        let arm_cluster = if tag == ARM_TAG
            || tag == UART_TAG
            || tag == SOURCE_ARM_TAG
            || tag == SOURCE_UART_TAG
            || tag == PREVIOUS_SOURCE_ARM_TAG
            || tag == PREVIOUS_SOURCE_UART_TAG
            || tag == PRE_APR_POWER_TAG
            || tag == PRE_APR_POWER_UART_TAG
            || tag == ARM_POWER_TAG
            || tag == ARM_POWER_UART_TAG
        {
            let length = reader.u32()? as usize;
            if length > MAX_SECTION as usize || (length == 0 && tag != UART_TAG) {
                return Err(invalid("bad ARM platform length"));
            }
            if length == 0 {
                None
            } else {
                let cluster: crate::backend::emulator::aarch64::cluster::ArmClusterCheckpoint =
                    if tag == ARM_TAG || tag == UART_TAG {
                        crate::backend::emulator::aarch64::cluster::ArmClusterCheckpoint::decode_legacy(reader.take(length)?)?
                    } else if tag == PREVIOUS_SOURCE_ARM_TAG || tag == PREVIOUS_SOURCE_UART_TAG {
                        crate::backend::emulator::aarch64::cluster::ArmClusterCheckpoint::decode_previous_sources(reader.take(length)?)?
                    } else if tag == SOURCE_ARM_TAG || tag == SOURCE_UART_TAG {
                        crate::backend::emulator::aarch64::cluster::ArmClusterCheckpoint::decode_without_terminal(reader.take(length)?)?
                    } else if tag == PRE_APR_POWER_TAG || tag == PRE_APR_POWER_UART_TAG {
                        crate::backend::emulator::aarch64::cluster::ArmClusterCheckpoint::decode_pre_apr(reader.take(length)?)?
                    } else {
                        crate::codec::deserialize_limited::<_, { MAX_SECTION as usize }>(
                            reader.take(length)?,
                        )
                        .map_err(invalid)?
                    };
                cluster.validate(&online)?;
                Some(cluster)
            }
        } else {
            None
        };
        let pl011 = if tag == UART_TAG
            || tag == SOURCE_UART_TAG
            || tag == PREVIOUS_SOURCE_UART_TAG
            || tag == PRE_APR_POWER_UART_TAG
            || tag == ARM_POWER_UART_TAG
        {
            let length = reader.u32()? as usize;
            if length == 0 || length > MAX_SECTION as usize {
                return Err(invalid("bad UART length"));
            }
            let uart: crate::devices::pl011::Pl011Checkpoint = crate::codec::deserialize_limited::<
                _,
                { MAX_SECTION as usize },
            >(reader.take(length)?)
            .map_err(invalid)?;
            uart.validate()?;
            Some(uart)
        } else {
            None
        };
        let pc = if tag == PC_TAG {
            let length = reader.u32()? as usize;
            if length == 0 || length as u64 > MAX_SECTION {
                return Err(invalid("invalid PC control length"));
            }
            Some(crate::machine::pc::PcCheckpoint::decode(
                reader.take(length)?,
            )?)
        } else {
            None
        };
        let riscv_platform = if tag == RISCV_TAG {
            let length = reader.u32()? as usize;
            if length == 0 || length > MAX_RISCV_CONTROL {
                return Err(invalid("bad RISC-V platform length"));
            }
            Some(
                crate::backend::emulator::riscv::platform::PlatformCheckpoint::decode::<
                    MAX_RISCV_CONTROL,
                >(reader.take(length)?)?,
            )
        } else {
            None
        };
        let last_snapshot_insn = if reader.0.is_empty() {
            None
        } else {
            if reader.take(8)? != SNAPSHOT_SCHEDULE_TAG {
                return Err(invalid("unexpected execution extension"));
            }
            Some(reader.u64()?)
        };
        validate_snapshot_schedule(retired, last_snapshot_insn)?;
        if !reader.0.is_empty() {
            return Err(invalid("trailing execution data"));
        }
        Ok(Self {
            cursor,
            retired,
            last_snapshot_insn,
            online,
            local_apics,
            pending_ipi: None,
            arm_cluster,
            riscv_platform,
            pl011,
            pc,
        })
    }
}

#[cfg(test)]
mod riscv_frame_tests {
    use super::*;
    #[test]
    fn clint_frame_is_bounded_required_and_rejects_every_truncated_prefix() {
        let clock = std::sync::Arc::new(crate::vm::timing::TimingContext::with_mode(
            crate::vm::timing::ClockMode::Retired,
        ));
        let platform =
            crate::backend::emulator::riscv::platform::Platform::new(1, 0x8000000, clock, false)
                .unwrap();
        let mut state = ExecutionSnapshot {
            cursor: 0,
            retired: 0,
            last_snapshot_insn: None,
            online: vec![true],
            pending_ipi: None,
            local_apics: vec![LocalApic::new(0).checkpoint_at(crate::host::time::Instant::now())],
            pc: None,
            pl011: None,
            arm_cluster: None,
            riscv_platform: platform.checkpoint().unwrap(),
        };
        let raw = state.encoded().unwrap();
        assert_eq!(&raw[..8], RISCV_TAG);
        assert_eq!(
            ExecutionSnapshot::decode(&raw, 1)
                .unwrap()
                .encoded()
                .unwrap(),
            raw
        );
        for end in 0..raw.len() {
            assert!(
                ExecutionSnapshot::decode(&raw[..end], 1).is_err(),
                "prefix {end}"
            );
        }
        let mut missing = raw.clone();
        missing[..8].copy_from_slice(TAG);
        assert!(ExecutionSnapshot::decode(&missing, 1).is_err());
        let mut trailing = raw;
        trailing.push(0);
        assert!(ExecutionSnapshot::decode(&trailing, 1).is_err());
        state.arm_cluster = Some(
            crate::backend::emulator::aarch64::cluster::ArmCluster::new(1, 0x8000000)
                .unwrap()
                .checkpoint()
                .unwrap(),
        );
        assert!(state.encoded().is_err());
    }
}
