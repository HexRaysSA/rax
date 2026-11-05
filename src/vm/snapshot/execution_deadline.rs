//! Complete per-CPU deadline/expiry ownership around the stable base frame.
//! Canonical order is deadline -> EOI -> base; reverse nesting is rejected.
use super::*;
use crate::devices::lapic::tsc_deadline::Image;

pub(super) const TAG: &[u8; 8] = b"RAXEXE11";

impl ExecutionSnapshot {
    pub(super) fn encode_deadlines(&self, base: Vec<u8>) -> Result<Vec<u8>> {
        let images: Vec<_> = self
            .local_apics
            .iter()
            .map(|apic| apic.registers.deadline_handle().snapshot())
            .collect();
        if images.iter().any(|image| !image.valid()) {
            return Err(invalid("armed timer outside deadline mode"));
        }
        if images.iter().all(Image::is_quiescent) {
            return Ok(base);
        }
        if images.len() != self.online.len()
            || images.is_empty()
            || images.len() > usize::from(u8::MAX)
        {
            return Err(invalid("deadline controller identity count differs"));
        }
        let length = 16usize
            .checked_add(base.len())
            .and_then(|length| length.checked_add(images.len() * Image::BYTES))
            .ok_or_else(|| invalid("deadline frame length overflow"))?;
        if length as u64 > MAX_SECTION {
            return Err(invalid("deadline section exceeds format limit"));
        }
        let mut raw = Vec::new();
        raw.try_reserve_exact(length).map_err(invalid)?;
        raw.extend_from_slice(TAG);
        raw.extend_from_slice(&(base.len() as u32).to_le_bytes());
        raw.extend_from_slice(&base);
        raw.extend_from_slice(&(images.len() as u32).to_le_bytes());
        for image in images {
            raw.extend(image.encode());
        }
        Ok(raw)
    }

    pub(super) fn decode_deadlines(raw: &[u8], expected_count: u8) -> Result<Option<Self>> {
        if !raw.starts_with(TAG) {
            return Ok(None);
        }
        let length = raw
            .get(8..12)
            .map(|value| u32::from_le_bytes(value.try_into().unwrap()) as usize)
            .ok_or_else(|| invalid("truncated deadline frame"))?;
        let end = 12usize
            .checked_add(length)
            .ok_or_else(|| invalid("deadline inner length overflow"))?;
        let inner = raw
            .get(12..end)
            .ok_or_else(|| invalid("truncated deadline inner frame"))?;
        if inner.starts_with(TAG) {
            return Err(invalid("nested deadline frame"));
        }
        let count = raw
            .get(end..end + 4)
            .map(|value| u32::from_le_bytes(value.try_into().unwrap()) as usize)
            .ok_or_else(|| invalid("truncated deadline count"))?;
        if count == 0
            || count != usize::from(expected_count)
            || raw.len() != end + 4 + count * Image::BYTES
        {
            return Err(invalid("deadline controller count or length differs"));
        }
        let mut restored = Self::decode(inner, expected_count)?;
        if restored.local_apics.len() != count {
            return Err(invalid("deadline controller identity count differs"));
        }
        let mut nonempty = false;
        for (apic, bytes) in restored
            .local_apics
            .iter_mut()
            .zip(raw[end + 4..].chunks_exact(Image::BYTES))
        {
            let image = Image::decode(bytes).ok_or_else(|| invalid("invalid deadline image"))?;
            let timer = apic.registers.deadline_handle();
            if image.lvt != timer.snapshot().lvt {
                return Err(invalid("deadline LVT differs from controller"));
            }
            nonempty |= !image.is_quiescent();
            timer.restore(image);
        }
        if !nonempty {
            return Err(invalid("empty deadline extension"));
        }
        Ok(Some(restored))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(count: usize) -> ExecutionSnapshot {
        ExecutionSnapshot {
            cursor: count - 1,
            retired: 53,
            online: vec![true; count],
            local_apics: (0..count)
                .map(|id| LocalApic::new(id as u32).checkpoint_at(std::time::Instant::now()))
                .collect(),
            pc: None,
            pl011: None,
            riscv_platform: None,
            arm_cluster: None,
        }
    }

    #[test]
    fn armed_deadlines_and_undelivered_expiries_round_trip_with_eoi_queues() {
        for count in [1, 2, 4] {
            let mut state = fixture(count);
            for (id, apic) in state.local_apics.iter_mut().enumerate() {
                apic.registers.write_register(0x320, 0x40051 + id as u32);
                let timer = apic.registers.deadline_handle();
                timer.write(1);
                timer.expire(1);
                timer.write(u64::MAX - id as u64);
                apic.eois.push_back(0x61 + id as u8);
            }
            let expected: Vec<_> = state
                .local_apics
                .iter()
                .map(|apic| apic.registers.deadline_handle().snapshot())
                .collect();
            let raw = state.encoded().unwrap();
            assert!(raw.starts_with(TAG));
            drop(state);
            let restored = ExecutionSnapshot::decode(&raw, count as u8).unwrap();
            assert_eq!(restored.encoded().unwrap(), raw);
            for (id, apic) in restored.local_apics.iter().enumerate() {
                let mut live = apic.prepare(std::time::Instant::now());
                assert_eq!(live.deadline_handle().snapshot(), expected[id]);
                live.poll_tsc_deadline(2);
                assert_eq!(live.get_pending_vector(), Some(0x51 + id as u8));
                assert_eq!(live.deadline_handle().read(), u64::MAX - id as u64);
                assert_eq!(live.take_pending_eoi(), Some(0x61 + id as u8));
            }
        }
    }

    #[test]
    fn unarmed_timer_modes_keep_the_exact_legacy_execution_bytes() {
        let mut state = fixture(2);
        for apic in &mut state.local_apics {
            apic.registers.write_register(0x320, 0x40051);
        }
        let raw = state.encoded().unwrap();
        assert_eq!(raw, state.encoded_base().unwrap());
        assert_eq!(
            ExecutionSnapshot::decode(&raw, 2)
                .unwrap()
                .encoded()
                .unwrap(),
            raw
        );
    }

    #[test]
    fn malformed_lengths_images_counts_and_recursive_extensions_reject() {
        let mut state = fixture(1);
        state.local_apics[0]
            .registers
            .write_register(0x320, 0x40051);
        state.local_apics[0].registers.deadline_handle().write(123);
        let raw = state.encoded().unwrap();
        for end in 0..raw.len() {
            assert!(
                ExecutionSnapshot::decode(&raw[..end], 1).is_err(),
                "prefix {end}"
            );
        }
        let length = u32::from_le_bytes(raw[8..12].try_into().unwrap()) as usize;
        for case in 0..7 {
            let mut bad = raw.clone();
            let image = 16 + length;
            match case {
                0 => bad.push(0),
                1 => bad[12..20].copy_from_slice(TAG),
                2 => bad[12 + length..16 + length].copy_from_slice(&2u32.to_le_bytes()),
                3 => bad[image..image + 4].copy_from_slice(&0x40061u32.to_le_bytes()),
                4 => bad[image..image + 4].copy_from_slice(&0x51u32.to_le_bytes()),
                5 => bad[image + 4..].fill(0),
                _ => bad[8..12].copy_from_slice(&u32::MAX.to_le_bytes()),
            }
            assert!(ExecutionSnapshot::decode(&bad, 1).is_err(), "case {case}");
        }
        // Canonical deadline -> EOI -> base cannot be inverted to create
        // alternating recursive wrappers and exhaust the parser's stack.
        let mut inverted = b"RAXEXE10".to_vec();
        inverted.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        inverted.extend_from_slice(&raw);
        inverted.extend_from_slice(&1u32.to_le_bytes());
        inverted.extend_from_slice(&1u32.to_le_bytes());
        inverted.push(0x51);
        assert!(ExecutionSnapshot::decode(&inverted, 1).is_err());
    }
}
