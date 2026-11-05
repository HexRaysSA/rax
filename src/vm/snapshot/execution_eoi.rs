//! Required extension for local-APIC EOI broadcasts awaiting controller service.
//! Empty queues retain the exact earlier execution encoding. A nonempty queue
//! wraps one earlier frame; nested wrappers and trailing bytes are rejected.
use super::*;

const TAG: &[u8; 8] = b"RAXEXE10";

fn take<'a>(input: &mut &'a [u8], count: usize) -> Result<&'a [u8]> {
    let (part, rest) = input
        .split_at_checked(count)
        .ok_or_else(|| invalid("truncated EOI execution extension"))?;
    *input = rest;
    Ok(part)
}

fn count(input: &mut &[u8]) -> Result<usize> {
    Ok(u32::from_le_bytes(take(input, 4)?.try_into().unwrap()) as usize)
}

impl ExecutionSnapshot {
    pub(super) fn encode_eois(&self, base: Vec<u8>) -> Result<Vec<u8>> {
        if self.local_apics.iter().all(|apic| apic.eois.is_empty()) {
            return Ok(base);
        }
        if self.local_apics.len() != self.online.len()
            || self.online.is_empty()
            || self.online.len() > usize::from(u8::MAX)
        {
            return Err(invalid("EOI controller identity count differs"));
        }
        let mut length = 16usize
            .checked_add(base.len())
            .ok_or_else(|| invalid("EOI execution length overflow"))?;
        for apic in &self.local_apics {
            if apic.eois.len() > MAX_REQUESTS || apic.eois.iter().any(|vector| *vector < 16) {
                return Err(invalid("invalid EOI queue length or vector"));
            }
            length = length
                .checked_add(4 + apic.eois.len())
                .ok_or_else(|| invalid("EOI execution length overflow"))?;
        }
        if length as u64 > MAX_SECTION {
            return Err(invalid("EOI execution section exceeds format limit"));
        }
        let mut raw = Vec::new();
        raw.try_reserve_exact(length).map_err(invalid)?;
        raw.extend_from_slice(TAG);
        raw.extend_from_slice(&(base.len() as u32).to_le_bytes());
        raw.extend_from_slice(&base);
        raw.extend_from_slice(&(self.local_apics.len() as u32).to_le_bytes());
        for apic in &self.local_apics {
            raw.extend_from_slice(&(apic.eois.len() as u32).to_le_bytes());
            raw.extend(apic.eois.iter().copied());
        }
        Ok(raw)
    }

    pub(super) fn decode_eois(raw: &[u8], expected_count: u8) -> Result<Option<Self>> {
        if !raw.starts_with(TAG) {
            return Ok(None);
        }
        let mut input = &raw[8..];
        let length = count(&mut input)?;
        if length as u64 > MAX_SECTION {
            return Err(invalid("EOI inner frame exceeds format limit"));
        }
        let inner = take(&mut input, length)?;
        if inner.starts_with(TAG) || inner.starts_with(super::deadline::TAG) {
            return Err(invalid("nested EOI execution extension"));
        }
        let mut restored = Self::decode(inner, expected_count)?;
        if count(&mut input)? != restored.local_apics.len() {
            return Err(invalid("EOI controller identity count differs"));
        }
        let mut nonempty = false;
        for apic in &mut restored.local_apics {
            let length = count(&mut input)?;
            if length > MAX_REQUESTS {
                return Err(invalid("EOI queue exceeds format limit"));
            }
            let events = take(&mut input, length)?;
            if events.iter().any(|vector| *vector < 16) {
                return Err(invalid("invalid EOI vector"));
            }
            apic.eois.try_reserve_exact(length).map_err(invalid)?;
            apic.eois.extend(events.iter().copied());
            nonempty |= !events.is_empty();
        }
        if !input.is_empty() || !nonempty {
            return Err(invalid("trailing or empty EOI execution extension"));
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
    fn source_free_eoi_extension_retains_each_cpu_fifo_and_exact_inner_frame() {
        for count in [1, 2, 4] {
            let mut source = fixture(count);
            let base = source.encoded().unwrap();
            assert!(base.starts_with(super::super::TAG));
            for (id, apic) in source.local_apics.iter_mut().enumerate() {
                apic.eois = VecDeque::from([0x51 + id as u8, 0x61, 0x51]);
            }
            let raw = source.encoded().unwrap();
            assert!(raw.starts_with(TAG));
            assert_eq!(&raw[12..12 + base.len()], base);
            drop(source);
            let restored = ExecutionSnapshot::decode(&raw, count as u8).unwrap();
            assert_eq!(restored.encoded().unwrap(), raw);
            for (id, apic) in restored.local_apics.iter().enumerate() {
                let mut target = apic.prepare(std::time::Instant::now());
                for vector in [0x51 + id as u8, 0x61, 0x51] {
                    assert_eq!(target.take_pending_eoi(), Some(vector));
                }
                assert_eq!(target.take_pending_eoi(), None);
            }
        }
    }

    #[test]
    fn empty_eoi_queues_preserve_legacy_bytes_and_do_not_create_an_extension() {
        let source = fixture(2);
        let raw = source.encoded().unwrap();
        assert_eq!(raw, source.encoded_base().unwrap());
        let restored = ExecutionSnapshot::decode(&raw, 2).unwrap();
        assert!(restored.local_apics.iter().all(|apic| apic.eois.is_empty()));
        assert_eq!(restored.encoded().unwrap(), raw);
    }

    #[test]
    fn malformed_eoi_extension_rejects_truncation_counts_vectors_nesting_and_trailers() {
        let mut source = fixture(1);
        source.local_apics[0].eois.push_back(0x51);
        let raw = source.encoded().unwrap();
        for length in 0..raw.len() {
            assert!(
                ExecutionSnapshot::decode(&raw[..length], 1).is_err(),
                "prefix {length}"
            );
        }
        let base_length = u32::from_le_bytes(raw[8..12].try_into().unwrap()) as usize;
        let count_offset = 12 + base_length;
        for corruption in 0..6 {
            let mut bad = raw.clone();
            match corruption {
                0 => bad[12..20].copy_from_slice(TAG),
                1 => bad[count_offset..count_offset + 4].copy_from_slice(&2u32.to_le_bytes()),
                2 => {
                    bad[count_offset + 4..count_offset + 8].copy_from_slice(&u32::MAX.to_le_bytes())
                }
                3 => *bad.last_mut().unwrap() = 15,
                4 => bad.push(0),
                _ => {
                    bad[count_offset + 4..count_offset + 8].copy_from_slice(&0u32.to_le_bytes());
                    bad.pop();
                }
            }
            assert!(
                ExecutionSnapshot::decode(&bad, 1).is_err(),
                "corruption {corruption}"
            );
        }
        assert!(ExecutionSnapshot::decode(&raw, 2).is_err());
        source.local_apics[0].eois[0] = 15;
        assert!(source.encoded().is_err());
    }
}
