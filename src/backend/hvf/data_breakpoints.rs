//! Data-address matches for scalar accesses completed outside native execution.
//! Intel SDM086 Vol.3B 19.2.1/19.2.4-19.2.6/19.3.1.2 and Vol.3C 28.7.3.

pub(crate) const ENABLED_BREAKPOINT: u64 = 1 << 12;

/// Only enabled data conditions participate. Instruction and I/O conditions
/// are handled by their execution domains, not by a data-memory access.
pub(crate) fn relevant(dr7: u64, writing: bool) -> u8 {
    let mut enabled = 0;
    for slot in 0..4 {
        let condition = (dr7 >> (16 + slot * 4)) & 3;
        if (dr7 >> (slot * 2)) & 3 != 0 && (condition == 3 || (writing && condition == 1)) {
            enabled |= 1 << slot;
        }
    }
    enabled
}

/// Return VMCS pending-debug B0-B3 and enabled-breakpoint bit12, without
/// changing DR6. Hardware publishes DR6 only on delivery of the eventual #DB.
/// RF does not suppress data traps; TF is independently handled at retirement.
/// Four watches and at most eight bytes give O(1) time and auxiliary space.
pub(crate) fn causes(
    dr7: u64,
    addresses: &[u64; 4],
    linear: u64,
    size: u8,
    writing: bool,
) -> Result<u64, &'static str> {
    if !matches!(size, 1 | 2 | 4 | 8) {
        return Err("unsupported scalar data-breakpoint access width");
    }
    let enabled = relevant(dr7, writing);
    let mut hits = 0;
    for (slot, address) in addresses.iter().enumerate() {
        if enabled & (1 << slot) == 0 {
            continue;
        }
        let length = match (dr7 >> (18 + slot * 4)) & 3 {
            0 => 1,
            1 => 2,
            2 => 8,
            _ => 4,
        };
        // Defined watch ranges are naturally aligned. Apply the SDM's LEN
        // masking for other inputs without claiming their undefined results.
        let mask = !(length - 1);
        if (0..size).any(|offset| linear.wrapping_add(u64::from(offset)) & mask == address & mask) {
            hits |= 1 << slot;
        }
    }
    Ok(if hits == 0 {
        0
    } else {
        hits | ENABLED_BREAKPOINT
    })
}
