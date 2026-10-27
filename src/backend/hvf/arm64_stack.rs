//! Stack selection for the represented AArch64 EL0/EL1 native VM state.
fn bank(pstate: u64) -> Option<usize> {
    match pstate & 0x1f {
        0 | 4 => Some(0), // EL0t/EL1t use SP_EL0.
        5 => Some(1),     // EL1h uses SP_EL1.
        _ => None,        // AArch32/EL2/EL3 are not this native VM profile.
    }
}
pub(super) fn current_sp(pstate: u64, sp_el0: u64, sp_el1: u64) -> Option<u64> {
    Some([sp_el0, sp_el1][bank(pstate)?])
}
pub(super) fn restored_banks(
    pstate: u64,
    current: u64,
    sp_el0: u64,
    sp_el1: u64,
) -> Option<[u64; 2]> {
    let selected = bank(pstate)?;
    let mut banks = [sp_el0, sp_el1];
    banks[selected] = current;
    Some(banks)
}
