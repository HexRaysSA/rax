//! Formatting for physical-memory access failures.

/// Preserve the source diagnosis while rendering the address only once.
pub(super) fn guest_access_error(
    operation: &str,
    address: u64,
    source: vm_memory::GuestMemoryError,
) -> String {
    match source {
        // This variant's Display already embeds the address in decimal.
        vm_memory::GuestMemoryError::InvalidGuestAddress(_) => {
            format!("failed to {operation} at {address:#x}: physical range is unmapped")
        }
        other => format!("failed to {operation} at {address:#x}: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::guest_access_error;

    #[test]
    fn partial_access_retains_the_source_diagnosis() {
        let source = vm_memory::GuestMemoryError::PartialBuffer {
            expected: 8,
            completed: 4,
        };
        let diagnosis = source.to_string();
        let message = guest_access_error("read", 0xffc, source);
        assert_eq!(message, format!("failed to read at 0xffc: {diagnosis}"));
    }
}

/// Keep sparse-backing failures typed; callers must not parse formatted errors.
pub(super) fn guest_access_fault(
    access: crate::error::MemoryAccessKind,
    address: u64,
    size: usize,
    source: vm_memory::GuestMemoryError,
) -> crate::error::Error {
    use crate::error::{Error, GuestMemoryFault};
    let missing = match &source {
        vm_memory::GuestMemoryError::InvalidGuestAddress(at) => Some(at.0),
        vm_memory::GuestMemoryError::PartialBuffer { completed, .. } => {
            address.checked_add(*completed as u64)
        }
        _ => None,
    };
    if let Some(missing) = missing {
        return GuestMemoryFault::unmapped(
            missing,
            size.saturating_sub((missing.saturating_sub(address)) as usize),
            access,
        )
        .into();
    }
    Error::Emulator(guest_access_error(&access.to_string(), address, source))
}
