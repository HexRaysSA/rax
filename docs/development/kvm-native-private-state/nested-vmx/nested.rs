//! Exact native nested-state envelope, including live header-only VMXON state.
use crate::error::{Error, Result};
use kvm_ioctls::{KvmNestedStateBuffer, VcpuFd};
use serde::{Deserialize, Serialize};

const HEADER_BYTES: usize = 128;
const BUFFER_BYTES: usize = std::mem::size_of::<KvmNestedStateBuffer>();
const _: () = {
    assert!(std::mem::size_of::<kvm_bindings::kvm_nested_state>() == HEADER_BYTES);
    assert!(std::mem::offset_of!(KvmNestedStateBuffer, hdr) == 8);
    assert!(std::mem::offset_of!(KvmNestedStateBuffer, data) == HEADER_BYTES);
    assert!(BUFFER_BYTES == 8320);
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Image {
    bytes: Vec<u8>,
}

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(format!("native KVM nested-state envelope: {message}"))
}

impl Image {
    /// Capture actual returned bytes even when the SDK returns None. That
    /// return value only distinguishes a data tail; a 128-byte header can
    /// retain VMXON state needed for source-free VMXOFF continuation.
    pub(super) fn capture(cpu: &VcpuFd, capacity: usize) -> Result<Option<Self>> {
        if capacity == 0 {
            return Ok(None);
        }
        if !(HEADER_BYTES..=BUFFER_BYTES).contains(&capacity) {
            return Err(invalid("kernel capacity exceeds the admitted SDK buffer"));
        }
        let mut buffer = KvmNestedStateBuffer::empty();
        let _tail_length = cpu.nested_state(&mut buffer)?;
        let length = buffer.size as usize;
        if !(HEADER_BYTES..=capacity).contains(&length) {
            return Err(invalid("kernel returned an out-of-bounds state length"));
        }
        // SAFETY: empty() initializes the full fixed-size integer/byte/union
        // buffer before the synchronous GET. The layout assertions establish
        // contiguous 8-byte metadata, 120-byte header and 8192-byte data, with
        // no uncovered struct padding. Every union byte is represented by
        // byte arrays; no pointer, reference or invalid scalar representation
        // is present. The checked actual length fits the live local buffer.
        // No native entry or mutation occurs while these bytes are copied;
        // u8 needs no additional alignment and the copied Vec owns its data.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&buffer as *const KvmNestedStateBuffer).cast::<u8>(),
                length,
            )
        }
        .to_vec();
        Ok(Some(Self::from_bytes(bytes, capacity)?))
    }

    /// Envelope admission only. The complete producer must separately admit
    /// CPUID/vendor/profile compatibility, nested control fields, VMCS contents
    /// and restore order before coordinated publication and rollback.
    pub(super) fn from_bytes(bytes: Vec<u8>, capacity: usize) -> Result<Self> {
        let image = Self { bytes };
        image.validate_envelope(capacity)?;
        Ok(image)
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn validate_envelope(&self, capacity: usize) -> Result<()> {
        if !(HEADER_BYTES..=BUFFER_BYTES).contains(&capacity)
            || !(HEADER_BYTES..=capacity).contains(&self.bytes.len())
        {
            return Err(invalid("record length does not fit the target capacity"));
        }
        let format = u16::from_le_bytes(self.bytes[2..4].try_into().unwrap());
        if !matches!(format, 0 | 1) {
            return Err(invalid("unknown nested-state vendor format"));
        }
        let declared = u32::from_le_bytes(self.bytes[4..8].try_into().unwrap()) as usize;
        if declared != self.bytes.len() {
            return Err(invalid("declared length differs from the owned record"));
        }
        Ok(())
    }

    pub(super) fn restore(&self, cpu: &VcpuFd, capacity: usize) -> Result<()> {
        self.validate_envelope(capacity)?;
        let mut buffer = KvmNestedStateBuffer::empty();
        // SAFETY: the envelope has an exact validated length within the
        // initialized, statically checked fixed SDK layout. Source and target
        // are disjoint owned allocations, valid for the entire byte count;
        // u8 requires no alignment. All destination fields are integer/byte
        // representations. The local mutable buffer has no aliases and is
        // borrowed immutably by the subsequent synchronous native setter.
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.bytes.as_ptr(),
                (&mut buffer as *mut KvmNestedStateBuffer).cast::<u8>(),
                self.bytes.len(),
            );
        }
        cpu.set_nested_state(&buffer)?;
        Ok(())
    }
}
