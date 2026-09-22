//! Internal scalar atomic-transaction callback ABI.

/// Operation numbers passed to [`super::GuestRegs::atomic_rmw_fn`]. These are
/// explicit ABI values, not the discriminants of the SMIR `AtomicOp` enum.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86AtomicRmwOp {
    Add = 0,
    Or = 1,
    And = 2,
    Sub = 3,
    Xor = 4,
    Swap = 5,
}

impl X86AtomicRmwOp {
    pub const fn from_raw(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Add),
            1 => Some(Self::Or),
            2 => Some(Self::And),
            3 => Some(Self::Sub),
            4 => Some(Self::Xor),
            5 => Some(Self::Swap),
            _ => None,
        }
    }

    /// Compute a replacement element modulo 2^(8 * size), with `size` in
    /// bytes. This pure arithmetic helper supplies no synchronization itself.
    pub const fn apply(self, old: u64, operand: u64, size: u32) -> Option<u64> {
        let mask = match size {
            1 => u8::MAX as u64,
            2 => u16::MAX as u64,
            4 => u32::MAX as u64,
            8 => u64::MAX,
            _ => return None,
        };
        let value = match self {
            Self::Add => old.wrapping_add(operand),
            Self::Or => old | operand,
            Self::And => old & operand,
            Self::Sub => old.wrapping_sub(operand),
            Self::Xor => old ^ operand,
            Self::Swap => operand,
        };
        Some(value & mask)
    }
}

/// SysV two-eightbyte integer return: original zero-extended memory element
/// in RAX, success in RDX. On failure (`ok == 0`), the callback must not have
/// written guest memory or committed any architectural state.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X86AtomicRmwRet {
    pub old_value: u64,
    pub ok: u64,
}

/// Exactly one sequentially consistent read-modify-write transaction over
/// `size` bytes at `addr`. Concurrent backends must synchronize this transaction
/// with every overlapping access; the canonical vCPU relies on its existing
/// serial MMU execution contract. A callback must not unwind across this ABI.
/// `operand` is the SMIR source value: a folded immediate materializer is
/// truncated to its declared width, whereas a GPR source retains all 64 bits.
/// The selected operation reduces its result modulo 2^(8 * size).
pub type X86AtomicRmwFn = unsafe extern "C" fn(
    ctx: *mut core::ffi::c_void,
    addr: u64,
    operand: u64,
    size: u32,
    operation: u32,
) -> X86AtomicRmwRet;
