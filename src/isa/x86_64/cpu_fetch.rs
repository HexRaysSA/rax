//! Instruction-window acquisition. Speculative bytes do not fault until needed.
use super::cpu::{MAX_INSN_LEN, X86_64Vcpu};
use crate::error::{Error, GuestMemoryFault, MemoryAccessKind, Result};

#[derive(Clone, Copy, Debug)]
pub(super) enum DeferredFetchFault {
    Physical(GuestMemoryFault),
    Page { address: u64, error_code: u64 },
}
impl DeferredFetchFault {
    pub(super) fn error(self) -> Error {
        match self {
            Self::Physical(fault) => fault.into(),
            Self::Page {
                address,
                error_code,
            } => Error::PageFault {
                vaddr: address,
                error_code,
            },
        }
    }
}
type Window = ([u8; MAX_INSN_LEN], usize, bool, Option<DeferredFetchFault>);

fn execution_fault(error: Error) -> Error {
    match error {
        Error::GuestAccess(mut fault) => {
            fault.access = MemoryAccessKind::Fetch;
            fault.into()
        }
        Error::PageFault { vaddr, error_code } => Error::PageFault {
            vaddr,
            error_code: error_code | 0x10,
        },
        other => other,
    }
}

impl X86_64Vcpu {
    /// Fetch up to 15 bytes. Retain the exact inaccessible-byte address if the
    /// window is truncated; a short instruction that fits must still execute.
    pub(super) fn fetch(&mut self) -> Result<Window> {
        let base = if self.sregs.cs.l {
            0
        } else {
            self.sregs.cs.base
        };
        let rip = base.wrapping_add(self.regs.rip);
        self.mmu.mark_code_page(rip);
        self.mmu.set_fetch_active(true);
        let result = self.fetch_window(rip);
        self.mmu.set_fetch_active(false);
        if let Ok((_, len, _, _)) = &result {
            self.mmu.record_fetch(rip, (*len).min(MAX_INSN_LEN) as u8);
        }
        result
    }

    fn fetch_window(&mut self, rip: u64) -> Result<Window> {
        let mut buf = [0u8; MAX_INSN_LEN];
        let mut last_error = None;
        // Fixed upper bound: at most 15 reads, no mapping changes or retries of
        // execution. The decoder receives the fault only if it needs a missing byte.
        for len in (1..=MAX_INSN_LEN).rev() {
            match self.mmu.read(rip, &mut buf[..len], &self.sregs) {
                Ok(()) => {
                    let (gp, fault) = match last_error {
                        Some(Error::GeneralProtection { .. }) => (true, None),
                        Some(Error::GuestAccess(fault)) => {
                            (false, Some(DeferredFetchFault::Physical(fault)))
                        }
                        Some(Error::PageFault { vaddr, error_code }) => (
                            false,
                            Some(DeferredFetchFault::Page {
                                address: vaddr,
                                error_code,
                            }),
                        ),
                        _ => (false, None),
                    };
                    return Ok((buf, len, gp, fault));
                }
                Err(error) => last_error = Some(execution_fault(error)),
            }
        }
        Err(last_error.expect("nonempty instruction fetch attempted"))
    }
}
