//! A stopped CPU's address-space description, independent of data publication.
use crate::error::{Error, Result};
use crate::isa::x86_64::inspection::{LegacyFeatures, Paging, PhysicalMemory};
#[derive(Clone, Copy, Debug)]
pub struct X86DebugPaging {
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
    pub physical_bits: u32,
    /// Legacy PAE uses architectural cached PDPTEs, never invented RAM reloads.
    pub pdpte: Option<[u64; 4]>,
    pub pse36: bool,
    pub pat: bool,
}
#[derive(Clone, Copy, Debug)]
pub enum DebugAddressSpace {
    /// Legacy adapters without a translated debug view retain their physical view.
    Physical,
    X86(X86DebugPaging),
}
impl DebugAddressSpace {
    pub(crate) fn translate<M: PhysicalMemory>(self, memory: &mut M, linear: u64) -> Result<u64> {
        match self {
            Self::Physical => Ok(linear),
            Self::X86(p) => {
                if p.cr0 & (1 << 31) != 0
                    && p.cr4 & (1 << 5) != 0
                    && p.efer & (1 << 10) == 0
                    && p.pdpte.is_none()
                {
                    return Err(Error::Emulator(
                        "legacy PAE debugger translation requires cached PDPTE state".into(),
                    ));
                }
                Paging {
                    cr0: p.cr0,
                    cr3: p.cr3,
                    cr4: p.cr4,
                    efer: p.efer,
                    physical_bits: p.physical_bits,
                    pdpte: p.pdpte.unwrap_or([0; 4]),
                }
                .translate_with_legacy(
                    memory,
                    linear,
                    LegacyFeatures {
                        pse36: p.pse36,
                        pat: p.pat,
                    },
                )
                .map_err(Error::Emulator)
            }
        }
    }
}
