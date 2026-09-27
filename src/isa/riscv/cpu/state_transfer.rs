//! Architectural state beyond the register files, for vCPU state transfer:
//! the privilege level, the CSRs, and the vector unit.

use super::{Priv, RiscVCpu};
use crate::vm::vcpu::RiscVVectorState;

/// The CSRs exported by number: machine trap setup and handling, the
/// supervisor CSRs the hart keeps, identification, the unprivileged
/// counters, and Zcmt's `jvt`. `sstatus`, `sie`, and `sip` are views of
/// `mstatus`, `mie`, and `mip`.
const EXPORTED_CSRS: &[u16] = &[
    0x300, // mstatus
    0x301, // misa
    0x302, // medeleg
    0x303, // mideleg
    0x304, // mie
    0x305, // mtvec
    0x306, // mcounteren
    0x340, // mscratch
    0x341, // mepc
    0x342, // mcause
    0x343, // mtval
    0x344, // mip
    0x106, // scounteren
    0x141, // sepc
    0xF11, // mvendorid
    0xF12, // marchid
    0xF13, // mimpid
    0xF14, // mhartid
    0xC00, // cycle
    0xC01, // time
    0xC02, // instret
    0x017, // jvt
];

impl RiscVCpu {
    /// The CSRs the hart implements, as (number, value), then any vendor
    /// CSRs it keeps, by number.
    pub fn export_csrs(&self) -> Vec<(u16, u64)> {
        let mut csrs: Vec<(u16, u64)> = EXPORTED_CSRS
            .iter()
            .filter_map(|&n| {
                // The counters regardless of the counter-enable CSRs.
                let value = match n {
                    0xC00 => Some(self.cycle),
                    0xC01 => Some(self.time),
                    0xC02 => Some(self.instret),
                    _ => self.csr_read(n).ok(),
                };
                value.map(|v| (n, v & self.xmask()))
            })
            .collect();
        let mut vendor: Vec<(u16, u64)> = self
            .ext_csr
            .iter()
            .map(|(&n, &v)| (n, v & self.xmask()))
            .collect();
        vendor.sort_unstable();
        csrs.extend(vendor);
        csrs
    }

    /// Writes each CSR with its WARL rules; read-only CSRs and CSRs the
    /// hart does not implement are ignored. The counters are installed
    /// directly.
    pub fn import_csrs(&mut self, csrs: &[(u16, u64)]) {
        for &(n, value) in csrs {
            match n {
                0xC00 => self.cycle = value,
                0xC01 => self.time = value,
                0xC02 => self.instret = value,
                _ => {
                    let _ = self.csr_write(n, value);
                }
            }
        }
    }

    /// The vector unit, when the V extension is enabled.
    pub fn export_vector(&self) -> Option<RiscVVectorState> {
        self.cfg.isa.v.then(|| RiscVVectorState {
            vl: self.vl,
            vtype: self.vtype,
            vstart: self.vstart,
            vxrm: self.vxrm as u8,
            vxsat: self.vxsat as u8,
            v: self.v.to_vec(),
        })
    }

    /// Installs vector state; the register file must be 32 registers of
    /// `vlenb` bytes.
    pub fn import_vector(&mut self, vector: &RiscVVectorState) -> Result<(), String> {
        if vector.v.len() != self.v.len() {
            return Err(format!(
                "vector register file of {} bytes; this hart has {}",
                vector.v.len(),
                self.v.len()
            ));
        }
        self.vl = vector.vl;
        self.vtype = vector.vtype;
        self.vstart = vector.vstart;
        self.vxrm = u64::from(vector.vxrm & 3);
        self.vxsat = u64::from(vector.vxsat & 1);
        self.v.copy_from_slice(&vector.v);
        Ok(())
    }

    /// The privilege level for its encoding (0 = U, 1 = S, 3 = M).
    pub fn privilege_from_level(level: u8) -> Option<Priv> {
        match level {
            0 => Some(Priv::User),
            1 => Some(Priv::Supervisor),
            3 => Some(Priv::Machine),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "state_transfer_tests.rs"]
mod tests;
