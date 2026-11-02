//! Complete represented hart state, independent of RAM and host code caches.
use super::{Priv, RiscVConfig, RiscVCpu, VLENB};
use crate::isa::riscv::FlatMemory;
use crate::vm::vcpu::{CpuState, RiscVRegisters};
use serde::{Deserialize, Serialize};

fn vector_bytes<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    crate::devices::checkpoint_serde::vector::<u8, D, { 32 * VLENB as usize }>(d)
}
fn vendor_csrs<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<(u16, u64)>, D::Error> {
    crate::devices::checkpoint_serde::vector::<(u16, u64), D, 65536>(d)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CoreContext {
    cfg: RiscVConfig,
    x: [u64; 32],
    f: [u64; 32],
    pc: u64,
    fcsr: u32,
    priv_: Priv,
    reservation: Option<u64>,
    mstatus: u64,
    mtvec: u64,
    mepc: u64,
    sepc: u64,
    mcause: u64,
    mtval: u64,
    mscratch: u64,
    mie: u64,
    mip: u64,
    medeleg: u64,
    mideleg: u64,
    mcounteren: u64,
    scounteren: u64,
    mhartid: u64,
    jvt: u64,
    cycle: u64,
    time: u64,
    instret: u64,
    vl: u64,
    vtype: u64,
    vstart: u64,
    vxrm: u64,
    vxsat: u64,
    #[serde(deserialize_with = "vector_bytes")]
    v: Vec<u8>,
    #[serde(deserialize_with = "vendor_csrs")]
    ext_csr: Vec<(u16, u64)>,
}

impl CoreContext {
    pub(crate) fn configuration(&self) -> RiscVConfig {
        self.cfg
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.x[0] != 0 || self.fcsr & !0xff != 0 {
            return Err("invalid integer-zero register or FP status width".into());
        }
        if self.v.len() != 32 * VLENB as usize || self.vxrm > 3 || self.vxsat > 1 {
            return Err("invalid vector geometry or status width".into());
        }
        if self.ext_csr.len() > 65536 || self.ext_csr.windows(2).any(|p| p[0].0 >= p[1].0) {
            return Err("vendor CSR table is not strictly ordered and unique".into());
        }
        if self
            .reservation
            .is_some_and(|addr| addr & !self.cfg.xlen.mask() != 0)
        {
            return Err("reservation exceeds the configured address width".into());
        }
        Ok(())
    }

    pub(crate) fn hart_id(&self) -> u64 {
        self.mhartid
    }
    pub(crate) fn privilege(&self) -> Priv {
        self.priv_
    }

    pub(crate) fn public_state(&self, tohost: Option<u64>) -> CpuState {
        // Projection is defined by the same core getters/CSR views as the live
        // backend, including RV32 masks and read-only identification fields.
        let mut cpu = RiscVCpu::new(self.cfg, Box::new(FlatMemory::new(0, 0)));
        self.clone().install(&mut cpu);
        CpuState::riscv(cpu.public_registers(tohost))
    }

    /// Caller admits geometry and all fallible resource locks before install.
    pub(crate) fn install(self, cpu: &mut RiscVCpu) {
        cpu.cfg = self.cfg;
        cpu.x = self.x;
        cpu.f = self.f;
        cpu.pc = self.pc;
        cpu.fcsr = self.fcsr;
        cpu.priv_ = self.priv_;
        cpu.reservation = self.reservation;
        cpu.mstatus = self.mstatus;
        cpu.mtvec = self.mtvec;
        cpu.mepc = self.mepc;
        cpu.sepc = self.sepc;
        cpu.mcause = self.mcause;
        cpu.mtval = self.mtval;
        cpu.mscratch = self.mscratch;
        cpu.mie = self.mie;
        cpu.mip = self.mip;
        cpu.medeleg = self.medeleg;
        cpu.mideleg = self.mideleg;
        cpu.mcounteren = self.mcounteren;
        cpu.scounteren = self.scounteren;
        cpu.mhartid = self.mhartid;
        cpu.jvt = self.jvt;
        cpu.cycle = self.cycle;
        cpu.time = self.time;
        cpu.instret = self.instret;
        cpu.vl = self.vl;
        cpu.vtype = self.vtype;
        cpu.vstart = self.vstart;
        cpu.vxrm = self.vxrm;
        cpu.vxsat = self.vxsat;
        cpu.v.copy_from_slice(&self.v);
        cpu.ext_csr = self.ext_csr.into_iter().collect();
        // Native code addresses, decode decisions and host diagnostic cache
        // counters are derived; no native block is executing across this borrow.
        #[cfg(all(
            feature = "smir-jit",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        cpu.jit.clear();
    }
}

impl RiscVCpu {
    pub(crate) fn checkpoint_state(&self) -> CoreContext {
        // Intentionally exhaustive: a new core field must be classified here.
        let RiscVCpu {
            cfg,
            x,
            f,
            pc,
            fcsr,
            priv_,
            reservation,
            mstatus,
            mtvec,
            mepc,
            sepc,
            mcause,
            mtval,
            mscratch,
            mie,
            mip,
            medeleg,
            mideleg,
            mcounteren,
            scounteren,
            mhartid,
            jvt,
            cycle,
            time,
            instret,
            vl,
            vtype,
            vstart,
            vxrm,
            vxsat,
            v,
            ext_csr,
            mem: _,
            #[cfg(all(
                feature = "smir-jit",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
                jit: _,
        } = self;
        let mut vendor: Vec<_> = ext_csr.iter().map(|(&n, &value)| (n, value)).collect();
        vendor.sort_unstable_by_key(|row| row.0);
        CoreContext {
            cfg: *cfg,
            x: *x,
            f: *f,
            pc: *pc,
            fcsr: *fcsr,
            priv_: *priv_,
            reservation: *reservation,
            mstatus: *mstatus,
            mtvec: *mtvec,
            mepc: *mepc,
            sepc: *sepc,
            mcause: *mcause,
            mtval: *mtval,
            mscratch: *mscratch,
            mie: *mie,
            mip: *mip,
            medeleg: *medeleg,
            mideleg: *mideleg,
            mcounteren: *mcounteren,
            scounteren: *scounteren,
            mhartid: *mhartid,
            jvt: *jvt,
            cycle: *cycle,
            time: *time,
            instret: *instret,
            vl: *vl,
            vtype: *vtype,
            vstart: *vstart,
            vxrm: *vxrm,
            vxsat: *vxsat,
            v: v.to_vec(),
            ext_csr: vendor,
        }
    }

    pub(crate) fn public_registers(&self, tohost_addr: Option<u64>) -> RiscVRegisters {
        let mut regs = RiscVRegisters::default();
        for i in 0..32u8 {
            regs.x[i as usize] = self.x(i);
            regs.f[i as usize] = self.f(i);
        }
        regs.pc = self.pc();
        regs.fcsr = self.fcsr();
        regs.tohost_addr = tohost_addr;
        regs.privilege = Some(self.privilege() as u8);
        regs.csrs = self.export_csrs();
        regs.vector = self.export_vector();
        regs
    }
}

#[cfg(test)]
mod tests;
