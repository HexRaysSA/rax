//! Public architectural overlays preserve unprojected kernel state. Complete
//! migration additionally needs the private CPU/shared/in-flight producer.
use super::{KvmVcpu, convert, xsave};
use crate::error::{Error, Result};
use crate::vm::vcpu::CpuState;
use crate::vm::vcpu::X86_64CpuState;
use kvm_bindings::{Msrs, kvm_debugregs, kvm_msr_entry, kvm_regs, kvm_sregs, kvm_vcpu_events};
use kvm_ioctls::VcpuFd;

const MSRS: [u32; 7] = [
    0xc000_0081,
    0xc000_0082,
    0xc000_0083,
    0xc000_0084,
    0x174,
    0x175,
    0x176,
];

fn msr_table(entries: &[kvm_msr_entry]) -> Result<Msrs> {
    Msrs::from_entries(entries)
        .map_err(|error| Error::Emulator(format!("KVM public MSR table: {error}")))
}

fn write_msrs(cpu: &VcpuFd, entries: &[kvm_msr_entry]) -> Result<()> {
    let count = cpu.set_msrs(&msr_table(entries)?)?;
    if count != entries.len() {
        return Err(Error::Emulator(format!(
            "KVM public MSR write completed {count} of {} entries",
            entries.len()
        )));
    }
    Ok(())
}

fn stage(name: &str, error: impl std::fmt::Display) -> Error {
    Error::Emulator(format!("KVM {name}: {error}"))
}

struct Image {
    regs: kvm_regs,
    sregs: kvm_sregs,
    debug: kvm_debugregs,
    events: kvm_vcpu_events,
    msrs: Vec<kvm_msr_entry>,
    xsave: xsave::Image,
}

impl Image {
    fn read(cpu: &KvmVcpu) -> Result<Self> {
        let entries: Vec<_> = MSRS
            .iter()
            .map(|&index| kvm_msr_entry {
                index,
                ..Default::default()
            })
            .collect();
        let mut msrs = msr_table(&entries)?;
        let count = cpu.vcpu_fd.get_msrs(&mut msrs)?;
        if count != entries.len() {
            return Err(Error::Emulator(format!(
                "KVM public MSR read completed {count} of {} entries",
                entries.len()
            )));
        }
        Ok(Self {
            regs: cpu.vcpu_fd.get_regs()?,
            sregs: cpu.vcpu_fd.get_sregs()?,
            debug: cpu.vcpu_fd.get_debug_regs()?,
            events: cpu.vcpu_fd.get_vcpu_events()?,
            msrs: msrs.as_slice().to_vec(),
            xsave: xsave::Image::read(&cpu.memory_owner.vm_fd, &cpu.vcpu_fd)?,
        })
    }

    fn public(&self) -> Result<X86_64CpuState> {
        let mut regs = convert::regs_from_kvm(&self.regs);
        self.xsave.layout.project(&self.xsave.bytes, &mut regs)?;
        let mut sregs = convert::sregs_from_kvm(&self.sregs);
        sregs.dr0 = self.debug.db[0];
        sregs.dr1 = self.debug.db[1];
        sregs.dr2 = self.debug.db[2];
        sregs.dr3 = self.debug.db[3];
        sregs.dr6 = self.debug.dr6;
        sregs.dr7 = self.debug.dr7;
        sregs.star = self.msrs[0].data;
        sregs.lstar = self.msrs[1].data;
        sregs.cstar = self.msrs[2].data;
        sregs.fmask = self.msrs[3].data;
        sregs.sysenter_cs = self.msrs[4].data;
        sregs.sysenter_esp = self.msrs[5].data;
        sregs.sysenter_eip = self.msrs[6].data;
        Ok(X86_64CpuState { regs, sregs })
    }

    fn write(&self, cpu: &KvmVcpu) -> Result<()> {
        self.xsave
            .write(&cpu.memory_owner.vm_fd, &cpu.vcpu_fd)
            .map_err(|error| stage("SET_XSAVE", error))?;
        write_msrs(&cpu.vcpu_fd, &self.msrs)?;
        cpu.vcpu_fd
            .set_debug_regs(&self.debug)
            .map_err(|error| stage("SET_DEBUGREGS", error))?;
        // An unchanged public control bank must not reload cached PDPTRs or
        // republish its pending interrupt bitmap as a side effect.
        if cpu.vcpu_fd.get_sregs()? != self.sregs {
            cpu.vcpu_fd
                .set_sregs(&self.sregs)
                .map_err(|error| stage("SET_SREGS", error))?;
        }
        cpu.vcpu_fd
            .set_regs(&self.regs)
            .map_err(|error| stage("SET_REGS", error))?;
        cpu.vcpu_fd
            .set_vcpu_events(&self.events)
            .map_err(|error| stage("SET_VCPU_EVENTS", error))?;
        Ok(())
    }

    fn overlay(&self, state: &X86_64CpuState) -> Result<Self> {
        let bytes = self.xsave.layout.overlay(&self.xsave.bytes, &state.regs)?;
        let current = self.public()?;
        let same_vectors = current.regs.mm == state.regs.mm
            && current.regs.xmm == state.regs.xmm
            && current.regs.ymm_high == state.regs.ymm_high
            && current.regs.zmm_high == state.regs.zmm_high
            && current.regs.zmm_ext == state.regs.zmm_ext
            && current.regs.k == state.regs.k;
        let mut xsave = self.xsave.clone();
        // Preserve exact initialization/component state for a round trip.
        if !same_vectors {
            xsave.bytes = bytes;
        }
        let mut debug = self.debug;
        debug.db = [
            state.sregs.dr0,
            state.sregs.dr1,
            state.sregs.dr2,
            state.sregs.dr3,
        ];
        debug.dr6 = state.sregs.dr6;
        debug.dr7 = state.sregs.dr7;
        let mut msrs = self.msrs.clone();
        for (entry, value) in msrs.iter_mut().zip([
            state.sregs.star,
            state.sregs.lstar,
            state.sregs.cstar,
            state.sregs.fmask,
            state.sregs.sysenter_cs,
            state.sregs.sysenter_esp,
            state.sregs.sysenter_eip,
        ]) {
            entry.data = value;
        }
        Ok(Self {
            regs: convert::regs_to_kvm(&state.regs),
            sregs: convert::sregs_to_kvm(&state.sregs, &self.sregs),
            debug,
            events: self.events,
            msrs,
            xsave,
        })
    }
}

impl KvmVcpu {
    pub(super) fn state_ready(&self) -> Result<()> {
        match &self.state_failure {
            Some(error) => Err(Error::Emulator(error.clone())),
            None => Ok(()),
        }
    }

    pub(super) fn public_state(&self) -> Result<CpuState> {
        self.state_ready()?;
        Ok(CpuState::X86_64(Image::read(self)?.public()?))
    }

    pub(super) fn set_public_state(&mut self, state: &CpuState) -> Result<()> {
        self.state_ready()?;
        let CpuState::X86_64(state) = state else {
            return Err(Error::InvalidConfig(
                "KVM backend only supports x86_64 state".into(),
            ));
        };
        if self.pending_io_in.is_some() {
            return Err(Error::InvalidConfig(
                "KVM public state overlay requires completed input".into(),
            ));
        }
        let backup = Image::read(self)?;
        let desired = backup.overlay(state)?;
        if let Err(error) = desired.write(self) {
            if let Err(rollback) = backup.write(self) {
                let failure = format!(
                    "KVM public state publication failed: {error}; rollback failed: {rollback}; guest entry disabled"
                );
                self.state_failure = Some(failure.clone());
                return Err(Error::Emulator(failure));
            }
            return Err(error);
        }
        Ok(())
    }
}
