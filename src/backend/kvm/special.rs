//! Preserve native PAE caches when overlaying unrelated public registers.
//! Linux v6.8 KVM API 4.131/4.132 and x86.c __set_sregs{,2} define these ABIs.
use super::convert;
use crate::error::{Error, Result};
use crate::vm::vcpu::SystemRegisters;
use kvm_bindings::{KVM_CAP_SREGS2, kvm_sregs, kvm_sregs2};
use kvm_ioctls::{VcpuFd, VmFd};
use std::os::fd::AsRawFd;

pub(super) struct Image {
    pub(super) legacy: kvm_sregs,
    extended: Option<kvm_sregs2>,
}

fn get_extended(cpu: &VcpuFd) -> Result<kvm_sregs2> {
    let mut value = kvm_sregs2::default();
    // SAFETY: the retained x86 UAPI defines this output ioctl and struct. The
    // stopped CPU owns its FD; the initialized, aligned output stays exclusive
    // and live for the synchronous copy. The kernel retains no pointer.
    let result = unsafe {
        libc::ioctl(
            cpu.as_raw_fd(),
            libc::_IOR::<kvm_sregs2>(kvm_bindings::KVMIO, 0xcc),
            &mut value as *mut kvm_sregs2,
        )
    };
    if result < 0 {
        return Err(Error::Emulator(format!(
            "KVM GET_SREGS2: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(value)
}

fn set_extended(cpu: &VcpuFd, value: &kvm_sregs2) -> Result<()> {
    // SAFETY: the retained x86 UAPI defines this input ioctl and struct. The
    // stopped CPU owns its FD; this fully initialized, aligned input remains
    // borrowed for the synchronous copy. The kernel retains no pointer.
    let result = unsafe {
        libc::ioctl(
            cpu.as_raw_fd(),
            libc::_IOW::<kvm_sregs2>(kvm_bindings::KVMIO, 0xcd),
            value as *const kvm_sregs2,
        )
    };
    if result < 0 {
        return Err(Error::Emulator(format!(
            "KVM SET_SREGS2: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn pae_paging(value: &kvm_sregs) -> bool {
    value.cr0 & (1 << 31) != 0 && value.cr4 & (1 << 5) != 0 && value.efer & (1 << 10) == 0
}

impl Image {
    pub(super) fn read(vm: &VmFd, cpu: &VcpuFd) -> Result<Self> {
        let available = vm.check_extension_raw(KVM_CAP_SREGS2.into());
        if available < 0 {
            return Err(Error::Emulator(format!(
                "KVM SREGS2 capability query: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(Self {
            legacy: cpu.get_sregs()?,
            extended: (available > 0).then(|| get_extended(cpu)).transpose()?,
        })
    }

    pub(super) fn overlay(&self, public: &SystemRegisters) -> Result<Self> {
        let legacy = convert::sregs_to_kvm(public, &self.legacy);
        let extended = match self.extended {
            Some(current) => {
                // A public CR3 change requests a new page-directory table.
                // Other edits within PAE retain its already-cached pointers,
                // even when the corresponding physical table has changed.
                let preserve = pae_paging(&self.legacy)
                    && pae_paging(&legacy)
                    && self.legacy.cr3 == legacy.cr3;
                Some(kvm_sregs2 {
                    cs: legacy.cs,
                    ds: legacy.ds,
                    es: legacy.es,
                    fs: legacy.fs,
                    gs: legacy.gs,
                    ss: legacy.ss,
                    tr: legacy.tr,
                    ldt: legacy.ldt,
                    gdt: legacy.gdt,
                    idt: legacy.idt,
                    cr0: legacy.cr0,
                    cr2: legacy.cr2,
                    cr3: legacy.cr3,
                    cr4: legacy.cr4,
                    cr8: legacy.cr8,
                    efer: legacy.efer,
                    apic_base: legacy.apic_base,
                    flags: if preserve { current.flags } else { 0 },
                    pdptrs: if preserve { current.pdptrs } else { [0; 4] },
                })
            }
            None => {
                // Old kernels cannot export the PAE cache for publication or
                // rollback. Unchanged special registers need no setter.
                if pae_paging(&self.legacy) && legacy != self.legacy {
                    return Err(Error::InvalidConfig(
                        "KVM PAE special-register overlay requires KVM_CAP_SREGS2".into(),
                    ));
                }
                None
            }
        };
        Ok(Self { legacy, extended })
    }

    pub(super) fn write(&self, cpu: &VcpuFd) -> Result<()> {
        if let Some(extended) = &self.extended {
            // This ABI also avoids republishing the legacy interrupt bitmap.
            // Compare the cache as well: a rollback must restore it even if
            // the public control registers already match their backup.
            if get_extended(cpu)? != *extended {
                set_extended(cpu, extended)?;
            }
        } else if cpu.get_sregs()? != self.legacy {
            cpu.set_sregs(&self.legacy)
                .map_err(|error| Error::Emulator(format!("KVM SET_SREGS: {error}")))?;
        }
        Ok(())
    }
}
