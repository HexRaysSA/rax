//! Kernel-sized XSAVE transfer using the host's architectural component table.
//! KVM API sections 4.42/4.43/4.134 specify host CPUID.0DH offsets and the
//! VM-specific KVM_CAP_XSAVE2 allocation size. No guest instruction executes.
use crate::backend::intel_hvf_xsave::{Component, Layout, MAX_IMAGE};
use crate::error::{Error, Result};
use kvm_bindings::Xsave;
use kvm_ioctls::{Cap, VcpuFd, VmFd};

#[derive(Clone)]
pub(super) struct Image {
    pub(super) layout: Layout,
    pub(super) bytes: Vec<u8>,
}

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::InvalidConfig(format!("KVM XSAVE: {message}"))
}

fn cpuid(leaf: u32, subleaf: u32) -> std::arch::x86_64::CpuidResult {
    // SAFETY: this module only builds on x86-64, where CPUID is available.
    // No XGETBV or feature-dependent state instruction is executed.
    unsafe { std::arch::x86_64::__cpuid_count(leaf, subleaf) }
}

fn host_mxcsr_mask() -> Result<u32> {
    if cpuid(1, 0).edx & (1 << 24) == 0 {
        return Err(invalid("host has no architectural FXSAVE support"));
    }
    #[repr(C, align(16))]
    struct Legacy([u8; 512]);
    let mut legacy = Legacy([0; 512]);
    // SAFETY: CPUID confirmed FXSAVE support. The destination owns 512
    // initialized bytes with the required 16-byte alignment. FXSAVE reads the
    // current host FP state without changing it; no pointer escapes the call.
    unsafe { std::arch::x86_64::_fxsave64(legacy.0.as_mut_ptr()) };
    let mask = u32::from_le_bytes(legacy.0[28..32].try_into().unwrap());
    Ok(if mask == 0 { 0xffbf } else { mask })
}

fn kernel_size(vm: &VmFd) -> Result<Option<usize>> {
    let size = vm.check_extension_int(Cap::Xsave2);
    if size < 0 {
        return Err(Error::Emulator(format!(
            "KVM XSAVE capability query failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    checked_size(size)
}

fn checked_size(size: i32) -> Result<Option<usize>> {
    if size == 0 {
        return Ok(None);
    }
    let size = usize::try_from(size).map_err(|_| invalid("negative capability size"))?;
    if !(4096..=MAX_IMAGE).contains(&size) || size % 4 != 0 {
        return Err(invalid("invalid KVM_CAP_XSAVE2 size"));
    }
    Ok(Some(size))
}

fn buffer(size: usize) -> Result<Xsave> {
    if !(4096..=MAX_IMAGE).contains(&size) || size % 4 != 0 {
        return Err(invalid("image outside allocation bounds"));
    }
    Xsave::new((size - 4096) / 4).map_err(invalid)
}

impl Image {
    pub(super) fn read(vm: &VmFd, cpu: &VcpuFd) -> Result<Self> {
        let state = cpuid(0x0d, 0);
        let mask = u64::from(state.eax) | (u64::from(state.edx) << 32);
        let required = kernel_size(vm)?;
        // Also allocate for every host user component. A later dynamic XSTATE
        // permission cannot make the kernel copy beyond this retained buffer.
        let size = required.unwrap_or(4096).max(state.ecx as usize);
        let size = size
            .checked_add(3)
            .map(|size| size & !3)
            .filter(|&size| size <= MAX_IMAGE)
            .ok_or_else(|| invalid("host component image exceeds allocation bound"))?;
        let mut native = buffer(size)?;
        if required.is_some() {
            // SAFETY: `native` owns at least the VM-reported byte count and
            // the host's full user-XSTATE size, including components that a
            // later dynamic permission could enable. The kernel retains no
            // pointer after this synchronous ioctl.
            unsafe { cpu.get_xsave2(&mut native)? };
        } else {
            let fixed = cpu.get_xsave()?;
            // SAFETY: replace only the initialized fixed image; the wrapper's
            // allocation and FAM length remain unchanged.
            unsafe { native.as_mut_fam_struct().xsave = fixed };
        }
        let bytes: Vec<_> = native
            .as_fam_struct_ref()
            .xsave
            .region
            .iter()
            .chain(native.as_slice())
            .flat_map(|word| word.to_le_bytes())
            .collect();
        let mut components = Vec::new();
        for bit in 2..63 {
            if mask & (1u64 << bit) == 0 {
                continue;
            }
            let description = cpuid(0x0d, bit);
            if description.ecx & 1 != 0 {
                return Err(invalid("user component was described as supervisor state"));
            }
            components.push(Component {
                bit: bit as u8,
                size: description.eax,
                offset: description.ebx,
                align64: description.ecx & 2 != 0,
            });
        }
        let layout = Layout {
            mask,
            size: size as u32,
            components,
            // KVM can leave MXCSR_MASK zero in its exported image. The live
            // architectural mask also admits supported DAZ state correctly.
            mxcsr_mask: host_mxcsr_mask()?,
        };
        layout.validate_image(&bytes)?;
        Ok(Self { layout, bytes })
    }

    pub(super) fn write(&self, vm: &VmFd, cpu: &VcpuFd) -> Result<()> {
        self.layout.validate_image(&self.bytes)?;
        let required = kernel_size(vm)?;
        if required.is_some_and(|size| size > self.bytes.len()) {
            return Err(invalid(
                "native image requirement changed before publication",
            ));
        }
        let mut native = buffer(self.bytes.len())?;
        // SAFETY: borrow only the fixed 1024-word field. Neither the wrapper's
        // FAM length nor the allocation is changed while it is borrowed.
        let fixed = unsafe { &mut native.as_mut_fam_struct().xsave.region };
        for (word, bytes) in fixed.iter_mut().zip(self.bytes[..4096].chunks_exact(4)) {
            *word = u32::from_le_bytes(bytes.try_into().unwrap());
        }
        for (word, bytes) in native
            .as_mut_slice()
            .iter_mut()
            .zip(self.bytes[4096..].chunks_exact(4))
        {
            *word = u32::from_le_bytes(bytes.try_into().unwrap());
        }
        if required.is_some() {
            // SAFETY: this initialized FAM allocation covers the freshly
            // queried VM size and every host user-XSTATE component. Its owner
            // remains live until the synchronous kernel read has returned.
            unsafe { cpu.set_xsave2(&native)? };
        } else {
            // SAFETY: without KVM_CAP_XSAVE2 the old kernel ABI copies exactly
            // the initialized 4096-byte fixed image, which is retained here.
            unsafe { cpu.set_xsave(&native.as_fam_struct_ref().xsave)? };
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_bounds_cover_fixed_and_dynamic_images_without_rounding_down() {
        for size in [0, 4095, 4097, MAX_IMAGE + 4, usize::MAX] {
            assert!(buffer(size).is_err(), "{size}");
        }
        for size in [4096, 4100, MAX_IMAGE] {
            let native = buffer(size).unwrap();
            assert_eq!(4096 + native.as_slice().len() * 4, size);
        }
    }

    #[test]
    fn only_zero_capability_selects_the_legacy_image() {
        assert_eq!(checked_size(0).unwrap(), None);
        for size in [i32::MIN, -1, 1, 4095, 4097, MAX_IMAGE as i32 + 4, i32::MAX] {
            assert!(checked_size(size).is_err(), "{size}");
        }
        for size in [4096, 4100, MAX_IMAGE as i32] {
            assert_eq!(checked_size(size).unwrap(), Some(size as usize));
        }
    }
}
