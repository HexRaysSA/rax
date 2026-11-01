//! Owner-thread SDK transfer of the complete host-sized XSAVE image.
#[path = "intel_cpuid_profile.rs"]
mod fingerprint;

use super::bindings::{
    HV_SUCCESS, hv_error_string, hv_vcpu_read_fpstate, hv_vcpu_write_fpstate, hv_vcpuid_t,
};
use crate::backend::intel_hvf_context::{
    Capabilities, Cpuid, Identity, Profile, Register, optional_field, policy_fields,
    vmcs_candidates,
};
use crate::backend::intel_hvf_xsave::{Component, Layout, MAX_IMAGE};
use crate::error::{Error, Result};
use std::arch::x86_64::__cpuid_count;
use std::ffi::c_void;

#[repr(C, align(64))]
struct Block([u8; 64]);
struct Buffer {
    blocks: Vec<Block>,
    length: usize,
}
impl Buffer {
    fn new(length: usize) -> Result<Self> {
        if !(576..=MAX_IMAGE).contains(&length) {
            return Err(Error::InvalidConfig(
                "native XSAVE buffer length exceeds its profile".into(),
            ));
        }
        let count = length.div_ceil(64);
        let mut blocks = Vec::new();
        blocks
            .try_reserve_exact(count)
            .map_err(|error| Error::Emulator(format!("native XSAVE allocation: {error}")))?;
        blocks.resize_with(count, || Block([0; 64]));
        Ok(Self { blocks, length })
    }
    fn pointer(&mut self) -> *mut c_void {
        self.blocks.as_mut_ptr().cast()
    }
    fn bytes(&self) -> &[u8] {
        // SAFETY: Block is exactly 64 initialized bytes with 64-byte alignment.
        // The retained vector contains ceil(length/64) blocks; no SDK operation
        // is active while this shared view is borrowed.
        unsafe { std::slice::from_raw_parts(self.blocks.as_ptr().cast(), self.length) }
    }
    fn fill(&mut self, bytes: &[u8]) {
        // SAFETY: callers checked the exact logical length. This exclusive
        // view remains inside the initialized, retained aligned allocation.
        let target =
            unsafe { std::slice::from_raw_parts_mut(self.blocks.as_mut_ptr().cast(), self.length) };
        target.copy_from_slice(bytes);
    }
}

pub(super) fn cpuid(leaf: u32, subleaf: u32) -> [u32; 4] {
    // SAFETY: x86-64 provides CPUID. No feature-dependent state instruction is
    // executed; unsupported CPUID leaves are validated by the caller.
    let value = unsafe { __cpuid_count(leaf, subleaf) };
    [value.eax, value.ebx, value.ecx, value.edx]
}

pub(super) fn discover(id: hv_vcpuid_t) -> Result<Layout> {
    let state = cpuid(0x0d, 0);
    let mask = u64::from(state[0]) | (u64::from(state[3]) << 32);
    let mut components = Vec::new();
    for bit in 2..63 {
        if mask & (1u64 << bit) == 0 {
            continue;
        }
        let description = cpuid(0x0d, bit);
        if description[2] & 1 != 0 {
            return Err(Error::InvalidConfig(
                "host XCR0 component was described as supervisor state".into(),
            ));
        }
        components.push(Component {
            bit: bit as u8,
            size: description[0],
            offset: description[1],
            align64: description[2] & 2 != 0,
        });
    }
    let mut layout = Layout {
        mask,
        size: state[2],
        components,
        mxcsr_mask: 0xffbf,
    };
    layout.validate()?;
    let bytes = read_unchecked(id, layout.size as usize)?;
    let reported = u32::from_le_bytes(bytes[28..32].try_into().unwrap());
    // Intel SDM FXSAVE: zero MXCSR_MASK uses the architectural fallback mask.
    layout.mxcsr_mask = if reported == 0 { 0xffbf } else { reported };
    layout.validate_image(&bytes)?;
    Ok(layout)
}

fn read_unchecked(id: hv_vcpuid_t, length: usize) -> Result<Vec<u8>> {
    let mut buffer = Buffer::new(length)?;
    // SAFETY: permanent SDK owner and live handle. The exclusive buffer is
    // initialized, 64-byte aligned, and retained for this synchronous copy.
    // The ABI is checked against retained SDK hv.h; the SDK retains no pointer.
    let result = unsafe { hv_vcpu_read_fpstate(id, buffer.pointer(), length) };
    if result != HV_SUCCESS {
        return Err(Error::Emulator(format!(
            "native XSAVE read: {}",
            hv_error_string(result)
        )));
    }
    Ok(buffer.bytes().to_vec())
}
pub(super) fn read(id: hv_vcpuid_t, layout: &Layout) -> Result<Vec<u8>> {
    layout.validate()?;
    let bytes = read_unchecked(id, layout.size as usize)?;
    layout.validate_image(&bytes)?;
    Ok(bytes)
}
pub(super) fn write(id: hv_vcpuid_t, layout: &Layout, bytes: &[u8]) -> Result<()> {
    layout.validate_image(bytes)?;
    let mut buffer = Buffer::new(bytes.len())?;
    buffer.fill(bytes);
    // SAFETY: creator-thread handle; admitted complete image in an exclusive,
    // initialized and aligned allocation. The mutable SDK input pointer does
    // not alias the immutable source record and is not retained after return.
    let result = unsafe { hv_vcpu_write_fpstate(id, buffer.pointer(), bytes.len()) };
    if result == HV_SUCCESS {
        Ok(())
    } else {
        Err(Error::Emulator(format!(
            "native XSAVE write: {}",
            hv_error_string(result)
        )))
    }
}
pub(super) fn reset(id: hv_vcpuid_t, layout: &Layout) -> Result<()> {
    let mut image = vec![0; layout.size as usize];
    image[..2].copy_from_slice(&0x037fu16.to_le_bytes());
    image[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
    image[28..32].copy_from_slice(&layout.mxcsr_mask.to_le_bytes());
    image[512..520].copy_from_slice(&3u64.to_le_bytes());
    write(id, layout, &image)
}

pub(super) fn profile(
    id: hv_vcpuid_t,
    identity: &super::rosetta::CpuidConfig,
    layout: Layout,
) -> Result<Profile> {
    use super::bindings::*;
    let mut host = Vec::new();
    let maximum_basic = cpuid(0, 0)[0];
    let maximum_extended = cpuid(0x8000_0000, 0)[0];
    for (leaf, subleaf) in [
        (0, 0),
        (1, 0),
        (7, 0),
        (0x0d, 0),
        (0x0d, 1),
        (0x15, 0),
        (0x16, 0),
        (0x8000_0000, 0),
        (0x8000_0007, 0),
        (0x8000_0008, 0),
    ] {
        let supported = if leaf >= 0x8000_0000 {
            leaf <= maximum_extended
        } else {
            leaf <= maximum_basic
        };
        if !supported {
            continue;
        }
        let words = fingerprint::normalize(leaf, subleaf, cpuid(leaf, subleaf));
        host.push(Cpuid {
            leaf,
            subleaf,
            words,
        });
    }
    for component in &layout.components {
        host.push(Cpuid {
            leaf: 0x0d,
            subleaf: u32::from(component.bit),
            words: cpuid(0x0d, u32::from(component.bit)),
        });
    }
    host.sort_by_key(|entry| (entry.leaf, entry.subleaf));
    let cap = |field| -> Result<u64> {
        let mut value = 0;
        // SAFETY: exact SDK scalar output and capability identifier; no vCPU
        // thread affinity is required, and the caller is already its owner.
        let result = unsafe { hv_vmx_read_capability(field, &mut value) };
        if result == HV_SUCCESS {
            Ok(value)
        } else {
            Err(Error::Emulator(format!(
                "native context capability {field}: {}",
                hv_error_string(result)
            )))
        }
    };
    let capabilities = Capabilities {
        pin: cap(HV_VMX_CAP_PINBASED)?,
        primary: cap(HV_VMX_CAP_PROCBASED)?,
        secondary: cap(HV_VMX_CAP_PROCBASED2)?,
        entry: cap(HV_VMX_CAP_ENTRY)?,
        misc: cap(HV_VMX_CAP_MISC)?,
    };
    let mut fields = Vec::new();
    for field in vmcs_candidates() {
        let mut value = 0;
        // SAFETY: exact SDK field identifier and live scalar output word on
        // the creating thread. Unavailable unused optional fields are recorded
        // as absent; required guest state cannot be silently omitted.
        let result = unsafe { hv_vmx_vcpu_read_vmcs(id, field, &mut value) };
        if result == HV_SUCCESS {
            fields.push(field);
        } else if !optional_field(field) || !matches!(result, HV_BAD_ARGUMENT | HV_UNSUPPORTED) {
            return Err(Error::Emulator(format!(
                "native context VMCS field {field:#x}: {}",
                hv_error_string(result)
            )));
        }
    }
    let mut controls = Vec::new();
    for field in policy_fields() {
        controls.push(Register {
            id: field,
            value: super::convert::vmcs_read_raw(id, field)?,
        });
    }
    let mut frequency = 0u64;
    let mut size = std::mem::size_of_val(&frequency);
    // SAFETY: constant nul-terminated sysctl key, one live initialized scalar
    // and its in/out length; no write value is supplied. Some translated hosts
    // have no physical TSC frequency, which is retained as unknown.
    let status = unsafe {
        libc::sysctlbyname(
            c"machdep.tsc.frequency".as_ptr(),
            (&mut frequency as *mut u64).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    let tsc_hz = (status == 0 && size == 8 && frequency != 0).then_some(frequency);
    let profile = Profile {
        identity: Identity {
            maximum_basic: identity.max_basic_leaf,
            maximum_extended: identity.max_extended_leaf,
            vendor: identity.vendor,
            brand: identity.brand.to_vec(),
        },
        host,
        xsave: layout,
        capabilities,
        fields,
        controls,
        tsc_hz,
    };
    profile.validate()?;
    Ok(profile)
}
