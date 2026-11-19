//! Exact native nested-state envelope, including live header-only VMXON state.
use crate::error::{Error, Result};
use kvm_bindings::{
    CpuId, KVM_STATE_NESTED_EVMCS, KVM_STATE_NESTED_FORMAT_VMX, KVM_STATE_NESTED_GIF_SET,
    KVM_STATE_NESTED_GUEST_MODE, KVM_STATE_NESTED_MTF_PENDING, KVM_STATE_NESTED_RUN_PENDING,
    KVM_STATE_NESTED_SMM_GUEST_MODE, KVM_STATE_NESTED_SMM_VMXON, KVM_STATE_NESTED_VMX_VMCS_SIZE,
    KVM_STATE_VMX_PREEMPTION_TIMER_DEADLINE, kvm_vmx_nested_state_hdr,
};
use kvm_ioctls::{Kvm, KvmNestedStateBuffer, VcpuFd};
use serde::{Deserialize, Deserializer, Serialize};
use std::mem::offset_of;

const HEADER_BYTES: usize = 128;
const BUFFER_BYTES: usize = std::mem::size_of::<KvmNestedStateBuffer>();
const VMX_HEADER: usize = offset_of!(KvmNestedStateBuffer, hdr);
const SMM_FLAGS: usize = VMX_HEADER + offset_of!(kvm_vmx_nested_state_hdr, smm.flags);
const VMXON: usize = VMX_HEADER + offset_of!(kvm_vmx_nested_state_hdr, vmxon_pa);
const VMX_PAGE_BYTES: usize = KVM_STATE_NESTED_VMX_VMCS_SIZE as usize;
const _: () = {
    assert!(std::mem::size_of::<kvm_bindings::kvm_nested_state>() == HEADER_BYTES);
    assert!(std::mem::offset_of!(KvmNestedStateBuffer, hdr) == 8);
    assert!(std::mem::offset_of!(KvmNestedStateBuffer, data) == HEADER_BYTES);
    assert!(BUFFER_BYTES == 8320);
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::backend::kvm) struct Image {
    #[serde(deserialize_with = "bytes")]
    bytes: Vec<u8>,
}

fn bytes<'de, D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error> {
    super::bounded::sequence::<_, _, BUFFER_BYTES>(deserializer)
}

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(format!("native KVM nested-state envelope: {message}"))
}

impl Image {
    fn format(&self) -> u32 {
        u32::from(u16::from_le_bytes(self.bytes[2..4].try_into().unwrap()))
    }

    fn flags(&self) -> u32 {
        u32::from(u16::from_le_bytes(self.bytes[..2].try_into().unwrap()))
    }

    fn vmx_smm_flags(&self) -> u32 {
        u32::from(u16::from_le_bytes(
            self.bytes[SMM_FLAGS..SMM_FLAGS + 2].try_into().unwrap(),
        ))
    }

    fn vmxon_page(&self) -> u64 {
        u64::from_le_bytes(self.bytes[VMXON..VMXON + 8].try_into().unwrap())
    }

    fn suspended_vmx_root(&self) -> bool {
        self.bytes.len() == HEADER_BYTES
            && self.format() == KVM_STATE_NESTED_FORMAT_VMX
            && self.vmx_smm_flags() == KVM_STATE_NESTED_SMM_VMXON
    }

    /// Capture actual returned bytes even when the SDK returns None. That
    /// return value only distinguishes a data tail; a 128-byte header can
    /// retain VMXON state needed for source-free VMXOFF continuation.
    pub(in crate::backend::kvm) fn capture(cpu: &VcpuFd, capacity: usize) -> Result<Option<Self>> {
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
    pub(in crate::backend::kvm) fn from_bytes(bytes: Vec<u8>, capacity: usize) -> Result<Self> {
        let image = Self { bytes };
        image.validate_envelope(capacity)?;
        Ok(image)
    }

    pub(in crate::backend::kvm) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(in crate::backend::kvm) fn validate_envelope(&self, capacity: usize) -> Result<()> {
        if !(HEADER_BYTES..=BUFFER_BYTES).contains(&capacity)
            || !(HEADER_BYTES..=capacity).contains(&self.bytes.len())
        {
            return Err(invalid("record length does not fit the target capacity"));
        }
        if !matches!(self.format(), 0 | 1) {
            return Err(invalid("unknown nested-state vendor format"));
        }
        let declared = u32::from_le_bytes(self.bytes[4..8].try_into().unwrap()) as usize;
        if declared != self.bytes.len() {
            return Err(invalid("declared length differs from the owned record"));
        }
        let flags = self.flags();
        let allowed = KVM_STATE_NESTED_GUEST_MODE
            | KVM_STATE_NESTED_RUN_PENDING
            | KVM_STATE_NESTED_EVMCS
            | KVM_STATE_NESTED_MTF_PENDING
            | KVM_STATE_NESTED_GIF_SET;
        if flags & !allowed != 0
            || (flags & KVM_STATE_NESTED_RUN_PENDING != 0
                && flags & KVM_STATE_NESTED_GUEST_MODE == 0)
        {
            return Err(invalid("invalid native nested-state flags"));
        }
        Ok(())
    }

    pub(super) fn validate_event_mode(&self, capacity: usize, in_smm: bool) -> Result<()> {
        self.validate_envelope(capacity)?;
        if self.format() != KVM_STATE_NESTED_FORMAT_VMX {
            return Ok(());
        }
        let flags = self.flags();
        let smm_flags = self.vmx_smm_flags();
        if smm_flags & !(KVM_STATE_NESTED_SMM_GUEST_MODE | KVM_STATE_NESTED_SMM_VMXON) != 0
            || (smm_flags & KVM_STATE_NESTED_SMM_GUEST_MODE != 0
                && smm_flags & KVM_STATE_NESTED_SMM_VMXON == 0)
        {
            return Err(invalid("invalid suspended VMX mode"));
        }
        // SET_VCPU_EVENTS installs the SMM mode read by SET_NESTED_STATE.
        // Compare the two incoming banks before installing either one.
        if (in_smm && flags & (KVM_STATE_NESTED_GUEST_MODE | KVM_STATE_NESTED_RUN_PENDING) != 0)
            || (!in_smm && smm_flags != 0)
        {
            return Err(invalid("VMX mode disagrees with the saved SMM event state"));
        }
        self.validate_vmx_pages(flags, smm_flags)
    }

    fn validate_vmx_pages(&self, flags: u32, smm_flags: u32) -> Result<()> {
        const VMCS12: usize = VMX_HEADER + offset_of!(kvm_vmx_nested_state_hdr, vmcs12_pa);
        const VMX_FLAGS: usize = VMX_HEADER + offset_of!(kvm_vmx_nested_state_hdr, flags);
        let vmxon = self.vmxon_page();
        let vmcs = u64::from_le_bytes(self.bytes[VMCS12..VMCS12 + 8].try_into().unwrap());
        let vmx_flags =
            u32::from_le_bytes(self.bytes[VMX_FLAGS..VMX_FLAGS + 4].try_into().unwrap());
        if vmx_flags & !KVM_STATE_VMX_PREEMPTION_TIMER_DEADLINE != 0 {
            return Err(invalid("invalid VMX header flags"));
        }
        if vmxon == u64::MAX {
            if vmcs != u64::MAX || smm_flags != 0 || flags & !KVM_STATE_NESTED_EVMCS != 0 {
                return Err(invalid("VMX guest state lacks its VMXON page"));
            }
            return Ok(());
        }
        let page_mask = (VMX_PAGE_BYTES - 1) as u64;
        if vmxon & page_mask != 0 || vmcs != u64::MAX && (vmcs == vmxon || vmcs & page_mask != 0) {
            return Err(invalid("VMXON and VMCS12 must use distinct aligned pages"));
        }
        let has_vmcs = vmcs != u64::MAX || flags & KVM_STATE_NESTED_EVMCS != 0;
        let active_guest = flags & KVM_STATE_NESTED_GUEST_MODE != 0
            || smm_flags & KVM_STATE_NESTED_SMM_GUEST_MODE != 0;
        if active_guest && !has_vmcs
            || has_vmcs && self.bytes.len() < HEADER_BYTES + VMX_PAGE_BYTES
            || !has_vmcs && self.bytes.len() != HEADER_BYTES
        {
            return Err(invalid(
                "nested VMX mode requires a complete VMCS12 payload",
            ));
        }
        Ok(())
    }

    /// Some kernels return success for a 128-byte VMXON record before
    /// assigning the suspended-SMM flags. Test the same record and CPUID on
    /// a disposable descriptor. No guest entry or mapped guest RAM is needed.
    pub(super) fn requires_smi(
        &self,
        kvm: &Kvm,
        cpuid: &CpuId,
        capacity: usize,
        fresh: bool,
        irqchip: bool,
    ) -> Result<bool> {
        use std::sync::{Mutex, atomic::AtomicBool};

        if !self.suspended_vmx_root() {
            return Ok(false);
        }
        // Keep the backing alive if slot removal fails and the disposable
        // VM must be closed to release it.
        let backing = Mutex::new(None);
        let fence = AtomicBool::new(false);
        let vm = kvm.create_vm()?;
        if irqchip {
            vm.create_irq_chip()?;
        }
        let mut cpu = vm.create_vcpu(0)?;
        cpu.set_cpuid2(cpuid)?;
        let mut events = cpu.get_vcpu_events()?;
        events.smi.smm = 1;
        cpu.set_vcpu_events(&events)?;
        self.install(&cpu, capacity)?;
        if self.suspended_root_matches(&cpu, capacity)? {
            return Ok(false);
        }
        if !fresh {
            return Err(invalid(
                "host loses suspended VMXON without a loaded VMCS and the destination is already in use",
            ));
        }
        let scratch = super::smm::Scratch::install(&vm, &backing, &fence)?;
        self.materialize_smm(&mut cpu, capacity)?;
        scratch.finish()?;
        Ok(true)
    }

    pub(super) fn materialize_smm(&self, cpu: &mut VcpuFd, capacity: usize) -> Result<()> {
        super::smm::prepare(cpu)?;
        let mut active = self.clone();
        active.bytes[SMM_FLAGS..SMM_FLAGS + 2].fill(0);
        active.install(cpu, capacity)?;
        super::smm::enter(cpu)?;
        self.verify_suspended_root(cpu, capacity)
    }

    fn suspended_root_matches(&self, cpu: &VcpuFd, capacity: usize) -> Result<bool> {
        Ok(Self::capture(cpu, capacity)?
            .is_some_and(|restored| restored.suspended_vmx_root() && restored.bytes == self.bytes))
    }

    pub(super) fn verify_suspended_root(&self, cpu: &VcpuFd, capacity: usize) -> Result<()> {
        if self.suspended_vmx_root() && !self.suspended_root_matches(cpu, capacity)? {
            return Err(invalid("host loses suspended VMXON without a loaded VMCS"));
        }
        Ok(())
    }

    fn install(&self, cpu: &VcpuFd, capacity: usize) -> Result<()> {
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

    pub(in crate::backend::kvm) fn restore(&self, cpu: &VcpuFd, capacity: usize) -> Result<()> {
        self.install(cpu, capacity)?;
        self.verify_suspended_root(cpu, capacity)
    }
}
