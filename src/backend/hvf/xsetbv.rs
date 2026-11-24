//! XSETBV exit semantics independent of the host Hypervisor.framework calls.
//! Intel SDM086 Vol.1 section13.3 and Vol.2D XSETBV define this contract.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum XsetbvFault {
    UndefinedOpcode,
    GeneralProtection,
}

impl XsetbvFault {
    /// VM-entry interruption information (hardware exception) and error code.
    pub(crate) fn injection(self, protected_mode: bool) -> (u64, Option<u64>) {
        match self {
            Self::UndefinedOpcode => (0x8000_0306, None),
            Self::GeneralProtection if protected_mode => (0x8000_0b0d, Some(0)),
            Self::GeneralProtection => (0x8000_030d, None),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct XsetbvInput {
    pub xsave_supported: bool,
    pub supported_xcr0: u64,
    pub cr0: u64,
    pub cr4: u64,
    pub rflags: u64,
    pub cs_selector: u16,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
}

/// Validate without changing guest state. High halves of RAX/RCX/RDX are ignored.
/// Fault precedence checks XSAVE/OSXSAVE before privilege and XCR0 contents.
pub(crate) fn xsetbv_value(input: XsetbvInput) -> Result<u64, XsetbvFault> {
    if !input.xsave_supported || input.cr4 & (1 << 18) == 0 {
        return Err(XsetbvFault::UndefinedOpcode);
    }
    let protected = input.cr0 & 1 != 0;
    if protected && (input.rflags & (1 << 17) != 0 || input.cs_selector & 3 != 0) {
        return Err(XsetbvFault::GeneralProtection);
    }
    let value = u64::from(input.rax as u32) | (u64::from(input.rdx as u32) << 32);
    let mpx = value & 0x18;
    let avx512 = value & 0xe0;
    let amx = value & (3 << 17);
    if input.rcx as u32 != 0
        || value & 1 == 0
        || value & !input.supported_xcr0 != 0
        || value & 6 == 4
        || (mpx != 0 && mpx != 0x18)
        || (avx512 != 0 && (avx512 != 0xe0 || value & 6 != 6))
        || (amx != 0 && amx != 3 << 17)
    {
        return Err(XsetbvFault::GeneralProtection);
    }
    Ok(value)
}

/// Boundary between architectural decisions and fallible host API calls.
pub(crate) trait XsetbvAccess {
    type Error;
    fn input(&mut self) -> Result<XsetbvInput, Self::Error>;
    fn write_xcr0(&mut self, value: u64) -> Result<(), Self::Error>;
    fn advance_rip(&mut self) -> Result<(), Self::Error>;
    fn inject_fault(&mut self, fault: XsetbvFault) -> Result<(), Self::Error>;
}

/// Write XCR0 before advancing on success; faults preserve XCR0 and faulting RIP.
pub(crate) fn handle_xsetbv<T: XsetbvAccess>(io: &mut T) -> Result<(), T::Error> {
    match xsetbv_value(io.input()?) {
        Ok(value) => {
            io.write_xcr0(value)?;
            io.advance_rip()
        }
        Err(fault) => io.inject_fault(fault),
    }
}

/// Dynamic XSAVE enumeration for the configured x87/SSE/AVX-only HVF profile.
/// The standard area is 576 bytes without AVX and 832 bytes with YMM_Hi128.
pub(crate) fn xsave_cpuid(
    leaf: u32,
    subleaf: u32,
    mut reply: (u32, u32, u32, u32),
    cr4: u64,
    xcr0: u64,
) -> (u32, u32, u32, u32) {
    if leaf == 1 {
        reply.2 &= !(1 << 27);
        if reply.2 & (1 << 26) != 0 && cr4 & (1 << 18) != 0 {
            reply.2 |= 1 << 27;
        }
    } else if leaf == 0x0d && subleaf == 0 {
        reply.1 = if xcr0 & 4 != 0 { 832 } else { 576 };
    }
    reply
}
