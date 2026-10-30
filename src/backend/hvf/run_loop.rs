//! Iterative Intel VM-exit dispatch, independent of native host calls.
//! Constants retain Intel SDM086 AppendixC basic exit reasons.

pub(crate) mod reason {
    pub const VMX_EXIT_REASON_HLT: u32 = 12;
    pub const VMX_EXIT_REASON_IO: u32 = 30;
    pub const VMX_EXIT_REASON_EPT_VIOLATION: u32 = 48;
    pub const VMX_EXIT_REASON_CPUID: u32 = 10;
    pub const VMX_EXIT_REASON_RDMSR: u32 = 31;
    pub const VMX_EXIT_REASON_WRMSR: u32 = 32;
    pub const VMX_EXIT_REASON_TRIPLE_FAULT: u32 = 2;
    pub const VMX_EXIT_REASON_EXCEPTION_NMI: u32 = 0;
    pub const VMX_EXIT_REASON_EXT_INTERRUPT: u32 = 1;
    pub const VMX_EXIT_REASON_IRQ_WINDOW: u32 = 7;
    pub const VMX_EXIT_REASON_CR_ACCESS: u32 = 28;
    pub const VMX_EXIT_REASON_XSETBV: u32 = 55;
    pub const VMX_EXIT_REASON_MONITOR_TRAP: u32 = 37;
}
use reason::*;

/// One host VM-entry/exit boundary. Methods may return a public exit or resume.
pub(crate) trait ExitHandler {
    type Exit;
    type Error;
    fn prepare(&mut self) -> Result<Option<Self::Exit>, Self::Error>;
    fn next_reason(&mut self) -> Result<u32, Self::Error>;
    fn halt(&mut self) -> Result<Self::Exit, Self::Error>;
    fn port_io(&mut self) -> Result<Self::Exit, Self::Error>;
    fn mmio(&mut self) -> Result<Self::Exit, Self::Error>;
    fn cpuid(&mut self) -> Result<(), Self::Error>;
    fn rdmsr(&mut self) -> Result<Option<Self::Exit>, Self::Error>;
    fn wrmsr(&mut self) -> Result<Option<Self::Exit>, Self::Error>;
    fn shutdown(&mut self) -> Result<Self::Exit, Self::Error>;
    fn exception(&mut self) -> Result<Self::Exit, Self::Error>;
    fn monitor_trap(&mut self) -> Result<Self::Exit, Self::Error>;
    fn interrupt_window(&mut self) -> Result<(), Self::Error>;
    fn control_register(&mut self) -> Result<(), Self::Error>;
    fn xsetbv(&mut self) -> Result<(), Self::Error>;
    fn fail_entry(&mut self, raw_reason: u32) -> Result<Self::Exit, Self::Error>;
    fn unknown(&mut self, basic_reason: u32) -> Result<Self::Exit, Self::Error>;
}

/// O(n) work for n internal exits; O(1) host stack and auxiliary storage.
pub(crate) fn run<T: ExitHandler>(handler: &mut T) -> Result<T::Exit, T::Error> {
    loop {
        if let Some(exit) = handler.prepare()? {
            return Ok(exit);
        }
        let raw_reason = handler.next_reason()?;
        if raw_reason & (1 << 31) != 0 {
            return handler.fail_entry(raw_reason);
        }
        match raw_reason & 0xffff {
            VMX_EXIT_REASON_HLT => return handler.halt(),
            VMX_EXIT_REASON_IO => return handler.port_io(),
            VMX_EXIT_REASON_EPT_VIOLATION => return handler.mmio(),
            VMX_EXIT_REASON_CPUID => handler.cpuid()?,
            VMX_EXIT_REASON_RDMSR => {
                if let Some(exit) = handler.rdmsr()? {
                    return Ok(exit);
                }
            }
            VMX_EXIT_REASON_WRMSR => {
                if let Some(exit) = handler.wrmsr()? {
                    return Ok(exit);
                }
            }
            VMX_EXIT_REASON_TRIPLE_FAULT => return handler.shutdown(),
            VMX_EXIT_REASON_EXCEPTION_NMI => return handler.exception(),
            VMX_EXIT_REASON_MONITOR_TRAP => return handler.monitor_trap(),
            VMX_EXIT_REASON_EXT_INTERRUPT => {}
            VMX_EXIT_REASON_IRQ_WINDOW => handler.interrupt_window()?,
            VMX_EXIT_REASON_CR_ACCESS => handler.control_register()?,
            VMX_EXIT_REASON_XSETBV => handler.xsetbv()?,
            basic => return handler.unknown(basic),
        }
    }
}
