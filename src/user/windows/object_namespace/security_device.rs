//! A selected kernel security device supplies guest-owned file objects.
use super::{Namespace, invalid};
use std::io;

pub(crate) const NAME: &str = "\\Device\\KsecDD";

/// Fixed native identity, captured before guest execution without retaining a HANDLE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecurityDevice {
    pub(crate) kernel: (u32, u32, u32),
    pub(crate) revision: u32,
    pub(crate) native_machine: u16,
    pub(crate) device_type: u32,
    pub(crate) characteristics: u32,
}

impl SecurityDevice {
    pub(crate) fn selected(self) -> io::Result<Self> {
        if self.kernel != (10, 0, 29704)
            || self.revision != 1010
            || self.native_machine != 0xaa64
            || self.device_type != 0x39
            || self.characteristics != 0x100
        {
            return Err(invalid("kernel security-device profile is not measured"));
        }
        Ok(self)
    }
}

impl Namespace {
    pub(crate) fn select_security_device(&mut self, device: SecurityDevice) -> io::Result<()> {
        let device = device.selected()?;
        if self.security_device.is_some() || self.native_machine != Some(device.native_machine) {
            return Err(invalid(
                "kernel security-device namespace identity conflicts",
            ));
        }
        self.security_device = Some(device);
        Ok(())
    }

    pub(crate) fn security_device(&self) -> Option<SecurityDevice> {
        self.security_device
    }

    pub(crate) fn capture_security_device(&mut self, kernel: (u32, u32, u32)) -> io::Result<()> {
        #[cfg(windows)]
        {
            super::installed::security_device::select(self, kernel)
        }
        #[cfg(not(windows))]
        {
            let _ = kernel;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "installed kernel security-device identity requires Windows",
            ))
        }
    }
}
