//! A selected kernel security device supplies guest-owned file objects.
use super::{Namespace, invalid};
use crate::user::windows::arch::WinArch;
use std::io;

pub(crate) const NAME: &str = "\\Device\\KsecDD";
pub(crate) const CNG_NAME: &str = "\\Device\\CNG";
pub(crate) const SRP_NAME: &str = "\\Device\\SrpDevice";
pub(crate) const KSEC_DEVICE_TYPE: u32 = 0x39;
pub(crate) const CNG_DEVICE_TYPE: u32 = 0x3f;

pub(crate) fn supports_srp_device_absence(
    kernel: (u32, u32, u32),
    arch: WinArch,
    machine: Option<u16>,
) -> bool {
    kernel == (10, 0, 26200)
        && matches!(arch, WinArch::Arm64 | WinArch::X86)
        && machine == Some(0xaa64)
}

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
    pub(crate) fn gameos_provider(kernel: (u32, u32, u32)) -> Self {
        Self {
            kernel,
            revision: 0,
            native_machine: WinArch::X64.machine(),
            device_type: KSEC_DEVICE_TYPE,
            characteristics: 0x100,
        }
    }

    pub(super) fn expected_revision(
        kernel: (u32, u32, u32),
        native_machine: Option<u16>,
    ) -> Option<u32> {
        match (kernel, native_machine) {
            ((10, 0, 29704), Some(0xaa64)) => Some(1010),
            ((10, 0, 29708), Some(0xaa64)) => Some(1003),
            _ => None,
        }
    }

    pub(super) fn supports_server_2022(kernel: (u32, u32, u32), native_machine: u16) -> bool {
        kernel == (10, 0, 20348) && native_machine == WinArch::X64.machine()
    }

    pub(crate) fn server_2022_profile(self) -> bool {
        Self::supports_server_2022(self.kernel, self.native_machine)
    }

    pub(crate) fn selected(self) -> io::Result<Self> {
        let measured = Self::expected_revision(self.kernel, Some(self.native_machine))
            == Some(self.revision)
            && self.characteristics == 0x100;
        if self.device_type != KSEC_DEVICE_TYPE || !(measured || self.server_2022_profile()) {
            return Err(invalid("kernel security-device profile is not measured"));
        }
        Ok(self)
    }

    pub(crate) fn cng_profile(self) -> bool {
        self.kernel == (10, 0, 29708)
            && self.revision == 1003
            && self.native_machine == 0xaa64
            && self.device_type == CNG_DEVICE_TYPE
            && self.characteristics == 0x100
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

    pub(crate) fn select_cng_device(&mut self, device: SecurityDevice) -> io::Result<()> {
        if self.cng_device.is_some()
            || self.native_machine != Some(device.native_machine)
            || !device.cng_profile()
        {
            return Err(invalid("kernel CNG device profile is not measured"));
        }
        self.cng_device = Some(device);
        Ok(())
    }

    pub(crate) fn cng_device(&self) -> Option<SecurityDevice> {
        self.cng_device
    }

    pub(crate) fn capture_security_device(
        &mut self,
        kernel: (u32, u32, u32),
        arch: WinArch,
    ) -> io::Result<()> {
        #[cfg(windows)]
        {
            if supports_srp_device_absence(kernel, arch, self.native_machine) {
                self.srp_device_absent = super::installed::security_device::srp_device_absent();
            }
            super::installed::security_device::select(self, kernel)
        }
        #[cfg(not(windows))]
        {
            let _ = (kernel, arch);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "installed kernel security-device identity requires Windows",
            ))
        }
    }
}
