//! Installed 32-bit USER/Win32u pairs and their measured 64-bit companions.

use super::{WinArch, WinVersion, invalid, read_image};
use crate::user::windows::gui::Wow64Gdi;
use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};

pub(super) struct Profile {
    pub(super) native_arch: WinArch,
    pub(super) gdi: Wow64Gdi,
    /// SysWOW64 USER32 and Win32u, followed by the native USER32 and Win32u.
    hashes: [&'static str; 4],
}

impl Profile {
    pub(super) fn select(
        arch: WinArch,
        native_machine: Option<u16>,
        version: &WinVersion,
        session: u32,
    ) -> Option<Self> {
        if arch != WinArch::X86 || (version.major, version.minor) != (10, 0) {
            return None;
        }
        let (native_arch, gdi, hashes) = match (version.build, version.product_type, native_machine)
        {
            (29708, _, Some(0xaa64)) if session == 1 => (
                WinArch::Arm64,
                Wow64Gdi::Insider,
                [
                    "0a3c3525232a4309340c4f3012697d1ba543484e66277dca9e5544e2bdabc443",
                    "e9144fb081b9377c670c71eba451a804f987e325bced93a1589533b78a80a528",
                    "55f65842f48d0bb35bd293cc7dc3826a86fc7d39af754575a05d66397932083d",
                    "663353eea03927cae7e882b24fd776e81ecf4072ba4a30e933628342f09eee07",
                ],
            ),
            (26100, 3, Some(0x8664)) if session != 0 => (
                WinArch::X64,
                Wow64Gdi::Released,
                [
                    "41a7f65dcc6ac4cf6c51cc6b107373df1ef48e149ebee90f4a613cd211a81583",
                    "4320e5fb652aae3344859d7d30dc052e16adfb92a11ddceded8e5c7d7b377281",
                    "d2bcc3d2fc93d4c237eade68ea6a6599ed3db8afef1e8b9bf0dd4874e1ed1dff",
                    "c93914457894f5980719c747c7e44dfa1338c71182106b47fbd5f9f998f4600a",
                ],
            ),
            (26200, 1, Some(0xaa64)) if session != 0 => (
                WinArch::Arm64,
                Wow64Gdi::Released,
                [
                    "009912a61639dcaf593dcc99f97796df84adc5fb877461fa7d643d6afc9a0fb0",
                    "bd319b02be682c01dfc69fb678da82b10b54c2733d906054e0f9be2fcd5df2b7",
                    "5d26276f596482c2e6474689e0dd72f885549f313bdac6ae91f4c706f9307b5a",
                    "5d09940ec84656795cd4584178e01d243f257f5b849650ddc34e695f02e6f106",
                ],
            ),
            _ => return None,
        };
        Some(Self {
            native_arch,
            gdi,
            hashes,
        })
    }

    pub(super) fn libraries(
        &self,
        wow_user: &Path,
        wow_win32u: &Path,
        directory: &Path,
    ) -> io::Result<(PathBuf, PathBuf)> {
        // The API-set directory is also the only source of companion DLLs.
        let user = directory.join("user32.dll").canonicalize()?;
        let win32u = directory.join("win32u.dll").canonicalize()?;
        if !user.starts_with(directory) || !win32u.starts_with(directory) {
            return Err(invalid(
                "WoW64 GUI companion DLL escapes the native directory",
            ));
        }
        for (path, hash) in [wow_user, wow_win32u, &user, &win32u]
            .into_iter()
            .zip(self.hashes)
        {
            if format!("{:x}", Sha256::digest(read_image(path)?)) != hash {
                return Err(invalid(
                    "WoW64 GUI paired contexts require the measured installed images",
                ));
            }
        }
        Ok((user, win32u))
    }
}
