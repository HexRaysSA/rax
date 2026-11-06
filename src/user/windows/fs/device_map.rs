//! Drive types and logon visibility belong to mapped guest roots.
use super::DriveMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DeviceMap {
    all: [u8; 36],
    logon: [u8; 36],
}

impl Default for DeviceMap {
    fn default() -> Self {
        let mut value = Self::empty();
        value.map_fixed('C');
        value
    }
}

impl DeviceMap {
    pub(super) fn empty() -> Self {
        Self {
            all: [0; 36],
            logon: [0; 36],
        }
    }

    pub(super) fn map_fixed(&mut self, letter: char) {
        if !letter.is_ascii_uppercase() {
            return;
        }
        let index = usize::from(letter as u8 - b'A');
        let bit = 1u32 << index;
        let mask = u32::from_le_bytes(self.all[..4].try_into().unwrap()) | bit;
        self.all[..4].copy_from_slice(&mask.to_le_bytes());
        self.all[4 + index] = 3;
        let logon = u32::from_le_bytes(self.logon[..4].try_into().unwrap()) & !bit;
        self.logon[..4].copy_from_slice(&logon.to_le_bytes());
        self.logon[4 + index] = 0;
    }
}

impl DriveMap {
    /// O(1) time and storage: the native record contains a mask and 32 types.
    pub(crate) fn device_map(&self, logon_only: bool) -> [u8; 36] {
        if logon_only {
            self.devices.logon
        } else {
            self.devices.all
        }
    }

    /// Captured records cannot advertise a drive without a mapped guest root.
    pub(crate) fn apply_device_maps(
        &mut self,
        all: [u8; 36],
        logon: [u8; 36],
    ) -> Result<(), &'static str> {
        let mapped = self.letters().into_iter().fold(0u32, |mask, letter| {
            if letter.is_ascii_uppercase() {
                mask | (1 << (letter as u8 - b'A'))
            } else {
                mask
            }
        });
        let all_mask = u32::from_le_bytes(all[..4].try_into().unwrap());
        let logon_mask = u32::from_le_bytes(logon[..4].try_into().unwrap());
        if all_mask != mapped || logon_mask & !all_mask != 0 {
            return Err("captured device map does not match the mapped guest roots");
        }
        self.devices = DeviceMap { all, logon };
        Ok(())
    }
}

#[cfg(windows)]
mod native;

#[cfg(test)]
mod tests;
