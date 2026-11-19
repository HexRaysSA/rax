//! Self-relative descriptors captured for the fixed RPC Control directory.

pub(crate) const LABEL_SECURITY_INFORMATION: u32 = 0x10;
pub(crate) const CAPTURED_SECURITY_INFORMATION: u32 = 0x07 | LABEL_SECURITY_INFORMATION;
pub(crate) const SE_SELF_RELATIVE: u16 = 0x8000;
pub(crate) const READ_CONTROL: u32 = 0x0002_0000;
pub(crate) const SACL_SECURITY_INFORMATION: u32 = 0x08;
pub(crate) const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
const UNPROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x2000_0000;

#[derive(Debug)]
pub(crate) struct RpcSecurity {
    pub(crate) descriptors: [Option<Box<[u8]>>; 16],
}

impl RpcSecurity {
    pub(crate) fn descriptor(&self, mask: u32) -> Option<&[u8]> {
        let mask = match mask {
            UNPROTECTED_DACL_SECURITY_INFORMATION => 0,
            mask if mask & !CAPTURED_SECURITY_INFORMATION == 0 => mask,
            _ => return None,
        };
        let index = (mask & 7) | ((mask & LABEL_SECURITY_INFORMATION) >> 1);
        self.descriptors[index as usize].as_deref()
    }
}
