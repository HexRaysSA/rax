//! TOKEN_PRIVILEGES buffer geometry shared by the native capture and guest query.

pub(crate) const TOKEN_PRIVILEGES: u32 = 3;
pub(crate) const HEADER_BYTES: usize = 4;
pub(crate) const ENTRY_BYTES: usize = 12;

/// Returns the required capacity and the number of bytes published. An empty
/// array still requires sizeof(TOKEN_PRIVILEGES), which includes one entry.
pub(crate) fn sizes(count: usize) -> Option<(usize, usize)> {
    if count > 4096 {
        return None;
    }
    let data_bytes = HEADER_BYTES + ENTRY_BYTES * count;
    Some((data_bytes.max(HEADER_BYTES + ENTRY_BYTES), data_bytes))
}
