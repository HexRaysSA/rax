//! Fallible bounded compressed output shared by checkpoint payloads.
use std::io::Write;
pub(super) fn compressed_limit(size: u64) -> u64 {
    size + size / 128 + 1024 * 1024
}
pub(super) struct FallibleBytes {
    pub(super) bytes: Vec<u8>,
    pub(super) limit: usize,
}
impl Write for FallibleBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > self.limit)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "compressed media exceeds limit",
            ));
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(std::io::Error::other)?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
