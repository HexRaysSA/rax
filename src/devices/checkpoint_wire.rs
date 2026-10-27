//! Shared fixed-width device checkpoint primitives; no host or guest I/O.
use std::io;
pub(super) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
pub(super) struct Writer(pub Vec<u8>);
impl Writer {
    pub fn new(tag: &[u8; 8]) -> Self {
        Self(tag.to_vec())
    }
    pub fn byte(&mut self, v: u8) {
        self.0.push(v);
    }
    pub fn boolean(&mut self, v: bool) {
        self.byte(u8::from(v));
    }
    pub fn short(&mut self, v: u16) {
        self.0.extend(v.to_le_bytes());
    }
    pub fn word(&mut self, v: u32) {
        self.0.extend(v.to_le_bytes());
    }
    pub fn long(&mut self, v: u64) {
        self.0.extend(v.to_le_bytes());
    }
}
pub(super) struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8], tag: &[u8; 8]) -> io::Result<Self> {
        if data.get(..8) != Some(tag) {
            return Err(invalid("unsupported device checkpoint tag"));
        }
        Ok(Self { data, at: 8 })
    }
    fn take<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        let end = self
            .at
            .checked_add(N)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| invalid("truncated device checkpoint"))?;
        let value = self.data[self.at..end].try_into().unwrap();
        self.at = end;
        Ok(value)
    }
    pub fn byte(&mut self) -> io::Result<u8> {
        Ok(self.take::<1>()?[0])
    }
    pub fn boolean(&mut self) -> io::Result<bool> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(invalid("invalid device checkpoint boolean")),
        }
    }
    pub fn short(&mut self) -> io::Result<u16> {
        Ok(u16::from_le_bytes(self.take()?))
    }
    pub fn word(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(self.take()?))
    }
    pub fn long(&mut self) -> io::Result<u64> {
        Ok(u64::from_le_bytes(self.take()?))
    }
    pub fn end(self) -> io::Result<()> {
        if self.at != self.data.len() {
            return Err(invalid("trailing device checkpoint bytes"));
        }
        Ok(())
    }
}
