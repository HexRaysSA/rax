//! Pure dual-controller admission, including byte-pointer and read-clear latches.
use super::*;
impl Dma {
    pub(crate) fn validate_checkpoint(&self) -> crate::error::Result<()> {
        if [&self.c1, &self.c2].iter().any(|c| c.request & !0x0f != 0) {
            return Err(crate::error::Error::InvalidConfig(
                "invalid DMA request mask".into(),
            ));
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partial_register_bytes_and_read_clear_status_survive() {
        let mut source = Dma::new();
        source.write(0x00, 0x34);
        source.write(0x83, 0x56);
        source.c1.status = 1;
        source.c2.flip_flop = true;
        let raw = crate::codec::serialize(&source).unwrap();
        let mut target: Dma = crate::codec::deserialize_strict(&raw).unwrap();
        target.validate_checkpoint().unwrap();
        target.write(0x00, 0x12);
        assert_eq!(target.current_address(0), 0x1234);
        assert_eq!(target.channel(1).page, 0x56);
        assert!(target.c2.flip_flop);
        assert_eq!(target.read(0x08) & 1, 1);
        assert_eq!(target.read(0x08) & 1, 0);
    }
}
