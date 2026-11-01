//! Complete FIFO protocol and owned floppy image; publication issues no command.
use super::*;
impl Fdc {
    pub(crate) fn take_checkpoint_image(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.image)
    }
    pub(crate) fn bind_checkpoint_image(&mut self, image: Vec<u8>) {
        self.image = image;
    }

    pub(crate) fn validate_checkpoint(&self, image_len: usize) -> crate::error::Result<()> {
        if image_len != IMAGE_SIZE
            || self.params_needed > 8
            || self.params.len() > self.params_needed
            || self.result_pos > self.result.len()
            || self.xfer_pos > self.xfer.len()
            || self.xfer_lba > image_len
            || self.xfer.len() > IMAGE_SIZE
            || self.result.len() > 16
            || self.reset_senses_pending > 4
            || (self.phase == Phase::Parameters && self.params.len() >= self.params_needed)
            || (self.phase == Phase::WriteExecution
                && self.xfer_lba.checked_add(self.xfer.len()).is_none())
        {
            return Err(crate::error::Error::InvalidConfig(
                "invalid FDC checkpoint".into(),
            ));
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partial_command_and_result_cursor_survive_without_reexecution() {
        let mut source = Fdc::new();
        source.write(0x3f2, 0x0c);
        source.write(0x3f5, CMD_SPECIFY);
        source.write(0x3f5, 0xa5);
        let image = source.image.clone();
        let raw = crate::codec::serialize(&source).unwrap();
        let mut target: Fdc = crate::codec::deserialize_strict(&raw).unwrap();
        target.bind_checkpoint_image(image);
        target.validate_checkpoint(IMAGE_SIZE).unwrap();
        target.write(0x3f5, 0x23);
        assert_eq!(target.srt_hut, 0xa5);
        assert_eq!(target.hlt_nd, 0x23);
        target.write(0x3f5, CMD_DUMPREG);
        let first = target.read(0x3f5);
        let mut resumed: Fdc =
            crate::codec::deserialize_strict(&crate::codec::serialize(&target).unwrap()).unwrap();
        resumed.bind_checkpoint_image(target.image.clone());
        resumed.validate_checkpoint(IMAGE_SIZE).unwrap();
        assert_eq!(first, 0);
        for _ in 0..9 {
            assert_eq!(resumed.read(0x3f5), target.read(0x3f5));
        }
    }
}

pub(super) fn params<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    crate::devices::checkpoint_serde::vector::<u8, D, 8>(d)
}

pub(super) fn result<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    crate::devices::checkpoint_serde::vector::<u8, D, 16>(d)
}

pub(super) fn xfer<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    crate::devices::checkpoint_serde::vector::<u8, D, 1474560>(d)
}

#[cfg(test)]
mod write_continuation_tests {
    use super::*;
    #[test]
    fn partial_floppy_write_keeps_staging_cursor_and_owned_image() {
        let mut source = Fdc::new();
        source.write(0x3f2, 0x0c);
        source.write(0x3f5, CMD_WRITE_DATA);
        for byte in [0, 0, 0, 1, 2, 1, 0x1b, 0xff] {
            source.write(0x3f5, byte);
        }
        assert_eq!(source.phase, Phase::WriteExecution);
        for index in 0..123 {
            source.write(0x3f5, index as u8);
        }
        let raw = crate::codec::serialize(&source).unwrap();
        let mut target: Fdc = crate::codec::deserialize_strict(&raw).unwrap();
        target.bind_checkpoint_image(source.image.clone());
        target.validate_checkpoint(IMAGE_SIZE).unwrap();
        for index in 123..512 {
            target.write(0x3f5, index as u8);
        }
        assert_eq!(
            &target.image[..512],
            &(0..512).map(|i| i as u8).collect::<Vec<_>>()
        );
        assert!(source.image[..512].iter().all(|byte| *byte == 0));
        assert_eq!(target.phase, Phase::Result);
        assert!(target.irq_pending);
    }
}
