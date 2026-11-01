//! Complete ATA/ATAPI control image; immutable CD media bind through resources.
use super::*;
impl IdeController {
    pub(crate) fn take_checkpoint_buffers(&mut self) -> [Vec<u8>; 3] {
        [
            std::mem::take(&mut self.disk),
            std::mem::take(&mut self.buffer),
            std::mem::take(&mut self.atapi_data),
        ]
    }
    pub(crate) fn bind_checkpoint_buffers(&mut self, [disk, buffer, data]: [Vec<u8>; 3]) {
        self.disk = disk;
        self.buffer = buffer;
        self.atapi_data = data;
    }

    pub(crate) fn checkpoint_cdrom(&self) -> Option<Arc<Vec<u8>>> {
        self.cdrom.clone()
    }
    pub(crate) fn bind_checkpoint_cdrom(&mut self, cdrom: Option<Arc<Vec<u8>>>) {
        self.cdrom = cdrom;
    }
    pub(crate) fn validate_checkpoint(
        &self,
        cmd: u16,
        ctrl: u16,
        media_len: Option<usize>,
        buffer_sizes: [usize; 3],
    ) -> crate::error::Result<()> {
        let [_, buffer_len, atapi_len] = buffer_sizes;
        let bad = || crate::error::Error::InvalidConfig("invalid IDE checkpoint".into());
        if self.cmd_base != cmd
            || self.ctrl_base != ctrl
            || self.buf_pos > self.buf_len
            || self.buf_len > buffer_len
            || buffer_len < SECTOR_SIZE
            || self.atapi_pos > atapi_len
            || self.sectors_left > 65536
            || self.current_lba > ((1u64 << 48) - 1) + 65536
        {
            return Err(bad());
        }
        if self.atapi_media_remaining != 0 {
            let media_len = media_len.ok_or_else(bad)?;
            if self
                .atapi_media_offset
                .checked_add(self.atapi_media_remaining)
                .is_none_or(|end| end > media_len)
                || (self.atapi_in
                    && self.transfer == Transfer::PioIn
                    && self.buf_len > self.atapi_media_remaining)
            {
                return Err(bad());
            }
        } else if self.atapi_in
            && self.transfer == Transfer::PioIn
            && self.buf_len > atapi_len - self.atapi_pos
        {
            return Err(bad());
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partially_written_sector_preserves_buffer_and_mutable_media() {
        let mut source = IdeController::with_sectors(2);
        source.write(0x1f2, 1);
        source.write(0x1f3, 0);
        source.write(0x1f4, 0);
        source.write(0x1f5, 0);
        source.write(0x1f6, 0xe0);
        source.write(0x1f7, 0x30);
        for b in 0..123u8 {
            source.write(0x1f0, b);
        }
        let buffers = source.clone().take_checkpoint_buffers();
        let raw = crate::codec::serialize(&source).unwrap();
        let mut target: IdeController = crate::codec::deserialize_strict(&raw).unwrap();
        target.bind_checkpoint_buffers(buffers);
        target
            .validate_checkpoint(
                0x1f0,
                0x3f6,
                None,
                [
                    target.disk.len(),
                    target.buffer.len(),
                    target.atapi_data.len(),
                ],
            )
            .unwrap();
        for i in 123..512 {
            target.write(0x1f0, i as u8);
            source.write(0x1f0, i as u8);
        }
        assert_eq!(target.disk, source.disk);
        assert_eq!(
            &target.disk[..512],
            &(0..512).map(|i| i as u8).collect::<Vec<_>>()
        );
        assert_eq!(
            crate::codec::serialize(&target).unwrap(),
            crate::codec::serialize(&source).unwrap()
        );
    }
}

#[cfg(test)]
mod interrupted_command_tests {
    use super::*;
    #[test]
    fn control_admission_preserves_guest_interruptions_of_packet_and_data_phases() {
        let mut source = IdeController::new_primary(Vec::new());
        source.attach_cdrom(Arc::new(vec![0x5a; 4096]));
        source.atapi_start_media_read(0, 7);
        source.write(0x1f7, CMD_PACKET);
        assert!(source.awaiting_packet && source.atapi_in);
        for command in [
            CMD_IDENTIFY_PACKET,
            CMD_PACKET,
            CMD_DEVICE_RESET,
            CMD_PACKET,
        ] {
            source.write(0x1f7, command);
            let mut captured = source.clone();
            let buffers = captured.take_checkpoint_buffers();
            let sizes = [buffers[0].len(), buffers[1].len(), buffers[2].len()];
            captured
                .validate_checkpoint(0x1f0, 0x3f6, Some(4096), sizes)
                .unwrap();
            let raw = crate::codec::serialize(&captured).unwrap();
            let mut restored: IdeController = crate::codec::deserialize_strict(&raw).unwrap();
            restored.bind_checkpoint_buffers(buffers);
            restored.bind_checkpoint_cdrom(source.checkpoint_cdrom());
            assert_eq!(
                crate::codec::serialize(&restored).unwrap(),
                crate::codec::serialize(&source).unwrap()
            );
        }
    }
}
