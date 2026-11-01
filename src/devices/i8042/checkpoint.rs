//! Queues, visible output latch, command parameter and mouse handshake state.
use super::*;
impl I8042 {
    pub(crate) fn validate_checkpoint(&self) -> crate::error::Result<()> {
        if self.kbd_queue.len() > DEVICE_QUEUE_CAPACITY
            || self.aux_queue.len() > DEVICE_QUEUE_CAPACITY
            || self.mouse.resolution > 3
            || self.mouse.buttons & !7 != 0
            || ![MOUSE_ID_STANDARD, MOUSE_ID_INTELLIMOUSE].contains(&self.mouse.device_id)
        {
            return Err(crate::error::Error::InvalidConfig(
                "invalid i8042 checkpoint".into(),
            ));
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_mouse_parameter_and_interleaved_output_survive() {
        let mut source = I8042::new();
        source.write(0x64, 0xd4);
        source.write(0x60, 0xf3);
        source.write(0x64, 0xd4);
        source.kbd_queue.extend([0x1c, 0x9c]);
        source.aux_queue.push_back(0x55);
        let raw = crate::codec::serialize(&source).unwrap();
        let mut target: I8042 = crate::codec::deserialize_strict(&raw).unwrap();
        target.validate_checkpoint().unwrap();
        target.write(0x60, 200);
        source.write(0x60, 200);
        assert_eq!(target.mouse.sample_rate, 200);
        for _ in 0..8 {
            assert_eq!(target.read(0x60), source.read(0x60));
        }
        assert_eq!(
            crate::codec::serialize(&target).unwrap(),
            crate::codec::serialize(&source).unwrap()
        );
    }
}

pub(super) fn queue<'de, D: serde::Deserializer<'de>>(d: D) -> Result<VecDeque<u8>, D::Error> {
    crate::devices::checkpoint_serde::vector::<u8, D, DEVICE_QUEUE_CAPACITY>(d).map(Into::into)
}
