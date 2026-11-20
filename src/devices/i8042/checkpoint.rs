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
    fn pending_auxiliary_loopback_preserves_latch_source_and_irq() {
        for enable_irq in [false, true] {
            let mut source = I8042::new();
            source.write(STATUS_PORT, CMD_WRITE_CMD_BYTE);
            let irq = if enable_irq { CMD_BYTE_AUX_IRQ } else { 0 };
            source.write(DATA_PORT, CMD_BYTE_KBD_DISABLE | CMD_BYTE_AUX_DISABLE | irq);
            source.write(STATUS_PORT, CMD_READ_CMD_BYTE);
            source.write(STATUS_PORT, CMD_WRITE_AUX_OUTPUT_BUFFER);
            assert!(!source.aux_irq_pending());
            assert_eq!(
                source.read(STATUS_PORT) & (STATUS_OBF | STATUS_AUX | STATUS_IBF),
                STATUS_OBF
            );

            let raw = crate::codec::serialize(&source).unwrap();
            let mut target: I8042 = crate::codec::deserialize_strict(&raw).unwrap();
            target.validate_checkpoint().unwrap();
            target.write(DATA_PORT, 0x5a);
            assert!(!target.aux_irq_pending());
            assert_eq!(
                target.read(DATA_PORT),
                irq | CMD_BYTE_KBD_DISABLE | CMD_BYTE_AUX_DISABLE
            );
            assert_eq!(
                target.read(STATUS_PORT) & (STATUS_OBF | STATUS_AUX | STATUS_IBF),
                STATUS_OBF | STATUS_AUX
            );
            assert_eq!(target.aux_irq_pending(), enable_irq);
            assert!(!target.keyboard_irq_pending());
            assert_eq!(target.read(DATA_PORT), 0x5a);
            assert_eq!(target.read(STATUS_PORT) & (STATUS_OBF | STATUS_AUX), 0);
            assert_eq!(target.mouse.sample_rate, source.mouse.sample_rate);
            assert_eq!(crate::codec::serialize(&source).unwrap(), raw);
        }
    }

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
