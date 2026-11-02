//! Bounded collection codecs and pure validation for S5L private device state.
use super::*;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

pub(super) const MAX_BYTES: usize = 64 * 1024 * 1024;
const ROWS: usize = 65536;
fn invalid(message: &str) -> Error {
    Error::InvalidConfig(format!("S5L device checkpoint: {message}"))
}
pub(super) fn bytes<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<u8>, D::Error> {
    crate::devices::checkpoint_serde::vector::<u8, D, MAX_BYTES>(d)
}
pub(super) fn queue<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<VecDeque<u8>, D::Error> {
    bytes(d).map(VecDeque::from)
}
pub(super) fn serialize_map<S: serde::Serializer>(
    map: &HashMap<u32, u32>,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    let mut rows: Vec<_> = map.iter().map(|(&key, &value)| (key, value)).collect();
    rows.sort_unstable_by_key(|row| row.0);
    rows.serialize(s)
}
pub(super) fn map<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<HashMap<u32, u32>, D::Error> {
    let rows = crate::devices::checkpoint_serde::vector::<(u32, u32), D, ROWS>(d)?;
    if rows.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(serde::de::Error::custom(
            "S5L map keys are duplicated or unordered",
        ));
    }
    let mut map = HashMap::new();
    map.try_reserve(rows.len())
        .map_err(serde::de::Error::custom)?;
    map.extend(rows);
    Ok(map)
}
impl Pl192 {
    pub(crate) fn validate_checkpoint(&self) -> Result<()> {
        if self.vect_priority.iter().any(|&v| v >= 16)
            || self.daisy_priority >= 16
            || self.stack_i > 16
            || self.current > 33
            || self.current_highest > 33
            || self.priority > 16
            || self.priority_stack.iter().any(|&v| v > 16)
            || self.irq_stack.iter().any(|&v| v > 33)
        {
            return Err(invalid("invalid VIC priority stack/cursor"));
        }
        Ok(())
    }
}
impl S5lDmac {
    pub(crate) fn validate_checkpoint(&self) -> Result<()> {
        if self.pending.is_some_and(|v| v >= 8) {
            return Err(invalid("DMA channel out of range"));
        }
        Ok(())
    }
}
impl S5lUsb {
    pub(crate) fn validate_checkpoint(&self) -> Result<()> {
        if self.fifos.len() != super::usb::USB_FIFO_SIZE as usize
            || self.otg.len() > ROWS
            || self.phy.len() > ROWS
        {
            return Err(invalid("USB FIFO/map shape differs"));
        }
        Ok(())
    }
}
impl S5lI2c {
    pub(crate) fn validate_checkpoint(&self, pmu: bool, accel: bool) -> Result<()> {
        if self.pmu.is_some() != pmu || self.accel.is_some() != accel {
            return Err(invalid("I2C endpoint wiring differs"));
        }
        Ok(())
    }
}
impl S5lSpi {
    pub(crate) fn new_checkpoint_target(index: u8) -> Self {
        use super::spi::{MultitouchSpi, SpiPeripheral};
        let peripheral = match index {
            1 => SpiPeripheral::LcdPanel { cur_cmd: 0 },
            2 => SpiPeripheral::Multitouch(MultitouchSpi {
                cur_cmd: 0,
                out: Vec::new(),
                input: Vec::new(),
                pos: 0,
                hbpp_ack: [0, 0],
                trace: false,
            }),
            _ => SpiPeripheral::None,
        };
        Self {
            regs: [0; 64],
            tx: VecDeque::new(),
            rx: VecDeque::new(),
            peripheral,
        }
    }
    pub(crate) fn validate_checkpoint(&self, index: u8) -> Result<()> {
        use super::spi::SpiPeripheral;
        if self.tx.len() > MAX_BYTES || self.rx.len() > super::spi::SPI_RX_FIFO_MAX {
            return Err(invalid("SPI queue exceeds bound"));
        }
        match (&self.peripheral, index) {
            (SpiPeripheral::None, 0) | (SpiPeripheral::LcdPanel { .. }, 1) => {}
            (SpiPeripheral::Multitouch(mt), 2) => {
                if mt.out.len() > MAX_BYTES
                    || mt.input.len() > MAX_BYTES
                    || mt.pos > mt.out.len()
                    || (mt.cur_cmd != 0 && mt.out.is_empty())
                    || (matches!(mt.cur_cmd, 0xe3 | 0xe6) && mt.out.len() < 16)
                {
                    return Err(invalid("multitouch transaction shape differs"));
                }
            }
            _ => return Err(invalid("SPI endpoint wiring differs")),
        }
        Ok(())
    }
}
impl S5lLcd {
    pub(crate) fn validate_checkpoint(&self) -> Result<()> {
        if self.tick_acc >= 200_000 {
            return Err(invalid("LCD timer phase out of range"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_index_and_topology_validation_rejects_before_use() {
        let mut vic = Pl192::new();
        vic.stack_i = 17;
        assert!(vic.validate_checkpoint().is_err());
        for daisy in [false, true] {
            let mut vic = Pl192::new();
            if daisy {
                vic.daisy_priority = 16;
            } else {
                vic.vect_priority[31] = 16;
            }
            assert!(vic.validate_checkpoint().is_err());
        }
        for cmd in [0xe3, 0xe6] {
            let mut spi = S5lSpi::new_checkpoint_target(2);
            let super::super::spi::SpiPeripheral::Multitouch(mt) = &mut spi.peripheral else {
                panic!()
            };
            mt.cur_cmd = cmd;
            mt.input = vec![cmd];
            mt.out = vec![0];
            assert!(spi.validate_checkpoint(2).is_err());
        }
        let mut dma = S5lDmac::new();
        dma.pending = Some(8);
        assert!(dma.validate_checkpoint().is_err());
        assert!(
            S5lI2c::new(true, false)
                .validate_checkpoint(false, true)
                .is_err()
        );
        assert!(
            S5lSpi::new_checkpoint_target(2)
                .validate_checkpoint(0)
                .is_err()
        );
        let mut lcd = S5lLcd::new();
        lcd.tick_acc = 200_000;
        assert!(lcd.validate_checkpoint().is_err());
        let mut usb = S5lUsb::new();
        usb.fifos.pop();
        assert!(usb.validate_checkpoint().is_err());
    }
    #[test]
    fn canonical_maps_preserve_values_and_reject_duplicate_order_and_counts() {
        #[derive(Deserialize)]
        struct Map(#[serde(deserialize_with = "map")] HashMap<u32, u32>);
        for rows in [vec![(2u32, 3u32), (1, 4)], vec![(1, 3), (1, 4)]] {
            assert!(
                crate::codec::deserialize_strict::<Map>(&crate::codec::serialize(&rows).unwrap())
                    .is_err()
            );
        }
        assert!(crate::codec::deserialize_strict::<Map>(&u64::MAX.to_le_bytes()).is_err());
        let raw = crate::codec::serialize(&vec![(1u32, 3u32), (2, 4)]).unwrap();
        let map = crate::codec::deserialize_strict::<Map>(&raw).unwrap().0;
        assert_eq!(map.get(&2), Some(&4));
    }
    #[test]
    fn all_device_models_roundtrip_through_private_codec_with_partial_protocols() {
        let mut spi = S5lSpi::new_checkpoint_target(2);
        spi.write(0x10, 0x18);
        let encoded = crate::codec::serialize(&spi).unwrap();
        let copy: S5lSpi = crate::codec::deserialize_strict(&encoded).unwrap();
        copy.validate_checkpoint(2).unwrap();
        assert_eq!(crate::codec::serialize(&copy).unwrap(), encoded);
        let usb = S5lUsb::new();
        let encoded = crate::codec::serialize(&usb).unwrap();
        let copy: S5lUsb = crate::codec::deserialize_strict(&encoded).unwrap();
        copy.validate_checkpoint().unwrap();
        assert_eq!(crate::codec::serialize(&copy).unwrap(), encoded);
    }
}
