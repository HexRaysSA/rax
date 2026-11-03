//! Width-preserving fixed-port reads for scalar and batched PIO input.
use super::SERIAL_BASE;
use crate::devices::bus::{IoBus, IoDevice};
use crate::devices::serial::Serial16550;
use crate::error::{Error, Result};
use std::sync::{Arc, Mutex};

/// Each element is one scalar port transaction. Generic byte lanes advance
/// within that element; the next element starts at the original port again.
/// IDE data-register bytes all use the same FIFO port. O(count * size) work
/// and storage, with allocation completed before any device read side effects.
pub(super) fn read(
    bus: &mut IoBus,
    serial: &Arc<Mutex<Serial16550>>,
    port: u16,
    size: u8,
    count: u32,
) -> Result<Vec<u8>> {
    if !matches!(size, 1 | 2 | 4) || count == 0 {
        return Err(Error::InvalidConfig(
            "invalid port input element width or count".into(),
        ));
    }
    let width = usize::from(size);
    let length = width
        .checked_mul(count as usize)
        .ok_or_else(|| Error::InvalidConfig("port input byte count overflow".into()))?;
    let mut data = Vec::new();
    data.try_reserve_exact(length)
        .map_err(|error| Error::Emulator(format!("port input allocation: {error}")))?;
    data.resize(length, 0);
    if (SERIAL_BASE..SERIAL_BASE + 8).contains(&port) {
        if let Ok(mut serial) = serial.lock() {
            for element in data.chunks_exact_mut(width) {
                for (lane, byte) in element.iter_mut().enumerate() {
                    *byte = IoDevice::read(&mut *serial, port + lane as u16);
                }
            }
        }
    } else if matches!(port, 0x1f0 | 0x170) {
        for byte in &mut data {
            bus.read(port, std::slice::from_mut(byte))?;
        }
    } else {
        for element in data.chunks_exact_mut(width) {
            bus.read(port, element)?;
        }
    }
    Ok(data)
}

#[cfg(test)]
#[path = "port_io_tests.rs"]
mod tests;
