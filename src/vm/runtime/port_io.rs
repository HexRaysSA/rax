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
        let mut serial = serial
            .lock()
            .map_err(|_| Error::Emulator("serial input lock poisoned".into()))?;
        for element in data.chunks_exact_mut(width) {
            for (lane, byte) in element.iter_mut().enumerate() {
                *byte = IoDevice::read(&mut *serial, port + lane as u16);
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

/// Return true only for the actual ACPI S5 output. Both normal dispatch and
/// stopped native completion use these same device operations and byte lanes.
#[allow(clippy::too_many_arguments)]
pub(super) fn write(
    bus: &mut IoBus,
    serial: &Arc<Mutex<Serial16550>>,
    pic: &Arc<Mutex<crate::devices::pic::DualPic>>,
    vm: &dyn crate::backend::Vm,
    backend: crate::config::BackendKind,
    serial_irq: Option<u32>,
    port: u16,
    bytes: &[u8],
) -> Result<bool> {
    if port == 0x604 && bytes.len() >= 2 && u16::from_le_bytes([bytes[0], bytes[1]]) == 0x2000 {
        return Ok(true);
    }
    if (SERIAL_BASE..SERIAL_BASE + 8).contains(&port) {
        let pending = {
            let mut serial = serial
                .lock()
                .map_err(|_| Error::Emulator("serial output lock poisoned".into()))?;
            for (lane, byte) in bytes.iter().enumerate() {
                IoDevice::write(&mut *serial, port + lane as u16, *byte);
            }
            serial.has_pending_interrupt()
        };
        if let Some(irq) = serial_irq {
            pic.lock()
                .map_err(|_| Error::Emulator("serial interrupt controller lock poisoned".into()))?
                .set_irq(irq as u8, pending);
            if backend == crate::config::BackendKind::Kvm {
                vm.set_irq_line(irq, pending)?;
            }
        }
    } else if port == 0xe9 {
        for byte in bytes {
            eprint!("{}", *byte as char);
        }
    } else if matches!(port, 0x1f0 | 0x170) {
        for byte in bytes {
            bus.write(port, std::slice::from_ref(byte))?;
        }
    } else {
        bus.write(port, bytes)?;
    }
    Ok(false)
}
