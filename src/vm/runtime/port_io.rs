//! Width-preserving fixed-port reads for scalar and batched PIO input.
use super::{SERIAL_BASE, publish_native_serial_irq};
use crate::backend::Vm;
use crate::config::BackendKind;
use crate::cpu::VcpuExit;
use crate::devices::bus::{IoBus, IoDevice};
use crate::devices::i8042::{DATA_PORT, I8042, STATUS_PORT};
use crate::devices::pic::DualPic;
use crate::devices::rtc::{RTC_ADDRESS, RTC_DATA};
use crate::devices::serial::Serial16550;
use crate::error::{Error, Result};
use crate::machine::pc::PcDevices;
use std::sync::{Arc, Mutex};

pub(super) fn touches_rtc(exit: &VcpuExit) -> bool {
    let (port, width) = match exit {
        VcpuExit::IoIn { port, size } | VcpuExit::IoInString { port, size, .. } => {
            (*port, usize::from(*size))
        }
        VcpuExit::IoOut { port, data } => (*port, data.len()),
        _ => return false,
    };
    port <= RTC_DATA && width > usize::from(RTC_ADDRESS.saturating_sub(port))
}

pub(super) struct KeyboardIrqs<'a> {
    pub(super) pc: &'a PcDevices,
    pub(super) pic: &'a Mutex<DualPic>,
    pub(super) vm: &'a dyn Vm,
}

impl KeyboardIrqs<'_> {
    fn with_controller<T>(
        &self,
        operation: impl FnOnce(&mut I8042, &mut dyn FnMut(u8, bool) -> Result<()>) -> Result<T>,
    ) -> Result<T> {
        let native = self.vm.uses_native_x86_irqchip();
        // Capture visits the PC I/O APIC, then the 8042, then the legacy PIC
        // and backend owner. Hold the same order. All software locks precede
        // guest-visible controller mutation.
        let mut ioapic = if native {
            None
        } else {
            Some(
                self.pc
                    .ioapic
                    .lock()
                    .map_err(|_| Error::Emulator("i8042 I/O APIC route lock poisoned".into()))?,
            )
        };
        let mut controller = self
            .pc
            .i8042
            .lock()
            .map_err(|_| Error::Emulator("i8042 controller lock poisoned".into()))?;
        let mut pic = if native {
            None
        } else {
            Some(
                self.pic
                    .lock()
                    .map_err(|_| Error::Emulator("i8042 PIC route lock poisoned".into()))?,
            )
        };
        operation(&mut controller, &mut |irq, asserted| {
            if let (Some(ioapic), Some(pic)) = (&mut ioapic, &mut pic) {
                ioapic.set_irq(irq, asserted);
                pic.set_irq(irq, asserted);
                Ok(())
            } else {
                // A failed native publication can follow a device mutation
                // or a completed edge on the other side of the route.
                self.vm
                    .set_irq_line(u32::from(irq), asserted)
                    .inspect_err(|_| self.vm.poison_checkpoint_restore())
            }
        })
    }

    fn read_data(&self) -> Result<u8> {
        self.with_controller(|controller, set_irq| {
            // Reading the latch deasserts its line before promoting a queued
            // byte. Publish both transitions even for another byte on this
            // same line and when several reads share one native PIO exit.
            if let Some(irq) = controller.output_irq() {
                set_irq(irq, false)?;
            }
            let value = controller.read(DATA_PORT);
            if let Some(irq) = controller.output_irq() {
                set_irq(irq, true)?;
            }
            Ok(value)
        })
    }

    fn write(&self, port: u16, value: u8) -> Result<()> {
        self.with_controller(|controller, set_irq| {
            let previous = controller.output_irq();
            controller.write(port, value);
            let current = controller.output_irq();
            if previous != current {
                if let Some(irq) = previous {
                    set_irq(irq, false)?;
                }
                if let Some(irq) = current {
                    set_irq(irq, true)?;
                }
            }
            Ok(())
        })
    }
}

/// Each element is one scalar port transaction. Generic byte lanes advance
/// within that element; the next element starts at the original port again.
/// IDE data-register bytes all use the same FIFO port. O(count * size) work
/// and storage, with allocation completed before any device read side effects.
pub(super) fn read(
    bus: &mut IoBus,
    serial: &Arc<Mutex<Serial16550>>,
    backend: BackendKind,
    keyboard: Option<&KeyboardIrqs<'_>>,
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
    } else if managed_pit_port(backend, port) {
        // KVM PIT and speaker ports generate one byte per scalar transaction.
        // The remaining lanes read zero and do not address the next port.
        for element in data.chunks_exact_mut(width) {
            bus.read(port, &mut element[..1])?;
        }
    } else if matches!(port, 0x1f0 | 0x170) {
        for byte in &mut data {
            bus.read(port, std::slice::from_mut(byte))?;
        }
    } else if let Some(keyboard) =
        keyboard.filter(|_| (port..=port.saturating_add(u16::from(size - 1))).contains(&DATA_PORT))
    {
        for element in data.chunks_exact_mut(width) {
            for (lane, byte) in element.iter_mut().enumerate() {
                let address = port.saturating_add(lane as u16);
                if address == DATA_PORT {
                    *byte = keyboard.read_data()?;
                } else {
                    bus.read(address, std::slice::from_mut(byte))?;
                }
            }
        }
    } else {
        for element in data.chunks_exact_mut(width) {
            bus.read(port, element)?;
        }
    }
    Ok(data)
}

fn managed_pit_port(backend: BackendKind, port: u16) -> bool {
    backend == BackendKind::Kvm && matches!(port, 0x40..=0x43 | 0x61)
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
    backend: BackendKind,
    serial_irq: Option<u32>,
    keyboard: Option<&KeyboardIrqs<'_>>,
    port: u16,
    bytes: &[u8],
) -> Result<bool> {
    if port == 0x604 && bytes.len() >= 2 && u16::from_le_bytes([bytes[0], bytes[1]]) == 0x2000 {
        return Ok(true);
    }
    if (SERIAL_BASE..SERIAL_BASE + 8).contains(&port) {
        // Capture acquires the legacy PIC before the UART. Admit both owners
        // before any output reaches the UART so a failed lock is retryable.
        let route = serial_irq
            .map(|irq| {
                pic.lock().map(|pic| (irq, pic)).map_err(|_| {
                    Error::Emulator("serial interrupt controller lock poisoned".into())
                })
            })
            .transpose()?;
        let pending = {
            let mut serial = serial
                .lock()
                .map_err(|_| Error::Emulator("serial output lock poisoned".into()))?;
            for (lane, byte) in bytes.iter().enumerate() {
                IoDevice::write(&mut *serial, port + lane as u16, *byte);
            }
            serial.has_pending_interrupt()
        };
        if let Some((irq, mut pic)) = route {
            pic.set_irq(irq as u8, pending);
            drop(pic);
            if vm.uses_native_x86_irqchip() {
                publish_native_serial_irq(vm, irq, pending)?;
            }
        }
    } else if port == 0xe9 {
        for byte in bytes {
            eprint!("{}", *byte as char);
        }
    } else if managed_pit_port(backend, port) {
        let low_byte = bytes
            .first()
            .ok_or_else(|| Error::InvalidConfig("empty native PIT output".into()))?;
        bus.write(port, std::slice::from_ref(low_byte))?;
    } else if matches!(port, 0x1f0 | 0x170) {
        for byte in bytes {
            bus.write(port, std::slice::from_ref(byte))?;
        }
    } else if let Some(keyboard) = keyboard.filter(|_| {
        let end = port.saturating_add(bytes.len().saturating_sub(1) as u16);
        [DATA_PORT, STATUS_PORT]
            .iter()
            .any(|lane| (port..=end).contains(lane))
    }) {
        for (lane, byte) in bytes.iter().copied().enumerate() {
            let address = port.saturating_add(lane as u16);
            if matches!(address, DATA_PORT | STATUS_PORT) {
                keyboard.write(address, byte)?;
            } else {
                bus.write(address, std::slice::from_ref(&byte))?;
            }
        }
    } else {
        bus.write(port, bytes)?;
    }
    Ok(false)
}
