//! Service the originating CPU's real devices before checkpoint writer locks.
use super::*;
use crate::vm::vcpu::{CheckpointIoReply, CheckpointIoState};

impl Vmm {
    /// Complete actual native device requests before taking writer locks.
    /// A full producer also retains deferred and terminal results. Once KVM
    /// publishes power-off, settlement returns deferred for every remaining
    /// CPU without servicing its devices.
    pub(super) fn settle_checkpoint_io(&self, retains_native_io: bool) -> Result<()> {
        for (id, cpu) in self.vcpus.iter().enumerate() {
            if cpu.settle_checkpoint_io(&mut |event| self.checkpoint_io_service(id, event))?
                == CheckpointIoState::Deferred
                && !retains_native_io
            {
                return Err(Error::InvalidConfig(
                    "native deferred/terminal I/O requires its complete checkpoint producer".into(),
                ));
            }
        }
        Ok(())
    }

    pub(super) fn checkpoint_io_service(
        &self,
        cpu: usize,
        event: VcpuExit,
    ) -> Result<CheckpointIoReply> {
        let port = match &event {
            VcpuExit::IoIn { port, size } | VcpuExit::IoInString { port, size, .. } => {
                Some((*port, usize::from(*size)))
            }
            VcpuExit::IoOut { port, data } => Some((*port, data.len())),
            _ => None,
        };
        let serial_input = match &event {
            VcpuExit::IoIn { port, .. } | VcpuExit::IoInString { port, .. } => Some(*port),
            _ => None,
        };
        let rtc = port.is_some_and(|(port, width)| {
            use crate::devices::rtc::{RTC_ADDRESS, RTC_DATA};
            port <= RTC_DATA && width > usize::from(RTC_ADDRESS.saturating_sub(port))
        });
        if rtc {
            self.poll_pc_rtc()?;
        }
        let keyboard = self.pc_devices.as_ref().map(|pc| port_io::KeyboardIrqs {
            pc,
            pic: &self.pic,
            vm: &*self.vm,
        });
        let reply = match event {
            VcpuExit::IoIn { port, size } => self.io_bus.with_stopped(|bus| {
                port_io::read(
                    bus,
                    &self.serial,
                    self.backend_kind,
                    keyboard.as_ref(),
                    port,
                    size,
                    1,
                )
                .map(CheckpointIoReply::Input)
            }),
            VcpuExit::IoInString { port, size, count } => self.io_bus.with_stopped(|bus| {
                port_io::read(
                    bus,
                    &self.serial,
                    self.backend_kind,
                    keyboard.as_ref(),
                    port,
                    size,
                    count,
                )
                .map(CheckpointIoReply::Input)
            }),
            VcpuExit::IoOut { port, data } => {
                let power_off = self.io_bus.with_stopped(|bus| {
                    port_io::write(
                        bus,
                        &self.serial,
                        &self.pic,
                        &*self.vm,
                        self.backend_kind,
                        self.serial_irq,
                        keyboard.as_ref(),
                        port,
                        &data,
                    )
                })?;
                Ok(if power_off {
                    CheckpointIoReply::PowerOff
                } else {
                    CheckpointIoReply::Output
                })
            }
            VcpuExit::MmioRead { addr, size } => {
                if !(1..=8).contains(&size) {
                    return Err(Error::InvalidConfig(
                        "native checkpoint MMIO input width is invalid".into(),
                    ));
                }
                let mut bytes = vec![0; usize::from(size)];
                self.mmio_bus.with_stopped(|bus| {
                    mmio::read(bus, &self.local_apics, cpu, addr, &mut bytes)
                })?;
                Ok(CheckpointIoReply::Input(bytes))
            }
            VcpuExit::MmioWrite { addr, data } => {
                self.mmio_bus
                    .with_stopped(|bus| mmio::write(bus, &self.local_apics, cpu, addr, &data))?;
                Ok(CheckpointIoReply::Output)
            }
            event => Err(Error::InvalidConfig(format!(
                "unexpected native checkpoint device event: {event:?}"
            ))),
        }?;
        if rtc {
            self.sync_pc_rtc_irq(None)?;
        }
        if let Some(port) = serial_input {
            self.sync_pc_serial_pio_input(port)?;
        }
        Ok(reply)
    }
}

#[cfg(all(test, feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
#[path = "checkpoint_io_tests.rs"]
mod tests;
