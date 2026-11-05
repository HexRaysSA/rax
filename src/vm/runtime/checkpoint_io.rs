//! Service the originating CPU's real devices before checkpoint writer locks.
use super::*;
use crate::vm::vcpu::{CheckpointIoReply, CheckpointIoState};

impl Vmm {
    /// Complete actual native device requests before taking writer locks.
    /// Deferred/terminal state needs its full producer; stop here so later
    /// CPUs cannot cause device effects after a power-off reply.
    pub(super) fn settle_checkpoint_io(&self) -> Result<()> {
        for (id, cpu) in self.vcpus.iter().enumerate() {
            if cpu.settle_checkpoint_io(&mut |event| self.checkpoint_io_service(id, event))?
                == CheckpointIoState::Deferred
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
        match event {
            VcpuExit::IoIn { port, size } => self.io_bus.with_stopped(|bus| {
                port_io::read(bus, &self.serial, port, size, 1).map(CheckpointIoReply::Input)
            }),
            VcpuExit::IoInString { port, size, count } => self.io_bus.with_stopped(|bus| {
                port_io::read(bus, &self.serial, port, size, count).map(CheckpointIoReply::Input)
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
        }
    }
}

#[cfg(all(test, feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
#[path = "checkpoint_io_tests.rs"]
mod tests;
