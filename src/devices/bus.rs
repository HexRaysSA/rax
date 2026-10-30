use crate::error::{Error, Result};

mod fallback;
mod rmw;
pub use rmw::MmioRmwOp;

pub trait IoDevice: Send {
    fn read(&mut self, port: u16) -> u8;
    fn write(&mut self, port: u16, value: u8);
}

/// Adapter that registers a single shared device (held behind `Arc<Mutex<_>>`)
/// at one or more, possibly non-contiguous, I/O port ranges. Clone the `Arc`
/// and register one adapter per range; all of them dispatch to the same
/// underlying device state (e.g. the 8237 DMA controller is reachable at
/// 0x00-0x0F, 0x80-0x8F and 0xC0-0xDF but is one device).
pub struct SharedIoDevice<D: IoDevice> {
    inner: std::sync::Arc<std::sync::Mutex<D>>,
}

impl<D: IoDevice> SharedIoDevice<D> {
    pub fn new(inner: std::sync::Arc<std::sync::Mutex<D>>) -> Self {
        SharedIoDevice { inner }
    }
}

impl<D: IoDevice> IoDevice for SharedIoDevice<D> {
    fn read(&mut self, port: u16) -> u8 {
        self.inner.lock().map(|mut d| d.read(port)).unwrap_or(0xFF)
    }

    fn write(&mut self, port: u16, value: u8) {
        if let Ok(mut d) = self.inner.lock() {
            d.write(port, value);
        }
    }
}

pub trait MmioDevice: Send {
    fn read(&mut self, addr: u64, data: &mut [u8]);
    fn write(&mut self, addr: u64, data: &[u8]);

    /// Perform a single device transaction and return the pre-write operand.
    /// Shared adapters must hold their model lock across this complete call.
    fn read_modify_write(&mut self, addr: u64, size: u8, operation: MmioRmwOp) -> Result<Vec<u8>> {
        operation.validate(size)?;
        let mut old = vec![0; usize::from(size)];
        self.read(addr, &mut old);
        let mut new = old.clone();
        operation.apply(&mut new)?;
        self.write(addr, &new);
        Ok(old)
    }
}

/// Register a shared MMIO model while retaining typed state ownership.
pub struct SharedMmioDevice<D: MmioDevice> {
    inner: std::sync::Arc<std::sync::Mutex<D>>,
}
impl<D: MmioDevice> SharedMmioDevice<D> {
    pub fn new(inner: std::sync::Arc<std::sync::Mutex<D>>) -> Self {
        Self { inner }
    }
}
impl<D: MmioDevice> MmioDevice for SharedMmioDevice<D> {
    fn read(&mut self, address: u64, data: &mut [u8]) {
        match self.inner.lock() {
            Ok(mut device) => device.read(address, data),
            Err(_) => data.fill(0xff),
        }
    }
    fn write(&mut self, address: u64, data: &[u8]) {
        if let Ok(mut device) = self.inner.lock() {
            device.write(address, data);
        }
    }

    fn read_modify_write(
        &mut self,
        address: u64,
        size: u8,
        operation: MmioRmwOp,
    ) -> Result<Vec<u8>> {
        operation.validate(size)?;
        self.inner
            .lock()
            .map_err(|_| Error::Emulator("MMIO RMW device lock poisoned".into()))?
            .read_modify_write(address, size, operation)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct IoRange {
    pub base: u16,
    pub len: u16,
}

impl IoRange {
    pub fn contains(&self, port: u16) -> bool {
        port >= self.base && port < self.base.saturating_add(self.len)
    }

    pub fn overlaps(&self, other: &IoRange) -> bool {
        let end = self.base.saturating_add(self.len);
        let other_end = other.base.saturating_add(other.len);
        self.base < other_end && other.base < end
    }
}

pub struct IoBus {
    devices: Vec<(IoRange, Box<dyn IoDevice>)>,
    /// Optional PCI host bridge consulted for ports not claimed by a fixed
    /// device — this is how dynamically-assigned PCI I/O BARs are reached.
    pci: Option<std::sync::Arc<std::sync::Mutex<crate::devices::pci::PciStub>>>,
}

impl IoBus {
    pub fn new() -> Self {
        IoBus {
            devices: Vec::new(),
            pci: None,
        }
    }

    /// Attach the PCI host bridge as the fallback for unclaimed I/O ports.
    pub fn set_pci(
        &mut self,
        bridge: std::sync::Arc<std::sync::Mutex<crate::devices::pci::PciStub>>,
    ) {
        self.pci = Some(bridge);
    }

    pub fn register(&mut self, range: IoRange, dev: Box<dyn IoDevice>) -> Result<()> {
        for (existing_range, _) in &self.devices {
            if existing_range.overlaps(&range) {
                return Err(Error::DeviceOverlap {
                    base: range.base,
                    len: range.len,
                });
            }
        }
        self.devices.push((range, dev));
        Ok(())
    }

    pub fn read(&mut self, port: u16, data: &mut [u8]) -> Result<()> {
        for (index, byte) in data.iter_mut().enumerate() {
            let current_port = port.saturating_add(index as u16);
            if let Some(dev_index) = self
                .devices
                .iter()
                .position(|(range, _)| range.contains(current_port))
            {
                let device = &mut self.devices[dev_index].1;
                *byte = device.read(current_port);
            } else if let Some(ref pci) = self.pci {
                // Fall back to a PCI I/O BAR, else open bus (0xff).
                *byte = pci
                    .lock()
                    .ok()
                    .and_then(|mut b| b.io_read(current_port))
                    .unwrap_or(0xff);
            } else {
                // Return 0xff for unhandled ports (no device present)
                *byte = 0xff;
            }
        }
        Ok(())
    }

    pub fn write(&mut self, port: u16, data: &[u8]) -> Result<()> {
        for (index, byte) in data.iter().enumerate() {
            let current_port = port.saturating_add(index as u16);
            if let Some(dev_index) = self
                .devices
                .iter()
                .position(|(range, _)| range.contains(current_port))
            {
                let device = &mut self.devices[dev_index].1;
                device.write(current_port, *byte);
            } else if let Some(ref pci) = self.pci {
                // Fall back to a PCI I/O BAR if one decodes this port.
                if let Ok(mut b) = pci.lock() {
                    b.io_write(current_port, *byte);
                }
            }
            // Silently ignore writes to unhandled ports
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MmioRange {
    pub base: u64,
    pub len: u64,
}

impl MmioRange {
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base.saturating_add(self.len)
    }

    pub fn overlaps(&self, other: &MmioRange) -> bool {
        let end = self.base.saturating_add(self.len);
        let other_end = other.base.saturating_add(other.len);
        self.base < other_end && other.base < end
    }
}

pub struct MmioBus {
    devices: Vec<(MmioRange, Box<dyn MmioDevice>)>,
    fallback: fallback::Fallback,
}

impl MmioBus {
    pub fn new() -> Self {
        MmioBus {
            devices: Vec::new(),
            fallback: fallback::Fallback::default(),
        }
    }

    /// Fixed device windows. Native backends must exclude their complete pages.
    pub fn ranges(&self) -> Vec<MmioRange> {
        self.devices.iter().map(|(range, _)| *range).collect()
    }

    /// Route unclaimed native MMIO exits through live PCI BAR decode.
    pub fn set_pci(
        &mut self,
        bridge: std::sync::Arc<std::sync::Mutex<crate::devices::pci::PciStub>>,
    ) {
        self.fallback.pci = Some(bridge);
    }

    /// Service ordinary RAM bytes trapped because a device shares their native
    /// page. Padding remains open bus. Only the native Intel backend needs this.
    pub(crate) fn set_ram_fallback(
        &mut self,
        memory: std::sync::Arc<vm_memory::GuestMemoryMmap>,
        reported: u64,
    ) {
        self.fallback.ram = Some((memory, reported));
    }

    pub fn register(&mut self, range: MmioRange, dev: Box<dyn MmioDevice>) -> Result<()> {
        for (existing_range, _) in &self.devices {
            if existing_range.overlaps(&range) {
                return Err(Error::MmioOverlap {
                    base: range.base,
                    len: range.len,
                });
            }
        }
        self.devices.push((range, dev));
        Ok(())
    }

    fn validate_extent(addr: u64, len: usize) -> Result<()> {
        if len != 0 && addr.checked_add((len - 1) as u64).is_none() {
            return Err(Error::InvalidConfig(
                "MMIO access extent wraps the address space".into(),
            ));
        }
        Ok(())
    }

    /// Keep one callback for each contiguous portion owned by one device.
    /// Splitting a register-sized transaction into byte writes changes device
    /// semantics; holes and mapping boundaries are the only bus split points.
    fn transaction_chunk(&self, addr: u64, remaining: usize) -> Result<(Option<usize>, usize)> {
        if let Some(index) = self
            .devices
            .iter()
            .position(|(range, _)| range.contains(addr))
        {
            let range = self.devices[index].0;
            let available = range.base.saturating_add(range.len) - addr;
            return Ok((Some(index), available.min(remaining as u64) as usize));
        }
        let next = self
            .devices
            .iter()
            .map(|(range, _)| range.base)
            .filter(|base| *base > addr)
            .min();
        let count = next.map_or(remaining, |base| {
            (base - addr).min(remaining as u64) as usize
        });
        Ok((None, self.fallback.chunk(addr, count)?))
    }

    pub fn read(&mut self, addr: u64, data: &mut [u8]) -> Result<()> {
        Self::validate_extent(addr, data.len())?;
        let mut offset = 0;
        while offset < data.len() {
            let current = addr + offset as u64;
            let (device, count) = self.transaction_chunk(current, data.len() - offset)?;
            let part = &mut data[offset..offset + count];
            match device {
                Some(index) => self.devices[index].1.read(current, part),
                None => self.fallback.read(current, part)?,
            }
            offset += count;
        }
        Ok(())
    }

    pub fn write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        Self::validate_extent(addr, data.len())?;
        let mut offset = 0;
        while offset < data.len() {
            let current = addr + offset as u64;
            let (device, count) = self.transaction_chunk(current, data.len() - offset)?;
            if let Some(index) = device {
                self.devices[index]
                    .1
                    .write(current, &data[offset..offset + count]);
            } else {
                self.fallback
                    .write(current, &data[offset..offset + count])?;
            }
            offset += count;
        }
        Ok(())
    }

    /// Apply an indivisible scalar operation to one complete device mapping.
    /// A cross-mapping operation is rejected before any device access, since
    /// independent device locks cannot establish one atomic transaction.
    pub fn read_modify_write(
        &mut self,
        addr: u64,
        size: u8,
        operation: MmioRmwOp,
    ) -> Result<Vec<u8>> {
        operation.validate(size)?;
        Self::validate_extent(addr, usize::from(size))?;
        let (device, count) = self.transaction_chunk(addr, usize::from(size))?;
        if count != usize::from(size) {
            return Err(Error::InvalidConfig(
                "MMIO RMW crosses device mappings".into(),
            ));
        }
        match device {
            Some(index) => self.devices[index]
                .1
                .read_modify_write(addr, size, operation),
            None => self.fallback.rmw(addr, size, operation),
        }
    }
}

#[cfg(test)]
mod mmio_tests {
    use super::*;

    struct DummyMmio {
        last: u8,
    }

    impl MmioDevice for DummyMmio {
        fn read(&mut self, _addr: u64, data: &mut [u8]) {
            if let Some(first) = data.first_mut() {
                *first = self.last;
            }
        }

        fn write(&mut self, _addr: u64, data: &[u8]) {
            if let Some(first) = data.first() {
                self.last = *first;
            }
        }
    }

    #[test]
    fn mmio_register_rejects_overlap() {
        let mut bus = MmioBus::new();
        bus.register(
            MmioRange {
                base: 0x1000,
                len: 0x10,
            },
            Box::new(DummyMmio { last: 0 }),
        )
        .unwrap();
        let err = bus
            .register(
                MmioRange {
                    base: 0x1008,
                    len: 0x10,
                },
                Box::new(DummyMmio { last: 0 }),
            )
            .unwrap_err();
        match err {
            Error::MmioOverlap { .. } => {}
            _ => panic!("unexpected error"),
        }
    }

    #[test]
    fn mmio_read_write_dispatches() {
        let mut bus = MmioBus::new();
        bus.register(
            MmioRange {
                base: 0x2000,
                len: 1,
            },
            Box::new(DummyMmio { last: 0 }),
        )
        .unwrap();
        bus.write(0x2000, &[0xaa]).unwrap();
        let mut data = [0u8; 1];
        bus.read(0x2000, &mut data).unwrap();
        assert_eq!(data[0], 0xaa);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyDevice {
        last: u8,
    }

    impl IoDevice for DummyDevice {
        fn read(&mut self, _port: u16) -> u8 {
            self.last
        }

        fn write(&mut self, _port: u16, value: u8) {
            self.last = value;
        }
    }

    #[test]
    fn register_rejects_overlap() {
        let mut bus = IoBus::new();
        bus.register(
            IoRange {
                base: 0x3f8,
                len: 8,
            },
            Box::new(DummyDevice { last: 0 }),
        )
        .unwrap();
        let err = bus
            .register(
                IoRange {
                    base: 0x3fc,
                    len: 8,
                },
                Box::new(DummyDevice { last: 0 }),
            )
            .unwrap_err();
        match err {
            Error::DeviceOverlap { .. } => {}
            _ => panic!("unexpected error"),
        }
    }

    #[test]
    fn read_write_dispatches() {
        let mut bus = IoBus::new();
        bus.register(
            IoRange { base: 0x60, len: 1 },
            Box::new(DummyDevice { last: 0 }),
        )
        .unwrap();

        bus.write(0x60, &[0x5a]).unwrap();
        let mut data = [0u8; 1];
        bus.read(0x60, &mut data).unwrap();
        assert_eq!(data[0], 0x5a);
    }
}

#[cfg(test)]
#[path = "bus/mmio_transactions.rs"]
mod mmio_transactions;

#[cfg(test)]
mod native_fallback_tests;
