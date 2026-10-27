//! Typed optional PCI ownership and atomic device-set state replacement.
use super::{Ac97NabmWindow, Ac97NamWindow, GuestDmaMem, PCI_MMIO_AP_BASE};
use crate::config::StorageConfig;
use crate::devices::bus::{SharedIoDevice, SharedMmioDevice};
use crate::devices::{ac97, ahci, e1000, nvme, pci, uhci};
use crate::error::{Error, Result};
use std::sync::{Arc, Mutex, MutexGuard};
use vm_memory::GuestMemoryMmap;
/// All represented optional endpoints. Guest RAM is captured separately.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PciEndpointCheckpoint {
    pub e1000: e1000::E1000Checkpoint,
    pub uhci: uhci::UhciCheckpoint,
    pub nvme: nvme::NvmeCheckpoint,
    pub ahci: ahci::AhciCheckpoint,
    pub ac97: ac97::Ac97Checkpoint,
}
/// The bridge is present on x86 even when optional endpoints are disabled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PciDeviceCheckpoint {
    pub bridge: pci::PciCheckpoint,
    pub endpoints: Option<PciEndpointCheckpoint>,
}
struct Endpoints {
    e1000: Arc<Mutex<e1000::E1000>>,
    uhci: Arc<Mutex<uhci::Uhci>>,
    nvme: Arc<Mutex<nvme::NvmeController<GuestDmaMem>>>,
    ahci: Arc<Mutex<ahci::AhciController<GuestDmaMem>>>,
    ac97: Arc<Mutex<ac97::Ac97>>,
}
/// Retains typed handles to exactly the models registered behind the bridge.
/// Capture/restore hold the bridge lock before taking endpoint locks, matching
/// MMIO/PIO dispatch. Callers must separately quiesce CPUs/RAM writers and must
/// not retain a bridge guard while calling these methods.
pub struct PciDevices {
    bridge: Arc<Mutex<pci::PciStub>>,
    memory: Arc<GuestMemoryMmap>,
    topology: pci::PciCheckpoint,
    endpoints: Option<Endpoints>,
}
impl std::fmt::Debug for PciDevices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PciDevices")
            .field("optional_endpoints", &self.endpoints.is_some())
            .finish_non_exhaustive()
    }
}
fn state_error(error: std::io::Error) -> Error {
    Error::Emulator(format!("PCI checkpoint: {error}"))
}
fn locked<T>(value: &Mutex<T>) -> Result<MutexGuard<'_, T>> {
    value
        .lock()
        .map_err(|_| Error::Emulator("PCI state lock poisoned".to_string()))
}
impl PciDevices {
    /// Build the same firmware-assigned bridge/endpoints as the x86 runtime.
    pub fn new(
        memory: Arc<GuestMemoryMmap>,
        storage: &StorageConfig,
        enabled: bool,
    ) -> Result<Self> {
        let bridge = Arc::new(Mutex::new(pci::PciStub::new()));
        if enabled {
            Self::attach(&bridge, memory, storage)
        } else if storage.has_images() {
            Err(Error::InvalidConfig(
                "PCI images require enabled optional endpoints".to_string(),
            ))
        } else {
            Self::bridge_only(bridge, memory)
        }
    }
    /// Access the actual runtime bridge for config/PIO/MMIO dispatch.
    pub fn bridge(&self) -> Arc<Mutex<pci::PciStub>> {
        self.bridge.clone()
    }
    pub(super) fn bridge_only(
        bridge: Arc<Mutex<pci::PciStub>>,
        memory: Arc<GuestMemoryMmap>,
    ) -> Result<Self> {
        let topology = locked(&bridge)?.checkpoint().map_err(state_error)?;
        Ok(Self {
            bridge,
            memory,
            topology,
            endpoints: None,
        })
    }
    /// Capture a consistent bridge/endpoint boundary without running DMA. This
    /// does not serialize or stop independent guest-memory writers.
    pub fn checkpoint(&self) -> Result<PciDeviceCheckpoint> {
        let bridge = locked(&self.bridge)?;
        bridge
            .validate_checkpoint(&self.topology)
            .map_err(state_error)?;
        let state = bridge.checkpoint().map_err(state_error)?;
        let endpoints = match &self.endpoints {
            None => None,
            Some(e) => Some(PciEndpointCheckpoint {
                e1000: locked(&e.e1000)?.checkpoint().map_err(state_error)?,
                uhci: locked(&e.uhci)?.checkpoint().map_err(state_error)?,
                nvme: locked(&e.nvme)?.checkpoint().map_err(state_error)?,
                ahci: locked(&e.ahci)?.checkpoint().map_err(state_error)?,
                ac97: locked(&e.ac97)?.checkpoint().map_err(state_error)?,
            }),
        };
        Ok(PciDeviceCheckpoint {
            bridge: state,
            endpoints,
        })
    }
    /// Validate every endpoint into detached candidates before changing live
    /// state. Bridge restore is atomic; all endpoint assignments after it are
    /// infallible. Restore performs no DMA or external-file write/reopen.
    pub fn restore_checkpoint(&self, checkpoint: PciDeviceCheckpoint) -> Result<()> {
        self.restore_checkpoint_with(checkpoint, || Ok(()))
    }
    /// Admit all candidates and obtain every live PCI lock before calling the
    /// represented CPU/RAM/device commit. No PCI mutation occurs if it fails.
    pub(super) fn restore_checkpoint_with<T>(
        &self,
        checkpoint: PciDeviceCheckpoint,
        commit: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        match (&self.endpoints, checkpoint.endpoints) {
            (None, None) => {
                let mut bridge = locked(&self.bridge)?;
                bridge
                    .validate_checkpoint(&self.topology)
                    .map_err(state_error)?;
                bridge.restore_checkpoint_with(checkpoint.bridge, commit, state_error)
            }
            (Some(e), Some(state)) => {
                let mut net = e1000::E1000::default();
                net.restore_checkpoint(state.e1000).map_err(state_error)?;
                let mut usb = uhci::Uhci::new(0);
                usb.restore_checkpoint(state.uhci).map_err(state_error)?;
                let mut n =
                    nvme::NvmeController::new(0, GuestDmaMem(self.memory.clone()), Vec::new());
                n.restore_checkpoint(state.nvme).map_err(state_error)?;
                let mut a =
                    ahci::AhciController::new(0, GuestDmaMem(self.memory.clone()), Vec::new());
                a.restore_checkpoint(state.ahci).map_err(state_error)?;
                let mut audio = ac97::Ac97::new();
                audio.restore_checkpoint(state.ac97).map_err(state_error)?;
                if usb.base() != 0 || n.mmio_base() != 0 || a.mmio_base() != 0 {
                    return Err(Error::InvalidConfig(
                        "PCI checkpoint endpoint origin must be BAR-relative zero".to_string(),
                    ));
                }
                let mut bridge = locked(&self.bridge)?;
                bridge
                    .validate_checkpoint(&self.topology)
                    .map_err(state_error)?;
                let mut net_live = locked(&e.e1000)?;
                let mut usb_live = locked(&e.uhci)?;
                let mut n_live = locked(&e.nvme)?;
                let mut a_live = locked(&e.ahci)?;
                let mut audio_live = locked(&e.ac97)?;
                let result =
                    bridge.restore_checkpoint_with(checkpoint.bridge, commit, state_error)?;
                *net_live = net;
                *usb_live = usb;
                *n_live = n;
                *a_live = a;
                *audio_live = audio;
                Ok(result)
            }
            _ => Err(Error::InvalidConfig(
                "PCI checkpoint optional-endpoint topology mismatch".to_string(),
            )),
        }
    }
    pub(super) fn attach(
        pci: &Arc<std::sync::Mutex<pci::PciStub>>,
        mem: Arc<vm_memory::GuestMemoryMmap>,
        storage: &crate::config::StorageConfig,
    ) -> Result<Self> {
        use crate::devices::virtio::block_image::BlockImage;
        let n = match &storage.nvme {
            Some(image) => image.open()?,
            None => BlockImage::from_bytes(Vec::new()),
        };
        let a = match &storage.ahci {
            Some(image) => image.open()?,
            None => BlockImage::from_bytes(Vec::new()),
        };
        Self::attach_images(pci, mem, n, a)
    }
    /// Register the same fixed endpoints with empty detached images. A private
    /// resume constructor imports the verified checkpoint before exposing the VM.
    pub(super) fn attach_detached(
        pci: &Arc<Mutex<pci::PciStub>>,
        mem: Arc<GuestMemoryMmap>,
    ) -> Result<Self> {
        use crate::devices::virtio::block_image::BlockImage;
        Self::attach_images(
            pci,
            mem,
            BlockImage::from_bytes(Vec::new()),
            BlockImage::from_bytes(Vec::new()),
        )
    }
    fn attach_images(
        pci: &Arc<Mutex<pci::PciStub>>,
        mem: Arc<GuestMemoryMmap>,
        nvme_image: crate::devices::virtio::block_image::BlockImage,
        ahci_image: crate::devices::virtio::block_image::BlockImage,
    ) -> Result<Self> {
        use crate::devices::pci::{Bar, ConfigSpace};
        let mut bridge = pci
            .lock()
            .map_err(|_| Error::Emulator("pci bridge lock poisoned".to_string()))?;

        // Intel 82540EM (e1000) NIC at 00:01.0 — BAR0 is a 128 KiB MMIO register
        // block, pre-assigned at the base of the MMIO aperture.
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let mut e1000_cfg = ConfigSpace::device(0x8086, 0x100E, 0x02_00_00, 0x00);
        e1000_cfg.set_bar(0, Bar::mem32(0x2_0000));
        e1000_cfg.set_u32(0x10, PCI_MMIO_AP_BASE as u32);
        e1000_cfg.set_u16(0x04, 0x0006); // memory-space + bus-master enable
        e1000_cfg.set_u8(0x3d, 0x01); // interrupt pin INTA#
        let e1000 = Arc::new(Mutex::new(crate::devices::e1000::E1000::new(mac)));
        bridge.attach_mmio(
            0,
            1,
            0,
            e1000_cfg,
            0,
            Box::new(SharedMmioDevice::new(e1000.clone())),
        );

        // Intel PIIX-style UHCI USB controller at 00:02.0 — BAR4 is a 32-byte I/O
        // window pre-assigned at port 0xC000, reached via the IoBus PCI fallback.
        let mut uhci_cfg = ConfigSpace::device(0x8086, 0x7020, 0x0C_03_00, 0x00);
        uhci_cfg.set_bar(4, Bar::io(0x20));
        uhci_cfg.set_u32(0x10 + 4 * 4, 0x0000_C001); // I/O base 0xC000 (bit0 = I/O)
        uhci_cfg.set_u16(0x04, 0x0001); // I/O-space enable
        let uhci = Arc::new(Mutex::new(crate::devices::uhci::Uhci::new(0)));
        bridge.attach_pio(
            0,
            2,
            0,
            uhci_cfg,
            4,
            Box::new(SharedIoDevice::new(uhci.clone())),
        );

        // NVMe controller at 00:03.0 — BAR0 is an 8 KiB MMIO register block. The
        // controller DMAs its admin queues from guest RAM via the Mem adapter. With
        // no disk attached it enumerates with zero namespaces.
        let nvme = Arc::new(Mutex::new(
            crate::devices::nvme::NvmeController::with_image(
                0,
                GuestDmaMem(mem.clone()),
                nvme_image,
            ),
        ));
        let mut nvme_cfg = ConfigSpace::device(0x8086, 0x5845, 0x01_08_02, 0x00);
        nvme_cfg.set_bar(0, Bar::mem32(0x2000));
        nvme_cfg.set_u32(0x10, (PCI_MMIO_AP_BASE + 0x10_0000) as u32);
        nvme_cfg.set_u16(0x04, 0x0006); // memory-space + bus-master enable
        bridge.attach_mmio(
            0,
            3,
            0,
            nvme_cfg,
            0,
            Box::new(SharedMmioDevice::new(nvme.clone())),
        );

        // AHCI SATA controller at 00:04.0 — ABAR (BAR5) is an 8 KiB MMIO block. No
        // SATA drive attached, so it enumerates with no ports populated.
        let ahci = Arc::new(Mutex::new(
            crate::devices::ahci::AhciController::with_image(
                0,
                GuestDmaMem(mem.clone()),
                ahci_image,
            ),
        ));
        let mut ahci_cfg = ConfigSpace::device(0x8086, 0x2922, 0x01_06_01, 0x00);
        ahci_cfg.set_bar(5, Bar::mem32(0x2000));
        ahci_cfg.set_u32(0x10 + 5 * 4, (PCI_MMIO_AP_BASE + 0x20_0000) as u32);
        ahci_cfg.set_u16(0x04, 0x0006);
        bridge.attach_mmio(
            0,
            4,
            0,
            ahci_cfg,
            5,
            Box::new(SharedMmioDevice::new(ahci.clone())),
        );

        // Intel ICH AC'97 audio at 00:05.0 — two I/O BARs: BAR0 = NAM (256-byte
        // codec mixer), BAR1 = NABM (64-byte bus-master). One shared device, two
        // window endpoints.
        let ac97 = Arc::new(std::sync::Mutex::new(crate::devices::ac97::Ac97::new()));
        let mut ac97_cfg = ConfigSpace::device(0x8086, 0x2415, 0x04_01_00, 0x00);
        ac97_cfg.set_bar(0, Bar::io(0x100));
        ac97_cfg.set_bar(1, Bar::io(0x40));
        ac97_cfg.set_u32(0x10, 0x0000_D001); // NAM  @ I/O 0xD000
        ac97_cfg.set_u32(0x14, 0x0000_D101); // NABM @ I/O 0xD100
        ac97_cfg.set_u16(0x04, 0x0001); // I/O-space enable
        bridge.attach_pio(
            0,
            5,
            0,
            ac97_cfg.clone(),
            0,
            Box::new(Ac97NamWindow(ac97.clone())),
        );
        bridge.attach_pio(0, 5, 0, ac97_cfg, 1, Box::new(Ac97NabmWindow(ac97.clone())));

        let topology = bridge.checkpoint().map_err(state_error)?;
        drop(bridge);
        Ok(Self {
            bridge: pci.clone(),
            memory: mem,
            topology,
            endpoints: Some(Endpoints {
                e1000,
                uhci,
                nvme,
                ahci,
                ac97,
            }),
        })
    }
}

#[cfg(test)]
#[path = "pci_state_checkpoint_tests.rs"]
mod checkpoint_commit_tests;
