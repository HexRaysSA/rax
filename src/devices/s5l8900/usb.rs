// =============================================================================
// USB OTG (Synopsys DWC) + USB PHY — minimal stub
// =============================================================================

pub(super) const USB_NUM_ENDPOINTS: usize = 8;
pub(super) const USB_NUM_FIFOS: usize = 16;

pub(super) const USB_GOTGINT: u32 = 0x004;
pub(super) const USB_GAHBCFG: u32 = 0x008;
pub(super) const USB_GUSBCFG: u32 = 0x00c;
pub(super) const USB_GRSTCTL: u32 = 0x010;
pub(super) const USB_GINTSTS: u32 = 0x014;
pub(super) const USB_GINTMSK: u32 = 0x018;
pub(super) const USB_GRXSTSR: u32 = 0x01c;
pub(super) const USB_GRXSTSP: u32 = 0x020;
pub(super) const USB_GRXFSIZ: u32 = 0x024;
pub(super) const USB_GNPTXFSIZ: u32 = 0x028;
pub(super) const USB_GNPTXFSTS: u32 = 0x02c;
pub(super) const USB_GHWCFG1: u32 = 0x044;
pub(super) const USB_GHWCFG2: u32 = 0x048;
pub(super) const USB_GHWCFG3: u32 = 0x04c;
pub(super) const USB_GHWCFG4: u32 = 0x050;
pub(super) const USB_DIEPTXF1: u32 = 0x104;
pub(super) const USB_DCFG: u32 = 0x800;
pub(super) const USB_DCTL: u32 = 0x804;
pub(super) const USB_DSTS: u32 = 0x808;
pub(super) const USB_DIEPMSK: u32 = 0x810;
pub(super) const USB_DOEPMSK: u32 = 0x814;
pub(super) const USB_DAINTSTS: u32 = 0x818;
pub(super) const USB_DAINTMSK: u32 = 0x81c;
pub(super) const USB_INREGS: u32 = 0x900;
pub(super) const USB_OUTREGS: u32 = 0xb00;
pub(super) const USB_EPREGS_SIZE: u32 = 0x200;
pub(super) const USB_PCGCCTL: u32 = 0xe00;
pub(super) const USB_FIFO_START: u32 = 0x1000;
pub(super) const USB_FIFO_SIZE: u32 = 0x100 * (USB_NUM_FIFOS as u32 + 1);
pub(super) const USB_FIFO_END: u32 = USB_FIFO_START + USB_FIFO_SIZE;

pub(super) const USB_GRSTCTL_AHBIDLE: u32 = 1 << 31;
pub(super) const USB_GRSTCTL_CORESOFTRESET: u32 = 1;
pub(super) const USB_GINTMSK_GINNAKEFF: u32 = 1 << 6;
pub(super) const USB_GINTMSK_GOUTNAKEFF: u32 = 1 << 7;
pub(super) const USB_GINTMSK_RESET: u32 = 1 << 12;
pub(super) const USB_DCTL_SGNPINNAK: u32 = 1 << 7;
pub(super) const USB_DCTL_SGOUTNAK: u32 = 1 << 9;
pub(super) const USB_EPCON_ENABLE: u32 = 1 << 31;
pub(super) const USB_EPCON_DISABLE: u32 = 1 << 30;
pub(super) const USB_EPCON_SETNAK: u32 = 1 << 27;
pub(super) const USB_EPCON_NAKSTS: u32 = 1 << 17;
pub(super) const USB_EPINT_INEP_NAK_EFF: u32 = 0x40;
pub(super) const USB_EPINT_EP_DISBLD: u32 = 0x2;

#[derive(Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
pub(super) struct S5lUsbEp {
    pub(super) control: u32,
    pub(super) interrupt_status: u32,
    pub(super) tx_size: u32,
    pub(super) dma_address: u32,
    pub(super) dma_buffer: u32,
}

/// Minimal Synopsys DWC USB OTG (0x38400000) + USB PHY (0x3C400000). iBoot
/// initialises the USB controller during early boot (for DFU/recovery) and
/// polls the core soft-reset to complete; without it the boot task blocks
/// forever. The kernel also probes AppleSynopsysOTG2, so mirror the QEMU
/// reference's reset values for the hardware-configuration and FIFO registers.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct S5lUsb {
    #[serde(
        serialize_with = "super::context::serialize_map",
        deserialize_with = "super::context::map"
    )]
    pub(super) otg: std::collections::HashMap<u32, u32>,
    #[serde(deserialize_with = "super::context::bytes")]
    pub(super) fifos: Vec<u8>,
    pub(super) in_eps: [S5lUsbEp; USB_NUM_ENDPOINTS],
    pub(super) out_eps: [S5lUsbEp; USB_NUM_ENDPOINTS],
    #[serde(
        serialize_with = "super::context::serialize_map",
        deserialize_with = "super::context::map"
    )]
    pub(super) phy: std::collections::HashMap<u32, u32>,
}

impl S5lUsb {
    pub fn new() -> Self {
        let mut usb = S5lUsb {
            otg: std::collections::HashMap::with_capacity(64),
            fifos: vec![0; USB_FIFO_SIZE as usize],
            in_eps: [S5lUsbEp::default(); USB_NUM_ENDPOINTS],
            out_eps: [S5lUsbEp::default(); USB_NUM_ENDPOINTS],
            phy: std::collections::HashMap::new(),
        };
        usb.reset_otg();
        usb
    }

    fn reset_otg(&mut self) {
        self.otg.clear();
        self.otg.insert(USB_PCGCCTL, 3);
        self.otg.insert(USB_GAHBCFG, 0);
        self.otg.insert(USB_GUSBCFG, 0);
        self.otg.insert(USB_GRSTCTL, 0);
        self.otg.insert(USB_GINTSTS, 0);
        self.otg.insert(USB_GINTMSK, 0);
        self.otg.insert(USB_GRXFSIZ, 0x100);
        self.otg.insert(USB_GNPTXFSIZ, (0x100 << 16) | 0x100);
        self.otg.insert(USB_GHWCFG1, 0);
        self.otg.insert(USB_GHWCFG2, 0x7a8f_60d0);
        self.otg.insert(USB_GHWCFG3, 0x0820_00e8);
        self.otg.insert(USB_GHWCFG4, 0x01f0_8024);
        self.otg.insert(USB_DCFG, 0);
        self.otg.insert(USB_DCTL, 0);
        self.otg.insert(USB_DSTS, 0);
        self.otg.insert(USB_DIEPMSK, 0);
        self.otg.insert(USB_DOEPMSK, 0);
        self.otg.insert(USB_DAINTSTS, 0);
        self.otg.insert(USB_DAINTMSK, 0);

        let mut counter = 0x200;
        for fifo in 0..USB_NUM_FIFOS {
            self.otg
                .insert(USB_DIEPTXF1 + fifo as u32 * 4, (counter << 16) | 0x100);
            counter += 0x100;
        }

        self.in_eps = [S5lUsbEp::default(); USB_NUM_ENDPOINTS];
        self.out_eps = [S5lUsbEp::default(); USB_NUM_ENDPOINTS];
        self.fifos.fill(0);
    }

    pub fn otg_read(&self, off: u32) -> u32 {
        match off {
            USB_GRXSTSR | USB_GRXSTSP => 0,
            USB_GNPTXFSTS => 0xffff_ffff,
            off if (USB_INREGS..USB_INREGS + USB_EPREGS_SIZE).contains(&off) => {
                Self::ep_read(&self.in_eps, off - USB_INREGS)
            }
            off if (USB_OUTREGS..USB_OUTREGS + USB_EPREGS_SIZE).contains(&off) => {
                Self::ep_read(&self.out_eps, off - USB_OUTREGS)
            }
            off if (USB_FIFO_START..USB_FIFO_END).contains(&off) => {
                let idx = (off - USB_FIFO_START) as usize;
                self.fifos
                    .get(idx..idx + 4)
                    .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                    .unwrap_or(0)
            }
            _ => self.otg.get(&off).copied().unwrap_or(0),
        }
    }

    pub fn otg_write(&mut self, off: u32, val: u32) {
        match off {
            USB_GOTGINT | USB_GINTSTS | USB_DAINTSTS => {
                let cur = self.otg.get(&off).copied().unwrap_or(0);
                self.otg.insert(off, cur & !val);
            }
            USB_GRSTCTL => {
                if val & USB_GRSTCTL_CORESOFTRESET != 0 {
                    self.otg.insert(USB_GRSTCTL, USB_GRSTCTL_AHBIDLE);
                    let cur = self.otg.get(&USB_GINTSTS).copied().unwrap_or(0);
                    self.otg.insert(USB_GINTSTS, cur | USB_GINTMSK_RESET);
                } else if val == 0 {
                    self.otg.insert(USB_GRSTCTL, 0);
                } else {
                    self.otg.insert(USB_GRSTCTL, USB_GRSTCTL_AHBIDLE);
                }
            }
            USB_DCTL => {
                let cur = self.otg.get(&USB_DCTL).copied().unwrap_or(0);
                let mut next = val;
                let mut gintsts = self.otg.get(&USB_GINTSTS).copied().unwrap_or(0);
                if val & USB_DCTL_SGNPINNAK != 0 && cur & USB_DCTL_SGNPINNAK == 0 {
                    gintsts |= USB_GINTMSK_GINNAKEFF;
                    next &= !USB_DCTL_SGNPINNAK;
                }
                if val & USB_DCTL_SGOUTNAK != 0 && cur & USB_DCTL_SGOUTNAK == 0 {
                    gintsts |= USB_GINTMSK_GOUTNAKEFF;
                    next &= !USB_DCTL_SGOUTNAK;
                }
                self.otg.insert(USB_DCTL, next);
                self.otg.insert(USB_GINTSTS, gintsts);
            }
            off if (USB_INREGS..USB_INREGS + USB_EPREGS_SIZE).contains(&off) => {
                Self::ep_write(&mut self.in_eps, off - USB_INREGS, val);
                self.update_daintsts();
            }
            off if (USB_OUTREGS..USB_OUTREGS + USB_EPREGS_SIZE).contains(&off) => {
                Self::ep_write(&mut self.out_eps, off - USB_OUTREGS, val);
                self.update_daintsts();
            }
            off if (USB_FIFO_START..USB_FIFO_END).contains(&off) => {
                let idx = (off - USB_FIFO_START) as usize;
                if let Some(bytes) = self.fifos.get_mut(idx..idx + 4) {
                    bytes.copy_from_slice(&val.to_le_bytes());
                }
            }
            _ => {
                self.otg.insert(off, val);
            }
        }
    }

    pub fn irq_pending(&self) -> bool {
        let gintsts = self.otg.get(&USB_GINTSTS).copied().unwrap_or(0);
        let gintmsk = self.otg.get(&USB_GINTMSK).copied().unwrap_or(0);
        let daintsts = self.otg.get(&USB_DAINTSTS).copied().unwrap_or(0);
        let daintmsk = self.otg.get(&USB_DAINTMSK).copied().unwrap_or(0);
        (gintsts & gintmsk) != 0 || (daintsts & daintmsk) != 0
    }

    fn ep_read(eps: &[S5lUsbEp; USB_NUM_ENDPOINTS], off: u32) -> u32 {
        let ep = (off / 0x20) as usize;
        let reg = off & 0x1f;
        let Some(ep) = eps.get(ep) else {
            return 0;
        };

        match reg {
            0x00 => ep.control,
            0x08 => ep.interrupt_status,
            0x10 => ep.tx_size,
            0x14 => ep.dma_address,
            0x1c => ep.dma_buffer,
            _ => 0,
        }
    }

    fn ep_write(eps: &mut [S5lUsbEp; USB_NUM_ENDPOINTS], off: u32, val: u32) {
        let ep = (off / 0x20) as usize;
        let reg = off & 0x1f;
        let Some(ep) = eps.get_mut(ep) else {
            return;
        };

        match reg {
            0x00 => {
                ep.control = val;
                if ep.control & USB_EPCON_SETNAK != 0 {
                    ep.control |= USB_EPCON_NAKSTS;
                    ep.control &= !USB_EPCON_SETNAK;
                    ep.interrupt_status |= USB_EPINT_INEP_NAK_EFF;
                }
                if ep.control & USB_EPCON_DISABLE != 0 {
                    ep.interrupt_status |= USB_EPINT_EP_DISBLD;
                    ep.control &= !(USB_EPCON_DISABLE | USB_EPCON_ENABLE);
                }
            }
            0x08 => ep.interrupt_status &= !val,
            0x10 => ep.tx_size = val,
            0x14 => ep.dma_address = val,
            0x1c => ep.dma_buffer = val,
            _ => {}
        }
    }

    fn update_daintsts(&mut self) {
        let mut daint = 0;
        for (idx, ep) in self.in_eps.iter().enumerate() {
            if ep.interrupt_status != 0 {
                daint |= 1 << idx;
            }
        }
        for (idx, ep) in self.out_eps.iter().enumerate() {
            if ep.interrupt_status != 0 {
                daint |= 1 << (16 + idx);
            }
        }
        self.otg.insert(USB_DAINTSTS, daint);
    }

    pub fn phy_read(&self, off: u32) -> u32 {
        self.phy.get(&off).copied().unwrap_or(0)
    }

    pub fn phy_write(&mut self, off: u32, val: u32) {
        self.phy.insert(off, val);
    }
}

impl Default for S5lUsb {
    fn default() -> Self {
        Self::new()
    }
}
