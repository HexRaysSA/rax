//! Complete port/engine/fatal-task state plus detached logical media.
use super::super::virtio::block_image::ImageCheckpoint;
use super::*;
use std::io;
#[path = "../checkpoint_wire.rs"]
mod wire;
use wire::{Reader, Writer, invalid};
const TAG: &[u8; 8] = b"RAXAHC01";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AhciCheckpoint {
    pub state: Vec<u8>,
    pub media: ImageCheckpoint,
}
impl<M: Mem> AhciController<M> {
    pub fn checkpoint(&self) -> io::Result<AhciCheckpoint> {
        let media = self.disk.checkpoint()?;
        let mut w = Writer::new(TAG);
        w.long(self.base);
        w.long(media.bytes.len() as u64);
        w.boolean(media.read_only);
        w.word(self.ghc);
        w.word(self.is);
        w.word(self.num_slots);
        w.boolean(self.interrupt_pending);
        w.long(self.port.clb);
        w.long(self.port.fb);
        for v in [
            self.port.is,
            self.port.ie,
            self.port.cmd,
            self.port.tfd,
            self.port.sig,
            self.port.ssts,
            self.port.sctl,
            self.port.serr,
            self.port.sact,
            self.port.ci,
        ] {
            w.word(v);
        }
        w.boolean(self.port.present);
        w.boolean(self.port.fatal);
        w.byte(self.port.current_slot);
        w.byte(self.port.next_slot);
        w.byte(self.port.task_fis.command);
        w.byte(self.port.task_fis.device);
        w.long(self.port.task_fis.lba);
        w.word(self.port.task_fis.count);
        Ok(AhciCheckpoint { state: w.0, media })
    }
    /// Restore the exact stopped/running/fatal state without executing pending CI.
    /// No DMA or host-file mutation occurs; RAM and VM quiescence are external.
    pub fn restore_checkpoint(&mut self, checkpoint: AhciCheckpoint) -> io::Result<()> {
        let mut r = Reader::new(&checkpoint.state, TAG)?;
        let base = r.long()?;
        let length = r.long()?;
        let readonly = r.boolean()?;
        if length != checkpoint.media.bytes.len() as u64 || readonly != checkpoint.media.read_only {
            return Err(invalid("AHCI checkpoint media metadata mismatch"));
        }
        let ghc = r.word()?;
        let is = r.word()?;
        let slots = r.word()?;
        let pending = r.boolean()?;
        let clb = r.long()?;
        let fb = r.long()?;
        let port = Port {
            clb,
            fb,
            is: r.word()?,
            ie: r.word()?,
            cmd: r.word()?,
            tfd: r.word()?,
            sig: r.word()?,
            ssts: r.word()?,
            sctl: r.word()?,
            serr: r.word()?,
            sact: r.word()?,
            ci: r.word()?,
            present: r.boolean()?,
            fatal: r.boolean()?,
            current_slot: r.byte()?,
            next_slot: r.byte()?,
            task_fis: FisH2D {
                command: r.byte()?,
                device: r.byte()?,
                lba: r.long()?,
                count: r.word()?,
            },
        };
        r.end()?;
        if slots != 32
            || ghc & !GHC_IE != GHC_AE
            || is & !1 != 0
            || port.current_slot >= 32
            || port.next_slot >= 32
            || port.task_fis.lba >= 1u64 << 48
            || port.task_fis.count > 65535
            || port.present == checkpoint.media.bytes.is_empty()
        {
            return Err(invalid("invalid AHCI checkpoint profile or engine state"));
        }
        if clb & 0x3ff != 0 || fb & 0xff != 0 || port.cmd & (PXCMD_CR | PXCMD_FR | (0x1f << 8)) != 0
        {
            return Err(invalid("invalid AHCI checkpoint register state"));
        }
        if port.is & port.ie != 0 && is == 0 {
            return Err(invalid("missing AHCI checkpoint aggregate interrupt"));
        }
        if pending != (ghc & GHC_IE != 0 && is != 0) {
            return Err(invalid("inconsistent AHCI checkpoint interrupt level"));
        }
        let media = checkpoint.media.into_detached()?;
        self.base = base;
        self.ghc = ghc;
        self.is = is;
        self.num_slots = slots;
        self.interrupt_pending = pending;
        self.port = port;
        self.disk = media;
        Ok(())
    }
}
