//! UHCI register and port state; guest RAM and frame scheduling are external.
use super::*;
use std::io;
#[path = "../checkpoint_wire.rs"]
mod wire;
use wire::{Reader, Writer, invalid};
const TAG: &[u8; 8] = b"RAXUHC01";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UhciCheckpoint {
    pub state: Vec<u8>,
}
impl Uhci {
    /// Capture without advancing a frame or reading guest memory.
    pub fn checkpoint(&self) -> io::Result<UhciCheckpoint> {
        let mut w = Writer::new(TAG);
        for value in [self.base, self.cmd, self.sts, self.intr, self.frnum] {
            w.short(value);
        }
        w.word(self.frbase);
        w.byte(self.sofmod);
        for p in &self.ports {
            for value in [
                p.connected,
                p.low_speed,
                p.connect_change,
                p.enabled,
                p.enable_change,
                p.reset,
                p.suspended,
                p.resume_detect,
            ] {
                w.boolean(value);
            }
        }
        Ok(UhciCheckpoint { state: w.0 })
    }
    /// Replace all registers/ports only after full validation; execute no frame.
    pub fn restore_checkpoint(&mut self, checkpoint: UhciCheckpoint) -> io::Result<()> {
        let mut r = Reader::new(&checkpoint.state, TAG)?;
        let base = r.short()?;
        let cmd = r.short()?;
        let sts = r.short()?;
        let intr = r.short()?;
        let frnum = r.short()?;
        let frbase = r.word()?;
        let sofmod = r.byte()?;
        let mut ports = [Port::default(); NUM_PORTS];
        for p in &mut ports {
            *p = Port {
                connected: r.boolean()?,
                low_speed: r.boolean()?,
                connect_change: r.boolean()?,
                enabled: r.boolean()?,
                enable_change: r.boolean()?,
                reset: r.boolean()?,
                suspended: r.boolean()?,
                resume_detect: r.boolean()?,
            };
        }
        r.end()?;
        if frnum > 0x7ff || frbase & 0xfff != 0 {
            return Err(invalid("invalid UHCI checkpoint frame registers"));
        }
        *self = Self {
            base,
            cmd,
            sts,
            intr,
            frnum,
            frbase,
            sofmod,
            ports,
        };
        Ok(())
    }
}
