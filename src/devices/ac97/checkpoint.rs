//! AC'97 mixer, DMA channels and retained sink accounting.
use super::*;
use std::io;
#[path = "../checkpoint_wire.rs"]
mod wire;
use wire::{Reader, Writer, invalid};
const TAG: &[u8; 8] = b"RAXAC901";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ac97Checkpoint {
    pub state: Vec<u8>,
}
fn save(w: &mut Writer, c: &BmChannel) {
    w.word(c.bdbar);
    w.byte(c.civ);
    w.byte(c.lvi);
    w.short(c.sr);
    w.short(c.picb);
    w.byte(c.piv);
    w.byte(c.cr);
}
fn load(r: &mut Reader<'_>) -> io::Result<BmChannel> {
    let c = BmChannel {
        bdbar: r.word()?,
        civ: r.byte()?,
        lvi: r.byte()?,
        sr: r.short()?,
        picb: r.short()?,
        piv: r.byte()?,
        cr: r.byte()?,
    };
    if c.bdbar & 7 != 0 || c.civ >= BDL_ENTRIES || c.piv >= BDL_ENTRIES {
        return Err(invalid("invalid AC97 checkpoint DMA channel"));
    }
    Ok(c)
}
impl Ac97 {
    /// Capture without performing DMA or consuming an audio buffer.
    pub fn checkpoint(&self) -> io::Result<Ac97Checkpoint> {
        let mut w = Writer::new(TAG);
        for value in self.mixer {
            w.short(value);
        }
        for c in [&self.pcm_in, &self.pcm_out, &self.mic_in] {
            save(&mut w, c);
        }
        w.word(self.glob_cnt);
        w.word(self.glob_sta);
        w.long(self.sink_bytes);
        Ok(Ac97Checkpoint { state: w.0 })
    }
    /// Validate all fields before changing the live device; do not replay DMA.
    pub fn restore_checkpoint(&mut self, checkpoint: Ac97Checkpoint) -> io::Result<()> {
        let mut r = Reader::new(&checkpoint.state, TAG)?;
        let mut mixer = [0; 128];
        for value in &mut mixer {
            *value = r.short()?;
        }
        let pcm_in = load(&mut r)?;
        let pcm_out = load(&mut r)?;
        let mic_in = load(&mut r)?;
        let glob_cnt = r.word()?;
        let glob_sta = r.word()?;
        let sink_bytes = r.long()?;
        r.end()?;
        *self = Self {
            mixer,
            pcm_in,
            pcm_out,
            mic_in,
            glob_cnt,
            glob_sta,
            sink_bytes,
        };
        Ok(())
    }
}
