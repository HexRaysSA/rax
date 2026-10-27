//! Lossless, bounded e1000 private state without replaying DMA or output.
use super::*;
use std::io;
#[path = "../checkpoint_wire.rs"]
mod wire;
use wire::{Reader, Writer, invalid};
const TAG: &[u8; 8] = b"RAXE1K01";
const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_FRAMES: usize = 65536;
const FIXED_BYTES: usize = 751;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct E1000Checkpoint {
    pub state: Vec<u8>,
}
fn put_frame(w: &mut Writer, bytes: &[u8]) {
    w.word(bytes.len() as u32);
    for byte in bytes {
        w.byte(*byte);
    }
}
fn get_frame(r: &mut Reader<'_>, remaining: &mut usize) -> io::Result<Vec<u8>> {
    let length = r.word()? as usize;
    if length > MAX_FRAME || length > *remaining {
        return Err(invalid("invalid e1000 checkpoint frame size"));
    }
    *remaining -= length;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| invalid("e1000 checkpoint allocation failed"))?;
    for _ in 0..length {
        bytes.push(r.byte()?);
    }
    Ok(bytes)
}
impl E1000 {
    /// Capture all represented state, including unsent partial/complete frames.
    /// Oversized state returns an error; no frames are silently discarded.
    pub fn checkpoint(&self) -> io::Result<E1000Checkpoint> {
        if self.tx_queue.len() > MAX_FRAMES
            || self.tx_partial.len() > MAX_FRAME
            || self
                .tx_queue
                .iter()
                .any(|f| f.is_empty() || f.len() > MAX_FRAME)
        {
            return Err(invalid("e1000 checkpoint frame limits exceeded"));
        }
        let length = self
            .tx_queue
            .iter()
            .try_fold(FIXED_BYTES + self.tx_partial.len(), |n, f| {
                n.checked_add(4 + f.len())
            })
            .filter(|n| *n <= MAX_BYTES)
            .ok_or_else(|| invalid("e1000 checkpoint byte limit exceeded"))?;
        let mut w = Writer::new(TAG);
        w.0.try_reserve_exact(length - 8)
            .map_err(|_| invalid("e1000 checkpoint allocation failed"))?;
        w.word(self.ctrl);
        w.word(self.status);
        for value in self.eeprom {
            w.short(value);
        }
        w.word(self.eecd);
        w.word(self.eerd);
        w.short(self.ee_shift);
        w.byte(self.ee_count);
        w.boolean(self.ee_reading);
        w.short(self.ee_dataout);
        w.byte(self.ee_dataout_count);
        w.boolean(self.ee_prev_sk);
        w.boolean(self.ee_do);
        for value in self.mac {
            w.byte(value);
        }
        for value in [
            self.icr, self.ims, self.rctl, self.rdbal, self.rdbah, self.rdlen, self.rdh, self.rdt,
            self.tctl, self.tdbal, self.tdbah, self.tdlen, self.tdh, self.tdt, self.ral0,
            self.rah0,
        ] {
            w.word(value);
        }
        for value in self.mta {
            w.word(value);
        }
        put_frame(&mut w, &self.tx_partial);
        w.word(self.tx_queue.len() as u32);
        for frame in &self.tx_queue {
            put_frame(&mut w, frame);
        }
        debug_assert_eq!(w.0.len(), length);
        Ok(E1000Checkpoint { state: w.0 })
    }
    /// Parse all fields and frame bounds before replacing the device. Restore
    /// neither walks descriptors nor delivers queued network frames.
    pub fn restore_checkpoint(&mut self, checkpoint: E1000Checkpoint) -> io::Result<()> {
        if !(FIXED_BYTES..=MAX_BYTES).contains(&checkpoint.state.len()) {
            return Err(invalid("invalid e1000 checkpoint length"));
        }
        let mut r = Reader::new(&checkpoint.state, TAG)?;
        let ctrl = r.word()?;
        let status = r.word()?;
        let mut eeprom = [0; EEPROM_WORDS];
        for value in &mut eeprom {
            *value = r.short()?;
        }
        let eecd = r.word()?;
        let eerd = r.word()?;
        let ee_shift = r.short()?;
        let ee_count = r.byte()?;
        let ee_reading = r.boolean()?;
        let ee_dataout = r.short()?;
        let ee_dataout_count = r.byte()?;
        let ee_prev_sk = r.boolean()?;
        let ee_do = r.boolean()?;
        if ee_count > 3 + MICROWIRE_ADDR_BITS
            || ee_dataout_count > 16
            || (ee_reading && ee_dataout_count >= 16)
        {
            return Err(invalid("invalid e1000 checkpoint EEPROM phase"));
        }
        let mut mac = [0; 6];
        for value in &mut mac {
            *value = r.byte()?;
        }
        let icr = r.word()?;
        let ims = r.word()?;
        let rctl = r.word()?;
        let rdbal = r.word()?;
        let rdbah = r.word()?;
        let rdlen = r.word()?;
        let rdh = r.word()?;
        let rdt = r.word()?;
        let tctl = r.word()?;
        let tdbal = r.word()?;
        let tdbah = r.word()?;
        let tdlen = r.word()?;
        let tdh = r.word()?;
        let tdt = r.word()?;
        let ral0 = r.word()?;
        let rah0 = r.word()?;
        let mut mta = [0; MTA_LEN];
        for value in &mut mta {
            *value = r.word()?;
        }
        let mut remaining = checkpoint.state.len() - FIXED_BYTES;
        let tx_partial = get_frame(&mut r, &mut remaining)?;
        let count = r.word()? as usize;
        if count > MAX_FRAMES || count > remaining / 4 {
            return Err(invalid("invalid e1000 checkpoint frame count"));
        }
        let mut tx_queue = Vec::new();
        tx_queue
            .try_reserve_exact(count)
            .map_err(|_| invalid("e1000 checkpoint allocation failed"))?;
        for _ in 0..count {
            remaining = remaining
                .checked_sub(4)
                .ok_or_else(|| invalid("truncated e1000 checkpoint frame length"))?;
            let frame = get_frame(&mut r, &mut remaining)?;
            if frame.is_empty() {
                return Err(invalid("empty e1000 checkpoint output frame"));
            }
            tx_queue.push(frame);
        }
        r.end()?;
        *self = Self {
            ctrl,
            status,
            eeprom,
            eecd,
            eerd,
            ee_shift,
            ee_count,
            ee_reading,
            ee_dataout,
            ee_dataout_count,
            ee_prev_sk,
            ee_do,
            mac,
            icr,
            ims,
            rctl,
            rdbal,
            rdbah,
            rdlen,
            rdh,
            rdt,
            tctl,
            tdbal,
            tdbah,
            tdlen,
            tdh,
            tdt,
            ral0,
            rah0,
            mta,
            tx_partial,
            tx_queue,
        };
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capture_rejects_excess_frames_without_dropping_state() {
        let mut d = E1000::default();
        d.tx_queue = vec![vec![0xa5]; MAX_FRAMES + 1];
        assert!(d.checkpoint().is_err());
        assert_eq!(d.tx_queue.len(), MAX_FRAMES + 1);
    }
    #[test]
    fn capture_rejects_excess_encoded_bytes_without_dropping_state() {
        let mut d = E1000::default();
        d.tx_queue = vec![vec![0xa5; MAX_FRAME]; 4096];
        assert!(d.checkpoint().is_err());
        assert_eq!(d.tx_queue.len(), 4096);
        assert_eq!(d.tx_queue[4095].len(), MAX_FRAME);
    }
}
