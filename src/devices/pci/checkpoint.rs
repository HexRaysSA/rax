//! Host-bridge state only: endpoint handlers remain owned by the caller.
use super::*;
use std::io;
#[path = "../checkpoint_wire.rs"]
mod wire;
use wire::{Reader, Writer, invalid};
const TAG: &[u8; 8] = b"RAXPCI01";
const MAX_FUNCTIONS: usize = 65536;
const MAX_ENDPOINTS: usize = MAX_FUNCTIONS * NUM_BARS;
const FUNCTION_BYTES: usize = 3 + CONFIG_SPACE_SIZE + NUM_BARS * 8;
const ENDPOINT_BYTES: usize = 3 + 1 + 8 + 1 + 8;
/// Versioned PCI latch, raw configuration bytes, BAR profiles and routing state.
/// Handler-private state and synchronization belong to the caller. Restore
/// requires the same registered function/BAR/ordered-endpoint topology.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PciCheckpoint {
    pub state: Vec<u8>,
}
fn put_key(w: &mut Writer, key: FunctionKey) {
    w.byte(key.0);
    w.byte(key.1);
    w.byte(key.2);
}
fn get_key(r: &mut Reader<'_>) -> io::Result<FunctionKey> {
    Ok((r.byte()?, r.byte()?, r.byte()?))
}
struct Decoded {
    address: u32,
    functions: HashMap<FunctionKey, ConfigSpace>,
    bases: Vec<u64>,
}
impl PciStub {
    /// Capture without calling any endpoint handler. Functions are canonicalized
    /// by raw key; endpoint order is retained because overlap routing uses it.
    pub fn checkpoint(&self) -> io::Result<PciCheckpoint> {
        if self.functions.len() > MAX_FUNCTIONS || self.endpoints.len() > MAX_ENDPOINTS {
            return Err(invalid("PCI checkpoint topology exceeds limit"));
        }
        let mut keys = Vec::new();
        keys.try_reserve_exact(self.functions.len())
            .map_err(|_| invalid("PCI checkpoint allocation failed"))?;
        keys.extend(self.functions.keys().copied());
        keys.sort_unstable();
        let mut w = Writer::new(TAG);
        let bytes =
            20 + self.functions.len() * FUNCTION_BYTES + self.endpoints.len() * ENDPOINT_BYTES;
        w.0.try_reserve_exact(bytes - 8)
            .map_err(|_| invalid("PCI checkpoint allocation failed"))?;
        w.word(self.address);
        w.word(keys.len() as u32);
        w.word(self.endpoints.len() as u32);
        for key in keys {
            put_key(&mut w, key);
            let cs = &self.functions[&key];
            for byte in cs.bytes {
                w.byte(byte);
            }
            for bar in cs.bars {
                w.boolean(bar.is_some());
                let bar = bar.unwrap_or(Bar::mem32(0));
                w.word(bar.size);
                w.boolean(bar.io);
                w.boolean(bar.prefetchable);
                w.boolean(bar.bits64);
            }
        }
        for ep in &self.endpoints {
            if ep.bar_index >= NUM_BARS
                || ep.bar_size > u32::MAX as u64
                || ep.current_base > u32::MAX as u64
            {
                return Err(invalid("unsupported PCI checkpoint endpoint"));
            }
            put_key(&mut w, ep.key);
            w.byte(ep.bar_index as u8);
            w.long(ep.bar_size);
            w.boolean(ep.io);
            w.long(ep.current_base);
        }
        Ok(PciCheckpoint { state: w.0 })
    }
    /// Validate the entire record and registration topology before changing any
    /// field. No handler is called and no BAR write side effect is replayed.
    pub fn restore_checkpoint(&mut self, checkpoint: PciCheckpoint) -> io::Result<()> {
        let decoded = self.decode_checkpoint(&checkpoint)?;
        self.address = decoded.address;
        self.functions = decoded.functions;
        for (ep, base) in self.endpoints.iter_mut().zip(decoded.bases) {
            ep.current_base = base;
        }
        Ok(())
    }
    /// Check the complete record against current registration topology without
    /// changing registers, routes or calling any handler.
    pub fn validate_checkpoint(&self, checkpoint: &PciCheckpoint) -> io::Result<()> {
        self.decode_checkpoint(checkpoint).map(|_| ())
    }
    fn decode_checkpoint(&self, checkpoint: &PciCheckpoint) -> io::Result<Decoded> {
        let mut r = Reader::new(&checkpoint.state, TAG)?;
        let address = r.word()?;
        let count = r.word()? as usize;
        let endpoints = r.word()? as usize;
        if count > MAX_FUNCTIONS || endpoints > MAX_ENDPOINTS {
            return Err(invalid("PCI checkpoint topology exceeds limit"));
        }
        let expected = count
            .checked_mul(FUNCTION_BYTES)
            .and_then(|n| {
                endpoints
                    .checked_mul(ENDPOINT_BYTES)
                    .and_then(|e| n.checked_add(e))
            })
            .and_then(|n| n.checked_add(20))
            .ok_or_else(|| invalid("PCI checkpoint size overflow"))?;
        if checkpoint.state.len() != expected
            || count != self.functions.len()
            || endpoints != self.endpoints.len()
        {
            return Err(invalid("PCI checkpoint size or topology mismatch"));
        }
        let mut functions = HashMap::new();
        functions
            .try_reserve(count)
            .map_err(|_| invalid("PCI checkpoint allocation failed"))?;
        let mut previous = None;
        for _ in 0..count {
            let key = get_key(&mut r)?;
            if previous.is_some_and(|p| p >= key) {
                return Err(invalid("PCI checkpoint function order is not canonical"));
            }
            previous = Some(key);
            let existing = self
                .functions
                .get(&key)
                .ok_or_else(|| invalid("PCI checkpoint function mismatch"))?;
            let mut cs = ConfigSpace::new();
            for byte in &mut cs.bytes {
                *byte = r.byte()?;
            }
            for bar in &mut cs.bars {
                let present = r.boolean()?;
                let value = Bar {
                    size: r.word()?,
                    io: r.boolean()?,
                    prefetchable: r.boolean()?,
                    bits64: r.boolean()?,
                };
                if !present && value != Bar::mem32(0) {
                    return Err(invalid("PCI checkpoint absent BAR has metadata"));
                }
                *bar = present.then_some(value);
            }
            if cs.bars != existing.bars {
                return Err(invalid("PCI checkpoint BAR profile mismatch"));
            }
            functions.insert(key, cs);
        }
        let mut bases = Vec::new();
        bases
            .try_reserve_exact(endpoints)
            .map_err(|_| invalid("PCI checkpoint allocation failed"))?;
        for ep in &self.endpoints {
            let key = get_key(&mut r)?;
            let index = r.byte()? as usize;
            let size = r.long()?;
            let io = r.boolean()?;
            let base = r.long()?;
            if (key, index, size, io) != (ep.key, ep.bar_index, ep.bar_size, ep.io)
                || base > u32::MAX as u64
            {
                return Err(invalid("PCI checkpoint endpoint topology mismatch"));
            }
            bases.push(base);
        }
        r.end()?;
        Ok(Decoded {
            address,
            functions,
            bases,
        })
    }
}
