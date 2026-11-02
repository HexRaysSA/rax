//! Private packet images, admitted before a detached CPU can execute.
use super::*;
use crate::vm::memory::checkpoint::{CheckpointBindings, CheckpointPublication, CpuPublication};
use crate::vm::snapshot::{BackendContext, EmulatorState, HEXAGON_CONTEXT};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};

const TAG: &[u8; 8] = b"RAXHX001";
const MAX_PAYLOAD: usize = 16 * 1024 * 1024 - 8;
const MAX_WRITES: usize = 4096;
const MAX_WRITE_BYTES: usize = 65536;
const MAX_OUTPUTS: usize = 16;
fn invalid(message: impl std::fmt::Display) -> Error {
    Error::InvalidConfig(format!("Hexagon checkpoint: {message}"))
}
fn bytes<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
    crate::devices::checkpoint_serde::vector::<u8, D, MAX_WRITE_BYTES>(d)
}
fn output_bytes<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
    crate::devices::checkpoint_serde::vector::<u8, D, 4>(d)
}
fn writes<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<WriteImage>, D::Error> {
    crate::devices::checkpoint_serde::vector::<WriteImage, D, MAX_WRITES>(d)
}
fn outputs<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<OutputImage>, D::Error> {
    crate::devices::checkpoint_serde::vector::<OutputImage, D, MAX_OUTPUTS>(d)
}
fn producers<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
    crate::devices::checkpoint_serde::vector::<u8, D, 8>(d)
}
#[derive(Serialize, Deserialize)]
struct WriteImage {
    address: u32,
    #[serde(deserialize_with = "bytes")]
    data: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
struct OutputImage {
    address: u32,
    #[serde(deserialize_with = "output_bytes")]
    data: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
enum Finished {
    Continue,
    Shutdown,
}
#[derive(Serialize, Deserialize)]
struct Gather {
    data: [u32; 32],
    valid: [u32; 4],
}
#[derive(Serialize, Deserialize)]
struct Image {
    id: u32,
    isa: HexagonIsa,
    endian: Endianness,
    registers: HexagonRegisters,
    halted: bool,
    mmio: Option<MmioPending>,
    packet: Option<PacketState>,
    initial: Option<Box<HexagonRegisters>>,
    initial_reservation: Option<u32>,
    #[serde(deserialize_with = "writes")]
    writes: Vec<WriteImage>,
    #[serde(deserialize_with = "outputs")]
    outputs: Vec<OutputImage>,
    finished: Option<Finished>,
    #[serde(deserialize_with = "producers")]
    producers: Vec<u8>,
    new_v: [Option<[u32; 32]>; 32],
    new_q: [Option<[u32; 4]>; 4],
    new_v_tmp: [Option<[u32; 32]>; 32],
    gather: Option<Gather>,
    last_v: Option<u8>,
    reservation: Option<u32>,
    packets: u64,
}
impl Image {
    fn capture(cpu: &HexagonVcpu) -> Result<Self> {
        let writes = cpu
            .effects
            .writes
            .lock()
            .map_err(|_| invalid("store log lock poisoned"))?;
        let total = writes
            .iter()
            .try_fold(0usize, |n, w| n.checked_add(w.data.len()))
            .ok_or_else(|| invalid("store log length overflow"))?;
        if writes.len() > MAX_WRITES
            || writes.iter().any(|w| w.data.len() > MAX_WRITE_BYTES)
            || total > MAX_PAYLOAD
            || cpu.effects.outputs.len() > MAX_OUTPUTS
            || cpu.packet_producers.len() > 8
        {
            return Err(invalid("packet collections exceed budget"));
        }
        let outputs = cpu
            .effects
            .outputs
            .iter()
            .map(|exit| match exit {
                VcpuExit::MmioWrite { addr, data }
                    if *addr <= u64::from(u32::MAX) && data.len() <= 4 =>
                {
                    Ok(OutputImage {
                        address: *addr as u32,
                        data: data.clone(),
                    })
                }
                _ => Err(invalid("unsupported queued packet exit")),
            })
            .collect::<Result<Vec<_>>>()?;
        let finished = cpu
            .effects
            .finished
            .as_ref()
            .map(|f| match &f.exit {
                None => Ok(Finished::Continue),
                Some(VcpuExit::Shutdown) => Ok(Finished::Shutdown),
                _ => Err(invalid("unsupported finished packet exit")),
            })
            .transpose()?;
        Ok(Self {
            id: cpu.id,
            isa: cpu._isa,
            endian: cpu.endian,
            registers: cpu.regs.clone(),
            halted: cpu.halted,
            mmio: cpu.pending_mmio.clone(),
            packet: cpu.pending_packet.clone(),
            initial: cpu.effects.initial.clone(),
            initial_reservation: cpu.effects.initial_reservation,
            writes: writes
                .iter()
                .map(|w| WriteImage {
                    address: w.address,
                    data: w.data.clone(),
                })
                .collect(),
            outputs,
            finished,
            producers: cpu.packet_producers.clone(),
            new_v: cpu.new_v,
            new_q: cpu.new_q,
            new_v_tmp: cpu.new_v_tmp,
            gather: cpu.gather_tmp.as_ref().map(|(data, valid)| {
                let mut mask = [0; 4];
                for (i, set) in valid.iter().enumerate() {
                    if *set {
                        mask[i / 32] |= 1 << (i % 32);
                    }
                }
                Gather {
                    data: bytes_to_vec(data),
                    valid: mask,
                }
            }),
            last_v: cpu.last_v_produced,
            reservation: cpu.lock_addr,
            packets: cpu.packets,
        })
    }
    fn validate(&self, target: &HexagonVcpu) -> Result<()> {
        if self.id != target.id || self.isa != target._isa || self.endian != target.endian {
            return Err(invalid("CPU identity or ISA/endian profile differs"));
        }
        if self.producers.len() > 8
            || self.producers.iter().any(|r| *r >= 32)
            || self.last_v.is_some_and(|r| r >= 32)
            || self.writes.len() > MAX_WRITES
            || self.outputs.len() > MAX_OUTPUTS
        {
            return Err(invalid("register indices or collection counts differ"));
        }
        for address in [self.reservation, self.initial_reservation]
            .into_iter()
            .flatten()
        {
            if address & 3 != 0 || !target.mem.check_range(GuestAddress(u64::from(address)), 4) {
                return Err(invalid("local reservation range differs"));
            }
        }
        let mut total = 0usize;
        for write in &self.writes {
            total = total
                .checked_add(write.data.len())
                .ok_or_else(|| invalid("store log length overflow"))?;
            if write.data.len() > MAX_WRITE_BYTES || total > MAX_PAYLOAD {
                return Err(invalid("store log exceeds budget"));
            }
            target
                .require_ram_span(write.address, write.data.len())
                .map_err(invalid)?;
            if !target
                .mem
                .check_range(GuestAddress(u64::from(write.address)), write.data.len())
            {
                return Err(invalid("deferred store range differs"));
            }
        }
        for output in &self.outputs {
            if !matches!(output.data.len(), 1 | 2 | 4)
                || !HexagonVcpu::is_mmio(output.address)
                || output.address as usize % output.data.len() != 0
            {
                return Err(invalid("queued MMIO output differs"));
            }
        }
        if self.initial.is_none() {
            if self.mmio.is_some()
                || self.packet.is_some()
                || self.finished.is_some()
                || self.initial_reservation.is_some()
                || !self.writes.is_empty()
                || !self.outputs.is_empty()
                || !self.producers.is_empty()
                || self.new_v.iter().any(Option::is_some)
                || self.new_q.iter().any(Option::is_some)
                || self.new_v_tmp.iter().any(Option::is_some)
                || self.gather.is_some()
                || self.last_v.is_some()
            {
                return Err(invalid("idle CPU retains an in-flight packet image"));
            }
            return Ok(());
        }
        if self.packet.is_some() == self.finished.is_some()
            || (self.mmio.is_some() && self.packet.is_none())
        {
            return Err(invalid("packet phase graph differs"));
        }
        if let Some(packet) = &self.packet {
            if self.halted
                || !self.outputs.is_empty()
                || !(1..=4).contains(&packet.inst_index)
                || packet.pc != packet.packet_pc.wrapping_add(4 * packet.inst_index as u32)
                || self.registers.pc() != packet.pc
                || self.initial.as_ref().unwrap().pc() != packet.packet_pc
                || !matches!(packet.first_parse, Some(0..=3))
                || (packet.inst_index == 1 && packet.second_parse.is_some())
                || (packet.inst_index > 1 && !matches!(packet.second_parse, Some(0..=3)))
            {
                return Err(invalid("pending packet cursor or phase differs"));
            }
            if let Some(word) = packet.pending_duplex {
                if (word >> 14) & 3 != 0 {
                    return Err(invalid("retained word is not duplex"));
                }
                let (_, sub) = decode_duplex(word, self.isa)
                    .ok_or_else(|| invalid("invalid retained duplex word"))?;
                if !packet.pending_end || !isa_supports_insn(self.isa, &sub.insn, sub.opcode) {
                    return Err(invalid("retained duplex profile differs"));
                }
            }
        }
        if let Some(mmio) = &self.mmio {
            if mmio.dst >= 32
                || !matches!(mmio.size, 1 | 2 | 4)
                || (mmio.signed && mmio.size == 4)
                || !HexagonVcpu::is_mmio(mmio.addr)
                || mmio.addr % u32::from(mmio.size) != 0
            {
                return Err(invalid("pending input descriptor differs"));
            }
        }
        Ok(())
    }
    fn install(self, cpu: &mut HexagonVcpu) {
        cpu.regs = self.registers;
        cpu.halted = self.halted;
        cpu.pending_mmio = self.mmio;
        cpu.pending_packet = self.packet;
        cpu.effects = PacketEffects {
            initial: self.initial,
            initial_reservation: self.initial_reservation,
            writes: Mutex::new(
                self.writes
                    .into_iter()
                    .map(|w| MemoryWrite {
                        address: w.address,
                        data: w.data,
                    })
                    .collect(),
            ),
            outputs: self
                .outputs
                .into_iter()
                .map(|o| VcpuExit::MmioWrite {
                    addr: u64::from(o.address),
                    data: o.data,
                })
                .collect(),
            finished: self.finished.map(|f| FinishedPacket {
                exit: match f {
                    Finished::Continue => None,
                    Finished::Shutdown => Some(VcpuExit::Shutdown),
                },
            }),
        };
        cpu.packet_producers = self.producers;
        cpu.new_v = self.new_v;
        cpu.new_q = self.new_q;
        cpu.new_v_tmp = self.new_v_tmp;
        cpu.gather_tmp = self.gather.map(|g| {
            (
                vec_to_bytes(&g.data),
                std::array::from_fn(|i| g.valid[i / 32] & (1 << (i % 32)) != 0),
            )
        });
        cpu.last_v_produced = self.last_v;
        cpu.lock_addr = self.reservation;
        cpu.packets = self.packets;
    }
}
impl HexagonVcpu {
    fn check_publication(&self) -> Result<()> {
        if self
            .checkpoint_publication
            .as_ref()
            .is_some_and(|p| !p.load(Ordering::Acquire))
        {
            return Err(invalid("detached CPU has not been published"));
        }
        Ok(())
    }
    pub(crate) fn finish_publication(&mut self) -> Result<()> {
        self.check_publication()?;
        self.checkpoint_publication = None;
        Ok(())
    }
    pub(crate) fn capture_private(&self, remap: bool) -> Result<BackendContext> {
        self.check_publication()?;
        let mut image = Image::capture(self)?;
        if remap {
            image.reservation = None;
            image.initial_reservation = None;
        }
        image.validate(self)?;
        let payload = crate::codec::serialize_limited(&image, MAX_PAYLOAD).map_err(invalid)?;
        let mut data = TAG.to_vec();
        data.extend_from_slice(&payload);
        Ok(BackendContext {
            kind: HEXAGON_CONTEXT,
            data,
        })
    }
    pub(crate) fn prepare_private(
        &self,
        state: &CpuState,
        emulator: &EmulatorState,
        raw: &BackendContext,
    ) -> Result<Self> {
        if raw.kind != HEXAGON_CONTEXT {
            return Err(invalid("producer differs"));
        }
        if crate::codec::serialize(emulator).map_err(invalid)?
            != crate::codec::serialize(&EmulatorState::default()).map_err(invalid)?
        {
            return Err(invalid("legacy emulator projection differs"));
        }
        let payload = raw
            .data
            .strip_prefix(TAG)
            .ok_or_else(|| invalid("tag differs"))?;
        if payload.len() > MAX_PAYLOAD {
            return Err(invalid("record exceeds budget"));
        }
        let image: Image =
            crate::codec::deserialize_limited::<_, MAX_PAYLOAD>(payload).map_err(invalid)?;
        image.validate(self)?;
        let mut candidate = Self::new(self.id, self.mem.clone(), self._isa, self.endian);
        image.install(&mut candidate);
        if crate::codec::serialize(&candidate.get_state()?).map_err(invalid)?
            != crate::codec::serialize(state).map_err(invalid)?
        {
            return Err(invalid("public registers disagree with private record"));
        }
        candidate.checkpoint_publication = Some(Arc::new(AtomicBool::new(false)));
        Ok(candidate)
    }
    pub(crate) fn publication<'scope, 'bindings>(
        &self,
        scope: &'scope CheckpointPublication<'bindings>,
    ) -> Result<CpuPublication<'scope, 'bindings>> {
        match &self.checkpoint_publication {
            Some(done) if !done.load(Ordering::Acquire) => {
                scope.prepare_detached(&self.mem, done.clone())
            }
            _ => Ok(scope.empty()),
        }
    }
    pub(crate) fn restore_private(
        &mut self,
        state: &CpuState,
        emulator: &EmulatorState,
        raw: &BackendContext,
    ) -> Result<()> {
        let candidate = self.prepare_private(state, emulator, raw)?;
        let bindings = CheckpointBindings::new(&self.mem, vec![]);
        let scope = bindings.enter()?;
        candidate.publication(&scope)?.commit();
        *self = candidate;
        Ok(())
    }
}

#[cfg(test)]
#[path = "checkpoint_tests.rs"]
mod tests;
