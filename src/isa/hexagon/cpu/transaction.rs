//! Packet-visible RAM, register, reservation and MMIO commit boundaries.

#[path = "checkpoint.rs"]
mod checkpoint;

use super::*;
use std::collections::VecDeque;
use std::sync::Mutex;
use vm_memory::GuestMemory;

struct MemoryWrite {
    address: u32,
    data: Vec<u8>,
}

struct FinishedPacket {
    exit: Option<VcpuExit>,
}

#[derive(Default)]
pub(super) struct PacketEffects {
    pub(super) initial: Option<Box<HexagonRegisters>>,
    initial_reservation: Option<u32>,
    writes: Mutex<Vec<MemoryWrite>>,
    pub(super) outputs: VecDeque<VcpuExit>,
    finished: Option<FinishedPacket>,
}

impl HexagonVcpu {
    /// Ordinary reads and the public register API observe packet-entry state.
    pub(super) fn old_regs(&self) -> &HexagonRegisters {
        self.effects.initial.as_deref().unwrap_or(&self.regs)
    }

    pub(super) fn write_packet_control(
        &mut self,
        index: usize,
        value: u32,
        predicates: &mut [Option<u8>; 4],
    ) {
        if index == 4 {
            for byte in 0..4 {
                super::super::semantics::merge_predicate(
                    predicates,
                    byte as u8,
                    (value >> (byte * 8)) as u8,
                );
            }
        } else {
            self.regs.set_control(index, value);
        }
    }

    fn require_ram_span(&self, address: u32, size: usize) -> Result<()> {
        let start = u64::from(address);
        let end = start + size as u64;
        for (base, length) in [
            (SERIAL_MMIO_BASE, SERIAL_MMIO_LEN),
            (DEBUG_MMIO_BASE, DEBUG_MMIO_LEN),
        ] {
            if start < base + length && end > base {
                return Err(Error::Emulator(
                    "Hexagon bulk/implicit MMIO access is not supported".into(),
                ));
            }
        }
        Ok(())
    }

    pub(super) fn read_packet_ram(&self, address: u32, data: &mut [u8]) -> Result<()> {
        self.require_ram_span(address, data.len())?;
        self.mem
            .read_slice(data, GuestAddress(u64::from(address)))
            .map_err(Error::from)
    }

    /// V68 section 5.5: a slot-0 load after a slot-1 store receives its
    /// overlapping bytes (:mem_noshuf). Scatter-add also sees prior increments.
    /// Ordinary load-before-store packets have no preceding writes to forward.
    pub(super) fn read_packet_data(&self, address: u32, data: &mut [u8]) -> Result<()> {
        self.read_packet_ram(address, data)?;
        for write in self
            .effects
            .writes
            .lock()
            .expect("Hexagon store log")
            .iter()
        {
            for (index, byte) in data.iter_mut().enumerate() {
                let location = u64::from(address) + index as u64;
                if let Some(offset) = location.checked_sub(u64::from(write.address))
                    && let Some(value) = write.data.get(offset as usize)
                {
                    *byte = *value;
                }
            }
        }
        Ok(())
    }

    pub(super) fn write_packet_memory(&self, address: u32, data: &[u8]) -> Result<()> {
        self.require_ram_span(address, data.len())?;
        // GuestMemoryMmap's region map is immutable for the lifetime of this
        // vCPU. Probe every slice before logging, including holes and spans.
        for slice in self
            .mem
            .get_slices(GuestAddress(address as u64), data.len())
        {
            slice.map_err(Error::from)?;
        }
        if self.effects.initial.is_some() {
            self.effects
                .writes
                .lock()
                .expect("Hexagon store log")
                .push(MemoryWrite {
                    address,
                    data: data.to_vec(),
                });
        } else {
            self.mem
                .write_slice(data, GuestAddress(address as u64))
                .map_err(Error::from)?;
        }
        Ok(())
    }

    pub(super) fn discard_packet(&mut self) {
        self.effects = Default::default();
        self.pending_packet = None;
        self.pending_mmio = None;
        self.packet_producers.clear();
        self.new_v = [None; 32];
        self.new_q = [None; 4];
        self.new_v_tmp = [None; 32];
        self.gather_tmp = None;
        self.last_v_produced = None;
    }

    fn abort_packet(&mut self) {
        if let Some(registers) = self.effects.initial.take() {
            self.regs = *registers;
            self.lock_addr = self.effects.initial_reservation;
        }
        self.discard_packet();
    }

    fn complete_packet_outputs(&mut self) -> Result<Option<VcpuExit>> {
        if let Some(output) = self.effects.outputs.pop_front() {
            return Ok(Some(output));
        }
        let finished = self.effects.finished.take().expect("finished packet");
        // All accesses have succeeded and all store ranges were validated
        // against the same immutable RAM map. No instruction can fault after
        // the first externally delivered MMIO write.
        let writes = std::mem::take(self.effects.writes.get_mut().expect("Hexagon store log"));
        for write in writes {
            if let Err(error) = self
                .mem
                .write_slice(&write.data, GuestAddress(write.address as u64))
            {
                self.abort_packet();
                return Err(Error::from(error));
            }
        }
        self.packets = self.packets.wrapping_add(1);
        self.discard_packet();
        Ok(finished.exit)
    }

    pub(super) fn step_packet_atomic(&mut self) -> Result<Option<VcpuExit>> {
        if self.effects.finished.is_some() {
            return self.complete_packet_outputs();
        }
        if let Some(pending) = &self.pending_mmio {
            // A short/missing completion cannot execute the remainder using
            // an invented value or lose the outstanding device request.
            return Ok(Some(VcpuExit::MmioRead {
                addr: pending.addr as u64,
                size: pending.size,
            }));
        }
        if self.effects.initial.is_none() {
            self.effects.initial = Some(Box::new(self.regs.clone()));
            self.effects.initial_reservation = self.lock_addr;
        }
        let exit = match self.step_packet() {
            Ok(exit) => exit,
            Err(error) => {
                self.abort_packet();
                return Err(error);
            }
        };
        if self.pending_packet.is_some() {
            return Ok(exit);
        }
        // Completed registers remain private behind old_regs() while queued
        // MMIO writes are acknowledged. Avoid copying the full vector file.
        self.effects.finished = Some(FinishedPacket { exit });
        self.complete_packet_outputs()
    }
}
