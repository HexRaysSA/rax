mod alignment;
mod execute;
mod transaction;

use std::sync::Arc;

use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use super::decode::{
    AddrMode, CmpKind, CombineOperand, DecodedInsn, ExtendKind, MemOpKind, MemOpSrc, MemSign,
    MemWidth, PredCond, ShiftKind, SpliceAmount, decode, decode_duplex, isa_supports_insn,
};
use super::opcode::Opcode;
use crate::config::{Endianness, HexagonIsa};
use crate::error::{Error, Result};
use crate::vm::vcpu::{CpuState, HexagonRegisters, VCpu, VcpuExit};

const SERIAL_MMIO_BASE: u64 = 0xf000_0000;
const SERIAL_MMIO_LEN: u64 = 8;
/// Debug-console MMIO port (single byte sink/source); see `crate::devices::map`.
const DEBUG_MMIO_BASE: u64 = crate::devices::map::HEXAGON_DEBUG_MMIO_BASE;
const DEBUG_MMIO_LEN: u64 = 8;

/// 32-bit register-amount shift (`asl`/`asr`/`lsr`(Rs,Rt)).
///
/// The shift amount is the low 7 bits of `rt` sign-extended to a signed value
/// in `[-64, 63]` (`fSXTN(7,32,RtV)`); a negative amount reverses the shift
/// direction (`fBIDIR_*` macros). The shift is evaluated in 64 bits then
/// truncated, so amounts up to 63 are well defined and saturate to all-zero or
/// all-sign as the spec requires.
fn hex_reg_shift32(val: u32, rt: u32, kind: ShiftKind) -> u32 {
    let raw = rt & 0x7f;
    let shamt = ((raw as i32) << 25) >> 25; // sign-extend bit 6
    let result: i64 = match kind {
        // asl: signed source, left-biased (negative amount -> arithmetic right).
        ShiftKind::Lsl => {
            let s = val as i32 as i64;
            if shamt < 0 {
                (s >> ((-shamt) - 1)) >> 1
            } else {
                s << shamt
            }
        }
        // asr: signed source, right-biased (negative amount -> left).
        ShiftKind::Asr => {
            let s = val as i32 as i64;
            if shamt < 0 {
                (s << ((-shamt) - 1)) << 1
            } else {
                s >> shamt
            }
        }
        // lsr: unsigned source, right-biased (negative amount -> logical left).
        ShiftKind::Lsr => {
            let u = val as u64;
            (if shamt < 0 {
                (u << ((-shamt) - 1)) << 1
            } else {
                u >> shamt
            }) as i64
        }
    };
    result as u32
}

/// Bit-reverse the low 16 bits of `addr`, keeping the upper 16 bits intact
/// (`fbrev`/`fEA_BREVR`). Used by bit-reverse post-increment addressing, where
/// the FFT-style address is `brev(Rx)`.
fn hex_brev(addr: u32) -> u32 {
    let low = (addr & 0xffff) as u16;
    let rev = low.reverse_bits() as u32;
    (addr & 0xffff_0000) | rev
}

/// Hexagon circular-buffer post-increment (`fcirc_add`). `reg` is the current
/// pointer, `incr` the signed byte increment, `m` the modifier register
/// (M0/M1: bits 0..16 are the buffer length, bits 24..27 the K field), and
/// `cs` the circular-start register (CS0/CS1). The pointer wraps within
/// `[start, start+length)`. With `K==0` (the common case) `start` is exactly
/// `cs`; otherwise the start is derived from the masked pointer (matching
/// hardware behavior, which is only well-defined for K==0 / length>=4).
fn hex_circ_add(reg: u32, incr: i32, m: u32, cs: u32) -> u32 {
    let length = m & 0x0001_ffff;
    let k_const = (m >> 24) & 0xf;
    let new_ptr = reg.wrapping_add(incr as u32);
    let (start_addr, end_addr) = if k_const == 0 && length >= 4 {
        (cs, cs.wrapping_add(length))
    } else {
        let mask = (1u32 << (k_const + 2)).wrapping_sub(1);
        let start = reg & !mask;
        (start, start | (length & mask))
    };
    if new_ptr >= end_addr {
        new_ptr.wrapping_sub(length)
    } else if new_ptr < start_addr {
        new_ptr.wrapping_add(length)
    } else {
        new_ptr
    }
}

/// Read the I field of a modifier register (`fREAD_IREG`): an 11-bit signed
/// value packed as `((M & 0xf0000000) >> 21) | ((M >> 17) & 0x7f)`.
fn hex_read_ireg(m: u32) -> i32 {
    let packed = ((m & 0xf000_0000) >> 21) | ((m >> 17) & 0x7f);
    // Sign-extend the 11-bit value.
    ((packed << 21) as i32) >> 21
}

/// An HVX vector's 32 little-endian words as a flat 128-byte array.
fn vec_to_bytes(v: &[u32; 32]) -> [u8; 128] {
    let mut b = [0u8; 128];
    for i in 0..32 {
        b[i * 4..i * 4 + 4].copy_from_slice(&v[i].to_le_bytes());
    }
    b
}

/// Inverse of [`vec_to_bytes`].
fn bytes_to_vec(b: &[u8; 128]) -> [u32; 32] {
    let mut v = [0u32; 32];
    for i in 0..32 {
        v[i] = u32::from_le_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]]);
    }
    v
}

/// Snapshot of which GPRs currently have a buffered (in-flight) write.
fn producer_mask(new_r: &[Option<u32>; 32]) -> [bool; 32] {
    std::array::from_fn(|i| new_r[i].is_some())
}

/// Record the GPR an instruction just produced (the lowest newly-written
/// register) into the packet's producer list, for new-value resolution.
fn record_producer(new_r: &[Option<u32>; 32], before: [bool; 32], producers: &mut Vec<u8>) {
    for i in 0..32 {
        if new_r[i].is_some() && !before[i] {
            producers.push(i as u8);
            return;
        }
    }
}

/// Resolve a new-value store: `Nt8 >> 1` is the back-distance (1 = most recent)
/// among the packet's GPR producers; the selected producer's register is the
/// store data source (read as a `.new`/in-flight value). Non-`StoreNew` insns
/// pass through unchanged.
fn resolve_new_value(insn: DecodedInsn, producers: &[u8]) -> DecodedInsn {
    match insn {
        DecodedInsn::StoreNew {
            nt,
            addr,
            width,
            pred,
        } => {
            let back = (nt >> 1) as usize;
            let src = if back >= 1 && back <= producers.len() {
                producers[producers.len() - back]
            } else {
                0
            };
            DecodedInsn::Store {
                src,
                addr,
                width,
                pred,
                src_new: true,
                high_half: false,
            }
        }
        // New-value compound compare-and-jump (`_jumpnv`): `src1` is the `Ns8`
        // producer index (`Ns8 >> 1` = back-distance among the packet's GPR
        // producers, identical to a new-value store). Rewrite `src1` to the
        // resolved producer register while retaining its .new read mode.
        DecodedInsn::CompoundCmpJump {
            kind,
            src1,
            src2,
            write_pred,
            sense,
            new_value: true,
            offset,
        } => {
            let back = (src1 >> 1) as usize;
            let resolved = if back >= 1 && back <= producers.len() {
                producers[producers.len() - back]
            } else {
                0
            };
            DecodedInsn::CompoundCmpJump {
                kind,
                src1: resolved,
                src2,
                write_pred,
                sense,
                new_value: true,
                offset,
            }
        }
        other => other,
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct MmioPending {
    addr: u32,
    dst: u8,
    size: u8,
    signed: bool,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct BranchTarget {
    target: u32,
    is_call: bool,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct PacketState {
    packet_pc: u32,
    pc: u32,
    immext: Option<u32>,
    new_r: [Option<u32>; 32],
    new_p: [Option<u8>; 4],
    branch: Option<BranchTarget>,
    inst_index: usize,
    first_parse: Option<u32>,
    second_parse: Option<u32>,
    pending_duplex: Option<u32>,
    pending_end: bool,
}

impl PacketState {
    fn new(pc: u32) -> Self {
        PacketState {
            packet_pc: pc,
            pc,
            immext: None,
            new_r: [None; 32],
            new_p: [None; 4],
            branch: None,
            inst_index: 0,
            first_parse: None,
            second_parse: None,
            pending_duplex: None,
            pending_end: false,
        }
    }
}

pub struct HexagonVcpu {
    id: u32,
    regs: HexagonRegisters,
    mem: Arc<GuestMemoryMmap>,
    halted: bool,
    pending_mmio: Option<MmioPending>,
    pending_packet: Option<PacketState>,
    effects: transaction::PacketEffects,
    packet_producers: Vec<u8>,
    _isa: HexagonIsa,
    endian: Endianness,
    /// In-flight HVX vector writes for the current packet (committed at packet
    /// end so vector reads observe old values, matching VLIW semantics).
    new_v: [Option<[u32; 32]>; 32],
    new_q: [Option<[u32; 4]>; 4],
    /// `.tmp` HVX vector loads: forwarded to same-packet consumers (read via
    /// `vread_new`) but NEVER committed to the architectural register file —
    /// `.tmp` is scratch. Cleared each packet alongside `new_v`.
    new_v_tmp: [Option<[u32; 32]>; 32],
    /// Per-packet HVX gather scratch (`vtmp`, qemu `tmp_VRegs[0]`): the result of
    /// the packet's `vgather`, consumed by the paired `vmem(Rs+#k)=vtmp.new`
    /// store. A packet has at most one gather. Cleared each packet.
    ///
    /// `(data, valid)`: byte `b` of `data` is meaningful only where `valid[b]`.
    /// On hardware the gather temp is initialised from the destination memory and
    /// only in-range / predicate-on lanes are overwritten; the paired store thus
    /// writes only the `valid` bytes, leaving the rest of the destination intact.
    gather_tmp: Option<([u8; 128], [bool; 128])>,
    /// The most recently produced architectural HVX vector register in the current
    /// packet (in execution order). Resolves a new-value vector store
    /// (`vmem(...) = V.new`) to its in-packet producer. `None` when no vector has
    /// been produced yet (then a `vmem=vtmp.new` store falls back to `gather_tmp`).
    last_v_produced: Option<u8>,
    /// LL/SC reservation: the (word/dword-aligned) address reserved by the most
    /// recent load-locked, or `None`. A store-conditional succeeds (and clears
    /// it) only when this matches the SC address; otherwise the SC fails. Models
    /// the qemu-hexagon behaviour where a bare store-conditional fails.
    lock_addr: Option<u32>,
    /// Packets committed, reported as the vCPU instruction count.
    packets: u64,
    checkpoint_publication: Option<Arc<std::sync::atomic::AtomicBool>>,
}

impl HexagonVcpu {
    pub fn new(id: u32, mem: Arc<GuestMemoryMmap>, isa: HexagonIsa, endian: Endianness) -> Self {
        HexagonVcpu {
            id,
            regs: HexagonRegisters::default(),
            mem,
            halted: false,
            pending_mmio: None,
            pending_packet: None,
            effects: Default::default(),
            packet_producers: Vec::new(),
            _isa: isa,
            endian,
            new_v: [None; 32],
            new_q: [None; 4],
            new_v_tmp: [None; 32],
            gather_tmp: None,
            last_v_produced: None,
            lock_addr: None,
            packets: 0,
            checkpoint_publication: None,
        }
    }

    fn read_u8(&self, addr: u32) -> Result<u8> {
        let mut buf = [0u8; 1];
        self.read_packet_data(addr, &mut buf)?;
        Ok(buf[0])
    }

    fn read_u16(&self, addr: u32) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.read_packet_data(addr, &mut buf)?;
        Ok(match self.endian {
            Endianness::Little => u16::from_le_bytes(buf),
            Endianness::Big => u16::from_be_bytes(buf),
        })
    }

    fn read_u32(&self, addr: u32) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.read_packet_data(addr, &mut buf)?;
        Ok(match self.endian {
            Endianness::Little => u32::from_le_bytes(buf),
            Endianness::Big => u32::from_be_bytes(buf),
        })
    }

    fn read_u64(&self, addr: u32) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.read_packet_data(addr, &mut buf)?;
        Ok(match self.endian {
            Endianness::Little => u64::from_le_bytes(buf),
            Endianness::Big => u64::from_be_bytes(buf),
        })
    }

    fn write_u8(&self, addr: u32, value: u8) -> Result<()> {
        self.write_packet_memory(addr, &[value])?;
        Ok(())
    }

    fn write_u16(&self, addr: u32, value: u16) -> Result<()> {
        let bytes = match self.endian {
            Endianness::Little => value.to_le_bytes(),
            Endianness::Big => value.to_be_bytes(),
        };
        self.write_packet_memory(addr, &bytes)?;
        Ok(())
    }

    fn write_u32(&self, addr: u32, value: u32) -> Result<()> {
        let bytes = match self.endian {
            Endianness::Little => value.to_le_bytes(),
            Endianness::Big => value.to_be_bytes(),
        };
        self.write_packet_memory(addr, &bytes)?;
        Ok(())
    }

    fn write_u64(&self, addr: u32, value: u64) -> Result<()> {
        let bytes = match self.endian {
            Endianness::Little => value.to_le_bytes(),
            Endianness::Big => value.to_be_bytes(),
        };
        self.write_packet_memory(addr, &bytes)?;
        Ok(())
    }

    /// Read a 128-byte HVX vector from memory as 32 little-endian words. HVX
    /// vmem is byte-transparent (the vector's byte order is memory order), so
    /// the words use the same LE packing as the `v[]` register storage.
    fn read_vec(&self, addr: u32) -> Result<[u32; 32]> {
        let mut buf = [0u8; 128];
        self.read_packet_data(addr, &mut buf)?;
        let mut v = [0u32; 32];
        for i in 0..32 {
            v[i] = u32::from_le_bytes([buf[i * 4], buf[i * 4 + 1], buf[i * 4 + 2], buf[i * 4 + 3]]);
        }
        Ok(v)
    }

    /// Write a 128-byte HVX vector to memory (32 little-endian words).
    fn write_vec(&self, addr: u32, vec: &[u32; 32]) -> Result<()> {
        let mut buf = [0u8; 128];
        for i in 0..32 {
            buf[i * 4..i * 4 + 4].copy_from_slice(&vec[i].to_le_bytes());
        }
        self.write_packet_memory(addr, &buf)?;
        Ok(())
    }

    /// Read element `idx` (0-based) of an HVX vector register `vreg` as an
    /// `esz`-byte little-endian value (`esz` = 2 or 4).
    fn velem(&self, vreg: u8, esz: u8, idx: usize) -> u32 {
        // `.w` (off_pair) scatter/gather reads offsets from a vector PAIR
        // (Vv, Vv+1); an odd pair base such as V31 implies the nonexistent V32.
        // Guard the index so a crafted packet can't panic the emulator.
        let Some(reg) = self.regs.v.get(vreg as usize) else {
            return 0;
        };

        let bytes = vec_to_bytes(reg);
        let off = idx * esz as usize;
        match esz {
            2 => u16::from_le_bytes([bytes[off], bytes[off + 1]]) as u32,
            _ => u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]),
        }
    }

    /// Vector-byte predicate bit `i` (0..128) of vector predicate register `q`.
    /// Predicated scatter/gather mask per byte: byte `b` of element `k` is gated
    /// on bit `k*esz + b` (qemu's byte-granular scatter/gather predicate).
    fn qbit(&self, q: u8, i: usize) -> bool {
        let qv = self.regs.q[q as usize];
        (qv[i / 32] >> (i % 32)) & 1 != 0
    }

    /// HVX V65 scatter. For each element the (data) effective address is
    /// `EA = Rt + offset[i]`; the element is committed only if `Rt <= EA <= Rt+Mu`
    /// (and, for the `q` forms, its predicate bit is set). `_add` forms align the
    /// offset (`offset &= ~(esz-1)`) and accumulate (`*EA += data`); plain forms
    /// store (`*EA = data`). Elements are processed in order (later wins).
    #[allow(clippy::too_many_arguments)]
    fn exec_scatter(
        &mut self,
        base: u8,
        modsel: u8,
        offsets: u8,
        data: u8,
        esz: u8,
        off_pair: bool,
        add: bool,
        pred: Option<u8>,
    ) -> Result<()> {
        let mask = (esz as u32) - 1;
        let rt = self.regs.r[base as usize] & !mask;
        let mu = self.modifier(modsel) | mask;
        let rt_hi = rt.wrapping_add(mu);
        // hw (off_pair) forms: 64 halfword elements, each from a word offset in
        // the Vvv pair; element k's offset is word (k>>1) of vector (offsets+(k&1)).
        let nelem = if off_pair { 64 } else { 128 / esz as usize };
        let width = if esz == 2 {
            MemWidth::Half
        } else {
            MemWidth::Word
        };
        let esz = esz as usize;
        for k in 0..nelem {
            let mut off = if off_pair {
                self.velem(offsets + (k & 1) as u8, 4, k >> 1)
            } else {
                self.velem(offsets, esz as u8, k)
            };
            if add {
                off &= !mask;
            }
            let ea = rt.wrapping_add(off);
            if ea < rt || ea > rt_hi {
                continue;
            }
            let datum = self.velem(data, esz as u8, k);
            if add {
                // Accumulate forms are never predicated (no `q` variant); RMW the
                // whole element width, wrapping at that width.
                let cur = self.load_mem(ea, width, MemSign::Unsigned)?;
                let sum = match esz {
                    2 => (cur as u16).wrapping_add(datum as u16) as u32,
                    _ => cur.wrapping_add(datum),
                };
                self.store_mem(ea, width, sum)?;
            } else {
                // Plain store. The `q` forms mask PER BYTE: byte `b` of element
                // `k` is written iff predicate bit `k*esz + b` is set (matching
                // qemu's byte-granular scatter predicate).
                let bytes = datum.to_le_bytes();
                for b in 0..esz {
                    if let Some(q) = pred {
                        if !self.qbit(q, k * esz + b) {
                            continue;
                        }
                    }
                    self.store_mem(ea.wrapping_add(b as u32), MemWidth::Byte, bytes[b] as u32)?;
                }
            }
        }
        Ok(())
    }

    /// HVX V65 gather: read elements from `Rt + offset[i]` into a 128-byte vector,
    /// returning `(data, valid)`. Byte `b` is gathered (`valid[b] = true`) iff its
    /// element's effective address is in range and (for the `q` forms) its
    /// predicate bit is set; non-valid bytes are left for the paired store to
    /// preserve from the destination memory (matching hardware, where the gather
    /// temp is initialised from the destination and only valid lanes overwrite).
    fn exec_gather(
        &self,
        base: u8,
        modsel: u8,
        offsets: u8,
        esz: u8,
        off_pair: bool,
        pred: Option<u8>,
    ) -> Result<([u8; 128], [bool; 128])> {
        let mask = (esz as u32) - 1;
        let rt = self.regs.r[base as usize] & !mask;
        let mu = self.modifier(modsel) | mask;
        let rt_hi = rt.wrapping_add(mu);
        let nelem = if off_pair { 64 } else { 128 / esz as usize };
        let width = if esz == 2 {
            MemWidth::Half
        } else {
            MemWidth::Word
        };
        let esz = esz as usize;
        let mut out = [0u8; 128];
        let mut valid = [false; 128];
        for k in 0..nelem {
            let off = if off_pair {
                self.velem(offsets + (k & 1) as u8, 4, k >> 1)
            } else {
                self.velem(offsets, esz as u8, k)
            };
            let ea = rt.wrapping_add(off);
            if ea < rt || ea > rt_hi {
                continue;
            }
            let datum = self.load_mem(ea, width, MemSign::Unsigned)?;
            let bytes = datum.to_le_bytes();
            let dst = k * esz;
            // The `q` forms gather PER BYTE: byte `b` of element `k` is gathered
            // iff predicate bit `k*esz + b` is set.
            for b in 0..esz {
                if let Some(q) = pred {
                    if !self.qbit(q, k * esz + b) {
                        continue;
                    }
                }
                out[dst + b] = bytes[b];
                valid[dst + b] = true;
            }
        }
        Ok((out, valid))
    }

    fn fetch_word(&self, pc: u32) -> Result<u32> {
        if pc & 3 != 0 {
            return Err(Error::AlignmentFault {
                pc: pc as u64,
                address: pc as u64,
                alignment: 4,
                access: crate::error::MemoryAccessKind::Fetch,
            });
        }
        // Instruction words belong to the packet-entry image even when a
        // pending store overlaps a later word of this same packet.
        let mut bytes = [0; 4];
        self.read_packet_ram(pc, &mut bytes)?;
        Ok(match self.endian {
            Endianness::Little => u32::from_le_bytes(bytes),
            Endianness::Big => u32::from_be_bytes(bytes),
        })
    }

    fn ensure_isa_supports(
        &self,
        word: u32,
        insn: &DecodedInsn,
        opcode: Option<Opcode>,
    ) -> Result<()> {
        if isa_supports_insn(self._isa, insn, opcode) {
            return Ok(());
        }
        Err(Error::Emulator(format!(
            "hexagon instruction 0x{word:08x} not supported by ISA {:?}",
            self._isa
        )))
    }

    fn is_mmio(addr: u32) -> bool {
        let addr = addr as u64;
        (addr >= SERIAL_MMIO_BASE && addr < SERIAL_MMIO_BASE + SERIAL_MMIO_LEN)
            || (addr >= DEBUG_MMIO_BASE && addr < DEBUG_MMIO_BASE + DEBUG_MMIO_LEN)
    }

    fn set_pc(&mut self, pc: u32) {
        self.regs.set_pc(pc);
    }

    /// USR.LPCFG (bits 9:8): software-pipelined loop config. Counts the number of
    /// loop iterations remaining before the pipeline predicate (P3) is set.
    fn get_lpcfg(&self) -> u32 {
        (self.regs.c[8] >> 8) & 0x3
    }

    fn set_lpcfg(&mut self, value: u32) {
        self.regs.c[8] = (self.regs.c[8] & !(0x3 << 8)) | ((value & 0x3) << 8);
    }

    fn load_mem(&self, addr: u32, width: MemWidth, sign: MemSign) -> Result<u32> {
        match width {
            MemWidth::Byte => {
                let val = self.read_u8(addr)?;
                Ok(match sign {
                    MemSign::Signed => (val as i8 as i32) as u32,
                    MemSign::Unsigned => val as u32,
                })
            }
            MemWidth::Half => {
                let val = self.read_u16(addr)?;
                Ok(match sign {
                    MemSign::Signed => (val as i16 as i32) as u32,
                    MemSign::Unsigned => val as u32,
                })
            }
            MemWidth::Word => self.read_u32(addr),
            MemWidth::Double => Err(Error::Emulator(
                "doubleword load not supported yet".to_string(),
            )),
        }
    }

    fn store_mem(&self, addr: u32, width: MemWidth, value: u32) -> Result<()> {
        match width {
            MemWidth::Byte => self.write_u8(addr, value as u8),
            MemWidth::Half => self.write_u16(addr, value as u16),
            MemWidth::Word => self.write_u32(addr, value),
            MemWidth::Double => Err(Error::Emulator(
                "doubleword store not supported yet".to_string(),
            )),
        }
    }

    fn commit_packet(&mut self, new_r: &[Option<u32>; 32], new_p: &[Option<u8>; 4]) {
        for (idx, val) in new_r.iter().enumerate() {
            if let Some(value) = val {
                self.regs.r[idx] = *value;
            }
        }
        for (idx, val) in new_p.iter().enumerate() {
            if let Some(value) = val {
                self.regs.set_predicate(idx, *value);
            }
        }
        // Commit in-flight HVX vector / vector-predicate writes. `.tmp` loads
        // (new_v_tmp) are scratch: discard them without writing the register file.
        for idx in 0..32 {
            if let Some(value) = self.new_v[idx].take() {
                self.regs.v[idx] = value;
            }
            self.new_v_tmp[idx] = None;
        }
        for idx in 0..4 {
            if let Some(value) = self.new_q[idx].take() {
                self.regs.q[idx] = value;
            }
        }
    }

    fn eval_pred(&self, cond: PredCond, new_p: &[Option<u8>; 4]) -> bool {
        let val = if cond.pred_new {
            new_p[cond.pred as usize].unwrap_or(self.old_regs().p[cond.pred as usize])
        } else {
            self.old_regs().p[cond.pred as usize]
        };
        // Conditional execution tests only the least-significant bit.
        let lsb = val & 1 != 0;
        if cond.sense { lsb } else { !lsb }
    }

    fn read_reg_with_new(&self, reg: u8, new_r: &[Option<u32>; 32]) -> u32 {
        new_r[reg as usize].unwrap_or(self.regs.r[reg as usize])
    }

    /// Modifier register value for `modsel` (0 -> M0/C6, 1 -> M1/C7).
    fn modifier(&self, modsel: u8) -> u32 {
        self.old_regs().control(if modsel & 1 == 0 { 6 } else { 7 })
    }

    /// Circular-start register for `modsel` (0 -> CS0/C12, 1 -> CS1/C13).
    fn circ_start(&self, modsel: u8) -> u32 {
        self.old_regs()
            .control(if modsel & 1 == 0 { 12 } else { 13 })
    }

    /// Resolve a load/store `AddrMode` to `(effective_addr, base_update)`,
    /// where `base_update` is the post-increment write-back `(reg, value)`.
    fn resolve_addr(&self, addr: AddrMode) -> (u32, Option<(u8, u32)>) {
        match addr {
            AddrMode::Offset { base, offset } => {
                let base_val = self.regs.r[base as usize];
                (base_val.wrapping_add(offset as u32), None)
            }
            AddrMode::PostIncImm { base, offset } => {
                let base_val = self.regs.r[base as usize];
                let new_base = base_val.wrapping_add(offset as u32);
                (base_val, Some((base, new_base)))
            }
            AddrMode::GpOffset { offset } => {
                let gp = self.old_regs().control(11) & !0x3f; // GP low 6 bits hardwired zero
                (gp.wrapping_add(offset as u32), None)
            }
            AddrMode::Abs { addr } => (addr, None),
            AddrMode::PostIncReg { base, modsel } => {
                let base_val = self.regs.r[base as usize];
                let new_base = base_val.wrapping_add(self.modifier(modsel));
                (base_val, Some((base, new_base)))
            }
            AddrMode::PostIncBrev { base, modsel } => {
                let base_val = self.regs.r[base as usize];
                let ea = hex_brev(base_val);
                let new_base = base_val.wrapping_add(self.modifier(modsel));
                (ea, Some((base, new_base)))
            }
            AddrMode::PostIncCircImm { base, modsel, incr } => {
                let base_val = self.regs.r[base as usize];
                let new_base = hex_circ_add(
                    base_val,
                    incr,
                    self.modifier(modsel),
                    self.circ_start(modsel),
                );
                (base_val, Some((base, new_base)))
            }
            AddrMode::PostIncCircReg {
                base,
                modsel,
                shift,
            } => {
                let base_val = self.regs.r[base as usize];
                let m = self.modifier(modsel);
                let incr = hex_read_ireg(m).wrapping_shl(shift as u32);
                let new_base = hex_circ_add(base_val, incr, m, self.circ_start(modsel));
                (base_val, Some((base, new_base)))
            }
            AddrMode::RegScaled { base, index, shift } => {
                let base_val = self.regs.r[base as usize];
                let idx = self.regs.r[index as usize].wrapping_shl(shift as u32);
                (base_val.wrapping_add(idx), None)
            }
            // `memX(Re=##U6)`: EA is the absolute address; the address register
            // Re is also written with that same absolute (a base "update").
            AddrMode::AbsSet { areg, addr } => (addr, Some((areg, addr))),
            // `memX(Ru<<#u2+##U6)`: EA = abs + (Ru << shift); no register update.
            AddrMode::IndexAbs { index, shift, addr } => {
                let idx = self.regs.r[index as usize].wrapping_shl(shift as u32);
                (addr.wrapping_add(idx), None)
            }
        }
    }

    fn set_branch(
        &self,
        branch: &mut Option<BranchTarget>,
        target: u32,
        is_call: bool,
    ) -> Result<()> {
        if branch.is_some() {
            return Err(Error::Emulator("multiple branches in packet".to_string()));
        }
        *branch = Some(BranchTarget { target, is_call });
        Ok(())
    }

    /// Attempt to execute `word` via the direct opcode-dispatch semantic layer.
    /// Returns `Ok(true)` if a handler ran, `Ok(false)` if the opcode is not yet
    /// modelled there (caller treats it as a genuine decode failure).
    fn try_sem(
        &mut self,
        word: u32,
        immext: Option<u32>,
        new_r: &mut [Option<u32>; 32],
        new_p: &mut [Option<u8>; 4],
    ) -> Result<bool> {
        let dop = match super::opcode::decode_word(word) {
            Some(d) => d,
            None => return Ok(false),
        };
        let (usr_or, v_writes, q_writes) = {
            let mut ctx = super::semantics::SemCtx {
                regs: self.effects.initial.as_deref().unwrap_or(&self.regs),
                new_r: &mut *new_r,
                new_p: &mut *new_p,
                vnew: &self.new_v,
                vtmp: &self.new_v_tmp,
                qnew: &self.new_q,
                v_writes: Vec::new(),
                q_writes: Vec::new(),
                invalid_hvx_access: std::cell::Cell::new(false),
                immext,
                usr_or: 0,
            };
            if !super::semantics::dispatch(&dop, &mut ctx) {
                if ctx.invalid_hvx_access() {
                    return Err(Error::Emulator(format!(
                        "invalid HVX register operand for {:?}",
                        dop.opcode
                    )));
                }
                return Ok(false);
            }
            (ctx.usr_or, ctx.v_writes, ctx.q_writes)
        };
        if let Some((i, _)) = v_writes
            .iter()
            .find(|(i, _)| (*i as usize) >= self.new_v.len())
        {
            return Err(Error::Emulator(format!(
                "invalid HVX vector register write V{i}"
            )));
        }
        if let Some((i, _)) = q_writes
            .iter()
            .find(|(i, _)| (*i as usize) >= self.new_q.len())
        {
            return Err(Error::Emulator(format!(
                "invalid HVX predicate register write Q{i}"
            )));
        }
        for (i, val) in v_writes {
            self.new_v[i as usize] = Some(val);
            // Track the in-packet vector producer for new-value vector stores.
            self.last_v_produced = Some(i);
        }
        for (i, val) in q_writes {
            self.new_q[i as usize] = Some(val);
        }
        if usr_or != 0 {
            self.regs.c[8] |= usr_or;
        }
        Ok(true)
    }

    fn finish_packet(
        &mut self,
        pc: u32,
        packet_pc: u32,
        new_r: [Option<u32>; 32],
        new_p: [Option<u8>; 4],
        branch: Option<BranchTarget>,
        first_parse: Option<u32>,
        second_parse: Option<u32>,
    ) {
        self.commit_packet(&new_r, &new_p);
        let packet_end = pc;

        let (loop0_end, loop1_end) = match (first_parse, second_parse) {
            (Some(first), Some(second)) => {
                let loop0 = first == 0b10 && second != 0;
                let loop1 = second == 0b10 && first != 0;
                (loop0, loop1)
            }
            _ => (false, false),
        };

        // Software-pipelined loop predicate (P3) maintenance: at every `endloop0`
        // (and the loop0 half of `endloop01`), if USR.LPCFG is non-zero then
        // when it reaches 1 P3 is set to 0xff, after which LPCFG is decremented.
        // This runs regardless of whether the back-edge is taken (`sp*loop0`
        // presets P3=0 at setup; the kernel predicate goes true on the final
        // prologue iterations).
        if loop0_end {
            let lpcfg = self.get_lpcfg();
            if lpcfg != 0 {
                if lpcfg == 1 {
                    self.regs.set_predicate(3, 0xff);
                }
                self.set_lpcfg(lpcfg - 1);
            }
        }

        if let Some(branch) = branch {
            if branch.is_call {
                self.regs.r[31] = packet_end;
            }
            self.set_pc(branch.target);
        } else if loop0_end && self.regs.c[1] > 1 {
            self.regs.c[1] = self.regs.c[1].wrapping_sub(1);
            self.set_pc(self.regs.c[0]);
        } else if loop1_end && self.regs.c[3] > 1 {
            self.regs.c[3] = self.regs.c[3].wrapping_sub(1);
            self.set_pc(self.regs.c[2]);
        } else {
            self.set_pc(packet_end);
        }
    }

    fn save_packet_state(
        &mut self,
        packet_pc: u32,
        pc: u32,
        immext: Option<u32>,
        new_r: [Option<u32>; 32],
        new_p: [Option<u8>; 4],
        branch: Option<BranchTarget>,
        inst_index: usize,
        first_parse: Option<u32>,
        second_parse: Option<u32>,
        pending_duplex: Option<u32>,
        pending_end: bool,
    ) {
        self.pending_packet = Some(PacketState {
            packet_pc,
            pc,
            immext,
            new_r,
            new_p,
            branch,
            inst_index,
            first_parse,
            second_parse,
            pending_duplex,
            pending_end,
        });
        self.set_pc(pc);
    }

    fn step_packet(&mut self) -> Result<Option<VcpuExit>> {
        let resuming = self.pending_packet.is_some();
        let mut state = self
            .pending_packet
            .take()
            .unwrap_or_else(|| PacketState::new(self.regs.pc()));
        // Fresh packet: clear the in-flight HVX vector write buffers (they
        // persist across an MMIO suspend/resume of the same packet).
        if !resuming {
            self.packet_producers.clear();
            self.new_v = [None; 32];
            self.new_q = [None; 4];
            self.new_v_tmp = [None; 32];
            self.gather_tmp = None;
            self.last_v_produced = None;
            // Pre-execute vector `.tmp` loads so their data is visible to a
            // same-packet consumer (e.g. vhist, which the assembler encodes
            // BEFORE the producing `.tmp` load). Read-only here: the producing
            // load still runs normally in the main loop (post-increment, etc.).
            let mut scan_pc = state.pc;
            for _ in 0..4 {
                let w = match self.fetch_word(scan_pc) {
                    Ok(w) => w,
                    Err(_) => break,
                };
                let pb = (w >> 14) & 0x3;
                match decode(w, None, self._isa).insn {
                    DecodedInsn::VLoad {
                        dst,
                        base,
                        offset,
                        aligned,
                        commit: false,
                        pred,
                        ..
                    } => {
                        // A scalar-predicated `.tmp` load that is cancelled
                        // (predicate false) must NOT seed the scratch buffer: a
                        // same-packet consumer would otherwise observe data from
                        // a memory access that architecturally did not occur.
                        let do_load = match pred {
                            Some(cond) => self.eval_pred(cond, &[None; 4]),
                            None => true,
                        };
                        if do_load {
                            let mut ea = self.regs.r[base as usize].wrapping_add(offset as u32);
                            if aligned {
                                ea &= !127;
                            }
                            if let Ok(vec) = self.read_vec(ea) {
                                self.new_v_tmp[dst as usize] = Some(vec);
                            }
                        }
                    }
                    // Pre-run the gather: its result (`gather_tmp`) feeds the
                    // paired `vmem=vtmp.new` store, which the assembler encodes
                    // BEFORE the gather. The gather instruction itself still runs
                    // in the main loop (recomputing the same scratch).
                    DecodedInsn::VGather {
                        base,
                        modsel,
                        offsets,
                        esz,
                        off_pair,
                        pred,
                    } => {
                        if let Ok(vec) =
                            self.exec_gather(base, modsel, offsets, esz, off_pair, pred)
                        {
                            self.gather_tmp = Some(vec);
                        }
                    }
                    _ => {}
                }
                scan_pc = scan_pc.wrapping_add(4);
                if pb == 0b11 || pb == 0b00 {
                    break;
                }
            }
        }

        let mut pc = state.pc;
        let packet_pc = state.packet_pc;
        let mut immext = state.immext;
        let mut new_r = state.new_r;
        let mut new_p = state.new_p;
        let mut branch = state.branch;
        let mut inst_index = state.inst_index;
        let mut first_parse = state.first_parse;
        let mut second_parse = state.second_parse;
        let mut pending_duplex = state.pending_duplex;
        let mut pending_end = state.pending_end;

        loop {
            if let Some(word) = pending_duplex.take() {
                // Retain the original word across a pause: guest code may have
                // changed since slot 1 ran, and decoded enums are derived state.
                let (_, sub) = decode_duplex(word, self._isa).ok_or_else(|| {
                    Error::Emulator("invalid retained Hexagon duplex word".into())
                })?;
                self.ensure_isa_supports(word, &sub.insn, sub.opcode)?;
                if let Some(exit) = self.execute_aligned_insn(
                    sub.insn,
                    packet_pc,
                    None,
                    &mut new_r,
                    &mut new_p,
                    &mut branch,
                )? {
                    if matches!(exit, VcpuExit::Shutdown) {
                        self.finish_packet(
                            pc,
                            packet_pc,
                            new_r,
                            new_p,
                            branch,
                            first_parse,
                            second_parse,
                        );
                        return Ok(Some(exit));
                    }

                    self.save_packet_state(
                        packet_pc,
                        pc,
                        immext,
                        new_r,
                        new_p,
                        branch,
                        inst_index,
                        first_parse,
                        second_parse,
                        None,
                        pending_end,
                    );
                    return Ok(Some(exit));
                }

                if pending_end {
                    self.finish_packet(
                        pc,
                        packet_pc,
                        new_r,
                        new_p,
                        branch,
                        first_parse,
                        second_parse,
                    );
                    return Ok(None);
                }

                continue;
            }

            if pending_end {
                break;
            }
            if inst_index >= 4 {
                return Err(Error::Emulator("Hexagon packet exceeds four words".into()));
            }
            let word = self.fetch_word(pc)?;
            let parse = (word >> 14) & 0x3;

            if inst_index == 0 {
                first_parse = Some(parse);
            } else if inst_index == 1 {
                second_parse = Some(parse);
            }
            inst_index += 1;

            if parse == 0 {
                let (slot1, slot0) = decode_duplex(word, self._isa).ok_or_else(|| {
                    Error::Emulator(format!(
                        "unknown duplex instruction 0x{word:08x} at pc=0x{pc:08x}"
                    ))
                })?;
                self.ensure_isa_supports(word, &slot1.insn, slot1.opcode)?;
                self.ensure_isa_supports(word, &slot0.insn, slot0.opcode)?;

                if let Some(exit) = self.execute_aligned_insn(
                    slot1.insn,
                    packet_pc,
                    None,
                    &mut new_r,
                    &mut new_p,
                    &mut branch,
                )? {
                    if matches!(exit, VcpuExit::Shutdown) {
                        self.finish_packet(
                            pc.wrapping_add(4),
                            packet_pc,
                            new_r,
                            new_p,
                            branch,
                            first_parse,
                            second_parse,
                        );
                        return Ok(Some(exit));
                    }

                    pc = pc.wrapping_add(4);
                    pending_end = true;
                    pending_duplex = Some(word);
                    self.save_packet_state(
                        packet_pc,
                        pc,
                        immext,
                        new_r,
                        new_p,
                        branch,
                        inst_index,
                        first_parse,
                        second_parse,
                        pending_duplex,
                        pending_end,
                    );
                    return Ok(Some(exit));
                }

                if let Some(exit) = self.execute_aligned_insn(
                    slot0.insn,
                    packet_pc,
                    None,
                    &mut new_r,
                    &mut new_p,
                    &mut branch,
                )? {
                    if matches!(exit, VcpuExit::Shutdown) {
                        self.finish_packet(
                            pc.wrapping_add(4),
                            packet_pc,
                            new_r,
                            new_p,
                            branch,
                            first_parse,
                            second_parse,
                        );
                        return Ok(Some(exit));
                    }

                    pc = pc.wrapping_add(4);
                    pending_end = true;
                    self.save_packet_state(
                        packet_pc,
                        pc,
                        immext,
                        new_r,
                        new_p,
                        branch,
                        inst_index,
                        first_parse,
                        second_parse,
                        None,
                        pending_end,
                    );
                    return Ok(Some(exit));
                }

                pc = pc.wrapping_add(4);
                pending_end = true;
                break;
            }

            let cur_immext = immext;
            let decoded = decode(word, immext, self._isa);
            immext = None;
            self.ensure_isa_supports(word, &decoded.insn, decoded.opcode)?;

            match decoded.insn {
                DecodedInsn::ImmExt { value } => {
                    immext = Some(value);
                    pc = pc.wrapping_add(4);
                    if parse == 0x3 {
                        self.finish_packet(
                            pc,
                            packet_pc,
                            new_r,
                            new_p,
                            branch,
                            first_parse,
                            second_parse,
                        );
                        return Ok(None);
                    }
                    continue;
                }
                insn => {
                    // Resolve a new-value store's `Nt8` against the packet's
                    // GPR producers before executing it.
                    let insn = resolve_new_value(insn, &self.packet_producers);
                    let before = producer_mask(&new_r);
                    if let Some(exit) = self.execute_aligned_insn(
                        insn,
                        packet_pc,
                        cur_immext,
                        &mut new_r,
                        &mut new_p,
                        &mut branch,
                    )? {
                        if matches!(exit, VcpuExit::Shutdown) {
                            self.finish_packet(
                                pc.wrapping_add(4),
                                packet_pc,
                                new_r,
                                new_p,
                                branch,
                                first_parse,
                                second_parse,
                            );
                            return Ok(Some(exit));
                        }

                        // The MMIO destination is a producer even before its
                        // value arrives; retain exactly one producer per word.
                        let mut produced = new_r.iter().enumerate().find_map(|(index, value)| {
                            (value.is_some() && !before[index]).then_some(index as u8)
                        });
                        if let Some(pending) = &self.pending_mmio {
                            produced =
                                Some(produced.map_or(pending.dst, |index| index.min(pending.dst)));
                        }
                        if let Some(register) = produced {
                            self.packet_producers.push(register);
                        }
                        pc = pc.wrapping_add(4);
                        pending_end = parse == 0x3;
                        self.save_packet_state(
                            packet_pc,
                            pc,
                            immext,
                            new_r,
                            new_p,
                            branch,
                            inst_index,
                            first_parse,
                            second_parse,
                            None,
                            pending_end,
                        );
                        return Ok(Some(exit));
                    }
                    record_producer(&new_r, before, &mut self.packet_producers);
                }
            }

            pc = pc.wrapping_add(4);
            if parse == 0x3 {
                break;
            }
        }

        self.finish_packet(
            pc,
            packet_pc,
            new_r,
            new_p,
            branch,
            first_parse,
            second_parse,
        );
        Ok(None)
    }
}

#[path = "cpu_vcpu.rs"]
mod vcpu_impl;
