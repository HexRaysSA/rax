//! RVV memory operations and precise `vstart` publication.

use super::{Insn, Op, RiscVCpu, Trap, VLENB};

#[inline]
fn encoded_width(insn: &Insn) -> Result<usize, Trap> {
    match insn.funct3 {
        0 => Ok(1),
        5 => Ok(2),
        6 => Ok(4),
        7 => Ok(8),
        _ => Err(Trap::illegal(insn.raw)),
    }
}

impl RiscVCpu {
    fn vector_read(&mut self, element: usize, addr: u64, buf: &mut [u8]) -> Result<(), Trap> {
        if let Err(trap) = self.load_bytes(addr, buf) {
            self.vstart = element as u64;
            return Err(trap);
        }
        Ok(())
    }

    fn vector_write(&mut self, element: usize, addr: u64, data: &[u8]) -> Result<(), Trap> {
        if let Err(trap) = self.store_bytes(addr, data) {
            self.vstart = element as u64;
            return Err(trap);
        }
        Ok(())
    }

    pub(super) fn exec_vector_memory(
        &mut self,
        insn: &Insn,
        vm: bool,
        vd: u8,
        vstart: usize,
        vl: usize,
    ) -> Result<(), Trap> {
        match insn.op {
            Op::Vle | Op::Vse => {
                let eb = encoded_width(insn)?;
                let base = self.x(insn.rs1) & self.xmask();
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let addr = base.wrapping_add((e * eb) as u64) & self.xmask();
                    if insn.op == Op::Vle {
                        let mut buf = [0u8; 8];
                        self.vector_read(e, addr, &mut buf[..eb])?;
                        self.set_velem(vd, e, eb, u64::from_le_bytes(buf));
                    } else {
                        let val = self.velem(vd, e, eb);
                        self.vector_write(e, addr, &val.to_le_bytes()[..eb])?;
                    }
                }
            }
            Op::Vlse | Op::Vsse => {
                let eb = encoded_width(insn)?;
                let base = self.x(insn.rs1) & self.xmask();
                let stride = self.x(insn.rs2) as i64;
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let addr =
                        base.wrapping_add((e as i64).wrapping_mul(stride) as u64) & self.xmask();
                    if insn.op == Op::Vlse {
                        let mut buf = [0u8; 8];
                        self.vector_read(e, addr, &mut buf[..eb])?;
                        self.set_velem(vd, e, eb, u64::from_le_bytes(buf));
                    } else {
                        let val = self.velem(vd, e, eb);
                        self.vector_write(e, addr, &val.to_le_bytes()[..eb])?;
                    }
                }
            }
            Op::Vlxei | Op::Vsxei => {
                let ieb = encoded_width(insn)?;
                let eb = self.sew_bytes();
                let base = self.x(insn.rs1) & self.xmask();
                // A non-segment indexed load may legally overlap its index
                // group under the general mixed-EEW rules. Preserve the
                // original indices before destination writes begin.
                let indices = (insn.op == Op::Vlxei).then(|| self.vector_snapshot());
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let index = indices.as_ref().map_or_else(
                        || self.velem(insn.rs2, e, ieb),
                        |snapshot| Self::snapshot_velem(snapshot, insn.rs2, e, ieb),
                    );
                    let addr = base.wrapping_add(index) & self.xmask();
                    if insn.op == Op::Vlxei {
                        let mut buf = [0u8; 8];
                        self.vector_read(e, addr, &mut buf[..eb])?;
                        self.set_velem(vd, e, eb, u64::from_le_bytes(buf));
                    } else {
                        let val = self.velem(vd, e, eb);
                        self.vector_write(e, addr, &val.to_le_bytes()[..eb])?;
                    }
                }
            }
            Op::Vleff => {
                let eb = encoded_width(insn)?;
                let base = self.x(insn.rs1) & self.xmask();
                let mut new_vl = vl;
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let addr = base.wrapping_add((e * eb) as u64) & self.xmask();
                    let mut buf = [0u8; 8];
                    match self.load_bytes(addr, &mut buf[..eb]) {
                        Ok(()) => self.set_velem(vd, e, eb, u64::from_le_bytes(buf)),
                        Err(trap) if e == 0 => {
                            self.vstart = 0;
                            return Err(trap);
                        }
                        Err(_) => {
                            new_vl = e;
                            break;
                        }
                    }
                }
                self.vl = new_vl as u64;
            }
            Op::Vlseg | Op::Vsseg => {
                let nf = ((insn.raw >> 29) & 7) as usize + 1;
                let mop = (insn.raw >> 26) & 3;
                let is_load = insn.op == Op::Vlseg;
                let width = encoded_width(insn)?;
                let indexed = mop == 0b01 || mop == 0b11;
                let fault_only_first =
                    is_load && mop == 0b00 && ((insn.raw >> 20) & 0x1f) == 0b10000;
                let eb = if indexed { self.sew_bytes() } else { width };

                let sew_bits = 8u32 << ((self.vtype >> 3) & 0x7);
                let eew_bits = if indexed {
                    sew_bits
                } else {
                    (width as u32) * 8
                };
                let (lmul_n, lmul_d): (u32, u32) = match self.vtype & 0x7 {
                    0 => (1, 1),
                    1 => (2, 1),
                    2 => (4, 1),
                    3 => (8, 1),
                    5 => (1, 8),
                    6 => (1, 4),
                    7 => (1, 2),
                    _ => (1, 1),
                };
                let emul_regs = ((eew_bits * lmul_n) / (sew_bits * lmul_d)).max(1) as usize;
                if emul_regs > 8 || nf * emul_regs > 8 || vd as usize + nf * emul_regs > 32 {
                    return Err(Trap::illegal(insn.raw));
                }

                let base = self.x(insn.rs1) & self.xmask();
                let stride = self.x(insn.rs2) as i64;
                let mut new_vl = vl;
                'elements: for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let elem_base = match mop {
                        0b00 => base.wrapping_add((e * nf * eb) as u64),
                        0b10 => base.wrapping_add((e as i64).wrapping_mul(stride) as u64),
                        _ => base.wrapping_add(self.velem(insn.rs2, e, width)),
                    } & self.xmask();
                    for f in 0..nf {
                        let addr = elem_base.wrapping_add((f * eb) as u64) & self.xmask();
                        let reg = (vd as usize + f * emul_regs) as u8;
                        if is_load {
                            let mut buf = [0u8; 8];
                            if fault_only_first {
                                if let Err(trap) = self.load_bytes(addr, &mut buf[..eb]) {
                                    if e == 0 {
                                        self.vstart = 0;
                                        return Err(trap);
                                    }
                                    new_vl = e;
                                    break 'elements;
                                }
                            } else {
                                self.vector_read(e, addr, &mut buf[..eb])?;
                            }
                            self.set_velem(reg, e, eb, u64::from_le_bytes(buf));
                        } else {
                            let val = self.velem(reg, e, eb);
                            self.vector_write(e, addr, &val.to_le_bytes()[..eb])?;
                        }
                    }
                }
                if fault_only_first {
                    self.vl = new_vl as u64;
                }
            }
            Op::Vlm | Op::Vsm => {
                // Mask transfers use byte-sized elements and vstart is a byte
                // index into their effective length ceil(vl/8).
                if !vm {
                    return Err(Trap::illegal(insn.raw));
                }
                let base = self.x(insn.rs1) & self.xmask();
                let evl = vl.div_ceil(8);
                for e in vstart..evl {
                    let addr = base.wrapping_add(e as u64) & self.xmask();
                    if insn.op == Op::Vlm {
                        let mut buf = [0u8; 1];
                        self.vector_read(e, addr, &mut buf)?;
                        self.set_velem(vd, e, 1, u64::from(buf[0]));
                    } else {
                        let val = self.velem(vd, e, 1);
                        self.vector_write(e, addr, &[val as u8])?;
                    }
                }
            }
            Op::Vlre | Op::Vsre => {
                // Whole-register transfers ignore vtype/vl. vstart indexes
                // encoded-EEW elements in the independent effective length.
                let eb = encoded_width(insn)?;
                let nreg = ((insn.raw >> 29) & 7) as usize + 1;
                if !vm
                    || !matches!(nreg, 1 | 2 | 4 | 8)
                    || vd as usize % nreg != 0
                    || vd as usize + nreg > 32
                {
                    return Err(Trap::illegal(insn.raw));
                }
                let base = self.x(insn.rs1) & self.xmask();
                let evl = nreg * VLENB as usize / eb;
                for e in vstart..evl {
                    let addr = base.wrapping_add((e * eb) as u64) & self.xmask();
                    if insn.op == Op::Vlre {
                        let mut buf = [0u8; 8];
                        self.vector_read(e, addr, &mut buf[..eb])?;
                        self.set_velem(vd, e, eb, u64::from_le_bytes(buf));
                    } else {
                        let val = self.velem(vd, e, eb);
                        self.vector_write(e, addr, &val.to_le_bytes()[..eb])?;
                    }
                }
            }
            _ => return Err(Trap::illegal(insn.raw)),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::riscv::cpu::acc_fault;
    use crate::isa::riscv::{FlatMemory, Isa, RiscVConfig, RiscVExit, Xlen, decode};

    fn cpu(memory: FlatMemory, vl: u64, vtype: u64) -> RiscVCpu {
        let mut cpu = RiscVCpu::new(RiscVConfig::rv64gc(), Box::new(memory));
        cpu.set_vl_vtype(vl, vtype);
        cpu
    }

    fn execute(cpu: &mut RiscVCpu, raw: u32) -> Result<RiscVExit, Trap> {
        let insn = decode(raw, Xlen::Rv64, &Isa::rv64gc());
        assert_ne!(insn.op, Op::Illegal, "test encoding {raw:08x} is illegal");
        cpu.execute_insn(&insn, 0x1000)
    }

    fn load(vm: u32, nf: u32, lumop: u32, rs1: u32, width: u32, vd: u32) -> u32 {
        (nf << 29) | (vm << 25) | (lumop << 20) | (rs1 << 15) | (width << 12) | (vd << 7) | 0x07
    }

    fn store(vm: u32, nf: u32, sumop: u32, rs1: u32, width: u32, vs3: u32) -> u32 {
        (nf << 29) | (vm << 25) | (sumop << 20) | (rs1 << 15) | (width << 12) | (vs3 << 7) | 0x27
    }

    fn memory_op(
        opcode: u32,
        vm: u32,
        nf: u32,
        mop: u32,
        field: u32,
        rs1: u32,
        width: u32,
        vd: u32,
    ) -> u32 {
        (nf << 29)
            | (mop << 26)
            | (vm << 25)
            | (field << 20)
            | (rs1 << 15)
            | (width << 12)
            | (vd << 7)
            | opcode
    }

    #[test]
    fn mask_load_and_store_use_byte_indexed_vstart() {
        let mut load_cpu = cpu(FlatMemory::with_data(0x100, vec![0x11, 0x22, 0x33]), 24, 0);
        load_cpu.set_x(10, 0x100);
        load_cpu.set_vreg(1, &[0xaa; 16]);
        load_cpu.set_vstart(1);
        assert_eq!(
            execute(&mut load_cpu, load(1, 0, 0b01011, 10, 0, 1)),
            Ok(RiscVExit::Continue)
        );
        assert_eq!(&load_cpu.vreg(1)[..3], &[0xaa, 0x22, 0x33]);
        assert_eq!(load_cpu.vstart(), 0);

        let mut store_cpu = cpu(FlatMemory::with_data(0x100, vec![0xee; 3]), 24, 0);
        store_cpu.set_x(10, 0x100);
        let mut source = [0u8; 16];
        source[..3].copy_from_slice(&[0x11, 0x22, 0x33]);
        store_cpu.set_vreg(1, &source);
        store_cpu.set_vstart(1);
        assert_eq!(
            execute(&mut store_cpu, store(1, 0, 0b01011, 10, 0, 1)),
            Ok(RiscVExit::Continue)
        );
        let mut stored = [0u8; 3];
        store_cpu.read_memory(0x100, &mut stored).unwrap();
        assert_eq!(stored, [0xee, 0x22, 0x33]);
        assert_eq!(store_cpu.vstart(), 0);
    }

    #[test]
    fn whole_register_transfer_uses_encoded_eew_and_ignores_vill() {
        let memory: Vec<u8> = (0..32).collect();
        let mut load_cpu = cpu(FlatMemory::with_data(0x100, memory.clone()), 0, 1u64 << 63);
        load_cpu.set_x(10, 0x100);
        load_cpu.set_vreg(2, &[0xaa; 16]);
        load_cpu.set_vreg(3, &[0xaa; 16]);
        load_cpu.set_vstart(2); // two e32 elements = eight bytes

        assert_eq!(
            execute(&mut load_cpu, load(1, 1, 0b01000, 10, 6, 2)),
            Ok(RiscVExit::Continue)
        );

        let mut actual = [0u8; 32];
        actual[..16].copy_from_slice(&load_cpu.vreg(2));
        actual[16..].copy_from_slice(&load_cpu.vreg(3));
        assert_eq!(&actual[..8], &[0xaa; 8]);
        assert_eq!(&actual[8..], &memory[8..]);
        assert_eq!(load_cpu.vstart(), 0);

        let mut store_cpu = cpu(FlatMemory::with_data(0x100, vec![0xee; 32]), 0, 1u64 << 63);
        store_cpu.set_x(10, 0x100);
        let source2: [u8; 16] = memory[..16].try_into().unwrap();
        let source3: [u8; 16] = memory[16..].try_into().unwrap();
        store_cpu.set_vreg(2, &source2);
        store_cpu.set_vreg(3, &source3);
        store_cpu.set_vstart(2);
        assert_eq!(
            execute(&mut store_cpu, store(1, 1, 0b01000, 10, 6, 2)),
            Ok(RiscVExit::Continue)
        );
        let mut stored = [0u8; 32];
        store_cpu.read_memory(0x100, &mut stored).unwrap();
        assert_eq!(&stored[..8], &[0xee; 8]);
        assert_eq!(&stored[8..], &memory[8..]);
        assert_eq!(store_cpu.vstart(), 0);
    }

    #[test]
    fn mask_transfer_respects_vill_and_whole_register_groups_are_validated() {
        let mut vill_cpu = cpu(FlatMemory::new(0x100, 64), 8, 1u64 << 63);
        vill_cpu.set_x(10, 0x100);
        vill_cpu.set_vstart(3);
        let raw = load(1, 0, 0b01011, 10, 0, 1);
        assert_eq!(execute(&mut vill_cpu, raw), Err(Trap::illegal(raw)));
        assert_eq!(vill_cpu.vstart(), 3);

        let mut group_cpu = cpu(FlatMemory::new(0x100, 64), 0, 0);
        group_cpu.set_x(10, 0x100);
        let misaligned = load(1, 1, 0b01000, 10, 0, 3);
        assert_eq!(
            execute(&mut group_cpu, misaligned),
            Err(Trap::illegal(misaligned))
        );
    }

    #[test]
    fn vector_memory_faults_publish_the_faulting_element() {
        let mut cpu = cpu(
            FlatMemory::with_data(0x100, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
            4,
            0x10,
        );
        cpu.set_x(10, 0x100);
        cpu.set_vreg(1, &[0xaa; 16]);

        let trap = execute(&mut cpu, load(1, 0, 0, 10, 6, 1)).unwrap_err();

        assert_eq!(trap, acc_fault(false, 0x108));
        assert_eq!(cpu.vstart(), 2);
        assert_eq!(&cpu.vreg(1)[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&cpu.vreg(1)[8..], &[0xaa; 8]);
    }

    #[test]
    fn memory_operands_validate_data_index_and_segment_groups() {
        let mut cpu = cpu(FlatMemory::new(0x100, 0x100), 2, 0x11); // e32,m2
        cpu.set_x(10, 0x100);

        let misaligned_unit = memory_op(0x07, 1, 0, 0, 0, 10, 6, 1);
        assert_eq!(
            execute(&mut cpu, misaligned_unit),
            Err(Trap::illegal(misaligned_unit))
        );
        let misaligned_unit_store = memory_op(0x27, 1, 0, 0, 0, 10, 6, 1);
        assert_eq!(
            execute(&mut cpu, misaligned_unit_store),
            Err(Trap::illegal(misaligned_unit_store))
        );

        let misaligned_index_data = memory_op(0x07, 1, 0, 1, 2, 10, 6, 1);
        assert_eq!(
            execute(&mut cpu, misaligned_index_data),
            Err(Trap::illegal(misaligned_index_data))
        );

        // EI64 at SEW=32, LMUL=2 gives the index operand EMUL=4, so v2 is
        // misaligned even though the data group v4-v5 is valid.
        let misaligned_index = memory_op(0x07, 1, 0, 1, 2, 10, 7, 4);
        assert_eq!(
            execute(&mut cpu, misaligned_index),
            Err(Trap::illegal(misaligned_index))
        );

        let misaligned_segment = memory_op(0x07, 1, 1, 0, 0, 10, 6, 1);
        assert_eq!(
            execute(&mut cpu, misaligned_segment),
            Err(Trap::illegal(misaligned_segment))
        );
        let misaligned_segment_store = memory_op(0x27, 1, 1, 0, 0, 10, 6, 1);
        assert_eq!(
            execute(&mut cpu, misaligned_segment_store),
            Err(Trap::illegal(misaligned_segment_store))
        );

        let aligned_segment = memory_op(0x07, 1, 1, 0, 0, 10, 6, 2);
        assert_eq!(execute(&mut cpu, aligned_segment), Ok(RiscVExit::Continue));

        // Unlike an ordinary indexed load, an indexed segment load cannot
        // overlap its index group even when the data and index EEWs match.
        let overlapping_indexed_segment = memory_op(0x07, 1, 1, 1, 4, 10, 6, 4);
        assert_eq!(
            execute(&mut cpu, overlapping_indexed_segment),
            Err(Trap::illegal(overlapping_indexed_segment))
        );
    }

    #[test]
    fn indexed_segment_fields_use_sew_while_indices_use_encoded_eew() {
        // vluxseg2ei8.v v4, (a0), v2 with SEW=32. The encoded EI8 controls
        // index decoding; each data field is still one SEW-wide (4-byte) word.
        let raw = memory_op(0x07, 1, 1, 1, 2, 10, 0, 4);
        let mut memory = vec![0u8; 16];
        memory[0..4].copy_from_slice(&0x1122_3344u32.to_le_bytes());
        memory[4..8].copy_from_slice(&0x5566_7788u32.to_le_bytes());
        let mut hart = cpu(FlatMemory::with_data(0x100, memory), 1, 0x10); // e32,m1
        hart.set_x(10, 0x100);
        hart.set_vreg(2, &[0; 16]); // byte offset zero

        assert_eq!(execute(&mut hart, raw), Ok(RiscVExit::Continue));
        assert_eq!(&hart.vreg(4)[..4], &0x1122_3344u32.to_le_bytes());
        assert_eq!(&hart.vreg(5)[..4], &0x5566_7788u32.to_le_bytes());
    }

    #[test]
    fn segment_fault_only_first_traps_at_zero_and_trims_later_faults() {
        let raw = memory_op(0x07, 1, 1, 0, 0b10000, 10, 0, 1);

        let mut later = cpu(FlatMemory::with_data(0x100, vec![0x10, 0x20, 0x30]), 3, 0);
        later.set_x(10, 0x100);
        later.set_vreg(1, &[0xaa; 16]);
        later.set_vreg(2, &[0xbb; 16]);
        assert_eq!(execute(&mut later, raw), Ok(RiscVExit::Continue));
        assert_eq!(later.vl(), 1);
        assert_eq!(later.vstart(), 0);
        assert_eq!(later.vreg(1)[0], 0x10);
        assert_eq!(later.vreg(2)[0], 0x20);
        assert_eq!(later.vreg(1)[1], 0x30); // partial faulting segment is allowed

        let mut first = cpu(FlatMemory::with_data(0x100, vec![0x10]), 3, 0);
        first.set_x(10, 0x100);
        assert_eq!(execute(&mut first, raw), Err(acc_fault(false, 0x101)));
        assert_eq!(first.vl(), 3);
        assert_eq!(first.vstart(), 0);
    }

    #[test]
    fn mask_and_whole_register_fault_indices_use_their_effective_elements() {
        let mut mask_cpu = cpu(FlatMemory::with_data(0x100, vec![0; 2]), 24, 0);
        mask_cpu.set_x(10, 0x100);
        let mask_trap = execute(&mut mask_cpu, load(1, 0, 0b01011, 10, 0, 1)).unwrap_err();
        assert_eq!(mask_trap, acc_fault(false, 0x102));
        assert_eq!(mask_cpu.vstart(), 2);

        let mut whole_cpu = cpu(FlatMemory::with_data(0x100, vec![0; 10]), 0, 0);
        whole_cpu.set_x(10, 0x100);
        let whole_trap = execute(&mut whole_cpu, load(1, 0, 0b01000, 10, 6, 2)).unwrap_err();
        assert_eq!(whole_trap, acc_fault(false, 0x108));
        assert_eq!(whole_cpu.vstart(), 2);
    }
}
