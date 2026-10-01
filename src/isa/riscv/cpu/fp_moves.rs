//! Bit-preserving moves between scalar floating-point and integer registers.

use super::*;

impl RiscVCpu {
    pub(super) fn exec_fp_move(&mut self, insn: &Insn) {
        match insn.op {
            Op::FmvXW => self.set_x(insn.rd, self.f(insn.rs1) as u32 as i32 as i64 as u64),
            Op::FmvWX => self.wf32(insn.rd, self.x(insn.rs1) as u32),
            Op::FmvXD => self.set_x(insn.rd, self.f(insn.rs1)),
            Op::FmvDX => self.wf64(insn.rd, self.x(insn.rs1)),
            Op::FmvhXD => self.set_x(insn.rd, self.f(insn.rs1) >> 32),
            Op::FmvpDX => {
                let low = self.x(insn.rs1) as u32 as u64;
                let high = (self.x(insn.rs2) as u32 as u64) << 32;
                self.wf64(insn.rd, high | low);
            }
            Op::FmvXH => self.set_x(insn.rd, self.f(insn.rs1) as u16 as i16 as i64 as u64),
            Op::FmvHX => self.wf16(insn.rd, self.x(insn.rs1) as u16),
            _ => unreachable!("non-move operation passed to exec_fp_move"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::riscv::{FlatMemory, Isa, RiscVConfig, Xlen, decode};

    fn enc(funct7: u32, rs2: u32, rs1: u32, rd: u32) -> u32 {
        (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (rd << 7) | 0x53
    }

    #[test]
    fn rv32_zfa_doubleword_moves_preserve_both_halves() {
        let isa = Isa::rv64gc();
        let mut hart = RiscVCpu::new(RiscVConfig::rv32(isa), Box::new(FlatMemory::new(0, 0x1000)));
        hart.csr_write(0x300, 0b01 << 13).unwrap(); // mstatus.FS=Initial

        hart.set_f(10, 0x89ab_cdef_0123_4567);
        let high = decode(enc(0b1110001, 1, 10, 11), Xlen::Rv32, &isa);
        assert_eq!(hart.execute_insn(&high, 0x100), Ok(RiscVExit::Continue));
        assert_eq!(hart.x(11), 0x89ab_cdef);

        hart.set_x(11, 0x7654_3210);
        hart.set_x(12, 0xfedc_ba98);
        let pack = decode(enc(0b1011001, 12, 11, 10), Xlen::Rv32, &isa);
        assert_eq!(hart.execute_insn(&pack, 0x104), Ok(RiscVExit::Continue));
        assert_eq!(hart.f(10), 0xfedc_ba98_7654_3210);
        assert_eq!(hart.fcsr(), 0);
    }
}
