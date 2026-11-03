//! A-extension and Zacas execution, including architectural fault classification.

use super::*;

impl RiscVCpu {
    // ---------------------------------------------------------------
    // A-extension.
    // ---------------------------------------------------------------

    pub(super) fn exec_lrsc(&mut self, insn: &Insn) -> Result<(), Trap> {
        let addr = self.x(insn.rs1) & self.xmask();
        let is_d = matches!(insn.op, Op::LrD | Op::ScD);
        let size = if is_d { 8 } else { 4 };
        if addr % size as u64 != 0 {
            let c = if matches!(insn.op, Op::ScW | Op::ScD) {
                cause::STORE_MISALIGNED
            } else {
                cause::LOAD_MISALIGNED
            };
            return Err(Trap {
                cause: c,
                tval: addr,
            });
        }
        match insn.op {
            Op::LrW => {
                let mut bytes = [0; 4];
                self.mem
                    .load_reserved(addr, &mut bytes)
                    .map_err(|_| acc_fault(false, addr))?;
                let v = u32::from_le_bytes(bytes);
                self.reservation = Some(addr);
                self.set_x(insn.rd, v as i32 as i64 as u64);
            }
            Op::LrD => {
                let mut bytes = [0; 8];
                self.mem
                    .load_reserved(addr, &mut bytes)
                    .map_err(|_| acc_fault(false, addr))?;
                let v = u64::from_le_bytes(bytes);
                self.reservation = Some(addr);
                self.set_x(insn.rd, v);
            }
            Op::ScW | Op::ScD => {
                let eligible = self.reservation.take() == Some(addr);
                let data = self.x(insn.rs2).to_le_bytes();
                let ok = self
                    .mem
                    .store_conditional(addr, &data[..size], eligible)
                    .map_err(|_| acc_fault(true, addr))?;
                self.set_x(insn.rd, if ok { 0 } else { 1 });
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    // An AMO read is part of a store/AMO access for architectural traps.
    // RISC-V Privileged Architecture 1.13, Machine Cause table.
    pub(super) fn exec_amo(&mut self, insn: &Insn) -> Result<(), Trap> {
        let addr = self.x(insn.rs1) & self.xmask();
        let src = self.x(insn.rs2);
        let is_d = matches!(
            insn.op,
            Op::AmoswapD
                | Op::AmoaddD
                | Op::AmoxorD
                | Op::AmoandD
                | Op::AmoorD
                | Op::AmominD
                | Op::AmomaxD
                | Op::AmominuD
                | Op::AmomaxuD
        );
        let size: u64 = if is_d { 8 } else { 4 };
        if addr % size != 0 {
            return Err(Trap {
                cause: cause::STORE_MISALIGNED,
                tval: addr,
            });
        }
        if is_d {
            let old = self.mem.read_u64(addr).map_err(|_| acc_fault(true, addr))?;
            let new = amo_compute64(insn.op, old, src);
            self.mem
                .write_u64(addr, new)
                .map_err(|_| acc_fault(true, addr))?;
            self.set_x(insn.rd, old);
        } else {
            let old = self.mem.read_u32(addr).map_err(|_| acc_fault(true, addr))?;
            let new = amo_compute32(insn.op, old, src as u32);
            self.mem
                .write_u32(addr, new)
                .map_err(|_| acc_fault(true, addr))?;
            self.set_x(insn.rd, old as i32 as i64 as u64);
        }
        Ok(())
    }

    pub(super) fn exec_amocas(&mut self, insn: &Insn) -> Result<(), Trap> {
        let addr = self.x(insn.rs1) & self.xmask();
        match insn.op {
            Op::AmocasW => {
                if addr % 4 != 0 {
                    return Err(Trap {
                        cause: cause::STORE_MISALIGNED,
                        tval: addr,
                    });
                }
                let old = self.mem.read_u32(addr).map_err(|_| acc_fault(true, addr))?;
                if old == self.x(insn.rd) as u32 {
                    self.mem
                        .write_u32(addr, self.x(insn.rs2) as u32)
                        .map_err(|_| acc_fault(true, addr))?;
                }
                self.set_x(insn.rd, old as i32 as i64 as u64);
            }
            Op::AmocasD => {
                if addr % 8 != 0 {
                    return Err(Trap {
                        cause: cause::STORE_MISALIGNED,
                        tval: addr,
                    });
                }
                let old = self.mem.read_u64(addr).map_err(|_| acc_fault(true, addr))?;
                if old == self.x(insn.rd) {
                    self.mem
                        .write_u64(addr, self.x(insn.rs2))
                        .map_err(|_| acc_fault(true, addr))?;
                }
                self.set_x(insn.rd, old);
            }
            Op::AmocasQ => {
                if addr % 16 != 0 {
                    return Err(Trap {
                        cause: cause::STORE_MISALIGNED,
                        tval: addr,
                    });
                }
                let cmp = if insn.rd == 0 {
                    0
                } else {
                    (self.x(insn.rd) as u128) | ((self.x(insn.rd.wrapping_add(1)) as u128) << 64)
                };
                let new = if insn.rs2 == 0 {
                    0
                } else {
                    (self.x(insn.rs2) as u128) | ((self.x(insn.rs2.wrapping_add(1)) as u128) << 64)
                };
                let mut old_bytes = [0u8; 16];
                self.mem
                    .read(addr, &mut old_bytes)
                    .map_err(|_| acc_fault(true, addr))?;
                let old = u128::from_le_bytes(old_bytes);
                if old == cmp {
                    self.mem
                        .write(addr, &new.to_le_bytes())
                        .map_err(|_| acc_fault(true, addr))?;
                }
                if insn.rd != 0 {
                    self.set_x(insn.rd, old as u64);
                    self.set_x(insn.rd.wrapping_add(1), (old >> 64) as u64);
                }
            }
            _ => unreachable!(),
        }
        Ok(())
    }
}

fn amo_compute32(op: Op, old: u32, src: u32) -> u32 {
    match op {
        Op::AmoswapW => src,
        Op::AmoaddW => old.wrapping_add(src),
        Op::AmoxorW => old ^ src,
        Op::AmoandW => old & src,
        Op::AmoorW => old | src,
        Op::AmominW => (old as i32).min(src as i32) as u32,
        Op::AmomaxW => (old as i32).max(src as i32) as u32,
        Op::AmominuW => old.min(src),
        Op::AmomaxuW => old.max(src),
        _ => unreachable!(),
    }
}

fn amo_compute64(op: Op, old: u64, src: u64) -> u64 {
    match op {
        Op::AmoswapD => src,
        Op::AmoaddD => old.wrapping_add(src),
        Op::AmoxorD => old ^ src,
        Op::AmoandD => old & src,
        Op::AmoorD => old | src,
        Op::AmominD => (old as i64).min(src as i64) as u64,
        Op::AmomaxD => (old as i64).max(src as i64) as u64,
        Op::AmominuD => old.min(src),
        Op::AmomaxuD => old.max(src),
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests;
