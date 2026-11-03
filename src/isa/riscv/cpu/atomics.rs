//! A-extension and Zacas execution, including architectural fault classification.

use super::*;
use crate::isa::riscv::memory::AtomicOp as MemoryAtomicOp;

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
        atomic_fence(insn, true);
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
        atomic_fence(insn, false);
        Ok(())
    }

    // RISC-V Privileged 1.13 Machine Cause: read-phase AMO failures are stores.
    pub(super) fn exec_amo(&mut self, insn: &Insn) -> Result<(), Trap> {
        let address = self.x(insn.rs1) & self.xmask();
        let size = match insn.op {
            Op::AmoswapD
            | Op::AmoaddD
            | Op::AmoxorD
            | Op::AmoandD
            | Op::AmoorD
            | Op::AmominD
            | Op::AmomaxD
            | Op::AmominuD
            | Op::AmomaxuD => 8,
            _ => 4,
        };
        if address & (u64::from(size) - 1) != 0 {
            return Err(Trap {
                cause: cause::STORE_MISALIGNED,
                tval: address,
            });
        }
        let operation = amo_operation(insn.op, self.x(insn.rs2));
        atomic_fence(insn, true);
        let old = self
            .mem
            .atomic(address, size, operation)
            .map_err(|_| acc_fault(true, address))?;
        atomic_fence(insn, false);
        self.set_x(
            insn.rd,
            if size == 4 {
                old as u32 as i32 as i64 as u64
            } else {
                old as u64
            },
        );
        Ok(())
    }

    pub(super) fn exec_amocas(&mut self, insn: &Insn) -> Result<(), Trap> {
        let address = self.x(insn.rs1) & self.xmask();
        let size = match insn.op {
            Op::AmocasW => 4,
            Op::AmocasD => 8,
            Op::AmocasQ => 16,
            _ => unreachable!(),
        };
        if address & (u64::from(size) - 1) != 0 {
            return Err(Trap {
                cause: cause::STORE_MISALIGNED,
                tval: address,
            });
        }
        let pair = insn.op == Op::AmocasQ || (insn.op == Op::AmocasD && self.rv32());
        let expected = self.cas_operand(insn.rd, pair);
        let replacement = self.cas_operand(insn.rs2, pair);
        atomic_fence(insn, true);
        let old = self
            .mem
            .atomic(
                address,
                size,
                MemoryAtomicOp::CompareExchange {
                    expected,
                    replacement,
                },
            )
            .map_err(|_| acc_fault(true, address))?;
        atomic_fence(insn, false);
        if pair {
            if insn.rd != 0 {
                self.set_x(insn.rd, old as u64);
                self.set_x(insn.rd + 1, (old >> self.cfg.xlen.bits()) as u64);
            }
        } else {
            self.set_x(
                insn.rd,
                if size == 4 {
                    old as u32 as i32 as i64 as u64
                } else {
                    old as u64
                },
            );
        }
        Ok(())
    }

    fn cas_operand(&self, register: u8, pair: bool) -> u128 {
        if pair && register == 0 {
            return 0;
        }
        let low = u128::from(self.x(register));
        if pair {
            low | (u128::from(self.x(register + 1)) << self.cfg.xlen.bits())
        } else {
            low
        }
    }
}

fn amo_operation(op: Op, source: u64) -> MemoryAtomicOp {
    match op {
        Op::AmoswapW | Op::AmoswapD => MemoryAtomicOp::Exchange(source),
        Op::AmoaddW | Op::AmoaddD => MemoryAtomicOp::Add(source),
        Op::AmoxorW | Op::AmoxorD => MemoryAtomicOp::Xor(source),
        Op::AmoandW | Op::AmoandD => MemoryAtomicOp::And(source),
        Op::AmoorW | Op::AmoorD => MemoryAtomicOp::Or(source),
        Op::AmominW | Op::AmominD => MemoryAtomicOp::SignedMin(source),
        Op::AmomaxW | Op::AmomaxD => MemoryAtomicOp::SignedMax(source),
        Op::AmominuW | Op::AmominuD => MemoryAtomicOp::UnsignedMin(source),
        Op::AmomaxuW | Op::AmomaxuD => MemoryAtomicOp::UnsignedMax(source),
        _ => unreachable!(),
    }
}

// A stronger host ordering is permitted by RVWMO; both bits retain SC ordering.
fn atomic_fence(insn: &Insn, before: bool) {
    use std::sync::atomic::{Ordering, fence};
    let acquire = insn.raw & (1 << 26) != 0;
    let release = insn.raw & (1 << 25) != 0;
    if acquire && release {
        fence(Ordering::SeqCst);
    } else if before && release {
        fence(Ordering::Release);
    } else if !before && acquire {
        fence(Ordering::Acquire);
    }
}

#[cfg(test)]
mod tests;
