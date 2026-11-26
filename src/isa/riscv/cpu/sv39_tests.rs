use super::*;
use crate::isa::riscv::csr::SATP;
use crate::isa::riscv::{FlatMemory, memory::MemResult};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

const ROOT: u64 = 0x1000;
const MID: u64 = 0x2000;
const TABLE: u64 = 0x3000;
const FIRST_FRAME: u64 = 0x5000;
const SECOND_FRAME: u64 = 0x8000;
const FIRST_PAGE: u64 = 0x4000_0000;
const SECOND_PAGE: u64 = 0x4000_1000;
const SV39: u64 = (8 << 60) | (ROOT >> 12);

#[derive(Debug)]
struct Sv39Memory {
    ram: FlatMemory,
    pte_reads: Arc<AtomicUsize>,
}

impl Memory for Sv39Memory {
    fn supports_sv39(&self) -> bool {
        true
    }

    fn read(&self, address: u64, bytes: &mut [u8]) -> MemResult<()> {
        self.ram.read(address, bytes)
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> MemResult<()> {
        self.ram.write(address, bytes)
    }

    fn read_page_table_entry(&self, address: u64) -> MemResult<u64> {
        self.pte_reads.fetch_add(1, Ordering::Relaxed);
        self.ram.read_u64(address)
    }
}

fn cpu() -> RiscVCpu {
    counted_cpu().0
}

fn counted_cpu() -> (RiscVCpu, Arc<AtomicUsize>) {
    let pte_reads = Arc::new(AtomicUsize::new(0));
    let mut cpu = RiscVCpu::new(
        RiscVConfig::rv64gc(),
        Box::new(Sv39Memory {
            ram: FlatMemory::new(0, 0xa000),
            pte_reads: Arc::clone(&pte_reads),
        }),
    );
    cpu.memory_mut()
        .write_u64(ROOT + 8, (MID >> 2) | 1)
        .unwrap();
    cpu.memory_mut().write_u64(MID, (TABLE >> 2) | 1).unwrap();
    cpu.csr_write(SATP, SV39).unwrap();
    cpu.set_privilege(Priv::Supervisor);
    (cpu, pte_reads)
}

#[test]
fn same_page_parcels_walk_once_and_next_instruction_rechecks_the_mapping() {
    let (mut cpu, pte_reads) = counted_cpu();
    let offset = 0x126;
    let pc = FIRST_PAGE + offset;
    for (frame, value) in [(FIRST_FRAME, 1), (SECOND_FRAME, 2)] {
        cpu.memory_mut()
            .write_u64(TABLE, (frame >> 2) | 0x49) // Valid, executable, accessed.
            .unwrap();
        cpu.memory_mut()
            .write_u32(frame + offset, (value << 20) | 0x93) // ADDI x1, x0, value.
            .unwrap();
        pte_reads.store(0, Ordering::Relaxed);
        cpu.set_pc(pc);
        assert_eq!(cpu.step(), RiscVExit::Continue);
        assert_eq!(cpu.x(1), u64::from(value));
        assert_eq!(cpu.pc(), pc + 4);
        assert_eq!(pte_reads.load(Ordering::Relaxed), 3);
    }
}

#[test]
fn satp_mode_changes_preserve_or_clear_the_page_table_as_defined() {
    let mut cpu = cpu();
    let asid = 0xa519 << 44;
    cpu.csr_write(SATP, SV39 | asid).unwrap();
    assert_eq!(cpu.csr_read(SATP), Ok(SV39 | asid));
    cpu.csr_write(SATP, 9 << 60).unwrap();
    assert_eq!(cpu.csr_read(SATP), Ok(SV39 | asid));
    cpu.csr_write(SATP, u32::MAX.into()).unwrap();
    assert_eq!(cpu.csr_read(SATP), Ok(0));
    cpu.csr_write(SATP, SV39).unwrap();
    cpu.reset(0);
    assert_eq!(cpu.csr_read(SATP), Ok(0));
}

#[test]
fn cross_page_load_reports_the_inaccessible_part_and_no_destination_write() {
    let mut cpu = cpu();
    let address = SECOND_PAGE - 4;
    cpu.memory_mut()
        .write_u64(TABLE, (FIRST_FRAME >> 2) | 7)
        .unwrap();
    cpu.memory_mut()
        .write_u32(FIRST_FRAME + 0xffc, 0x7654_3210)
        .unwrap();
    cpu.set_x(5, 0x5555);
    assert_eq!(
        cpu.load(5, address, 0, 8, false),
        Err(Trap {
            cause: cause::LOAD_PAGE_FAULT,
            tval: SECOND_PAGE
        })
    );
    assert_eq!(cpu.x(5), 0x5555);
    cpu.memory_mut()
        .write_u64(TABLE + 8, (SECOND_FRAME >> 2) | 7)
        .unwrap();
    cpu.memory_mut()
        .write_u32(SECOND_FRAME, 0xfedc_ba98)
        .unwrap();
    cpu.load(5, address, 0, 8, false).unwrap();
    assert_eq!(cpu.x(5), 0xfedc_ba98_7654_3210);
    assert_eq!(cpu.memory().read_u64(TABLE).unwrap() & 0xc0, 0x40);
    assert_eq!(cpu.memory().read_u64(TABLE + 8).unwrap() & 0xc0, 0x40);
}

#[test]
fn diagnostic_fetch_is_read_only_and_split_fetch_sets_each_accessed_bit() {
    let mut cpu = cpu();
    cpu.memory_mut()
        .write_u64(TABLE, (FIRST_FRAME >> 2) | 9)
        .unwrap();
    cpu.memory_mut()
        .write_u64(TABLE + 8, (SECOND_FRAME >> 2) | 9)
        .unwrap();
    cpu.memory_mut()
        .write_u16(FIRST_FRAME + 0xffe, 0x0093)
        .unwrap();
    cpu.memory_mut().write_u16(SECOND_FRAME, 0x0010).unwrap();
    cpu.set_pc(SECOND_PAGE - 2);
    assert_eq!(cpu.inspect_instruction(cpu.pc()).unwrap().op, Op::Addi);
    assert_eq!(cpu.memory().read_u64(TABLE).unwrap() & 0xc0, 0);
    assert_eq!(cpu.memory().read_u64(TABLE + 8).unwrap() & 0xc0, 0);
    assert_eq!(cpu.step(), RiscVExit::Continue);
    assert_eq!(cpu.x(1), 1);
    assert_eq!(cpu.pc(), SECOND_PAGE + 2);
    assert_eq!(cpu.memory().read_u64(TABLE).unwrap() & 0xc0, 0x40);
    assert_eq!(cpu.memory().read_u64(TABLE + 8).unwrap() & 0xc0, 0x40);
}

#[test]
fn machine_fetch_and_mprv_user_data_use_distinct_privileges() {
    let mut cpu = cpu();
    cpu.memory_mut()
        .write_u64(TABLE, (FIRST_FRAME >> 2) | 0x19)
        .unwrap();
    cpu.memory_mut().write_u64(FIRST_FRAME, 0x1234).unwrap();
    cpu.memory_mut().write_u32(0, 0x0003_3283).unwrap(); // LD x5, 0(x6)
    cpu.set_x(6, FIRST_PAGE);
    cpu.set_privilege(Priv::Machine);
    cpu.csr_write(Csr::Mstatus as u16, (1 << 17) | (1 << 19))
        .unwrap();
    cpu.set_pc(0);
    assert_eq!(cpu.step(), RiscVExit::Continue);
    assert_eq!(cpu.x(5), 0x1234);
    assert_eq!(cpu.memory().read_u64(TABLE).unwrap() & 0xc0, 0x40);
}
