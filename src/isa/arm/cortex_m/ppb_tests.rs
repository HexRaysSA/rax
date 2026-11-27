//! The Private Peripheral Bus as memory: guest memory unless mapped, then
//! the NVIC, SCB and SysTick models, CPACR, the narrow accesses, ICTR and
//! DWT_CYCCNT.

use crate::isa::arm::common::memory::{ArmMemory, FlatMemory};
use crate::isa::arm::cortex_m::cpu::CortexMCpu;
use crate::isa::arm::cortex_m::exec::Fault;
use crate::isa::arm::cortex_m::scb::CortexMVariant;

const CODE: u32 = 0x100;

fn m7(code: &[u8]) -> CortexMCpu {
    let mut memory = FlatMemory::new(0, 0x1_0000);
    memory.write(u64::from(CODE), code).unwrap();
    let mut cpu = CortexMCpu::new(CortexMVariant::CortexM7, Box::new(memory));
    cpu.pc = CODE;
    cpu.sp_main = 0x8000;
    cpu
}

/// str r1, [r0] (6001) then ldr r2, [r0] (6802), on `address`.
fn store_load(cpu: &mut CortexMCpu, address: u32, value: u32) -> Result<u32, Fault> {
    cpu.memory
        .write(u64::from(CODE), &[0x01, 0x60, 0x02, 0x68])
        .unwrap();
    cpu.pc = CODE;
    cpu.set_r(0, address);
    cpu.set_r(1, value);
    cpu.execute_one()?;
    cpu.execute_one()?;
    Ok(cpu.r(2))
}

#[test]
fn unmapped_ppb_addresses_are_guest_memory() {
    let mut cpu = m7(&[]);
    assert!(matches!(
        store_load(&mut cpu, 0xE000_E100, 1),
        Err(Fault::Bus { .. })
    ));
    assert!(!cpu.nvic().is_enabled(0));
}

#[test]
fn mapped_ppb_reaches_the_nvic_scb_and_cpacr() {
    let mut cpu = m7(&[]);
    cpu.map_private_peripheral_bus(true);
    assert_eq!(store_load(&mut cpu, 0xE000_E100, 1 << 5).unwrap(), 1 << 5);
    assert!(cpu.nvic().is_enabled(5));
    store_load(&mut cpu, 0xE000_ED08, 0x0800_0000).unwrap();
    assert_eq!(cpu.scb().vtor(), 0x0800_0000);
    // ICTR: 240 lines, 8 blocks of 32
    assert_eq!(store_load(&mut cpu, 0xE000_E004, 0).unwrap(), 7);
    // CPACR keeps CP10 and CP11 only with the FPU
    assert_eq!(store_load(&mut cpu, 0xE000_ED88, u32::MAX).unwrap(), 0);
    cpu.set_floating_point(true);
    assert_eq!(
        store_load(&mut cpu, 0xE000_ED88, u32::MAX).unwrap(),
        0x00F0_0000
    );
}

#[test]
fn narrow_stores_keep_neighbouring_priorities_and_enables() {
    let mut cpu = m7(&[]);
    cpu.map_private_peripheral_bus(true);
    cpu.nvic_mut().enable(4);
    // strb r1, [r0] (7001): IPR bytes of IRQ 5 then 4
    cpu.memory
        .write(u64::from(CODE), &[0x01, 0x70, 0x01, 0x70])
        .unwrap();
    cpu.set_r(0, 0xE000_E405);
    cpu.set_r(1, 0x80);
    cpu.execute_one().unwrap();
    cpu.set_r(0, 0xE000_E404);
    cpu.set_r(1, 0x40);
    cpu.execute_one().unwrap();
    assert_eq!(cpu.nvic().get_priority(5), 0x80);
    assert_eq!(cpu.nvic().get_priority(4), 0x40);
    // a byte of ISER (IRQs 8..15) leaves IRQ 4 enabled
    cpu.memory.write(u64::from(CODE), &[0x01, 0x70]).unwrap();
    cpu.pc = CODE;
    cpu.set_r(0, 0xE000_E101);
    cpu.set_r(1, 1);
    cpu.execute_one().unwrap();
    assert!(cpu.nvic().is_enabled(8) && cpu.nvic().is_enabled(4));
}

#[test]
fn cyccnt_counts_only_when_enabled() {
    // nop (BF00) eight times
    let mut cpu = m7(&[0x00, 0xBF].repeat(8));
    cpu.map_private_peripheral_bus(true);
    for _ in 0..2 {
        cpu.execute_one().unwrap();
    }
    assert_eq!(cpu.ppb_load(0xE000_1004, 4), 0);
    // DEMCR.TRCENA, then DWT_CTRL.CYCCNTENA
    cpu.ppb_store(0xE000_EDFC, 4, 1 << 24);
    cpu.ppb_store(0xE000_1000, 4, 1);
    for _ in 0..3 {
        cpu.execute_one().unwrap();
    }
    assert_eq!(cpu.ppb_load(0xE000_1004, 4), 3);
    cpu.ppb_store(0xE000_1000, 4, 0);
    cpu.execute_one().unwrap();
    assert_eq!(cpu.ppb_load(0xE000_1004, 4), 3);
    // written while stopped, counts on from the value written
    cpu.ppb_store(0xE000_1004, 4, 100);
    cpu.ppb_store(0xE000_1000, 4, 1);
    cpu.execute_one().unwrap();
    assert_eq!(cpu.ppb_load(0xE000_1004, 4), 101);
}

#[test]
fn cache_identification_is_the_embedders_and_survives_reset() {
    use crate::isa::arm::common::cpu::ArmCpu;
    use crate::isa::arm::cortex_m::ppb::CacheIdentification;

    let mut cpu = m7(&[]);
    cpu.map_private_peripheral_bus(true);
    assert_eq!(cpu.ppb_load(0xE000_ED78, 4), 0);
    let caches = CacheIdentification {
        clidr: 0x0900_0003,
        ctr: 0x8303_C003,
        ccsidr_data: 0xF00F_E019,
        ccsidr_instruction: 0xF01F_E009,
    };
    cpu.set_cache_identification(caches);
    cpu.reset();
    assert_eq!(cpu.ppb_load(0xE000_ED78, 4), caches.clidr);
    assert_eq!(cpu.ppb_load(0xE000_ED80, 4), caches.ccsidr_data);
    cpu.ppb_store(0xE000_ED84, 4, 1);
    assert_eq!(cpu.ppb_load(0xE000_ED80, 4), caches.ccsidr_instruction);
}
