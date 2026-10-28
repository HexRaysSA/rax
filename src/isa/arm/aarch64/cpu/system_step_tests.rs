//! Prove one interpreted step bypasses a runnable cache without disabling it.
use super::*;
use crate::isa::arm::common::memory::FlatMemory;
#[test]
fn interpreted_step_preserves_cached_region_and_unbounded_native_execution() {
    const ENTRY: u64 = 0x1000;
    let mut cpu = AArch64Cpu::new(
        AArch64Config::default(),
        Box::new(FlatMemory::new(0, 0x4000)),
    );
    let code = [
        0x91000400u32,
        0x91000421,
        0xf13ffc1f,
        0x54ffffa3,
        0xd4200000,
    ]
    .into_iter()
    .flat_map(u32::to_le_bytes)
    .collect::<Vec<_>>();
    cpu.write_memory(ENTRY, &code).unwrap();
    cpu.set_pc(ENTRY);
    cpu.current_el = 1;
    cpu.sp_sel = true;
    #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
    let (key, region, disabled) = {
        let region = std::sync::Arc::new(cpu.jit_compile_region().expect("runnable loop region"));
        let key = (ENTRY, cpu.jit_mode_tag());
        cpu.jit.cache.insert(key, Some(region.clone()));
        assert!(cpu.jit_lookup(ENTRY).is_some());
        (key, region, cpu.execution.disabled)
    };
    assert!(matches!(
        cpu.step_system_interpreted(true).unwrap(),
        CpuExit::Continue
    ));
    assert_eq!(
        (
            cpu.get_pc(),
            cpu.get_x(0),
            cpu.get_x(1),
            cpu.instruction_count()
        ),
        (ENTRY + 4, 1, 0, 1)
    );
    #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
    {
        assert_eq!(cpu.execution.disabled, disabled);
        let cached = cpu.jit.cache.get(&key).unwrap().as_ref().unwrap();
        assert!(std::sync::Arc::ptr_eq(cached, &region));
        cpu.set_pc(ENTRY);
        cpu.set_x(0, 0);
        cpu.set_x(1, 0);
        assert!(cpu.jit_lookup(ENTRY).is_some());
        assert!(matches!(cpu.step_system().unwrap(), CpuExit::Continue));
        assert_eq!(
            (cpu.get_pc(), cpu.get_x(0), cpu.get_x(1)),
            (ENTRY + 16, 4095, 4095)
        );
    }
}
