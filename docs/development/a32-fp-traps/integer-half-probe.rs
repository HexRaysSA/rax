//! Public state API probe: exact-tiny and rounded-to-zero integer-to-half conversion.
use rax::isa::arm::aarch64::{AArch64Config, AArch64Cpu};
use rax::isa::arm::common::{
    cpu::{ArmCpu, ArmError, CpuExit},
    memory::FlatMemory,
    sysreg::Aarch64SysRegEncoding,
};
fn main() {
    let mut count = 0;
    for (word, expected) in [(0x9ec2b020u32, 0x10u128), (0x9ec20020, 0)] {
        for enabled in [false, true] {
            for flush in [false, true] {
                let mut config = AArch64Config::v8_2();
                config.initial_el = 1;
                config.gic_config = None;
                let mut cpu = AArch64Cpu::new(config, Box::new(FlatMemory::new(0, 0x4000)));
                let mut state = cpu.export_sregs();
                let sys = &mut state.execution.as_mut().unwrap().sysregs;
                sys.scr_el3 = 0x501;
                sys.hcr_el2 = 1 << 31;
                sys.el1.cpacr = 3 << 20;
                sys.impl_defined.insert(
                    Aarch64SysRegEncoding::new(3, 0, 0, 3, 0).encode(),
                    0x10111222,
                );
                cpu.import_sregs(&state).unwrap();
                cpu.set_fpcr_value(u32::from(enabled) << 11 | u32::from(flush) << 19);
                cpu.set_pc(0x100);
                cpu.set_x(1, 1);
                cpu.set_simd(0, 0xdeadbeef);
                cpu.write_memory(0x100, &word.to_le_bytes()).unwrap();
                let result = cpu.step();
                let untrapped = if word == 0x9ec20020 && !flush {
                    0x18
                } else if flush {
                    8
                } else {
                    0
                };
                if enabled && !flush {
                    assert!(
                        matches!(
                            result,
                            Err(ArmError::ArchitecturalException {
                                ec: 0x2c,
                                iss: 0x800008,
                                ..
                            })
                        ),
                        "{word:08x} {result:?}"
                    );
                    assert_eq!(cpu.get_simd(0), 0xdeadbeef);
                    assert_eq!(cpu.fpsr_value(), untrapped & !8);
                    assert_eq!(cpu.get_pc(), 0x100);
                } else {
                    assert_eq!(result.unwrap(), CpuExit::Continue);
                    assert_eq!(cpu.get_simd(0), if flush { 0 } else { expected });
                    assert_eq!(cpu.fpsr_value(), untrapped);
                }
                count += 1;
            }
        }
    }
    println!("{count} integer-to-half public-state cases passed");
}
