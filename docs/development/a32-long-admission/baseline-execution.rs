use rax::isa::arm::aarch32::{cp15::Cpacr, cpu::ProcessorMode};
use rax::isa::arm::decoder::{Aarch32Decoder, ThumbDecoder};
use rax::isa::arm::execution::FlatMemory;
use rax::isa::arm::{Armv7Cpu, Executor};
fn main() {
    for (family, base) in [
        ("poly", 0xf280_0e00u32),
        ("qdmlal16", 0xf290_0900),
        ("qdmlsl16", 0xf290_0b00),
        ("qdmull16", 0xf290_0d00),
        ("qdmlal32", 0xf2a0_0900),
        ("qdmlsl32", 0xf2a0_0b00),
        ("qdmull32", 0xf2a0_0d00),
    ] {
        for thumb in [false, true] {
            for u in [0u32, 1] {
                for denial in 0..3 {
                    let raw = base | (u << 24);
                    let encoded = if thumb {
                        (raw & 0x00ff_ffff) | 0xef00_0000 | (u << 28)
                    } else {
                        raw
                    };
                    let instruction = if thumb {
                        ThumbDecoder::decode_32bit(encoded).unwrap()
                    } else {
                        Aarch32Decoder::decode(encoded).unwrap()
                    };
                    let mut cpu = Armv7Cpu::new();
                    cpu.cpsr.t = thumb;
                    cpu.regs[15] = 0x800;
                    cpu.cp15.cpacr = Cpacr::from_bits(0x00f0_0000);
                    cpu.vfp.fpexc = 1 << 30;
                    for (i, v) in cpu.vfp.dregs.iter_mut().enumerate() {
                        *v = 0x0706_0504_0302_0100 ^ (i as u64 * 0x0101_0101_0101_0101);
                    }
                    if denial == 1 {
                        cpu.cp15.cpacr = Cpacr::from_bits(0);
                        cpu.vfp.fpexc = 0;
                    }
                    if denial == 2 {
                        cpu.cpsr.mode = ProcessorMode::Hyp as u8;
                        cpu.cp15.scr = 1;
                        cpu.cp15.nsacr = 1 << 10;
                        cpu.cp15.hcptr = 1 << 10;
                    }
                    let before = cpu.vfp.dregs;
                    let mut memory = FlatMemory::new(4096, 0);
                    let result = Executor::new(&mut cpu, &mut memory).execute(&instruction);
                    println!(
                        "family={family} thumb={thumb} u={u} denial={denial} raw={encoded:08x} mnemonic={:?} result={result:?} registers_changed={}",
                        instruction.mnemonic,
                        before != cpu.vfp.dregs
                    );
                }
            }
        }
    }
}
