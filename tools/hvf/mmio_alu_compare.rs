//! Compare actual read-ALU planning and complete publication with QEMU records.
use rax::{devices, isa};
use std::collections::BTreeMap;
#[path = "../../src/isa/x86_64/inspection.rs"]
mod guest_translation;
#[path = "../../src/backend/hvf/mmio.rs"]
mod mmio;

struct Memory(BTreeMap<u64, u8>);
impl Memory {
    fn put(&mut self, address: u64, data: &[u8]) {
        for (i, &byte) in data.iter().enumerate() {
            self.0.insert(address + i as u64, byte);
        }
    }
}
impl guest_translation::PhysicalMemory for Memory {
    fn contains_ram(&self, address: u64, size: usize) -> bool {
        (0..size).all(|i| self.0.contains_key(&(address + i as u64)))
    }
    fn read_physical(&mut self, address: u64, data: &mut [u8]) -> Result<(), String> {
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = *self
                .0
                .get(&(address + i as u64))
                .ok_or("missing reference RAM")?;
        }
        Ok(())
    }
}
struct Host {
    registers: [u64; 16],
    flags: u64,
    pc: u64,
}
impl mmio::CompletionAccess for Host {
    type Error = String;
    fn write_gpr(&mut self, index: usize, value: u64) -> Result<(), String> {
        self.registers[index] = value;
        Ok(())
    }
    fn write_rflags(&mut self, flags: u64) -> Result<(), String> {
        self.flags = flags;
        Ok(())
    }
    fn finish_instruction(&mut self, length: u64) -> Result<(), String> {
        mmio::retire(self, length)
    }
}
impl mmio::RetirementAccess for Host {
    type Error = String;
    fn rflags(&mut self) -> Result<u64, String> {
        Ok(self.flags)
    }
    fn advance_instruction(&mut self, length: u64) -> Result<(), String> {
        self.pc = self.pc.wrapping_add(length);
        Ok(())
    }
    fn write_rflags(&mut self, flags: u64) -> Result<(), String> {
        self.flags = flags;
        Ok(())
    }
}
fn quad(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}
fn word(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

pub fn compare(cases: &[u8], records: &[u8]) -> (usize, usize) {
    assert!(!cases.is_empty() && cases.len() % 168 == 0);
    let count = cases.len() / 168;
    assert_eq!(records.len(), 20 + count * 152);
    assert_eq!(&records[..8], b"RAXAL001");
    assert_eq!(word(records, 8) as usize, count);
    assert_eq!(&records[records.len() - 8..], b"AL_DONE!");
    let mut mismatches = 0;
    for (index, case) in cases.chunks_exact(168).enumerate() {
        let length = word(case, 144) as usize;
        assert!((1..=15).contains(&length));
        let code = &case[148..148 + length];
        let registers = std::array::from_fn(|i| quad(case, i * 8));
        let flags = quad(case, 136);
        let reference = &records[12 + index * 152..12 + (index + 1) * 152];
        let actual: [u64; 16] = std::array::from_fn(|i| quad(reference, i * 8));
        assert_eq!(
            quad(reference, 128),
            quad(case, 128),
            "reference mutated read-only memory,case{index}"
        );
        assert_eq!(
            quad(reference, 136),
            flags,
            "reference entry flags,case{index}"
        );
        let context = mmio::Context {
            registers,
            segments: [0; 6],
            code_bits: 64,
            rip: 0x300000,
            // EPT exits save RF1; successful emulated retirement must clear it.
            rflags: flags | (1 << 16),
            paging: guest_translation::Paging {
                cr0: (1 << 31) | 1,
                cr3: 0x1000,
                cr4: 1 << 5,
                efer: (1 << 10) | (1 << 8),
                physical_bits: 40,
                pdpte: [0; 4],
            },
        };
        let mut memory = Memory(BTreeMap::new());
        for (address, value) in [
            (0x1000, 0x2003u64),
            (0x2000, 0x3003),
            (0x3000, 0x83),
            (0x3008, 0x200083),
        ] {
            memory.put(address, &value.to_le_bytes());
        }
        memory.put(context.rip, code);
        let plan = mmio::prepare(
            &context,
            &mut memory,
            mmio::ExitRecord {
                qualification: 0x181,
                linear: 0x200000,
                physical: 0x200000,
                vectoring_information: 0,
            },
        )
        .unwrap_or_else(|error| panic!("case{index},code{code:02x?}: {error}"));
        assert_eq!((plan.physical, plan.length), (0x200000, length as u64));
        let mmio::Action::AluRead(input) = plan.action else {
            panic!("not an ALU read,case{index}")
        };
        let size = usize::from(input.size);
        let mut state = mmio::InputState::default();
        state.begin_alu_read(input).unwrap();
        let mut host = Host {
            registers,
            flags: context.rflags,
            pc: context.rip,
        };
        state.complete(&mut host, &case[128..128 + size]);
        assert!(state.ready().is_ok(), "case{index}: completion failed");
        let mask = u64::from(word(case, 164)) | 0xffffffff00000000;
        if host.registers != actual
            || (host.flags ^ quad(reference, 144)) & mask != 0
            || host.pc != context.rip + length as u64
        {
            mismatches += 1;
            if mismatches <= 12 {
                eprintln!(
                    "case{index},code{code:02x?}:flags={:#x}/{:#x},mask={mask:#x},registers={:?}",
                    host.flags,
                    quad(reference, 144),
                    (0..16)
                        .filter(|&i| host.registers[i] != actual[i])
                        .map(|i| (i, host.registers[i], actual[i]))
                        .collect::<Vec<_>>()
                );
            }
        }
    }
    (count, mismatches)
}

#[cfg(not(test))]
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 3);
    let (count, mismatches) = compare(
        &std::fs::read(&args[1]).unwrap(),
        &std::fs::read(&args[2]).unwrap(),
    );
    println!("{{\"cases\":{count},\"mismatches\":{mismatches}}}");
    if mismatches != 0 {
        std::process::exit(1);
    }
}
