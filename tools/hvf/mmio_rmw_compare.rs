//! Compare actual RMW planner/completion source with independent guest records.
use rax::{devices, isa};
use std::collections::BTreeMap;

#[path = "../../src/backend/hvf/guest_translation.rs"]
mod guest_translation;
#[path = "../../src/backend/hvf/mmio.rs"]
mod mmio;

struct Memory(BTreeMap<u64, u8>);
impl Memory {
    fn put(&mut self, address: u64, bytes: &[u8]) {
        for (offset, byte) in bytes.iter().enumerate() {
            self.0.insert(address + offset as u64, *byte);
        }
    }
}
impl guest_translation::PhysicalMemory for Memory {
    fn contains_ram(&self, address: u64, size: usize) -> bool {
        (0..size).all(|offset| self.0.contains_key(&(address + offset as u64)))
    }
    fn read_physical(&mut self, address: u64, data: &mut [u8]) -> Result<(), String> {
        for (offset, byte) in data.iter_mut().enumerate() {
            *byte = *self
                .0
                .get(&(address + offset as u64))
                .ok_or("missing RAM backing")?;
        }
        Ok(())
    }
}
fn quad(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

pub fn compare(cases: &[u8], records: &[u8]) -> (usize, usize) {
    assert!(!cases.is_empty() && cases.len() % 172 == 0);
    let count = cases.len() / 172;
    assert_eq!(records.len(), 20 + count * 168);
    assert_eq!(&records[..8], b"RAXRM001");
    assert_eq!(word(&records, 8) as usize, count);
    assert_eq!(&records[records.len() - 8..], b"RM_DONE!");
    let mut mismatches = 0;
    for (index, case) in cases.chunks_exact(172).enumerate() {
        let length = word(case, 144) as usize;
        assert!((1..=15).contains(&length));
        let registers: [u64; 16] = std::array::from_fn(|i| quad(case, i * 8));
        let flags = quad(case, 136);
        let code = &case[148..148 + length];
        let delta = i32::from_le_bytes(case[164..168].try_into().unwrap());
        let address = 0x200000u64.wrapping_add(i64::from(delta) as u64);
        let record = &records[12 + index * 168..12 + (index + 1) * 168];
        let actual: [u64; 16] = std::array::from_fn(|i| quad(record, i * 8));
        assert_eq!(
            quad(record, 152),
            flags,
            "reference entry flags,case{index}"
        );
        let mask = u64::from(word(case, 168)) | 0xffff_ffff_0000_0000;
        for qualification in [0x182, 0x183] {
            let context = mmio::Context {
                registers,
                segments: [0; 6],
                code_bits: 64,
                rip: 0x300000,
                rflags: flags,
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
                    qualification,
                    linear: address,
                    physical: address,
                    vectoring_information: 0,
                },
            )
            .unwrap_or_else(|e| panic!("case{index},code{code:02x?}: {e}"));
            assert_eq!((plan.physical, plan.length), (address, length as u64));
            let mmio::Action::Rmw(input) = plan.action else {
                panic!("not RMW,case{index}")
            };
            let mut expected_memory = quad(case, 128).to_le_bytes().repeat(3);
            let old = expected_memory[8..8 + usize::from(input.size)].to_vec();
            input
                .operation
                .apply(&mut expected_memory[8..8 + usize::from(input.size)])
                .unwrap();
            let (register, updated_flags, _) = input.completion(&old).unwrap();
            let mut expected = registers;
            if let Some((register, value)) = register {
                expected[register] = value;
            }
            let updated_flags = updated_flags.unwrap_or(flags);
            if expected != actual
                || expected_memory != record[128..152]
                || (updated_flags ^ quad(record, 160)) & mask != 0
            {
                mismatches += 1;
                if mismatches <= 12 {
                    eprintln!(
                        "case{index},qual{qualification:#x},code{code:02x?}:regs{:?},memory={:02x?}/{:02x?},flags={updated_flags:#x}/{:#x},mask={mask:#x}",
                        (0..16)
                            .filter(|i| expected[*i] != actual[*i])
                            .map(|i| (i, expected[i], actual[i]))
                            .collect::<Vec<_>>(),
                        expected_memory,
                        &record[128..152],
                        quad(record, 160)
                    );
                }
            }
        }
    }
    (count, mismatches)
}

#[cfg(not(test))]
fn main() {
    let arguments: Vec<_> = std::env::args().collect();
    assert_eq!(arguments.len(), 3);
    let cases = std::fs::read(&arguments[1]).unwrap();
    let records = std::fs::read(&arguments[2]).unwrap();
    let (count, mismatches) = compare(&cases, &records);
    println!(
        "{{\"cases\":{count},\"plans\":{},\"mismatches\":{mismatches}}}",
        count * 2
    );
    if mismatches != 0 {
        std::process::exit(1);
    }
}
