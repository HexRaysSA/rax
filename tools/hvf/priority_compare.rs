//! Compare actual software guest instructions/controller aliases with QEMU.
//! Reserved-bit records remain retained primary-source cases in cr8_oracle.py;
//! this consumer compares all 272 independently recorded legal transfers.
use rax::devices::bus::MmioDevice;
use rax::devices::lapic::{LapicDevice, LocalApic};
use rax::isa::x86_64::X86_64Vcpu;
use rax::vm::memory::vm::{Bytes, GuestAddress, GuestMemoryMmap};
use rax::vm::vcpu::{CpuState, DescriptorTable, Segment, VCpu};
use std::sync::{Arc, Mutex};
fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 3);
    let cases = std::fs::read(&args[1]).unwrap();
    let records = std::fs::read(&args[2]).unwrap();
    assert_eq!(cases.len() % 16, 0);
    let n = cases.len() / 16;
    assert_eq!(&records[..8], b"RAXCR801");
    assert_eq!(word(&records, 8) as usize, n);
    assert_eq!(records.len(), 20 + n * 24);
    assert_eq!(&records[12 + n * 24..], b"CR8_DONE");
    let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
    // Real four-level paging: identity-map low code/data and the APIC page.
    for (address, value) in [
        (0x1000u64, 0x2003u64),
        (0x2000, 0x3003),
        (0x2018, 0x4003),
        (0x3000, 0x83),
        (0x4000 + ((0xfee0_0000u64 >> 21) & 511) * 8, 0xfee0_0083),
    ] {
        memory
            .write_slice(&value.to_le_bytes(), GuestAddress(address))
            .unwrap();
    }
    for (index, value) in [0u64, 0x00af9a000000ffff, 0x00cf92000000ffff]
        .into_iter()
        .enumerate()
    {
        memory
            .write_slice(
                &value.to_le_bytes(),
                GuestAddress(0x5000 + index as u64 * 8),
            )
            .unwrap();
    }
    let owner = Arc::new(Mutex::new(LocalApic::new(1)));
    let mut device = LapicDevice::new(owner.clone());
    let mut cpu = X86_64Vcpu::new(1, memory.clone());
    cpu.set_jit_enabled(false);
    cpu.attach_local_apic(owner);
    let mut compared = 0;
    let mut reserved = 0;
    let mut mismatches = 0;
    for (index, case) in cases.chunks_exact(16).enumerate() {
        let read = word(case, 0) == 1;
        let value = u64::from(word(case, 8)) | (u64::from(word(case, 12)) << 32);
        if !read && value > 15 {
            reserved += 1;
            continue;
        }
        let mut state = cpu.get_state().unwrap();
        let CpuState::X86_64(s) = &mut state else {
            panic!()
        };
        s.regs.rip = 0;
        s.regs.rax = value;
        s.regs.rbx = 0xfee0_0080;
        s.regs.rflags = 2;
        s.sregs.cr0 = 0x8005_0033;
        s.sregs.cr3 = 0x1000;
        s.sregs.cr4 = 1 << 5;
        s.sregs.efer = (1 << 8) | (1 << 10);
        s.sregs.cs = Segment {
            selector: 8,
            limit: u32::MAX,
            type_: 11,
            present: true,
            s: true,
            l: true,
            g: true,
            ..Default::default()
        };
        let data = Segment {
            selector: 16,
            limit: u32::MAX,
            type_: 3,
            present: true,
            s: true,
            db: true,
            g: true,
            ..Default::default()
        };
        s.sregs.ds = data.clone();
        s.sregs.es = data.clone();
        s.sregs.ss = data;
        s.sregs.gdt = DescriptorTable {
            base: 0x5000,
            limit: 23,
        };
        cpu.set_state(&state).unwrap();
        let mut code = vec![0xc7, 0x03];
        code.extend_from_slice(&(if read { value as u32 } else { 0xa7 }).to_le_bytes());
        if !read {
            code.extend_from_slice(&[0x44, 0x0f, 0x22, 0xc0]);
        }
        code.extend_from_slice(&[0x44, 0x0f, 0x20, 0xc0]);
        memory.write_slice(&code, GuestAddress(0)).unwrap();
        for _ in 0..if read { 2 } else { 3 } {
            assert!(cpu.step_insn().unwrap().is_none());
        }
        let CpuState::X86_64(s) = cpu.get_state().unwrap() else {
            panic!()
        };
        let mut tpr = [0; 4];
        device.read(0xfee0_0080, &mut tpr);
        let record = &records[12 + index * 24..12 + (index + 1) * 24];
        assert_eq!(word(record, 0), 0);
        assert_eq!(word(record, 4), 0);
        let expected = (
            u64::from(word(record, 8)) | (u64::from(word(record, 12)) << 32),
            word(record, 16),
        );
        let actual = (s.regs.rax, u32::from_le_bytes(tpr));
        compared += 1;
        if actual != expected || s.sregs.cr8 != actual.0 || s.regs.rip != code.len() as u64 {
            mismatches += 1;
            eprintln!("case {index}: actual={actual:?} expected={expected:?}");
        }
    }
    println!(
        "{{\"compared_legal\":{compared},\"retained_reserved_primary_cases\":{reserved},\"mismatches\":{mismatches}}}"
    );
    assert_eq!(compared, 272);
    assert_eq!(reserved, 63);
    assert_eq!(mismatches, 0);
}
