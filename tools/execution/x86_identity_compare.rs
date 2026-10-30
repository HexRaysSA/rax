//! Compare actual software CPU identity/default state with independent QEMU records.
//! BSP writes use Intel's R/W rule; QEMU's preserved-bit differences stay visible.
use rax::devices::bus::MmioDevice;
use rax::devices::lapic::{LapicDevice, LocalApic};
use rax::isa::x86_64::X86_64Vcpu;
use rax::vm::memory::vm::{Bytes, GuestAddress, GuestMemoryMmap};
use rax::vm::vcpu::{CpuState, Segment, VCpu};
use std::sync::{Arc, Mutex};

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn execute(
    cpu: &mut X86_64Vcpu,
    memory: &GuestMemoryMmap,
    code: &[u8],
    leaf: u64,
    value: u64,
) -> u64 {
    memory.write_slice(code, GuestAddress(0)).unwrap();
    let mut state = cpu.get_state().unwrap();
    let CpuState::X86_64(s) = &mut state else {
        panic!()
    };
    s.regs.rip = 0;
    s.regs.rax = value & u64::from(u32::MAX);
    s.regs.rdx = value >> 32;
    s.regs.rcx = leaf;
    s.regs.rflags = 2;
    s.sregs.cr0 = 0x50033;
    s.sregs.cr4 = 0;
    s.sregs.efer = 0;
    s.sregs.cs = Segment {
        selector: 8,
        limit: u32::MAX,
        type_: 11,
        present: true,
        s: true,
        db: true,
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
    cpu.set_state(&state).unwrap();
    assert!(cpu.step_insn().unwrap().is_none());
    let regs = cpu.get_regs().unwrap();
    assert_eq!(regs.rip, code.len() as u64);
    (regs.rax & u64::from(u32::MAX)) | ((regs.rdx & u64::from(u32::MAX)) << 32)
}
fn main() {
    let directory = std::path::PathBuf::from(std::env::args_os().nth(1).unwrap());
    let mut observed = 0;
    let mut reference_write_differences = 0;
    for count in [1, 2, 4] {
        let raw = std::fs::read(directory.join(format!("records-{count}.bin"))).unwrap();
        assert_eq!(&raw[..8], b"RAXID001");
        assert_eq!(word(&raw, 8), count);
        assert_eq!(raw.len(), 20 + count as usize * 40);
        assert_eq!(&raw[raw.len() - 8..], b"ID_DONE!");
        for index in 0..count {
            let row = &raw[12 + index as usize * 40..12 + (index as usize + 1) * 40];
            let memory =
                Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 65536)]).unwrap());
            let owner = Arc::new(Mutex::new(LocalApic::new(index)));
            let mut device = LapicDevice::new(owner.clone());
            let mut cpu = X86_64Vcpu::new(index, memory.clone());
            cpu.set_jit_enabled(false);
            cpu.attach_local_apic(owner);
            execute(&mut cpu, &memory, &[0x0f, 0xa2], 0, 1);
            assert_eq!(cpu.get_regs().unwrap().rbx >> 24, u64::from(word(row, 0)));
            let mut apic_id = [0; 4];
            device.read(0xfee0_0020, &mut apic_id);
            assert_eq!(u32::from_le_bytes(apic_id) >> 24, word(row, 36));
            let initial = u64::from(word(row, 8)) | (u64::from(word(row, 12)) << 32);
            assert_eq!(execute(&mut cpu, &memory, &[0x0f, 0x32], 0x1b, 0), initial);
            execute(&mut cpu, &memory, &[0x0f, 0x30], 0x1b, initial ^ 256);
            let written = execute(&mut cpu, &memory, &[0x0f, 0x32], 0x1b, 0);
            assert_eq!(written, initial ^ 256, "Intel Table2-2 defines BSP as R/W");
            let reference_written = u64::from(word(row, 16)) | (u64::from(word(row, 20)) << 32);
            assert_eq!(word(row, 32), 0);
            assert!([initial, initial ^ 256].contains(&reference_written));
            reference_write_differences += usize::from(written != reference_written);
            execute(&mut cpu, &memory, &[0x0f, 0x30], 0x1b, initial);
            assert_eq!(
                execute(&mut cpu, &memory, &[0x0f, 0x32], 0x1b, 0),
                u64::from(word(row, 24)) | (u64::from(word(row, 28)) << 32)
            );
            observed += 1;
        }
    }
    assert_eq!(observed, 7);
    println!(
        "{{\"cpu_observations\":{observed},\"independent_identity_and_restore_mismatches\":0,\"primary_bsp_write_mismatches\":0,\"raw_reference_bsp_write_differences\":{reference_write_differences}}}"
    );
}
