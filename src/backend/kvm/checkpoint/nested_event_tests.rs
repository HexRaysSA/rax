//! Active L2 continuation through the managed native owner.
use super::*;
use crate::vm::vcpu::{CheckpointIoReply, CheckpointIoState};
use kvm_bindings::{KVM_STATE_NESTED_GUEST_MODE, Msrs, kvm_msr_entry, kvm_segment, kvm_sregs};
use kvm_ioctls::{KvmNestedStateBuffer, VcpuFd};
use vm_memory::{GuestMemory, GuestMemoryMmap};

const ENTRY: u64 = 0x1000;
const L1_RESUME: u64 = 0x1080;
const L2_ENTRY: u64 = 0x1100;
const L2_STOPPED: u64 = L2_ENTRY + 4;
const GDT: u64 = 0x5000;
const TSS: u64 = 0x5400;
const PML4: u64 = 0x2000;
const RAM_BYTES: usize = 2 * 1024 * 1024;
const SMRAM_BASE: u64 = 0x8_0000;
const SMRAM_PER_CPU: u64 = 0x1_0000;
// VMXON, VMCLEAR, VMPTRLD, load field/value pairs from the RDI table,
// VMWRITE, VMLAUNCH. CF or ZF branches to an error canary on port 0x80.
const L1: &[u8] = &[
    0xf3, 0x0f, 0xc7, 0x33, 0x76, 0x22, 0x66, 0x0f, 0xc7, 0x73, 0x08, 0x76, 0x1b, 0x0f, 0xc7, 0x73,
    0x08, 0x76, 0x15, 0x48, 0x8b, 0x07, 0x48, 0x8b, 0x57, 0x08, 0x0f, 0x79, 0xc2, 0x76, 0x09, 0x48,
    0x83, 0xc7, 0x10, 0xe2, 0xee, 0x0f, 0x01, 0xc2, 0xb9, 0x00, 0x44, 0x00, 0x00, 0x41, 0x0f, 0x78,
    0xce, 0xb0, 0xff, 0xe6, 0x80, 0xf4,
];
// Read the exit reason, interrupt info, error code and guest RIP, then
// VMXOFF, OUT 0x80,AL and HLT. R12-R15 retain the four observed fields.
const L1_EXIT: &[u8] = &[
    0xb9, 0x02, 0x44, 0x00, 0x00, 0x41, 0x0f, 0x78, 0xcc, 0xb9, 0x04, 0x44, 0x00, 0x00, 0x41, 0x0f,
    0x78, 0xcd, 0xb9, 0x06, 0x44, 0x00, 0x00, 0x41, 0x0f, 0x78, 0xce, 0xb9, 0x1e, 0x68, 0x00, 0x00,
    0x41, 0x0f, 0x78, 0xcf, 0x44, 0x89, 0xe0, 0x0f, 0x01, 0xc4, 0xe6, 0x80, 0xf4,
];
// MOV AL,0x6c; OUT 0xe9,AL; VMCALL; HLT.
const L2: &[u8] = &[0xb0, 0x6c, 0xe6, 0xe9, 0x0f, 0x01, 0xc1, 0xf4];

fn msr(cpu: &VcpuFd, index: u32) -> u64 {
    let mut table = Msrs::from_entries(&[kvm_msr_entry {
        index,
        ..Default::default()
    }])
    .unwrap();
    assert_eq!(cpu.get_msrs(&mut table).unwrap(), 1, "MSR {index:#x}");
    table.as_slice()[0].data
}

fn vmcs_control(cpu: &VcpuFd, index: u32, required: u32) -> u64 {
    let allowed = msr(cpu, index);
    let value = allowed as u32 | required;
    assert_eq!(u64::from(value) & !(allowed >> 32), 0);
    u64::from(value)
}

fn word(ram: &GuestMemoryMmap, address: u64, value: u64) {
    ram.write_obj(value.to_le(), GuestAddress(address)).unwrap();
}

fn register_smram(vm: &KvmVm, memory: &GuestMemoryWrapper, count: u8) {
    let userspace_addr = memory
        .memory()
        .get_host_address(GuestAddress(SMRAM_BASE))
        .unwrap() as u64;
    // SAFETY: the fixture has exclusive setup access. This aligned range is
    // part of the owner-retained 2 MiB backing in both address spaces. The
    // fixture drops the VM and its vCPUs before releasing the backing.
    unsafe {
        vm.memory
            .vm_fd
            .set_user_memory_region(kvm_bindings::kvm_userspace_memory_region {
                slot: 1 << 16, // Slot 0 in the SMM address space.
                flags: 0,
                guest_phys_addr: SMRAM_BASE,
                memory_size: SMRAM_PER_CPU * u64::from(count),
                userspace_addr,
            })
    }
    .unwrap();
}

fn prepare_l1(memory: &GuestMemoryWrapper, core: &NativeCore, enters_smm: bool) {
    let ram = memory.memory();
    let cpu = &core.vcpu_fd;
    let base = 0x1_0000 * (u64::from(core.id) + 1);
    let vmxon = base;
    let vmcs = base + 0x1000;
    let pointers = base + 0x2000;
    let fields = base + 0x3000;
    let host_sp = base + 0x6000;
    let guest_sp = base + 0x8000;
    const FEATURE_CONTROL: u32 = 0x3a;
    let mut initial_msrs = vec![kvm_msr_entry {
        index: FEATURE_CONTROL,
        data: 5, // Locked, VMX outside SMX.
        ..Default::default()
    }];
    if enters_smm {
        let smbase = SMRAM_BASE + SMRAM_PER_CPU * u64::from(core.id);
        initial_msrs.push(kvm_msr_entry {
            index: 0x9e, // IA32_SMBASE
            data: smbase,
            ..Default::default()
        });
        // MOV AL,0x7a; OUT 0xe9,AL; RSM.
        ram.write_slice(
            &[0xb0, 0x7a, 0xe6, 0xe9, 0x0f, 0xaa],
            GuestAddress(smbase + 0x8000),
        )
        .unwrap();
    }
    let table = Msrs::from_entries(&initial_msrs).unwrap();
    assert_eq!(cpu.set_msrs(&table).unwrap(), initial_msrs.len());
    let basic = msr(cpu, 0x480);
    let revision = basic & 0x7fff_ffff;
    word(ram, vmxon, revision);
    word(ram, vmcs, revision);
    word(ram, pointers, vmxon);
    word(ram, pointers + 8, vmcs);

    let cr0 = (msr(cpu, 0x486) | 0x8001_0021) & msr(cpu, 0x487);
    let cr4 = (msr(cpu, 0x488) | 0x2020) & msr(cpu, 0x489);
    let true_controls = basic & (1 << 55) != 0;
    let control =
        |legacy, modern, bits| vmcs_control(cpu, if true_controls { modern } else { legacy }, bits);
    let table = [
        (0x4000, control(0x481, 0x48d, 0)), // PIN_BASED_VM_EXEC_CONTROL
        (0x4002, control(0x482, 0x48e, 0)), // CPU_BASED_VM_EXEC_CONTROL
        (0x4004, 1 << 13),                  // EXCEPTION_BITMAP: intercept #GP.
        (0x400c, control(0x483, 0x48f, 1 << 9)), // VM_EXIT_CONTROLS: 64-bit host.
        (0x4012, control(0x484, 0x490, 1 << 9)), // VM_ENTRY_CONTROLS: 64-bit guest.
        (0x2800, u64::MAX),                 // VMCS_LINK_POINTER
        (0x0800, 16),                       // GUEST_ES_SELECTOR
        (0x0802, 8),                        // GUEST_CS_SELECTOR
        (0x0804, 16),                       // GUEST_SS_SELECTOR
        (0x0806, 16),                       // GUEST_DS_SELECTOR
        (0x0808, 16),                       // GUEST_FS_SELECTOR
        (0x080a, 16),                       // GUEST_GS_SELECTOR
        (0x080e, 24),                       // GUEST_TR_SELECTOR
        (0x0c00, 16),                       // HOST_ES_SELECTOR
        (0x0c02, 8),                        // HOST_CS_SELECTOR
        (0x0c04, 16),                       // HOST_SS_SELECTOR
        (0x0c06, 16),                       // HOST_DS_SELECTOR
        (0x0c08, 16),                       // HOST_FS_SELECTOR
        (0x0c0a, 16),                       // HOST_GS_SELECTOR
        (0x0c0c, 24),                       // HOST_TR_SELECTOR
        (0x4800, u32::MAX.into()),          // GUEST_ES_LIMIT
        (0x4802, u32::MAX.into()),          // GUEST_CS_LIMIT
        (0x4804, u32::MAX.into()),          // GUEST_SS_LIMIT
        (0x4806, u32::MAX.into()),          // GUEST_DS_LIMIT
        (0x4808, u32::MAX.into()),          // GUEST_FS_LIMIT
        (0x480a, u32::MAX.into()),          // GUEST_GS_LIMIT
        (0x480e, 0x67),                     // GUEST_TR_LIMIT
        (0x4810, 39),                       // GUEST_GDTR_LIMIT
        (0x4814, 0xc093),                   // GUEST_ES_AR_BYTES
        (0x4816, 0xa09b),                   // GUEST_CS_AR_BYTES
        (0x4818, 0xc093),                   // GUEST_SS_AR_BYTES
        (0x481a, 0xc093),                   // GUEST_DS_AR_BYTES
        (0x481c, 0xc093),                   // GUEST_FS_AR_BYTES
        (0x481e, 0xc093),                   // GUEST_GS_AR_BYTES
        (0x4820, 0x10000),                  // GUEST_LDTR_AR_BYTES: unusable.
        (0x4822, 0x8b),                     // GUEST_TR_AR_BYTES
        (0x6800, cr0),                      // GUEST_CR0
        (0x6802, PML4),                     // GUEST_CR3
        (0x6804, cr4),                      // GUEST_CR4
        (0x6814, TSS),                      // GUEST_TR_BASE
        (0x6816, GDT),                      // GUEST_GDTR_BASE
        (0x681a, 0x400),                    // GUEST_DR7
        (0x681c, guest_sp),                 // GUEST_RSP
        (0x681e, L2_ENTRY),                 // GUEST_RIP
        (0x6820, 2),                        // GUEST_RFLAGS
        (0x6c00, cr0),                      // HOST_CR0
        (0x6c02, PML4),                     // HOST_CR3
        (0x6c04, cr4),                      // HOST_CR4
        (0x6c0a, TSS),                      // HOST_TR_BASE
        (0x6c0c, GDT),                      // HOST_GDTR_BASE
        (0x6c14, host_sp),                  // HOST_RSP
        (0x6c16, L1_RESUME),                // HOST_RIP
    ];
    for (row, (field, value)) in table.iter().enumerate() {
        let address = fields + 16 * row as u64;
        word(ram, address, *field);
        word(ram, address + 8, *value);
    }

    let data = kvm_segment {
        limit: u32::MAX,
        selector: 16,
        type_: 3,
        present: 1,
        db: 1,
        s: 1,
        g: 1,
        ..Default::default()
    };
    let special = kvm_sregs {
        cr0,
        cr3: PML4,
        cr4,
        efer: 0x500, // Long mode enabled and active.
        apic_base: cpu.get_sregs().unwrap().apic_base,
        gdt: kvm_bindings::kvm_dtable {
            base: GDT,
            limit: 39,
            ..Default::default()
        },
        cs: kvm_segment {
            selector: 8,
            type_: 11,
            db: 0,
            l: 1,
            ..data
        },
        ds: data,
        es: data,
        ss: data,
        fs: data,
        gs: data,
        ldt: kvm_segment {
            unusable: 1,
            ..Default::default()
        },
        tr: kvm_segment {
            base: TSS,
            limit: 0x67,
            selector: 24,
            type_: 11,
            present: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    cpu.set_sregs(&special).unwrap();
    cpu.set_regs(&kvm_bindings::kvm_regs {
        rip: ENTRY,
        rsp: host_sp,
        rflags: 2,
        rbx: pointers,
        rdi: fields,
        rcx: table.len() as u64,
        ..Default::default()
    })
    .unwrap();
}

#[derive(Clone, Copy, Debug)]
enum Event {
    None,
    PendingGp,
    TripleFault,
    Smi,
}

impl Event {
    fn queue(self, cpu: &VcpuFd) {
        let mut events = cpu.get_vcpu_events().unwrap();
        assert_eq!(events.exception.pending, 0);
        assert_eq!(events.triple_fault.pending, 0);
        match self {
            Self::None => return,
            Self::PendingGp => {
                events.exception.nr = 13;
                events.exception.pending = 1;
                events.exception.has_error_code = 1;
                events.exception.error_code = 0x125a;
            }
            Self::TripleFault => events.triple_fault.pending = 1,
            Self::Smi => events.smi.pending = 1,
        }
        cpu.set_vcpu_events(&events).unwrap();
    }

    fn expected_reason(self) -> u8 {
        match self {
            Self::None | Self::Smi => 18, // VMCALL
            Self::PendingGp => 0,         // exception or NMI
            Self::TripleFault => 2,       // triple fault
        }
    }

    fn require_l1_exit(self, cpu: &mut dyn VCpu) {
        let observed = exit(cpu);
        assert!(
            matches!(&observed, VcpuExit::IoOut { port: 0x80, data } if data == &[self.expected_reason()]),
            "{self:?}, unexpected nested continuation: {observed:?}"
        );
        let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
            unreachable!()
        };
        assert_eq!(state.regs.r12, u64::from(self.expected_reason()));
        assert_eq!(state.regs.r15, L2_STOPPED);
        if matches!(self, Self::PendingGp) {
            assert_eq!(state.regs.r13, 0x8000_0b0d);
            assert_eq!(state.regs.r14, 0x125a);
        }
        cpu.complete_io_out().unwrap();
        assert!(matches!(exit(cpu), VcpuExit::Hlt));
    }
}

fn has_active_l2(cpu: &VcpuFd) -> bool {
    let mut nested = KvmNestedStateBuffer::empty();
    cpu.nested_state(&mut nested).unwrap();
    u32::from(nested.flags) & KVM_STATE_NESTED_GUEST_MODE != 0
}

fn require_suspended_l2(cpu: &VcpuFd) {
    let mut nested = KvmNestedStateBuffer::empty();
    cpu.nested_state(&mut nested).unwrap();
    assert_eq!(u32::from(nested.flags) & KVM_STATE_NESTED_GUEST_MODE, 0);
    assert_eq!(
        nested.format,
        kvm_bindings::KVM_STATE_NESTED_FORMAT_VMX as u16
    );
    // SAFETY: the returned initialized header has the VMX format checked above.
    let flags = unsafe { nested.hdr.vmx.smm.flags };
    assert_eq!(
        u32::from(flags),
        kvm_bindings::KVM_STATE_NESTED_SMM_VMXON | kvm_bindings::KVM_STATE_NESTED_SMM_GUEST_MODE
    );
    assert_eq!(cpu.get_vcpu_events().unwrap().smi.smm, 1);
    assert_eq!(cpu.get_regs().unwrap().rip, 0x8004);
}

fn settle_output(cpu: &dyn VCpu, value: u8) {
    assert_eq!(
        cpu.settle_checkpoint_io(&mut |exit| {
            assert!(matches!(exit, VcpuExit::IoOut { port: 0xe9, data } if data == [value]));
            Ok(CheckpointIoReply::Output)
        })
        .unwrap(),
        CheckpointIoState::Complete
    );
}

fn replace_event_bytes(image: &Image, cpu: usize, offset: usize, bytes: &[u8]) -> Image {
    replace_bank_bytes(image, cpu, "events", offset, bytes)
}

fn replace_bank_bytes(image: &Image, cpu: usize, name: &str, offset: usize, bytes: &[u8]) -> Image {
    let mut serialized = serde_json::to_value(image).unwrap();
    let bank = serialized["cpus"][cpu][name]["bytes"]
        .as_array_mut()
        .unwrap();
    for (slot, byte) in bank[offset..offset + bytes.len()].iter_mut().zip(bytes) {
        *slot = serde_json::json!(byte);
    }
    serde_json::from_value(serialized).unwrap()
}

fn require_pristine_rejection(
    image: &Image,
    owner: &KvmVm,
    boundary: &CheckpointBoundary<'_>,
    message: &str,
) {
    let handles = owner.checkpoint_cpu_handles(boundary).unwrap();
    let read_rips = || {
        lock_cpus(owner, &handles)
            .unwrap()
            .iter()
            .map(|core| core.vcpu_fd.get_regs().unwrap().rip)
            .collect::<Vec<_>>()
    };
    let before = read_rips();
    let error = image.restore_stored(owner, boundary).unwrap_err();
    assert_eq!(
        read_rips(),
        before,
        "failed admission changed the native CPU register banks: {error}"
    );
    assert!(matches!(error, Error::InvalidConfig(text) if text.contains(message)));
}

fn reject_invalid_vmx_pages(
    saved: &Image,
    index: usize,
    owner: &KvmVm,
    boundary: &CheckpointBoundary<'_>,
) {
    use std::mem::offset_of;
    const HEADER: usize = offset_of!(KvmNestedStateBuffer, hdr);
    const VMXON: usize = HEADER + offset_of!(kvm_bindings::kvm_vmx_nested_state_hdr, vmxon_pa);
    const VMCS12: usize = HEADER + offset_of!(kvm_bindings::kvm_vmx_nested_state_hdr, vmcs12_pa);
    const FLAGS: usize = HEADER + offset_of!(kvm_bindings::kvm_vmx_nested_state_hdr, flags);
    let vmxon = 0x1_0000u64 * (index as u64 + 1);
    for (offset, bytes, message) in [
        (
            VMCS12,
            vmxon.to_le_bytes().to_vec(),
            "distinct aligned pages",
        ),
        (
            VMCS12,
            (vmxon + 4097).to_le_bytes().to_vec(),
            "distinct aligned pages",
        ),
        (
            VMXON,
            u64::MAX.to_le_bytes().to_vec(),
            "lacks its VMXON page",
        ),
        (
            VMCS12,
            u64::MAX.to_le_bytes().to_vec(),
            "requires a complete VMCS12 payload",
        ),
        (
            FLAGS,
            (1u32 << 31).to_le_bytes().to_vec(),
            "invalid VMX header flags",
        ),
        (
            0,
            (kvm_bindings::KVM_STATE_NESTED_RUN_PENDING as u16)
                .to_le_bytes()
                .to_vec(),
            "invalid native nested-state flags",
        ),
    ] {
        let malformed = replace_bank_bytes(saved, index, "nested", offset, &bytes);
        require_pristine_rejection(&malformed, owner, boundary, message);
    }
}

#[test]
#[ignore = "requires Linux x86-64 KVM with nested Intel VMX"]
fn active_or_smm_suspended_l2_restores_after_source_destruction() {
    let backend = KvmBackend::new().unwrap();
    let supported = backend
        .kvm()
        .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
        .unwrap();
    if !supported
        .as_slice()
        .iter()
        .any(|leaf| leaf.function == 1 && leaf.index == 0 && leaf.ecx & (1 << 5) != 0)
    {
        eprintln!("nested VMX unavailable on this KVM host");
        return;
    }
    let mut events = vec![Event::None, Event::PendingGp, Event::TripleFault];
    if backend
        .kvm()
        .check_extension_raw(kvm_bindings::KVM_CAP_X86_SMM.into())
        > 0
    {
        events.push(Event::Smi);
    } else {
        eprintln!("SMM unavailable on this KVM host");
    }
    for count in [1, 2, 4] {
        for &event in &events {
            let enters_smm = matches!(event, Event::Smi);
            let (source, memory, mut cpus) = graph(count, false);
            let ram = memory.memory();
            word(ram, PML4, 0x3003);
            word(ram, 0x3000, 0x4003);
            word(ram, 0x4000, 0x83); // Map the first 2 MiB.
            word(ram, GDT + 8, 0x00af_9b00_0000_ffff);
            word(ram, GDT + 16, 0x00cf_9300_0000_ffff);
            word(ram, GDT + 24, 0x0000_8b00_5400_0067);
            ram.write_slice(L1, GuestAddress(ENTRY)).unwrap();
            ram.write_slice(L1_EXIT, GuestAddress(L1_RESUME)).unwrap();
            ram.write_slice(L2, GuestAddress(L2_ENTRY)).unwrap();

            let owner = native(&*source);
            if enters_smm {
                register_smram(owner, &memory, count);
            }
            let boundary = source.checkpoint_boundary().unwrap();
            let handles = owner.checkpoint_cpu_handles(&boundary).unwrap();
            for core in lock_cpus(owner, &handles).unwrap() {
                prepare_l1(&memory, &core, enters_smm);
            }
            drop(boundary);
            for cpu in &mut cpus {
                let observed = exit(&mut **cpu);
                assert!(
                    matches!(&observed, VcpuExit::IoOut { port: 0xe9, data } if data == &[0x6c]),
                    "L2 did not launch: {observed:?}, R14={:#x}",
                    match cpu.get_state().unwrap() {
                        CpuState::X86_64(state) => state.regs.r14,
                        _ => unreachable!(),
                    }
                );
                settle_output(&**cpu, 0x6c);
            }

            let boundary = source.checkpoint_boundary().unwrap();
            for core in lock_cpus(owner, &handles).unwrap() {
                assert!(has_active_l2(&core.vcpu_fd));
                assert_eq!(core.vcpu_fd.get_regs().unwrap().rip, L2_STOPPED);
                event.queue(&core.vcpu_fd);
            }
            drop(boundary);
            if enters_smm {
                for cpu in &mut cpus {
                    let observed = exit(&mut **cpu);
                    assert!(
                        matches!(&observed, VcpuExit::IoOut { port: 0xe9, data } if data == &[0x7a]),
                        "SMI did not enter its handler: {observed:?}"
                    );
                    settle_output(&**cpu, 0x7a);
                }
            }
            let boundary = source.checkpoint_boundary().unwrap();
            if enters_smm {
                for core in lock_cpus(owner, &handles).unwrap() {
                    require_suspended_l2(&core.vcpu_fd);
                }
            }
            let saved = owner.capture_native_banks(&boundary).unwrap();
            let bytes = crate::codec::serialize(&saved).unwrap();
            let mut ram_bytes = vec![0; RAM_BYTES];
            ram.read_slice(&mut ram_bytes, GuestAddress(0)).unwrap();
            drop(boundary);
            drop(handles);
            for cpu in &mut cpus {
                event.require_l1_exit(&mut **cpu);
            }
            drop(saved);
            drop(cpus);
            drop(source);
            drop(memory);

            let saved: Image = crate::codec::deserialize_strict(&bytes).unwrap();
            let (target, memory, mut cpus) = graph(count, false);
            memory
                .memory()
                .write_slice(&ram_bytes, GuestAddress(0))
                .unwrap();
            let owner = native(&*target);
            if enters_smm {
                register_smram(owner, &memory, count);
            }
            let boundary = target.checkpoint_boundary().unwrap();
            if matches!(event, Event::None | Event::Smi) {
                // Corrupt the last CPU only. Rejection after starting the
                // setter loop would already have replaced any earlier CPUs.
                let index = usize::from(count) - 1;
                reject_invalid_vmx_pages(&saved, index, owner, &boundary);
                eprintln!("rejected malformed VMX page records for {count} vCPUs, {event:?}");
                let conflicting = replace_event_bytes(
                    &saved,
                    index,
                    std::mem::offset_of!(kvm_bindings::kvm_vcpu_events, smi.smm),
                    &[u8::from(!enters_smm)],
                );
                require_pristine_rejection(&conflicting, owner, &boundary, "VMX mode disagrees");

                let handles = owner.checkpoint_cpu_handles(&boundary).unwrap();
                let flags = lock_cpus(owner, &handles).unwrap()[index]
                    .vcpu_fd
                    .get_vcpu_events()
                    .unwrap()
                    .flags
                    & !kvm_bindings::KVM_VCPUEVENT_VALID_SMM;
                let ambiguous = replace_event_bytes(
                    &saved,
                    index,
                    std::mem::offset_of!(kvm_bindings::kvm_vcpu_events, flags),
                    &flags.to_le_bytes(),
                );
                require_pristine_rejection(&ambiguous, owner, &boundary, "SMM event state");
                eprintln!("rejected mismatched VMX/SMM records for {count} vCPUs, {event:?}");
            }
            saved
                .restore_stored(owner, &boundary)
                .unwrap_or_else(|error| panic!("{count} vCPUs, {event:?}: {error}"));
            saved.stage_resume_clock(owner, &boundary).unwrap();
            let handles = owner.checkpoint_cpu_handles(&boundary).unwrap();
            for core in lock_cpus(owner, &handles).unwrap() {
                if enters_smm {
                    require_suspended_l2(&core.vcpu_fd);
                } else {
                    assert!(has_active_l2(&core.vcpu_fd));
                    assert_eq!(core.vcpu_fd.get_regs().unwrap().rip, L2_STOPPED);
                }
            }
            drop(boundary);
            for cpu in &mut cpus {
                event.require_l1_exit(&mut **cpu);
            }
            eprintln!("restored {count} vCPUs, {event:?}");
        }
    }
}
