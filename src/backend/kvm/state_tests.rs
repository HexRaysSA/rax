//! Native KVM producer regressions. These cases require a usable `/dev/kvm`.
use super::*;

fn native_xsave(cpu: &KvmVcpu) -> kvm_bindings::Xsave {
    let size = cpu
        .memory_owner
        .vm_fd
        .check_extension_int(kvm_ioctls::Cap::Xsave2);
    assert!(size >= 4096 && size % 4 == 0);
    // The hardware witnesses run serially, without dynamic XSTATE permission
    // changes. Use the VM's exact kernel allocation contract independently of
    // the public projection/overlay implementation being tested.
    let mut image = kvm_bindings::Xsave::new((size as usize - 4096) / 4).unwrap();
    // SAFETY: the live VM supplied this exact byte count; this initialized
    // allocation remains exclusive and owned for the synchronous kernel copy.
    unsafe { cpu.vcpu_fd.get_xsave2(&mut image).unwrap() };
    image
}

fn seed_legacy_registers(cpu: &KvmVcpu, fpu: &kvm_bindings::kvm_fpu) {
    let mut image = native_xsave(cpu);
    // SAFETY: only the fixed region is borrowed. Its initialized storage and
    // FAM length remain unchanged; no native operation is active here.
    let words = unsafe { &mut image.as_mut_fam_struct().xsave.region };
    let mut legacy = [0; 512];
    for (bytes, word) in legacy.chunks_exact_mut(4).zip(&words[..128]) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    legacy[..2].copy_from_slice(&fpu.fcw.to_le_bytes());
    legacy[2..4].copy_from_slice(&fpu.fsw.to_le_bytes());
    legacy[4] = fpu.ftwx;
    legacy[6..8].copy_from_slice(&fpu.last_opcode.to_le_bytes());
    legacy[8..16].copy_from_slice(&fpu.last_ip.to_le_bytes());
    legacy[16..24].copy_from_slice(&fpu.last_dp.to_le_bytes());
    legacy[24..28].copy_from_slice(&fpu.mxcsr.to_le_bytes());
    for (destination, source) in legacy[32..160].chunks_exact_mut(16).zip(fpu.fpr) {
        destination.copy_from_slice(&source);
    }
    for (destination, source) in legacy[160..416].chunks_exact_mut(16).zip(fpu.xmm) {
        destination.copy_from_slice(&source);
    }
    for (word, bytes) in words[..128].iter_mut().zip(legacy.chunks_exact(4)) {
        *word = u32::from_le_bytes(bytes.try_into().unwrap());
    }
    // Linux's legacy SET_FPU does not activate these XSAVE components. Seed
    // operative architectural state, not an inactive legacy backing buffer.
    words[128] |= 3;
    // SAFETY: the exact VM-sized FAM and all untouched extended components
    // remain live. Only initialized fixed x87/SSE fields and their active bits
    // changed. The hardware/kernel validates the supplied state.
    unsafe { cpu.vcpu_fd.set_xsave2(&image).unwrap() };
}

fn cpu() -> (Kvm, Arc<MemoryOwner>, KvmVcpu) {
    cpu_with_irqchip(false)
}

fn cpu_with_irqchip(irqchip: bool) -> (Kvm, Arc<MemoryOwner>, KvmVcpu) {
    let kvm = Kvm::new().expect("native KVM tests require /dev/kvm");
    let vm = kvm.create_vm().unwrap();
    if irqchip {
        vm.create_irq_chip().unwrap();
    }
    let memory = GuestMemoryWrapper::new(2 * 1024 * 1024).unwrap();
    memory.register(&vm).unwrap();
    let vcpu_fd = vm.create_vcpu(0).unwrap();
    vcpu_fd
        .set_cpuid2(
            &kvm.get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
                .unwrap(),
        )
        .unwrap();
    let memory_owner = Arc::new(MemoryOwner {
        vm_fd: vm,
        registered: Mutex::new(vec![memory.memory().clone()]),
    });
    let cpu = KvmVcpu {
        vcpu_fd,
        id: 0,
        pending_io_in: None,
        io: super::io::State::default(),
        memory_owner: memory_owner.clone(),
        _memory: Arc::new(memory.memory().clone()),
        state_failure: None,
    };
    (kvm, memory_owner, cpu)
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn public_state_roundtrip_preserves_native_apic_base_and_pending_vector() {
    let (_kvm, _vm, mut cpu) = cpu();
    let mut original = cpu.vcpu_fd.get_sregs().unwrap();
    original.interrupt_bitmap = [0, 0, 0, 1 << 8]; // Pending vector 200.
    cpu.vcpu_fd.set_sregs(&original).unwrap();
    let original = cpu.vcpu_fd.get_sregs().unwrap();
    assert_ne!(original.apic_base, 0);
    assert_eq!(original.interrupt_bitmap, [0, 0, 0, 1 << 8]);
    let mut events = cpu.vcpu_fd.get_vcpu_events().unwrap();
    events.nmi.pending = 1;
    events.nmi.masked = 1;
    events.interrupt.shadow = 1;
    cpu.vcpu_fd.set_vcpu_events(&events).unwrap();
    let events = cpu.vcpu_fd.get_vcpu_events().unwrap();

    let state = cpu.get_state().unwrap();
    cpu.set_state(&state).unwrap();
    let restored = cpu.vcpu_fd.get_sregs().unwrap();
    assert_eq!(restored.apic_base, original.apic_base);
    assert_eq!(restored.interrupt_bitmap, original.interrupt_bitmap);
    assert_eq!(cpu.vcpu_fd.get_vcpu_events().unwrap(), events);
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn public_state_reads_native_xmm_and_debug_registers() {
    let (_kvm, _vm, cpu) = cpu();
    let mut fpu = cpu.vcpu_fd.get_fpu().unwrap();
    fpu.xmm[0] = std::array::from_fn(|index| 0x80 + index as u8);
    fpu.xmm[15] = std::array::from_fn(|index| 0x40 + index as u8);
    fpu.mxcsr = 0x1f80;
    seed_legacy_registers(&cpu, &fpu);
    let mut debug = cpu.vcpu_fd.get_debug_regs().unwrap();
    debug.db[0] = 0x1234;
    debug.db[3] = 0x5678;
    cpu.vcpu_fd.set_debug_regs(&debug).unwrap();

    let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
        panic!("KVM returned a foreign public CPU projection");
    };
    for index in [0, 15] {
        let low = u64::from_le_bytes(fpu.xmm[index][..8].try_into().unwrap());
        let high = u64::from_le_bytes(fpu.xmm[index][8..].try_into().unwrap());
        assert_eq!(state.regs.xmm[index], [low, high]);
    }
    assert_eq!(state.sregs.dr0, debug.db[0]);
    assert_eq!(state.sregs.dr3, debug.db[3]);
}

fn encoded_state(cpu: &KvmVcpu) -> Vec<u8> {
    crate::codec::serialize_limited(&cpu.get_state().unwrap(), 1024 * 1024).unwrap()
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn public_overlay_updates_all_represented_banks_and_retains_x87_controls() {
    let (_kvm, _vm, mut cpu) = cpu();
    let mut fpu = cpu.vcpu_fd.get_fpu().unwrap();
    fpu.fcw = 0x027f;
    fpu.fsw = (2 << 11) | (1 << 5);
    fpu.ftwx = 0xff;
    fpu.last_opcode = 0x321;
    fpu.last_ip = 0x1234;
    fpu.last_dp = 0x5678;
    fpu.mxcsr = 0x3fc0; // Include DAZ and nondefault rounding.
    for (index, value) in fpu.fpr.iter_mut().enumerate() {
        value[..8].copy_from_slice(&(0x8000_0000_0000_0000u64 | index as u64).to_le_bytes());
        value[8..10].copy_from_slice(&0x3fffu16.to_le_bytes());
    }
    seed_legacy_registers(&cpu, &fpu);
    let original = cpu.vcpu_fd.get_fpu().unwrap();
    assert_eq!(
        native_xsave(&cpu).as_fam_struct_ref().xsave.region[6],
        0x3fc0
    );
    let CpuState::X86_64(mut desired) = cpu.get_state().unwrap() else {
        unreachable!()
    };
    desired.regs.rax = 0x1234_5678;
    desired.regs.mm = std::array::from_fn(|index| 0x1122_3344_5566_7700 | index as u64);
    desired.regs.xmm = std::array::from_fn(|index| [0x100 + index as u64, 0x200 + index as u64]);
    desired.regs.ymm_high =
        std::array::from_fn(|index| [0x300 + index as u64, 0x400 + index as u64]);
    let layout = xsave::Image::read(&cpu.memory_owner.vm_fd, &cpu.vcpu_fd)
        .unwrap()
        .layout;
    eprintln!(
        "KVM_PUBLIC_XSAVE mask={:#x} size={} mxcsr_mask={:#x}",
        layout.mask, layout.size, layout.mxcsr_mask
    );
    if layout.mask & (1 << 5) != 0 {
        desired.regs.k = std::array::from_fn(|index| 0x55aa + index as u64);
    }
    if layout.mask & (1 << 6) != 0 {
        desired.regs.zmm_high = std::array::from_fn(|index| [0x500 + index as u64; 4]);
    }
    if layout.mask & (1 << 7) != 0 {
        desired.regs.zmm_ext = std::array::from_fn(|index| [0x600 + index as u64; 8]);
    }
    desired.sregs.dr0 = 0x1234;
    desired.sregs.dr1 = 0x2345;
    desired.sregs.dr2 = 0x3456;
    desired.sregs.dr3 = 0x4567;
    desired.sregs.star = 0x001b_0008_0000_0000;
    desired.sregs.lstar = 0x1234_5000;
    desired.sregs.cstar = 0x1234_6000;
    desired.sregs.fmask = 0x202;
    desired.sregs.sysenter_cs = 0x10;
    desired.sregs.sysenter_esp = 0x1234_7000;
    desired.sregs.sysenter_eip = 0x1234_8000;
    let desired = CpuState::X86_64(desired);
    cpu.set_state(&desired).unwrap();
    assert_eq!(
        encoded_state(&cpu),
        crate::codec::serialize_limited(&desired, 1024 * 1024).unwrap()
    );
    let actual = cpu.vcpu_fd.get_fpu().unwrap();
    assert_eq!(actual.fcw, original.fcw);
    assert_eq!(actual.fsw, original.fsw);
    assert_eq!(actual.ftwx, original.ftwx);
    assert_eq!(actual.last_opcode, original.last_opcode);
    assert_eq!(actual.last_ip, original.last_ip);
    assert_eq!(actual.last_dp, original.last_dp);
    assert_eq!(actual.mxcsr, original.mxcsr);
    assert_eq!(
        native_xsave(&cpu).as_fam_struct_ref().xsave.region[6],
        0x3fc0
    );
    for (actual, original) in actual.fpr.iter().zip(original.fpr) {
        assert_eq!(&actual[8..], &original[8..]);
    }
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn unsupported_public_bank_rejects_before_native_register_mutation() {
    let (_kvm, _vm, mut cpu) = cpu();
    let before = encoded_state(&cpu);
    let original = xsave::Image::read(&cpu.memory_owner.vm_fd, &cpu.vcpu_fd).unwrap();
    let CpuState::X86_64(mut desired) = cpu.get_state().unwrap() else {
        unreachable!()
    };
    desired.regs.rax = 0x1234;
    desired.regs.r16 = 1;
    desired.regs.xmm[0] = [0x1234, 0x5678];
    let error = cpu.set_state(&CpuState::X86_64(desired)).unwrap_err();
    assert!(error.to_string().contains("APX"), "{error}");
    assert_eq!(encoded_state(&cpu), before);
    assert_eq!(
        xsave::Image::read(&cpu.memory_owner.vm_fd, &cpu.vcpu_fd)
            .unwrap()
            .bytes,
        original.bytes
    );
    assert!(cpu.state_failure.is_none());
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn rejected_control_register_rolls_back_prior_vector_msr_and_debug_writes() {
    let (_kvm, _vm, mut cpu) = cpu();
    let before = encoded_state(&cpu);
    let original = xsave::Image::read(&cpu.memory_owner.vm_fd, &cpu.vcpu_fd).unwrap();
    let kernel_special = cpu.vcpu_fd.get_sregs().unwrap();
    let CpuState::X86_64(mut desired) = cpu.get_state().unwrap() else {
        unreachable!()
    };
    desired.regs.rax = 0x1234;
    desired.regs.xmm[0] = [0x1234, 0x5678];
    desired.sregs.lstar = 0x1234_5000;
    desired.sregs.dr0 = 0x1234;
    desired.sregs.cr4 |= 1 << 63; // Reserved CR4 bit: rejected by KVM.
    let error = cpu.set_state(&CpuState::X86_64(desired)).unwrap_err();
    assert!(error.to_string().contains("SET_SREGS"), "{error}");
    assert_eq!(encoded_state(&cpu), before);
    assert_eq!(
        xsave::Image::read(&cpu.memory_owner.vm_fd, &cpu.vcpu_fd)
            .unwrap()
            .bytes,
        original.bytes
    );
    assert_eq!(cpu.vcpu_fd.get_sregs().unwrap(), kernel_special);
    assert!(cpu.state_failure.is_none());
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn managed_native_cpu_retains_registered_ram_after_vm_owner_drop() {
    use vm_memory::{Bytes, GuestAddress};
    let backend = KvmBackend::new().unwrap();
    let vm = backend.create_vm().unwrap();
    let memory = GuestMemoryWrapper::new(2 * 1024 * 1024).unwrap();
    vm.as_any()
        .downcast_ref::<KvmVm>()
        .unwrap()
        .register_memory(&memory)
        .unwrap();
    // INC byte ptr [0x2000]; HLT, in 16-bit real mode.
    memory
        .memory()
        .write_slice(&[0xfe, 0x06, 0x00, 0x20, 0xf4], GuestAddress(0x1000))
        .unwrap();
    let shared = Arc::new(memory.memory().clone());
    let witness = Arc::downgrade(&shared);
    let mut cpu = vm.create_vcpu(0, shared.clone()).unwrap();
    let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
        unreachable!()
    };
    state.regs.rip = 0x1000;
    state.sregs.cs.base = 0;
    state.sregs.cs.selector = 0;
    cpu.set_state(&CpuState::X86_64(state)).unwrap();
    drop(shared);
    drop(memory);
    drop(vm);
    drop(backend);
    assert!(witness.upgrade().is_some());
    assert!(matches!(cpu.run().unwrap(), VcpuExit::Hlt));
    assert_eq!(
        witness
            .upgrade()
            .unwrap()
            .read_obj::<u8>(GuestAddress(0x2000))
            .unwrap(),
        1
    );
    drop(cpu);
    assert!(witness.upgrade().is_none());
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn registered_native_ram_outlives_the_registration_borrow() {
    use vm_memory::{Bytes, GuestAddress};
    let backend = KvmBackend::new().unwrap();
    let vm = backend.create_vm().unwrap();
    let memory = GuestMemoryWrapper::new(2 * 1024 * 1024).unwrap();
    let native = vm.as_any().downcast_ref::<KvmVm>().unwrap();
    native.register_memory(&memory).unwrap();
    // MOV AL,[0x2000]; OUT 0xe9,AL; HLT, in 16-bit real mode.
    memory
        .memory()
        .write_slice(&[0xa0, 0x00, 0x20, 0xe6, 0xe9, 0xf4], GuestAddress(0x1000))
        .unwrap();
    memory
        .memory()
        .write_obj(0x5au8, GuestAddress(0x2000))
        .unwrap();
    drop(memory);
    let mut cpu = native.create_vcpu_fd(0).unwrap();
    let mut special = cpu.get_sregs().unwrap();
    special.cs.base = 0;
    special.cs.selector = 0;
    cpu.set_sregs(&special).unwrap();
    cpu.set_regs(&kvm_bindings::kvm_regs {
        rip: 0x1000,
        rflags: 2,
        ..Default::default()
    })
    .unwrap();
    match cpu.run().unwrap() {
        kvm_ioctls::VcpuExit::IoOut(0xe9, value) => assert_eq!(value, &[0x5a]),
        exit => panic!("registered-RAM guest did not produce its byte: {exit:?}"),
    }
    assert!(matches!(cpu.run().unwrap(), kvm_ioctls::VcpuExit::Hlt));
}

fn real_mode_entry(cpu: &mut KvmVcpu, program: &[u8]) {
    use vm_memory::{Bytes, GuestAddress};
    cpu._memory
        .write_slice(program, GuestAddress(0x1000))
        .unwrap();
    let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
        unreachable!()
    };
    state.regs.rip = 0x1000;
    state.regs.rflags = 2;
    state.sregs.cs.base = 0;
    state.sregs.cs.selector = 0;
    state.sregs.cr0 &= !((1 << 2) | (1 << 3));
    state.sregs.cr4 |= 1 << 9;
    cpu.set_state(&CpuState::X86_64(state)).unwrap();
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn native_guest_consumes_the_overlaid_mmx_and_xmm_banks() {
    use vm_memory::{Bytes, GuestAddress};
    let (_kvm, _vm, mut cpu) = cpu();
    // LLVM MC i386/.code16: MOVQ [0x2010],MM0; EMMS;
    // MOVDQU [0x2000],XMM0; HLT.
    real_mode_entry(
        &mut cpu,
        &[
            0x0f, 0x7f, 0x06, 0x10, 0x20, 0x0f, 0x77, 0xf3, 0x0f, 0x7f, 0x06, 0x00, 0x20, 0xf4,
        ],
    );
    let mut fpu = cpu.vcpu_fd.get_fpu().unwrap();
    fpu.fsw = 2 << 11;
    fpu.ftwx = 0xff;
    fpu.mxcsr = 0x1f80;
    seed_legacy_registers(&cpu, &fpu);
    let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
        unreachable!()
    };
    state.regs.mm[0] = 0x1122_3344_5566_7788;
    state.regs.xmm[0] = [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210];
    cpu.set_state(&CpuState::X86_64(state)).unwrap();
    assert!(matches!(cpu.run().unwrap(), VcpuExit::Hlt));
    let mut result = [0; 24];
    cpu._memory
        .read_slice(&mut result, GuestAddress(0x2000))
        .unwrap();
    assert_eq!(&result[..8], &0x0123_4567_89ab_cdefu64.to_le_bytes());
    assert_eq!(&result[8..16], &0xfedc_ba98_7654_3210u64.to_le_bytes());
    assert_eq!(&result[16..], &0x1122_3344_5566_7788u64.to_le_bytes());
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn public_overlay_rejection_keeps_the_uncompleted_native_input() {
    let (_kvm, _vm, mut cpu) = cpu();
    real_mode_entry(&mut cpu, &[0xe4, 0x70, 0xf4]); // IN AL,0x70; HLT.
    assert!(matches!(
        cpu.run().unwrap(),
        VcpuExit::IoIn {
            port: 0x70,
            size: 1
        }
    ));
    let before = cpu.vcpu_fd.get_regs().unwrap();
    let CpuState::X86_64(mut desired) = cpu.get_state().unwrap() else {
        unreachable!()
    };
    desired.regs.rax = 0x1234;
    desired.regs.xmm[0] = [0x1234, 0x5678];
    let error = cpu.set_state(&CpuState::X86_64(desired)).unwrap_err();
    assert!(
        error.to_string().contains("native I/O completion"),
        "{error}"
    );
    assert_eq!(cpu.vcpu_fd.get_regs().unwrap(), before);
    assert!(cpu.pending_io_in.is_some());
    cpu.complete_io_in(&[0x5a]);
    assert!(matches!(cpu.run().unwrap(), VcpuExit::Hlt));
    assert_eq!(cpu.vcpu_fd.get_regs().unwrap().rax & 255, 0x5a);
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn public_overlay_preserves_native_halted_and_startup_mp_states() {
    let (_kvm, _vm, mut cpu) = cpu_with_irqchip(true);
    for mp_state in [
        kvm_bindings::KVM_MP_STATE_RUNNABLE,
        kvm_bindings::KVM_MP_STATE_UNINITIALIZED,
        kvm_bindings::KVM_MP_STATE_INIT_RECEIVED,
        kvm_bindings::KVM_MP_STATE_HALTED,
    ] {
        cpu.vcpu_fd
            .set_mp_state(kvm_bindings::kvm_mp_state { mp_state })
            .unwrap();
        let before = cpu.vcpu_fd.get_regs().unwrap();
        let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
            panic!()
        };
        state.sregs.cr8 = (state.sregs.cr8 + 1) & 15;
        let tpr = state.sregs.cr8;
        cpu.set_state(&CpuState::X86_64(state)).unwrap();
        assert_eq!(cpu.vcpu_fd.get_mp_state().unwrap().mp_state, mp_state);
        assert_eq!(cpu.vcpu_fd.get_regs().unwrap(), before);
        let CpuState::X86_64(after) = cpu.get_state().unwrap() else {
            panic!()
        };
        assert_eq!(after.sregs.cr8, tpr);
    }
}

fn native_special(cpu: &KvmVcpu) -> kvm_bindings::kvm_sregs2 {
    use kvm_bindings::kvm_sregs2;
    use std::os::fd::AsRawFd;
    let mut value = kvm_sregs2::default();
    // SAFETY: the retained UAPI defines this output ioctl and struct. The
    // stopped CPU and exclusive initialized output remain live throughout;
    // the synchronous kernel copy retains no pointer.
    let result = unsafe {
        libc::ioctl(
            cpu.vcpu_fd.as_raw_fd(),
            libc::_IOR::<kvm_sregs2>(kvm_bindings::KVMIO, 0xcc),
            &mut value as *mut kvm_sregs2,
        )
    };
    assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
    value
}

fn set_native_special(cpu: &KvmVcpu, value: &kvm_bindings::kvm_sregs2) {
    use kvm_bindings::kvm_sregs2;
    use std::os::fd::AsRawFd;
    // SAFETY: the retained UAPI defines this input ioctl and struct. The
    // stopped CPU's live FD and initialized input stay owned throughout the
    // synchronous copy, which retains no pointer.
    let result = unsafe {
        libc::ioctl(
            cpu.vcpu_fd.as_raw_fd(),
            libc::_IOW::<kvm_sregs2>(kvm_bindings::KVMIO, 0xcd),
            value as *const kvm_sregs2,
        )
    };
    assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
}

fn cached_pae_cpu() -> (Kvm, Arc<MemoryOwner>, KvmVcpu) {
    use vm_memory::{Bytes, GuestAddress};
    let (kvm, vm, cpu) = cpu();
    let mut special = native_special(&cpu);
    special.cr0 |= (1 << 31) | 1;
    special.cr4 |= 1 << 5;
    special.cr3 = 0x2000;
    special.flags = u64::from(kvm_bindings::KVM_SREGS2_FLAGS_PDPTRS_VALID);
    special.pdptrs = [0x3001, 0, 0, 0];
    set_native_special(&cpu, &special);
    // The native cache deliberately differs from its physical backing.
    cpu._memory.write_obj(0u64, GuestAddress(0x2000)).unwrap();
    assert_eq!(native_special(&cpu).pdptrs, [0x3001, 0, 0, 0]);
    (kvm, vm, cpu)
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn unchanged_public_paging_controls_preserve_cached_pae_pdptrs() {
    let (_kvm, _vm, mut cpu) = cached_pae_cpu();
    let original = native_special(&cpu);
    let state = cpu.get_state().unwrap();
    cpu.set_state(&state).unwrap();
    assert_eq!(native_special(&cpu), original);
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn changed_nonpaging_public_controls_preserve_cached_pae_pdptrs() {
    let (_kvm, _vm, mut cpu) = cached_pae_cpu();
    let original = native_special(&cpu).pdptrs;
    for field in 0..5 {
        let CpuState::X86_64(mut desired) = cpu.get_state().unwrap() else {
            unreachable!()
        };
        match field {
            0 => desired.sregs.cr8 = 1,
            1 => desired.sregs.cr2 = 0x1234,
            2 => desired.sregs.cr4 |= 1 << 9, // OSFXSR does not reload PDPTRs.
            3 => desired.sregs.cs.selector ^= 8,
            4 => desired.sregs.gdt.limit = 0x3f,
            _ => unreachable!(),
        }
        let desired = CpuState::X86_64(desired);
        cpu.set_state(&desired).unwrap();
        assert_eq!(native_special(&cpu).pdptrs, original, "field {field}");
        assert_eq!(
            encoded_state(&cpu),
            crate::codec::serialize_limited(&desired, 1024 * 1024).unwrap()
        );
    }
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn changed_public_cr3_loads_the_requested_new_pae_table() {
    use vm_memory::{Bytes, GuestAddress};
    let (_kvm, _vm, mut cpu) = cached_pae_cpu();
    cpu._memory
        .write_obj(0x5001u64, GuestAddress(0x4000))
        .unwrap();
    let CpuState::X86_64(mut desired) = cpu.get_state().unwrap() else {
        unreachable!()
    };
    desired.sregs.cr3 = 0x4000;
    cpu.set_state(&CpuState::X86_64(desired)).unwrap();
    let actual = native_special(&cpu);
    assert_eq!(actual.cr3, 0x4000);
    assert_eq!(actual.pdptrs, [0x5001, 0, 0, 0]);
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn native_special_backup_restores_cache_when_public_controls_already_match() {
    let (_kvm, _vm, cpu) = cached_pae_cpu();
    let original = native_special(&cpu);
    let backup = special::Image::read(&cpu.memory_owner.vm_fd, &cpu.vcpu_fd).unwrap();
    let mut changed = original;
    changed.pdptrs[0] = 0x6001;
    set_native_special(&cpu, &changed);
    assert_eq!(cpu.vcpu_fd.get_sregs().unwrap(), backup.legacy);
    assert_eq!(native_special(&cpu).pdptrs[0], 0x6001);
    backup.write(&cpu.vcpu_fd).unwrap();
    assert_eq!(native_special(&cpu), original);
}

#[test]
#[ignore = "requires native Linux KVM; executed by the KVM CI job"]
fn inactive_legacy_backing_does_not_override_architectural_initial_state() {
    let (_kvm, _vm, cpu) = cpu();
    let mut fpu = cpu.vcpu_fd.get_fpu().unwrap();
    fpu.fcw = 0x027f;
    fpu.xmm[0] = [0x80; 16];
    cpu.vcpu_fd.set_fpu(&fpu).unwrap();
    let image = native_xsave(&cpu);
    assert_eq!(image.as_fam_struct_ref().xsave.region[128] & 3, 0);
    assert_eq!(image.as_fam_struct_ref().xsave.region[0] & 0xffff, 0x037f);
    let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
        unreachable!()
    };
    assert_eq!(state.regs.xmm, [[0; 2]; 16]);
    assert_eq!(state.regs.mm, [0; 8]);
}
