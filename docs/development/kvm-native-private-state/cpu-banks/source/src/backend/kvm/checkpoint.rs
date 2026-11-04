mod bank;
mod bounded;
mod cpu;
mod msrs;
mod nested;
mod profile;
mod sregs2;

use cpu::Image;
use kvm_bindings::{CpuId, kvm_userspace_memory_region};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use std::os::fd::AsRawFd;

unsafe extern "C" {
    fn enter_vmx_for_rust(kvm: i32, cpu: i32, ram: *mut u8) -> i32;
}

const RAM_BYTES: usize = 0x20_000;
struct Ram(*mut libc::c_void);

impl Ram {
    fn new() -> Self {
        // SAFETY: an anonymous private mapping creates RAM_BYTES initialized,
        // writable, page-aligned bytes. No file or borrowed pointer is supplied.
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                RAM_BYTES,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(pointer, libc::MAP_FAILED);
        // Read XMM0, RBX, then YMM0[255:128] into three distinct outputs.
        let code = [
            0x66, 0x0f, 0x7e, 0xc0, 0xe7, 0xe9, 0x66, 0x89, 0xd8, 0x66, 0xe7, 0xea, 0xc4, 0xe3,
            0x7d, 0x19, 0xc1, 0x01, // VEXTRACTF128 XMM1,YMM0,1.
            0xc5, 0xf9, 0x7e, 0xc8, // VMOVD EAX,XMM1.
            0xe7, 0xeb, 0xf4,
        ];
        // SAFETY: the fresh exclusive mapping covers the entire code span at 0x1000. Source
        // and destination do not overlap, and no KVM descriptor exists yet.
        unsafe {
            std::ptr::copy_nonoverlapping(
                code.as_ptr(),
                pointer.cast::<u8>().add(0x1000),
                code.len(),
            )
        };
        Self(pointer)
    }
}

impl Drop for Ram {
    fn drop(&mut self) {
        // SAFETY: Graph's field order drops all native CPU/VM references
        // before this original, exclusively owned mapping and exact length.
        assert_eq!(unsafe { libc::munmap(self.0, RAM_BYTES) }, 0);
    }
}

struct Graph {
    cpus: Vec<VcpuFd>,
    profiles: Vec<CpuId>,
    vm: VmFd,
    kvm: Kvm,
    _ram: Ram,
}

impl Graph {
    fn new(count: u8, irqchip: bool, initialize: bool) -> Self {
        let ram = Ram::new();
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        if irqchip {
            vm.create_irq_chip().unwrap();
        }
        // SAFETY: the single nonoverlapping slot covers the page-aligned live
        // mapping. Graph retains RAM until every VM and CPU FD is dropped.
        // No host writes occur after registration and guest execution is serial.
        unsafe {
            vm.set_user_memory_region(kvm_userspace_memory_region {
                slot: 0,
                flags: 0,
                guest_phys_addr: 0,
                memory_size: RAM_BYTES as u64,
                userspace_addr: ram.0 as u64,
            })
            .unwrap();
        }
        let supported = kvm
            .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .unwrap();
        let topology = super::cpuid::Topology::new(count).unwrap();
        let mut cpus = Vec::new();
        let mut profiles = Vec::new();
        for id in 0..count {
            let mut profile = topology.project(&supported, u32::from(id)).unwrap();
            super::cpuid_apic::admit(
                &mut profile,
                irqchip,
                kvm.check_extension(kvm_ioctls::Cap::TscDeadlineTimer),
            );
            let cpu = vm.create_vcpu(u64::from(id)).unwrap();
            cpu.set_cpuid2(&profile).unwrap();
            if initialize {
                let mut special = cpu.get_sregs().unwrap();
                // AVX VEX instructions require protected mode. Install flat
                // hidden segment caches directly; this guest never reloads a
                // selector, so it does not depend on an uninitialized GDT.
                special.cs = kvm_bindings::kvm_segment {
                    base: 0,
                    limit: u32::MAX,
                    selector: 8,
                    type_: 11,
                    present: 1,
                    s: 1,
                    db: 1,
                    g: 1,
                    ..Default::default()
                };
                let data = kvm_bindings::kvm_segment {
                    base: 0,
                    limit: u32::MAX,
                    selector: 16,
                    type_: 3,
                    present: 1,
                    s: 1,
                    db: 1,
                    g: 1,
                    ..Default::default()
                };
                special.ds = data;
                special.es = data;
                special.fs = data;
                special.gs = data;
                special.ss = data;
                special.cr0 = (special.cr0 & !((1 << 2) | (1 << 3))) | 1;
                special.cr4 |= (1 << 9) | (1 << 10) | (1 << 18);
                cpu.set_sregs(&special).unwrap();
                let mut xcrs = cpu.get_xcrs().unwrap();
                xcrs.xcrs[0].value = 7;
                cpu.set_xcrs(&xcrs).unwrap();
                let mut regs = cpu.get_regs().unwrap();
                regs.rip = 0x1000;
                regs.rflags = 2;
                regs.rax = 0x1234_5678 + u64::from(id);
                regs.rbx = 0xab00 + u64::from(id);
                regs.r12 = 0xcafe_0000 + u64::from(id);
                cpu.set_regs(&regs).unwrap();
                let mut debug = cpu.get_debug_regs().unwrap();
                debug.db[0] = 0x10_000 + u64::from(id) * 16;
                cpu.set_debug_regs(&debug).unwrap();
                let mut native = super::xsave::Image::read(&vm, &cpu).unwrap();
                let mut public = crate::vm::vcpu::Registers::default();
                native.layout.project(&native.bytes, &mut public).unwrap();
                public.xmm[0][0] = 0xface_0000 + u64::from(id);
                public.ymm_high[0][0] = 0xfeed_0000 + u64::from(id);
                native.bytes = native.layout.overlay(&native.bytes, &public).unwrap();
                native.write(&vm, &cpu).unwrap();
                cpu.set_mp_state(kvm_bindings::kvm_mp_state {
                    mp_state: kvm_bindings::KVM_MP_STATE_RUNNABLE,
                })
                .unwrap();
            }
            cpus.push(cpu);
            profiles.push(profile);
        }
        Self {
            cpus,
            profiles,
            vm,
            kvm,
            _ram: ram,
        }
    }

    fn capture(&self, irqchip: bool) -> Vec<Image> {
        self.cpus
            .iter()
            .enumerate()
            .map(|(id, cpu)| {
                Image::capture(
                    &self.kvm,
                    &self.vm,
                    cpu,
                    id as u32,
                    &self.profiles[id],
                    irqchip,
                )
                .unwrap_or_else(|error| panic!("capture CPU{id}, irqchip={irqchip}: {error}"))
            })
            .collect()
    }
}

fn stored_json(image: &Image) -> serde_json::Value {
    let mut value = serde_json::to_value(image).unwrap();
    // The independent coordinated-clock producer retains these values. This
    // CPU-bank equality check explicitly excludes advancing counters only.
    value["msrs"]["counters"] = serde_json::Value::Null;
    value
}

fn flip_cpuid(value: &mut serde_json::Value, leaf: u32, register: usize, mask: u32) {
    for record in value["observed_cpuid"].as_array_mut().unwrap() {
        let bank: bank::Bank<kvm_bindings::kvm_cpuid_entry2> =
            serde_json::from_value(record.clone()).unwrap();
        let mut entry = bank.decode().unwrap();
        if entry.function == leaf && entry.index == 0 {
            match register {
                0 => entry.eax ^= mask,
                1 => entry.ebx ^= mask,
                2 => entry.ecx ^= mask,
                3 => entry.edx ^= mask,
                _ => unreachable!(),
            }
            *record = serde_json::to_value(bank::Bank::capture(&entry).unwrap()).unwrap();
            return;
        }
    }
    panic!("required probe CPUID leaf {leaf:#x} is absent");
}

fn nested_continuation() -> serde_json::Value {
    let mut source = Graph::new(1, false, false);
    // SAFETY: the retained independent helper exclusively configures and
    // enters this stopped CPU and private RAM. Its writes stay below 0x10008,
    // within RAM_BYTES. No Rust run-buffer or RAM reference is live; it drops
    // its own run mapping before return and retains no descriptor or pointer.
    assert_eq!(
        unsafe {
            enter_vmx_for_rust(
                source.kvm.as_raw_fd(),
                source.cpus[0].as_raw_fd(),
                source._ram.0.cast(),
            )
        },
        0
    );
    // The independent setup installs its own raw SDK profile. Preserve that
    // actual configuration explicitly; do not attribute it to managed CPUID
    // policy. Each disposable target installs this identical profile first.
    let profile = source.cpus[0]
        .get_cpuid2(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
        .unwrap();
    source.profiles[0] = profile.clone();
    let image = source.capture(false).remove(0);
    let json = serde_json::to_vec(&image).unwrap();
    let binary = crate::codec::serialize(&image).unwrap();
    // SAFETY: no CPU runs and the owned live mapping covers this entire copy.
    // The copied Vec outlives source destruction and contains no native pointer.
    let ram = unsafe { std::slice::from_raw_parts(source._ram.0.cast::<u8>(), RAM_BYTES) }.to_vec();
    let original = stored_json(&image);
    drop(image);
    drop(source);
    for codec in 0..2 {
        let image: Image = if codec == 0 {
            serde_json::from_slice(&json).unwrap()
        } else {
            crate::codec::deserialize_strict(&binary).unwrap()
        };
        let mut target = Graph::new(1, false, false);
        target.cpus[0].set_cpuid2(&profile).unwrap();
        target.profiles[0] = profile.clone();
        // SAFETY: the stopped destination mapping is private, live and exactly
        // RAM_BYTES long. No native entry, Rust RAM reference or aliasing writer
        // exists. Source Vec and destination mapping are disjoint allocations.
        unsafe {
            std::ptr::copy_nonoverlapping(ram.as_ptr(), target._ram.0.cast::<u8>(), RAM_BYTES)
        };
        image
            .restore_stored(
                &target.kvm,
                &target.vm,
                &target.cpus[0],
                0,
                &target.profiles[0],
                false,
            )
            .unwrap();
        let restored = target.capture(false).remove(0);
        assert_eq!(stored_json(&restored), original);
        match target.cpus[0].run().unwrap() {
            VcpuExit::IoOut(0x81, data) => assert_eq!(data, &[2]),
            exit => panic!("combined nested continuation: {exit:?}"),
        }
        assert_eq!(target.cpus[0].get_regs().unwrap().rax & 0x41, 0);
        // SAFETY: CPU is stopped at OUT and each unaligned initialized u64
        // lies inside the owned RAM mapping. No reference escapes these reads.
        unsafe {
            assert_eq!(
                std::ptr::read_unaligned(target._ram.0.cast::<u8>().add(0x6010).cast::<u64>()),
                0x9000
            );
            assert_eq!(
                std::ptr::read_unaligned(target._ram.0.cast::<u8>().add(0x6020).cast::<u64>()),
                0x4142_4344_4546_4748
            );
        }
        // This particular immediate-OUT frontier is finite and represented in
        // the independent probe. It does not establish generic MMIO settling.
        target.cpus[0].set_kvm_immediate_exit(1);
        assert_eq!(target.cpus[0].run().unwrap_err().errno(), libc::EINTR);
        target.cpus[0].set_kvm_immediate_exit(0);
        assert!(matches!(target.cpus[0].run().unwrap(), VcpuExit::Hlt));
    }
    serde_json::json!({"source_free_combined_restores":2,"vmcs_guest_rip":0x4142_4344_4546_4748u64,"loaded_vmcs_gpa":0x9000,"active_l2_exercised":false})
}

pub(crate) fn probe() {
    let mut counts = serde_json::json!({"graphs":0,"source_free_cpu_restores":0,"guest_outputs":0,"negative_controls":0});
    for count in [1, 2, 4] {
        for irqchip in [false, true] {
            let source = Graph::new(count, irqchip, true);
            let images = source.capture(irqchip);
            let originals: Vec<_> = images.iter().map(stored_json).collect();
            let json = serde_json::to_vec(&images).unwrap();
            let binary = crate::codec::serialize(&images).unwrap();
            drop(images);
            drop(source); // No native source FD or RAM mapping survives decode.
            for codec in 0..2 {
                let images: Vec<Image> = if codec == 0 {
                    serde_json::from_slice(&json).unwrap()
                } else {
                    crate::codec::deserialize_strict(&binary).unwrap()
                };
                let mut target = Graph::new(count, irqchip, false);
                for (id, image) in images.iter().enumerate() {
                    let before = stored_json(
                        &Image::capture(
                            &target.kvm,
                            &target.vm,
                            &target.cpus[id],
                            id as u32,
                            &target.profiles[id],
                            irqchip,
                        )
                        .unwrap(),
                    );
                    for case in 0..25 {
                        let mut bad = serde_json::to_value(image).unwrap();
                        match case {
                            0 => bad["version"] = serde_json::json!(2),
                            1 => bad["id"] = serde_json::json!(id + 100),
                            2 => bad["irqchip"] = serde_json::json!(!irqchip),
                            3 => bad["profile"] = serde_json::json!([]),
                            4 => bad["xsave"]["layout"]["size"] = serde_json::json!(4095),
                            5 => {
                                bad["msrs"]["registers"][0]["index"] =
                                    serde_json::json!(0xffff_ffffu32)
                            }
                            6 => bad["nested_capacity"] = serde_json::json!(0xffff_ffffu32),
                            7 => bad["events"]["bytes"] = serde_json::json!([]),
                            8 => flip_cpuid(&mut bad, 1, 2, 1 << 27),
                            9 => flip_cpuid(&mut bad, 1, 3, 1 << 9),
                            10 => flip_cpuid(&mut bad, 7, 2, 1 << 4),
                            11 => flip_cpuid(&mut bad, 0xd, 1, 64),
                            12 => flip_cpuid(&mut bad, 0xd, 1, 1),
                            13 => flip_cpuid(&mut bad, 1, 1, 1 << 24),
                            14 => flip_cpuid(&mut bad, 0x4000_0001, 0, 1 << 2),
                            15 => {
                                let bank: bank::Bank<kvm_bindings::kvm_xcrs> =
                                    serde_json::from_value(bad["xcrs"].clone()).unwrap();
                                let mut xcrs = bank.decode().unwrap();
                                xcrs.nr_xcrs = 17;
                                bad["xcrs"] =
                                    serde_json::to_value(bank::Bank::capture(&xcrs).unwrap())
                                        .unwrap();
                            }
                            16 => {
                                let bank: bank::Bank<kvm_bindings::kvm_sregs> =
                                    serde_json::from_value(bad["special"].clone()).unwrap();
                                let mut special = bank.decode().unwrap();
                                special.cr2 ^= 0x1000;
                                bad["special"] =
                                    serde_json::to_value(bank::Bank::capture(&special).unwrap())
                                        .unwrap();
                            }
                            17 => bad["xsave"]["bytes"][519] = serde_json::json!(128),
                            18 => bad["nested"]["bytes"][4] = serde_json::json!(0),
                            19 => bad["regs"]["version"] = serde_json::json!(2),
                            20 => {
                                bad["profile"] = serde_json::json!(vec![
                                    bad["profile"][0].clone();
                                    kvm_bindings::KVM_MAX_CPUID_ENTRIES
                                        + 1
                                ])
                            }
                            21 => {
                                bad["xsave"]["layout"]["components"] = serde_json::json!(vec![
                                        bad["xsave"]["layout"]["components"][0]
                                            .clone();
                                        62
                                    ])
                            }
                            22 => {
                                bad["msrs"]["registers"] = serde_json::json!(vec![
                                        bad["msrs"]["registers"][0].clone();
                                        kvm_bindings::KVM_MAX_MSR_ENTRIES + 1
                                    ])
                            }
                            23 => bad["nested"]["bytes"] = serde_json::json!(vec![0; 8321]),
                            24 => flip_cpuid(&mut bad, 0x4000_0001, 0, 1 << 7),
                            _ => unreachable!(),
                        }
                        if let Ok(bad) = serde_json::from_value::<Image>(bad) {
                            assert!(
                                bad.restore_stored(
                                    &target.kvm,
                                    &target.vm,
                                    &target.cpus[id],
                                    id as u32,
                                    &target.profiles[id],
                                    irqchip
                                )
                                .is_err(),
                                "case {case}"
                            );
                        }
                        let after = Image::capture(
                            &target.kvm,
                            &target.vm,
                            &target.cpus[id],
                            id as u32,
                            &target.profiles[id],
                            irqchip,
                        )
                        .unwrap();
                        assert_eq!(
                            stored_json(&after),
                            before,
                            "case {case} mutated a destination bank"
                        );
                        counts["negative_controls"] =
                            serde_json::json!(counts["negative_controls"].as_u64().unwrap() + 1);
                    }
                    image
                        .restore_stored(
                            &target.kvm,
                            &target.vm,
                            &target.cpus[id],
                            id as u32,
                            &target.profiles[id],
                            irqchip,
                        )
                        .unwrap_or_else(|error| {
                            panic!("restore CPU{id}, irqchip={irqchip}: {error}")
                        });
                    let restored = Image::capture(
                        &target.kvm,
                        &target.vm,
                        &target.cpus[id],
                        id as u32,
                        &target.profiles[id],
                        irqchip,
                    )
                    .unwrap();
                    assert_eq!(
                        stored_json(&restored),
                        originals[id],
                        "stored CPU bank mismatch for id {id}, irqchip {irqchip}"
                    );
                    let public = restored.public().unwrap().0;
                    assert_eq!(public.regs.rax, 0x1234_5678 + id as u64);
                    assert_eq!(public.regs.rbx, 0xab00 + id as u64);
                    assert_eq!(public.regs.r12, 0xcafe_0000 + id as u64);
                    assert_eq!(public.regs.xmm[0][0] as u32, 0xface_0000 + id as u32);
                    assert_eq!(public.sregs.dr0, 0x10_000 + id as u64 * 16);
                    counts["source_free_cpu_restores"] =
                        serde_json::json!(counts["source_free_cpu_restores"].as_u64().unwrap() + 1);
                }
                for (id, cpu) in target.cpus.iter_mut().enumerate() {
                    match cpu.run().unwrap() {
                        VcpuExit::IoOut(0xe9, data) => {
                            assert_eq!(data, &(0xface_0000 + id as u32).to_le_bytes())
                        }
                        exit => panic!("CPU{id} first continuation: {exit:?}"),
                    }
                    match cpu.run().unwrap() {
                        VcpuExit::IoOut(0xea, data) => {
                            assert_eq!(data, &(0xab00 + id as u16).to_le_bytes())
                        }
                        exit => panic!("CPU{id} second continuation: {exit:?}"),
                    }
                    match cpu.run().unwrap() {
                        VcpuExit::IoOut(0xeb, data) => {
                            assert_eq!(data, &(0xfeed_0000 + id as u32).to_le_bytes())
                        }
                        exit => panic!("CPU{id} third continuation: {exit:?}"),
                    }
                    // In-kernel IRQchip HLT sleeps inside KVM until a wake event.
                    // This guest-output probe does not manufacture one. The
                    // disposable target closes after the third observed OUT.
                    if !irqchip {
                        assert!(matches!(cpu.run().unwrap(), VcpuExit::Hlt));
                    }
                    counts["guest_outputs"] =
                        serde_json::json!(counts["guest_outputs"].as_u64().unwrap() + 3);
                }
            }
            counts["graphs"] = serde_json::json!(counts["graphs"].as_u64().unwrap() + 1);
        }
    }
    counts["nested"] = nested_continuation();
    println!("{}", serde_json::to_string_pretty(&counts).unwrap());
}
