mod bank;
mod codec;
mod sregs2;

use kvm_bindings::{kvm_sregs2, kvm_userspace_memory_region};
use kvm_ioctls::{Kvm, VcpuFd, VmFd};
use std::os::fd::AsRawFd;

const RAM_BYTES: usize = 0x20_000;

struct Ram(*mut libc::c_void);

impl Ram {
    fn new() -> Self {
        // SAFETY: anonymous private mmap creates RAM_BYTES writable initialized
        // bytes, aligned to the host page size. No file or borrowed pointer is
        // supplied. Failure is checked before any access or KVM registration.
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
        Self(pointer)
    }
}

impl Drop for Ram {
    fn drop(&mut self) {
        // SAFETY: this is the original mmap allocation and exact byte count.
        // Graph drops every vCPU and VM FD before this field. No native owner
        // or escaped reference can still access or register these bytes.
        assert_eq!(unsafe { libc::munmap(self.0, RAM_BYTES) }, 0);
    }
}

// Fields drop in declaration order; RAM outlives every KVM memory reference.
struct Graph {
    cpus: Vec<VcpuFd>,
    _vm: VmFd,
    _kvm: Kvm,
    _ram: Ram,
}

impl Graph {
    fn new(count: u32, irqchip: bool) -> Self {
        let ram = Ram::new();
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        assert!(vm.check_extension_raw(kvm_bindings::KVM_CAP_SREGS2.into()) > 0);
        if irqchip {
            vm.create_irq_chip().unwrap();
        }
        // SAFETY: ram is page-aligned, initialized, writable and RAM_BYTES
        // long. Only this single nonoverlapping slot is registered. Graph owns
        // the mapping until every vCPU and VM FD has been dropped; no guest
        // entry or concurrent access occurs in this probe.
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
        let cpus = (0..count)
            .map(|id| {
                let cpu = vm.create_vcpu(u64::from(id)).unwrap();
                cpu.set_cpuid2(&supported).unwrap();
                cpu
            })
            .collect();
        Self {
            cpus,
            _vm: vm,
            _kvm: kvm,
            _ram: ram,
        }
    }
}

fn get(cpu: &VcpuFd) -> kvm_sregs2 {
    let mut value = kvm_sregs2::default();
    // SAFETY: the retained x86 UAPI defines GET_SREGS2 and this output type.
    // The stopped CPU FD and aligned initialized exclusive output remain live
    // throughout the synchronous ioctl. The kernel retains no pointer.
    let result = unsafe {
        libc::ioctl(
            cpu.as_raw_fd(),
            libc::_IOR::<kvm_sregs2>(kvm_bindings::KVMIO, 0xcc),
            &mut value as *mut kvm_sregs2,
        )
    };
    assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
    value
}

fn set(cpu: &VcpuFd, value: &kvm_sregs2) {
    // SAFETY: the retained x86 UAPI defines SET_SREGS2 and this input type.
    // The stopped CPU FD and aligned initialized input stay live and borrowed
    // for the synchronous ioctl; no pointer escapes or overlaps mutable data.
    let result = unsafe {
        libc::ioctl(
            cpu.as_raw_fd(),
            libc::_IOW::<kvm_sregs2>(kvm_bindings::KVMIO, 0xcd),
            value as *const kvm_sregs2,
        )
    };
    assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
}

fn reject(value: serde_json::Value) -> bool {
    match serde_json::from_value::<sregs2::Image>(value) {
        Err(_) => true,
        Ok(image) => image.decode().is_err(),
    }
}

fn main() {
    for irqchip in [false, true] {
        for count in [1u32, 2, 4] {
            let images = {
                let source = Graph::new(count, irqchip);
                let images: Vec<_> = source
                    .cpus
                    .iter()
                    .enumerate()
                    .map(|(id, cpu)| {
                        let mut value = get(cpu);
                        value.cr0 |= (1 << 31) | 1;
                        value.cr4 |= 1 << 5;
                        value.cr3 = 0x2000;
                        value.cr2 = 0x1234_5600 | id as u64;
                        value.flags = u64::from(kvm_bindings::KVM_SREGS2_FLAGS_PDPTRS_VALID);
                        value.pdptrs = [0x3001 + (id as u64) * 0x1000, 0, 0, 0];
                        set(cpu, &value);
                        let observed = get(cpu);
                        assert_eq!(observed, value);
                        (sregs2::Image::capture(&observed).unwrap(), observed)
                    })
                    .collect();
                drop(source);
                images
            };
            let target = Graph::new(count, irqchip);
            let mut malformed = 0;
            let mut legacy_losses = 0;
            let mut restores = 0;
            for ((image, expected), cpu) in images.iter().zip(&target.cpus) {
                let json = serde_json::to_value(image).unwrap();
                let encoded = codec::serialize(image).unwrap();
                let binary: sregs2::Image =
                    codec::deserialize_limited::<_, 8192>(&encoded).unwrap();
                let textual: sregs2::Image = serde_json::from_value(json.clone()).unwrap();
                // A legacy special-register setter reloads the intentionally
                // zero physical table instead of retaining cached PDPTRs.
                let mut legacy = cpu.get_sregs().unwrap();
                legacy.cr0 = expected.cr0;
                legacy.cr2 = expected.cr2;
                legacy.cr3 = expected.cr3;
                legacy.cr4 = expected.cr4;
                cpu.set_sregs(&legacy).unwrap();
                assert_ne!(get(cpu).pdptrs, expected.pdptrs);
                legacy_losses += 1;
                for restored in [binary, textual] {
                    assert_eq!(restored, *image);
                    let native = restored.decode().unwrap();
                    assert_eq!(native, *expected);
                    set(cpu, &native);
                    assert_eq!(get(cpu), *expected);
                    restores += 1;
                }
                let before = get(cpu);
                for case in 0..6 {
                    let mut bad = json.clone();
                    match case {
                        0 => bad["version"] = serde_json::json!(2),
                        1 => bad["flags"] = serde_json::json!(2),
                        2 => bad["common"]["kind"] = serde_json::json!(1),
                        3 => {
                            bad["common"]["bytes"].as_array_mut().unwrap().pop();
                        }
                        4 => bad["common"]["bytes"][280] = serde_json::json!(1),
                        5 => bad["unrecognized"] = serde_json::json!(0),
                        _ => unreachable!(),
                    }
                    assert!(reject(bad), "malformed case {case}");
                    assert_eq!(get(cpu), before);
                    malformed += 1;
                }
            }
            println!(
                "{}",
                serde_json::json!({
                    "cpu_count":count,"irqchip":irqchip,"source_cpus":images.len(),
                    "legacy_cache_losses_observed":legacy_losses,"source_free_exact_restores":restores,
                    "malformed_rejected_without_native_change":malformed,
                    "source_graph_destroyed_before_restore":true,"physical_table_zero":true,
                    "guest_entered":false,"full_cpu_producer":false
                })
            );
        }
    }
}
