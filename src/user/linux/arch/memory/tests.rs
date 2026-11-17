//! A failure during Linux's software MRS reread occurs after the architectural
//! CPU exit and must not be returned to the guest as SIGILL.

use super::LinuxAddressSpace;
use crate::error::{GuestMemoryFault, MemoryAccessKind, MemoryFaultKind};
use crate::user::cpu::CpuAddressSpace;
use crate::user::cpu::arm::A32AddressSpace;
use crate::user::cpu::memory::TraceMapping;
use crate::user::linux::abi::LinuxAbi;
use crate::user::linux::arch::{CpuEvent, CpuOptions, CpuWithSpace};
use crate::user::mm::{AddressSpace, CodeChanges, EXTENT, Mapping, PAGE_SIZE, Perms, SpaceConfig};
use crate::vm::memory::FlatTranslation;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use vm_memory::GuestMemoryMmap;

#[derive(Clone, Debug)]
struct ReadFailure {
    local: AddressSpace,
    failed: Arc<AtomicBool>,
    fatal: bool,
}

impl A32AddressSpace for ReadFailure {
    fn fatal_error(&self) -> Option<String> {
        (self.fatal && self.failed.load(Ordering::Acquire))
            .then(|| "injected owner instruction-reread failure".into())
    }

    fn read(&self, address: u64, bytes: &mut [u8]) -> Result<(), GuestMemoryFault> {
        self.failed.store(true, Ordering::Release);
        Err(GuestMemoryFault {
            address,
            size: bytes.len() as u32,
            access: MemoryAccessKind::Read,
            kind: MemoryFaultKind::Other,
        })
    }

    fn write(&self, address: u64, bytes: &[u8]) -> Result<(), GuestMemoryFault> {
        self.local.write(address, bytes)
    }

    fn fetch(&self, address: u64, bytes: &mut [u8]) -> Result<(), GuestMemoryFault> {
        self.local.fetch(address, bytes)
    }
}

impl FlatTranslation for ReadFailure {
    fn translate(&self, address: u64, access: MemoryAccessKind) -> Result<u64, GuestMemoryFault> {
        self.local.translate(address, access)
    }
}

impl CpuAddressSpace for ReadFailure {
    fn physical_memory(&self) -> &Arc<GuestMemoryMmap> {
        self.local.physical_memory()
    }
    fn code_epoch(&self) -> u64 {
        self.local.code_epoch()
    }
    fn code_changes_since(&self, epoch: u64) -> (CodeChanges, u64) {
        self.local.code_changes_since(epoch)
    }
    fn probe(
        &self,
        address: u64,
        len: usize,
        access: MemoryAccessKind,
    ) -> Result<(), GuestMemoryFault> {
        self.local.probe(address, len, access)
    }
    fn trace_mappings(&self) -> Vec<TraceMapping> {
        self.local.trace_mappings()
    }
}

impl LinuxAddressSpace for ReadFailure {
    fn resident_accessible(&self, address: u64) -> Result<bool, String> {
        self.local.resident_accessible(address)
    }
}

#[test]
fn a64_cpuid_reread_failure_returns_internal_without_delivering_sigill() {
    const ENTRY: u64 = 0x10000;
    let local = AddressSpace::new(SpaceConfig {
        va_limit: 1 << 47,
        arena_bytes: 8 * EXTENT,
        reserved_phys: vec![(PAGE_SIZE, PAGE_SIZE)],
    })
    .unwrap();
    local
        .map(
            ENTRY,
            PAGE_SIZE,
            Mapping::anonymous(Perms::READ | Perms::WRITE | Perms::EXEC),
        )
        .unwrap();
    // MRS X0,MIDR_EL1: Linux advertises HWCAP_CPUID and emulates this
    // privileged-register fault after rereading the instruction from userspace.
    local.write(ENTRY, &0xd538_0000u32.to_le_bytes()).unwrap();
    let memory = ReadFailure {
        local,
        failed: Arc::new(AtomicBool::new(false)),
        fatal: true,
    };
    let mut cpu = CpuWithSpace::with_space(LinuxAbi::Aarch64, &memory, &CpuOptions::default());
    cpu.start(ENTRY, ENTRY + PAGE_SIZE);
    let event = cpu.run(1);
    assert!(
        memory.failed.load(Ordering::Acquire),
        "the Linux CPUID emulation reread actually ran"
    );
    assert_eq!(
        event,
        CpuEvent::Internal("injected owner instruction-reread failure".into())
    );
    assert_eq!(
        cpu.pc(),
        ENTRY,
        "host failure must not retire the trapped MRS"
    );
    assert_eq!(
        cpu.syscall_return_value(),
        0,
        "host failure must not fabricate a result"
    );
}

#[test]
fn concrete_linux_cpu_function_items_require_no_storage_type_annotation() {
    let _new = crate::user::linux::arch::GuestCpu::new;
    let _run = crate::user::linux::arch::GuestCpu::run;
    let _step = crate::user::linux::arch::GuestCpu::step;
    let _clone = crate::user::linux::arch::GuestCpu::clone_thread;
}

#[test]
fn a64_cpuid_guest_reread_fault_retains_the_existing_sigill_result() {
    const ENTRY: u64 = 0x10000;
    let local = AddressSpace::new(SpaceConfig {
        va_limit: 1 << 47,
        arena_bytes: 8 * EXTENT,
        reserved_phys: vec![(PAGE_SIZE, PAGE_SIZE)],
    })
    .unwrap();
    local
        .map(
            ENTRY,
            PAGE_SIZE,
            Mapping::anonymous(Perms::READ | Perms::WRITE | Perms::EXEC),
        )
        .unwrap();
    local.write(ENTRY, &0xd538_0000u32.to_le_bytes()).unwrap();
    let memory = ReadFailure {
        local,
        failed: Arc::new(AtomicBool::new(false)),
        fatal: false,
    };
    let mut cpu = CpuWithSpace::with_space(LinuxAbi::Aarch64, &memory, &CpuOptions::default());
    cpu.start(ENTRY, ENTRY + PAGE_SIZE);
    let event = cpu.run(1);
    assert!(memory.failed.load(Ordering::Acquire));
    assert!(memory.fatal_error().is_none());
    assert!(matches!(event, CpuEvent::Signal(info, _)
        if info.signo == crate::user::linux::signal::SIGILL
            && info.code == crate::user::linux::signal::code::ILL_ILLOPC));
    assert_eq!(cpu.pc(), ENTRY);
    assert_eq!(cpu.syscall_return_value(), 0);
}
