use super::memory_layout;
#[path = "../../../../src/backend/hvf/native_memory.rs"]
mod native_memory;
use rax::devices::bus::{IoDevice, MmioDevice, MmioRange};
use rax::devices::pci::{Bar, ConfigSpace, PciStub};
use rax::vm::memory::GuestMemoryWrapper;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, mpsc};
use vm_memory::{GuestMemory, GuestMemoryRegion};

static SERIAL: Mutex<()> = Mutex::new(());
static SDK: Mutex<Sdk> = Mutex::new(Sdk::new());
struct Sdk {
    pages: BTreeSet<u64>,
    calls: usize,
    fail: Option<usize>,
    entries: Vec<(u32, BTreeSet<u64>)>,
    backing: usize,
    reported: u64,
    pause: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
}
impl Sdk {
    const fn new() -> Self {
        Self {
            pages: BTreeSet::new(),
            calls: 0,
            fail: None,
            entries: Vec::new(),
            backing: 0,
            reported: 0,
            pause: None,
        }
    }
}
#[allow(non_camel_case_types)]
mod bindings {
    use super::SDK;
    pub type hv_vcpuid_t = u32;
    pub type hv_return_t = i32;
    pub const HV_SUCCESS: i32 = 0;
    pub const HV_MEMORY_READ: u64 = 1;
    pub const HV_MEMORY_WRITE: u64 = 2;
    pub const HV_MEMORY_EXEC: u64 = 4;
    pub fn hv_error_string(_: i32) -> &'static str {
        "owned SDK fault"
    }
    pub unsafe fn hv_vm_map(
        pointer: *mut std::ffi::c_void,
        address: u64,
        size: usize,
        flags: u64,
    ) -> i32 {
        let mut sdk = SDK.lock().unwrap();
        assert_eq!(flags, 7);
        assert_eq!(pointer as usize, sdk.backing + address as usize);
        assert!(address + size as u64 <= sdk.reported);
        sdk.calls += 1;
        if sdk.fail == Some(sdk.calls) {
            return -1;
        }
        for page in (address..address + size as u64).step_by(4096) {
            assert!(sdk.pages.insert(page));
        }
        0
    }
    pub unsafe fn hv_vm_unmap(address: u64, size: usize) -> i32 {
        let mut sdk = SDK.lock().unwrap();
        sdk.calls += 1;
        if sdk.fail == Some(sdk.calls) {
            return -1;
        }
        for page in (address..address + size as u64).step_by(4096) {
            assert!(sdk.pages.remove(&page));
        }
        0
    }
    pub unsafe fn hv_vcpu_run(id: u32) -> i32 {
        let pause = {
            let mut sdk = SDK.lock().unwrap();
            let pages = sdk.pages.clone();
            sdk.entries.push((id, pages));
            sdk.pause.take()
        };
        if let Some((entered, release)) = pause {
            entered.send(()).unwrap();
            release
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
        }
        0
    }
}
fn backing() -> GuestMemoryWrapper {
    let memory = GuestMemoryWrapper::new(0x10000).unwrap();
    let mut sdk = SDK.lock().unwrap();
    *sdk = Sdk::new();
    sdk.backing = memory.memory().iter().next().unwrap().as_ptr() as usize;
    sdk.reported = memory.size();
    memory
}
struct Device;
impl MmioDevice for Device {
    fn read(&mut self, _: u64, bytes: &mut [u8]) {
        bytes.fill(0xab);
    }
    fn write(&mut self, _: u64, _: &[u8]) {}
}
fn bridge() -> Arc<Mutex<PciStub>> {
    let mut pci = PciStub::new();
    let mut config = ConfigSpace::device(0x1234, 0xabcd, 0, 0).with_bar(0, Bar::mem32(32));
    config.set_u32(0x10, 0x2020);
    config.set_u16(4, 2);
    pci.attach_mmio(0, 1, 0, config, 0, Box::new(Device));
    Arc::new(Mutex::new(pci))
}
fn config_write(pci: &Arc<Mutex<PciStub>>, offset: u8, value: u32) {
    let mut pci = pci.lock().unwrap();
    for (i, byte) in (0x8000_0800u32 | u32::from(offset))
        .to_le_bytes()
        .iter()
        .enumerate()
    {
        IoDevice::write(&mut *pci, 0xcf8 + i as u16, *byte);
    }
    for (i, byte) in value.to_le_bytes().iter().enumerate() {
        IoDevice::write(&mut *pci, 0xcfc + i as u16, *byte);
    }
}

#[test]
fn real_adapter_registers_reported_ram_and_rejects_changed_registration() {
    let _serial = SERIAL.lock().unwrap();
    let memory = backing();
    let shared = native_memory::Shared::default();
    assert!(native_memory::validate_cpu_backing(&shared, memory.memory()).is_err());
    native_memory::register(&shared, &memory, &[], None).unwrap();
    native_memory::validate_cpu_backing(&shared, memory.memory()).unwrap();
    assert_eq!(SDK.lock().unwrap().pages.len(), 16);
    native_memory::register(&shared, &memory, &[], None).unwrap();
    assert_eq!(SDK.lock().unwrap().calls, 1);
    assert!(
        native_memory::register(
            &shared,
            &memory,
            &[MmioRange {
                base: 0x2020,
                len: 32
            }],
            None
        )
        .is_err()
    );
    let other = GuestMemoryWrapper::new(0x10000).unwrap();
    assert!(native_memory::validate_cpu_backing(&shared, other.memory()).is_err());
    assert!(
        !shared
            .read()
            .unwrap()
            .as_ref()
            .unwrap()
            .matches_backing(other.memory())
    );
    assert!(native_memory::register(&shared, &other, &[], None).is_err());
    native_memory::enter(&shared, 7).unwrap();
    assert_eq!(SDK.lock().unwrap().entries[0].0, 7);
}

#[test]
fn real_entry_adapter_reconciles_bar_relocation_disable_and_checkpoint_restore() {
    let _serial = SERIAL.lock().unwrap();
    let memory = backing();
    let shared = native_memory::Shared::default();
    let pci = bridge();
    let checkpoint = pci.lock().unwrap().checkpoint().unwrap();
    native_memory::register(&shared, &memory, &[], Some(pci.clone())).unwrap();
    native_memory::enter(&shared, 0).unwrap();
    assert!(!SDK.lock().unwrap().pages.contains(&0x2000));
    let calls = SDK.lock().unwrap().calls;
    config_write(&pci, 0x10, 0x2040);
    native_memory::enter(&shared, 0).unwrap();
    assert_eq!(
        SDK.lock().unwrap().calls,
        calls,
        "same-page BAR relocation changes metadata only"
    );
    assert!(
        shared
            .read()
            .unwrap()
            .as_ref()
            .unwrap()
            .mapping
            .layout
            .contains_logical(0x2020, 32)
    );
    assert!(
        !shared
            .read()
            .unwrap()
            .as_ref()
            .unwrap()
            .mapping
            .layout
            .contains_logical(0x2040, 1)
    );
    config_write(&pci, 0x10, 0x7020);
    native_memory::enter(&shared, 1).unwrap();
    assert!(SDK.lock().unwrap().pages.contains(&0x2000));
    assert!(!SDK.lock().unwrap().pages.contains(&0x7000));
    config_write(&pci, 4, 0);
    native_memory::enter(&shared, 0).unwrap();
    assert_eq!(SDK.lock().unwrap().pages.len(), 16);
    pci.lock().unwrap().restore_checkpoint(checkpoint).unwrap();
    native_memory::enter(&shared, 1).unwrap();
    assert!(!SDK.lock().unwrap().pages.contains(&0x2000));
    assert!(SDK.lock().unwrap().pages.contains(&0x7000));
    assert_eq!(SDK.lock().unwrap().entries.len(), 5);
}

#[test]
fn live_bar_map_failure_rolls_back_and_blocks_all_subsequent_entries() {
    let _serial = SERIAL.lock().unwrap();
    let memory = backing();
    let shared = native_memory::Shared::default();
    let pci = bridge();
    native_memory::register(&shared, &memory, &[], Some(pci.clone())).unwrap();
    native_memory::enter(&shared, 0).unwrap();
    let old = SDK.lock().unwrap().pages.clone();
    config_write(&pci, 0x10, 0x7020);
    {
        let mut sdk = SDK.lock().unwrap();
        sdk.fail = Some(sdk.calls + 2);
    }
    assert!(native_memory::enter(&shared, 1).is_err());
    assert_eq!(SDK.lock().unwrap().pages, old);
    let calls = SDK.lock().unwrap().calls;
    assert!(native_memory::enter(&shared, 0).is_err());
    let retained = shared.read().unwrap().as_ref().unwrap().backing.clone();
    assert!(native_memory::validate_cpu_backing(&shared, &retained).is_err());
    assert_eq!(SDK.lock().unwrap().calls, calls);
    assert_eq!(SDK.lock().unwrap().entries.len(), 1);
}

#[test]
fn real_adapter_retains_backing_and_blocks_entry_after_native_map_error() {
    let _serial = SERIAL.lock().unwrap();
    let memory = backing();
    let shared = native_memory::Shared::default();
    SDK.lock().unwrap().fail = Some(2);
    assert!(
        native_memory::register(
            &shared,
            &memory,
            &[MmioRange {
                base: 0x2020,
                len: 32
            }],
            None
        )
        .is_err()
    );
    drop(memory);
    assert!(
        shared
            .read()
            .unwrap()
            .as_ref()
            .unwrap()
            .backing
            .iter()
            .next()
            .is_some()
    );
    assert!(native_memory::enter(&shared, 0).is_err());
    assert!(SDK.lock().unwrap().entries.is_empty());
}

#[test]
fn rejected_pci_layout_never_publishes_registration_or_turns_retry_into_success() {
    let _serial = SERIAL.lock().unwrap();
    let memory = backing();
    let shared = native_memory::Shared::default();
    let pci = bridge();
    let other = pci.clone();
    assert!(
        std::thread::spawn(move || {
            let _guard = other.lock().unwrap();
            panic!("owned PCI admission poison");
        })
        .join()
        .is_err()
    );
    for _ in 0..2 {
        assert!(native_memory::register(&shared, &memory, &[], Some(pci.clone())).is_err());
        assert!(shared.read().unwrap().is_none());
        assert_eq!(SDK.lock().unwrap().calls, 0);
        assert!(native_memory::validate_cpu_backing(&shared, memory.memory()).is_err());
    }
}

#[test]
fn real_adapter_holds_shared_mapping_guard_for_the_entire_native_entry() {
    let _serial = SERIAL.lock().unwrap();
    let memory = backing();
    let shared = native_memory::Shared::default();
    native_memory::register(&shared, &memory, &[], None).unwrap();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    SDK.lock().unwrap().pause = Some((entered_tx, release_rx));
    let other = shared.clone();
    let entry = std::thread::spawn(move || native_memory::enter(&other, 3));
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    assert!(shared.try_write().is_err());
    release_tx.send(()).unwrap();
    entry.join().unwrap().unwrap();
    assert!(shared.try_write().is_ok());
}
