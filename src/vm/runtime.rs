use std::sync::Arc;
#[cfg(feature = "debug")]
use std::sync::mpsc::TryRecvError;

use tracing::{debug, info};
use vm_memory::Bytes;

#[cfg(all(feature = "hvf", target_os = "macos", target_arch = "x86_64"))]
use crate::backend::hvf::HvfVm;
#[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
use crate::backend::kvm::KvmVm;
use crate::backend::{self, Vm};
use crate::config::{ArchKind, BackendKind, CheckpointConfig, VmConfig};
#[cfg(feature = "debug")]
use crate::debug::gdb::{self, GdbCommand, GdbResponse, VmmGdbChannels};
use crate::devices::bus::{IoBus, IoDevice, IoRange, MmioBus, MmioRange, SharedIoDevice};
use crate::devices::lapic::{
    IpiRequest, IpiTarget, LAPIC_BASE, LAPIC_SIZE, LapicDevice, LocalApic,
};
use crate::devices::pci::{PCI_CONFIG_ADDRESS, PciStub};
use crate::devices::pic::{DualPic, MasterPicDevice, SlavePicDevice};
use crate::devices::pit::Pit;
use crate::devices::pl011::{Pl011, Pl011MmioDevice};
use crate::devices::s3c64xx::S3cUart;
use crate::devices::serial::{Serial16550, SerialMmioDevice};
use crate::error::{Error, Result};
use crate::host::console::{Console, ConsoleAction, ESCAPE_HELP};
use crate::host::terminal::RawTty;
use crate::machine::{
    self, ArmBootInfo, BootInfo, HexagonBootInfo, Machine, RiscVBootInfo, X86_64BootInfo,
};
use crate::vm::memory::GuestMemoryWrapper;
use crate::vm::snapshot::{
    DEFAULT_CHECKPOINT_FILE, DeviceState, EmulatorState, Snapshot, SnapshotConfig,
};
use crate::vm::vcpu::{CpuState, VCpu, VcpuExit};

const SERIAL_BASE: u16 = 0x3f8;

/// Physical aperture diverted from RAM to PCI BAR-mapped MMIO when the optional
/// PCI devices are attached. Chosen high (just below the IOAPIC/HPET/LAPIC fixed
/// MMIO at 0xFEC00000+) so it sits above the guest's RAM and per-CPU overflow
/// window, and inside the 32-bit PCI memory window the kernel advertises.
const PCI_MMIO_AP_BASE: u64 = 0xFC00_0000;
const PCI_MMIO_AP_END: u64 = 0xFE00_0000;

/// Set by the SIGUSR1 handler to request a checkpoint from the run loop. This is
/// the non-keyboard "event" trigger: `kill -USR1 <pid>` dumps a checkpoint to
/// the configured `--snapshot-out` path, the same as the `Ctrl-A s` hotkey.
static CHECKPOINT_SIGNAL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn sigusr1_handler(_sig: libc::c_int) {
    CHECKPOINT_SIGNAL.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// A zeroed [`BootInfo`] for the given arch, used when resuming from a
/// checkpoint (where no kernel is loaded, so there is no real boot info — the
/// machine state comes entirely from the checkpoint).
fn null_boot_info(arch: ArchKind) -> BootInfo {
    match arch {
        ArchKind::Hexagon => BootInfo::Hexagon(HexagonBootInfo {
            entry_point: 0,
            load_addr: 0,
            image_size: 0,
        }),
        ArchKind::Riscv64 => BootInfo::RiscV(RiscVBootInfo {
            entry_point: 0,
            load_addr: 0,
            image_size: 0,
            tohost_addr: None,
        }),
        ArchKind::Aarch64
        | ArchKind::Armv7a
        | ArchKind::Armv8a32
        | ArchKind::CortexM
        | ArchKind::CortexR => BootInfo::Arm(ArmBootInfo {
            entry_point: 0,
            load_addr: 0,
            image_size: 0,
            dtb_addr: None,
            initial_sp: None,
        }),
        ArchKind::X86_64 => BootInfo::X86_64(X86_64BootInfo {
            entry_point: 0,
            boot_params_addr: vm_memory::GuestAddress(0),
            tss_addr: 0,
            identity_map_addr: 0,
            real_mode: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::any::Any;

    use vm_memory::GuestMemoryMmap;

    use super::*;
    use crate::vm::vcpu::VCpu;

    #[derive(Default)]
    struct RecordingVm {
        irq_calls: std::sync::Mutex<Vec<(u32, bool)>>,
    }

    impl Vm for RecordingVm {
        fn create_vcpu(&self, _id: u32, _mem: Arc<GuestMemoryMmap>) -> Result<Box<dyn VCpu>> {
            Err(Error::InvalidConfig("unused test vcpu".to_string()))
        }

        fn set_irq_line(&self, irq: u32, level: bool) -> Result<()> {
            self.irq_calls.lock().unwrap().push((irq, level));
            Ok(())
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn legacy_serial_irq_drives_pic_and_kvm_irq_line() {
        let vm = RecordingVm::default();
        let pic = Arc::new(std::sync::Mutex::new(DualPic::new()));

        drive_legacy_serial_irq(&vm, BackendKind::Kvm, &pic, Some(4), true);

        assert_eq!(vm.irq_calls.lock().unwrap().as_slice(), &[(4, true)]);
        let (master_irr, _, _, _, _, _) = pic.lock().unwrap().debug_info();
        assert_eq!(master_irr & (1 << 4), 1 << 4);
    }

    #[test]
    fn legacy_serial_irq_does_not_call_backend_for_emulator() {
        let vm = RecordingVm::default();
        let pic = Arc::new(std::sync::Mutex::new(DualPic::new()));

        drive_legacy_serial_irq(&vm, BackendKind::Emulator, &pic, Some(4), true);

        assert!(vm.irq_calls.lock().unwrap().is_empty());
        let (master_irr, _, _, _, _, _) = pic.lock().unwrap().debug_info();
        assert_eq!(master_irr & (1 << 4), 1 << 4);
    }
}

/// Guest-memory DMA adapter for the PCI device models (e.g. the NVMe/AHCI
/// admin/command queues). Wraps the guest RAM mmap behind the device models'
/// `virtio::Mem` trait so a bus-master device can read/write guest physical
/// memory; the same mmap the CPU sees, so DMA is coherent.
struct GuestDmaMem(Arc<vm_memory::GuestMemoryMmap>);

impl crate::devices::virtio::Mem for GuestDmaMem {
    fn read(&self, gpa: u64, buf: &mut [u8]) -> bool {
        self.0.read_slice(buf, vm_memory::GuestAddress(gpa)).is_ok()
    }
    fn write(&mut self, gpa: u64, buf: &[u8]) -> bool {
        crate::vm::memory::reservations::write(&self.0, gpa, buf).is_ok()
    }
}

/// AC'97 has two separate I/O BARs (the 16-bit codec mixer "NAM" and the
/// bus-master "NABM" register blocks). The PCI bridge maps one handler per BAR,
/// so the device is shared behind an Arc<Mutex<Ac97>> and exposed through two
/// thin window adapters that receive BAR-relative offsets.
type SharedAc97 = Arc<std::sync::Mutex<crate::devices::ac97::Ac97>>;

/// BAR0 window: the 16-bit codec mixer (NAM). The bus dispatches byte-wise, so
/// each access maps to the appropriate byte of the 16-bit mixer register.
struct Ac97NamWindow(SharedAc97);
impl IoDevice for Ac97NamWindow {
    fn read(&mut self, off: u16) -> u8 {
        match self.0.lock() {
            Ok(d) => {
                let word = d.mixer_read(off & !1);
                if off & 1 == 0 {
                    word as u8
                } else {
                    (word >> 8) as u8
                }
            }
            Err(_) => 0xff,
        }
    }
    fn write(&mut self, off: u16, value: u8) {
        if let Ok(mut d) = self.0.lock() {
            let reg = off & !1;
            let cur = d.mixer_read(reg);
            let new = if off & 1 == 0 {
                (cur & 0xFF00) | u16::from(value)
            } else {
                (cur & 0x00FF) | (u16::from(value) << 8)
            };
            d.mixer_write(reg, new);
        }
    }
}

/// BAR1 window: the bus-master register block (NABM).
struct Ac97NabmWindow(SharedAc97);
impl IoDevice for Ac97NabmWindow {
    fn read(&mut self, off: u16) -> u8 {
        self.0.lock().map(|d| d.nabm_read_u8(off)).unwrap_or(0xff)
    }
    fn write(&mut self, off: u16, value: u8) {
        if let Ok(mut d) = self.0.lock() {
            d.nabm_write_u8(off, value);
        }
    }
}

/// Attach the optional PCI device models to the host bridge. Their BARs are
/// pre-assigned (memory BARs inside [`PCI_MMIO_AP_BASE`], I/O BARs at fixed
/// ports) so the guest sees valid firmware resources; the bridge tracks any
/// reprogramming. Device models are built with a zero base so the bridge can
/// feed them BAR-relative offsets wherever the BAR lands.
fn attach_pci_devices(
    pci: &Arc<std::sync::Mutex<PciStub>>,
    mem: Arc<vm_memory::GuestMemoryMmap>,
    storage: &crate::config::StorageConfig,
) -> Result<PciDevices> {
    PciDevices::attach(pci, mem, storage)
}

/// Wrapper to make Pit implement IoDevice via shared reference
struct PitDevice {
    pit: Arc<std::sync::Mutex<Pit>>,
}

impl PitDevice {
    fn new(pit: Arc<std::sync::Mutex<Pit>>) -> Self {
        PitDevice { pit }
    }
}

impl IoDevice for PitDevice {
    fn read(&mut self, port: u16) -> u8 {
        if let Ok(mut pit) = self.pit.lock() {
            pit.read(port)
        } else {
            0xFF
        }
    }

    fn write(&mut self, port: u16, value: u8) {
        if let Ok(mut pit) = self.pit.lock() {
            pit.write(port, value);
        }
    }
}

pub mod pci_state;
use pci_state::PciDevices;

pub struct Vmm {
    timing_context: Arc<crate::vm::timing::TimingContext>,
    /// Typed ownership of the x86 bridge and every optional endpoint.
    pci_devices: Option<PciDevices>,
    pc_devices: Option<crate::machine::pc::PcDevices>,
    vm: Box<dyn Vm>,
    backend_kind: BackendKind,
    guest_mem: GuestMemoryWrapper,
    io_bus: IoBus,
    mmio_bus: MmioBus,
    serial: Arc<std::sync::Mutex<Serial16550>>,
    /// PL011 console device (AArch64 machines only).
    pl011: Option<Arc<std::sync::Mutex<Pl011>>>,
    /// Samsung S3C UART console device (ARMv6 machines only).
    s3c_uart: Option<Arc<std::sync::Mutex<S3cUart>>>,
    pit: Arc<std::sync::Mutex<Pit>>,
    pic: Arc<std::sync::Mutex<DualPic>>,
    lapic: Arc<std::sync::Mutex<LocalApic>>,
    /// One owner per configured CPU; element zero aliases the legacy BSP view.
    local_apics: Vec<Arc<std::sync::Mutex<LocalApic>>>,
    vcpus: Vec<Box<dyn VCpu>>,
    coordinator: coordinator::ExecutionCoordinator,
    machine: Box<dyn Machine>,
    boot_info: BootInfo,
    serial_mmio_base: Option<u64>,
    serial_irq: Option<u32>,
    /// GDB server channels (when --features debug and --gdb is used).
    #[cfg(feature = "debug")]
    gdb_channels: Option<VmmGdbChannels>,
    /// GDB server thread handle.
    #[cfg(feature = "debug")]
    gdb_thread: Option<gdb::OwnedServer>,
    /// Whether in single-step mode for GDB.
    #[cfg(feature = "debug")]
    gdb_single_step: bool,
    #[cfg(feature = "debug")]
    debugger: debugger::State,
    /// Whether GDB requested a stop.
    #[cfg(feature = "debug")]
    gdb_stopped: bool,
    /// Internal debugger execute breakpoints.
    #[cfg(feature = "debug")]
    gdb_breakpoints: std::collections::HashSet<u64>,
    /// Wait for GDB connection before starting.
    #[cfg(feature = "debug")]
    wait_gdb: bool,
    /// Snapshot configuration
    snapshot_config: Option<SnapshotConfig>,
    /// Last instruction count when snapshot was taken
    last_snapshot_insn: u64,
    /// Machine-defining configuration embedded in checkpoints this VM writes.
    checkpoint_config: CheckpointConfig,
    /// Where hotkey/signal-triggered checkpoints are written.
    snapshot_out: std::path::PathBuf,
}

fn drive_legacy_serial_irq(
    vm: &dyn Vm,
    backend_kind: BackendKind,
    pic: &Arc<std::sync::Mutex<DualPic>>,
    serial_irq: Option<u32>,
    pending: bool,
) {
    let Some(irq) = serial_irq else {
        return;
    };

    if let Ok(mut pic) = pic.lock() {
        pic.set_irq(irq as u8, pending);
    }

    if backend_kind == BackendKind::Kvm {
        if let Err(e) = vm.set_irq_line(irq, pending) {
            debug!(irq, pending, error = %e, "failed to drive serial irq line");
        }
    }
}

impl Vmm {
    /// Build a fresh machine: load the kernel and set boot-time CPU state.
    pub fn new(config: VmConfig) -> Result<Self> {
        Self::build(config, false, false)
    }

    /// Build a machine for base checkpoint restoration, skipping kernel loading,
    /// backend VM init and boot-time CPU injection. The caller supplies represented
    /// base state through [`restore_snapshot`](Self::restore_snapshot); expanded
    /// private/platform/SMP state is a separate checkpoint contract.
    pub fn new_resume(config: VmConfig) -> Result<Self> {
        Self::build(config, true, false)
    }

    /// Construct and restore the represented bundle without reopening kernel,
    /// initrd or configured image sources. Additional CPU/platform/scheduler
    /// capture and full quiescence remain separate contracts.
    pub fn new_resume_bundle(
        config: VmConfig,
        bundle: &crate::vm::snapshot::SnapshotBundle,
    ) -> Result<Self> {
        config.validate_resume_bundle(bundle)?;
        if config.arch == ArchKind::X86_64
            && bundle.execution().is_some_and(|state| state.pc.is_none())
        {
            return Err(Error::InvalidConfig(
                "checkpoint PC component is missing; complete restore requires its device image"
                    .into(),
            ));
        }

        if config.storage.has_images() {
            info!(
                "using captured media; writable disk changes are retained in memory and subsequent checkpoints"
            );
        }
        let mode = bundle
            .clock()
            .map_or(crate::vm::timing::ClockMode::Wall, |clock| clock.mode);
        let mut vm =
            Self::build_with_contexts(config, true, true, bundle.backend_contexts(), mode)?;
        vm.restore_snapshot_bundle(bundle)?;
        Ok(vm)
    }

    fn build(config: VmConfig, resume: bool, detached_media: bool) -> Result<Self> {
        Self::build_with_contexts(
            config,
            resume,
            detached_media,
            None,
            crate::vm::timing::ClockMode::Wall,
        )
    }

    fn build_with_contexts(
        config: VmConfig,
        resume: bool,
        detached_media: bool,
        contexts: Option<&crate::vm::snapshot::BackendContexts>,
        clock_mode: crate::vm::timing::ClockMode,
    ) -> Result<Self> {
        config.validate_clock_mode(clock_mode)?;
        let timing_context = Arc::new(crate::vm::timing::TimingContext::with_mode(clock_mode));
        let _timing = timing_context.enter();
        info!(
            vcpus = config.vcpus,
            mem_bytes = config.memory.bytes(),
            resume = resume,
            "initializing VMM"
        );

        // Initialize instruction tracing if requested (requires trace feature)
        #[cfg(feature = "trace")]
        if let Some(ref trace_path) = config.trace {
            crate::observability::trace::init(trace_path)
                .map_err(|e| Error::InvalidConfig(format!("failed to open trace file: {}", e)))?;
            info!(trace_path = ?trace_path, "instruction tracing enabled");
        }
        #[cfg(not(feature = "trace"))]
        if config.trace.is_some() {
            return Err(Error::InvalidConfig(
                "--trace requires building with --features trace".to_string(),
            ));
        }

        // Create backend
        let backend = backend::create_for_checkpoint(&config, contexts)?;
        info!(backend = backend.name(), "using backend");

        // Create VM
        let vm = backend.create_vm()?;

        // Allocate guest memory
        let guest_mem = GuestMemoryWrapper::new(config.memory.bytes())?;

        // Register memory with VM (backend-specific)
        #[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
        if matches!(config.backend, BackendKind::Kvm) {
            let kvm_vm = vm
                .as_any()
                .downcast_ref::<KvmVm>()
                .ok_or_else(|| Error::InvalidConfig("expected KVM VM".to_string()))?;
            kvm_vm.register_memory(&guest_mem)?;
        }
        // Emulator accesses memory directly, no registration needed

        // Select the guest machine.
        let machine = machine::from_arch_kind(config.arch);
        vm.configure_cpu_topology(
            config.vcpus,
            machine
                .ram_base()
                .checked_add(guest_mem.size())
                .ok_or_else(|| Error::InvalidConfig("guest RAM extent overflows".into()))?,
        )?;

        info!(machine = machine.name(), "selected guest machine");

        // ARM64 HVF: map only the platform RAM window into the guest so that
        // device MMIO below it (UART, ...) traps out as data aborts.
        #[cfg(all(feature = "hvf", target_os = "macos", target_arch = "aarch64"))]
        if matches!(config.backend, BackendKind::Hvf) {
            use crate::backend::hvf::HvfArm64Vm;
            let hvf_vm = vm
                .as_any()
                .downcast_ref::<HvfArm64Vm>()
                .ok_or_else(|| Error::InvalidConfig("expected ARM64 HVF VM".to_string()))?;
            hvf_vm.register_memory(&guest_mem, machine.ram_base(), config.memory.bytes())?;
        }

        // Setup I/O devices
        let mut io_bus = IoBus::new();
        let mut mmio_bus = MmioBus::new();
        let pc_devices = machine.setup_owned_devices(&mut io_bus, &mut mmio_bus)?;

        // PCI host bridge (x86). Owned here so it can be shared with the
        // emulator MMU for BAR-mapped MMIO routing. The bridge (config ports
        // 0xCF8-0xCFF) is always present on x86; the optional device models are
        // attached only with --pci-devices.
        let mut pci_devices = None;
        let pci_bridge: Option<Arc<std::sync::Mutex<PciStub>>> = if config.arch == ArchKind::X86_64
        {
            let pci = Arc::new(std::sync::Mutex::new(PciStub::new()));
            if config.pci_devices {
                pci_devices = Some(if detached_media {
                    PciDevices::attach_detached(&pci, Arc::new(guest_mem.memory().clone()))?
                } else {
                    attach_pci_devices(&pci, Arc::new(guest_mem.memory().clone()), &config.storage)?
                });
                info!("attached optional PCI devices (e1000, uhci, nvme, ahci, ac97)");
            }
            if pci_devices.is_none() {
                pci_devices = Some(PciDevices::bridge_only(
                    pci.clone(),
                    Arc::new(guest_mem.memory().clone()),
                )?);
            }
            io_bus.register(
                IoRange {
                    base: PCI_CONFIG_ADDRESS,
                    len: 8,
                },
                Box::new(SharedIoDevice::new(pci.clone())),
            )?;
            // Dynamically-assigned PCI I/O BARs are reached via this fallback.
            io_bus.set_pci(pci.clone());
            mmio_bus.set_pci(pci.clone());
            Some(pci)
        } else {
            None
        };

        let serial_mmio_base = machine.serial_mmio_base();
        let serial_irq = machine.serial_irq();

        // Create serial device with input enabled. AArch64 uses a PL011 at
        // the platform UART base; everything else keeps the 16550.
        let pl011 = if config.arch == ArchKind::Aarch64 {
            let uart = Arc::new(std::sync::Mutex::new(Pl011::new()));
            if let Some(base) = serial_mmio_base {
                mmio_bus.register(
                    MmioRange { base, len: 0x1000 },
                    Box::new(Pl011MmioDevice::new(base, uart.clone())),
                )?;
            }
            Some(uart)
        } else {
            None
        };

        // ARMv6/S3C64xx console: the UART lives inside the vCPU's memory
        // bridge; the VMM only feeds it host console input.
        let s3c_uart = if config.arch == ArchKind::Armv7a {
            Some(Arc::new(std::sync::Mutex::new(S3cUart::new())))
        } else {
            None
        };

        let serial = Arc::new(std::sync::Mutex::new(Serial16550::new(SERIAL_BASE)));
        if let Ok(mut serial_guard) = serial.lock() {
            if let Some(base) = serial_mmio_base {
                serial_guard.set_mmio_base(base);
            }
        }
        if pl011.is_none() && s3c_uart.is_none() {
            if let Some(base) = serial_mmio_base {
                mmio_bus.register(
                    MmioRange { base, len: 8 },
                    Box::new(SerialMmioDevice::new(serial.clone())),
                )?;
            }
        }

        // Create PIT (Programmable Interval Timer) at ports 0x40-0x43
        let pit = Arc::new(std::sync::Mutex::new(Pit::new()));

        // Create PIC (Programmable Interrupt Controller)
        let pic = Arc::new(std::sync::Mutex::new(DualPic::new()));

        // Register PIT on I/O bus
        io_bus.register(
            IoRange { base: 0x40, len: 4 },
            Box::new(PitDevice::new(pit.clone())),
        )?;

        // Register master PIC (0x20-0x21)
        io_bus.register(
            IoRange { base: 0x20, len: 2 },
            Box::new(MasterPicDevice::new(pic.clone())),
        )?;

        // Register slave PIC (0xA0-0xA1)
        io_bus.register(
            IoRange { base: 0xA0, len: 2 },
            Box::new(SlavePicDevice::new(pic.clone())),
        )?;

        // Create and register Local APIC at 0xFEE00000
        let lapic = Arc::new(std::sync::Mutex::new(LocalApic::new(0)));
        mmio_bus.register(
            MmioRange {
                base: LAPIC_BASE,
                len: LAPIC_SIZE,
            },
            Box::new(LapicDevice::new(lapic.clone())),
        )?;

        // Intel EPT must reflect the actual fixed device windows and live BARs,
        // after device construction and before creating any native CPU.
        #[cfg(all(feature = "hvf", target_os = "macos", target_arch = "x86_64"))]
        if matches!(config.backend, BackendKind::Hvf) {
            let hvf_vm = vm
                .as_any()
                .downcast_ref::<crate::backend::hvf::HvfVm>()
                .ok_or_else(|| Error::InvalidConfig("expected HVF VM".into()))?;
            hvf_vm.register_memory_with_mmio(&guest_mem, &mmio_bus.ranges(), pci_bridge.clone())?;
            mmio_bus.set_ram_fallback(Arc::new(guest_mem.memory().clone()), guest_mem.size());
        }

        // Load kernel — skipped when resuming (the kernel is already present in
        // the RAM image restored from the checkpoint).
        let boot_info = if resume {
            null_boot_info(config.arch)
        } else {
            machine.load_kernel_with_devices(guest_mem.memory(), &config, pc_devices.as_ref())?
        };

        // Initialize VM (backend-specific). Skipped on resume: the emulator
        // backend needs none, and a resumed machine takes its full CPU/segment
        // state from the checkpoint rather than the boot-time init.
        #[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
        if !resume && matches!(config.backend, BackendKind::Kvm) {
            let kvm_vm = vm
                .as_any()
                .downcast_ref::<KvmVm>()
                .ok_or_else(|| Error::InvalidConfig("expected KVM VM".to_string()))?;
            machine.init_vm(kvm_vm, &boot_info)?;
        }
        // Emulator doesn't need VM-level initialization

        debug!("creating vCPUs");
        // Create vCPUs
        let mem_arc = Arc::new(guest_mem.memory().clone());
        let mut vcpus = Vec::with_capacity(config.vcpus as usize);
        let mut coordinator = coordinator::ExecutionCoordinator::new(usize::from(config.vcpus));
        let mut local_apics = Vec::with_capacity(config.vcpus as usize);
        for cpu_id in 0..config.vcpus {
            debug!(cpu_id, "creating vCPU");
            let mut vcpu = vm.create_vcpu(cpu_id as u32, mem_arc.clone())?;
            if clock_mode == crate::vm::timing::ClockMode::Retired && !vcpu.supports_stepping() {
                return Err(Error::InvalidConfig(
                    "retired VM clock requires single-instruction stepping for every vCPU".into(),
                ));
            }
            debug!(cpu_id, "created vCPU, setting initial state");

            // A fresh machine supplies its platform's initial CPU set. Resume
            // leaves captured registers and online/cursor state to publication.
            if !resume {
                if let Some(initial_state) = riscv_startup::boot_state(
                    &*vm,
                    &*machine,
                    guest_mem.memory(),
                    &boot_info,
                    &*vcpu,
                    config.vcpus,
                )? {
                    vcpu.set_state(&initial_state)?;
                    coordinator.online[usize::from(cpu_id)] = true;
                }
            }
            if cpu_id == 0 {
                if let Some(real_mode) = boot_info
                    .as_x86_64()
                    .and_then(|boot| boot.real_mode.as_ref())
                {
                    vcpu.attach_x86_64_bios(Some(real_mode.cdrom.clone()), real_mode.mem_bytes);
                }
            }
            #[cfg(feature = "debug")]
            if config.gdb_port.is_some() {
                vcpu.set_debugger_active(true);
            }

            // Share the PL011 console device with the vCPU so its memory
            // bridge services UART MMIO against the instance the VMM feeds.
            if let (Some(pl011), Some(base)) = (&pl011, serial_mmio_base) {
                vcpu.attach_pl011(base, pl011.clone());
            }
            if let Some(uart) = &s3c_uart {
                vcpu.attach_s3c_uart(uart.clone());
            }

            let local_apic = if cpu_id == 0 {
                lapic.clone()
            } else {
                Arc::new(std::sync::Mutex::new(LocalApic::new(u32::from(cpu_id))))
            };
            if config.arch == ArchKind::X86_64 {
                local_apic
                    .lock()
                    .map_err(|_| Error::Emulator("local APIC lock poisoned".into()))?
                    .enable_coordinated_delivery();
                vcpu.attach_local_apic(local_apic.clone());
            }
            local_apics.push(local_apic);

            debug!(vcpu_id = cpu_id, "created vCPU");
            vcpus.push(vcpu);
        }

        // Hand the PCI host bridge to the BSP's MMU so BAR-mapped MMIO in the
        // aperture is routed to PCI device handlers (emulator backend only; the
        // default VCpu::set_pci_bridge is a no-op for KVM/HVF). Only needed when
        // device models are actually attached.
        if config.pci_devices {
            if let Some(ref pci) = pci_bridge {
                for vcpu in &mut vcpus {
                    vcpu.set_pci_bridge(pci.clone(), PCI_MMIO_AP_BASE, PCI_MMIO_AP_END);
                }
            }
        }

        // Initialize GDB server if configured
        #[cfg(feature = "debug")]
        let (gdb_channels, gdb_thread) = if let Some(port) = config.gdb_port {
            let (gdb_ch, vmm_ch) = gdb::create_channels();
            let handle = gdb::spawn_owned_server(port, gdb_ch, config.wait_gdb)
                .map_err(|e| Error::InvalidConfig(format!("failed to start GDB server: {}", e)))?;
            (Some(vmm_ch), Some(handle))
        } else {
            (None, None)
        };

        #[cfg(not(feature = "debug"))]
        if config.gdb_port.is_some() {
            return Err(Error::InvalidConfig(
                "--gdb requires building with --features debug".to_string(),
            ));
        }

        // Capture the machine-defining config for embedding in checkpoints, and
        // resolve where hotkey/signal checkpoints will be written.
        let mut checkpoint_config = config.to_checkpoint();
        checkpoint_config.memory_bytes = guest_mem.size();
        let snapshot_out = config
            .snapshot_out
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from(DEFAULT_CHECKPOINT_FILE));

        Ok(Vmm {
            timing_context,
            pci_devices,
            pc_devices,
            vm,
            backend_kind: config.backend,
            guest_mem,
            io_bus,
            mmio_bus,
            serial,
            pl011,
            s3c_uart,
            pit,
            pic,
            lapic,
            local_apics,
            coordinator,
            vcpus,
            machine,
            boot_info,
            serial_mmio_base,
            serial_irq,
            #[cfg(feature = "debug")]
            gdb_channels,
            #[cfg(feature = "debug")]
            gdb_thread,
            #[cfg(feature = "debug")]
            gdb_single_step: false,
            #[cfg(feature = "debug")]
            debugger: debugger::State::default(),
            #[cfg(feature = "debug")]
            gdb_stopped: false,
            #[cfg(feature = "debug")]
            gdb_breakpoints: std::collections::HashSet::new(),
            #[cfg(feature = "debug")]
            wait_gdb: config.wait_gdb,
            snapshot_config: if config.snapshot_interval > 0 || !config.snapshot_at.is_empty() {
                Some(SnapshotConfig {
                    interval: config.snapshot_interval,
                    at_instructions: config.snapshot_at.clone(),
                    output_dir: config
                        .snapshot_dir
                        .as_ref()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|| ".".to_string()),
                    prefix: "snapshot".to_string(),
                })
            } else {
                None
            },
            last_snapshot_insn: 0,
            checkpoint_config,
            snapshot_out,
        })
    }

    /// Bind this VM's timing domain in explicitly managed worker threads.
    /// Worker contexts are not inherited implicitly across thread creation.
    pub fn timing_context(&self) -> &Arc<crate::vm::timing::TimingContext> {
        &self.timing_context
    }

    pub fn boot_info(&self) -> &BootInfo {
        &self.boot_info
    }

    pub fn guest_mem(&self) -> &GuestMemoryWrapper {
        &self.guest_mem
    }

    pub fn machine(&self) -> &dyn Machine {
        self.machine.as_ref()
    }

    /// Compatibility accessor for callers using the previous terminology.
    pub fn arch(&self) -> &dyn Machine {
        self.machine()
    }

    /// Capture the four represented legacy device models into [`DeviceState`].
    fn capture_devices(&self) -> Result<DeviceState> {
        let lock_err =
            |what: &str| Error::Emulator(format!("device {what} lock poisoned during snapshot"));
        let pic = self.pic.lock().map_err(|_| lock_err("pic"))?.clone();
        let pit = self.pit.lock().map_err(|_| lock_err("pit"))?.clone();
        let serial = self.serial.lock().map_err(|_| lock_err("serial"))?.clone();
        let lapic = self
            .lapic
            .lock()
            .map_err(|_| lock_err("lapic"))?
            .checkpoint_registers();
        Ok(DeviceState {
            pic,
            pit,
            serial,
            lapic,
        })
    }

    /// Capture the represented CPU-0 and legacy-device base checkpoint.
    pub fn take_snapshot(&self, insn_count: u64) -> Result<Snapshot> {
        if self
            .vm
            .as_any()
            .downcast_ref::<crate::backend::emulator::EmulatorVm>()
            .and_then(|vm| vm.riscv_platform())
            .is_some_and(|platform| platform.enabled())
        {
            return Err(Error::InvalidConfig(
                "CLINT capture requires a complete snapshot bundle".into(),
            ));
        }
        self.validate_base_snapshot_clock()?;
        #[cfg(feature = "debug")]
        self.debugger.ready()?;
        let _timing = self.timing_context.enter();
        if self.checkpoint_config.storage.has_images() {
            return Err(Error::InvalidConfig(
                "image-backed checkpoint capture requires complete device/media state".to_string(),
            ));
        }
        let vcpu = self
            .vcpus
            .get(0)
            .ok_or_else(|| Error::InvalidConfig("no vcpu available".to_string()))?;

        let cpu_state = vcpu.get_state()?;
        let emulator_state = vcpu.get_emulator_state().unwrap_or_default();
        let devices = self.capture_devices()?;
        let memory = self.guest_mem.try_read_all()?;

        Snapshot::new(
            self.checkpoint_config.clone(),
            insn_count,
            crate::vm::timing::elapsed_nanos(),
            cpu_state,
            emulator_state,
            devices,
            &memory,
        )
    }

    /// Capture each vCPU's represented public/base-private payload in ID order.
    /// Callers must quiesce independent writers. Additional backend-private and
    /// scheduler state remains outside this represented-state interface.
    pub fn capture_cpu_states(&self) -> Result<Vec<crate::vm::snapshot::CpuSnapshot>> {
        #[cfg(feature = "debug")]
        self.debugger.ready()?;
        let _timing = self.timing_context.enter();
        use crate::vm::snapshot::CpuSnapshot;
        let mut cpus = Vec::new();
        cpus.try_reserve_exact(self.vcpus.len())
            .map_err(|e| Error::Emulator(format!("CPU capture allocation: {e}")))?;
        for vcpu in &self.vcpus {
            cpus.push(CpuSnapshot {
                state: vcpu.get_state()?,
                emulator: vcpu.get_emulator_state().unwrap_or_default(),
            });
        }
        Ok(cpus)
    }

    /// Write a checkpoint to the configured `--snapshot-out` path (default
    /// `./checkpoint.rxc`). Invoked from the `Ctrl-A s` console hotkey and the
    /// SIGUSR1 signal. The machine is effectively paused while this runs because
    /// the run loop is single-threaded — the vCPU is not executing during the
    /// poll phase where this is called.
    pub fn console_checkpoint(&self) {
        let insn = self.coordinator.retired;
        let path = self.snapshot_out.clone();
        info!(path = %path.display(), insn = insn, "checkpoint requested");
        match self.take_snapshot_bundle(insn) {
            Ok(snapshot) => match snapshot.save(&path) {
                Ok(()) => {
                    // \r\n so the message renders cleanly in raw terminal mode.
                    eprint!("\r\n[rax] checkpoint written: {}\r\n", path.display());
                    info!(summary = %snapshot.base().summary(), "checkpoint written");
                }
                Err(e) => eprint!("\r\n[rax] checkpoint save failed: {}\r\n", e),
            },
            Err(e) => eprint!("\r\n[rax] checkpoint capture failed: {}\r\n", e),
        }
    }

    /// Check if we should take a snapshot and do so if needed
    fn maybe_snapshot(&mut self, insn_count: u64) -> Result<()> {
        let should_snapshot = if let Some(ref config) = self.snapshot_config {
            // Debug: print instruction count periodically
            if insn_count % 1_000_000_000 == 0 {
                eprintln!(
                    "[SNAPSHOT] insn_count={} interval={} at={:?}",
                    insn_count, config.interval, config.at_instructions
                );
            }
            // Check interval-based snapshotting
            if config.interval > 0 && insn_count >= self.last_snapshot_insn + config.interval {
                true
            } else {
                // Check if we passed any specific instruction counts
                config
                    .at_instructions
                    .iter()
                    .any(|&at| at > self.last_snapshot_insn && at <= insn_count)
            }
        } else {
            false
        };

        if should_snapshot {
            let snapshot = self.take_snapshot_bundle(insn_count)?;
            let filename = self
                .snapshot_config
                .as_ref()
                .map(|c| c.filename(insn_count))
                .unwrap_or_else(|| format!("snapshot_{:012}.snap", insn_count));

            info!(
                filename = %filename,
                insn_count = insn_count,
                summary = %snapshot.base().summary(),
                "saving snapshot"
            );

            snapshot.save(&filename)?;
            self.last_snapshot_insn = insn_count;
        }

        Ok(())
    }
}

#[cfg(test)]
#[path = "runtime/storage_tests.rs"]
mod storage_tests;

#[cfg(test)]
#[path = "runtime/checkpoint_tests.rs"]
mod checkpoint_tests;

#[cfg(test)]
#[path = "runtime/backend_context_tests.rs"]
mod backend_context_tests;

#[cfg(test)]
#[path = "runtime/cortex_m_context_tests.rs"]
mod cortex_m_context_tests;

#[cfg(test)]
#[path = "runtime/hexagon_context_tests.rs"]
mod hexagon_context_tests;

#[cfg(test)]
#[path = "runtime/gsc_bounded_tests.rs"]
mod gsc_bounded_tests;

#[cfg(test)]
#[path = "runtime/gsc_context_tests.rs"]
mod gsc_context_tests;

#[cfg(test)]
#[path = "runtime/riscv_context_tests.rs"]
mod riscv_context_tests;

#[cfg(test)]
#[path = "runtime/x86_context_tests.rs"]
mod x86_context_tests;

#[cfg(test)]
#[path = "runtime/bundle_tests.rs"]
mod bundle_tests;

#[cfg(test)]
#[path = "runtime/resume_tests.rs"]
mod resume_tests;

#[cfg(test)]
#[path = "runtime/cpu_set_tests.rs"]
mod cpu_set_tests;

#[cfg(test)]
#[path = "runtime/lapic_tests.rs"]
mod lapic_tests;

#[path = "runtime/lapic.rs"]
mod lapic;

#[cfg(test)]
mod execution_tests;

#[cfg(test)]
mod native_scheduling_tests;

mod checkpoint_capture;
mod coordinator;
mod execution;
#[path = "runtime/mmio.rs"]
mod mmio;

#[cfg(test)]
#[path = "runtime/mmio_rmw_tests.rs"]
mod mmio_rmw_tests;

#[cfg(test)]
#[path = "runtime/native_mmio_tests.rs"]
mod native_mmio_tests;

#[cfg(test)]
#[path = "runtime/lapic_priority_tests.rs"]
mod lapic_priority_tests;

#[cfg(test)]
#[path = "runtime/cpu_identity_tests.rs"]
mod cpu_identity_tests;

#[cfg(test)]
mod aarch64_cluster_tests;

#[cfg(all(test, feature = "hvf", target_os = "macos", target_arch = "aarch64"))]
mod native_checkpoint_tests;

mod backend_transaction;
mod checkpoint_restore;

#[cfg(all(test, feature = "debug"))]
#[path = "runtime/gdb_smp_tests.rs"]
mod gdb_smp_tests;

#[cfg(all(test, feature = "debug"))]
mod gdb_lifecycle_tests;

#[cfg(feature = "debug")]
mod debugger;
#[cfg(feature = "debug")]
mod debugger_control;

#[cfg(feature = "debug")]
mod debugger_memory;

#[cfg(feature = "debug")]
impl Drop for Vmm {
    fn drop(&mut self) {
        // Cancel pending owner-response waits before joining the transport.
        // Guest/backend resources remain alive until this shutdown completes.
        drop(self.gdb_channels.take());
        drop(self.gdb_thread.take());
    }
}

#[cfg(test)]
mod lapic_clock_tests;

#[cfg(test)]
mod pc_owned_capture_tests;

#[cfg(test)]
#[path = "runtime/s5l_bounded_tests.rs"]
mod s5l_bounded_tests;

#[cfg(test)]
mod s5l_context_tests;

#[cfg(test)]
#[path = "runtime/clock_tests.rs"]
mod clock_tests;

#[path = "runtime/clock.rs"]
mod clock;

#[cfg(test)]
#[path = "runtime/rtc_clock_tests.rs"]
mod rtc_clock_tests;

#[cfg(test)]
#[path = "runtime/riscv_startup_tests.rs"]
mod riscv_startup_tests;

#[path = "runtime/riscv_startup.rs"]
mod riscv_startup;

#[cfg(test)]
mod riscv_clint_tests;
