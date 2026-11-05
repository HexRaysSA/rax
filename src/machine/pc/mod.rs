// On x86 hosts, use linux-loader's native types
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod acpi;

/// El-Torito (BIOS CD) boot support for legacy/real-mode boot (e.g. TempleOS).
pub mod bios_boot;
pub(crate) mod multiprocessor;
pub(crate) mod ram;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod native_imports {
    pub use linux_loader::cmdline::Cmdline;
    pub use linux_loader::configurator::linux::LinuxBootConfigurator;
    pub use linux_loader::configurator::{BootConfigurator, BootParams};
    pub use linux_loader::loader::bootparam::{boot_e820_entry, boot_params};
    pub use linux_loader::loader::elf::PvhBootCapability;
    pub use linux_loader::loader::{BzImage, KernelLoader, KernelLoaderResult, load_cmdline};
}

// On non-x86 hosts, use our local bootparam module
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
mod bootparam;

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
mod native_imports {
    pub use super::bootparam::{
        BootE820Entry as boot_e820_entry, BootParams as boot_params, KernelLoaderResult,
        PvhBootCapability, SetupHeader,
    };
    pub use linux_loader::cmdline::Cmdline;

    // Wrapper types to match linux-loader API
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    pub fn load_cmdline(
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        cmdline: &Cmdline,
    ) -> Result<(), crate::error::Error> {
        let s = cmdline
            .as_cstring()
            .map_err(|e| crate::error::Error::KernelLoad(format!("cmdline error: {e}")))?;
        super::bootparam::load_cmdline(mem, addr, s.to_str().unwrap_or(""))
    }

    pub struct BzImage;
    impl BzImage {
        pub fn load<F: std::io::Read + std::io::Seek>(
            mem: &GuestMemoryMmap,
            kernel_offset: Option<GuestAddress>,
            kernel_file: &mut F,
            _highmem_start: Option<GuestAddress>,
        ) -> Result<KernelLoaderResult, crate::error::Error> {
            use std::io::{Read, Seek, SeekFrom};

            let start = kernel_offset.unwrap_or(GuestAddress(0x1000000));

            // Read entire file
            kernel_file
                .seek(SeekFrom::Start(0))
                .map_err(|e| crate::error::Error::Io(e))?;
            let mut data = Vec::new();
            kernel_file
                .read_to_end(&mut data)
                .map_err(|e| crate::error::Error::Io(e))?;

            super::bootparam::load_bzimage_from_bytes(mem, &data, start)
        }
    }

    // Wrapper for boot params writing
    pub struct LinuxBootConfigurator;
    impl LinuxBootConfigurator {
        pub fn write_bootparams(
            params: &BootParams,
            mem: &GuestMemoryMmap,
        ) -> Result<(), crate::error::Error> {
            super::bootparam::write_boot_params(mem, &params.params, params.addr)
        }
    }

    pub struct BootParams {
        pub params: boot_params,
        pub addr: GuestAddress,
    }

    impl BootParams {
        pub fn new(params: &boot_params, addr: GuestAddress) -> Self {
            Self {
                params: *params,
                addr,
            }
        }
    }
}

use goblin::elf::Elf as GoblinElf;
use native_imports::*;
use tracing::{debug, info};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

#[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
use crate::backend::kvm::KvmVm;
use crate::config::VmConfig;
use crate::devices::bus::{IoBus, IoRange, MmioBus, MmioRange, SharedIoDevice};
use crate::devices::debug::DebugPort;
use crate::devices::dma::Dma;
use crate::devices::fdc::Fdc;
use crate::devices::fw_cfg::FwCfg;
use crate::devices::i8042::I8042;
use crate::devices::ide::IdeController;
use crate::devices::ioapic::IoApic;
use crate::devices::map::{X86_DEBUG_PORT_BASE, X86_DEBUG_PORT_LEN};
use crate::devices::rtc::{RTC_ADDRESS, RtcStub};
use crate::devices::sysctl::SystemControl;
use crate::error::{Error, Result};
use crate::machine::{BootInfo, Machine, X86_64BootInfo, X86_64RealModeBootInfo};
use crate::vm::memory::{KVM_TSS_IDENTITY_GAP_START, PAGE_SIZE, align_down};
use crate::vm::vcpu::{
    CpuState, DescriptorTable, Registers, Segment, SystemRegisters, X86_64CpuState,
};
use std::sync::{Arc, Mutex};

/// The primary IDE controller, stashed during device setup so the ISO boot path
/// (which runs later, in `load_kernel`) can attach the CD image as an ATAPI
/// CD-ROM on the primary master. Single-vCPU legacy boot, so a static suffices.
static BOOT_IDE_PRIMARY: Mutex<Option<Arc<Mutex<IdeController>>>> = Mutex::new(None);

/// Kernel load address - must match ELF PhysAddr (typically 16MB for x86_64 Linux)
const KERNEL_LOAD_ADDR: u64 = 0x1000000;
const BOOT_PARAMS_ADDR: u64 = 0x7000;
const CMDLINE_ADDR: u64 = 0x20000;
const GDT_ADDR: u64 = 0x500;
const TSS_ADDR: u64 = 0x1000;
const BOOT_STACK_ADDR: u64 = 0x8ff0;

// Page table addresses for identity mapping and kernel space
const PML4_ADDR: u64 = 0x9000;
const PDPTE_ADDR: u64 = 0xa000; // PDPTE for PML4[0] - initial identity mapping
const PDE_ADDR: u64 = 0xb000; // PDE for PDPTE[0] - 512 x 2MB pages = 1GB
// Additional page tables for kernel virtual address space
const PDPTE_KERNEL_ADDR: u64 = 0xc000; // PDPTE for PML4[511] - kernel text
const PDE_KERNEL_ADDR: u64 = 0xd000; // PDE for PDPTE_KERNEL[510/511]
const PDPTE_DIRECT_ADDR: u64 = 0xe000; // PDPTE for PML4[273] - direct map

// Cover the complete configured RAM cap plus its physical device-window gap.
const BOOTSTRAP_RAM_GIB: u64 =
    (crate::vm::memory::MAX_GUEST_MEMORY_BYTES + ram::HIGH_START - ram::LOW_END + (1 << 30) - 1)
        >> 30;
const _: () = assert!(BOOTSTRAP_RAM_GIB <= 512);

const BOOT_CS: u16 = 0x10;
const BOOT_DS: u16 = 0x18;
const BOOT_TR: u16 = 0x20;

// x86 control register bits
const X86_CR0_PE: u64 = 1 << 0;
const X86_CR0_PG: u64 = 1 << 31;
const X86_CR4_PAE: u64 = 1 << 5;
const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;

const E820_RAM: u32 = 1;
const E820_RESERVED: u32 = 2;

const LOW_MEM_END: u64 = 0x9fc00;
const BIOS_END: u64 = 0x100000;

const KVM_RESERVED_SIZE: u64 = 0x4000;

pub struct PcMachine;

/// Compatibility name for the previous architecture-oriented API.
pub use PcMachine as X86_64Arch;

impl PcMachine {
    pub fn new() -> Self {
        PcMachine
    }

    pub(crate) fn kvm_setup_addresses() -> (u64, u64) {
        let identity_map_addr = KVM_TSS_IDENTITY_GAP_START;
        let tss_addr = KVM_TSS_IDENTITY_GAP_START + PAGE_SIZE;
        (tss_addr, identity_map_addr)
    }

    fn build_cmdline(cmdline: &str) -> Result<Cmdline> {
        let mut cmdline_builder = Cmdline::new(4096)
            .map_err(|e| Error::InvalidConfig(format!("invalid cmdline: {e}")))?;
        cmdline_builder
            .insert_str(cmdline)
            .map_err(|e| Error::InvalidConfig(format!("invalid cmdline: {e}")))?;
        Ok(cmdline_builder)
    }

    /// Resolve the linked entry into one admitted segment's physical address.
    /// Legacy images that already supply a physical entry retain that convention.
    fn elf_physical_entry(
        entry: u64,
        segments: &[&goblin::elf::program_header::ProgramHeader],
    ) -> Result<u64> {
        let mut physical = None;
        for header in segments {
            let end = header
                .p_vaddr
                .checked_add(header.p_memsz)
                .ok_or_else(|| Error::KernelLoad("ELF virtual extent wraps".into()))?;
            if entry >= header.p_vaddr && entry < end {
                let candidate = header
                    .p_paddr
                    .checked_add(entry - header.p_vaddr)
                    .ok_or_else(|| Error::KernelLoad("ELF entry translation wraps".into()))?;
                if physical.is_some_and(|previous| previous != candidate) {
                    return Err(Error::KernelLoad("ELF entry mapping is ambiguous".into()));
                }
                physical = Some(candidate);
            }
        }
        let physical = physical.or_else(|| {
            segments
                .iter()
                .any(|header| {
                    entry
                        .checked_sub(header.p_paddr)
                        .is_some_and(|offset| offset < header.p_memsz)
                })
                .then_some(entry)
        });
        physical
            .filter(|address| *address < BOOTSTRAP_RAM_GIB << 30)
            .ok_or_else(|| {
                Error::KernelLoad("ELF entry is outside the bootable load segments".into())
            })
    }

    /// Load an admitted PC kernel and retain the occupied low-RAM endpoint
    /// separately from high ELF segments, so a 32-bit initrd pointer stays low.
    fn load_kernel_image(
        mem: &GuestMemoryMmap,
        config: &VmConfig,
        layout: ram::Layout,
        reserved_start: u64,
    ) -> Result<(KernelLoaderResult, bool, Option<u64>, u64)> {
        let kernel_data = std::fs::read(&config.kernel)?;
        let kernel_size = kernel_data.len() as u64;
        let is_bzimage = kernel_data.get(0x202..0x206) == Some(b"HdrS");
        if is_bzimage {
            let mut image = std::io::Cursor::new(kernel_data.as_slice());
            let result = BzImage::load(
                mem,
                Some(GuestAddress(KERNEL_LOAD_ADDR)),
                &mut image,
                Some(GuestAddress(0)),
            )
            .map_err(|error| Error::KernelLoad(format!("failed to load bzImage: {error}")))?;
            let end = result.kernel_end as u64;
            if end >= reserved_start {
                return Err(Error::KernelLoad(
                    "kernel image overlaps reserved low RAM".into(),
                ));
            }
            return Ok((result, false, None, end));
        }
        if kernel_data.starts_with(b"\x7fELF") {
            let elf = GoblinElf::parse(&kernel_data)
                .map_err(|error| Error::KernelLoad(format!("failed to parse ELF: {error}")))?;
            let segments: Vec<_> = elf
                .program_headers
                .iter()
                .filter(|header| header.p_type == goblin::elf::program_header::PT_LOAD)
                .collect();
            if segments.iter().all(|header| header.p_memsz == 0) {
                return Err(Error::KernelLoad(
                    "ELF kernel has no loadable memory".into(),
                ));
            }
            let mut kernel_end = KERNEL_LOAD_ADDR;
            let mut low_end = KERNEL_LOAD_ADDR;
            // Admit every segment before publishing any file or BSS bytes.
            for header in &segments {
                if header.p_filesz > header.p_memsz {
                    return Err(Error::KernelLoad(
                        "ELF file extent exceeds its memory extent".into(),
                    ));
                }
                if header.p_memsz == 0 {
                    continue;
                }
                if header.p_filesz != 0 {
                    header
                        .p_offset
                        .checked_add(header.p_filesz)
                        .filter(|end| *end <= kernel_size)
                        .ok_or_else(|| {
                            Error::KernelLoad("ELF file extent is outside its input".into())
                        })?;
                }
                if header.p_paddr < BIOS_END || !layout.contains(header.p_paddr, header.p_memsz) {
                    return Err(Error::KernelLoad(
                        "ELF segment is outside usable PC RAM".into(),
                    ));
                }
                let end = header.p_paddr + header.p_memsz;
                if header.p_paddr < ram::LOW_END {
                    if end > reserved_start {
                        return Err(Error::KernelLoad(
                            "ELF segment overlaps reserved low RAM".into(),
                        ));
                    }
                    low_end = low_end.max(end);
                }
                kernel_end = kernel_end.max(end);
            }
            let entry = Self::elf_physical_entry(elf.header.e_entry, &segments)?;
            for header in segments.into_iter().filter(|header| header.p_memsz != 0) {
                let begin = header.p_offset as usize;
                let end = begin + header.p_filesz as usize;
                if begin != end {
                    mem.write_slice(&kernel_data[begin..end], GuestAddress(header.p_paddr))?;
                }
                // A large sparse BSS does not require an equally large host
                // allocation. Every chunk stays in the admitted segment.
                let zeros = [0u8; 64 * 1024];
                let mut address = header.p_paddr + header.p_filesz;
                let end = header.p_paddr + header.p_memsz;
                while address < end {
                    let count = (end - address).min(zeros.len() as u64) as usize;
                    mem.write_slice(&zeros[..count], GuestAddress(address))?;
                    address += count as u64;
                }
            }
            let result = KernelLoaderResult {
                kernel_load: GuestAddress(KERNEL_LOAD_ADDR),
                kernel_end,
                setup_header: None,
                pvh_boot_cap: PvhBootCapability::PvhEntryNotPresent,
            };
            return Ok((result, true, Some(entry), low_end));
        }
        let end = KERNEL_LOAD_ADDR
            .checked_add(kernel_size)
            .filter(|end| *end < reserved_start)
            .ok_or_else(|| Error::KernelLoad("raw kernel overlaps reserved low RAM".into()))?;
        if !layout.contains(KERNEL_LOAD_ADDR, kernel_size) {
            return Err(Error::KernelLoad(
                "raw kernel is outside usable PC RAM".into(),
            ));
        }
        mem.write_slice(&kernel_data, GuestAddress(KERNEL_LOAD_ADDR))?;
        let result = KernelLoaderResult {
            kernel_load: GuestAddress(KERNEL_LOAD_ADDR),
            kernel_end: end,
            setup_header: None,
            pvh_boot_cap: PvhBootCapability::PvhEntryNotPresent,
        };
        Ok((result, false, None, end))
    }

    fn load_initrd(
        mem: &GuestMemoryMmap,
        initrd_path: &std::path::Path,
        max_addr: u64,
        kernel_end: u64,
    ) -> Result<(GuestAddress, u64)> {
        info!(path = %initrd_path.display(), "loading initrd");
        let buf = std::fs::read(initrd_path)?;
        let size = buf.len() as u64;
        if size == 0 {
            return Err(Error::KernelLoad("initrd is empty".to_string()));
        }
        let available_end = max_addr
            .checked_add(1)
            .and_then(|end| end.checked_sub(size))
            .ok_or_else(|| Error::KernelLoad("initrd does not fit in guest memory".into()))?;
        let start = align_down(available_end, PAGE_SIZE);
        if start < kernel_end {
            return Err(Error::KernelLoad(
                "initrd overlaps kernel image".to_string(),
            ));
        }
        let start_addr = GuestAddress(start);
        mem.write_slice(&buf, start_addr)?;
        Ok((start_addr, size))
    }

    fn build_e820(layout: ram::Layout, reserved_start: u64) -> Vec<boot_e820_entry> {
        let mut entries = Vec::new();
        if LOW_MEM_END > 0 {
            entries.push(boot_e820_entry {
                addr: 0,
                size: LOW_MEM_END,
                type_: E820_RAM,
            });
        }
        if BIOS_END > LOW_MEM_END {
            entries.push(boot_e820_entry {
                addr: LOW_MEM_END,
                size: BIOS_END - LOW_MEM_END,
                type_: E820_RESERVED,
            });
        }
        if reserved_start > BIOS_END {
            entries.push(boot_e820_entry {
                addr: BIOS_END,
                size: reserved_start - BIOS_END,
                type_: E820_RAM,
            });
        }
        if layout.low_end > reserved_start {
            let reserved_end = if layout.low_end == ram::LOW_END {
                ram::HIGH_START
            } else {
                layout.low_end
            };
            entries.push(boot_e820_entry {
                addr: reserved_start,
                size: reserved_end - reserved_start,
                type_: E820_RESERVED,
            });
        }
        if let Some(high) = layout.high() {
            entries.push(boot_e820_entry {
                addr: high.start,
                size: high.end - high.start,
                type_: E820_RAM,
            });
        }
        entries
    }

    /// Build initial system registers for 64-bit long mode boot.
    fn build_sregs() -> SystemRegisters {
        // 64-bit code segment (L=1, D=0 for long mode)
        let cs = Segment {
            base: 0,
            limit: 0xfffff,
            selector: BOOT_CS,
            type_: 0x0b, // Execute/Read, accessed
            present: true,
            dpl: 0,
            db: false, // Must be 0 for 64-bit code
            s: true,
            l: true, // 64-bit mode
            g: true,
            avl: false,
            unusable: false,
        };

        // Data segment
        let ds = Segment {
            base: 0,
            limit: 0xfffff,
            selector: BOOT_DS,
            type_: 0x03, // Read/Write, accessed
            present: true,
            dpl: 0,
            db: true,
            s: true,
            l: false,
            g: true,
            avl: false,
            unusable: false,
        };

        // TSS segment
        let tr = Segment {
            base: TSS_ADDR,
            limit: 0x67, // Minimum TSS size - 1
            selector: BOOT_TR,
            type_: 0x0b, // 32-bit busy TSS
            present: true,
            dpl: 0,
            db: false,
            s: false, // System segment
            l: false,
            g: false,
            avl: false,
            unusable: false,
        };

        // LDT (not used but needs valid state)
        let ldt = Segment {
            base: 0,
            limit: 0xffff,
            selector: 0,
            type_: 2,
            present: true,
            dpl: 0,
            db: false,
            s: false,
            l: false,
            g: false,
            avl: false,
            unusable: true,
        };

        SystemRegisters {
            cs,
            ds: ds.clone(),
            es: ds.clone(),
            fs: ds.clone(),
            gs: ds.clone(),
            ss: ds,
            tr,
            ldt,
            gdt: DescriptorTable {
                base: GDT_ADDR,
                limit: (5 * 8 - 1) as u16,
            },
            idt: DescriptorTable {
                base: 0,
                limit: 0xffff,
            },
            cr0: X86_CR0_PE | X86_CR0_PG | 0x20, // PE + PG + NE
            cr2: 0,
            cr3: PML4_ADDR,
            cr4: X86_CR4_PAE,
            cr8: 0,
            efer: EFER_LME | EFER_LMA,
            star: 0,
            lstar: 0,
            cstar: 0,
            fmask: 0,
            sysenter_cs: 0,
            sysenter_esp: 0,
            sysenter_eip: 0,
            dr0: 0,
            dr1: 0,
            dr2: 0,
            dr3: 0,
            dr6: 0xFFFF0FF0, // Default value after reset
            dr7: 0x00000400, // Default value after reset
        }
    }

    /// Set up page tables for identity mapping and kernel virtual address space.
    ///
    /// Creates the following mappings:
    /// - PML4[0]: Identity maps the complete PC RAM capacity and device window
    /// - PML4[273]: Direct physical memory map at 0xffff888000000000
    /// - PML4[511]: Kernel text area at 0xffffffff80000000
    fn setup_page_tables(mem: &GuestMemoryMmap) -> Result<()> {
        // Clear all page table pages first
        let zero_page = [0u8; 4096];
        mem.write_slice(&zero_page, GuestAddress(PML4_ADDR))?;
        mem.write_slice(&zero_page, GuestAddress(PDPTE_ADDR))?;
        mem.write_slice(&zero_page, GuestAddress(PDE_ADDR))?;
        mem.write_slice(&zero_page, GuestAddress(PDPTE_KERNEL_ADDR))?;
        mem.write_slice(&zero_page, GuestAddress(PDE_KERNEL_ADDR))?;
        mem.write_slice(&zero_page, GuestAddress(PDPTE_DIRECT_ADDR))?;

        // === PML4 entries ===
        // PML4[0] selects the PDPT populated for the complete PC RAM cap below.
        let pml4_entry_0: u64 = PDPTE_ADDR | 0x3; // Present + Writable
        mem.write_obj(pml4_entry_0, GuestAddress(PML4_ADDR + 0 * 8))?;

        // PML4[273] - Direct physical memory map at 0xffff888000000000
        // Linux uses this for the "direct map" of all physical memory
        let pml4_entry_273: u64 = PDPTE_DIRECT_ADDR | 0x3;
        mem.write_obj(pml4_entry_273, GuestAddress(PML4_ADDR + 273 * 8))?;

        // PML4[511] - Kernel text area at 0xffffffff80000000
        let pml4_entry_511: u64 = PDPTE_KERNEL_ADDR | 0x3;
        mem.write_obj(pml4_entry_511, GuestAddress(PML4_ADDR + 511 * 8))?;

        // === PDPTE for identity mapping (PML4[0]) ===
        // Use 1GB huge pages directly in PDPTE to cover more memory
        // One PDPT contains512 one-GiB leaves. The configured cap plus the
        // device window needs65; the compile-time bound prevents page overflow.
        for i in 0u64..BOOTSTRAP_RAM_GIB {
            let pdpte_entry: u64 = (i << 30) | 0x83; // Present + Writable + Huge (1GB page)
            mem.write_obj(pdpte_entry, GuestAddress(PDPTE_ADDR + i * 8))?;
        }

        // === PDPTE for direct map (PML4[273] at 0xffff888000000000) ===
        // The direct map provides physical memory access at high virtual addresses.
        // Cover every possible configured physical RAM address. Retain the
        // historical physical-zero aliases beyond the supported PC extent.
        for i in 0u64..512 {
            let phys_addr = if i < BOOTSTRAP_RAM_GIB { i << 30 } else { 0 };
            let pdpte_entry: u64 = phys_addr | 0x83; // Present + Writable + Huge (1GB page)
            mem.write_obj(pdpte_entry, GuestAddress(PDPTE_DIRECT_ADDR + i * 8))?;
        }

        // === PDPTE for kernel text (PML4[511]) ===
        // PML4[511] covers virtual 0xffffff8000000000 to 0xffffffffffffffff (512 GB).
        // The kernel text area starts at 0xffffffff80000000.
        //
        // Virtual address 0xffffffff80000000 is in PML4[511] at:
        //   offset = 0xffffffff80000000 - 0xffffff8000000000 = 0x7f80000000
        //   PDPTE index = offset / 1GB = 510
        //
        // Linux kernel expects: virt 0xffffffff80000000 + X -> phys X
        // So PDPTE[510] should map to physical 0, PDPTE[511] to physical 1GB, etc.
        //
        // PDPTE[i] for i < 510: not used by kernel, map to 0
        // PDPTE[510]: physical 0 (covers 0xffffffff80000000-0xffffffffbfffffff)
        // PDPTE[511]: physical 1GB (covers 0xffffffffc0000000-0xffffffffffffffff)
        for i in 0u64..512 {
            let phys_addr = if i >= 510 {
                // Kernel text region: PDPTE[510+j] -> physical j*1GB
                ((i - 510) % 8) << 30
            } else {
                // Below kernel text: not normally used, map to 0 for safety
                0
            };
            let pdpte_entry: u64 = phys_addr | 0x83; // Present + Writable + Huge (1GB page)
            mem.write_obj(pdpte_entry, GuestAddress(PDPTE_KERNEL_ADDR + i * 8))?;
        }

        debug!(
            pml4 = format!("{:#x}", PML4_ADDR),
            "setup page tables: identity map + kernel space + direct map"
        );
        Ok(())
    }

    fn write_gdt(mem: &GuestMemoryMmap) -> Result<()> {
        // Build TSS descriptor (16 bytes for 32-bit TSS)
        let tss_base = TSS_ADDR;
        let tss_limit: u32 = 0x67;

        // 32-bit TSS descriptor (type 0x89 = available 32-bit TSS)
        let tss_low = (tss_limit & 0xffff) as u64
            | ((tss_base & 0xffffff) << 16)
            | (0x89u64 << 40)
            | ((tss_limit as u64 >> 16) & 0xf) << 48
            | ((tss_base >> 24) & 0xff) << 56;

        // 64-bit code segment: L=1, D=0
        let code64_entry = gdt_entry_64bit(0x9a);

        let gdt = [
            0u64,            // 0x00: null
            0u64,            // 0x08: null
            code64_entry,    // 0x10: 64-bit code segment
            gdt_entry(0x92), // 0x18: data segment
            tss_low,         // 0x20: TSS descriptor
        ];
        debug!(
            gdt_entries = format!("{:#018x?}", gdt),
            gdt_addr = format!("{:#x}", GDT_ADDR),
            "writing GDT"
        );
        for (index, entry) in gdt.iter().enumerate() {
            let addr = GuestAddress(GDT_ADDR + (index as u64 * 8));
            mem.write_obj(*entry, addr)?;
        }

        // Write a minimal TSS at TSS_ADDR
        let tss = [0u8; 104];
        mem.write_slice(&tss, GuestAddress(TSS_ADDR))?;

        debug!(tss_addr = format!("{:#x}", TSS_ADDR), "wrote TSS");
        Ok(())
    }
}

mod devices;
mod owned_setup;
pub(crate) use devices::PcCheckpoint;
pub use devices::PcDevices;

impl Machine for PcMachine {
    fn name(&self) -> &'static str {
        "x86_64"
    }

    fn setup_devices(&self, io_bus: &mut IoBus, mmio_bus: &mut MmioBus) -> Result<()> {
        // Historical two-call API. The VMM uses setup_owned_devices instead.
        let devices = self.setup_pc_devices(io_bus, mmio_bus)?;
        *BOOT_IDE_PRIMARY
            .lock()
            .map_err(|_| Error::Emulator("legacy IDE binding poisoned".into()))? =
            Some(devices.ide_primary.clone());
        Ok(())
    }

    fn setup_owned_devices(
        &self,
        io_bus: &mut IoBus,
        mmio_bus: &mut MmioBus,
    ) -> Result<Option<PcDevices>> {
        self.setup_pc_devices(io_bus, mmio_bus).map(Some)
    }

    fn load_kernel_with_devices(
        &self,
        mem: &GuestMemoryMmap,
        config: &VmConfig,
        devices: Option<&PcDevices>,
    ) -> Result<BootInfo> {
        let devices = devices
            .ok_or_else(|| Error::InvalidConfig("missing owned PC device binding".into()))?;
        self.load_pc_kernel(mem, config, Some(&devices.ide_primary))
    }

    fn serial_irq(&self) -> Option<u32> {
        Some(4)
    }

    fn load_kernel(&self, mem: &GuestMemoryMmap, config: &VmConfig) -> Result<BootInfo> {
        let legacy = BOOT_IDE_PRIMARY
            .lock()
            .map_err(|_| Error::Emulator("legacy IDE binding poisoned".into()))?
            .clone();
        self.load_pc_kernel(mem, config, legacy.as_ref())
    }

    #[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
    fn init_vm(&self, vm: &KvmVm, boot: &BootInfo) -> Result<()> {
        let boot = boot
            .as_x86_64()
            .ok_or_else(|| Error::InvalidConfig("expected x86_64 boot info".to_string()))?;
        debug!("creating IRQ chip");
        vm.create_irq_chip()?;
        debug!("creating PIT2");
        vm.create_pit2_with_speaker()?;
        debug!(
            tss_addr = format!("{:#x}", boot.tss_addr),
            "setting TSS address"
        );
        vm.set_tss_address(boot.tss_addr)?;
        debug!(
            identity_map_addr = format!("{:#x}", boot.identity_map_addr),
            "setting identity map address"
        );
        vm.set_identity_map_address(boot.identity_map_addr)?;
        debug!("init_vm complete");
        Ok(())
    }

    fn initial_cpu_state(&self, mem: &GuestMemoryMmap, boot: &BootInfo) -> Result<CpuState> {
        // El-Torito real-mode boot: use the armed 16-bit CPU state (CR0.PE=0,
        // CS:IP=0:0x7C00, boot image already loaded) — skip the long-mode page
        // tables / GDT entirely.
        let boot = boot
            .as_x86_64()
            .ok_or_else(|| Error::InvalidConfig("expected x86_64 boot info".to_string()))?;
        if let Some(real_mode) = &boot.real_mode {
            return Ok(CpuState::X86_64(X86_64CpuState {
                regs: real_mode.regs.clone(),
                sregs: real_mode.sregs.clone(),
            }));
        }

        // Setup page tables and GDT in guest memory
        Self::setup_page_tables(mem)?;
        Self::write_gdt(mem)?;

        // Build initial CPU state
        let regs = Registers {
            rip: boot.entry_point,
            rflags: 0x2,
            rsp: BOOT_STACK_ADDR,
            rbp: 0,
            rbx: 0,
            rdi: 0,
            rsi: boot.boot_params_addr.raw_value(),
            ..Default::default()
        };

        let sregs = Self::build_sregs();

        info!(
            rip = format!("{:#x}", regs.rip),
            rsp = format!("{:#x}", regs.rsp),
            rsi = format!("{:#x}", regs.rsi),
            cr0 = format!("{:#x}", sregs.cr0),
            cr3 = format!("{:#x}", sregs.cr3),
            cr4 = format!("{:#x}", sregs.cr4),
            efer = format!("{:#x}", sregs.efer),
            cs_l = sregs.cs.l,
            "initial CPU state built"
        );

        Ok(CpuState::X86_64(X86_64CpuState { regs, sregs }))
    }
}

fn gdt_entry(access: u8) -> u64 {
    let flags: u64 = 0xcf; // G=1, D/B=1, L=0, AVL=1
    let limit: u64 = 0xffff;
    let base: u64 = 0;
    (limit & 0xffff)
        | ((base & 0xffffff) << 16)
        | ((access as u64) << 40)
        | ((flags as u64) << 48)
        | ((base >> 24) << 56)
}

/// Create a 64-bit code segment GDT entry (L=1, D=0)
fn gdt_entry_64bit(access: u8) -> u64 {
    let flags: u64 = 0xaf; // G=1, D/B=0, L=1, AVL=1 (64-bit mode)
    let limit: u64 = 0xffff;
    let base: u64 = 0;
    (limit & 0xffff)
        | ((base & 0xffffff) << 16)
        | ((access as u64) << 40)
        | ((flags as u64) << 48)
        | ((base >> 24) << 56)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempIso {
        path: std::path::PathBuf,
    }

    impl Drop for TempIso {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn synthetic_iso() -> Vec<u8> {
        const CD_SECTOR: usize = 2048;
        let cat_sector = 0x14u32;
        let image_lba = 0x15u32;
        let sector_count = 4u16;
        let mut iso = vec![0u8; (image_lba as usize + 1) * CD_SECTOR];

        let pvd = 16 * CD_SECTOR;
        iso[pvd] = 1;
        iso[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
        iso[pvd + 6] = 1;

        let brvd = 17 * CD_SECTOR;
        iso[brvd] = 0;
        iso[brvd + 1..brvd + 6].copy_from_slice(b"CD001");
        iso[brvd + 6] = 1;
        iso[brvd + 7..brvd + 7 + 23].copy_from_slice(b"EL TORITO SPECIFICATION");
        iso[brvd + 0x47..brvd + 0x4B].copy_from_slice(&cat_sector.to_le_bytes());

        let cat = cat_sector as usize * CD_SECTOR;
        iso[cat] = 0x01;
        iso[cat + 0x1E] = 0x55;
        iso[cat + 0x1F] = 0xAA;
        let entry = cat + 32;
        iso[entry] = 0x88;
        iso[entry + 1] = 0x00;
        iso[entry + 2..entry + 4].copy_from_slice(&0u16.to_le_bytes());
        iso[entry + 6..entry + 8].copy_from_slice(&sector_count.to_le_bytes());
        iso[entry + 8..entry + 12].copy_from_slice(&image_lba.to_le_bytes());

        let image = image_lba as usize * CD_SECTOR;
        iso[image] = 0xFC;
        iso[image + 1] = 0xB8;
        iso
    }

    fn temp_iso_file() -> TempIso {
        let unique = crate::host::time::system_now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "rax-iso-boot-test-{}-{unique}.iso",
            std::process::id()
        ));
        std::fs::write(&path, synthetic_iso()).expect("write synthetic ISO");
        TempIso { path }
    }

    #[test]
    fn build_e820_layout() {
        let entries =
            PcMachine::build_e820(ram::Layout::new(512 * 1024 * 1024).unwrap(), 0x1fffc000);
        assert!(entries.len() >= 3);
        let first_type = unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(entries[0].type_)) };
        assert_eq!(first_type, E820_RAM);
    }

    #[test]
    fn e820_conserves_large_ram_and_excludes_the_entire_device_window() {
        for bytes in [(3 << 30) + PAGE_SIZE, 4 << 30, 5 << 30, 64 << 30] {
            let layout = ram::Layout::new(bytes).unwrap();
            let reserved = layout.low_end - KVM_RESERVED_SIZE;
            let entries = PcMachine::build_e820(layout, reserved);
            let rows: Vec<_> = entries
                .iter()
                .map(|entry| (entry.addr, entry.size, entry.type_))
                .collect();
            assert!(
                rows.windows(2)
                    .all(|pair| pair[0].0 + pair[0].1 <= pair[1].0)
            );
            let usable: u64 = rows
                .iter()
                .filter(|row| row.2 == E820_RAM)
                .map(|row| row.1)
                .sum();
            assert_eq!(usable, bytes - (BIOS_END - LOW_MEM_END) - KVM_RESERVED_SIZE);
            assert!(
                rows.iter()
                    .filter(|row| row.2 == E820_RAM)
                    .all(|row| row.0 + row.1 <= ram::LOW_END || row.0 >= ram::HIGH_START)
            );
            assert!(rows.contains(&(ram::HIGH_START, bytes - ram::LOW_END, E820_RAM)));
        }
    }

    #[test]
    fn iso_boot_uses_kvm_setup_addresses() {
        let iso = temp_iso_file();
        let config = crate::config::VmConfig::from_sources(
            crate::config::CliConfig {
                arch: Some(crate::config::ArchKind::X86_64),
                backend: Some(crate::config::BackendKind::Kvm),
                kernel: Some(iso.path.clone()),
                ..Default::default()
            },
            None,
        )
        .expect("test VM config");
        let mem =
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x20_0000)]).expect("guest mem");

        let boot = PcMachine::new()
            .load_kernel(&mem, &config)
            .expect("ISO load_kernel");
        let BootInfo::X86_64(boot) = boot else {
            panic!("expected x86_64 boot info");
        };

        assert_eq!(boot.entry_point, 0x7C00);
        assert_eq!(boot.boot_params_addr, GuestAddress(0));
        assert_eq!(boot.identity_map_addr, KVM_TSS_IDENTITY_GAP_START);
        assert_eq!(boot.tss_addr, KVM_TSS_IDENTITY_GAP_START + PAGE_SIZE);
        assert_ne!(boot.identity_map_addr, 0);
        assert_ne!(boot.tss_addr, 0);
    }
}
