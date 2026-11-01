//! Owned PC setup and boot helper; the VMM never uses the legacy global slot.
use super::*;
impl PcMachine {
    pub(super) fn setup_pc_devices(
        &self,
        io_bus: &mut IoBus,
        mmio_bus: &mut MmioBus,
    ) -> Result<PcDevices> {
        // The PCI host bridge (config ports 0xCF8-0xCFF) is created and owned by
        // the VMM so it can be shared with the emulator MMU for BAR-mapped MMIO
        // routing; it is no longer registered here.

        let rtc = Arc::new(Mutex::new(RtcStub::new()));
        let fw_cfg = Arc::new(Mutex::new(FwCfg::new()));
        let ioapic = Arc::new(Mutex::new(IoApic::new()));
        // CMOS/RTC
        io_bus.register(
            IoRange {
                base: RTC_ADDRESS,
                len: 2,
            },
            Box::new(SharedIoDevice::new(rtc.clone())),
        )?;

        io_bus.register(
            IoRange {
                base: X86_DEBUG_PORT_BASE,
                len: X86_DEBUG_PORT_LEN,
            },
            Box::new(DebugPort::new()),
        )?;

        // QEMU fw_cfg (selector 0x510, data 0x511) - reachable via PIO exits.
        io_bus.register(
            IoRange {
                base: 0x510,
                len: 2,
            },
            Box::new(SharedIoDevice::new(fw_cfg.clone())),
        )?;

        // I/O APIC MMIO window at 0xFEC00000 (24 redirection entries).
        mmio_bus.register(
            MmioRange {
                base: 0xFEC0_0000,
                len: 0x20,
            },
            Box::new(crate::devices::bus::SharedMmioDevice::new(ioapic.clone())),
        )?;

        // ---------------------------------------------------------------------
        // Legacy ISA devices. These are wired so the guest's drivers can probe
        // and attach to them. Devices that span several non-contiguous port
        // windows share one instance via SharedIoDevice.
        // ---------------------------------------------------------------------

        // 8237A DMA controller pair. Reachable at 0x00-0x0F (controller 1),
        // 0xC0-0xDF (controller 2), and the page-register file 0x80-0x8F (which
        // also covers the 0x80 POST diagnostic port).
        let dma = Arc::new(Mutex::new(Dma::new()));
        for range in [
            IoRange {
                base: 0x00,
                len: 0x10,
            },
            IoRange {
                base: 0x80,
                len: 0x10,
            },
            IoRange {
                base: 0xC0,
                len: 0x20,
            },
        ] {
            io_bus.register(range, Box::new(SharedIoDevice::new(dma.clone())))?;
        }

        // Legacy system-control ports: 0x61 (NMI status / PC speaker / refresh)
        // and 0x92 (Port A: A20 gate + fast reset). 0xCF9 (reset control) is not
        // wired separately because it falls inside the PCI CONFIG_ADDRESS window
        // (0xCF8-0xCFF) owned by the PCI host bridge.
        let sysctl = Arc::new(Mutex::new(SystemControl::new()));
        for base in [0x61u16, 0x92] {
            io_bus.register(
                IoRange { base, len: 1 },
                Box::new(SharedIoDevice::new(sysctl.clone())),
            )?;
        }

        // i8042 PS/2 keyboard/mouse controller: data 0x60, status/command 0x64.
        // 0x61 in between belongs to the system-control block above.
        let i8042 = Arc::new(Mutex::new(I8042::new()));
        io_bus.register(
            IoRange { base: 0x60, len: 1 },
            Box::new(SharedIoDevice::new(i8042.clone())),
        )?;
        io_bus.register(
            IoRange { base: 0x64, len: 1 },
            Box::new(SharedIoDevice::new(i8042.clone())),
        )?;

        // Legacy IDE/ATA controllers, present with no media attached (the guest
        // detects the channel and finds no drive). Primary: 0x1F0-0x1F7 cmd +
        // 0x3F6 control; secondary: 0x170-0x177 cmd + 0x376 control.
        let ide_primary = Arc::new(Mutex::new(IdeController::new(0x1F0, 0x3F6, Vec::new())));
        io_bus.register(
            IoRange {
                base: 0x1F0,
                len: 8,
            },
            Box::new(SharedIoDevice::new(ide_primary.clone())),
        )?;
        io_bus.register(
            IoRange {
                base: 0x3F6,
                len: 1,
            },
            Box::new(SharedIoDevice::new(ide_primary.clone())),
        )?;
        let ide_secondary = Arc::new(Mutex::new(IdeController::new(0x170, 0x376, Vec::new())));
        io_bus.register(
            IoRange {
                base: 0x170,
                len: 8,
            },
            Box::new(SharedIoDevice::new(ide_secondary.clone())),
        )?;
        io_bus.register(
            IoRange {
                base: 0x376,
                len: 1,
            },
            Box::new(SharedIoDevice::new(ide_secondary.clone())),
        )?;

        // 82077AA floppy disk controller, no floppy inserted. The 0x3F0-0x3F7
        // window minus 0x3F6 (which is the IDE primary control port above):
        // 0x3F0-0x3F5 plus 0x3F7.
        let fdc = Arc::new(Mutex::new(Fdc::new()));
        io_bus.register(
            IoRange {
                base: 0x3F0,
                len: 6,
            },
            Box::new(SharedIoDevice::new(fdc.clone())),
        )?;
        io_bus.register(
            IoRange {
                base: 0x3F7,
                len: 1,
            },
            Box::new(SharedIoDevice::new(fdc.clone())),
        )?;

        Ok(PcDevices {
            rtc,
            fw_cfg,
            ioapic,
            dma,
            sysctl,
            i8042,
            ide_primary,
            ide_secondary,
            fdc,
        })
    }
    pub(super) fn load_pc_kernel(
        &self,
        mem: &GuestMemoryMmap,
        config: &VmConfig,
        ide_primary: Option<&Arc<Mutex<IdeController>>>,
    ) -> Result<BootInfo> {
        // Legacy/El-Torito boot: if the image is an ISO-9660 CD (cheap probe for
        // "CD001" at offset 0x8001), set it up for a 16-bit real-mode BIOS boot
        // (load the boot image at 0x7C00, install the CD for INT 13h) instead of
        // loading a Linux kernel into long mode.
        {
            use std::io::{Read, Seek, SeekFrom};
            let mut magic = [0u8; 5];
            let looks_iso = File::open(&config.kernel)
                .and_then(|mut f| {
                    f.seek(SeekFrom::Start(0x8001))?;
                    f.read_exact(&mut magic)
                })
                .map(|_| bios_boot::is_iso_image_header(&magic))
                .unwrap_or(false);
            if looks_iso {
                info!(path = %config.kernel.display(), "ISO image detected — El-Torito real-mode boot");
                let data = std::fs::read(&config.kernel)?;
                let boot = bios_boot::arm_real_mode_boot(mem, data)
                    .map_err(|e| Error::KernelLoad(format!("El-Torito boot setup: {e}")))?;
                let cdrom = Arc::new(boot.iso);
                // Also expose the ISO as an ATAPI CD-ROM on the primary IDE
                // master, so a guest that probes ATA for its CD/DVD (e.g.
                // TempleOS) finds and mounts it instead of stalling.
                if let Some(ide) = ide_primary {
                    ide.lock()
                        .map_err(|_| Error::Emulator("IDE boot binding poisoned".into()))?
                        .attach_cdrom(cdrom.clone());
                }
                let (tss_addr, identity_map_addr) = Self::kvm_setup_addresses();
                return Ok(BootInfo::X86_64(X86_64BootInfo {
                    entry_point: 0x7C00,
                    boot_params_addr: GuestAddress(0),
                    tss_addr,
                    identity_map_addr,
                    real_mode: Some(X86_64RealModeBootInfo {
                        sregs: boot.sregs,
                        regs: boot.regs,
                        cdrom,
                        mem_bytes: config.memory.bytes(),
                    }),
                }));
            }
        }

        // Use the configured memory size (what we report to the kernel via e820),
        // NOT the actual allocated size (which includes padding for per-CPU overflow).
        let mem_size = config.memory.bytes();
        if mem_size <= KERNEL_LOAD_ADDR + KVM_RESERVED_SIZE {
            return Err(Error::InvalidConfig(
                "memory is too small for kernel and reserved pages".to_string(),
            ));
        }

        // Calculate reserved_start for e820 and initrd placement (within reported memory)
        let reserved_start = align_down(mem_size - KVM_RESERVED_SIZE, PAGE_SIZE);

        // Place identity map and TSS addresses in the MMIO gap below 4GB.
        // These must NOT overlap with registered guest memory slots.
        // KVM's set_tss_address creates an internal memory slot, which fails
        // with EEXIST if it overlaps user-registered memory.
        // The memory registration leaves a gap at KVM_TSS_IDENTITY_GAP_START for this purpose.
        let (tss_addr, identity_map_addr) = Self::kvm_setup_addresses();

        let (loader_result, is_elf, elf_phys_entry) = Self::load_kernel_image(mem, config)?;

        let kernel_end = loader_result.kernel_end as u64;
        if kernel_end >= reserved_start {
            return Err(Error::KernelLoad(
                "kernel image overlaps reserved KVM region".to_string(),
            ));
        }

        // Build command line
        let cmdline = Self::build_cmdline(&config.cmdline)?;
        info!(cmdline = %config.cmdline, "loading kernel command line");
        load_cmdline(mem, GuestAddress(CMDLINE_ADDR), &cmdline).map_err(Error::from)?;
        let cmdline_size = cmdline
            .as_cstring()
            .map_err(|e| Error::KernelLoad(format!("cmdline error: {e}")))?
            .as_bytes_with_nul()
            .len() as u32;
        if CMDLINE_ADDR + cmdline_size as u64 >= BIOS_END {
            return Err(Error::KernelLoad("cmdline exceeds low memory".to_string()));
        }

        let entry_point = if is_elf {
            // ELF kernel (vmlinux) - simpler boot process
            // The entry point is directly from the ELF header
            let mut params = boot_params::default();

            // Configure VGA text mode console (80x25, mode 3)
            params.screen_info.orig_video_mode = 3; // Standard VGA text mode
            params.screen_info.orig_video_cols = 80; // 80 columns
            params.screen_info.orig_video_lines = 25; // 25 rows
            params.screen_info.orig_video_isVGA = 1; // VGA detected
            params.screen_info.orig_video_points = 16; // 16 scanlines per char

            params.hdr.type_of_loader = 0xff;
            params.hdr.loadflags = 0x1 | 0x40; // LOADED_HIGH + KEEP_SEGMENTS
            params.hdr.cmd_line_ptr = CMDLINE_ADDR as u32;
            params.hdr.cmdline_size = cmdline_size;

            // Load initrd if specified
            if let Some(initrd_path) = &config.initrd {
                let initrd_max = reserved_start - 1;
                let (initrd_addr, initrd_size) =
                    Self::load_initrd(mem, initrd_path, initrd_max, kernel_end)?;
                params.hdr.ramdisk_image = initrd_addr.raw_value() as u32;
                params.hdr.ramdisk_size = initrd_size as u32;
            }

            // Build e820 memory map
            let e820_entries = Self::build_e820(mem_size, reserved_start);
            debug!(entries = e820_entries.len(), "built e820 map");
            params.e820_entries = e820_entries.len() as u8;
            for (index, entry) in e820_entries.iter().enumerate() {
                params.e820_table[index] = *entry;
            }

            let boot_params = BootParams::new(&params, GuestAddress(BOOT_PARAMS_ADDR));
            LinuxBootConfigurator::write_bootparams(&boot_params, mem)?;

            // For ELF vmlinux, use the physical address of the first LOAD segment
            // This is where startup_64 (or a jump to it) is located
            // Note: We use the parsed PhysAddr, NOT the ELF e_entry which may be different
            let entry = elf_phys_entry.unwrap_or(loader_result.kernel_load.raw_value());
            debug!(
                entry = format!("{:#x}", entry),
                kernel_end = format!("{:#x}", kernel_end),
                "ELF kernel entry point (physical start of first LOAD segment)"
            );
            entry
        } else if let Some(setup_header) = loader_result.setup_header {
            // bzImage kernel - needs decompression setup
            // Note: Do NOT patch the bzImage - the compressed kernel data would be corrupted.
            // Any patches should be applied after decompression by the kernel itself.

            let hdr_version = { setup_header.version };
            let hdr_loadflags = { setup_header.loadflags };
            let hdr_code32_start = { setup_header.code32_start };
            debug!(
                version = format!("{:#x}", hdr_version),
                loadflags = format!("{:#x}", hdr_loadflags),
                code32_start = format!("{:#x}", hdr_code32_start),
                "setup header"
            );

            let mut params = boot_params::default();

            // Configure VGA text mode console (80x25, mode 3)
            params.screen_info.orig_video_mode = 3; // Standard VGA text mode
            params.screen_info.orig_video_cols = 80; // 80 columns
            params.screen_info.orig_video_lines = 25; // 25 rows
            params.screen_info.orig_video_isVGA = 1; // VGA detected
            params.screen_info.orig_video_points = 16; // 16 scanlines per char

            params.hdr = setup_header;
            params.hdr.type_of_loader = 0xff;
            params.hdr.loadflags |= 0x1 | 0x40;
            params.hdr.cmd_line_ptr = CMDLINE_ADDR as u32;
            params.hdr.cmdline_size = cmdline_size;
            params.hdr.pref_address = 0x5076000;

            let pref_addr = params.hdr.pref_address;
            let init_sz = params.hdr.init_size;
            debug!(
                pref_address = format!("{:#x}", pref_addr),
                init_size = format!("{:#x}", init_sz),
                "set pref_address close to decompressor bp"
            );

            if let Some(initrd_path) = &config.initrd {
                let initrd_addr_max = if params.hdr.initrd_addr_max == 0 {
                    reserved_start - 1
                } else {
                    params.hdr.initrd_addr_max as u64
                };
                let initrd_max = initrd_addr_max.min(reserved_start - 1);
                let (initrd_addr, initrd_size) =
                    Self::load_initrd(mem, initrd_path, initrd_max, kernel_end)?;
                params.hdr.ramdisk_image = initrd_addr.raw_value() as u32;
                params.hdr.ramdisk_size = initrd_size as u32;
            }

            let e820_entries = Self::build_e820(mem_size, reserved_start);
            debug!(entries = e820_entries.len(), "built e820 map");
            params.e820_entries = e820_entries.len() as u8;
            for (index, entry) in e820_entries.iter().enumerate() {
                params.e820_table[index] = *entry;
            }

            let boot_params = BootParams::new(&params, GuestAddress(BOOT_PARAMS_ADDR));
            LinuxBootConfigurator::write_bootparams(&boot_params, mem)?;

            // Verify kernel is loaded
            let mut first_bytes = [0u8; 16];
            mem.read_slice(
                &mut first_bytes,
                GuestAddress(loader_result.kernel_load.raw_value()),
            )
            .map_err(|e| Error::KernelLoad(format!("failed to read kernel: {e}")))?;
            debug!(
                entry = format!("{:#x}", loader_result.kernel_load.raw_value()),
                kernel_end = format!("{:#x}", loader_result.kernel_end),
                first_bytes = format!("{:02x?}", first_bytes),
                "kernel loaded"
            );

            // For 64-bit boot, use startup_64 at offset 0x200 from the 32-bit entry
            let entry_point_64 = loader_result.kernel_load.raw_value() + 0x200;

            let mut entry64_bytes = [0u8; 16];
            mem.read_slice(&mut entry64_bytes, GuestAddress(entry_point_64))
                .map_err(|e| Error::KernelLoad(format!("failed to read entry64: {e}")))?;

            debug!(
                entry32 = format!("{:#x}", loader_result.kernel_load.raw_value()),
                entry64 = format!("{:#x}", entry_point_64),
                entry64_bytes = format!("{:02x?}", entry64_bytes),
                "kernel entry points"
            );

            entry_point_64
        } else {
            // Raw binary - just load and jump to it
            // Load initrd if specified (place it after the kernel)
            if let Some(initrd_path) = &config.initrd {
                let initrd_max = reserved_start - 1;
                let (initrd_addr, initrd_size) =
                    Self::load_initrd(mem, initrd_path, initrd_max, kernel_end)?;
                info!(
                    initrd_addr = format!("{:#x}", initrd_addr.raw_value()),
                    initrd_size = initrd_size,
                    "initrd loaded for raw binary"
                );
            }

            info!(
                entry = format!("{:#x}", loader_result.kernel_load.raw_value()),
                "raw binary entry point"
            );
            loader_result.kernel_load.raw_value()
        };

        Ok(BootInfo::X86_64(X86_64BootInfo {
            entry_point,
            boot_params_addr: GuestAddress(BOOT_PARAMS_ADDR),
            tss_addr,
            identity_map_addr,
            real_mode: None,
        }))
    }
}
