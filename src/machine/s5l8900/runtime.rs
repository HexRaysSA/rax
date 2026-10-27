//! S5L8900 (iPod Touch 1G / iPhone 1) vCPU: boots Apple's iBoot on the
//! software ARMv6 emulator.
//!
//! Drives the AArch32 [`Armv7Cpu`] + [`Executor`] over guest memory with the
//! S5L8900 platform device set (clock, timer, PL192 VIC pair, SYSIC, GPIO,
//! chip-ID, UART, 8900 crypto engine) served at their physical MMIO windows.
//! Firmware (bootrom, iBoot, NOR) and the bootrom-call patches are placed in
//! guest RAM by the arch boot setup; the CPU resets to IBOOT_BASE.

use std::cell::RefCell;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use tracing::{debug, info};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use crate::devices::crypto::{AesKey, aes_cbc_decrypt, sha1};
use crate::devices::s3c64xx::S3cUart;
use crate::devices::s5l8900::{
    AES_UID_KEY, AesKeyType, GPIO_NUMINTGROUPS, NAND_BYTES_PER_SPARE, Pl192, S5lAes, S5lChipId,
    S5lClock, S5lDmac, S5lGpio, S5lI2c, S5lLcd, S5lNand, S5lNandEcc, S5lSdio, S5lSpi, S5lSysic,
    S5lTimer, S5lUsb,
};
use crate::error::{Error, Result};
use crate::isa::arm::execution::{ArmMemory, MemoryError};
use crate::isa::arm::mmu_v6::{self, V6Access, V6Fault, V6MmuConfig};
use crate::isa::arm::{
    Armv7Cpu, Decoder, ExceptionType, ExecResult, ExecutionState, Executor, Mnemonic, ProcessorMode,
};
use crate::vm::vcpu::{
    Aarch32CpuState, Aarch32Registers, Aarch32SystemRegisters, CpuState, VCpu, VcpuExit,
};

mod crypto;

// Device MMIO base addresses (see the QEMU iPod Touch 1G reference).
const CLOCK0_BASE: u32 = 0x3810_0000;
const CLOCK1_BASE: u32 = 0x3C50_0000;
const VIC0_BASE: u32 = 0x38E0_0000;
const VIC1_BASE: u32 = 0x38E0_1000;
const SYSIC_BASE: u32 = 0x39A0_0000;
const TIMER1_BASE: u32 = 0x3E20_0000;
const GPIO_BASE: u32 = 0x3E40_0000;
const CHIPID_BASE: u32 = 0x3E50_0000;
const UART0_BASE: u32 = 0x3CC0_0000;
const I2C0_BASE: u32 = 0x3C60_0000;
const I2C1_BASE: u32 = 0x3C90_0000;
const SPI0_BASE: u32 = 0x3C30_0000;
const SPI1_BASE: u32 = 0x3CE0_0000;
const SPI2_BASE: u32 = 0x3D20_0000;
const LCD_BASE: u32 = 0x3890_0000;
const NAND_BASE: u32 = 0x38A0_0000;
const NAND_ECC_BASE: u32 = 0x38F0_0000;
const SDIO_BASE: u32 = 0x38D0_0000;
const ADM_BASE: u32 = 0x3880_0000;
const DMAC0_BASE: u32 = 0x3820_0000;
const DMAC1_BASE: u32 = 0x3990_0000;
const USB_OTG_BASE: u32 = 0x3840_0000;
const USB_PHYS_BASE: u32 = 0x3C40_0000;
const MBX_BASE: u32 = 0x3B00_0000;
const MBX_SIZE: u32 = 0x0100_0000;
const MPVD_BASE: u32 = 0x3960_0000;
const MPVD_SIZE: u32 = 0x0007_0000;
const H264BPD_BASE: u32 = 0x3980_0000;
const H264BPD_SIZE: u32 = 0x1000;
const EDGEIC_BASE: u32 = 0x38E0_2000;
const WATCHDOG_BASE: u32 = 0x3E30_0000;
const IIS0_BASE: u32 = 0x3D40_0000;
const IIS1_BASE: u32 = 0x3CD0_0000;
const IIS2_BASE: u32 = 0x3CA0_0000;
const ENGINE_8900_BASE: u32 = 0x3F00_0000;
const AES_BASE: u32 = 0x38C0_0000;
const NOR_BASE: u32 = 0x2400_0000;
const NOR_SIZE: u32 = 1024 * 1024;
const NOR_MANUFACTURER_ID: u16 = 0x00bf;
const NOR_DEVICE_ID: u16 = 0x273f;
const ARM_LDR_PC_PC_0X18: u32 = 0xe59f_f018;
const ARM_MOV_PC_R9: u32 = 0xe1a0_f009;

const IBOOT_BASE: u32 = 0x1800_0000;
const LLB_BASE: u32 = 0x2200_0000;
/// The S5L8900 maps its 128 MiB DRAM window at 0x0800_0000, not at address zero.
const S5L_RAM_BASE: u64 = 0x0800_0000;
const S5L_8900_HEADER_LEN: usize = 2048;
const S5L_8900_IMAGE_KEY: [u8; 16] = [
    0x18, 0x84, 0x58, 0xA6, 0xD1, 0x50, 0x34, 0xDF, 0xE3, 0x86, 0xF2, 0x3B, 0x61, 0xD4, 0x37, 0x74,
];
/// iBoot's printf-style console formatter wrapper. Useful as a diagnostic
/// hook because normal serial output is still not visible.
const IBOOT_PRINTF: u32 = IBOOT_BASE + 0x0001_7466;
const IBOOT_SECURITY_STATE_CHECK: u32 = IBOOT_BASE + 0x0000_5064;
const IBOOT_SECURITY_STATE_WORD: u32 = IBOOT_BASE + 0x0002_2fa0;
const IBOOT_SECURITY_IMG2_LOAD_OK: u32 = 1 << 4;
const IBOOT_VFL_MASK_TEST: u32 = IBOOT_BASE + 0x0001_5b14;
const IBOOT_IMAGE_LIMIT: u32 = IBOOT_BASE + 0x0003_0000;
const KERNEL_PANIC: u32 = 0xC001_9790;
const KERNEL_IOPANIC: u32 = 0xC012_D734;
const KERNEL_SLEH_ABORT: u32 = 0xC006_3620;
const KERNEL_USB_WRANGLER_PHY_REGISTERED_NOTIFIER: u32 = 0xC04B_84DC;
const KERNEL_USB_WRANGLER_PHY_REGISTERED_AFTER_NOTIFIER: u32 = 0xC04B_84EC;
const KERNEL_ADMFMC_DISPATCH: u32 = 0xC04A_29D0;
const KERNEL_ADMFMC_PERFORM_IO: u32 = 0xC04A_2240;
const KERNEL_CLOCK_INITIALIZE_CALENDAR: u32 = 0xC001_8A68;
const KERNEL_ASSERT_WAIT: u32 = 0xC002_149A;
const KERNEL_ASSERT_WAIT_TIMEOUT: u32 = 0xC002_1A9C;
const KERNEL_ASSERT_WAIT_DEADLINE: u32 = 0xC002_1B4C;
const KERNEL_THREAD_BLOCK_REASON: u32 = 0xC002_2784;
const KERNEL_THREAD_BLOCK: u32 = 0xC002_2928;
const KERNEL_THREAD_WAIT: u32 = 0xC002_2E54;
const KERNEL_SEMAPHORE_TIMEDWAIT: u32 = 0xC002_4E08;
const KERNEL_SEMAPHORE_WAIT: u32 = 0xC002_4E78;
const KERNEL_WAKEUP: u32 = 0xC010_0776;
const KERNEL_WAKEUP_ONE: u32 = 0xC010_0784;
const KERNEL_IOLOCK_SLEEP: u32 = 0xC012_E0C2;
const KERNEL_IOLOCK_SLEEP_DEADLINE: u32 = 0xC012_E0D4;
const KERNEL_IOSYNCER_WAIT: u32 = 0xC012_E8F0;
const KERNEL_IOKIT_INITIALIZE_TIME: u32 = 0xC012_E958;
const KERNEL_START_IOKIT: u32 = 0xC012_E9A4;
const KERNEL_IO_SERVICE_PUBLISH_RESOURCE_CSTR: u32 = 0xC013_4858;
const KERNEL_IO_SERVICE_ADD_NEEDED_RESOURCE: u32 = 0xC013_4894;
const KERNEL_IO_SERVICE_CHECK_RESOURCES: u32 = 0xC013_4930;
const KERNEL_IO_SERVICE_WAIT_QUIET: u32 = 0xC013_49FA;
const KERNEL_IO_SERVICE_WAIT_FOR_SERVICE: u32 = 0xC013_4FBA;
const KERNEL_IO_SERVICE_WAIT_FOR_SERVICE_AFTER_SEM: u32 = 0xC013_5002;
const KERNEL_IO_SERVICE_RESOURCE_MATCHING_CSTR: u32 = 0xC013_5354;
const KERNEL_IO_SERVICE_START_CANDIDATE_AFTER_CHECK_RESOURCES: u32 = 0xC013_6627;
const KERNEL_IO_SERVICE_WAIT_MATCH_IDLE: u32 = 0xC013_75DC;
const KERNEL_IOKIT_BSD_INIT: u32 = 0xC015_5250;
const KERNEL_IOBSD_NAME_MATCHING: u32 = 0xC015_5264;
const KERNEL_IOUUID_MATCHING: u32 = 0xC015_52B0;
const KERNEL_IOBSD_REGISTRY_ENTRY_FOR_DEVICE_TREE: u32 = 0xC015_6118;
const KERNEL_IOBSD_REGISTRY_ENTRY_GET_DATA: u32 = 0xC015_6144;
const KERNEL_DI_ROOT_IMAGE: u32 = 0xC015_6170;
const KERNEL_VFS_MOUNTROOT: u32 = 0xC007_BAB4;
const KERNEL_DEVFS_KERNEL_MOUNT: u32 = 0xC009_0A70;
const KERNEL_BSD_AUTOCONF: u32 = 0xC01A_3730;
const KERNEL_BSD_INIT: u32 = 0xC01A_37A0;
const KERNEL_BSD_INIT_CALL_IOKIT_INITIALIZE_TIME: u32 = 0xC01A_3A32;
const KERNEL_BSD_INIT_CALL_BSD_AUTOCONF: u32 = 0xC01A_3ACE;
const KERNEL_BSD_INIT_CALL_VFS_MOUNTROOT: u32 = 0xC01A_3BBA;
const KERNEL_BSD_INIT_AFTER_VFS_MOUNTROOT: u32 = 0xC01A_3BBE;
const KERNEL_MOUNTROOT_GLOBAL: u32 = 0xC01A_F130;
const KERNEL_ROOTDEV_GLOBAL: u32 = 0xC026_19B4;
const KERNEL_ROOTDEVICE_GLOBAL: u32 = 0xC026_19C0;
const KERNEL_ROOTFS_GLOBAL: u32 = 0xC026_19D0;
const KERNEL_ROOTVNODE_GLOBAL: u32 = 0xC026_19D4;
const KERNEL_ROOTVP_GLOBAL: u32 = 0xC026_19D8;
const KERNEL_IOMEDIA_BSD_CLIENT_VTABLE: u32 = 0xC045_8A88;
const KERNEL_FDISK_TRACE_PCS: &[(u32, &str)] = &[
    (0xC036_7B18, "iofdisk class/meta init"),
    (0xC036_7B38, "iofdisk class string ref"),
    (0xC036_7B60, "iofdisk class string ref"),
    (0xC036_8518, "iofdisk class string ref"),
    (0xC036_99B8, "iomedia class string ref"),
    (0xC036_99E0, "iomedia class string ref"),
    (0xC036_9A58, "iomedia/storage helper"),
    (0xC036_9B5C, "iostorage/fdisk candidate"),
    (0xC036_9BF8, "iostorage/fdisk candidate"),
    (0xC036_9CA8, "content mask string ref"),
    (0xC036_9CB0, "iostorage/fdisk candidate"),
    (0xC036_9D78, "iostorage/fdisk candidate"),
    (0xC036_9E88, "iostorage/fdisk candidate"),
    (0xC036_9FB4, "iostorage/fdisk candidate"),
    (0xC036_A0E0, "iostorage/fdisk candidate"),
    (0xC036_A2F8, "content mask string ref"),
    (0xC036_A884, "iostorage/fdisk candidate"),
    (0xC036_A8C8, "iomedia class string ref"),
];
const KERNEL_NANDFTL_TRACE_PCS: &[(u32, &str)] = &[
    (0xC046_0800, "nandftl FIL init entry"),
    (0xC046_0824, "nandftl FIL read fallback path"),
    (0xC046_0860, "nandftl FIL write multiple capability"),
    (0xC046_08B4, "nandftl FIL init failure branch"),
    (0xC046_08C0, "nandftl FIL init failure cleanup"),
    (0xC046_09C0, "nandftl FIL init return path"),
    (0xC046_2858, "nandftl provider match result"),
    (0xC046_2890, "nandftl superclass start result"),
    (0xC046_28B4, "nandftl capabilities lookup result"),
    (0xC046_28D8, "nandftl call FIL init wrapper"),
    (0xC046_28E0, "nandftl FIL init wrapper result"),
    (0xC046_28EC, "nandftl call buffer init"),
    (0xC046_28F0, "nandftl buffer init result"),
    (0xC046_29C4, "nandftl AND init result"),
    (0xC046_29FC, "nandftl AND init success"),
    (0xC046_2AE4, "nandftl create workloop call"),
    (0xC046_2AF4, "nandftl workloop result"),
    (0xC046_2B04, "nandftl command gate result"),
    (0xC046_2B08, "nandftl workloop/command gate check"),
    (0xC046_2B24, "nandftl add command gate to workloop call"),
    (0xC046_2B28, "nandftl add command gate to workloop result"),
    (0xC046_2B30, "nandftl workloop/command gate failure"),
    (0xC046_2B4C, "nandftl resolve block device super"),
    (0xC046_2B5C, "nandftl store block device super"),
    (0xC046_2B88, "nandftl resolve userclient super"),
    (0xC046_2B9C, "nandftl register userclient class"),
    (0xC046_2BA4, "nandftl register userclient class call"),
    (0xC046_2BC0, "nandftl start workloop hookup"),
    (0xC046_2BD0, "nandftl start provider hookup"),
    (0xC046_2C1C, "nandftl start register service"),
    (0xC046_2C40, "nandftl allocate block device call"),
    (0xC046_2C48, "nandftl block device allocation result"),
    (0xC046_2C50, "nandftl block device allocation failure"),
    (0xC046_2C64, "nandftl attach block device call"),
    (0xC046_2C68, "nandftl attach block device result"),
    (0xC046_2C70, "nandftl attach block device failure"),
    (0xC046_2C94, "nandftl block device attached"),
    (0xC046_2CE4, "nandftl open block device"),
    (0xC046_2D04, "nandftl success log flag check"),
    (0xC046_2D14, "nandftl publish ready status"),
    (0xC046_2D2C, "nandftl start success return"),
    (0xC046_2D34, "nandftl inheritance retry decision"),
    (0xC046_2D44, "nandftl inheritance retry branch"),
    (0xC046_2D48, "nandftl inheritance unsupported branch"),
    (0xC046_2D4C, "nandftl start epilogue"),
];
const KERNEL_WMR_TRACE_PCS: &[(u32, &str)] = &[
    (0xC046_3AC8, "wmr init entry"),
    (0xC046_3B38, "wmr FIL init result"),
    (0xC046_3B50, "wmr BUF init result"),
    (0xC046_3B68, "wmr VFL init result"),
    (0xC046_3B80, "wmr FTL init result"),
    (0xC046_3B90, "wmr post FTL init ok"),
    (0xC046_3B98, "wmr function table result"),
    (0xC046_3BA4, "wmr BUF_Get call"),
    (0xC046_3BA8, "wmr BUF_Get result"),
    (0xC046_3BBC, "wmr signature loop enter"),
    (0xC046_3BC0, "wmr signature read setup"),
    (0xC046_3BD8, "wmr signature read call"),
    (0xC046_3BDC, "wmr signature read result"),
    (0xC046_3C08, "wmr signature fallback read call"),
    (0xC046_3C0C, "wmr signature fallback read result"),
    (0xC046_3C10, "wmr signature status check"),
    (0xC046_3C5C, "wmr unit NAND format info"),
    (0xC046_3C88, "wmr signature mismatch"),
    (0xC046_3C9C, "wmr signature loop condition"),
    (0xC046_3CB8, "wmr BUF_Free call"),
    (0xC046_3CC4, "wmr signature found check"),
    (0xC046_3CE8, "wmr epoch update notify call"),
    (0xC046_3D10, "wmr VFL_Open call"),
    (0xC046_3D18, "wmr VFL_Open result"),
    (0xC046_3D54, "wmr invalid format decision"),
    (0xC046_3D5C, "wmr invalid format log"),
    (0xC046_3DD4, "wmr reformat notify call"),
    (0xC046_3E14, "wmr production format call"),
    (0xC046_3F48, "wmr VFL_Open ok"),
    (0xC046_3F5C, "wmr FTL_Open call"),
    (0xC046_3F64, "wmr FTL_Open result"),
    (0xC046_3FA8, "wmr FTL_Open ok"),
    (0xC046_3FB0, "wmr success return"),
    (0xC046_3FB8, "wmr init critical error return"),
    (0xC046_3FC0, "wmr init unrecoverable return"),
    (0xC046_3FC4, "wmr init epilogue"),
];
const IBOOT_FSBOOT_TRACE_PCS: &[(u32, &str)] = &[
    (IBOOT_BASE + 0x0000_4224, "image-helper args"),
    (IBOOT_BASE + 0x0000_425a, "image-helper first read"),
    (IBOOT_BASE + 0x0000_427a, "image-helper descriptor"),
    (IBOOT_BASE + 0x0000_42b8, "image-helper body read"),
    (IBOOT_BASE + 0x0000_42c8, "image-helper bootrom call"),
    (IBOOT_BASE + 0x0000_42de, "image-helper failure return"),
    (IBOOT_BASE + 0x0000_434e, "fsboot hfs init"),
    (IBOOT_BASE + 0x0000_4372, "fsboot candidate lookup"),
    (IBOOT_BASE + 0x0000_4390, "fsboot call image-helper"),
    (IBOOT_BASE + 0x0000_4398, "fsboot image-helper returned"),
    (IBOOT_BASE + 0x0000_4e90, "boot-command fsboot returned"),
];

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

// IRQ line numbers on VIC0.
const TIMER1_IRQ: u32 = 0x7;
const SPI0_IRQ: u32 = 0x9;
const SPI1_IRQ: u32 = 0xA;
const SPI2_IRQ: u32 = 0xB;
const DMAC0_IRQ: u32 = 0x10;
const DMAC1_IRQ: u32 = 0x11;
const I2C0_IRQ: u32 = 0x15;
const I2C1_IRQ: u32 = 0x16;
const GPIO_GROUP_IRQS: [u32; GPIO_NUMINTGROUPS] = [0x21, 0x20, 0x1F, 0x03, 0x02, 0x01, 0x00];
/// NAND ECC engine: global IRQ 0x2B, i.e. VIC1 line (0x2B - 32) = 11.
const NAND_ECC_VIC1_LINE: u32 = 0x2B - 32;
/// ADM (Apple Data Mover): global IRQ 0x25, i.e. VIC1 line (0x25 - 32) = 5.
const ADM_VIC1_LINE: u32 = 0x25 - 32;
const LCD_IRQ: u32 = 0xD;
const USB_OTG_IRQ: u32 = 0xD;
const UART0_IRQ: u32 = 24;

/// Instructions per `run()` batch before yielding to the VMM loop.
const BATCH: u32 = 65_536;
const S5L_DMADUMP_DEFAULT_LIMIT: u64 = 16 * 1024 * 1024;

/// Guest-time scale for the µs timer. Keep the default at reference pace:
/// accelerating guest time can let timeout callouts run before their device
/// interrupt workloops, which races ADM completion during XNU boot. Explicit
/// diagnostic runs may still override the scale with RAX_S5L_TIMER_SPEEDUP.
fn parse_timer_speedup(value: Option<&str>) -> u64 {
    value
        .and_then(|value| value.parse().ok())
        .filter(|&scale| scale > 0)
        .unwrap_or(1)
}

fn timer_speedup() -> u64 {
    let value = std::env::var("RAX_S5L_TIMER_SPEEDUP").ok();
    parse_timer_speedup(value.as_deref())
}

/// Instructions per guest microsecond. Instruction pacing keeps XNU device
/// timeouts independent of how slowly the interpreter runs on the host.
fn parse_det_timer(value: Option<&str>) -> u64 {
    value.and_then(|value| value.parse().ok()).unwrap_or(32)
}

fn trace_budget_env(name: &str, default_when_present: u32) -> u32 {
    match std::env::var(name) {
        Ok(v) if v.is_empty() || v == "1" => default_when_present,
        Ok(v) => v.parse().unwrap_or(default_when_present),
        Err(_) => 0,
    }
}

fn u32_env(name: &str) -> Option<u32> {
    let value = std::env::var(name).ok()?;
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).ok()
    } else {
        value
            .parse()
            .ok()
            .or_else(|| u32::from_str_radix(value, 16).ok())
    }
}

fn u64_env(name: &str) -> Option<u64> {
    let value = std::env::var(name).ok()?;
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()
    } else {
        value
            .parse()
            .ok()
            .or_else(|| u64::from_str_radix(value, 16).ok())
    }
}

fn s5l_dmadump_limit() -> u64 {
    u64_env("RAX_S5L_DMADUMP_LIMIT").unwrap_or(S5L_DMADUMP_DEFAULT_LIMIT)
}

fn dmadump_remaining_for_path(path: &Path, limit: u64) -> usize {
    let remaining = limit.saturating_sub(std::fs::metadata(path).map(|m| m.len()).unwrap_or(0));
    remaining.min(usize::MAX as u64) as usize
}

fn append_limited_dmadump<P: AsRef<Path>>(
    path: P,
    header: &[u8],
    payload: &[u8],
    limit: u64,
) -> io::Result<()> {
    if limit == 0 {
        return Ok(());
    }

    let path = path.as_ref();
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let remaining = limit.saturating_sub(file.metadata()?.len());
    let mut remaining = remaining.min(usize::MAX as u64) as usize;

    write_limited_chunk(&mut file, &mut remaining, header)?;
    write_limited_chunk(&mut file, &mut remaining, payload)?;
    write_limited_chunk(&mut file, &mut remaining, b"\n")
}

fn write_limited_chunk<W: Write>(
    writer: &mut W,
    remaining: &mut usize,
    data: &[u8],
) -> io::Result<()> {
    if *remaining == 0 {
        return Ok(());
    }

    let len = data.len().min(*remaining);
    writer.write_all(&data[..len])?;
    *remaining -= len;
    Ok(())
}

fn parse_watch_range_env(name: &str) -> Option<(u32, u32)> {
    let v = std::env::var(name).ok()?;
    let (a, l) = v.split_once(':')?;
    let addr = u32::from_str_radix(a.trim_start_matches("0x"), 16).ok()?;
    let len = u32::from_str_radix(l.trim_start_matches("0x"), 16).ok()?;
    Some((addr, len))
}

/// Parsed-once physical write-watchpoint range from RAX_S5L_WATCH=hex:hex.
fn watch_range() -> &'static Option<(u32, u32)> {
    static WATCH: std::sync::OnceLock<Option<(u32, u32)>> = std::sync::OnceLock::new();
    WATCH.get_or_init(|| parse_watch_range_env("RAX_S5L_WATCH"))
}

/// Parsed-once virtual write-watchpoint range from RAX_S5L_VWATCH=hex:hex.
fn vwatch_range() -> &'static Option<(u32, u32)> {
    static WATCH: std::sync::OnceLock<Option<(u32, u32)>> = std::sync::OnceLock::new();
    WATCH.get_or_init(|| parse_watch_range_env("RAX_S5L_VWATCH"))
}

fn range_overlaps(addr: u32, len: usize, watch_addr: u32, watch_len: u32) -> bool {
    if len == 0 || watch_len == 0 {
        return false;
    }
    let start = addr as u64;
    let end = start + len as u64;
    let watch_start = watch_addr as u64;
    let watch_end = watch_start + watch_len as u64;
    start < watch_end && watch_start < end
}

fn bytes_hex(data: &[u8]) -> String {
    data.iter()
        .take(32)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn phys_bytes_hex(mem: &GuestMemoryMmap, pa: u32, len: usize) -> Option<String> {
    let len = len.min(32);
    if len == 0 {
        return Some(String::new());
    }
    let mut bytes = vec![0u8; len];
    mem.read_slice(&mut bytes, GuestAddress(pa as u64))
        .ok()
        .map(|()| bytes_hex(&bytes))
}

fn watch_offset(addr: u32, len: usize, watch_addr: u32) -> Option<u32> {
    let start = addr as u64;
    let end = start + len as u64;
    let watch = watch_addr as u64;
    (start <= watch && watch < end).then_some((watch - start) as u32)
}

/// The directory holding the NAND `bank<n>/<page>.page` dumps. From
/// RAX_S5L_NAND, else the iPod Touch reference dump next to the firmware.
fn nand_dir() -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("RAX_S5L_NAND") {
        return Some(std::path::PathBuf::from(p));
    }
    let default = std::path::PathBuf::from("docs/hardware/apple/iPodTouch1/nand");
    default.is_dir().then_some(default)
}

/// True when the guest-physical range `[addr, addr + len)` lies entirely within
/// the half-open guest RAM range `[mem_start, mem_end)`. Guest-controlled DMA
/// sizes (AES `insize`, the 8900 header's `data_len`) are validated against this
/// *before* any `vec![0u8; len]`, so a malicious size cannot drive a multi-GB
/// host allocation. (issues #43, #50)
fn dma_range_in_bounds(mem_start: u64, mem_end: u64, addr: u32, len: usize) -> bool {
    let start = addr as u64;
    start >= mem_start
        && start
            .checked_add(len as u64)
            .is_some_and(|end| end <= mem_end)
}

/// Recover the S5L8900 DRAM range from the padded `GuestMemoryMmap` end.
///
/// S5L gets only the mmap, not `GuestMemoryWrapper::size()`. The mmap created
/// by the VMM includes `GUEST_MEMORY_PADDING` after the memory reported to the
/// guest. The reported byte count is the length of the S5L DRAM window, whose
/// physical base is [`S5L_RAM_BASE`], rather than an address-zero upper bound.
/// Small unpadded test mappings continue to cover `[0, mmap_end)`.
fn dma_ram_bounds_from_mmap_end(mmap_end: u64) -> (u64, u64) {
    if let Some(reported_size) = mmap_end
        .checked_sub(crate::vm::memory::GUEST_MEMORY_PADDING)
        .filter(|&size| size > 0)
    {
        let end = S5L_RAM_BASE.saturating_add(reported_size);
        (S5L_RAM_BASE, end)
    } else {
        (0, mmap_end)
    }
}

/// Last memory fault recorded by the bridge (for DFSR/DFAR reporting).
#[derive(Clone, Copy, Default)]
struct LastFault {
    addr: u32,
    fsr: u32,
    domain: u32,
    access: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NorMode {
    ReadArray,
    Autoselect,
    CfiQuery,
}

impl Default for NorMode {
    fn default() -> Self {
        NorMode::ReadArray
    }
}

#[derive(Default)]
struct S5lNor {
    mode: NorMode,
    unlock_step: u8,
}

impl S5lNor {
    fn read(
        &self,
        mem: &GuestMemoryMmap,
        pa: u32,
        buf: &mut [u8],
    ) -> std::result::Result<(), MemoryError> {
        match self.mode {
            NorMode::ReadArray => mem
                .read_slice(buf, GuestAddress(pa as u64))
                .map_err(|_| MemoryError::BusError(pa)),
            NorMode::Autoselect | NorMode::CfiQuery => {
                let base = pa - NOR_BASE;
                for (i, b) in buf.iter_mut().enumerate() {
                    *b = match self.mode {
                        NorMode::Autoselect => Self::autoselect_byte(base + i as u32),
                        NorMode::CfiQuery => Self::cfi_query_byte(base + i as u32),
                        NorMode::ReadArray => unreachable!(),
                    };
                }
                Ok(())
            }
        }
    }

    fn write(&mut self, offset: u32, data: &[u8]) {
        let mut raw = [0u8; 4];
        let n = data.len().min(raw.len());
        raw[..n].copy_from_slice(&data[..n]);
        let value = u32::from_le_bytes(raw);
        let command = (value & 0xff) as u8;
        let offset = offset & !1;

        if command == 0xf0 || value == 0xffff {
            self.mode = NorMode::ReadArray;
            self.unlock_step = 0;
            return;
        }

        match self.unlock_step {
            0 if Self::is_unlock0(offset) && command == 0xaa => {
                self.unlock_step = 1;
            }
            1 if Self::is_unlock1(offset) && command == 0x55 => {
                self.unlock_step = 2;
            }
            2 if Self::is_unlock0(offset) => {
                self.mode = match command {
                    0x90 => NorMode::Autoselect,
                    0x98 => NorMode::CfiQuery,
                    _ => NorMode::ReadArray,
                };
                self.unlock_step = 0;
            }
            _ => {
                self.unlock_step = 0;
            }
        }
    }

    fn is_unlock0(offset: u32) -> bool {
        matches!(offset, 0x0aaa | 0xaaaa)
    }

    fn is_unlock1(offset: u32) -> bool {
        matches!(offset, 0x0554 | 0x5554)
    }

    fn autoselect_byte(offset: u32) -> u8 {
        let halfword = match offset & !1 {
            0x0 => NOR_MANUFACTURER_ID,
            0x2 => NOR_DEVICE_ID,
            0x4 => 0,
            _ => 0xffff,
        };
        halfword.to_le_bytes()[(offset & 1) as usize]
    }

    fn cfi_query_byte(offset: u32) -> u8 {
        let word_addr = offset >> 1;
        let value = match word_addr {
            0x10 => b'Q' as u16,
            0x11 => b'R' as u16,
            0x12 => b'Y' as u16,
            0x13 => 0x0002, // AMD/Fujitsu command set.
            0x14 => 0x0000,
            0x15 => 0x0040, // Primary extended table address.
            0x16 => 0x0000,
            0x27 => 20, // 1 MiB device size.
            0x2c => 0,  // One erase-region descriptor follows.
            0x2d => 0xff,
            0x2e => 0x00,
            0x2f => 0x10, // 4 KiB sectors.
            0x30 => 0x00,
            _ => 0xffff,
        };
        value.to_le_bytes()[(offset & 1) as usize]
    }
}

/// Mutable bridge internals (RefCell: the executor's read path is `&self`).
struct BridgeInner {
    mmu: V6MmuConfig,
    privileged: bool,
    /// PC of the instruction currently executing, for the write-watchpoint log.
    cur_pc: u32,
    /// Instruction count of the instruction currently executing.
    cur_insn: u64,
    kernel_started: bool,
    last_fault: LastFault,
    clock0: S5lClock,
    clock1: S5lClock,
    vic0: Pl192,
    vic1: Pl192,
    vic1_adm_daisy_latched: bool,
    vic1_adm_daisy_in_service: bool,
    sysic: S5lSysic,
    gpio: S5lGpio,
    timer: S5lTimer,
    i2c0: S5lI2c,
    i2c1: S5lI2c,
    spi0: S5lSpi,
    spi1: S5lSpi,
    spi2: S5lSpi,
    lcd: S5lLcd,
    nand: S5lNand,
    nand_ecc: S5lNandEcc,
    sdio: S5lSdio,
    aes: S5lAes,
    dmac0: S5lDmac,
    dmac1: S5lDmac,
    usb: S5lUsb,
    nor: S5lNor,
    /// ADM (Apple Data Mover) DMA data-section addresses.
    adm_data2: u32,
    adm_data3: u32,
    /// Pending ADM operation (ctrl value written), serviced by the vCPU step.
    adm_req: Option<u32>,
    /// ADM completion interrupt level (raised after a command, cleared on ack).
    adm_irq: bool,
    uart: Arc<OnceLock<Arc<Mutex<S3cUart>>>>,
    /// Pending 8900-engine decryption request: the physical address of the
    /// image header written to the engine MMIO. Serviced by the vCPU step.
    engine_8900_req: Option<u32>,
    /// Budget-limited log of accesses to unmapped MMIO windows.
    openbus_log_budget: u32,
    /// Log all handled device reads too (RAX_S5L_DEVLOG).
    devlog: bool,
    /// Budget-limited trace for VIC MMIO accesses (RAX_S5L_VIC_TRACE).
    vic_trace_budget: u32,
    vic_trace_start_insn: u64,
    vic_trace_adm: bool,
}

#[derive(Clone, Copy)]
struct VicTraceSnapshot {
    raw: u32,
    enabled: u32,
    selected: u32,
    irq: u32,
    fiq: u32,
    addr: u32,
    daisy_input: bool,
    daisy_vectaddr: u32,
    priority_mask: u32,
    current: u32,
    highest: u32,
    priority: u32,
    depth: usize,
    irq_line: bool,
    fiq_line: bool,
}

impl VicTraceSnapshot {
    fn capture(vic: &Pl192) -> Self {
        let (current, highest, priority, depth, irq_line, fiq_line) = vic.debug_priority_state();
        Self {
            raw: vic.rawintr,
            enabled: vic.intenable,
            selected: vic.intselect,
            irq: vic.irq_status,
            fiq: vic.fiq_status,
            addr: vic.address,
            daisy_input: vic.daisy_input,
            daisy_vectaddr: vic.daisy_vectaddr,
            priority_mask: vic.sw_priority_mask,
            current,
            highest,
            priority,
            depth,
            irq_line,
            fiq_line,
        }
    }
}

/// Memory bridge: VA→PA via the v6 MMU, S5L8900 device windows at their
/// physical addresses, everything else through the flat guest memory (which
/// backs RAM, iBoot, VROM, LLB and NOR).
struct S5lBridge {
    mem: Arc<GuestMemoryMmap>,
    inner: RefCell<BridgeInner>,
}

impl S5lBridge {
    fn translate(
        mem: &GuestMemoryMmap,
        inner: &mut BridgeInner,
        va: u32,
        access: V6Access,
    ) -> std::result::Result<u32, MemoryError> {
        let walk = |pa: u32| -> Option<u32> {
            let mut buf = [0u8; 4];
            mem.read_slice(&mut buf, GuestAddress(pa as u64)).ok()?;
            Some(u32::from_le_bytes(buf))
        };
        match mmu_v6::translate_v6(&inner.mmu, va, inner.privileged, access, walk) {
            Ok(t) => Ok(t.pa),
            Err(V6Fault { fsr, domain }) => {
                inner.last_fault = LastFault {
                    addr: va,
                    fsr,
                    domain,
                    access: match access {
                        V6Access::Read => 0,
                        V6Access::Write => 1,
                        V6Access::Execute => 2,
                    } | if inner.privileged { 4 } else { 0 },
                };
                Err(MemoryError::PermissionDenied(va))
            }
        }
    }
}

impl BridgeInner {
    fn should_trace_vic_access(&self, offset: u32) -> bool {
        if self.vic_trace_budget == 0 {
            return false;
        }
        if !(self.kernel_started || std::env::var_os("RAX_S5L_VIC_TRACE_EARLY").is_some()) {
            return false;
        }
        let interesting_offset = offset == 0xF00
            || offset <= 0x2c
            || offset == 0x30
            || offset == 0x34
            || offset == 0x300
            || (0x100..0x180).contains(&offset)
            || (0x200..0x280).contains(&offset);
        if !interesting_offset {
            return false;
        }
        if self.cur_insn >= self.vic_trace_start_insn {
            return true;
        }
        if self.vic_trace_adm {
            let adm_mask = 1 << ADM_VIC1_LINE;
            let (v0_current, v0_highest, _, _, _, _) = self.vic0.debug_priority_state();
            return self.adm_irq
                || self.vic1_adm_daisy_latched
                || self.vic1_adm_daisy_in_service
                || (self.vic1.rawintr & adm_mask) != 0
                || v0_current == 32
                || v0_highest == 32;
        }
        false
    }

    fn trace_vic_access(
        &mut self,
        vic: &'static str,
        op: &'static str,
        offset: u32,
        value: Option<u32>,
        result: Option<u32>,
        before: VicTraceSnapshot,
        after: VicTraceSnapshot,
    ) {
        if self.vic_trace_budget == 0 {
            return;
        }
        self.vic_trace_budget -= 1;
        info!(
            pc = format!("{:#x}", self.cur_pc),
            insns = self.cur_insn,
            vic,
            op,
            offset = format!("{offset:#x}"),
            value = value.map(|v| format!("{v:#x}")).unwrap_or_default(),
            result = result.map(|v| format!("{v:#x}")).unwrap_or_default(),
            before_raw = format!("{:#x}", before.raw),
            before_en = format!("{:#x}", before.enabled),
            before_sel = format!("{:#x}", before.selected),
            before_irq = format!("{:#x}", before.irq),
            before_fiq = format!("{:#x}", before.fiq),
            before_addr = format!("{:#x}", before.addr),
            before_daisy = before.daisy_input,
            before_daisy_addr = format!("{:#x}", before.daisy_vectaddr),
            before_mask = format!("{:#x}", before.priority_mask),
            before_cur = before.current,
            before_high = before.highest,
            before_prio = before.priority,
            before_depth = before.depth,
            before_irq_line = before.irq_line,
            before_fiq_line = before.fiq_line,
            after_raw = format!("{:#x}", after.raw),
            after_en = format!("{:#x}", after.enabled),
            after_sel = format!("{:#x}", after.selected),
            after_irq = format!("{:#x}", after.irq),
            after_fiq = format!("{:#x}", after.fiq),
            after_addr = format!("{:#x}", after.addr),
            after_daisy = after.daisy_input,
            after_daisy_addr = format!("{:#x}", after.daisy_vectaddr),
            after_mask = format!("{:#x}", after.priority_mask),
            after_cur = after.current,
            after_high = after.highest,
            after_prio = after.priority,
            after_depth = after.depth,
            after_irq_line = after.irq_line,
            after_fiq_line = after.fiq_line,
            adm_irq = self.adm_irq,
            adm_latched = self.vic1_adm_daisy_latched,
            adm_in_service = self.vic1_adm_daisy_in_service,
            "vic_trace"
        );
    }

    fn refresh_vic_daisy(&mut self) {
        self.vic0.daisy_input = self.vic1.irq_asserted() || self.vic1_adm_daisy_latched;
        self.vic0.daisy_vectaddr = if self.vic1_adm_daisy_latched && !self.vic1.irq_asserted() {
            self.vic1.vect_addr[ADM_VIC1_LINE as usize]
        } else {
            self.vic1.address
        };
        self.vic0.update();
    }

    /// Propagate the ADM completion level through VIC1 and its VIC0 daisy
    /// parent immediately. The reference QEMU model raises/lowers this line
    /// synchronously inside the ADM_CTRL2 MMIO write; deferring it until the
    /// next global IRQ resample can let the equal-priority DMAC0 completion win.
    fn set_adm_irq(&mut self, level: bool) {
        let was_raw = (self.vic1.rawintr & (1 << ADM_VIC1_LINE)) != 0;
        self.adm_irq = level;
        self.vic1.set_line(ADM_VIC1_LINE, level);
        if level && !was_raw {
            self.vic1_adm_daisy_latched = true;
            self.vic1_adm_daisy_in_service = false;
        } else if !level {
            self.vic1_adm_daisy_latched = false;
            self.vic1_adm_daisy_in_service = false;
        }
        self.refresh_vic_daisy();
    }

    /// Device-window read at a PHYSICAL address. Returns None when the address
    /// is plain memory (RAM/firmware) and should fall through to the mmap.
    fn dev_read(&mut self, pa: u32) -> Option<u32> {
        let off = |base: u32| pa - base;
        match pa {
            _ if (CLOCK0_BASE..CLOCK0_BASE + 0x1000).contains(&pa) => {
                Some(self.clock0.read(off(CLOCK0_BASE)))
            }
            _ if (CLOCK1_BASE..CLOCK1_BASE + 0x1000).contains(&pa) => {
                Some(self.clock1.read(off(CLOCK1_BASE)))
            }
            _ if (VIC0_BASE..VIC0_BASE + 0x1000).contains(&pa) => {
                let offset = off(VIC0_BASE);
                let trace = self.should_trace_vic_access(offset);
                let before0 = trace.then(|| VicTraceSnapshot::capture(&self.vic0));
                let before1 = trace.then(|| VicTraceSnapshot::capture(&self.vic1));
                let (value, is_daisy) = if offset == 0xF00 {
                    let (value, is_daisy) = self.vic0.acknowledge();
                    (value, is_daisy)
                } else {
                    (self.vic0.read(offset), false)
                };
                if is_daisy {
                    if self.vic1_adm_daisy_latched {
                        self.vic1_adm_daisy_in_service = true;
                    }
                    self.vic1.acknowledge_daisy_child();
                    self.refresh_vic_daisy();
                }
                if let Some(before0) = before0 {
                    self.trace_vic_access(
                        "VIC0",
                        "read",
                        offset,
                        None,
                        Some(value),
                        before0,
                        VicTraceSnapshot::capture(&self.vic0),
                    );
                    if is_daisy {
                        self.trace_vic_access(
                            "VIC1",
                            "ack_daisy",
                            0xF00,
                            None,
                            None,
                            before1.expect("VIC1 trace snapshot"),
                            VicTraceSnapshot::capture(&self.vic1),
                        );
                    }
                }
                Some(value)
            }
            _ if (VIC1_BASE..VIC1_BASE + 0x1000).contains(&pa) => {
                let offset = off(VIC1_BASE);
                let trace = self.should_trace_vic_access(offset);
                let before = trace.then(|| VicTraceSnapshot::capture(&self.vic1));
                let value = self.vic1.read(offset);
                if let Some(before) = before {
                    self.trace_vic_access(
                        "VIC1",
                        "read",
                        offset,
                        None,
                        Some(value),
                        before,
                        VicTraceSnapshot::capture(&self.vic1),
                    );
                }
                Some(value)
            }
            _ if (SYSIC_BASE..SYSIC_BASE + 0x1000).contains(&pa) => {
                Some(self.sysic.read(off(SYSIC_BASE)))
            }
            _ if (TIMER1_BASE..TIMER1_BASE + 0x10004).contains(&pa) => {
                Some(self.timer.read(off(TIMER1_BASE)))
            }
            _ if (GPIO_BASE..GPIO_BASE + 0x10000).contains(&pa) => {
                Some(self.gpio.read(off(GPIO_BASE)))
            }
            _ if (CHIPID_BASE..CHIPID_BASE + 0x10).contains(&pa) => {
                Some(S5lChipId::read(off(CHIPID_BASE)))
            }
            _ if (I2C0_BASE..I2C0_BASE + 0x1000).contains(&pa) => {
                Some(self.i2c0.read(off(I2C0_BASE)))
            }
            _ if (I2C1_BASE..I2C1_BASE + 0x1000).contains(&pa) => {
                Some(self.i2c1.read(off(I2C1_BASE)))
            }
            _ if (SPI0_BASE..SPI0_BASE + 0x100).contains(&pa) => {
                Some(self.spi0.read(off(SPI0_BASE)))
            }
            _ if (SPI1_BASE..SPI1_BASE + 0x100).contains(&pa) => {
                Some(self.spi1.read(off(SPI1_BASE)))
            }
            _ if (SPI2_BASE..SPI2_BASE + 0x100).contains(&pa) => {
                Some(self.spi2.read(off(SPI2_BASE)))
            }
            _ if (LCD_BASE..LCD_BASE + 0x1000).contains(&pa) => Some(self.lcd.read(off(LCD_BASE))),
            _ if (NAND_BASE..NAND_BASE + 0x1000).contains(&pa) => {
                self.nand.set_kernel_started(self.kernel_started);
                Some(self.nand.read(off(NAND_BASE)))
            }
            _ if (NAND_ECC_BASE..NAND_ECC_BASE + 0x1000).contains(&pa) => {
                Some(self.nand_ecc.read(off(NAND_ECC_BASE)))
            }
            _ if (SDIO_BASE..SDIO_BASE + 0x1000).contains(&pa) => {
                Some(self.sdio.read(off(SDIO_BASE)))
            }
            _ if (DMAC0_BASE..DMAC0_BASE + 0x1000).contains(&pa) => {
                Some(self.dmac0.read(off(DMAC0_BASE)))
            }
            _ if (DMAC1_BASE..DMAC1_BASE + 0x1000).contains(&pa) => {
                Some(self.dmac1.read(off(DMAC1_BASE)))
            }
            _ if (USB_OTG_BASE..USB_OTG_BASE + 0x10000).contains(&pa) => {
                Some(self.usb.otg_read(off(USB_OTG_BASE)))
            }
            _ if (USB_PHYS_BASE..USB_PHYS_BASE + 0x1000).contains(&pa) => {
                Some(self.usb.phy_read(off(USB_PHYS_BASE)))
            }
            _ if (MBX_BASE..MBX_BASE + MBX_SIZE).contains(&pa) => Some(match off(MBX_BASE) {
                0x12C => 0x100,
                0xF00 => (1 << 24) | 0x1_0000,
                0x1020 => 0x1_0000,
                _ => 0,
            }),
            _ if (ADM_BASE..ADM_BASE + 0x1000).contains(&pa) => Some(match off(ADM_BASE) {
                0x0 => 0x2,  // CTRL: device ready
                0x4 => 0x10, // CTRL2: upload event finished
                _ => 0,
            }),
            _ if (UART0_BASE..UART0_BASE + 0x1000).contains(&pa) => Some(
                self.uart
                    .get()
                    .and_then(|u| u.lock().ok().map(|mut u| u.read(off(UART0_BASE))))
                    .unwrap_or(0),
            ),
            _ if (ENGINE_8900_BASE..ENGINE_8900_BASE + 0x100).contains(&pa) => Some(0),
            _ if (AES_BASE..AES_BASE + 0x100).contains(&pa) => Some(self.aes.read(off(AES_BASE))),
            // Plain memory.
            _ if is_memory(pa) => None,
            // Unmapped MMIO: open bus (read as zero).
            _ => {
                if self.openbus_log_budget > 0 {
                    self.openbus_log_budget -= 1;
                    debug!(pa = format!("{pa:#x}"), "openbus read");
                }
                Some(0)
            }
        }
    }

    /// Device-window write. Returns true if the write was consumed by a device
    /// (or open bus); false if it should fall through to plain memory.
    fn dev_write(&mut self, pa: u32, value: u32) -> bool {
        let off = |base: u32| pa - base;
        if std::env::var("RAX_S5L_WLOG").is_ok()
            && ((0x3CC0_0000..0x3CC1_1000).contains(&pa)
                || (ADM_BASE..ADM_BASE + 0x1000).contains(&pa))
        {
            debug!(pa = format!("{pa:#x}"), val = format!("{value:#x}"), "wlog");
        }
        match pa {
            _ if (CLOCK0_BASE..CLOCK0_BASE + 0x1000).contains(&pa) => {
                self.clock0.write(off(CLOCK0_BASE), value);
                true
            }
            _ if (CLOCK1_BASE..CLOCK1_BASE + 0x1000).contains(&pa) => {
                self.clock1.write(off(CLOCK1_BASE), value);
                true
            }
            _ if (VIC0_BASE..VIC0_BASE + 0x1000).contains(&pa) => {
                let offset = off(VIC0_BASE);
                let trace = self.should_trace_vic_access(offset);
                let before0 = trace.then(|| VicTraceSnapshot::capture(&self.vic0));
                let before1 = trace.then(|| VicTraceSnapshot::capture(&self.vic1));
                let mut is_daisy = false;
                if offset == 0xF00 {
                    is_daisy = self.vic0.finish_irq();
                    if is_daisy {
                        self.vic1.finish_daisy_child();
                        if self.vic1_adm_daisy_in_service {
                            self.vic1_adm_daisy_latched = false;
                            self.vic1_adm_daisy_in_service = false;
                        }
                        self.refresh_vic_daisy();
                    }
                } else {
                    self.vic0.write(offset, value);
                }
                if let Some(before0) = before0 {
                    self.trace_vic_access(
                        "VIC0",
                        "write",
                        offset,
                        Some(value),
                        None,
                        before0,
                        VicTraceSnapshot::capture(&self.vic0),
                    );
                    if is_daisy {
                        self.trace_vic_access(
                            "VIC1",
                            "finish_daisy",
                            0xF00,
                            Some(value),
                            None,
                            before1.expect("VIC1 trace snapshot"),
                            VicTraceSnapshot::capture(&self.vic1),
                        );
                    }
                }
                true
            }
            _ if (VIC1_BASE..VIC1_BASE + 0x1000).contains(&pa) => {
                let offset = off(VIC1_BASE);
                let trace = self.should_trace_vic_access(offset);
                let before = trace.then(|| VicTraceSnapshot::capture(&self.vic1));
                self.vic1.write(offset, value);
                if offset == 0xF00 && self.vic1_adm_daisy_in_service {
                    self.vic1_adm_daisy_latched = false;
                    self.vic1_adm_daisy_in_service = false;
                    self.refresh_vic_daisy();
                }
                if let Some(before) = before {
                    self.trace_vic_access(
                        "VIC1",
                        "write",
                        offset,
                        Some(value),
                        None,
                        before,
                        VicTraceSnapshot::capture(&self.vic1),
                    );
                }
                true
            }
            _ if (SYSIC_BASE..SYSIC_BASE + 0x1000).contains(&pa) => {
                self.sysic.write(off(SYSIC_BASE), value);
                true
            }
            _ if (TIMER1_BASE..TIMER1_BASE + 0x10004).contains(&pa) => {
                self.timer.write(off(TIMER1_BASE), value);
                true
            }
            _ if (GPIO_BASE..GPIO_BASE + 0x10000).contains(&pa) => {
                self.gpio.write(off(GPIO_BASE), value);
                true
            }
            _ if (CHIPID_BASE..CHIPID_BASE + 0x10).contains(&pa) => true,
            _ if (I2C0_BASE..I2C0_BASE + 0x1000).contains(&pa) => {
                self.i2c0.write(off(I2C0_BASE), value);
                true
            }
            _ if (I2C1_BASE..I2C1_BASE + 0x1000).contains(&pa) => {
                self.i2c1.write(off(I2C1_BASE), value);
                true
            }
            _ if (SPI0_BASE..SPI0_BASE + 0x100).contains(&pa) => {
                self.spi0.write(off(SPI0_BASE), value);
                true
            }
            _ if (SPI1_BASE..SPI1_BASE + 0x100).contains(&pa) => {
                self.spi1.write(off(SPI1_BASE), value);
                true
            }
            _ if (SPI2_BASE..SPI2_BASE + 0x100).contains(&pa) => {
                self.spi2.write(off(SPI2_BASE), value);
                true
            }
            _ if (LCD_BASE..LCD_BASE + 0x1000).contains(&pa) => {
                self.lcd.write(off(LCD_BASE), value);
                true
            }
            _ if (NAND_BASE..NAND_BASE + 0x1000).contains(&pa) => {
                self.nand.write(off(NAND_BASE), value);
                true
            }
            _ if (NAND_ECC_BASE..NAND_ECC_BASE + 0x1000).contains(&pa) => {
                self.nand_ecc.write(off(NAND_ECC_BASE), value);
                true
            }
            _ if (SDIO_BASE..SDIO_BASE + 0x1000).contains(&pa) => {
                self.sdio.write(off(SDIO_BASE), value);
                true
            }
            _ if (DMAC0_BASE..DMAC0_BASE + 0x1000).contains(&pa) => {
                self.dmac0.write(off(DMAC0_BASE), value);
                true
            }
            _ if (DMAC1_BASE..DMAC1_BASE + 0x1000).contains(&pa) => {
                self.dmac1.write(off(DMAC1_BASE), value);
                true
            }
            _ if (USB_OTG_BASE..USB_OTG_BASE + 0x10000).contains(&pa) => {
                self.usb.otg_write(off(USB_OTG_BASE), value);
                true
            }
            _ if (USB_PHYS_BASE..USB_PHYS_BASE + 0x1000).contains(&pa) => {
                self.usb.phy_write(off(USB_PHYS_BASE), value);
                true
            }
            _ if (MBX_BASE..MBX_BASE + MBX_SIZE).contains(&pa) => true,
            _ if (ADM_BASE..ADM_BASE + 0x1000).contains(&pa) => {
                match off(ADM_BASE) {
                    0x88 => {
                        self.adm_data2 = value;
                        if std::env::var("RAX_S5L_ADM_TRACE").is_ok() {
                            debug!(addr = format!("{value:#x}"), "adm_data2");
                        }
                    }
                    0x8C => {
                        self.adm_data3 = value;
                        if std::env::var("RAX_S5L_ADM_TRACE").is_ok() {
                            debug!(addr = format!("{value:#x}"), "adm_data3");
                        }
                    }
                    0x0 | 0x4 => {
                        if std::env::var("RAX_S5L_ADM_TRACE").is_ok() {
                            debug!(
                                off = format!("{:#x}", off(ADM_BASE)),
                                val = format!("{value:#x}"),
                                adm_irq = self.adm_irq,
                                "adm_write"
                            );
                        }
                        self.adm_req = Some((off(ADM_BASE) << 28) | (value & 0xFF));
                    }
                    _ => {}
                }
                true
            }
            _ if (UART0_BASE..UART0_BASE + 0x1000).contains(&pa) => {
                if let Some(u) = self.uart.get() {
                    if let Ok(mut u) = u.lock() {
                        u.write(off(UART0_BASE), value);
                    }
                }
                true
            }
            _ if (ENGINE_8900_BASE..ENGINE_8900_BASE + 0x100).contains(&pa) => {
                // Writing the image header address to offset 0 triggers
                // in-place AES-CBC decryption (serviced by the vCPU step).
                if off(ENGINE_8900_BASE) == 0 {
                    self.engine_8900_req = Some(value);
                }
                true
            }
            _ if (AES_BASE..AES_BASE + 0x100).contains(&pa) => {
                self.aes.write(off(AES_BASE), value);
                true
            }
            _ if is_memory(pa) => false,
            _ => {
                if self.openbus_log_budget > 0 {
                    self.openbus_log_budget -= 1;
                    debug!(
                        pa = format!("{pa:#x}"),
                        val = format!("{value:#x}"),
                        "openbus write"
                    );
                }
                true
            }
        }
    }

    fn read_pa(
        &mut self,
        mem: &GuestMemoryMmap,
        pa: u32,
        buf: &mut [u8],
    ) -> std::result::Result<(), MemoryError> {
        if is_nor_range(pa, buf.len()) {
            return self.nor.read(mem, pa, buf);
        }

        if buf.len() <= 4 && !is_memory(pa) {
            if let Some(v) = self.dev_read(pa) {
                if self.openbus_log_budget > 0 && self.devlog {
                    self.openbus_log_budget -= 1;
                    debug!(pa = format!("{pa:#x}"), val = format!("{v:#x}"), "dev read");
                }
                let bytes = v.to_le_bytes();
                buf.copy_from_slice(&bytes[..buf.len()]);
                return Ok(());
            }
        }
        mem.read_slice(buf, GuestAddress(pa as u64))
            .map_err(|_| MemoryError::BusError(pa))
    }

    fn write_pa(
        &mut self,
        mem: &GuestMemoryMmap,
        pa: u32,
        data: &[u8],
    ) -> std::result::Result<(), MemoryError> {
        // Optional write-watchpoint (RAX_S5L_WATCH=hexaddr:hexlen): log writes
        // that land in [addr, addr+len) so heap/free-list corruption can be
        // traced to the offending store.
        if let Some((wa, wl)) = *watch_range() {
            if range_overlaps(pa, data.len(), wa, wl) {
                info!(
                    pa = format!("{pa:#x}"),
                    len = data.len(),
                    watch = format!("{wa:#x}:{wl:#x}"),
                    watch_offset = ?watch_offset(pa, data.len(), wa),
                    data = bytes_hex(data),
                    before = ?phys_bytes_hex(mem, pa, data.len()),
                    pc = format!("{:#x}", self.cur_pc),
                    insns = self.cur_insn,
                    "physical watch write"
                );
            }
        }
        if is_nor_range(pa, data.len()) {
            self.nor.write(pa - NOR_BASE, data);
            return Ok(());
        }

        if data.len() <= 4 && !is_memory(pa) {
            // QEMU dispatches MMIO subword accesses with the guest's exact
            // offset and the unshifted access value. This matters for SYSIC's
            // halfword status offsets (0x7a/0x7c), and it avoids synthetic
            // read-modify-write cycles on registers whose reads have effects.
            let mut bytes = [0u8; 4];
            bytes[..data.len()].copy_from_slice(data);
            if self.dev_write(pa, u32::from_le_bytes(bytes)) {
                // A channel-enable write to a DMAC schedules a transfer; run it
                // now (here we have the guest-memory handle the transfer needs).
                if let Some(ch) = self.dmac0.take_pending() {
                    self.dma_run(mem, 0, ch as usize);
                }
                if let Some(ch) = self.dmac1.take_pending() {
                    self.dma_run(mem, 1, ch as usize);
                }
                return Ok(());
            }
        }
        mem.write_slice(data, GuestAddress(pa as u64))
            .map_err(|_| MemoryError::BusError(pa))
    }

    /// Perform a PL080 channel transfer synchronously. The reference QEMU
    /// PL080 model moves one DMA element at a time, using source width for each
    /// read and destination width for each write, then reloads an optional LLI.
    /// Mirroring that shape matters for peripherals such as SPI FIFOs: a
    /// byte-wide peripheral write is a FIFO push, not just a byte in a bulk RAM
    /// copy.
    fn dma_run(&mut self, mem: &GuestMemoryMmap, controller: usize, ch: usize) {
        let trace = match std::env::var("RAX_S5L_DMA_TRACE") {
            Ok(value) if value.eq_ignore_ascii_case("all") => true,
            Ok(value) if value.eq_ignore_ascii_case("dmac0") => controller == 0,
            Ok(value) if value.eq_ignore_ascii_case("dmac1") => controller == 1,
            Ok(value) => value.parse::<usize>() == Ok(controller),
            Err(_) => false,
        };
        let dump_path = std::env::var("RAX_S5L_DMADUMP").ok();
        let dump_limit = s5l_dmadump_limit();
        let mut dump_remaining = dump_path
            .as_deref()
            .map(|path| dmadump_remaining_for_path(Path::new(path), dump_limit))
            .unwrap_or(0);
        let mut dump = dump_path
            .as_ref()
            .filter(|_| dump_remaining != 0)
            .map(|_| Vec::<u8>::new());
        let (mut src, mut dst, mut lli, mut ctl, cfg) = self.dma_descriptor(controller, ch);
        let mut total = 0usize;
        let mut descriptors = 0usize;

        loop {
            descriptors += 1;
            if descriptors > 4096 {
                info!(
                    controller,
                    ch,
                    lli = format!("{lli:#x}"),
                    "dma lli chain too long"
                );
                break;
            }

            let mut count = ctl & 0xFFF;
            let swidth = 1u32 << ((ctl >> 18) & 7).min(2);
            let dwidth = 1u32 << ((ctl >> 21) & 7).min(2);
            let s_inc = (ctl >> 26) & 1 != 0;
            let d_inc = (ctl >> 27) & 1 != 0;

            if trace {
                info!(
                    controller,
                    ch,
                    src = format!("{src:#x}"),
                    dst = format!("{dst:#x}"),
                    lli = format!("{lli:#x}"),
                    ctl = format!("{ctl:#x}"),
                    cfg = format!("{cfg:#x}"),
                    count,
                    swidth,
                    dwidth,
                    s_inc,
                    d_inc,
                    "dma descriptor"
                );
            }

            while count != 0 {
                let mut buf = [0u8; 4];
                let mut n = 0usize;
                while n < dwidth as usize {
                    let end = (n + swidth as usize).min(buf.len());
                    let _ = self.read_pa(mem, src, &mut buf[n..end]);
                    if s_inc {
                        src = src.wrapping_add(swidth);
                    }
                    n += swidth as usize;
                }

                let xsize = dwidth.max(swidth) as usize;
                let mut n = 0usize;
                while n < xsize {
                    let end = (n + dwidth as usize).min(buf.len());
                    let _ = self.write_pa(mem, dst.wrapping_add(n as u32), &buf[n..end]);
                    if d_inc {
                        dst = dst.wrapping_add(dwidth);
                    }
                    n += dwidth as usize;
                }

                if let Some(dump) = dump.as_mut() {
                    let bytes = &buf[..xsize.min(buf.len())];
                    let len = bytes.len().min(dump_remaining);
                    dump.extend_from_slice(&bytes[..len]);
                    dump_remaining -= len;
                }
                count -= 1;
                total += xsize;
            }

            ctl &= !0xFFF;
            self.dma_store_descriptor(controller, ch, src, dst, lli, ctl);
            if lli == 0 {
                break;
            }

            let next_src = self.dma_read_u32(mem, lli);
            let next_dst = self.dma_read_u32(mem, lli.wrapping_add(4));
            let next_lli = self.dma_read_u32(mem, lli.wrapping_add(8));
            let next_ctl = self.dma_read_u32(mem, lli.wrapping_add(12));
            src = next_src;
            dst = next_dst;
            lli = next_lli;
            ctl = next_ctl;
            self.dma_store_descriptor(controller, ch, src, dst, lli, ctl);
        }

        debug!(
            controller,
            ch = ch,
            src = format!("{src:#x}"),
            dst = format!("{dst:#x}"),
            bytes = total,
            "dma_run"
        );
        if let Some(path) = dump_path {
            let header =
                format!("--- dmac{controller} ch{ch} src={src:#x} dst={dst:#x} bytes={total}\n");
            let payload = dump.as_deref().unwrap_or(&[]);
            let _ = append_limited_dmadump(path, header.as_bytes(), payload, dump_limit);
        }
        self.dma_complete(controller, ch);
    }

    fn dma_complete(&mut self, controller: usize, ch: usize) {
        if controller == 0 {
            self.dmac0.complete(ch);
        } else {
            self.dmac1.complete(ch);
        }
    }

    fn dma_descriptor(&self, controller: usize, ch: usize) -> (u32, u32, u32, u32, u32) {
        if controller == 0 {
            (
                self.dmac0.src[ch],
                self.dmac0.dst[ch],
                self.dmac0.lli[ch],
                self.dmac0.control[ch],
                self.dmac0.config[ch],
            )
        } else {
            (
                self.dmac1.src[ch],
                self.dmac1.dst[ch],
                self.dmac1.lli[ch],
                self.dmac1.control[ch],
                self.dmac1.config[ch],
            )
        }
    }

    fn dma_store_descriptor(
        &mut self,
        controller: usize,
        ch: usize,
        src: u32,
        dst: u32,
        lli: u32,
        control: u32,
    ) {
        let dmac = if controller == 0 {
            &mut self.dmac0
        } else {
            &mut self.dmac1
        };
        dmac.src[ch] = src;
        dmac.dst[ch] = dst;
        dmac.lli[ch] = lli;
        dmac.control[ch] = control;
    }

    fn dma_read_u32(&mut self, mem: &GuestMemoryMmap, pa: u32) -> u32 {
        let mut bytes = [0u8; 4];
        let _ = self.read_pa(mem, pa, &mut bytes);
        u32::from_le_bytes(bytes)
    }
}

/// Whether a physical address is plain memory (RAM/firmware/NOR), as opposed
/// to a device MMIO window. Most S5L8900 devices live in 0x38000000..0x40000000,
/// but the QEMU reference maps a few inert coprocessor/audio/interrupt windows
/// as RAM so drivers can allocate/map them without seeing open bus.
fn is_memory(pa: u32) -> bool {
    !(0x3800_0000..0x4000_0000).contains(&pa) || is_s5l_plain_ram_window(pa)
}

fn is_s5l_plain_ram_window(pa: u32) -> bool {
    let in_window = |base: u32, size: u32| (base..base + size).contains(&pa);
    in_window(MPVD_BASE, MPVD_SIZE)
        || in_window(H264BPD_BASE, H264BPD_SIZE)
        || in_window(EDGEIC_BASE, 0x1000)
        || in_window(WATCHDOG_BASE, 0x1_0000)
        || in_window(IIS0_BASE, 0x1_0000)
        || in_window(IIS1_BASE, 0x1_0000)
        || in_window(IIS2_BASE, 0x1_0000)
}

fn is_nor_range(pa: u32, len: usize) -> bool {
    let Ok(len) = u32::try_from(len) else {
        return false;
    };
    let Some(end) = pa.checked_add(len) else {
        return false;
    };
    pa >= NOR_BASE && end <= NOR_BASE + NOR_SIZE
}

impl S5lBridge {
    fn access(
        &self,
        addr: u32,
        access: V6Access,
        data: Option<&[u8]>,
        out: Option<&mut [u8]>,
    ) -> std::result::Result<(), MemoryError> {
        let mut inner = self.inner.borrow_mut();
        let pa = Self::translate(&self.mem, &mut inner, addr, access)?;
        if let Some(buf) = out {
            inner.read_pa(&self.mem, pa, buf)
        } else if let Some(d) = data {
            let vwatch = vwatch_range()
                .and_then(|(wa, wl)| range_overlaps(addr, d.len(), wa, wl).then_some((wa, wl)));
            let before = vwatch.and_then(|_| phys_bytes_hex(&self.mem, pa, d.len()));
            let result = inner.write_pa(&self.mem, pa, d);
            if let Some((wa, wl)) = vwatch {
                info!(
                    va = format!("{addr:#x}"),
                    pa = format!("{pa:#x}"),
                    len = d.len(),
                    access = ?access,
                    watch = format!("{wa:#x}:{wl:#x}"),
                    watch_offset = ?watch_offset(addr, d.len(), wa),
                    data = bytes_hex(d),
                    before = ?before,
                    after = ?phys_bytes_hex(&self.mem, pa, d.len()),
                    pc = format!("{:#x}", inner.cur_pc),
                    insns = inner.cur_insn,
                    ok = result.is_ok(),
                    "virtual watch write"
                );
            }
            result
        } else {
            Ok(())
        }
    }
}

impl ArmMemory for S5lBridge {
    fn read_word(&self, addr: u32) -> std::result::Result<u32, MemoryError> {
        let mut b = [0u8; 4];
        self.access(addr, V6Access::Read, None, Some(&mut b))?;
        Ok(u32::from_le_bytes(b))
    }

    fn read_halfword(&self, addr: u32) -> std::result::Result<u16, MemoryError> {
        let mut b = [0u8; 2];
        self.access(addr, V6Access::Read, None, Some(&mut b))?;
        Ok(u16::from_le_bytes(b))
    }

    fn read_byte(&self, addr: u32) -> std::result::Result<u8, MemoryError> {
        let mut b = [0u8; 1];
        self.access(addr, V6Access::Read, None, Some(&mut b))?;
        Ok(b[0])
    }

    fn write_word(&mut self, addr: u32, value: u32) -> std::result::Result<(), MemoryError> {
        self.access(addr, V6Access::Write, Some(&value.to_le_bytes()), None)
    }

    fn write_halfword(&mut self, addr: u32, value: u16) -> std::result::Result<(), MemoryError> {
        self.access(addr, V6Access::Write, Some(&value.to_le_bytes()), None)
    }

    fn write_byte(&mut self, addr: u32, value: u8) -> std::result::Result<(), MemoryError> {
        self.access(addr, V6Access::Write, Some(&[value]), None)
    }
}

/// S5L8900 vCPU backed by the AArch32 interpreter.
pub struct S5L8900Vcpu {
    id: u32,
    cpu: Armv7Cpu,
    bridge: S5lBridge,
    decoder: Decoder,
    uart: Arc<OnceLock<Arc<Mutex<S3cUart>>>>,
    insn_count: u64,
    excl: crate::isa::arm::instructions::ExclusiveMonitor,
    pc_ring: [u32; 512],
    pc_ring_idx: usize,
    zero_slide: u32,
    trace_pcs: Vec<u32>,
    trace_log_budget: u32,
    trace_start_insn: u64,
    pc_sample_interval: u64,
    pc_sample_next_insn: u64,
    pc_sample_remaining: u32,
    trace_all: bool,
    storage_call_trace_seen: Vec<(u32, u32)>,
    storage_call_trace_remaining: u32,
    storage_call_trace_start_insn: u64,
    fdisk_trace_seen: Vec<(u32, u32)>,
    fdisk_trace_remaining: u32,
    nandftl_trace_seen: Vec<(u32, u32)>,
    nandftl_trace_remaining: u32,
    wmr_trace_seen: Vec<(u32, u32)>,
    wmr_trace_remaining: u32,
    wmr_init_active: bool,
    partition_trace_remaining: u32,
    iokit_match_follow_remaining: u32,
    kernel_trace_remaining: u32,
    root_trace_remaining: u32,
    root_trace_start_insn: u64,
    root_boot_trace_remaining: u32,
    root_boot_trace_start_insn: u64,
    apple_arm_function_trace_remaining: u32,
    iokit_lifetime_trace_remaining: u32,
    iokit_retain_trace: bool,
    ioreg_free_trace_remaining: u32,
    iokit_watch_object: Option<u32>,
    iokit_watch_trace_remaining: u32,
    sdio_power_trace_remaining: u32,
    iokit_message_trace_remaining: u32,
    pmqueue_trace_remaining: u32,
    admfmc_trace_remaining: u32,
    kernel_entry_logged: bool,
    kernel_fault_log_remaining: u32,
    kernel_exception_log_remaining: u32,
    fault_log_budget: u32,
    last_heartbeat: crate::host::time::Instant,
    boot_instant: crate::host::time::Instant,
    timer_speedup: u64,
    /// Derive guest µs from the instruction count so timeouts do not outrun
    /// device work while the interpreter executes below the guest CPU's speed.
    /// Holds the instructions-per-µs divisor; zero explicitly selects the host
    /// clock for timing diagnostics.
    det_timer: u64,
    /// Multiplier on the µs counter — iBoot treats the timer as a 12 MHz tick
    /// counter (it reads freq=12000000 and computes elapsed = ticks*1e6/freq),
    /// so providing 12 ticks/µs makes its time math correct. From RAX_S5L_TIMER_MUL.
    timer_mul: u64,
    input_seeded: bool,
    security_state_seeded: bool,
    input_payload: Option<Vec<u8>>,
    printf_trace: bool,
    vfl_scan_trace: bool,
    derail_trace: bool,
    no_usb_wrangler_race_fix: bool,
    force_iobsd: bool,
    force_iobsd_all: bool,
    sparse_vfl_mask_seeded: [bool; 8],
    fsboot_trace: bool,
    lcd_irq: bool,
    lcd_irq_armed: bool,
    lcd_irq_budget: u32,
    lcd_irq_arm_after_rootdev: bool,
    i2c_irq: bool,
    timer_irq: bool,
    timer_irq_ready: u64,
    timer_irq_interval: u64,
    timer_irq_clock: u64,
    irq_trace: bool,
    irq_trace_timer: bool,
    irq_trace_start_insn: u64,
    irq_trace_budget: u32,
    last_irq_trace: u128,
    fiq_trace_budget: u32,
    fiq_trace_start_insn: u64,
    last_fiq_trace: u128,
    idle_trace: bool,
    idle_trace_start_insn: u64,
    last_idle_trace_insn: u64,
    adm_irq_trace_budget: u32,
    adm_irq_trace_start_insn: u64,
    last_adm_irq_trace: u128,
    i2c_irq_trace_budget: u32,
    last_i2c1_irq_trace: u128,
    shutdown: bool,
}

enum StepOutcome {
    Progress,
    Idle,
}

impl S5L8900Vcpu {
    pub fn new(id: u32, mem: Arc<GuestMemoryMmap>) -> Self {
        // The console UART is provided by the VMM via attach_s3c_uart() so that
        // host stdin feeds the same instance the bridge serves.
        let uart = Arc::new(OnceLock::new());
        let bridge = S5lBridge {
            mem,
            inner: RefCell::new(BridgeInner {
                mmu: V6MmuConfig::default(),
                privileged: true,
                cur_pc: 0,
                cur_insn: 0,
                kernel_started: false,
                last_fault: LastFault::default(),
                clock0: S5lClock::new(),
                clock1: S5lClock::new(),
                vic0: Pl192::new(),
                vic1: Pl192::new(),
                vic1_adm_daisy_latched: false,
                vic1_adm_daisy_in_service: false,
                sysic: S5lSysic::new(),
                gpio: S5lGpio::new(),
                timer: S5lTimer::new(),
                i2c0: S5lI2c::new(false, true), // LIS302DL accelerometer lives on I2C0
                i2c1: S5lI2c::new(true, false), // PMU (pcf50633) lives on I2C1
                spi0: S5lSpi::new(0),
                spi1: S5lSpi::new(1), // LCD panel
                spi2: S5lSpi::new(2), // multitouch
                lcd: S5lLcd::new(),
                nand: S5lNand::new(nand_dir()),
                nand_ecc: S5lNandEcc::new(),
                sdio: S5lSdio::new(),
                aes: S5lAes::new(),
                dmac0: S5lDmac::new(),
                dmac1: S5lDmac::new(),
                usb: S5lUsb::new(),
                nor: S5lNor::default(),
                adm_data2: 0,
                adm_data3: 0,
                adm_req: None,
                adm_irq: false,
                uart: uart.clone(),
                engine_8900_req: None,
                openbus_log_budget: std::env::var("RAX_S5L_OPENBUS_LOG")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(256),
                devlog: std::env::var("RAX_S5L_DEVLOG").is_ok(),
                vic_trace_budget: trace_budget_env("RAX_S5L_VIC_TRACE", 4096),
                vic_trace_start_insn: std::env::var("RAX_S5L_VIC_TRACE_START")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0),
                vic_trace_adm: std::env::var("RAX_S5L_VIC_TRACE_ADM").is_ok(),
            }),
        };
        let mut cpu = Armv7Cpu::new();
        // ARM1176JZF-S (ARMv6K), the S5L8900 core.
        cpu.cp15.midr = 0x410F_B767;
        cpu.cp15.ctr = 0x1D15_2152;
        let lcd_irq_requested = !std::env::var("RAX_S5L_NO_LCD_IRQ").is_ok()
            && (std::env::var("RAX_S5L_LCD_IRQ").is_ok()
                || std::env::var("RAX_S5L_LCD_IRQ_EARLY").is_ok()
                || std::env::var("RAX_S5L_LCD_IRQ_AFTER_ROOTDEV").is_ok());
        let pc_sample_interval = std::env::var("RAX_S5L_PC_SAMPLE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let pc_sample_start_insn = std::env::var("RAX_S5L_PC_SAMPLE_START")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let input_payload = std::env::var("RAX_S5L_INPUT").ok().map(|s| {
            let mut bytes = s.replace("\\r", "\r").replace("\\n", "\n").into_bytes();
            bytes.push(b'\r');
            bytes
        });
        let input_seeded = input_payload.is_none();
        S5L8900Vcpu {
            id,
            cpu,
            bridge,
            decoder: Decoder::new_aarch32(),
            uart,
            insn_count: 0,
            excl: crate::isa::arm::instructions::ExclusiveMonitor::default(),
            pc_ring: [0; 512],
            pc_ring_idx: 0,
            zero_slide: 0,
            trace_pcs: std::env::var("RAX_TRACE_PC")
                .ok()
                .map(|v| {
                    v.split(',')
                        .filter_map(|a| u32::from_str_radix(a.trim_start_matches("0x"), 16).ok())
                        .collect()
                })
                .unwrap_or_default(),
            trace_log_budget: std::env::var("RAX_S5L_TRACE_BUDGET")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(400),
            trace_start_insn: std::env::var("RAX_S5L_TRACE_START")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            pc_sample_interval,
            pc_sample_next_insn: pc_sample_start_insn,
            pc_sample_remaining: std::env::var("RAX_S5L_PC_SAMPLE_BUDGET")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            trace_all: std::env::var_os("RAX_S5L_TRACE").is_some(),
            storage_call_trace_seen: Vec::new(),
            storage_call_trace_remaining: std::env::var("RAX_S5L_STORAGE_CALL_TRACE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            storage_call_trace_start_insn: std::env::var("RAX_S5L_STORAGE_CALL_TRACE_START")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            fdisk_trace_seen: Vec::new(),
            fdisk_trace_remaining: std::env::var("RAX_S5L_FDISK_TRACE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            nandftl_trace_seen: Vec::new(),
            nandftl_trace_remaining: std::env::var("RAX_S5L_NANDFTL_TRACE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            wmr_trace_seen: Vec::new(),
            wmr_trace_remaining: std::env::var("RAX_S5L_WMR_TRACE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            wmr_init_active: false,
            partition_trace_remaining: std::env::var("RAX_S5L_PARTITION_TRACE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            iokit_match_follow_remaining: 0,
            kernel_trace_remaining: std::env::var("RAX_S5L_KERNEL_TRACE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            root_trace_remaining: std::env::var("RAX_S5L_ROOT_TRACE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            root_trace_start_insn: std::env::var("RAX_S5L_ROOT_TRACE_START")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            root_boot_trace_remaining: std::env::var("RAX_S5L_ROOT_BOOT_TRACE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            root_boot_trace_start_insn: std::env::var("RAX_S5L_ROOT_BOOT_TRACE_START")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            apple_arm_function_trace_remaining: trace_budget_env("RAX_S5L_ARM_FUNCTION_TRACE", 128),
            iokit_lifetime_trace_remaining: trace_budget_env("RAX_S5L_IOKIT_LIFETIME_TRACE", 256),
            iokit_retain_trace: std::env::var_os("RAX_S5L_IOKIT_RETAIN_TRACE").is_some(),
            ioreg_free_trace_remaining: trace_budget_env("RAX_S5L_IOREG_FREE_TRACE", 64),
            iokit_watch_object: u32_env("RAX_S5L_IOKIT_OBJECT"),
            iokit_watch_trace_remaining: trace_budget_env("RAX_S5L_IOKIT_OBJECT_TRACE", 512),
            sdio_power_trace_remaining: trace_budget_env("RAX_S5L_SDIO_POWER_TRACE", 256),
            iokit_message_trace_remaining: trace_budget_env("RAX_S5L_MESSAGE_TRACE", 256),
            pmqueue_trace_remaining: trace_budget_env("RAX_S5L_PMQUEUE_TRACE", 256),
            admfmc_trace_remaining: std::env::var("RAX_S5L_ADMFMC_TRACE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            kernel_entry_logged: false,
            kernel_fault_log_remaining: std::env::var("RAX_S5L_KERNEL_FAULTS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(64),
            kernel_exception_log_remaining: std::env::var("RAX_S5L_EXCEPTION_FRAMES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(16),
            fault_log_budget: std::env::var("RAX_S5L_FAULT_BUDGET")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(64),
            last_heartbeat: crate::host::time::Instant::now(),
            boot_instant: crate::host::time::Instant::now(),
            timer_speedup: timer_speedup(),
            timer_mul: std::env::var("RAX_S5L_TIMER_MUL")
                .ok()
                .and_then(|v| v.parse().ok())
                .filter(|&n| n > 0)
                .unwrap_or(1),
            det_timer: {
                let value = std::env::var("RAX_S5L_DET_TIMER").ok();
                parse_det_timer(value.as_deref())
            },
            input_seeded,
            security_state_seeded: false,
            input_payload,
            printf_trace: std::env::var_os("RAX_S5L_PRINTF").is_some(),
            vfl_scan_trace: std::env::var_os("RAX_S5L_VFL_SCAN").is_some(),
            derail_trace: std::env::var_os("RAX_S5L_DERAIL").is_some(),
            no_usb_wrangler_race_fix: std::env::var_os("RAX_S5L_NO_USB_WRANGLER_RACE_FIX")
                .is_some(),
            force_iobsd: std::env::var_os("RAX_S5L_FORCE_IOBSD").is_some(),
            force_iobsd_all: std::env::var_os("RAX_S5L_FORCE_IOBSD_ALL").is_some(),
            sparse_vfl_mask_seeded: [false; 8],
            fsboot_trace: std::env::var("RAX_S5L_FSBOOT_TRACE").is_ok(),
            // QEMU raises LCD refresh IRQs from its display timer. RAX's
            // synthetic source is instruction-paced and can starve the guest
            // after root selection, so keep it opt-in until it is paced like
            // the reference display timer.
            lcd_irq: lcd_irq_requested,
            lcd_irq_armed: std::env::var("RAX_S5L_LCD_IRQ").is_ok()
                || std::env::var("RAX_S5L_LCD_IRQ_EARLY").is_ok(),
            lcd_irq_budget: std::env::var("RAX_S5L_LCD_IRQ_BUDGET")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(u32::MAX),
            lcd_irq_arm_after_rootdev: std::env::var("RAX_S5L_LCD_IRQ_AFTER_ROOTDEV").is_ok(),
            i2c_irq: !std::env::var("RAX_S5L_NO_I2C_IRQ").is_ok(),
            // The system-tick IRQ drives iBoot's cooperative scheduler (it wakes
            // tasks blocked in task_sleep). It self-gates on the timer's `started`
            // flag, which iBoot sets by writing START to TIMER_4 STATE only after
            // the scheduler is up — so it is safe to enable by default. Opt out
            // with RAX_S5L_NO_TIMER_IRQ for regression isolation.
            timer_irq: !std::env::var("RAX_S5L_NO_TIMER_IRQ").is_ok(),
            timer_irq_ready: std::env::var("RAX_S5L_IRQ_READY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            timer_irq_interval: std::env::var("RAX_S5L_IRQ_INTERVAL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(50_000),
            timer_irq_clock: 0,
            irq_trace: std::env::var("RAX_S5L_IRQ_TRACE").is_ok(),
            irq_trace_timer: std::env::var("RAX_S5L_IRQ_TRACE_TIMER").is_ok(),
            irq_trace_start_insn: std::env::var("RAX_S5L_IRQ_TRACE_START")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            irq_trace_budget: std::env::var("RAX_S5L_IRQ_TRACE_BUDGET")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(512),
            last_irq_trace: u128::MAX,
            fiq_trace_budget: std::env::var("RAX_S5L_FIQ_TRACE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            fiq_trace_start_insn: std::env::var("RAX_S5L_FIQ_TRACE_START")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            last_fiq_trace: u128::MAX,
            idle_trace: std::env::var("RAX_S5L_IDLE_TRACE").is_ok(),
            idle_trace_start_insn: std::env::var("RAX_S5L_IDLE_TRACE_START")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            last_idle_trace_insn: u64::MAX,
            adm_irq_trace_budget: std::env::var("RAX_S5L_ADMIRQ_TRACE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            adm_irq_trace_start_insn: std::env::var("RAX_S5L_ADMIRQ_TRACE_START")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            last_adm_irq_trace: u128::MAX,
            i2c_irq_trace_budget: std::env::var("RAX_S5L_I2CIRQLOG")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            last_i2c1_irq_trace: u128::MAX,
            shutdown: false,
        }
    }

    fn sync_mmu(&mut self) {
        let cp = &self.cpu.cp15;
        let mut inner = self.bridge.inner.borrow_mut();
        inner.mmu = V6MmuConfig {
            enabled: cp.sctlr.m(),
            ttbr0: cp.ttbr0 as u32,
            ttbr1: cp.ttbr1 as u32,
            ttbcr_n: cp.ttbcr & 0x7,
            dacr: cp.dacr,
            afe: false,
        };
        inner.privileged = self.cpu.cpsr.mode != ProcessorMode::User as u8;
    }

    /// Recompute VIC line levels from device state; return CPU IRQ/FIQ assertions.
    fn sync_irqs(&mut self) -> (bool, bool) {
        let uart_lvl = self
            .uart
            .get()
            .and_then(|u| u.lock().ok().map(|u| u.irq_pending()))
            .unwrap_or(false);
        let mut inner = self.bridge.inner.borrow_mut();
        let timer_lvl = inner.timer.irq_pending();
        let lcd_lvl = inner.lcd.irq_pending();
        let spi0_lvl = inner.spi0.irq_pending();
        let spi1_lvl = inner.spi1.irq_pending();
        let spi2_lvl = inner.spi2.irq_pending();
        let dmac0_lvl = inner.dmac0.irq_pending();
        let dmac1_lvl = inner.dmac1.irq_pending();
        let i2c0_raw = inner.i2c0.irq_pending();
        let i2c1_raw = inner.i2c1.irq_pending();
        let i2c_irq_enabled = self.i2c_irq || !inner.kernel_started;
        let i2c0_lvl = i2c_irq_enabled && i2c0_raw;
        let i2c1_lvl = i2c_irq_enabled && i2c1_raw;
        let nand_ecc_lvl = inner.nand_ecc.irq_pending();
        let adm_lvl = inner.adm_irq;
        let usb_lvl = inner.usb.irq_pending();
        let priority_mode = inner.kernel_started;
        inner.vic0.set_priority_mode(priority_mode);
        inner.vic1.set_priority_mode(priority_mode);
        inner.vic0.set_line(TIMER1_IRQ, timer_lvl);
        inner
            .vic0
            .set_line(LCD_IRQ, lcd_lvl || (USB_OTG_IRQ == LCD_IRQ && usb_lvl));
        if USB_OTG_IRQ != LCD_IRQ {
            inner.vic0.set_line(USB_OTG_IRQ, usb_lvl);
        }
        inner.vic0.set_line(UART0_IRQ, uart_lvl);
        inner.vic0.set_line(SPI0_IRQ, spi0_lvl);
        inner.vic0.set_line(SPI1_IRQ, spi1_lvl);
        inner.vic0.set_line(SPI2_IRQ, spi2_lvl);
        inner.vic0.set_line(DMAC0_IRQ, dmac0_lvl);
        inner.vic0.set_line(DMAC1_IRQ, dmac1_lvl);
        inner.vic0.set_line(I2C0_IRQ, i2c0_lvl);
        inner.vic0.set_line(I2C1_IRQ, i2c1_lvl);
        inner.vic1.set_line(NAND_ECC_VIC1_LINE, nand_ecc_lvl);
        inner.set_adm_irq(adm_lvl);
        for (group, &global_irq) in GPIO_GROUP_IRQS.iter().enumerate() {
            // The QEMU reference raises a SYSIC GPIO group line whenever a
            // device sets that group's status bit, and lowers it on the
            // guest's write-1-to-clear of GPIO_INTSTAT.
            let gpio_lvl = inner.sysic.gpio_int_status[group] != 0;
            if global_irq < 32 {
                inner.vic0.set_line(global_irq, gpio_lvl);
            } else {
                inner.vic1.set_line(global_irq - 32, gpio_lvl);
            }
        }
        // VIC1 daisy-chains into VIC0.
        inner.refresh_vic_daisy();
        let daisy = inner.vic0.daisy_input;
        let cpu_irq = inner.vic0.irq_asserted();
        let cpu_fiq = inner.vic0.fiq_asserted();
        if self.adm_irq_trace_budget != 0
            && inner.kernel_started
            && self.insn_count >= self.adm_irq_trace_start_insn
        {
            let (v0_cur, v0_high, v0_prio, v0_depth, v0_irq_line, _) =
                inner.vic0.debug_priority_state();
            let (v1_cur, v1_high, v1_prio, v1_depth, v1_irq_line, _) =
                inner.vic1.debug_priority_state();
            let trace = (adm_lvl as u128)
                | ((dmac0_lvl as u128) << 1)
                | ((daisy as u128) << 2)
                | ((cpu_irq as u128) << 3)
                | ((cpu_fiq as u128) << 4)
                | (((inner.vic0.rawintr as u128) & 0xffff) << 8)
                | (((inner.vic0.intenable as u128) & 0xffff) << 24)
                | (((inner.vic1.rawintr as u128) & 0xffff) << 40)
                | (((inner.vic1.intenable as u128) & 0xffff) << 56)
                | (((v0_cur as u128) & 0x3f) << 72)
                | (((v0_high as u128) & 0x3f) << 78)
                | (((v0_prio as u128) & 0x1f) << 84)
                | (((v1_cur as u128) & 0x3f) << 89)
                | (((v1_high as u128) & 0x3f) << 95)
                | (((v1_prio as u128) & 0x1f) << 101);
            if trace != self.last_adm_irq_trace {
                self.last_adm_irq_trace = trace;
                self.adm_irq_trace_budget -= 1;
                info!(
                    pc = format!("{:#x}", self.cpu.regs[15]),
                    cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
                    adm_lvl,
                    dmac0_lvl,
                    daisy,
                    cpu_irq,
                    cpu_fiq,
                    v0_raw = format!("{:#x}", inner.vic0.rawintr),
                    v0_en = format!("{:#x}", inner.vic0.intenable),
                    v0_irq = format!("{:#x}", inner.vic0.irq_status),
                    v0_addr = format!("{:#x}", inner.vic0.address),
                    v0_cur,
                    v0_high,
                    v0_prio,
                    v0_depth,
                    v0_irq_line,
                    v1_raw = format!("{:#x}", inner.vic1.rawintr),
                    v1_en = format!("{:#x}", inner.vic1.intenable),
                    v1_irq = format!("{:#x}", inner.vic1.irq_status),
                    v1_addr = format!("{:#x}", inner.vic1.address),
                    v1_cur,
                    v1_high,
                    v1_prio,
                    v1_depth,
                    v1_irq_line,
                    insns = self.insn_count,
                    "adm irq trace"
                );
            }
        }
        if self.irq_trace
            && inner.kernel_started
            && self.irq_trace_budget != 0
            && self.insn_count >= self.irq_trace_start_insn
        {
            let timer_bit = if self.irq_trace_timer {
                timer_lvl as u128
            } else {
                0
            };
            let vic0_raw_trace = if self.irq_trace_timer {
                inner.vic0.rawintr
            } else {
                inner.vic0.rawintr & !(1 << TIMER1_IRQ)
            };
            let trace = timer_bit
                | ((lcd_lvl as u128) << 1)
                | ((spi0_lvl as u128) << 2)
                | ((spi1_lvl as u128) << 3)
                | ((spi2_lvl as u128) << 4)
                | ((dmac0_lvl as u128) << 5)
                | ((dmac1_lvl as u128) << 6)
                | ((i2c0_lvl as u128) << 7)
                | ((i2c1_lvl as u128) << 8)
                | ((nand_ecc_lvl as u128) << 9)
                | ((adm_lvl as u128) << 10)
                | ((usb_lvl as u128) << 11)
                | ((uart_lvl as u128) << 12)
                | ((daisy as u128) << 13)
                | ((cpu_irq as u128) << 14)
                | ((cpu_fiq as u128) << 15)
                | ((vic0_raw_trace as u128) << 16)
                | ((inner.vic0.intenable as u128) << 48)
                | ((inner.vic1.rawintr as u128) << 80);
            if trace != self.last_irq_trace {
                self.last_irq_trace = trace;
                self.irq_trace_budget -= 1;
                let (
                    timer_micros,
                    timer_status,
                    timer_config,
                    timer_bcount1,
                    timer_bcount2,
                    timer_irq,
                    timer_started,
                    timer_next_irq_micros,
                    timer_next_irq_insn,
                ) = inner.timer.debug_state();
                info!(
                    pc = format!("{:#x}", self.cpu.regs[15]),
                    lr = format!("{:#x}", self.cpu.regs[14]),
                    cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
                    insns = self.insn_count,
                    timer_lvl,
                    lcd_lvl,
                    spi0_lvl,
                    spi1_lvl,
                    spi2_lvl,
                    dmac0_lvl,
                    dmac1_lvl,
                    i2c0_lvl,
                    i2c1_lvl,
                    i2c0_raw,
                    i2c1_raw,
                    nand_ecc_lvl,
                    adm_lvl,
                    usb_lvl,
                    uart_lvl,
                    daisy,
                    cpu_irq,
                    cpu_fiq,
                    vic0_raw = format!("{:#x}", inner.vic0.rawintr),
                    vic0_en = format!("{:#x}", inner.vic0.intenable),
                    vic0_irq = format!("{:#x}", inner.vic0.irq_status),
                    vic0_addr = format!("{:#x}", inner.vic0.address),
                    vic1_raw = format!("{:#x}", inner.vic1.rawintr),
                    vic1_en = format!("{:#x}", inner.vic1.intenable),
                    vic1_irq = format!("{:#x}", inner.vic1.irq_status),
                    vic1_addr = format!("{:#x}", inner.vic1.address),
                    timer_micros,
                    timer_status = format!("{timer_status:#x}"),
                    timer_config = format!("{timer_config:#x}"),
                    timer_bcount1 = format!("{timer_bcount1:#x}"),
                    timer_bcount2 = format!("{timer_bcount2:#x}"),
                    timer_irq,
                    timer_started,
                    timer_next_irq_micros,
                    timer_next_irq_insn,
                    "irq_trace"
                );
            }
        }
        (cpu_irq, cpu_fiq)
    }

    fn advance_irq_samples(&mut self) {
        let mut inner = self.bridge.inner.borrow_mut();
        inner.i2c0.advance_irq_sample();
        inner.i2c1.advance_irq_sample();
    }

    fn trace_i2c1_irq_handoff(&mut self, cpu_irq: bool, vectors_ready: bool) {
        if self.i2c_irq_trace_budget == 0 {
            return;
        }
        let inner = self.bridge.inner.borrow();
        let mask = 1u32 << I2C1_IRQ;
        let i2c1_raw = inner.i2c1.irq_pending();
        let vic_raw = inner.vic0.rawintr & mask != 0;
        let vic_enabled = inner.vic0.intenable & mask != 0;
        let vic_status = inner.vic0.irq_status & mask != 0;
        let interesting = i2c1_raw || vic_raw || vic_enabled || vic_status;
        if !interesting {
            return;
        }
        let (v0_cur, v0_high, v0_prio, v0_depth, v0_irq_line, _) =
            inner.vic0.debug_priority_state();
        let trace = (i2c1_raw as u128)
            | ((vic_raw as u128) << 1)
            | ((vic_enabled as u128) << 2)
            | ((vic_status as u128) << 3)
            | ((cpu_irq as u128) << 4)
            | ((self.cpu.cpsr.i as u128) << 5)
            | ((vectors_ready as u128) << 6)
            | ((self.cpu.is_halted as u128) << 7)
            | ((inner.kernel_started as u128) << 8)
            | ((inner.vic0.rawintr as u128) << 16)
            | ((inner.vic0.intenable as u128) << 48)
            | ((inner.vic0.irq_status as u128) << 80)
            | (((v0_cur as u128) & 0x3f) << 112)
            | (((v0_high as u128) & 0x3f) << 118)
            | (((v0_prio as u128) & 0x0f) << 124);
        if trace == self.last_i2c1_irq_trace {
            return;
        }
        self.last_i2c1_irq_trace = trace;
        self.i2c_irq_trace_budget -= 1;
        eprintln!(
            "I2C1 irq handoff pc={:#x} cpsr={:#x} insns={} raw={} vic_raw={} vic_en={} vic_irq={} cpu_irq={} cpsr_i={} vectors_ready={} halted={} kernel_started={} vic0_raw={:#x} vic0_en={:#x} vic0_irq={:#x} vic0_addr={:#x} v0_cur={} v0_high={} v0_prio={} v0_depth={} v0_irq_line={}",
            self.cpu.regs[15],
            self.cpu.cpsr.to_u32(),
            self.insn_count,
            i2c1_raw,
            vic_raw,
            vic_enabled,
            vic_status,
            cpu_irq,
            self.cpu.cpsr.i,
            vectors_ready,
            self.cpu.is_halted,
            inner.kernel_started,
            inner.vic0.rawintr,
            inner.vic0.intenable,
            inner.vic0.irq_status,
            inner.vic0.address,
            v0_cur,
            v0_high,
            v0_prio,
            v0_depth,
            v0_irq_line
        );
    }

    fn fiq_vector_ready(&self, irq_vector_ready: bool) -> bool {
        let vbar = self.cpu.cp15.sctlr.vector_base();
        match self.bridge.read_word(vbar.wrapping_add(0x1c)) {
            Ok(ARM_LDR_PC_PC_0X18) => true,
            Ok(ARM_MOV_PC_R9) => irq_vector_ready && self.fiq_r9_target_ready(self.cpu.regs_fiq[1]),
            _ => false,
        }
    }

    fn fiq_r9_target_ready(&self, target: u32) -> bool {
        let target = target & !1;
        (0xC000_0000..0xC080_0000).contains(&target) && self.bridge.read_word(target & !3).is_ok()
    }

    fn trace_fiq_gate(&mut self, fiq_pending: bool, irq_ready: bool, fiq_ready: bool) {
        if self.fiq_trace_budget == 0 || self.insn_count < self.fiq_trace_start_insn || !fiq_pending
        {
            return;
        }

        let pc = self.cpu.regs[15];
        let lr = self.cpu.regs[14];
        let sp = self.cpu.regs[13];
        let cpsr = self.cpu.cpsr.to_u32();
        let vbar = self.cpu.cp15.sctlr.vector_base();
        let irq_word = self.bridge.read_word(vbar.wrapping_add(0x18)).unwrap_or(0);
        let fiq_word = self.bridge.read_word(vbar.wrapping_add(0x1c)).unwrap_or(0);
        let vector_words = self.guest_word_window(vbar, 8);
        let fiq_r9_target_ready = self.fiq_r9_target_ready(self.cpu.regs_fiq[1]);
        let fiq_regs_banked = self
            .cpu
            .regs_fiq
            .iter()
            .enumerate()
            .map(|(i, value)| format!("r{}={:#x}", i + 8, *value))
            .collect::<Vec<_>>()
            .join(" ");
        let fiq_sp_banked = self.cpu.regs_fiq[5];
        let fiq_lr_banked = self.cpu.regs_fiq[6];
        let (
            kernel_started,
            v0_raw,
            v0_en,
            v0_intselect,
            v0_irq,
            v0_fiq,
            v0_addr,
            v0_cur,
            v0_high,
            v0_prio,
            v0_depth,
            v0_irq_line,
            v0_fiq_line,
        ) = {
            let inner = self.bridge.inner.borrow();
            let (v0_cur, v0_high, v0_prio, v0_depth, v0_irq_line, v0_fiq_line) =
                inner.vic0.debug_priority_state();
            (
                inner.kernel_started,
                inner.vic0.rawintr,
                inner.vic0.intenable,
                inner.vic0.intselect,
                inner.vic0.irq_status,
                inner.vic0.fiq_status,
                inner.vic0.address,
                v0_cur,
                v0_high,
                v0_prio,
                v0_depth,
                v0_irq_line,
                v0_fiq_line,
            )
        };

        let trace = (fiq_pending as u128)
            | ((self.cpu.cpsr.f as u128) << 1)
            | ((irq_ready as u128) << 2)
            | ((fiq_ready as u128) << 3)
            | (((fiq_word as u128) & 0xffff_ffff) << 16)
            | (((v0_raw as u128) & 0xffff_ffff) << 48)
            | (((v0_en as u128) & 0xffff_ffff) << 80)
            | (((pc as u128) & 0xffff) << 112);
        if trace == self.last_fiq_trace {
            return;
        }
        self.last_fiq_trace = trace;
        self.fiq_trace_budget -= 1;

        info!(
            pc = format!("{pc:#x}"),
            lr = format!("{lr:#x}"),
            sp = format!("{sp:#x}"),
            cpsr = format!("{cpsr:#x}"),
            insns = self.insn_count,
            kernel_started,
            irq_ready,
            fiq_ready,
            vbar = format!("{vbar:#x}"),
            irq_word = format!("{irq_word:#x}"),
            fiq_word = format!("{fiq_word:#x}"),
            vectors = vector_words,
            fiq_r9_target_ready,
            fiq_regs_banked,
            fiq_sp_banked = format!("{fiq_sp_banked:#x}"),
            fiq_lr_banked = format!("{fiq_lr_banked:#x}"),
            v0_raw = format!("{v0_raw:#x}"),
            v0_en = format!("{v0_en:#x}"),
            v0_intselect = format!("{v0_intselect:#x}"),
            v0_irq = format!("{v0_irq:#x}"),
            v0_fiq = format!("{v0_fiq:#x}"),
            v0_addr = format!("{v0_addr:#x}"),
            v0_cur,
            v0_high,
            v0_prio,
            v0_depth,
            v0_irq_line,
            v0_fiq_line,
            trail = self.recent_pc_trail(24),
            "fiq gate trace"
        );
    }

    fn take_exception(&mut self, exc: ExceptionType) {
        let vbar = self.cpu.cp15.sctlr.vector_base();
        let mut exec = Executor::with_vbar(&mut self.cpu, &mut self.bridge, vbar);
        exec.exclusive_monitor = self.excl.clone();
        exec.take_exception(exc);
        self.excl = exec.exclusive_monitor.clone();
    }

    /// Service a pending 8900-engine decryption request, if any.
    fn service_engine_8900(&mut self) {
        let req = self.bridge.inner.borrow_mut().engine_8900_req.take();
        if let Some(addr) = req {
            self.decrypt_8900(addr);
        }
    }

    fn phys_r32(&self, pa: u32) -> u32 {
        let mut b = [0u8; 4];
        let _ = self.bridge.mem.read_slice(&mut b, GuestAddress(pa as u64));
        u32::from_le_bytes(b)
    }

    fn phys_r(&self, pa: u32, len: usize) -> Vec<u8> {
        let mut b = vec![0u8; len];
        let _ = self.bridge.mem.read_slice(&mut b, GuestAddress(pa as u64));
        b
    }

    fn phys_w(&self, pa: u32, data: &[u8]) {
        let _ = self.bridge.mem.write_slice(data, GuestAddress(pa as u64));
    }

    /// Service a pending ADM (Apple Data Mover) command. The ADM is the
    /// high-level NAND DMA: iBoot writes a command structure into a data
    /// section in RAM, then pokes a control register; the ADM reads it, sets
    /// the NAND controller up for the page read, and deposits the page spare.
    fn service_adm(&mut self) {
        let req = self.bridge.inner.borrow_mut().adm_req.take();
        let Some(req) = req else { return };
        let off = req >> 28;
        let value = req & 0xFF;
        let (data2, data3) = {
            let i = self.bridge.inner.borrow();
            (i.adm_data2, i.adm_data3)
        };

        if off == 0 {
            // ADM_CTRL: start-up — mark device started and banks present.
            if value == 0x3 {
                self.phys_w(data2, &0x50u32.to_le_bytes());
                let mut chip = Vec::with_capacity(32);
                for _ in 0..8 {
                    chip.extend_from_slice(&0xA514_D3ADu32.to_le_bytes());
                }
                self.phys_w(data3, &chip);
            }
            return;
        }
        // ADM_CTRL2: devos50's reference only executes a command on the exact
        // value 0x2. The kernel also writes 0x6 while loading ADM/FMC firmware;
        // treating that as a command creates a spurious ADM interrupt storm.
        // A write without bit1 set acknowledges/clears the completion interrupt
        // (mirrors qemu_irq_lower when (value & 0x2) == 0).
        if value & 0x2 == 0 {
            let mut inner = self.bridge.inner.borrow_mut();
            inner.set_adm_irq(false);
            if std::env::var("RAX_S5L_ADM_TRACE").is_ok() {
                debug!(value = format!("{value:#x}"), "adm_irq_clear");
            }
            if std::env::var_os("RAX_S5L_ADMIRQ_TRACE").is_some()
                && inner.kernel_started
                && self.insn_count >= self.adm_irq_trace_start_insn
            {
                let (v0_cur, v0_high, v0_prio, v0_depth, v0_irq_line, _) =
                    inner.vic0.debug_priority_state();
                let (v1_cur, v1_high, v1_prio, v1_depth, v1_irq_line, _) =
                    inner.vic1.debug_priority_state();
                info!(
                    value = format!("{value:#x}"),
                    v0_raw = format!("{:#x}", inner.vic0.rawintr),
                    v0_en = format!("{:#x}", inner.vic0.intenable),
                    v0_irq = format!("{:#x}", inner.vic0.irq_status),
                    v0_cur,
                    v0_high,
                    v0_prio,
                    v0_depth,
                    v0_irq_line,
                    v1_raw = format!("{:#x}", inner.vic1.rawintr),
                    v1_en = format!("{:#x}", inner.vic1.intenable),
                    v1_irq = format!("{:#x}", inner.vic1.irq_status),
                    v1_cur,
                    v1_high,
                    v1_prio,
                    v1_depth,
                    v1_irq_line,
                    insns = self.insn_count,
                    "adm completion cleared"
                );
            }
            return;
        }
        if value != 0x2 {
            if std::env::var("RAX_S5L_ADM_TRACE").is_ok() {
                debug!(value = format!("{value:#x}"), "adm_ctrl2_ignored");
            }
            return;
        }
        let cmd = self.phys_r32(data2 + 0x1104 + 0x24);
        let num_pages = {
            let v = self.phys_r32(data2 + 0x1104 + 0x28) as u16;
            v.swap_bytes()
        };
        let bswap = |p: u32| p.swap_bytes();
        let mut first_page = None;
        let mut first_bank = None;
        let mut adm_page_dump = None;

        match cmd {
            0x300 if num_pages == 1 => {
                let mut bank = (self.phys_r32(data2 + 0x1104 + 0x44) & 0xFF) as u32;
                let mut page = bswap(self.phys_r32(data2 + 0x1104 + 0x244));
                let kernel_started = self.bridge.inner.borrow().kernel_started;
                if kernel_started && !self.wmr_init_active && bank == 0 && page == 0 {
                    let remapped_page = std::env::var("RAX_S5L_LOGICAL0_PAGE")
                        .ok()
                        .and_then(|value| value.parse::<u32>().ok());
                    if let Some(remapped_page) = remapped_page {
                        debug!(
                            from_bank = bank,
                            from_page = page,
                            to_bank = 0u32,
                            to_page = remapped_page,
                            "adm single-page logical0 remap"
                        );
                        bank = 0;
                        page = remapped_page;
                    }
                }
                first_bank = Some(bank);
                first_page = Some(page);
                let mut inner = self.bridge.inner.borrow_mut();
                inner.nand.set_kernel_started(kernel_started);
                inner.nand.reading_multiple_pages = false;
                inner.nand.set_bank(bank);
                inner.nand.write(0x30, 0x800 - 1); // FMDNUM
                inner.nand.write(0xC, page << 16); // FMADDR0
                inner.nand.write(0x10, (page >> 16) & 0xFF); // FMADDR1
                inner.nand.write(0x8, 0x30); // CMD = READ
                inner.nand.set_buffered_page(page);
                let spare = inner.nand.spare_buffer.clone();
                if kernel_started {
                    let dump_len = std::env::var("RAX_S5L_ADM_PAGE_DUMP")
                        .ok()
                        .map(|value| value.parse::<usize>().unwrap_or(512))
                        .unwrap_or(0);
                    if dump_len != 0 {
                        adm_page_dump = Some((
                            bank,
                            page,
                            inner.nand.buffered_page_prefix(dump_len).to_vec(),
                            inner.nand.spare_buffer[..NAND_BYTES_PER_SPARE.min(0x20)].to_vec(),
                        ));
                    }
                }
                drop(inner);
                self.phys_w(data3, &spare[..NAND_BYTES_PER_SPARE]);
            }
            0x300 | 0x200 => {
                // Scattered / multi-page read: queue the page/bank list.
                let n = num_pages as usize;
                let mut inner = self.bridge.inner.borrow_mut();
                let kernel_started = inner.kernel_started;
                inner.nand.set_kernel_started(kernel_started);
                inner.nand.reading_multiple_pages = true;
                for i in 0..n.min(512) {
                    let page = if cmd == 0x200 {
                        // Same starting page across all 8 banks per group.
                        let base = bswap(self.phys_r32(data2 + 0x1104 + 0x244));
                        base + (i / 8) as u32
                    } else {
                        bswap(self.phys_r32(data2 + 0x1104 + 0x244 + 4 * i as u32))
                    };
                    let bank = if cmd == 0x200 {
                        (i % 8) as u32
                    } else {
                        (self.phys_r32(data2 + 0x1104 + 0x44 + i as u32) & 0xFF) as u32
                    };
                    if i == 0 {
                        first_bank = Some(bank);
                        first_page = Some(page);
                    }
                    inner.nand.pages_to_read[i] = page;
                    inner.nand.banks_to_read[i] = bank;
                }
                inner.nand.fmdnum = num_pages as u32 * 0x800;
                inner.nand.cur_bank_reading = -1;
                drop(inner);
                // Mark each scattered page's spare slot as readable.
                for i in 0..n {
                    let mut sbuf = [0u8; 0xC];
                    sbuf[10] = 0xFF;
                    self.phys_w(data3 + i as u32 * 0xC, &sbuf);
                }
            }
            0x500 => {
                // Page write. QEMU arms the NAND FIFO here; the follow-up PL080
                // transfer writes page words into FMFIFO.
                let bank = (self.phys_r32(data2 + 0x1104 + 0x44) & 0xFF) as u32;
                let page = bswap(self.phys_r32(data2 + 0x1104 + 0x244));
                first_bank = Some(bank);
                first_page = Some(page);
                let mut inner = self.bridge.inner.borrow_mut();
                let kernel_started = inner.kernel_started;
                inner.nand.set_kernel_started(kernel_started);
                inner.nand.begin_page_write(bank, page);
            }
            _ => {}
        }
        if let Some((dump_bank, dump_page, page_data, spare_data)) = adm_page_dump {
            info!(
                cmd = format!("{cmd:#x}"),
                num_pages,
                bank = dump_bank,
                page = dump_page,
                data = hex_bytes(&page_data),
                spare = hex_bytes(&spare_data),
                pc = format!("{:#x}", self.cpu.regs[15]),
                lr = format!("{:#x}", self.cpu.regs[14]),
                insns = self.insn_count,
                "kernel adm page dump"
            );
        }
        // Raise the ADM completion interrupt (VIC1 line 5 / global IRQ 0x25).
        // iBoot's NAND/FTL driver issues the command then blocks waiting for it.
        debug!(
            cmd = format!("{cmd:#x}"),
            num_pages, first_bank, first_page, "adm_cmd"
        );
        if std::env::var_os("RAX_S5L_ADM_DUMP").is_some()
            && self.bridge.inner.borrow().kernel_started
        {
            let cmd_base = data2 + 0x1104;
            let cmd_head = self.phys_r(cmd_base, 0x80);
            let page_words = self.phys_r(cmd_base + 0x244, num_pages.max(1) as usize * 4);
            let bank_bytes = self.phys_r(cmd_base + 0x44, num_pages.max(1) as usize);
            let spare = self.phys_r(data3, NAND_BYTES_PER_SPARE.min(0x20));
            info!(
                cmd = format!("{cmd:#x}"),
                num_pages,
                first_bank,
                first_page,
                cmd_base = format!("{cmd_base:#x}"),
                data2 = format!("{data2:#x}"),
                data3 = format!("{data3:#x}"),
                head = hex_bytes(&cmd_head),
                pages = hex_bytes(&page_words),
                banks = hex_bytes(&bank_bytes),
                spare = hex_bytes(&spare),
                pc = format!("{:#x}", self.cpu.regs[15]),
                lr = format!("{:#x}", self.cpu.regs[14]),
                insns = self.insn_count,
                "kernel adm command dump"
            );
        }
        if std::env::var_os("RAX_S5L_ADM_STACK_TRACE").is_some()
            && self.bridge.inner.borrow().kernel_started
        {
            let sp = self.cpu.regs[13];
            let mut frames = Vec::new();
            for i in 0..256u32 {
                if let Ok(w) = self.bridge.read_word(sp.wrapping_add(i * 4)) {
                    let a = w & !1;
                    if (0xC000_0000..0xC060_0000).contains(&a) {
                        frames.push(format!("{a:#x}"));
                    }
                }
            }
            info!(
                cmd = format!("{cmd:#x}"),
                num_pages,
                first_bank,
                first_page,
                pc = format!("{:#x}", self.cpu.regs[15]),
                lr = format!("{:#x}", self.cpu.regs[14]),
                sp = format!("{sp:#x}"),
                r0 = format!("{:#x}", self.cpu.regs[0]),
                r1 = format!("{:#x}", self.cpu.regs[1]),
                r2 = format!("{:#x}", self.cpu.regs[2]),
                r3 = format!("{:#x}", self.cpu.regs[3]),
                data2 = format!("{data2:#x}"),
                data3 = format!("{data3:#x}"),
                stack = frames.join(" "),
                trail = self.recent_pc_trail(32),
                insns = self.insn_count,
                "kernel adm stack trace"
            );
        }
        let mut inner = self.bridge.inner.borrow_mut();
        inner.set_adm_irq(true);
        if std::env::var_os("RAX_S5L_ADMIRQ_TRACE").is_some()
            && inner.kernel_started
            && self.insn_count >= self.adm_irq_trace_start_insn
        {
            let (v0_cur, v0_high, v0_prio, v0_depth, v0_irq_line, _) =
                inner.vic0.debug_priority_state();
            let (v1_cur, v1_high, v1_prio, v1_depth, v1_irq_line, _) =
                inner.vic1.debug_priority_state();
            info!(
                cmd = format!("{cmd:#x}"),
                num_pages,
                first_bank,
                first_page,
                v0_raw = format!("{:#x}", inner.vic0.rawintr),
                v0_en = format!("{:#x}", inner.vic0.intenable),
                v0_irq = format!("{:#x}", inner.vic0.irq_status),
                v0_cur,
                v0_high,
                v0_prio,
                v0_depth,
                v0_irq_line,
                v1_raw = format!("{:#x}", inner.vic1.rawintr),
                v1_en = format!("{:#x}", inner.vic1.intenable),
                v1_irq = format!("{:#x}", inner.vic1.irq_status),
                v1_cur,
                v1_high,
                v1_prio,
                v1_depth,
                v1_irq_line,
                insns = self.insn_count,
                "adm completion raised"
            );
        }
    }

    fn tick_lcd_refresh(&mut self, ticks: u64) {
        if !self.lcd_irq || !self.lcd_irq_armed || self.lcd_irq_budget == 0 {
            return;
        }
        let raised = {
            let mut inner = self.bridge.inner.borrow_mut();
            inner.lcd.tick(ticks)
        };
        if raised {
            self.lcd_irq_budget = self.lcd_irq_budget.saturating_sub(1);
            if self.lcd_irq_budget == 0 {
                info!(insns = self.insn_count, "LCD refresh IRQ budget exhausted");
            }
        }
    }

    fn arm_lcd_refresh(&mut self, reason: &'static str) {
        self.lcd_irq_armed = true;
        info!(insns = self.insn_count, reason, "armed LCD refresh IRQ");
    }

    fn step(&mut self) -> StepOutcome {
        self.sync_mmu();
        let pc = self.cpu.regs[15];
        if self.lcd_irq && !self.lcd_irq_armed && pc == KERNEL_BSD_INIT_AFTER_VFS_MOUNTROOT {
            self.arm_lcd_refresh("vfs_mountroot returned");
        } else if self.lcd_irq
            && !self.lcd_irq_armed
            && self.lcd_irq_arm_after_rootdev
            && self.insn_count & 0xFFFF == 0
            && self.bridge.read_word(KERNEL_ROOTDEV_GLOBAL).unwrap_or(0) != 0
        {
            self.arm_lcd_refresh("root device selected");
        }
        self.tick_lcd_refresh(1);
        {
            self.timer_irq_clock = self.timer_irq_clock.saturating_add(1);
            let mut inner = self.bridge.inner.borrow_mut();
            // The synthesized system-tick IRQ drives iBoot's cooperative
            // scheduler. tick_irq self-gates on the timer's `started` flag, so
            // it only fires once iBoot has armed TIMER_4 (i.e. the scheduler is
            // up). This is what wakes tasks blocked in task_sleep.
            // Pace the µs timer from retired instructions by default. The
            // interpreter runs much slower than the real S5L8900 CPU, so using
            // host wall time lets XNU timeout callouts overtake interrupt and
            // configuration work. The explicit zero diagnostic mode below
            // retains the coarsely updated host-clock implementation.
            if self.det_timer != 0 {
                inner
                    .timer
                    .set_micros(self.timer_irq_clock / self.det_timer * self.timer_mul);
            } else if self.insn_count & 0xFF == 0 {
                let us = self.boot_instant.elapsed().as_micros() as u64;
                inner
                    .timer
                    .set_micros(us.wrapping_mul(self.timer_speedup) * self.timer_mul);
            }
            if self.timer_irq {
                inner.timer.tick_irq(
                    self.timer_irq_ready,
                    self.timer_irq_interval,
                    self.insn_count,
                    self.timer_irq_interval,
                );
            }
        }

        let (irq_pending, fiq_pending) = self.sync_irqs();
        if irq_pending || fiq_pending {
            self.cpu.is_halted = false;
        }
        // Only deliver external exceptions once the guest has actually
        // installed its vectors at the active vector base. iBoot runs from
        // 0x18000000 and maps virtual 0 -> its in-place vector table only after
        // early init; before that the vectors read back as zeros and the CPU
        // would walk off into low memory. The real vector instruction is
        // `LDR pc, [pc, #0x18]` (0xe59ff018), so gate on seeing it. This
        // replaces the fragile fixed-instruction-count readiness heuristic.
        let irq_vector_ready = {
            let vbar = self.cpu.cp15.sctlr.vector_base();
            matches!(
                self.bridge.read_word(vbar.wrapping_add(0x18)),
                Ok(ARM_LDR_PC_PC_0X18)
            )
        };
        let fiq_vector_ready = self.fiq_vector_ready(irq_vector_ready);
        self.trace_i2c1_irq_handoff(irq_pending, irq_vector_ready);
        self.trace_fiq_gate(fiq_pending, irq_vector_ready, fiq_vector_ready);
        self.advance_irq_samples();
        if fiq_pending && !self.cpu.cpsr.f && fiq_vector_ready {
            let from = self.cpu.regs[15];
            let from_cpsr = self.cpu.cpsr.to_u32();
            let vbar = self.cpu.cp15.sctlr.vector_base();
            self.take_exception(ExceptionType::Fiq);
            if self.fault_log_budget > 0 {
                self.fault_log_budget -= 1;
                debug!(
                    from = format!("{from:#x}"),
                    from_cpsr = format!("{from_cpsr:#x}"),
                    spsr_fiq = format!("{:#x}", self.cpu.spsr_fiq.to_u32()),
                    vbar = format!("{vbar:#x}"),
                    to = format!("{:#x}", self.cpu.regs[15]),
                    fiq_sp = format!("{:#x}", self.cpu.regs[13]),
                    insns = self.insn_count,
                    "fiq delivered"
                );
            }
            return StepOutcome::Progress;
        }

        if irq_pending && !self.cpu.cpsr.i && irq_vector_ready {
            let from = self.cpu.regs[15];
            let from_cpsr = self.cpu.cpsr.to_u32();
            let vbar = self.cpu.cp15.sctlr.vector_base();
            self.take_exception(ExceptionType::Irq);
            if self.fault_log_budget > 0 {
                self.fault_log_budget -= 1;
                debug!(
                    from = format!("{from:#x}"),
                    from_cpsr = format!("{from_cpsr:#x}"),
                    spsr_irq = format!("{:#x}", self.cpu.spsr_irq.to_u32()),
                    vbar = format!("{vbar:#x}"),
                    to = format!("{:#x}", self.cpu.regs[15]),
                    irq_sp = format!("{:#x}", self.cpu.regs[13]),
                    insns = self.insn_count,
                    "irq delivered"
                );
            }
            return StepOutcome::Progress;
        }

        if self.cpu.is_halted {
            self.timer_irq_clock = self
                .timer_irq_clock
                .saturating_add(self.timer_irq_interval.max(1));
            let micros = if self.det_timer != 0 {
                self.timer_irq_clock / self.det_timer * self.timer_mul
            } else {
                let us = self.boot_instant.elapsed().as_micros() as u64;
                us.wrapping_mul(self.timer_speedup) * self.timer_mul
            };
            {
                let mut inner = self.bridge.inner.borrow_mut();
                inner.timer.set_micros(micros);
                if self.timer_irq {
                    inner.timer.tick_irq(
                        self.timer_irq_ready,
                        self.timer_irq_interval,
                        self.timer_irq_clock,
                        self.timer_irq_interval,
                    );
                }
                if self.idle_trace
                    && self.insn_count >= self.idle_trace_start_insn
                    && self.last_idle_trace_insn != self.timer_irq_clock
                {
                    self.last_idle_trace_insn = self.timer_irq_clock;
                    let (
                        timer_micros,
                        timer_status,
                        timer_config,
                        bcount1,
                        bcount2,
                        timer_irq,
                        timer_started,
                        next_irq_micros,
                        next_irq_insn,
                    ) = inner.timer.debug_state();
                    info!(
                        pc = format!("{:#x}", self.cpu.regs[15]),
                        lr = format!("{:#x}", self.cpu.regs[14]),
                        cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
                        insns = self.insn_count,
                        timer_irq_clock = self.timer_irq_clock,
                        timer_micros,
                        timer_status = format!("{timer_status:#x}"),
                        timer_config = format!("{timer_config:#x}"),
                        bcount1 = format!("{bcount1:#x}"),
                        bcount2 = format!("{bcount2:#x}"),
                        timer_irq,
                        timer_started,
                        next_irq_micros,
                        next_irq_insn,
                        vic0_raw = format!("{:#x}", inner.vic0.rawintr),
                        vic0_en = format!("{:#x}", inner.vic0.intenable),
                        vic0_irq = format!("{:#x}", inner.vic0.irq_status),
                        vic1_raw = format!("{:#x}", inner.vic1.rawintr),
                        vic1_en = format!("{:#x}", inner.vic1.intenable),
                        vic1_irq = format!("{:#x}", inner.vic1.irq_status),
                        "s5l idle trace"
                    );
                }
            }
            // QEMU's LCD refresh is a display timer, not CPU-instruction
            // progress. Keep it able to wake the guest once the kernel blocks
            // waiting for post-root work.
            self.tick_lcd_refresh(200_000);
            return StepOutcome::Idle;
        }

        // Debug aid: once iBoot has reached its console wait, inject serial
        // input (RAX_S5L_INPUT) into the UART RX so its recovery console can be
        // driven (e.g. a boot command). Seeded once.
        if !self.input_seeded && self.insn_count > 50_000_000 {
            if let Some(bytes) = self.input_payload.as_ref() {
                if let Some(u) = self.uart.get() {
                    if let Ok(mut u) = u.lock() {
                        u.queue_input(bytes);
                    }
                }
                self.input_seeded = true;
            }
        }

        if self.fix_usb_wrangler_phy_registered_race(pc) {
            return StepOutcome::Progress;
        }
        if self.force_iomedia_bsd_resource_check(pc) {
            return StepOutcome::Progress;
        }
        if self.printf_trace && pc == IBOOT_PRINTF {
            self.trace_iboot_printf();
        }
        if pc == IBOOT_SECURITY_STATE_CHECK {
            self.seed_img2_security_state();
        }
        if pc == IBOOT_VFL_MASK_TEST {
            self.seed_sparse_vfl_mask();
            if self.vfl_scan_trace {
                self.trace_vfl_scan();
            }
        }
        if self.fsboot_trace {
            self.trace_fsboot_pc(pc);
        }
        self.pc_ring[self.pc_ring_idx] = pc;
        self.pc_ring_idx = (self.pc_ring_idx + 1) % self.pc_ring.len();
        let is_thumb = self.cpu.cpsr.t;

        let mut insn_len = 4u32;
        // Decode bytes in MEMORY order (the decoder reads hw1 from bytes[0..2],
        // hw2 from bytes[2..4]). For ARM and 16-bit Thumb this is just the
        // little-endian word/halfword.
        let mut decode_bytes = [0u8; 4];
        let raw = if is_thumb {
            let hw1 = match self.bridge.read_halfword(pc) {
                Ok(v) => v,
                Err(_) => return self.prefetch_abort(pc),
            };
            decode_bytes[0..2].copy_from_slice(&hw1.to_le_bytes());
            if (hw1 >> 11) >= 0x1D {
                let hw2 = match self.bridge.read_halfword(pc.wrapping_add(2)) {
                    Ok(v) => v,
                    Err(_) => return self.prefetch_abort(pc),
                };
                decode_bytes[2..4].copy_from_slice(&hw2.to_le_bytes());
                ((hw1 as u32) << 16) | hw2 as u32
            } else {
                insn_len = 2;
                hw1 as u32
            }
        } else {
            let w = match self.bridge.read_word(pc) {
                Ok(v) => v,
                Err(_) => return self.prefetch_abort(pc),
            };
            decode_bytes.copy_from_slice(&w.to_le_bytes());
            w
        };

        // Derail detector: a long run of all-zero instruction words means the
        // CPU has branched into zeroed memory. Dump the recent PC history so
        // the bad branch can be located, then stop.
        if raw == 0 && pc < 0x1800_0000 {
            self.zero_slide += 1;
            if self.zero_slide == 48 && self.derail_trace {
                let mut trail = Vec::new();
                for i in 0..self.pc_ring.len() {
                    let idx = (self.pc_ring_idx + i) % self.pc_ring.len();
                    let p = self.pc_ring[idx];
                    if p >= 0x1800_0000 {
                        trail.push(format!("{p:#x}"));
                    }
                }
                debug!(
                    trail = trail.join(" "),
                    insns = self.insn_count,
                    "derail trail"
                );
                self.shutdown = true;
                return StepOutcome::Idle;
            }
        } else {
            self.zero_slide = 0;
        }

        if pc >= 0xC000_0000 {
            self.bridge.inner.borrow_mut().kernel_started = true;
            self.trace_kernel_pc(pc, raw);
            self.trace_pc_sample(pc, raw);
            self.trace_storage_call(pc);
            self.trace_partition_scan(pc);
            self.trace_fdisk_partition(pc);
            self.trace_root_boot(pc);
            self.trace_apple_arm_function(pc, raw);
            self.trace_iokit_message_path(pc, raw);
            self.trace_pmqueue(pc, raw);
            self.trace_sdio_power(pc, raw);
            self.trace_iokit_object_watch(pc, raw);
            self.trace_ioreg_free(pc, raw);
            self.trace_iokit_lifetime(pc, raw);
            self.trace_admfmc_perform_io(pc);
            self.trace_nandftl_start(pc);
            self.track_wmr_init(pc);
            self.trace_wmr_init(pc);
        }
        if pc == KERNEL_SLEH_ABORT {
            self.trace_kernel_sleh_abort_frame();
        } else if pc == KERNEL_IOPANIC {
            self.trace_kernel_iopanic();
        } else if pc == KERNEL_PANIC {
            self.trace_kernel_panic();
        }

        if self.trace_all && self.insn_count >= self.trace_start_insn && self.trace_log_budget > 0 {
            self.trace_log_budget -= 1;
            info!(
                pc = format!("{pc:#x}"),
                raw = format!("{raw:#010x}"),
                lr = format!("{:#x}", self.cpu.regs[14]),
                cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
                spsr_irq = format!("{:#x}", self.cpu.spsr_irq.to_u32()),
                insns = self.insn_count,
                "insn"
            );
        }
        if self.trace_pcs.contains(&pc)
            && self.trace_log_budget > 0
            && self.insn_count >= self.trace_start_insn
        {
            self.trace_log_budget -= 1;
            let regs: Vec<String> = (0..16)
                .map(|i| format!("r{i}={:#x}", self.cpu.regs[i]))
                .collect();
            info!(
                pc = format!("{pc:#x}"),
                raw = format!("{raw:#010x}"),
                regs = regs.join(" "),
                cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
                insns = self.insn_count,
                "trace-pc hit"
            );
        }

        let state = if is_thumb {
            ExecutionState::Thumb
        } else {
            ExecutionState::Aarch32
        };
        let slice: &[u8] = if insn_len == 2 {
            &decode_bytes[..2]
        } else {
            &decode_bytes
        };
        self.decoder.set_state(state);
        let insn = match self.decoder.decode(slice) {
            Ok(i) => i,
            Err(_) => {
                self.log_undefined_instruction("decode", pc, raw, insn_len, None);
                self.take_exception(ExceptionType::UndefinedInstruction);
                return StepOutcome::Progress;
            }
        };

        {
            let mut inner = self.bridge.inner.borrow_mut();
            inner.cur_pc = pc;
            inner.cur_insn = self.insn_count;
        }
        let vbar = self.cpu.cp15.sctlr.vector_base();
        let advance_it = is_thumb && self.cpu.cpsr.in_it_block();
        let mut exec = Executor::with_vbar(&mut self.cpu, &mut self.bridge, vbar);
        exec.exclusive_monitor = self.excl.clone();
        let result = exec.execute(&insn);
        self.excl = exec.exclusive_monitor.clone();
        self.insn_count += 1;

        // Service any decryption request the just-executed store triggered.
        if self.bridge.inner.borrow().engine_8900_req.is_some() {
            self.service_engine_8900();
        }
        // Service an AES-engine GO the just-executed store triggered.
        if self.bridge.inner.borrow().aes.pending_go {
            self.service_aes();
        }
        // Service any ADM/NAND DMA command the just-executed store triggered.
        if self.bridge.inner.borrow().adm_req.is_some() {
            self.service_adm();
        }

        match result {
            ExecResult::Continue => {
                self.cpu.regs[15] = self.cpu.regs[15].wrapping_add(insn_len);
                if advance_it {
                    self.cpu.cpsr.advance_it_state();
                }
                StepOutcome::Progress
            }
            ExecResult::Branch(target) => {
                if insn.mnemonic == Mnemonic::RFE {
                    // RFE restored CPSR (including T) itself.
                    self.cpu.regs[15] = target & !1;
                } else if target & 1 != 0 {
                    self.cpu.cpsr.t = true;
                    self.cpu.regs[15] = target & !1;
                } else {
                    self.cpu.regs[15] = target;
                }
                if advance_it {
                    self.cpu.cpsr.advance_it_state();
                }
                StepOutcome::Progress
            }
            ExecResult::Exception(exc) => {
                self.take_exception(exc);
                StepOutcome::Progress
            }
            ExecResult::Halt => {
                self.cpu.is_halted = true;
                StepOutcome::Idle
            }
            ExecResult::Undefined => {
                self.log_undefined_instruction("execute", pc, raw, insn_len, Some(insn.mnemonic));
                self.take_exception(ExceptionType::UndefinedInstruction);
                StepOutcome::Progress
            }
            ExecResult::MemoryFault(_) => {
                let f = self.bridge.inner.borrow().last_fault;
                if self.should_log_kernel_fault(self.cpu.regs[15]) {
                    info!(
                        pc = format!("{:#x}", self.cpu.regs[15]),
                        raw = format!("{raw:#010x}"),
                        addr = format!("{:#x}", f.addr),
                        fsr = format!("{:#x}", f.fsr),
                        domain = f.domain,
                        access = format!("{:#x}", f.access),
                        r0 = format!("{:#x}", self.cpu.regs[0]),
                        r1 = format!("{:#x}", self.cpu.regs[1]),
                        r2 = format!("{:#x}", self.cpu.regs[2]),
                        r3 = format!("{:#x}", self.cpu.regs[3]),
                        r4 = format!("{:#x}", self.cpu.regs[4]),
                        r5 = format!("{:#x}", self.cpu.regs[5]),
                        r6 = format!("{:#x}", self.cpu.regs[6]),
                        r7 = format!("{:#x}", self.cpu.regs[7]),
                        sp = format!("{:#x}", self.cpu.regs[13]),
                        lr = format!("{:#x}", self.cpu.regs[14]),
                        cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
                        spsr_abt = format!("{:#x}", self.cpu.spsr_abt.to_u32()),
                        sp_abt = format!("{:#x}", self.cpu.regs_abt[0]),
                        lr_abt = format!("{:#x}", self.cpu.regs_abt[1]),
                        trail = self.recent_pc_trail(24),
                        insns = self.insn_count,
                        "kernel data abort"
                    );
                }
                if self.fault_log_budget > 0 {
                    self.fault_log_budget -= 1;
                    debug!(
                        pc = format!("{:#x}", self.cpu.regs[15]),
                        addr = format!("{:#x}", f.addr),
                        fsr = format!("{:#x}", f.fsr),
                        insns = self.insn_count,
                        "data abort"
                    );
                }
                self.cpu.cp15.dfsr =
                    f.fsr | (f.domain << 4) | if f.access & 3 == 1 { 1 << 11 } else { 0 };
                self.cpu.cp15.dfar = f.addr;
                self.take_exception(ExceptionType::DataAbort(f.addr));
                StepOutcome::Progress
            }
        }
    }

    fn prefetch_abort(&mut self, pc: u32) -> StepOutcome {
        let f = self.bridge.inner.borrow().last_fault;
        if self.should_log_kernel_fault(pc) {
            info!(
                pc = format!("{pc:#x}"),
                fsr = format!("{:#x}", f.fsr),
                sp = format!("{:#x}", self.cpu.regs[13]),
                lr = format!("{:#x}", self.cpu.regs[14]),
                cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
                spsr_abt = format!("{:#x}", self.cpu.spsr_abt.to_u32()),
                sp_abt = format!("{:#x}", self.cpu.regs_abt[0]),
                lr_abt = format!("{:#x}", self.cpu.regs_abt[1]),
                insns = self.insn_count,
                "kernel prefetch abort"
            );
        }
        if self.fault_log_budget > 0 {
            self.fault_log_budget -= 1;
            debug!(
                pc = format!("{pc:#x}"),
                fsr = format!("{:#x}", f.fsr),
                lr = format!("{:#x}", self.cpu.regs[14]),
                insns = self.insn_count,
                "prefetch abort"
            );
        }
        self.cpu.cp15.ifsr = f.fsr | (f.domain << 4);
        self.cpu.cp15.ifar = pc;
        self.take_exception(ExceptionType::PrefetchAbort(pc));
        StepOutcome::Progress
    }

    fn should_log_kernel_fault(&mut self, pc: u32) -> bool {
        if pc < 0xC000_0000 && std::env::var("RAX_S5L_FAULT_INFO").is_err() {
            return false;
        }
        if self.kernel_fault_log_remaining == 0 {
            return false;
        }
        self.kernel_fault_log_remaining -= 1;
        true
    }

    fn trace_storage_call(&mut self, pc: u32) {
        if self.storage_call_trace_remaining == 0
            || self.insn_count < self.storage_call_trace_start_insn
        {
            return;
        }

        let lr = self.cpu.regs[14];
        if !(0xc045_b000..0xc045_d1a8).contains(&pc)
            || !(0xc044_a000..0xc045_5e40).contains(&(lr & !1))
        {
            return;
        }

        let key = (pc, lr);
        if self.storage_call_trace_seen.contains(&key) {
            return;
        }
        self.storage_call_trace_seen.push(key);
        self.storage_call_trace_remaining -= 1;

        info!(
            pc = format!("{pc:#x}"),
            lr = format!("{lr:#x}"),
            r0 = format!("{:#x}", self.cpu.regs[0]),
            r1 = format!("{:#x}", self.cpu.regs[1]),
            r2 = format!("{:#x}", self.cpu.regs[2]),
            r3 = format!("{:#x}", self.cpu.regs[3]),
            r0_words = self.guest_word_window(self.cpu.regs[0], 6),
            r1_words = self.guest_word_window(self.cpu.regs[1], 4),
            r2_words = self.guest_word_window(self.cpu.regs[2], 4),
            insns = self.insn_count,
            "storage call trace"
        );
    }

    fn trace_fdisk_partition(&mut self, pc: u32) {
        if self.fdisk_trace_remaining == 0 {
            return;
        }

        let Some((_, reason)) = KERNEL_FDISK_TRACE_PCS
            .iter()
            .find(|(trace_pc, _)| *trace_pc == pc)
        else {
            return;
        };

        let lr = self.cpu.regs[14];
        let key = (pc, lr & !1);
        if self.fdisk_trace_seen.contains(&key) {
            return;
        }
        self.fdisk_trace_seen.push(key);
        self.fdisk_trace_remaining -= 1;

        let r0_vtable = self.bridge.read_word(self.cpu.regs[0]).unwrap_or(0);
        let r1_vtable = self.bridge.read_word(self.cpu.regs[1]).unwrap_or(0);
        let r2_vtable = self.bridge.read_word(self.cpu.regs[2]).unwrap_or(0);
        let r3_vtable = self.bridge.read_word(self.cpu.regs[3]).unwrap_or(0);
        let sp = self.cpu.regs[13];

        info!(
            pc = format!("{pc:#x}"),
            reason,
            r0 = format!("{:#x}", self.cpu.regs[0]),
            r1 = format!("{:#x}", self.cpu.regs[1]),
            r2 = format!("{:#x}", self.cpu.regs[2]),
            r3 = format!("{:#x}", self.cpu.regs[3]),
            r4 = format!("{:#x}", self.cpu.regs[4]),
            r5 = format!("{:#x}", self.cpu.regs[5]),
            r6 = format!("{:#x}", self.cpu.regs[6]),
            r7 = format!("{:#x}", self.cpu.regs[7]),
            r8 = format!("{:#x}", self.cpu.regs[8]),
            r9 = format!("{:#x}", self.cpu.regs[9]),
            r10 = format!("{:#x}", self.cpu.regs[10]),
            r11 = format!("{:#x}", self.cpu.regs[11]),
            r12 = format!("{:#x}", self.cpu.regs[12]),
            sp = format!("{sp:#x}"),
            lr = format!("{lr:#x}"),
            r0_str = ?self.guest_cstr(self.cpu.regs[0], 128),
            r1_str = ?self.guest_cstr(self.cpu.regs[1], 128),
            r2_str = ?self.guest_cstr(self.cpu.regs[2], 128),
            r3_str = ?self.guest_cstr(self.cpu.regs[3], 128),
            r0_vtable = format!("{r0_vtable:#x}"),
            r1_vtable = format!("{r1_vtable:#x}"),
            r2_vtable = format!("{r2_vtable:#x}"),
            r3_vtable = format!("{r3_vtable:#x}"),
            r0_words = self.guest_word_window(self.cpu.regs[0], 16),
            r1_words = self.guest_word_window(self.cpu.regs[1], 16),
            r2_words = self.guest_word_window(self.cpu.regs[2], 16),
            r3_words = self.guest_word_window(self.cpu.regs[3], 16),
            r4_words = self.guest_word_window(self.cpu.regs[4], 16),
            r5_words = self.guest_word_window(self.cpu.regs[5], 16),
            r6_words = self.guest_word_window(self.cpu.regs[6], 16),
            sp_words = self.guest_word_window(sp, 20),
            stack_refs = self.stack_code_refs(sp, 128),
            trail = self.recent_pc_trail(32),
            insns = self.insn_count,
            "fdisk partition trace"
        );
    }

    fn trace_nandftl_start(&mut self, pc: u32) {
        if self.nandftl_trace_remaining == 0 {
            return;
        }

        let Some((_, reason)) = KERNEL_NANDFTL_TRACE_PCS
            .iter()
            .find(|(trace_pc, _)| *trace_pc == pc)
        else {
            return;
        };

        let lr = self.cpu.regs[14];
        let key = (pc, lr & !1);
        if self.nandftl_trace_seen.contains(&key) {
            return;
        }
        self.nandftl_trace_seen.push(key);
        self.nandftl_trace_remaining -= 1;

        let sp = self.cpu.regs[13];
        let r0_vtable = self.bridge.read_word(self.cpu.regs[0]).unwrap_or(0);
        let r4_vtable = self.bridge.read_word(self.cpu.regs[4]).unwrap_or(0);
        let r5_vtable = self.bridge.read_word(self.cpu.regs[5]).unwrap_or(0);
        let r6_vtable = self.bridge.read_word(self.cpu.regs[6]).unwrap_or(0);
        let r6_block_device = self
            .bridge
            .read_word(self.cpu.regs[6].wrapping_add(0x54))
            .unwrap_or(0);
        let r6_workloop = self
            .bridge
            .read_word(self.cpu.regs[6].wrapping_add(0x8c))
            .unwrap_or(0);
        let r6_command_gate = self
            .bridge
            .read_word(self.cpu.regs[6].wrapping_add(0x94))
            .unwrap_or(0);

        info!(
            pc = format!("{pc:#x}"),
            reason,
            r0 = format!("{:#x}", self.cpu.regs[0]),
            r1 = format!("{:#x}", self.cpu.regs[1]),
            r2 = format!("{:#x}", self.cpu.regs[2]),
            r3 = format!("{:#x}", self.cpu.regs[3]),
            r4 = format!("{:#x}", self.cpu.regs[4]),
            r5 = format!("{:#x}", self.cpu.regs[5]),
            r6 = format!("{:#x}", self.cpu.regs[6]),
            r7 = format!("{:#x}", self.cpu.regs[7]),
            r8 = format!("{:#x}", self.cpu.regs[8]),
            r9 = format!("{:#x}", self.cpu.regs[9]),
            r10 = format!("{:#x}", self.cpu.regs[10]),
            r11 = format!("{:#x}", self.cpu.regs[11]),
            r12 = format!("{:#x}", self.cpu.regs[12]),
            sp = format!("{sp:#x}"),
            lr = format!("{lr:#x}"),
            r0_vtable = format!("{r0_vtable:#x}"),
            r4_vtable = format!("{r4_vtable:#x}"),
            r5_vtable = format!("{r5_vtable:#x}"),
            r6_vtable = format!("{r6_vtable:#x}"),
            r6_block_device = format!("{r6_block_device:#x}"),
            r6_workloop = format!("{r6_workloop:#x}"),
            r6_command_gate = format!("{r6_command_gate:#x}"),
            r0_words = self.guest_word_window(self.cpu.regs[0], 12),
            r4_words = self.guest_word_window(self.cpu.regs[4], 16),
            r5_words = self.guest_word_window(self.cpu.regs[5], 16),
            r6_words = self.guest_word_window(self.cpu.regs[6], 48),
            r6_state_words = self.guest_word_window(self.cpu.regs[6].wrapping_add(0x50), 24),
            block_device_words = self.guest_word_window(r6_block_device, 16),
            workloop_words = self.guest_word_window(r6_workloop, 12),
            command_gate_words = self.guest_word_window(r6_command_gate, 12),
            sp_words = self.guest_word_window(sp, 24),
            stack_refs = self.stack_code_refs(sp, 160),
            trail = self.recent_pc_trail(40),
            insns = self.insn_count,
            "nandftl start trace"
        );
    }

    fn trace_wmr_init(&mut self, pc: u32) {
        if self.wmr_trace_remaining == 0 {
            return;
        }

        let Some((_, reason)) = KERNEL_WMR_TRACE_PCS
            .iter()
            .find(|(trace_pc, _)| *trace_pc == pc)
        else {
            return;
        };

        let sp = self.cpu.regs[13];
        let lr = self.cpu.regs[14];
        let loop_index = self
            .bridge
            .read_word(sp.wrapping_add(0x24))
            .unwrap_or(self.cpu.regs[4]);
        let dedup_tag = match pc {
            0xC046_3BBC..=0xC046_3CB8 => loop_index,
            _ => lr & !1,
        };
        let key = (pc, dedup_tag);
        if self.wmr_trace_seen.contains(&key) {
            return;
        }
        self.wmr_trace_seen.push(key);
        self.wmr_trace_remaining -= 1;

        let func_tbl = self.bridge.read_word(sp.wrapping_add(0x14)).unwrap_or(0);
        let buf_desc = self.bridge.read_word(sp.wrapping_add(0x0c)).unwrap_or(0);
        let status = self.bridge.read_word(sp.wrapping_add(0x10)).unwrap_or(0);
        let unit_sig = self.bridge.read_word(sp.wrapping_add(0x18)).unwrap_or(0);
        let sig_found = self.bridge.read_word(sp.wrapping_add(0x1c)).unwrap_or(0);
        let blk0_clean = self.bridge.read_word(sp.wrapping_add(0x20)).unwrap_or(0);
        let func_read = self
            .bridge
            .read_word(func_tbl.wrapping_add(0x04))
            .unwrap_or(0);
        let func_read_sig = self
            .bridge
            .read_word(func_tbl.wrapping_add(0x14))
            .unwrap_or(0);
        let func_notify = self
            .bridge
            .read_word(func_tbl.wrapping_add(0x28))
            .unwrap_or(0);
        let buf_main = self.bridge.read_word(buf_desc).unwrap_or(0);
        let buf_spare = self
            .bridge
            .read_word(buf_desc.wrapping_add(0x04))
            .unwrap_or(0);
        let buf_state = self
            .bridge
            .read_word(buf_desc.wrapping_add(0x08))
            .unwrap_or(0);
        let cs_count = self
            .bridge
            .read_halfword(self.cpu.regs[6].wrapping_add(0x0c))
            .unwrap_or(0);

        info!(
            pc = format!("{pc:#x}"),
            reason,
            r0 = format!("{:#x}", self.cpu.regs[0]),
            r1 = format!("{:#x}", self.cpu.regs[1]),
            r2 = format!("{:#x}", self.cpu.regs[2]),
            r3 = format!("{:#x}", self.cpu.regs[3]),
            r4 = format!("{:#x}", self.cpu.regs[4]),
            r5 = format!("{:#x}", self.cpu.regs[5]),
            r6 = format!("{:#x}", self.cpu.regs[6]),
            r7 = format!("{:#x}", self.cpu.regs[7]),
            r8 = format!("{:#x}", self.cpu.regs[8]),
            r9 = format!("{:#x}", self.cpu.regs[9]),
            r10 = format!("{:#x}", self.cpu.regs[10]),
            r11 = format!("{:#x}", self.cpu.regs[11]),
            r12 = format!("{:#x}", self.cpu.regs[12]),
            sp = format!("{sp:#x}"),
            lr = format!("{lr:#x}"),
            func_tbl = format!("{func_tbl:#x}"),
            func_read = format!("{func_read:#x}"),
            func_read_sig = format!("{func_read_sig:#x}"),
            func_notify = format!("{func_notify:#x}"),
            buf_desc = format!("{buf_desc:#x}"),
            buf_main = format!("{buf_main:#x}"),
            buf_spare = format!("{buf_spare:#x}"),
            buf_state = format!("{buf_state:#x}"),
            status = format!("{status:#x}"),
            unit_sig = format!("{unit_sig:#x}"),
            sig_found = format!("{sig_found:#x}"),
            blk0_clean = format!("{blk0_clean:#x}"),
            loop_index = format!("{loop_index:#x}"),
            cs_count = cs_count,
            r0_words = self.guest_word_window(self.cpu.regs[0], 8),
            r1_words = self.guest_word_window(self.cpu.regs[1], 8),
            r2_words = self.guest_word_window(self.cpu.regs[2], 8),
            r3_words = self.guest_word_window(self.cpu.regs[3], 8),
            wmr_global_words = self.guest_word_window(self.cpu.regs[6], 24),
            func_tbl_words = self.guest_word_window(func_tbl, 12),
            buf_desc_words = self.guest_word_window(buf_desc, 6),
            buf_main_words = self.guest_word_window(buf_main, 8),
            sp_words = self.guest_word_window(sp, 16),
            stack_refs = self.stack_code_refs(sp, 96),
            trail = self.recent_pc_trail(36),
            insns = self.insn_count,
            "wmr init trace"
        );
    }

    fn track_wmr_init(&mut self, pc: u32) {
        match pc {
            0xC046_3AC8 => self.wmr_init_active = true,
            0xC046_3FB0 | 0xC046_3FB8 | 0xC046_3FC0 | 0xC046_3FC4 => {
                self.wmr_init_active = false;
            }
            _ => {}
        }
    }

    fn trace_partition_scan(&mut self, pc: u32) {
        if self.partition_trace_remaining == 0 {
            return;
        }

        let gpt_reason = match pc {
            0xc044_ffc8 => Some("gpt probe before scan"),
            0xc044_ffce => Some("gpt probe scan returned"),
            0xc044_ffd0 => Some("gpt probe stored partitions"),
            0xc044_ffd4 => Some("gpt probe success"),
            0xc044_ffd8 => Some("gpt probe failure"),
            0xc044_ffda => Some("gpt probe return"),
            0xc044_ffe0 => Some("gpt start entry"),
            0xc044_fff0 => Some("gpt start super result"),
            0xc044_fffa => Some("gpt start iterator result"),
            0xc045_0036 => Some("gpt start next partition result"),
            0xc045_0042 => Some("gpt start success"),
            0xc045_0046 => Some("gpt start failure"),
            0xc045_01fc => Some("gpt protective mbr signature mismatch"),
            0xc045_0216 => Some("gpt multiple protective mbr entries"),
            0xc045_0226 => Some("gpt missing protective mbr entry"),
            0xc045_024a => Some("gpt header read failed"),
            0xc045_0274 => Some("gpt header signature mismatch"),
            0xc045_02a6 => Some("gpt header size too small"),
            0xc045_02ce => Some("gpt header crc mismatch"),
            0xc045_036e => Some("gpt entry size too small"),
            0xc045_03ba if self.cpu.regs[0] == 0 => Some("gpt entry buffer allocation failed"),
            0xc045_03e2 if self.cpu.regs[0] != 0 => Some("gpt entry table read failed"),
            0xc045_0406 => Some("gpt entry loop"),
            0xc045_0436 => Some("gpt isPartitionUsed result"),
            0xc045_044c => Some("gpt isPartitionCorrupt result"),
            0xc045_044e if self.cpu.regs[0] != 0 => Some("gpt partition corrupt"),
            0xc045_0462 => Some("gpt isPartitionInvalid result"),
            0xc045_0464 if self.cpu.regs[0] != 0 => Some("gpt partition invalid"),
            0xc045_0478 => Some("gpt instantiateMediaObject result"),
            0xc045_048a => Some("gpt setObject result"),
            0xc045_0492 => Some("gpt entry skipped"),
            0xc045_04b8 => Some("gpt scan success"),
            0xc045_04ba => Some("gpt scan error exit"),
            0xc045_051c => Some("gpt scan return value"),
            _ => None,
        };
        if pc == 0xc044_ffda && self.cpu.regs[0] != 0 {
            self.iokit_match_follow_remaining = 160;
        }

        let iokit_match_reason = match pc {
            0xc012_5c84 => Some("osordered setObject index entry"),
            0xc012_5cd6 => Some("osordered setObject index store"),
            0xc012_5cea => Some("osordered setObject index count update"),
            0xc012_5d34 => Some("osordered setObject entry"),
            0xc012_5d5a => Some("osordered comparator result"),
            0xc012_5d5c => Some("osordered comparator branch"),
            0xc012_5d66 => Some("osordered insert index chosen"),
            0xc012_5d72 => Some("osordered insert call"),
            0xc012_5f28 => Some("osordered getNext entry"),
            0xc012_5f3c => Some("osordered getNext load item"),
            0xc013_6c42 => Some("iokit start categories entry"),
            0xc013_6c5a => Some("iokit start category iterator valid"),
            0xc013_6c6a => Some("iokit start lookup category list"),
            0xc013_6c76 => Some("iokit start category list result"),
            0xc013_6ca4 => Some("iokit start candidate result"),
            0xc013_6ca6 => Some("iokit start category empty"),
            0xc013_6cbe => Some("iokit start candidate before table"),
            0xc013_6ce0 => Some("iokit start candidate debug"),
            0xc013_6d18 => Some("iokit startCandidate call"),
            0xc013_6d28 => Some("iokit startCandidate returned"),
            0xc013_6d2c => Some("iokit startCandidate failed log"),
            0xc013_6d60 => Some("iokit start match category skip"),
            0xc013_6dd0 => Some("iokit start categories done"),
            0xc013_7082 => Some("iokit match probe returned"),
            0xc013_7092 => Some("iokit match after detach"),
            0xc013_7094 => Some("iokit match test probe result"),
            0xc013_7096 => Some("iokit match branch on probe result"),
            0xc013_70c0 => Some("iokit match current best check"),
            0xc013_70c6 => Some("iokit match start best service"),
            0xc013_70d2 => Some("iokit match start best returned"),
            0xc013_70d6 => Some("iokit match best start null"),
            0xc013_70e0 => Some("iokit match notify probe winner"),
            0xc013_70e2 => Some("iokit match notify returned"),
            0xc013_711e => Some("iokit match no probe result"),
            0xc013_7138 => Some("iokit match candidate cleanup"),
            0xc013_7162 => Some("iokit match start failed path"),
            0xc013_71a2 => Some("iokit match no current best"),
            _ => None,
        };

        let reason = gpt_reason.or_else(|| {
            if self.iokit_match_follow_remaining == 0 {
                None
            } else {
                iokit_match_reason
            }
        });
        let Some(reason) = reason else {
            return;
        };
        if gpt_reason.is_none() && iokit_match_reason.is_some() {
            self.iokit_match_follow_remaining = self.iokit_match_follow_remaining.saturating_sub(1);
        }
        self.partition_trace_remaining -= 1;

        if pc == 0xc044_ffda && std::env::var_os("RAX_S5L_GUID_PROBE_SCORE").is_some() {
            let score = std::env::var("RAX_S5L_GUID_PROBE_SCORE")
                .ok()
                .and_then(|value| value.parse::<u32>().ok())
                .unwrap_or(50_000);
            if let Err(err) = self.bridge.write_word(self.cpu.regs[5], score) {
                debug!(
                    addr = format!("{:#x}", self.cpu.regs[5]),
                    ?err,
                    "failed to raise GUID partition probe score"
                );
            }
        }

        let sp = self.cpu.regs[13];
        let scan_set = self
            .bridge
            .read_word(sp.wrapping_add(0x30))
            .unwrap_or_default();
        let r0_partitions = self
            .bridge
            .read_word(self.cpu.regs[0].wrapping_add(0x68))
            .unwrap_or_default();
        let r4_partitions = self
            .bridge
            .read_word(self.cpu.regs[4].wrapping_add(0x68))
            .unwrap_or_default();
        let r6_partitions = self
            .bridge
            .read_word(self.cpu.regs[6].wrapping_add(0x68))
            .unwrap_or_default();
        let sp_best = self
            .bridge
            .read_word(sp.wrapping_add(0x10))
            .unwrap_or_default();
        let sp_provider = self
            .bridge
            .read_word(sp.wrapping_add(0x28))
            .unwrap_or_default();
        let sp_score = self
            .bridge
            .read_word(sp.wrapping_add(0x2c))
            .unwrap_or_default();
        let sp_probe = self
            .bridge
            .read_word(sp.wrapping_add(0x30))
            .unwrap_or_default();
        let r0_set_items = self
            .bridge
            .read_word(self.cpu.regs[0].wrapping_add(0x10))
            .map(|addr| self.guest_word_window(addr, 8))
            .unwrap_or_else(|_| "<fault>".to_string());
        let r4_set_items = self
            .bridge
            .read_word(self.cpu.regs[4].wrapping_add(0x10))
            .map(|addr| self.guest_word_window(addr, 8))
            .unwrap_or_else(|_| "<fault>".to_string());
        let r5_set_items = self
            .bridge
            .read_word(self.cpu.regs[5].wrapping_add(0x10))
            .map(|addr| self.guest_word_window(addr, 8))
            .unwrap_or_else(|_| "<fault>".to_string());
        let r6_set_items = self
            .bridge
            .read_word(self.cpu.regs[6].wrapping_add(0x10))
            .map(|addr| self.guest_word_window(addr, 8))
            .unwrap_or_else(|_| "<fault>".to_string());

        info!(
            pc = format!("{pc:#x}"),
            reason,
            r0 = format!("{:#x}", self.cpu.regs[0]),
            r1 = format!("{:#x}", self.cpu.regs[1]),
            r2 = format!("{:#x}", self.cpu.regs[2]),
            r3 = format!("{:#x}", self.cpu.regs[3]),
            r4 = format!("{:#x}", self.cpu.regs[4]),
            r5 = format!("{:#x}", self.cpu.regs[5]),
            r6 = format!("{:#x}", self.cpu.regs[6]),
            r7 = format!("{:#x}", self.cpu.regs[7]),
            r8 = format!("{:#x}", self.cpu.regs[8]),
            r9 = format!("{:#x}", self.cpu.regs[9]),
            r10 = format!("{:#x}", self.cpu.regs[10]),
            r11 = format!("{:#x}", self.cpu.regs[11]),
            r12 = format!("{:#x}", self.cpu.regs[12]),
            sp = format!("{:#x}", self.cpu.regs[13]),
            lr = format!("{:#x}", self.cpu.regs[14]),
            r0_words = self.guest_word_window(self.cpu.regs[0], 8),
            r1_words = self.guest_word_window(self.cpu.regs[1], 8),
            r2_words = self.guest_word_window(self.cpu.regs[2], 8),
            r3_words = self.guest_word_window(self.cpu.regs[3], 8),
            r4_words = self.guest_word_window(self.cpu.regs[4], 24),
            r5_words = self.guest_word_window(self.cpu.regs[5], 24),
            r6_words = self.guest_word_window(self.cpu.regs[6], 16),
            r8_words = self.guest_word_window(self.cpu.regs[8], 16),
            r10_words = self.guest_word_window(self.cpu.regs[10], 16),
            r11_words = self.guest_word_window(self.cpu.regs[11], 16),
            sp_words = self.guest_word_window(self.cpu.regs[13], 16),
            sp_best = format!("{sp_best:#x}"),
            sp_best_words = self.guest_word_window(sp_best, 16),
            sp_provider = format!("{sp_provider:#x}"),
            sp_provider_words = self.guest_word_window(sp_provider, 16),
            sp_score = format!("{sp_score:#x}"),
            sp_probe = format!("{sp_probe:#x}"),
            sp_probe_words = self.guest_word_window(sp_probe, 16),
            scan_set = format!("{scan_set:#x}"),
            scan_set_words = self.guest_word_window(scan_set, 12),
            r0_partitions = format!("{r0_partitions:#x}"),
            r0_partitions_words = self.guest_word_window(r0_partitions, 12),
            r4_partitions = format!("{r4_partitions:#x}"),
            r4_partitions_words = self.guest_word_window(r4_partitions, 12),
            r6_partitions = format!("{r6_partitions:#x}"),
            r6_partitions_words = self.guest_word_window(r6_partitions, 12),
            r0_set_items,
            r4_set_items,
            r5_set_items,
            r6_set_items,
            trail = self.recent_pc_trail(32),
            insns = self.insn_count,
            "partition scan trace"
        );
    }

    fn trace_root_boot(&mut self, pc: u32) {
        let root_trace_allowed =
            self.root_trace_remaining > 0 && self.insn_count >= self.root_trace_start_insn;
        let root_boot_allowed = self.root_boot_trace_remaining > 0
            && self.insn_count >= self.root_boot_trace_start_insn;
        if !root_trace_allowed && !root_boot_allowed {
            return;
        }

        let Some((reason, boot_event)) = (match pc {
            KERNEL_CLOCK_INITIALIZE_CALENDAR => Some("clock_initialize_calendar"),
            KERNEL_ASSERT_WAIT => Some("assert_wait"),
            KERNEL_ASSERT_WAIT_TIMEOUT => Some("assert_wait_timeout"),
            KERNEL_ASSERT_WAIT_DEADLINE => Some("assert_wait_deadline"),
            KERNEL_THREAD_BLOCK_REASON => Some("thread_block_reason"),
            KERNEL_THREAD_BLOCK => Some("thread_block"),
            KERNEL_THREAD_WAIT => Some("thread_wait"),
            KERNEL_SEMAPHORE_TIMEDWAIT => Some("semaphore_timedwait"),
            KERNEL_SEMAPHORE_WAIT => Some("semaphore_wait"),
            KERNEL_WAKEUP => Some("wakeup"),
            KERNEL_WAKEUP_ONE => Some("wakeup_one"),
            KERNEL_IOLOCK_SLEEP => Some("IOLockSleep"),
            KERNEL_IOLOCK_SLEEP_DEADLINE => Some("IOLockSleepDeadline"),
            KERNEL_IOSYNCER_WAIT => Some("IOSyncer::wait"),
            KERNEL_IOKIT_INITIALIZE_TIME => Some("IOKitInitializeTime"),
            KERNEL_START_IOKIT => Some("StartIOKit"),
            KERNEL_IO_SERVICE_PUBLISH_RESOURCE_CSTR => Some("publishResource(char*)"),
            KERNEL_IO_SERVICE_ADD_NEEDED_RESOURCE => Some("addNeededResource(char*)"),
            KERNEL_IO_SERVICE_CHECK_RESOURCES => Some("IOService::checkResources"),
            KERNEL_IO_SERVICE_WAIT_QUIET => Some("IOService::waitQuiet"),
            KERNEL_IO_SERVICE_WAIT_FOR_SERVICE => Some("IOService::waitForService"),
            KERNEL_IO_SERVICE_WAIT_FOR_SERVICE_AFTER_SEM => {
                Some("IOService::waitForService after semaphore")
            }
            KERNEL_IO_SERVICE_RESOURCE_MATCHING_CSTR => Some("IOService::resourceMatching(char*)"),
            KERNEL_IO_SERVICE_WAIT_MATCH_IDLE => Some("IOService::waitMatchIdle"),
            KERNEL_IOKIT_BSD_INIT => Some("IOKitBSDInit"),
            KERNEL_IOBSD_NAME_MATCHING => Some("IOBSDNameMatching"),
            KERNEL_IOUUID_MATCHING => Some("IOUUIDMatching"),
            KERNEL_IOBSD_REGISTRY_ENTRY_FOR_DEVICE_TREE => Some("IOBSDRegistryEntryForDeviceTree"),
            KERNEL_IOBSD_REGISTRY_ENTRY_GET_DATA => Some("IOBSDRegistryEntryGetData"),
            KERNEL_DI_ROOT_IMAGE => Some("di_root_image"),
            KERNEL_VFS_MOUNTROOT => Some("vfs_mountroot"),
            KERNEL_DEVFS_KERNEL_MOUNT => Some("devfs_kernel_mount"),
            KERNEL_BSD_AUTOCONF => Some("bsd_autoconf"),
            KERNEL_BSD_INIT => Some("bsd_init"),
            KERNEL_BSD_INIT_CALL_IOKIT_INITIALIZE_TIME => Some("bsd_init -> IOKitInitializeTime"),
            KERNEL_BSD_INIT_CALL_BSD_AUTOCONF => Some("bsd_init -> bsd_autoconf"),
            KERNEL_BSD_INIT_CALL_VFS_MOUNTROOT => Some("bsd_init -> vfs_mountroot"),
            KERNEL_BSD_INIT_AFTER_VFS_MOUNTROOT => Some("bsd_init <- vfs_mountroot"),
            _ => None,
        })
        .map(|reason| {
            let boot_event = matches!(
                pc,
                KERNEL_CLOCK_INITIALIZE_CALENDAR
                    | KERNEL_IOKIT_INITIALIZE_TIME
                    | KERNEL_START_IOKIT
                    | KERNEL_IO_SERVICE_PUBLISH_RESOURCE_CSTR
                    | KERNEL_IO_SERVICE_ADD_NEEDED_RESOURCE
                    | KERNEL_IO_SERVICE_CHECK_RESOURCES
                    | KERNEL_IO_SERVICE_WAIT_QUIET
                    | KERNEL_IO_SERVICE_WAIT_FOR_SERVICE
                    | KERNEL_IO_SERVICE_WAIT_FOR_SERVICE_AFTER_SEM
                    | KERNEL_IO_SERVICE_RESOURCE_MATCHING_CSTR
                    | KERNEL_IO_SERVICE_WAIT_MATCH_IDLE
                    | KERNEL_IOKIT_BSD_INIT
                    | KERNEL_IOBSD_NAME_MATCHING
                    | KERNEL_IOUUID_MATCHING
                    | KERNEL_IOBSD_REGISTRY_ENTRY_FOR_DEVICE_TREE
                    | KERNEL_IOBSD_REGISTRY_ENTRY_GET_DATA
                    | KERNEL_DI_ROOT_IMAGE
                    | KERNEL_VFS_MOUNTROOT
                    | KERNEL_DEVFS_KERNEL_MOUNT
                    | KERNEL_BSD_AUTOCONF
                    | KERNEL_BSD_INIT
                    | KERNEL_BSD_INIT_CALL_IOKIT_INITIALIZE_TIME
                    | KERNEL_BSD_INIT_CALL_BSD_AUTOCONF
                    | KERNEL_BSD_INIT_CALL_VFS_MOUNTROOT
                    | KERNEL_BSD_INIT_AFTER_VFS_MOUNTROOT
            );
            (reason, boot_event)
        }) else {
            return;
        };
        if boot_event && root_boot_allowed {
            self.root_boot_trace_remaining -= 1;
        } else if root_trace_allowed {
            self.root_trace_remaining -= 1;
        } else {
            return;
        }

        let rootdev = self.bridge.read_word(KERNEL_ROOTDEV_GLOBAL).unwrap_or(0);
        let rootvnode = self.bridge.read_word(KERNEL_ROOTVNODE_GLOBAL).unwrap_or(0);
        let rootvp = self.bridge.read_word(KERNEL_ROOTVP_GLOBAL).unwrap_or(0);
        let rootfs = self.bridge.read_word(KERNEL_ROOTFS_GLOBAL).unwrap_or(0);
        let mountroot = self.bridge.read_word(KERNEL_MOUNTROOT_GLOBAL).unwrap_or(0);

        info!(
            pc = format!("{pc:#x}"),
            reason,
            r0 = format!("{:#x}", self.cpu.regs[0]),
            r1 = format!("{:#x}", self.cpu.regs[1]),
            r2 = format!("{:#x}", self.cpu.regs[2]),
            r3 = format!("{:#x}", self.cpu.regs[3]),
            r4 = format!("{:#x}", self.cpu.regs[4]),
            r5 = format!("{:#x}", self.cpu.regs[5]),
            r6 = format!("{:#x}", self.cpu.regs[6]),
            r7 = format!("{:#x}", self.cpu.regs[7]),
            sp = format!("{:#x}", self.cpu.regs[13]),
            lr = format!("{:#x}", self.cpu.regs[14]),
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            r0_str = ?self.guest_cstr(self.cpu.regs[0], 128),
            r1_str = ?self.guest_cstr(self.cpu.regs[1], 128),
            r2_str = ?self.guest_cstr(self.cpu.regs[2], 128),
            r0_words = self.guest_word_window(self.cpu.regs[0], 8),
            r1_words = self.guest_word_window(self.cpu.regs[1], 8),
            r2_words = self.guest_word_window(self.cpu.regs[2], 8),
            r3_words = self.guest_word_window(self.cpu.regs[3], 8),
            sp_words = self.guest_word_window(self.cpu.regs[13], 12),
            rootdev = format!("{rootdev:#x}"),
            rootdevice = ?self.guest_cstr(KERNEL_ROOTDEVICE_GLOBAL, 64),
            rootfs = format!("{rootfs:#x}"),
            rootvnode = format!("{rootvnode:#x}"),
            rootvp = format!("{rootvp:#x}"),
            mountroot = format!("{mountroot:#x}"),
            trail = self.recent_pc_trail(24),
            insns = self.insn_count,
            "root boot trace"
        );
    }

    fn recent_pc_trail(&self, limit: usize) -> String {
        let mut trail = Vec::new();
        for i in 0..self.pc_ring.len() {
            let idx = (self.pc_ring_idx + i) % self.pc_ring.len();
            let pc = self.pc_ring[idx];
            if pc != 0 {
                trail.push(format!("{pc:#x}"));
            }
        }
        let start = trail.len().saturating_sub(limit);
        trail[start..].join(" ")
    }

    fn trace_sdio_power(&mut self, pc: u32, raw: u32) {
        if self.sdio_power_trace_remaining == 0 || self.insn_count < self.trace_start_insn {
            return;
        }

        let Some(reason) = (match pc {
            0xc04d_44d0 => Some("SDIO power/message window prologue"),
            0xc04d_44d4 => Some("SDIO load fifth argument"),
            0xc04d_44d8 => Some("SDIO load command constant"),
            0xc04d_44e0 => Some("SDIO compare command"),
            0xc04d_44e4 => Some("SDIO save this"),
            0xc04d_44e8 => Some("SDIO zero fifth-argument status"),
            0xc04d_44ec => Some("SDIO command branch"),
            0xc04d_4500 => Some("SDIO provider virtual call setup"),
            0xc04d_4508 => Some("SDIO provider virtual call"),
            0xc04d_450c => Some("SDIO provider call returned"),
            0xc04d_4540 => Some("SDIO copy fifth-argument value"),
            0xc04d_4548 => Some("SDIO store copied argument"),
            0xc04d_4554 => Some("SDIO second virtual call"),
            0xc04d_455c => Some("SDIO load failure return"),
            0xc04d_4564 => Some("SDIO write fifth-argument status"),
            _ => None,
        }) else {
            return;
        };

        self.sdio_power_trace_remaining -= 1;
        let regs = (0..16)
            .map(|i| format!("r{i}={:#x}", self.cpu.regs[i]))
            .collect::<Vec<_>>()
            .join(" ");
        let sp = self.cpu.regs[13];
        let stack_arg0 = self.bridge.read_word(sp.wrapping_add(0x14)).unwrap_or(0);
        let stack_arg1 = self.bridge.read_word(sp.wrapping_add(0x18)).unwrap_or(0);
        let stack_arg2 = self.bridge.read_word(sp.wrapping_add(0x1c)).unwrap_or(0);

        info!(
            pc = format!("{pc:#x}"),
            raw = format!("{raw:#010x}"),
            reason,
            regs,
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            stack_arg0 = format!("{stack_arg0:#x}"),
            stack_arg1 = format!("{stack_arg1:#x}"),
            stack_arg2 = format!("{stack_arg2:#x}"),
            stack_arg0_obj = self.iokit_object_summary(stack_arg0),
            stack_arg1_obj = self.iokit_object_summary(stack_arg1),
            stack_arg2_obj = self.iokit_object_summary(stack_arg2),
            r0_obj = self.iokit_object_summary(self.cpu.regs[0]),
            r1_obj = self.iokit_object_summary(self.cpu.regs[1]),
            r2_obj = self.iokit_object_summary(self.cpu.regs[2]),
            r3_obj = self.iokit_object_summary(self.cpu.regs[3]),
            r4_obj = self.iokit_object_summary(self.cpu.regs[4]),
            r5_obj = self.iokit_object_summary(self.cpu.regs[5]),
            r6_obj = self.iokit_object_summary(self.cpu.regs[6]),
            r7_obj = self.iokit_object_summary(self.cpu.regs[7]),
            r0_str = ?self.guest_cstr(self.cpu.regs[0], 192),
            r1_str = ?self.guest_cstr(self.cpu.regs[1], 192),
            r2_str = ?self.guest_cstr(self.cpu.regs[2], 192),
            r3_str = ?self.guest_cstr(self.cpu.regs[3], 192),
            r4_str = ?self.guest_cstr(self.cpu.regs[4], 192),
            r5_str = ?self.guest_cstr(self.cpu.regs[5], 192),
            r0_words = self.guest_word_window(self.cpu.regs[0], 24),
            r1_words = self.guest_word_window(self.cpu.regs[1], 16),
            r2_words = self.guest_word_window(self.cpu.regs[2], 16),
            r3_words = self.guest_word_window(self.cpu.regs[3], 16),
            r4_words = self.guest_word_window(self.cpu.regs[4], 24),
            r5_words = self.guest_word_window(self.cpu.regs[5], 24),
            r6_words = self.guest_word_window(self.cpu.regs[6], 16),
            r7_words = self.guest_word_window(self.cpu.regs[7], 16),
            stack_arg0_words = self.guest_word_window(stack_arg0, 24),
            sp_words = self.guest_word_window(sp, 32),
            stack_refs = self.stack_code_refs(sp, 160),
            trail = self.recent_pc_trail(96),
            insns = self.insn_count,
            "sdio power trace"
        );
    }

    fn trace_iokit_message_path(&mut self, pc: u32, raw: u32) {
        if self.iokit_message_trace_remaining == 0 || self.insn_count < self.trace_start_insn {
            return;
        }

        let Some(reason) = (match pc {
            0xc013_3c38 => Some("IOService::messageClient entry"),
            0xc013_3c54 => Some("IOService::messageClient service cast call"),
            0xc013_3c58 => Some("IOService::messageClient service cast returned"),
            0xc013_3c6a => Some("IOService::messageClient direct message call"),
            0xc013_3c6c => Some("IOService::messageClient direct message returned"),
            0xc013_3c7c => Some("IOService::messageClient interest cast setup"),
            0xc013_3c82 => Some("IOService::messageClient interest cast call"),
            0xc013_3c86 => Some("IOService::messageClient interest cast returned"),
            0xc013_3ccc => Some("IOService::messageClient load arg size"),
            0xc013_3cd2 => Some("IOService::messageClient store arg size"),
            0xc013_3cd4 => Some("IOService::messageClient store argument"),
            0xc013_3cdc => Some("IOService::messageClient interest callback call"),
            0xc013_3cde => Some("IOService::messageClient interest callback returned"),
            0xc013_3e28 => Some("messageClients callback entry"),
            0xc013_3e4a => Some("messageClients callback store arg size"),
            0xc013_3e50 => Some("messageClients callback call messageClient"),
            0xc013_3e52 => Some("messageClients callback returned"),
            0xc013_3e60 => Some("IOService::messageClients entry"),
            0xc013_3e72 => Some("IOService::messageClients context initialized"),
            0xc013_3e82 => Some("IOService::messageClients applyToInterested call"),
            0xc013_3e84 => Some("IOService::messageClients applyToInterested returned"),
            _ => None,
        }) else {
            return;
        };

        self.iokit_message_trace_remaining -= 1;
        let regs = (0..16)
            .map(|i| format!("r{i}={:#x}", self.cpu.regs[i]))
            .collect::<Vec<_>>()
            .join(" ");
        let sp = self.cpu.regs[13];
        let context = match pc {
            0xc013_3e28..=0xc013_3e52 => self.cpu.regs[1],
            0xc013_3e60..=0xc013_3e84 => sp,
            _ => 0,
        };
        let context0 = self.bridge.read_word(context).unwrap_or(0);
        let context1 = self.bridge.read_word(context.wrapping_add(4)).unwrap_or(0);
        let context2 = self.bridge.read_word(context.wrapping_add(8)).unwrap_or(0);
        let context3 = self.bridge.read_word(context.wrapping_add(12)).unwrap_or(0);
        let context4 = self.bridge.read_word(context.wrapping_add(16)).unwrap_or(0);
        let stack_arg0 = self.bridge.read_word(sp).unwrap_or(0);
        let stack_arg1 = self.bridge.read_word(sp.wrapping_add(4)).unwrap_or(0);
        let message_client_arg_size = self.bridge.read_word(sp.wrapping_add(0x34)).unwrap_or(0);

        info!(
            pc = format!("{pc:#x}"),
            raw = format!("{raw:#010x}"),
            reason,
            regs,
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            context = format!("{context:#x}"),
            context0 = format!("{context0:#x}"),
            context1 = format!("{context1:#x}"),
            context2 = format!("{context2:#x}"),
            context3 = format!("{context3:#x}"),
            context4 = format!("{context4:#x}"),
            context0_obj = self.iokit_object_summary(context0),
            context1_obj = self.iokit_object_summary(context1),
            context2_obj = self.iokit_object_summary(context2),
            context3_obj = self.iokit_object_summary(context3),
            context4_obj = self.iokit_object_summary(context4),
            stack_arg0 = format!("{stack_arg0:#x}"),
            stack_arg1 = format!("{stack_arg1:#x}"),
            stack_arg0_obj = self.iokit_object_summary(stack_arg0),
            stack_arg1_obj = self.iokit_object_summary(stack_arg1),
            message_client_arg_size = format!("{message_client_arg_size:#x}"),
            r0_obj = self.iokit_object_summary(self.cpu.regs[0]),
            r1_obj = self.iokit_object_summary(self.cpu.regs[1]),
            r2_obj = self.iokit_object_summary(self.cpu.regs[2]),
            r3_obj = self.iokit_object_summary(self.cpu.regs[3]),
            r4_obj = self.iokit_object_summary(self.cpu.regs[4]),
            r5_obj = self.iokit_object_summary(self.cpu.regs[5]),
            r6_obj = self.iokit_object_summary(self.cpu.regs[6]),
            r8_obj = self.iokit_object_summary(self.cpu.regs[8]),
            r10_obj = self.iokit_object_summary(self.cpu.regs[10]),
            r11_obj = self.iokit_object_summary(self.cpu.regs[11]),
            r0_words = self.guest_word_window(self.cpu.regs[0], 16),
            r1_words = self.guest_word_window(self.cpu.regs[1], 16),
            r2_words = self.guest_word_window(self.cpu.regs[2], 16),
            r3_words = self.guest_word_window(self.cpu.regs[3], 16),
            r4_words = self.guest_word_window(self.cpu.regs[4], 16),
            r5_words = self.guest_word_window(self.cpu.regs[5], 16),
            r10_words = self.guest_word_window(self.cpu.regs[10], 16),
            context_words = self.guest_word_window(context, 16),
            sp_words = self.guest_word_window(sp, 40),
            stack_refs = self.stack_code_refs(sp, 192),
            trail = self.recent_pc_trail(96),
            insns = self.insn_count,
            "iokit message trace"
        );
    }

    fn trace_pmqueue(&mut self, pc: u32, raw: u32) {
        if self.pmqueue_trace_remaining == 0 || self.insn_count < self.trace_start_insn {
            return;
        }

        let Some(reason) = (match pc {
            0xc013_d618 => Some("IOPMPowerStateQueue::featureChangeOccurred entry"),
            0xc013_d624 => Some("featureChangeOccurred before IOMalloc"),
            0xc013_d628 => Some("featureChangeOccurred after IOMalloc"),
            0xc013_d62c => Some("featureChangeOccurred allocated item"),
            0xc013_d630 => Some("featureChangeOccurred store item kind"),
            0xc013_d632 => Some("featureChangeOccurred store item message"),
            0xc013_d634 => Some("featureChangeOccurred store item service"),
            0xc013_d636 => Some("featureChangeOccurred item populated"),
            0xc013_d63a => Some("featureChangeOccurred enqueue item"),
            0xc013_d640 => Some("featureChangeOccurred signal work"),
            0xc013_d6d0 => Some("IOPMPowerStateQueue::unIdleOccurred entry"),
            0xc013_d6e4 => Some("unIdleOccurred after IOMalloc"),
            0xc013_d6ea => Some("unIdleOccurred store item kind"),
            0xc013_d6ee => Some("unIdleOccurred store item service"),
            0xc013_d6f0 => Some("unIdleOccurred store item arg"),
            0xc013_d700 => Some("unIdleOccurred enqueue item"),
            0xc013_d71c => Some("IOPMPowerStateQueue::checkForWork entry"),
            0xc013_d734 => Some("checkForWork load queue head"),
            0xc013_d738 => Some("checkForWork queue head loaded"),
            0xc013_d752 => Some("checkForWork selected item"),
            0xc013_d754 => Some("checkForWork item loaded"),
            0xc013_d760 => Some("checkForWork load item kind"),
            0xc013_d762 => Some("checkForWork load item message"),
            0xc013_d76a => Some("checkForWork load item service"),
            0xc013_d770 => Some("checkForWork branch on kind zero"),
            0xc013_d774 => Some("checkForWork branch on kind one"),
            0xc013_d7ae => Some("checkForWork feature-change dispatch"),
            0xc013_d7ba => Some("checkForWork feature-change message loaded"),
            0xc013_d7c0 => Some("checkForWork feature-change call"),
            _ => None,
        }) else {
            return;
        };

        let sp = self.cpu.regs[13];
        let item = match pc {
            0xc013_d628 => self.cpu.regs[0],
            0xc013_d62c..=0xc013_d640 => self.cpu.regs[1],
            0xc013_d6e4 => self.cpu.regs[0],
            0xc013_d6ea..=0xc013_d700 => self.cpu.regs[4],
            0xc013_d738 | 0xc013_d752 => self.bridge.read_word(sp.wrapping_add(8)).unwrap_or(0),
            0xc013_d754..=0xc013_d7c0 => self.cpu.regs[4],
            _ => 0,
        };
        let queue = match pc {
            0xc013_d618..=0xc013_d640 => self.cpu.regs[6],
            0xc013_d6d0..=0xc013_d700 => self.cpu.regs[5],
            0xc013_d71c => self.cpu.regs[0],
            0xc013_d734..=0xc013_d7c0 => self.cpu.regs[8],
            _ => 0,
        };
        let queue_head = if pc == 0xc013_d734 {
            self.bridge.read_word(self.cpu.regs[4]).unwrap_or(0)
        } else {
            self.bridge.read_word(queue.wrapping_add(0x24)).unwrap_or(0)
        };
        if matches!(pc, 0xc013_d71c..=0xc013_d7c0)
            && item == 0
            && queue_head == 0
            && std::env::var_os("RAX_S5L_PMQUEUE_TRACE_EMPTY").is_none()
        {
            return;
        }

        self.pmqueue_trace_remaining -= 1;

        let regs = (0..16)
            .map(|i| format!("r{i}={:#x}", self.cpu.regs[i]))
            .collect::<Vec<_>>()
            .join(" ");
        let item_next = self.bridge.read_word(item).unwrap_or(0);
        let item_kind = self.bridge.read_halfword(item.wrapping_add(4)).unwrap_or(0);
        let item_message = self.bridge.read_word(item.wrapping_add(8)).unwrap_or(0);
        let item_service = self.bridge.read_word(item.wrapping_add(12)).unwrap_or(0);
        let queue_lock = self.bridge.read_word(queue.wrapping_add(0x28)).unwrap_or(0);

        info!(
            pc = format!("{pc:#x}"),
            raw = format!("{raw:#010x}"),
            reason,
            regs,
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            item = format!("{item:#x}"),
            item_next = format!("{item_next:#x}"),
            item_kind = format!("{item_kind:#x}"),
            item_message = format!("{item_message:#x}"),
            item_service = format!("{item_service:#x}"),
            queue = format!("{queue:#x}"),
            queue_head = format!("{queue_head:#x}"),
            queue_lock = format!("{queue_lock:#x}"),
            item_service_obj = self.iokit_object_summary(item_service),
            r0_obj = self.iokit_object_summary(self.cpu.regs[0]),
            r1_obj = self.iokit_object_summary(self.cpu.regs[1]),
            r2_obj = self.iokit_object_summary(self.cpu.regs[2]),
            r3_obj = self.iokit_object_summary(self.cpu.regs[3]),
            r4_obj = self.iokit_object_summary(self.cpu.regs[4]),
            r5_obj = self.iokit_object_summary(self.cpu.regs[5]),
            r6_obj = self.iokit_object_summary(self.cpu.regs[6]),
            r8_obj = self.iokit_object_summary(self.cpu.regs[8]),
            r10_obj = self.iokit_object_summary(self.cpu.regs[10]),
            item_words = self.guest_word_window(item, 8),
            queue_words = self.guest_word_window(queue, 16),
            r0_words = self.guest_word_window(self.cpu.regs[0], 8),
            r1_words = self.guest_word_window(self.cpu.regs[1], 8),
            r2_words = self.guest_word_window(self.cpu.regs[2], 8),
            r3_words = self.guest_word_window(self.cpu.regs[3], 8),
            r4_words = self.guest_word_window(self.cpu.regs[4], 8),
            r5_words = self.guest_word_window(self.cpu.regs[5], 8),
            r6_words = self.guest_word_window(self.cpu.regs[6], 8),
            r8_words = self.guest_word_window(self.cpu.regs[8], 8),
            r10_words = self.guest_word_window(self.cpu.regs[10], 8),
            sp_words = self.guest_word_window(sp, 32),
            stack_refs = self.stack_code_refs(sp, 160),
            trail = self.recent_pc_trail(96),
            insns = self.insn_count,
            "iopm queue trace"
        );
    }

    fn trace_apple_arm_function(&mut self, pc: u32, raw: u32) {
        if self.apple_arm_function_trace_remaining == 0 || self.insn_count < self.trace_start_insn {
            return;
        }

        let Some(reason) = (match pc {
            0xc015_7f04 => Some("AppleARMFunction::withProvider(char*) entry"),
            0xc015_7f0c => Some("AppleARMFunction::withProvider(char*) make symbol"),
            0xc015_7f18 => Some("AppleARMFunction::withProvider(char*) symbol overload returned"),
            0xc015_7f1c => Some("AppleARMFunction::withProvider(char*) release symbol"),
            0xc015_7e1c => Some("AppleARMFunction::withProvider(symbol) entry"),
            0xc015_7e40 => Some("AppleARMFunction provider getProperty call"),
            0xc015_7e46 => Some("AppleARMFunction provider getProperty returned"),
            0xc015_7e4c => Some("AppleARMFunction OSData safeMetaCast"),
            0xc015_7e54 => Some("AppleARMFunction OSData length call"),
            0xc015_7e5a => Some("AppleARMFunction OSData length returned"),
            0xc015_7e60 => Some("AppleARMFunction parent symbol"),
            0xc015_7e6c => Some("AppleARMFunction empty data"),
            0xc015_7e78 => Some("AppleARMFunction propertyMatching call"),
            0xc015_7e7c => Some("AppleARMFunction waitForService call"),
            0xc015_7e82 => Some("AppleARMFunction waitForService returned"),
            0xc015_7e84 => Some("AppleARMFunction function object load"),
            KERNEL_IO_SERVICE_WAIT_FOR_SERVICE => Some("IOService::waitForService entry"),
            KERNEL_IO_SERVICE_WAIT_FOR_SERVICE_AFTER_SEM => {
                Some("IOService::waitForService after semaphore")
            }
            _ => None,
        }) else {
            return;
        };

        self.apple_arm_function_trace_remaining -= 1;
        let regs = (0..16)
            .map(|i| format!("r{i}={:#x}", self.cpu.regs[i]))
            .collect::<Vec<_>>()
            .join(" ");
        let sp = self.cpu.regs[13];

        info!(
            pc = format!("{pc:#x}"),
            raw = format!("{raw:#010x}"),
            reason,
            regs,
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            r0_str = ?self.guest_cstr(self.cpu.regs[0], 128),
            r1_str = ?self.guest_cstr(self.cpu.regs[1], 128),
            r2_str = ?self.guest_cstr(self.cpu.regs[2], 128),
            r5_str = ?self.guest_cstr(self.cpu.regs[5], 128),
            r10_str = ?self.guest_cstr(self.cpu.regs[10], 128),
            r0_words = self.guest_word_window(self.cpu.regs[0], 12),
            r1_words = self.guest_word_window(self.cpu.regs[1], 12),
            r2_words = self.guest_word_window(self.cpu.regs[2], 12),
            r3_words = self.guest_word_window(self.cpu.regs[3], 12),
            r4_words = self.guest_word_window(self.cpu.regs[4], 16),
            r5_words = self.guest_word_window(self.cpu.regs[5], 16),
            r6_words = self.guest_word_window(self.cpu.regs[6], 16),
            r8_words = self.guest_word_window(self.cpu.regs[8], 16),
            r9_words = self.guest_word_window(self.cpu.regs[9], 16),
            r10_words = self.guest_word_window(self.cpu.regs[10], 16),
            r11_words = self.guest_word_window(self.cpu.regs[11], 16),
            sp_words = self.guest_word_window(sp, 24),
            stack_refs = self.stack_code_refs(sp, 96),
            trail = self.recent_pc_trail(48),
            insns = self.insn_count,
            "apple arm function trace"
        );
    }

    fn trace_ioreg_free(&mut self, pc: u32, raw: u32) {
        if self.ioreg_free_trace_remaining == 0 || self.insn_count < self.trace_start_insn {
            return;
        }

        let Some(reason) = (match pc {
            0xc012_2c48 => Some("OSObject::taggedRelease free object"),
            0xc012_2c53 => Some("OSObject::taggedRelease free returned"),
            0xc013_07d4 => Some("IORegistryEntry::free entry"),
            0xc013_07f8 => Some("IORegistryEntry::free check registered"),
            0xc013_0814 => Some("IORegistryEntry::free parent check returned"),
            0xc013_083e => Some("IORegistryEntry::free IOPanic call"),
            0xc013_0840 => Some("IORegistryEntry::free IOPanic"),
            KERNEL_IOPANIC => Some("_IOPanic entry"),
            _ => None,
        }) else {
            return;
        };

        self.ioreg_free_trace_remaining -= 1;

        let sp = self.cpu.regs[13];
        let tagged_release_obj = self.bridge.read_word(sp).unwrap_or(0);
        let free_obj = match pc {
            0xc012_2c48 | 0xc012_2c53 => tagged_release_obj,
            0xc013_07d4 => self.cpu.regs[0],
            0xc013_07f8 | 0xc013_0814 | 0xc013_083e | 0xc013_0840 => self.cpu.regs[4],
            _ => 0,
        };
        let regs = (0..16)
            .map(|i| format!("r{i}={:#x}", self.cpu.regs[i]))
            .collect::<Vec<_>>()
            .join(" ");

        info!(
            pc = format!("{pc:#x}"),
            raw = format!("{raw:#010x}"),
            reason,
            regs,
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            free_obj = self.iokit_object_summary(free_obj),
            tagged_release_obj = self.iokit_object_summary(tagged_release_obj),
            r0_obj = self.iokit_object_summary(self.cpu.regs[0]),
            r1_obj = self.iokit_object_summary(self.cpu.regs[1]),
            r2_obj = self.iokit_object_summary(self.cpu.regs[2]),
            r3_obj = self.iokit_object_summary(self.cpu.regs[3]),
            r4_obj = self.iokit_object_summary(self.cpu.regs[4]),
            r5_obj = self.iokit_object_summary(self.cpu.regs[5]),
            r0_str = ?self.guest_cstr(self.cpu.regs[0], 192),
            r1_str = ?self.guest_cstr(self.cpu.regs[1], 192),
            r2_str = ?self.guest_cstr(self.cpu.regs[2], 192),
            r3_str = ?self.guest_cstr(self.cpu.regs[3], 192),
            r4_str = ?self.guest_cstr(self.cpu.regs[4], 192),
            r5_str = ?self.guest_cstr(self.cpu.regs[5], 192),
            r4_words = self.guest_word_window(self.cpu.regs[4], 24),
            r5_words = self.guest_word_window(self.cpu.regs[5], 24),
            sp_words = self.guest_word_window(sp, 32),
            stack_refs = self.stack_code_refs(sp, 128),
            trail = self.recent_pc_trail(64),
            insns = self.insn_count,
            "iokit final free trace"
        );
    }

    fn trace_iokit_object_watch(&mut self, pc: u32, raw: u32) {
        if self.iokit_watch_trace_remaining == 0 || self.insn_count < self.trace_start_insn {
            return;
        }
        let Some(watch) = self.iokit_watch_object else {
            return;
        };

        let Some(reason) = (match pc {
            0xc005_c630 => Some("_hw_compare_and_store entry"),
            0xc005_c634 => Some("_hw_compare_and_store ldrex"),
            0xc005_c63a => Some("_hw_compare_and_store compare"),
            0xc005_c63e => Some("_hw_compare_and_store strex"),
            0xc005_c642 => Some("_hw_compare_and_store result"),
            0xc012_2b5e => Some("OSObject::taggedRetain entry"),
            0xc012_2b96 => Some("OSObject::taggedRetain compare/store"),
            0xc012_2b9e => Some("OSObject::taggedRetain return"),
            0xc012_2bb8 => Some("OSObject::taggedRelease entry"),
            0xc012_2bc6 => Some("OSObject::taggedRelease(count) entry"),
            0xc012_2bf0 => Some("OSObject::taggedRelease loaded count"),
            0xc012_2c1c => Some("OSObject::taggedRelease compare/store"),
            0xc012_2c24 => Some("OSObject::taggedRelease retry"),
            0xc012_2c48 => Some("OSObject::taggedRelease free object"),
            0xc012_2c53 => Some("OSObject::taggedRelease free returned"),
            0xc012_2c68 => Some("OSObject::release entry"),
            0xc012_2c76 => Some("OSObject::retain entry"),
            0xc012_5c66 => Some("OSOrderedSet::flushCollection item load"),
            0xc012_5c70 => Some("OSOrderedSet::flushCollection release item"),
            0xc012_5c76 => Some("OSOrderedSet::flushCollection item released"),
            0xc012_5ce8 => Some("OSOrderedSet::setObject retain item"),
            0xc013_07d4 => Some("IORegistryEntry::free entry"),
            0xc013_07f8 => Some("IORegistryEntry::free check registered"),
            0xc013_0814 => Some("IORegistryEntry::free parent check returned"),
            0xc013_083e => Some("IORegistryEntry::free IOPanic call"),
            0xc013_0840 => Some("IORegistryEntry::free IOPanic"),
            0xc013_20ba => Some("IORegistryIterator::reset store visited set"),
            0xc013_20dc => Some("IORegistryIterator::free reset returned"),
            0xc013_2116 => Some("IORegistryIterator::getNextObjectFlat release current"),
            0xc013_2136 => Some("IORegistryIterator::getNextObjectFlat retain next"),
            0xc013_213a => Some("IORegistryIterator::getNextObjectFlat store current"),
            0xc013_4b7a => Some("IOService::getExistingServices got next service"),
            0xc013_4ba0 => Some("IOService::getExistingServices passiveMatch returned"),
            0xc013_4bd6 => Some("IOService::getExistingServices release iterator"),
            0xc013_4bde => Some("IOService::getExistingServices iterator released"),
            KERNEL_IOPANIC => Some("_IOPanic entry"),
            _ => None,
        }) else {
            return;
        };

        let retain_word = watch.wrapping_add(4);
        let sp = self.cpu.regs[13];
        let tagged_release_obj = self.bridge.read_word(sp).unwrap_or(0);
        let mut hits = Vec::new();
        let mut operand_hit = false;

        let mut push_hit = |hit: &'static str| {
            operand_hit = true;
            hits.push(hit.to_string());
        };

        if matches!(
            pc,
            0xc005_c630
                | 0xc005_c634
                | 0xc005_c63a
                | 0xc005_c63e
                | 0xc005_c642
                | 0xc012_2b96
                | 0xc012_2b9e
                | 0xc012_2bf0
                | 0xc012_2c1c
                | 0xc012_2c24
        ) && self.cpu.regs[2] == retain_word
        {
            push_hit("retain_word_operand");
        }
        if matches!(pc, 0xc012_2b96 | 0xc012_2b9e) && self.cpu.regs[5] == retain_word {
            push_hit("retain_word_saved");
        }
        if matches!(
            pc,
            0xc012_2b5e | 0xc012_2bb8 | 0xc012_2bc6 | 0xc012_2c68 | 0xc012_2c76
        ) && self.cpu.regs[0] == watch
        {
            push_hit("object_operand");
        }
        if matches!(pc, 0xc012_2c48 | 0xc012_2c53) && tagged_release_obj == watch {
            push_hit("free_stack_object");
        }

        if matches!(pc, 0xc012_5c66 | 0xc012_5c70 | 0xc012_5c76) {
            if let Some(item) = self.collection_item(self.cpu.regs[4], self.cpu.regs[5]) {
                if item == watch {
                    push_hit("ordered_set_current_item");
                }
            }
        }
        if matches!(pc, 0xc012_5c70 | 0xc012_5c76) && self.cpu.regs[0] == watch {
            push_hit("ordered_set_release_operand");
        }
        if pc == 0xc012_5ce8
            && (self.cpu.regs[0] == watch || self.cpu.regs[1] == watch || self.cpu.regs[2] == watch)
        {
            push_hit("ordered_set_set_object_operand");
        }
        if matches!(pc, 0xc013_07d4) && self.cpu.regs[0] == watch {
            push_hit("ioreg_free_entry_object");
        }
        if matches!(pc, 0xc013_07f8 | 0xc013_0814 | 0xc013_083e | 0xc013_0840)
            && self.cpu.regs[4] == watch
        {
            push_hit("ioreg_free_this");
        }
        if matches!(pc, 0xc013_2116 | 0xc013_2136 | 0xc013_213a)
            && (self.cpu.regs[0] == watch || self.cpu.regs[4] == watch)
        {
            push_hit("registry_iterator_object");
        }
        if matches!(pc, 0xc013_4b7a | 0xc013_4ba0) && self.cpu.regs[0] == watch {
            push_hit("get_existing_services_candidate");
        }
        if matches!(pc, 0xc013_4bd6 | 0xc013_4bde)
            && self.bridge.read_word(sp).is_ok_and(|value| value == watch)
        {
            push_hit("get_existing_services_stack_result");
        }
        if pc == KERNEL_IOPANIC && (self.cpu.regs[0] == watch || self.cpu.regs[4] == watch) {
            push_hit("panic_object");
        }

        if !operand_hit {
            return;
        }

        if std::env::var_os("RAX_S5L_IOKIT_OBJECT_STACK_HITS").is_some() {
            for i in 0..16 {
                let value = self.cpu.regs[i];
                if value == watch {
                    hits.push(format!("r{i}=object"));
                } else if value == retain_word {
                    hits.push(format!("r{i}=retain_word"));
                }
            }

            let stack_words = 64;
            for i in 0..stack_words {
                let addr = sp.wrapping_add(i * 4);
                if let Ok(value) = self.bridge.read_word(addr) {
                    if value == watch {
                        hits.push(format!("sp+{:#x}=object", i * 4));
                    } else if value == retain_word {
                        hits.push(format!("sp+{:#x}=retain_word", i * 4));
                    }
                }
            }
            if tagged_release_obj == watch {
                hits.push("tagged_release_stack_object".to_string());
            }

            for &(name, reg) in &[
                ("r0_collection", 0usize),
                ("r1_collection", 1),
                ("r2_collection", 2),
                ("r3_collection", 3),
                ("r4_collection", 4),
                ("r5_collection", 5),
                ("r8_collection", 8),
                ("r10_collection", 10),
                ("r11_collection", 11),
            ] {
                if self.collection_contains_object(self.cpu.regs[reg], watch) {
                    hits.push(name.to_string());
                }
            }
        }

        self.iokit_watch_trace_remaining -= 1;
        let regs = (0..16)
            .map(|i| format!("r{i}={:#x}", self.cpu.regs[i]))
            .collect::<Vec<_>>()
            .join(" ");

        info!(
            pc = format!("{pc:#x}"),
            raw = format!("{raw:#010x}"),
            reason,
            hits = hits.join(" "),
            watch = self.iokit_object_summary(watch),
            watch_rc = format!("{:#x}", self.bridge.read_word(retain_word).unwrap_or(0)),
            regs,
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            r0_obj = self.iokit_object_summary(self.cpu.regs[0]),
            r1_obj = self.iokit_object_summary(self.cpu.regs[1]),
            r2_obj = self.iokit_object_summary(self.cpu.regs[2]),
            r3_obj = self.iokit_object_summary(self.cpu.regs[3]),
            r4_obj = self.iokit_object_summary(self.cpu.regs[4]),
            r5_obj = self.iokit_object_summary(self.cpu.regs[5]),
            r8_obj = self.iokit_object_summary(self.cpu.regs[8]),
            r10_obj = self.iokit_object_summary(self.cpu.regs[10]),
            r11_obj = self.iokit_object_summary(self.cpu.regs[11]),
            r4_iter = self.iokit_iterator_summary(self.cpu.regs[4]),
            r4_set = self.iokit_collection_summary(self.cpu.regs[4]),
            r8_set = self.iokit_collection_summary(self.cpu.regs[8]),
            tagged_release_obj = self.iokit_object_summary(tagged_release_obj),
            sp_words = self.guest_word_window(sp, 32),
            stack_refs = self.stack_code_refs(sp, 128),
            trail = self.recent_pc_trail(64),
            insns = self.insn_count,
            "iokit object watch"
        );
    }

    fn trace_iokit_lifetime(&mut self, pc: u32, raw: u32) {
        if self.iokit_lifetime_trace_remaining == 0 || self.insn_count < self.trace_start_insn {
            return;
        }

        let Some(reason) = (match pc {
            0xc013_4b1c => Some("IOService::getExistingServices entry"),
            0xc013_4b58 => Some("IOService::getExistingServices make iterator"),
            0xc013_4b6a => Some("IOService::getExistingServices reset iterator"),
            0xc013_4b7a => Some("IOService::getExistingServices got next service"),
            0xc013_4b80 => Some("IOService::getExistingServices service state filter"),
            0xc013_4b92 => Some("IOService::getExistingServices passiveMatch call"),
            0xc013_4ba0 => Some("IOService::getExistingServices passiveMatch returned"),
            0xc013_4ba4 => Some("IOService::getExistingServices matched service"),
            0xc013_4bd6 => Some("IOService::getExistingServices release iterator"),
            0xc013_4bde => Some("IOService::getExistingServices iterator released"),
            0xc013_4bec => Some("IOService::getExistingServices return"),
            0xc013_4c5e => Some("IOService::getExistingServices direct result"),
            0xc012_3d58 => Some("OSCollectionIterator::free entry"),
            0xc012_3d64 => Some("OSCollectionIterator::free release snapshot"),
            0xc012_3d88 => Some("OSCollectionIterator::free release collection"),
            0xc012_3d92 => Some("OSCollectionIterator::free collection release call"),
            0xc012_5b76 => Some("OSOrderedSet::free entry"),
            0xc012_5b88 => Some("OSOrderedSet::free after flush"),
            0xc012_5c4c => Some("OSOrderedSet::flushCollection entry"),
            0xc012_5c66 => Some("OSOrderedSet::flushCollection item load"),
            0xc012_5c70 => Some("OSOrderedSet::flushCollection release item"),
            0xc012_5c76 => Some("OSOrderedSet::flushCollection item released"),
            0xc012_2b5e if self.iokit_retain_trace => Some("OSObject::taggedRetain entry"),
            0xc012_2b9e if self.iokit_retain_trace => Some("OSObject::taggedRetain return"),
            0xc012_2bb8 if self.iokit_retain_trace => Some("OSObject::taggedRelease entry"),
            0xc012_2bc6 if self.iokit_retain_trace => Some("OSObject::taggedRelease(count) entry"),
            0xc012_2c48 if self.iokit_retain_trace => Some("OSObject::taggedRelease free object"),
            0xc012_2c53 if self.iokit_retain_trace => Some("OSObject::taggedRelease free returned"),
            0xc012_2c68 if self.iokit_retain_trace => Some("OSObject::release entry"),
            0xc012_2c76 if self.iokit_retain_trace => Some("OSObject::retain entry"),
            0xc013_07d4 => Some("IORegistryEntry::free entry"),
            0xc013_07f8 => Some("IORegistryEntry::free check registered"),
            0xc013_0814 => Some("IORegistryEntry::free parent check returned"),
            0xc013_083e => Some("IORegistryEntry::free IOPanic call"),
            0xc013_0840 => Some("IORegistryEntry::free IOPanic"),
            KERNEL_IOPANIC => Some("_IOPanic entry"),
            _ => None,
        }) else {
            return;
        };

        self.iokit_lifetime_trace_remaining -= 1;
        let regs = (0..16)
            .map(|i| format!("r{i}={:#x}", self.cpu.regs[i]))
            .collect::<Vec<_>>()
            .join(" ");
        let sp = self.cpu.regs[13];
        let stack_service = self.bridge.read_word(sp).unwrap_or(0);

        info!(
            pc = format!("{pc:#x}"),
            raw = format!("{raw:#010x}"),
            reason,
            regs,
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            r0_obj = self.iokit_object_summary(self.cpu.regs[0]),
            r1_obj = self.iokit_object_summary(self.cpu.regs[1]),
            r2_obj = self.iokit_object_summary(self.cpu.regs[2]),
            r3_obj = self.iokit_object_summary(self.cpu.regs[3]),
            r4_obj = self.iokit_object_summary(self.cpu.regs[4]),
            r4_iter = self.iokit_iterator_summary(self.cpu.regs[4]),
            r4_set = self.iokit_collection_summary(self.cpu.regs[4]),
            r5_obj = self.iokit_object_summary(self.cpu.regs[5]),
            r8_obj = self.iokit_object_summary(self.cpu.regs[8]),
            r8_set = self.iokit_collection_summary(self.cpu.regs[8]),
            r10_obj = self.iokit_object_summary(self.cpu.regs[10]),
            r11_obj = self.iokit_object_summary(self.cpu.regs[11]),
            stack0_obj = self.iokit_object_summary(stack_service),
            sp_words = self.guest_word_window(sp, 20),
            stack_refs = self.stack_code_refs(sp, 96),
            trail = self.recent_pc_trail(48),
            insns = self.insn_count,
            "iokit lifetime trace"
        );
    }

    fn iokit_object_summary(&self, addr: u32) -> String {
        if addr == 0 {
            return String::from("<null>");
        }

        let word = |off: u32| self.bridge.read_word(addr.wrapping_add(off)).unwrap_or(0);
        format!(
            "obj={addr:#x} vt={:#x} rc={:#x} off8={:#x} plane={:#x} props={:#x} state={:#x} words=[{}]",
            word(0),
            word(4),
            word(8),
            word(0xc),
            word(0x10),
            word(0x24),
            self.guest_word_window(addr, 10)
        )
    }

    fn iokit_iterator_summary(&self, addr: u32) -> String {
        if addr == 0 {
            return String::from("<null>");
        }

        let word = |off: u32| self.bridge.read_word(addr.wrapping_add(off)).unwrap_or(0);
        let collection = word(0x8);
        let snapshot = word(0xc);
        let cursor = word(0x10);
        let valid = self.bridge.read_byte(addr.wrapping_add(0x14)).unwrap_or(0);
        format!(
            "iter={addr:#x} vt={:#x} rc={:#x} collection={collection:#x} snapshot={snapshot:#x} cursor={cursor:#x} valid={valid:#x} words=[{}] collection=[{}]",
            word(0),
            word(4),
            self.guest_word_window(addr, 8),
            self.iokit_collection_summary(collection)
        )
    }

    fn collection_item(&self, addr: u32, index: u32) -> Option<u32> {
        let items = self.bridge.read_word(addr.wrapping_add(0x10)).ok()?;
        let count = self.bridge.read_word(addr.wrapping_add(0x1c)).ok()?;
        if index >= count {
            return None;
        }
        self.bridge.read_word(items.wrapping_add(index * 4)).ok()
    }

    fn collection_contains_object(&self, addr: u32, needle: u32) -> bool {
        if addr == 0 || needle == 0 {
            return false;
        }
        let Ok(items) = self.bridge.read_word(addr.wrapping_add(0x10)) else {
            return false;
        };
        let Ok(count) = self.bridge.read_word(addr.wrapping_add(0x1c)) else {
            return false;
        };
        for i in 0..count.min(64) {
            if self
                .bridge
                .read_word(items.wrapping_add(i * 4))
                .is_ok_and(|item| item == needle)
            {
                return true;
            }
        }
        false
    }

    fn iokit_collection_summary(&self, addr: u32) -> String {
        if addr == 0 {
            return String::from("<null>");
        }

        let word = |off: u32| self.bridge.read_word(addr.wrapping_add(off)).unwrap_or(0);
        let items = word(0x10);
        let count = word(0x1c);
        let capacity = word(0x20);
        let shown = count.min(8);
        let mut entries = Vec::new();
        for i in 0..shown {
            let item = self
                .bridge
                .read_word(items.wrapping_add(i * 4))
                .unwrap_or(0);
            let retain = if item == 0 {
                0
            } else {
                self.bridge.read_word(item.wrapping_add(4)).unwrap_or(0)
            };
            entries.push(format!("{i}:{item:#x}/rc={retain:#x}"));
        }
        format!(
            "collection={addr:#x} vt={:#x} rc={:#x} items={items:#x} count={count:#x} cap={capacity:#x} entries=[{}] words=[{}]",
            word(0),
            word(4),
            entries.join(","),
            self.guest_word_window(addr, 10)
        )
    }

    fn log_undefined_instruction(
        &self,
        reason: &'static str,
        pc: u32,
        raw: u32,
        insn_len: u32,
        mnemonic: Option<Mnemonic>,
    ) {
        if std::env::var_os("RAX_S5L_UNDEF_TRACE").is_none() {
            return;
        }

        info!(
            reason,
            pc = format!("{pc:#x}"),
            raw = format!("{raw:#010x}"),
            insn_len,
            mnemonic = ?mnemonic,
            r0 = format!("{:#x}", self.cpu.regs[0]),
            r1 = format!("{:#x}", self.cpu.regs[1]),
            r2 = format!("{:#x}", self.cpu.regs[2]),
            r3 = format!("{:#x}", self.cpu.regs[3]),
            r4 = format!("{:#x}", self.cpu.regs[4]),
            r5 = format!("{:#x}", self.cpu.regs[5]),
            r6 = format!("{:#x}", self.cpu.regs[6]),
            r7 = format!("{:#x}", self.cpu.regs[7]),
            r8 = format!("{:#x}", self.cpu.regs[8]),
            r9 = format!("{:#x}", self.cpu.regs[9]),
            r10 = format!("{:#x}", self.cpu.regs[10]),
            r11 = format!("{:#x}", self.cpu.regs[11]),
            r12 = format!("{:#x}", self.cpu.regs[12]),
            sp = format!("{:#x}", self.cpu.regs[13]),
            lr = format!("{:#x}", self.cpu.regs[14]),
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            spsr_und = format!("{:#x}", self.cpu.spsr_und.to_u32()),
            sp_und = format!("{:#x}", self.cpu.regs_und[0]),
            lr_und = format!("{:#x}", self.cpu.regs_und[1]),
            trail = self.recent_pc_trail(96),
            insns = self.insn_count,
            "undefined instruction trace"
        );
    }

    fn heartbeat(&mut self) {
        if self.last_heartbeat.elapsed() >= std::time::Duration::from_secs(2) {
            let heartbeat_info = std::env::var_os("RAX_S5L_HEARTBEAT_INFO").is_some();
            let mmu = self.bridge.inner.borrow().mmu.enabled;
            if heartbeat_info {
                info!(
                    insns = self.insn_count,
                    pc = format!("{:#x}", self.cpu.regs[15]),
                    lr = format!("{:#x}", self.cpu.regs[14]),
                    cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
                    mmu,
                    "s5l8900 emulator heartbeat"
                );
            } else {
                debug!(
                    insns = self.insn_count,
                    pc = format!("{:#x}", self.cpu.regs[15]),
                    lr = format!("{:#x}", self.cpu.regs[14]),
                    cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
                    mmu,
                    "s5l8900 emulator heartbeat"
                );
            }
            // Debug aid: dump the call stack (likely iBoot return addresses
            // found on the stack) to reveal the active loop.
            if std::env::var("RAX_S5L_STACKDUMP").is_ok() {
                let sp = self.cpu.regs[13];
                let mut frames = Vec::new();
                for i in 0..256u32 {
                    if let Ok(w) = self.bridge.read_word(sp.wrapping_add(i * 4)) {
                        let a = w & !1; // strip Thumb bit
                        if (0x1800_0000..0x1802_0000).contains(&a)
                            || (0xC000_0000..0xC060_0000).contains(&a)
                        {
                            frames.push(format!("{a:#x}"));
                        }
                    }
                }
                if heartbeat_info {
                    info!(
                        sp = format!("{sp:#x}"),
                        pc = format!("{:#x}", self.cpu.regs[15]),
                        stack = frames.join(" "),
                        "stack dump"
                    );
                } else {
                    debug!(
                        sp = format!("{sp:#x}"),
                        pc = format!("{:#x}", self.cpu.regs[15]),
                        stack = frames.join(" "),
                        "stack dump"
                    );
                }
            }
            // Debug aid: dump an arbitrary physical region (RAX_S5L_MEMDUMP=
            // <hexaddr>:<hexlen>:<path>) — e.g. iBoot's log/heap area.
            if let Ok(spec) = std::env::var("RAX_S5L_MEMDUMP") {
                let parts: Vec<&str> = spec.split(':').collect();
                if parts.len() == 3 {
                    if let (Ok(addr), Ok(len)) = (
                        u64::from_str_radix(parts[0].trim_start_matches("0x"), 16),
                        usize::from_str_radix(parts[1].trim_start_matches("0x"), 16),
                    ) {
                        let mut buf = vec![0u8; len];
                        if self
                            .bridge
                            .mem
                            .read_slice(&mut buf, GuestAddress(addr))
                            .is_ok()
                        {
                            let _ = std::fs::write(parts[2], &buf);
                        }
                    }
                }
            }
            // Debug aid: dump an arbitrary virtual region using the current MMU
            // translation (RAX_S5L_VMEMDUMP=<hexaddr>:<hexlen>:<path>).
            if let Ok(specs) = std::env::var("RAX_S5L_VMEMDUMP") {
                for spec in specs.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    let parts: Vec<&str> = spec.split(':').collect();
                    if parts.len() == 3 {
                        if let (Ok(addr), Ok(len)) = (
                            u32::from_str_radix(parts[0].trim_start_matches("0x"), 16),
                            usize::from_str_radix(parts[1].trim_start_matches("0x"), 16),
                        ) {
                            let mut buf = Vec::with_capacity(len);
                            for off in 0..len as u32 {
                                buf.push(
                                    self.bridge.read_byte(addr.wrapping_add(off)).unwrap_or(0),
                                );
                            }
                            let _ = std::fs::write(parts[2], &buf);
                        }
                    }
                }
            }
            // Debug aid: dump the LCD framebuffer (physical 0x0fe00000,
            // 320x480 BGRA) to a file so the rendered boot image can be
            // inspected. Gated by RAX_S5L_FBDUMP=<path>.
            if let Ok(path) = std::env::var("RAX_S5L_FBDUMP") {
                let mut buf = vec![0u8; 320 * 480 * 4];
                if self
                    .bridge
                    .mem
                    .read_slice(&mut buf, GuestAddress(0x0fe0_0000))
                    .is_ok()
                {
                    let _ = std::fs::write(&path, &buf);
                }
            }
            self.last_heartbeat = crate::host::time::Instant::now();
        }
    }

    fn trace_iboot_printf(&self) {
        let fmt_addr = self.cpu.regs[0];
        let Some(fmt) = self.guest_iboot_cstr(fmt_addr, 384) else {
            return;
        };
        info!(
            fmt = fmt,
            fmt_addr = format!("{fmt_addr:#x}"),
            r1 = format!("{:#x}", self.cpu.regs[1]),
            r2 = format!("{:#x}", self.cpu.regs[2]),
            r3 = format!("{:#x}", self.cpu.regs[3]),
            lr = format!("{:#x}", self.cpu.regs[14]),
            insns = self.insn_count,
            "iboot printf"
        );
    }

    fn trace_vfl_scan(&self) {
        let block = self.cpu.regs[4];
        let mask_base = self.cpu.regs[5];
        let mask_addr = mask_base.wrapping_add(block / 8);
        let mask_byte = self.bridge.read_byte(mask_addr).unwrap_or(0);
        let should_probe = (mask_byte & (1 << (block & 7))) != 0;

        if block <= 48 || should_probe {
            info!(
                block,
                mask_addr = format!("{mask_addr:#x}"),
                mask_byte = format!("{mask_byte:#x}"),
                should_probe,
                insns = self.insn_count,
                "iboot vfl scan"
            );
        }
    }

    fn trace_kernel_pc(&mut self, pc: u32, raw: u32) {
        if !self.kernel_entry_logged {
            self.kernel_entry_logged = true;
            info!(
                pc = format!("{pc:#x}"),
                raw = format!("{raw:#010x}"),
                r0 = format!("{:#x}", self.cpu.regs[0]),
                r1 = format!("{:#x}", self.cpu.regs[1]),
                r2 = format!("{:#x}", self.cpu.regs[2]),
                r3 = format!("{:#x}", self.cpu.regs[3]),
                sp = format!("{:#x}", self.cpu.regs[13]),
                lr = format!("{:#x}", self.cpu.regs[14]),
                cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
                spsr_irq = format!("{:#x}", self.cpu.spsr_irq.to_u32()),
                spsr_abt = format!("{:#x}", self.cpu.spsr_abt.to_u32()),
                sp_usr = format!("{:#x}", self.cpu.regs_usr[0]),
                sp_irq = format!("{:#x}", self.cpu.regs_irq[0]),
                sp_svc = format!("{:#x}", self.cpu.regs_svc[0]),
                sp_abt = format!("{:#x}", self.cpu.regs_abt[0]),
                ttbr0 = format!("{:#x}", self.cpu.cp15.ttbr0),
                dacr = format!("{:#x}", self.cpu.cp15.dacr),
                dfsr = format!("{:#x}", self.cpu.cp15.dfsr),
                dfar = format!("{:#x}", self.cpu.cp15.dfar),
                insns = self.insn_count,
                "kernel entry"
            );
        }

        if self.kernel_trace_remaining == 0 {
            return;
        }
        self.kernel_trace_remaining -= 1;
        info!(
            pc = format!("{pc:#x}"),
            raw = format!("{raw:#010x}"),
            r0 = format!("{:#x}", self.cpu.regs[0]),
            r1 = format!("{:#x}", self.cpu.regs[1]),
            r2 = format!("{:#x}", self.cpu.regs[2]),
            r3 = format!("{:#x}", self.cpu.regs[3]),
            sp = format!("{:#x}", self.cpu.regs[13]),
            lr = format!("{:#x}", self.cpu.regs[14]),
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            spsr_abt = format!("{:#x}", self.cpu.spsr_abt.to_u32()),
            sp_usr = format!("{:#x}", self.cpu.regs_usr[0]),
            sp_irq = format!("{:#x}", self.cpu.regs_irq[0]),
            sp_svc = format!("{:#x}", self.cpu.regs_svc[0]),
            sp_abt = format!("{:#x}", self.cpu.regs_abt[0]),
            insns = self.insn_count,
            "kernel trace"
        );
    }

    fn fix_usb_wrangler_phy_registered_race(&mut self, pc: u32) -> bool {
        if pc != KERNEL_USB_WRANGLER_PHY_REGISTERED_NOTIFIER || self.no_usb_wrangler_race_fix {
            return false;
        }

        let wrangler = self.cpu.regs[5];
        let notifier = self
            .bridge
            .read_word(wrangler.wrapping_add(0x6c))
            .unwrap_or(0);
        if notifier != 0 {
            return false;
        }

        info!(
            wrangler = format!("{wrangler:#x}"),
            phy = format!("{:#x}", self.cpu.regs[4]),
            insns = self.insn_count,
            "kernel usb wrangler null notifier race"
        );
        self.cpu.regs[15] = KERNEL_USB_WRANGLER_PHY_REGISTERED_AFTER_NOTIFIER;
        true
    }

    fn force_iomedia_bsd_resource_check(&mut self, pc: u32) -> bool {
        if pc != KERNEL_IO_SERVICE_CHECK_RESOURCES || !self.force_iobsd {
            return false;
        }

        let service = self.cpu.regs[0];
        let vtable = self.bridge.read_word(service).unwrap_or(0);
        let force_all = self.force_iobsd_all
            && self.cpu.regs[14] == KERNEL_IO_SERVICE_START_CANDIDATE_AFTER_CHECK_RESOURCES;
        if !force_all && vtable != KERNEL_IOMEDIA_BSD_CLIENT_VTABLE {
            return false;
        }

        let lr = self.cpu.regs[14];
        self.cpu.regs[0] = 1;
        self.cpu.cpsr.t = lr & 1 != 0;
        self.cpu.regs[15] = lr & !1;

        info!(
            service = format!("{service:#x}"),
            vtable = format!("{vtable:#x}"),
            lr = format!("{lr:#x}"),
            force_all,
            insns = self.insn_count,
            "kernel forced IOService resource check"
        );
        true
    }

    fn trace_kernel_sleh_abort_frame(&mut self) {
        if self.kernel_exception_log_remaining == 0 {
            return;
        }
        self.kernel_exception_log_remaining -= 1;

        let frame = self.cpu.regs[0];
        let word = |off: u32| self.bridge.read_word(frame.wrapping_add(off)).unwrap_or(0);
        let saved_r0 = word(0x00);
        let saved_r1 = word(0x04);
        let saved_r2 = word(0x08);
        let saved_r3 = word(0x0c);
        let saved_pc = word(0x3c);
        let saved_cpsr = word(0x40);
        let fsr = word(0x44);
        let far = word(0x48);

        info!(
            frame = format!("{frame:#x}"),
            kind = self.cpu.regs[1],
            saved_r0 = format!("{saved_r0:#x}"),
            saved_r1 = format!("{saved_r1:#x}"),
            saved_r2 = format!("{saved_r2:#x}"),
            saved_r3 = format!("{saved_r3:#x}"),
            saved_sp = format!("{:#x}", word(0x34)),
            saved_lr = format!("{:#x}", word(0x38)),
            saved_pc = format!("{saved_pc:#x}"),
            saved_pc_raw = format!("{:#010x}", self.bridge.read_word(saved_pc).unwrap_or(0)),
            saved_cpsr = format!("{saved_cpsr:#x}"),
            fsr = format!("{fsr:#x}"),
            far = format!("{far:#x}"),
            sp = format!("{:#x}", self.cpu.regs[13]),
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            trail = self.recent_pc_trail(24),
            insns = self.insn_count,
            "kernel sleh abort frame"
        );

        self.trace_kernel_abort_dump(frame, saved_pc, saved_cpsr);
    }

    fn trace_kernel_abort_dump(&self, frame: u32, saved_pc: u32, saved_cpsr: u32) {
        if std::env::var("RAX_S5L_ABORT_DUMP").is_err() {
            return;
        }

        let word = |off: u32| self.bridge.read_word(frame.wrapping_add(off)).unwrap_or(0);
        let saved_regs = (0..=12)
            .map(|i| format!("r{i}={:#x}", word(i * 4)))
            .collect::<Vec<_>>()
            .join(" ");
        let saved_sp = word(0x34);
        let saved_lr = word(0x38);
        let pc_base = saved_pc.wrapping_sub(0x20);
        let thumb = saved_cpsr & (1 << 5) != 0;

        info!(
            frame = format!("{frame:#x}"),
            saved_regs,
            saved_sp = format!("{saved_sp:#x}"),
            saved_lr = format!("{saved_lr:#x}"),
            saved_pc = format!("{saved_pc:#x}"),
            mode = if thumb { "thumb" } else { "arm" },
            pc_words = self.guest_word_window(pc_base, 20),
            pc_halfwords = self.guest_halfword_window(saved_pc.wrapping_sub(0x10), 24),
            r0_words = self.guest_word_window(word(0x00), 4),
            r1_words = self.guest_word_window(word(0x04), 4),
            r2_words = self.guest_word_window(word(0x08), 8),
            r3_words = self.guest_word_window(word(0x0c), 8),
            r4_words = self.guest_word_window(word(0x10), 12),
            r5_words = self.guest_word_window(word(0x14), 32),
            r6_words = self.guest_word_window(word(0x18), 8),
            r7_words = self.guest_word_window(word(0x1c), 8),
            r8_words = self.guest_word_window(word(0x20), 8),
            sp_words = self.guest_word_window(saved_sp, 12),
            lr_words = self.guest_word_window(saved_lr.wrapping_sub(0x20), 12),
            r9_words = self.guest_word_window(word(0x24), 8),
            "kernel abort dump"
        );

        if let Ok(path) = std::env::var("RAX_S5L_ABORT_DUMP_FILE") {
            let start = saved_pc & !0xfff;
            let mut buf = Vec::with_capacity(0x1000);
            for off in 0..0x1000u32 {
                buf.push(self.bridge.read_byte(start.wrapping_add(off)).unwrap_or(0));
            }
            if std::fs::write(&path, &buf).is_ok() {
                info!(
                    path,
                    start = format!("{start:#x}"),
                    len = buf.len(),
                    "dumped abort page"
                );
            }
        }
    }

    fn trace_admfmc_perform_io(&mut self, pc: u32) {
        if pc != KERNEL_ADMFMC_DISPATCH && pc != KERNEL_ADMFMC_PERFORM_IO
            || self.admfmc_trace_remaining == 0
        {
            return;
        }
        if !self.bridge.inner.borrow().kernel_started {
            return;
        }
        self.admfmc_trace_remaining -= 1;

        if pc == KERNEL_ADMFMC_DISPATCH {
            let fmc = self.cpu.regs[0];
            let gate = self.cpu.regs[1];
            let req = self.cpu.regs[2];
            let req_word = |off: u32| self.bridge.read_word(req.wrapping_add(off)).unwrap_or(0);
            let op = req_word(0x00);
            let flags = req_word(0x04);
            let span = req_word(0x08);
            let base = req_word(0x0c);
            let pages = req_word(0x10);
            let data = req_word(0x14);
            let data_offset = req_word(0x18);
            let banks = req_word(0x1c);
            let aux0 = req_word(0x20);
            let aux1 = req_word(0x24);
            let sp = self.cpu.regs[13];

            info!(
                pc = format!("{pc:#x}"),
                fmc = format!("{fmc:#x}"),
                gate = format!("{gate:#x}"),
                req = format!("{req:#x}"),
                op = format!("{op:#x}"),
                flags = format!("{flags:#x}"),
                span = format!("{span:#x}"),
                base = format!("{base:#x}"),
                pages = format!("{pages:#x}"),
                data = format!("{data:#x}"),
                data_offset = format!("{data_offset:#x}"),
                banks = format!("{banks:#x}"),
                aux0 = format!("{aux0:#x}"),
                aux1 = format!("{aux1:#x}"),
                req_words = self.guest_word_window(req, 12),
                page_words = self.guest_word_window(pages, 16),
                bank_halfwords = self.guest_halfword_window(banks, 16),
                bank_bytes = self.guest_byte_window(banks, 32),
                data_words = self.guest_word_window(data, 8),
                sp = format!("{sp:#x}"),
                stack_words = self.guest_word_window(sp, 64),
                stack_refs = self.stack_code_refs(sp, 256),
                r3 = format!("{:#x}", self.cpu.regs[3]),
                r4 = format!("{:#x}", self.cpu.regs[4]),
                r5 = format!("{:#x}", self.cpu.regs[5]),
                r6 = format!("{:#x}", self.cpu.regs[6]),
                r7 = format!("{:#x}", self.cpu.regs[7]),
                r8 = format!("{:#x}", self.cpu.regs[8]),
                r9 = format!("{:#x}", self.cpu.regs[9]),
                r10 = format!("{:#x}", self.cpu.regs[10]),
                r11 = format!("{:#x}", self.cpu.regs[11]),
                r12 = format!("{:#x}", self.cpu.regs[12]),
                lr = format!("{:#x}", self.cpu.regs[14]),
                trail = self.recent_pc_trail(48),
                insns = self.insn_count,
                "admfmc dispatch trace"
            );
            return;
        }

        let fmc = self.cpu.regs[0];
        let req = self.cpu.regs[1];
        let req_word = |off: u32| self.bridge.read_word(req.wrapping_add(off)).unwrap_or(0);
        let op = req_word(0x00);
        let flags = req_word(0x04);
        let span = req_word(0x08);
        let base = req_word(0x0c);
        let pages = req_word(0x10);
        let data = req_word(0x14);
        let data_offset = req_word(0x18);
        let banks = req_word(0x1c);
        let aux0 = req_word(0x20);
        let aux1 = req_word(0x24);

        info!(
            pc = format!("{pc:#x}"),
            fmc = format!("{fmc:#x}"),
            req = format!("{req:#x}"),
            op = format!("{op:#x}"),
            flags = format!("{flags:#x}"),
            span = format!("{span:#x}"),
            base = format!("{base:#x}"),
            pages = format!("{pages:#x}"),
            data = format!("{data:#x}"),
            data_offset = format!("{data_offset:#x}"),
            banks = format!("{banks:#x}"),
            aux0 = format!("{aux0:#x}"),
            aux1 = format!("{aux1:#x}"),
            req_words = self.guest_word_window(req, 12),
            page_words = self.guest_word_window(pages, 16),
            bank_halfwords = self.guest_halfword_window(banks, 16),
            bank_bytes = self.guest_byte_window(banks, 32),
            data_words = self.guest_word_window(data, 8),
            r2 = format!("{:#x}", self.cpu.regs[2]),
            r3 = format!("{:#x}", self.cpu.regs[3]),
            sp = format!("{:#x}", self.cpu.regs[13]),
            lr = format!("{:#x}", self.cpu.regs[14]),
            insns = self.insn_count,
            "admfmc perform io trace"
        );
    }

    fn trace_pc_sample(&mut self, pc: u32, raw: u32) {
        if self.pc_sample_interval == 0
            || self.pc_sample_remaining == 0
            || self.insn_count < self.pc_sample_next_insn
        {
            return;
        }

        self.pc_sample_remaining -= 1;
        self.pc_sample_next_insn = self.insn_count.saturating_add(self.pc_sample_interval);
        let regs: Vec<String> = (0..16)
            .map(|i| format!("r{i}={:#x}", self.cpu.regs[i]))
            .collect();
        info!(
            pc = format!("{pc:#x}"),
            raw = format!("{raw:#010x}"),
            regs = regs.join(" "),
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            spsr_irq = format!("{:#x}", self.cpu.spsr_irq.to_u32()),
            spsr_abt = format!("{:#x}", self.cpu.spsr_abt.to_u32()),
            sp_usr = format!("{:#x}", self.cpu.regs_usr[0]),
            sp_irq = format!("{:#x}", self.cpu.regs_irq[0]),
            sp_svc = format!("{:#x}", self.cpu.regs_svc[0]),
            trail = self.recent_pc_trail(48),
            insns = self.insn_count,
            "pc sample"
        );
    }

    fn stack_code_refs(&self, sp: u32, words: u32) -> String {
        let mut refs = Vec::new();
        for i in 0..words {
            if let Ok(w) = self.bridge.read_word(sp.wrapping_add(i * 4)) {
                let a = w & !1;
                if (0x1800_0000..0x1803_0000).contains(&a)
                    || (0xC000_0000..0xC060_0000).contains(&a)
                {
                    refs.push(format!("{a:#x}"));
                }
            }
        }
        refs.join(" ")
    }

    fn guest_word_window(&self, addr: u32, words: u32) -> String {
        if addr == 0 {
            return String::from("<null>");
        }

        (0..words)
            .map(|i| {
                let a = (addr & !3).wrapping_add(i * 4);
                match self.bridge.read_word(a) {
                    Ok(w) => format!("{a:#x}:{w:#010x}"),
                    Err(_) => format!("{a:#x}:<fault>"),
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn guest_byte_window(&self, addr: u32, bytes: u32) -> String {
        if addr == 0 {
            return String::from("<null>");
        }

        (0..bytes)
            .map(|i| {
                let a = addr.wrapping_add(i);
                match self.bridge.read_byte(a) {
                    Ok(b) => format!("{b:02x}"),
                    Err(_) => String::from("??"),
                }
            })
            .collect::<Vec<_>>()
            .join("")
    }

    fn guest_halfword_window(&self, addr: u32, halfwords: u32) -> String {
        if addr == 0 {
            return String::from("<null>");
        }

        (0..halfwords)
            .map(|i| {
                let a = (addr & !1).wrapping_add(i * 2);
                match self.bridge.read_halfword(a) {
                    Ok(w) => format!("{a:#x}:{w:#06x}"),
                    Err(_) => format!("{a:#x}:<fault>"),
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn trace_kernel_iopanic(&mut self) {
        if self.kernel_exception_log_remaining == 0 {
            return;
        }
        self.kernel_exception_log_remaining -= 1;

        info!(
            fmt = format!("{:#x}", self.cpu.regs[0]),
            fmt_str = ?self.guest_cstr(self.cpu.regs[0], 256),
            r1 = format!("{:#x}", self.cpu.regs[1]),
            r1_str = ?self.guest_cstr(self.cpu.regs[1], 256),
            r2 = format!("{:#x}", self.cpu.regs[2]),
            r2_str = ?self.guest_cstr(self.cpu.regs[2], 256),
            r3 = format!("{:#x}", self.cpu.regs[3]),
            r3_str = ?self.guest_cstr(self.cpu.regs[3], 256),
            r0_obj = self.iokit_object_summary(self.cpu.regs[0]),
            r1_obj = self.iokit_object_summary(self.cpu.regs[1]),
            r2_obj = self.iokit_object_summary(self.cpu.regs[2]),
            r3_obj = self.iokit_object_summary(self.cpu.regs[3]),
            sp = format!("{:#x}", self.cpu.regs[13]),
            lr = format!("{:#x}", self.cpu.regs[14]),
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            sp_words = self.guest_word_window(self.cpu.regs[13], 32),
            stack_refs = self.stack_code_refs(self.cpu.regs[13], 128),
            trail = self.recent_pc_trail(64),
            insns = self.insn_count,
            "kernel iopanic"
        );
    }

    fn trace_kernel_panic(&mut self) {
        if self.kernel_exception_log_remaining == 0 {
            return;
        }
        self.kernel_exception_log_remaining -= 1;

        info!(
            fmt = format!("{:#x}", self.cpu.regs[0]),
            fmt_str = ?self.guest_cstr(self.cpu.regs[0], 256),
            r1 = format!("{:#x}", self.cpu.regs[1]),
            r1_str = ?self.guest_cstr(self.cpu.regs[1], 256),
            r2 = format!("{:#x}", self.cpu.regs[2]),
            r2_str = ?self.guest_cstr(self.cpu.regs[2], 256),
            r3 = format!("{:#x}", self.cpu.regs[3]),
            r3_str = ?self.guest_cstr(self.cpu.regs[3], 256),
            sp = format!("{:#x}", self.cpu.regs[13]),
            lr = format!("{:#x}", self.cpu.regs[14]),
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            sp_words = self.guest_word_window(self.cpu.regs[13], 32),
            stack_refs = self.stack_code_refs(self.cpu.regs[13], 128),
            trail = self.recent_pc_trail(64),
            insns = self.insn_count,
            "kernel panic"
        );
    }

    fn seed_sparse_vfl_mask(&mut self) {
        if std::env::var("RAX_S5L_NO_SPARSE_VFL_MASK").is_ok() {
            return;
        }

        let bank = self.cpu.regs[8] as usize;
        if bank >= self.sparse_vfl_mask_seeded.len() || self.sparse_vfl_mask_seeded[bank] {
            return;
        }

        let blocks = {
            let mut inner = self.bridge.inner.borrow_mut();
            inner.nand.sparse_vfl_context_blocks(bank as i64)
        };
        if blocks.is_empty() {
            return;
        }

        let mask_base = self.cpu.regs[5];
        let mut changed = false;
        for block in &blocks {
            let mask_addr = mask_base.wrapping_add(*block / 8);
            let Ok(mask_byte) = self.bridge.read_byte(mask_addr) else {
                continue;
            };
            let new_mask_byte = mask_byte | (1 << (*block & 7));
            if new_mask_byte != mask_byte
                && self.bridge.write_byte(mask_addr, new_mask_byte).is_ok()
            {
                changed = true;
            }
        }

        self.sparse_vfl_mask_seeded[bank] = true;
        if changed {
            info!(
                bank,
                mask_base = format!("{mask_base:#x}"),
                blocks = ?blocks,
                "seeded sparse VFL mask"
            );
        }
    }

    fn seed_img2_security_state(&mut self) {
        if self.security_state_seeded
            || self.cpu.regs[0] != 1
            || std::env::var("RAX_S5L_NO_SECURITY_SEED").is_ok()
        {
            return;
        }

        let flags = self.phys_r32(IBOOT_SECURITY_STATE_WORD);
        if flags & IBOOT_SECURITY_IMG2_LOAD_OK == 0 {
            let new_flags = flags | IBOOT_SECURITY_IMG2_LOAD_OK;
            self.phys_w(IBOOT_SECURITY_STATE_WORD, &new_flags.to_le_bytes());
            info!(
                before = format!("{flags:#x}"),
                after = format!("{new_flags:#x}"),
                "seeded iBoot IMG2 security state"
            );
        }
        self.security_state_seeded = true;
    }

    fn trace_fsboot_pc(&self, pc: u32) {
        let Some((_, label)) = IBOOT_FSBOOT_TRACE_PCS
            .iter()
            .find(|(trace_pc, _)| *trace_pc == pc)
        else {
            return;
        };

        info!(
            pc = format!("{pc:#x}"),
            label,
            r0 = format!("{:#x}", self.cpu.regs[0]),
            r1 = format!("{:#x}", self.cpu.regs[1]),
            r2 = format!("{:#x}", self.cpu.regs[2]),
            r3 = format!("{:#x}", self.cpu.regs[3]),
            r4 = format!("{:#x}", self.cpu.regs[4]),
            r5 = format!("{:#x}", self.cpu.regs[5]),
            r8 = format!("{:#x}", self.cpu.regs[8]),
            r10 = format!("{:#x}", self.cpu.regs[10]),
            sp = format!("{:#x}", self.cpu.regs[13]),
            lr = format!("{:#x}", self.cpu.regs[14]),
            r0_str = ?self.guest_iboot_cstr(self.cpu.regs[0], 160),
            r1_str = ?self.guest_iboot_cstr(self.cpu.regs[1], 160),
            r2_str = ?self.guest_iboot_cstr(self.cpu.regs[2], 160),
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            insns = self.insn_count,
            "fsboot trace"
        );
    }

    fn guest_iboot_cstr(&self, addr: u32, max_len: usize) -> Option<String> {
        if !(IBOOT_BASE..IBOOT_IMAGE_LIMIT).contains(&addr) {
            return None;
        }

        self.guest_cstr(addr, max_len)
    }

    fn guest_cstr(&self, addr: u32, max_len: usize) -> Option<String> {
        if addr == 0 {
            return None;
        }

        let mut bytes = Vec::new();
        for off in 0..max_len as u32 {
            let b = self.bridge.read_byte(addr.wrapping_add(off)).ok()?;
            if b == 0 {
                break;
            }
            bytes.push(match b {
                b'\n' => b' ',
                b'\r' => b' ',
                0x20..=0x7e => b,
                _ => b'.',
            });
        }

        (!bytes.is_empty()).then(|| String::from_utf8_lossy(&bytes).into_owned())
    }
}

impl VCpu for S5L8900Vcpu {
    fn run(&mut self) -> Result<VcpuExit> {
        if self.shutdown {
            return Ok(VcpuExit::Shutdown);
        }
        for _ in 0..BATCH {
            match self.step() {
                StepOutcome::Progress => {}
                StepOutcome::Idle => {
                    self.heartbeat();
                    return Ok(VcpuExit::Hlt);
                }
            }
        }
        self.heartbeat();
        Ok(VcpuExit::Hlt)
    }

    fn get_state(&self) -> Result<CpuState> {
        let mut regs = Aarch32Registers::default();
        for i in 0..13 {
            regs.r[i] = self.cpu.regs[i];
        }
        regs.sp = self.cpu.regs[13];
        regs.lr = self.cpu.regs[14];
        regs.pc = self.cpu.regs[15];
        regs.cpsr = self.cpu.cpsr.to_u32();
        Ok(CpuState::Aarch32(Aarch32CpuState {
            regs,
            sregs: Aarch32SystemRegisters::default(),
        }))
    }

    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        let state = match state {
            CpuState::Aarch32(s) => s,
            _ => {
                return Err(Error::Emulator(
                    "expected aarch32 state for s5l8900 vCPU".to_string(),
                ));
            }
        };
        let cpsr = crate::isa::arm::Psr::from_u32(state.regs.cpsr);
        if let Some(mode) = ProcessorMode::from_bits(cpsr.mode) {
            self.cpu.change_mode(mode);
        }
        for i in 0..13 {
            self.cpu.regs[i] = state.regs.r[i];
        }
        self.cpu.regs[13] = state.regs.sp;
        self.cpu.regs[14] = state.regs.lr;
        self.cpu.regs[15] = state.regs.pc;
        self.cpu.cpsr = cpsr;
        Ok(())
    }

    fn complete_io_in(&mut self, _data: &[u8]) {}

    fn attach_s3c_uart(
        &mut self,
        uart: std::sync::Arc<std::sync::Mutex<crate::devices::s3c64xx::S3cUart>>,
    ) {
        // The S5L8900 UART is register-compatible with the Samsung s3c UART,
        // so it reuses the VMM's console plumbing (host stdin → guest serial).
        let _ = self.uart.set(uart);
    }

    fn id(&self) -> u32 {
        self.id
    }

    fn instruction_count(&self) -> u64 {
        self.insn_count
    }
}

#[cfg(test)]
mod dos_bounds_tests {
    use super::*;

    /// 16 KiB of guest RAM at physical 0.
    fn small_vcpu() -> (S5L8900Vcpu, Arc<GuestMemoryMmap>) {
        let mem =
            Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
        let vcpu = S5L8900Vcpu::new(0, mem.clone());
        (vcpu, mem)
    }

    fn unique_temp_path(name: &str) -> std::path::PathBuf {
        let now = crate::host::time::system_now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("rax-{name}-{}-{now}", std::process::id()))
    }

    #[test]
    fn timer_speedup_defaults_to_reference_pace() {
        assert_eq!(parse_timer_speedup(None), 1);
        assert_eq!(parse_timer_speedup(Some("")), 1);
        assert_eq!(parse_timer_speedup(Some("invalid")), 1);
        assert_eq!(parse_timer_speedup(Some("0")), 1);
    }

    #[test]
    fn timer_speedup_allows_explicit_diagnostic_override() {
        assert_eq!(parse_timer_speedup(Some("256")), 256);
    }

    #[test]
    fn deterministic_timer_is_the_default() {
        assert_eq!(parse_det_timer(None), 32);
        assert_eq!(parse_det_timer(Some("invalid")), 32);
        assert_eq!(parse_det_timer(Some("128")), 128);
        assert_eq!(parse_det_timer(Some("0")), 0);
    }

    #[test]
    fn dmadump_append_respects_cumulative_file_limit() {
        let path = unique_temp_path("s5l-dmadump-limit");
        let _ = std::fs::remove_file(&path);

        append_limited_dmadump(&path, b"hdr\n", b"abcdef", 8).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hdr\nabcd");

        append_limited_dmadump(&path, b"next\n", b"zzzz", 8).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hdr\nabcd");

        let _ = std::fs::remove_file(&path);
    }

    // issues #43 / #50: guest-controlled DMA sizes must be validated against
    // guest RAM before any `vec![0u8; len]`, so a malicious size cannot drive a
    // multi-GB host allocation.
    #[test]
    fn dma_range_in_bounds_rejects_oversized_sizes() {
        // 16 KiB of guest RAM at address zero.
        let (mem_start, mem_end) = (0, 0x4000);

        // Valid ranges within RAM are accepted (the bound must not over-reject).
        assert!(dma_range_in_bounds(mem_start, mem_end, 0, 0x1000));
        assert!(dma_range_in_bounds(mem_start, mem_end, 0x3000, 0x1000)); // exactly fills RAM
        assert!(dma_range_in_bounds(mem_start, mem_end, 0, 0)); // empty

        // Out-of-range / oversized requests are rejected (no allocation).
        assert!(!dma_range_in_bounds(mem_start, mem_end, 0x3001, 0x1000)); // one byte over
        assert!(!dma_range_in_bounds(mem_start, mem_end, 0, 0x8000_0000)); // ~2 GiB (issue #43)
        assert!(!dma_range_in_bounds(mem_start, mem_end, 0, 0xFFFF_FFF0)); // ~4 GiB (issue #50)
        assert!(!dma_range_in_bounds(mem_start, mem_end, u32::MAX, 16)); // base near top, no wrap
    }

    #[test]
    fn dma_bound_uses_s5l_ram_base_and_excludes_padding() {
        let reported = 0x0800_0000u64; // 128 MiB
        let padded_end = reported + crate::vm::memory::GUEST_MEMORY_PADDING;
        let (mem_start, mem_end) = dma_ram_bounds_from_mmap_end(padded_end);

        assert_eq!((mem_start, mem_end), (0x0800_0000, 0x1000_0000));
        // iBoot's real kernelcache buffer must fit in 128 MiB S5L DRAM. This
        // regresses the address-zero bound that incorrectly rejected 0x0b000000.
        assert!(dma_range_in_bounds(
            mem_start,
            mem_end,
            0x0b00_0800,
            3_319_392,
        ));
        assert!(!dma_range_in_bounds(mem_start, mem_end, 0, 0x1000)); // below S5L DRAM
        assert!(!dma_range_in_bounds(
            mem_start,
            mem_end,
            0x0fff_f000,
            0x2000,
        )); // one page over
        assert!(!dma_range_in_bounds(
            mem_start,
            mem_end,
            S5L_RAM_BASE as u32,
            0xFFFF_FFF0,
        )); // ~4 GiB
        assert_eq!(dma_ram_bounds_from_mmap_end(0x4000), (0, 0x4000));
    }

    // issue #50: a crafted 8900 header advertising a huge data_len must be
    // skipped (no multi-GB allocation, no decryption) rather than aborting.
    #[test]
    fn engine_8900_oversized_data_len_is_skipped() {
        let (mut vcpu, mem) = small_vcpu();
        let mut header = [0u8; S5L_8900_HEADER_LEN];
        header[..4].copy_from_slice(b"8900");
        header[7] = 0x03; // "encrypted" marker the engine requires
        header[12..16].copy_from_slice(&0x1000_0000u32.to_le_bytes()); // 256 MiB >> 16 KiB
        mem.write_slice(&header, GuestAddress(0)).unwrap();

        vcpu.decrypt_8900(0); // must return cleanly without a giant allocation

        // Nothing should have been decrypted into the (in-range) body slot.
        let mut probe = [0u8; 16];
        mem.read_slice(&mut probe, GuestAddress(S5L_8900_HEADER_LEN as u64))
            .unwrap();
        assert_eq!(
            probe, [0u8; 16],
            "an oversized 8900 request must not write a decrypted body",
        );
    }

    // issue #43: a huge AES insize must be rejected before allocation.
    #[test]
    fn aes_oversized_insize_is_skipped() {
        let (mut vcpu, _mem) = small_vcpu();
        {
            let mut inner = vcpu.bridge.inner.borrow_mut();
            inner.aes.keytype = AesKeyType::Custom; // 32-byte default key (AES-256)
            inner.aes.inaddr = 0;
            inner.aes.outaddr = 0;
            inner.aes.insize = 0x1000_0000; // 256 MiB, multiple of 16, >> 16 KiB
            inner.aes.pending_go = true;
        }
        vcpu.service_aes(); // must return cleanly without a giant allocation
        assert!(
            !vcpu.bridge.inner.borrow().aes.pending_go,
            "service_aes should consume the GO request",
        );
    }

    #[test]
    fn adm_irq_propagates_to_daisy_synchronously() {
        let (vcpu, _mem) = small_vcpu();
        let mut inner = vcpu.bridge.inner.borrow_mut();
        let adm_mask = 1 << ADM_VIC1_LINE;
        let adm_vector = 0x8000_0025;

        inner.vic0.set_priority_mode(true);
        inner.vic1.set_priority_mode(true);
        inner.vic1.write(0x100 + ADM_VIC1_LINE * 4, adm_vector);
        inner.vic1.write(0x10, adm_mask);

        // QEMU propagates qemu_irq_raise() through both PL192s before the ADM
        // control-register write returns. No sync_irqs() call may be required.
        inner.set_adm_irq(true);
        assert!(inner.adm_irq);
        assert_eq!(inner.vic1.rawintr & adm_mask, adm_mask);
        assert_eq!(inner.vic1.irq_status & adm_mask, adm_mask);
        assert!(inner.vic0.daisy_input);
        assert_eq!(inner.vic0.debug_priority_state().1, 32);
        assert_eq!(inner.vic0.address, adm_vector);
        assert!(inner.vic0.irq_asserted());

        inner.set_adm_irq(false);
        assert!(!inner.adm_irq);
        assert_eq!(inner.vic1.rawintr & adm_mask, 0);
        assert_eq!(inner.vic1.irq_status & adm_mask, 0);
        assert!(!inner.vic0.daisy_input);
        assert!(!inner.vic0.irq_asserted());
    }
}
