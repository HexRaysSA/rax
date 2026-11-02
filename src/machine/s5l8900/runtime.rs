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

mod bridge;
mod crypto;
mod diagnostics;
mod execution_support;
mod interrupts;
mod kernel_trace;
mod step;
mod storage_trace;
mod vcpu;

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
    Fault(Error),
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
}

#[cfg(test)]
#[path = "runtime/tests.rs"]
mod dos_bounds_tests;

#[cfg(test)]
#[path = "runtime/bounded_tests.rs"]
mod bounded_tests;
