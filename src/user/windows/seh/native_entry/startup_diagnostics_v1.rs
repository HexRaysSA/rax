//! Independent terminal-state observation; the original fixture stays frozen.

use crate::user::windows::arch::WinArch;
use crate::user::windows::memory::Mem;
use crate::user::windows::objects::Object;
use crate::user::windows::process::{
    ExitStatus, Proc, RunStatus, Thread, WindowsConfig, WindowsProcess,
};
use serde_json::{Value, json};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

fn add(address: u64, offset: u64) -> Result<u64, String> {
    address
        .checked_add(offset)
        .ok_or_else(|| "guest address overflow".into())
}

fn read<T>(value: Result<T, crate::user::windows::memory::MemFault>) -> Result<T, String> {
    value.map_err(|fault| format!("guest read fault at {:#x}", fault.addr))
}

fn section_request(p: &Proc, t: &Thread) -> Result<Value, String> {
    let arguments = match p.arch {
        WinArch::Arm64 => [t.cpu.gpr(0), t.cpu.gpr(1), t.cpu.gpr(2)],
        WinArch::X64 => [t.cpu.gpr(10), t.cpu.gpr(2), t.cpu.gpr(8)],
        // The WoW64 transition has its own return slot before entry_sp;
        // the stdcall arguments start a second slot beyond the retained SP.
        WinArch::X86 => [0, 1, 2]
            .map(|index| add(t.cpu.sp(), 8 + index * 4).and_then(|at| read(p.space.ptr(at, 4))))
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap(),
    };
    let attributes = arguments[2];
    let width = p.arch.ptr_size();
    let root_offset = if width == 4 { 4 } else { 8 };
    let size = if width == 4 { 24 } else { 48 };
    let length = read(p.space.u32(attributes))?;
    if length != size {
        return Err(format!(
            "OBJECT_ATTRIBUTES length {length}, expected {size}"
        ));
    }
    let root = read(p.space.ptr(add(attributes, root_offset)?, width))?;
    let name = read(p.space.ptr(add(attributes, root_offset + width)?, width))?;
    let flags = read(p.space.u32(add(attributes, root_offset + 2 * width)?))?;
    let name_length = read(p.space.u16(name))?;
    let name_maximum = read(p.space.u16(add(name, 2)?))?;
    if name_length % 2 != 0 || name_length > name_maximum {
        return Err(format!(
            "invalid UNICODE_STRING length={name_length}, maximum={name_maximum}"
        ));
    }
    let buffer = read(
        p.space
            .ptr(add(name, if width == 4 { 4 } else { 8 })?, width),
    )?;
    let observed_bytes = usize::from(name_length).min(1024);
    let bytes = read(p.space.bytes(buffer, observed_bytes))?;
    let units: Vec<_> = bytes
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    let root_directory = match p.objects.get(root) {
        Some(Object::Directory(directory)) => json!({
            "kind": "selected_directory",
            "units": directory.path,
            "text": String::from_utf16_lossy(&directory.path),
        }),
        Some(_) => json!({"kind": "non_directory"}),
        None => json!({"kind": if root == 0 { "absolute_namespace" } else { "unresolved_handle" }}),
    };
    Ok(json!({
        "output": format!("{:#x}", arguments[0]),
        "access": format!("{:#010x}", arguments[1] as u32),
        "attributes": format!("{attributes:#x}"),
        "attributes_length_bytes": length,
        "flags": format!("{flags:#010x}"),
        "root": format!("{root:#x}"),
        "root_directory": root_directory,
        "name_descriptor": format!("{name:#x}"),
        "name_buffer": format!("{buffer:#x}"),
        "name_length_bytes": name_length,
        "name_maximum_bytes": name_maximum,
        "observed_bytes": observed_bytes,
        "truncated": observed_bytes < usize::from(name_length),
        "name_units": units,
        "name_text": String::from_utf16_lossy(&units),
    }))
}

// Compile the diagnostic on every host; only Windows can run installed NTDLL.
#[cfg_attr(windows, test)]
#[cfg_attr(not(windows), allow(dead_code))]
fn native_entry_installed_startup_diagnostic_v1_requires_original_exit0() {
    let host = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    let arches = if host == WinArch::X86 {
        vec![host]
    } else {
        vec![host, WinArch::X86]
    };
    for arch in arches {
        let image: &[u8] = match arch {
            WinArch::X86 => include_bytes!(
                "../../../../../tests/fixtures/user/windows/native_exception_entry/bin/x86/fault.exe"
            ),
            WinArch::X64 => include_bytes!(
                "../../../../../tests/fixtures/user/windows/native_exception_entry/bin/x64/fault.exe"
            ),
            WinArch::Arm64 => include_bytes!(
                "../../../../../tests/fixtures/user/windows/native_exception_entry/bin/arm64/fault.exe"
            ),
        };
        let mut config =
            WindowsConfig::embedded("C:\\native-fault.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        config.slice_insns = 4096;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        let cancelled = AtomicBool::new(false);
        let mut terminal = None;
        let mut turns = 0;
        for _ in 0..16384 {
            assert!(
                Instant::now() < deadline,
                "{arch}: native fault diagnostic deadline"
            );
            turns += 1;
            match process.run_slice(1, &cancelled) {
                RunStatus::Complete(status) => {
                    terminal = Some(status);
                    break;
                }
                RunStatus::BudgetExhausted => {}
                status => panic!("{arch}: native fault diagnostic stopped: {status:?}"),
            }
        }
        let p = process.state();
        let open_section = matches!(&terminal, Some(ExitStatus::Internal(reason)) if reason.contains("native NTDLL service NtOpenSection:"));
        let threads: Vec<_> = p.threads.values().take(8).map(|t| json!({
            "tid": t.tid,
            "pc": format!("{:#x}", t.cpu.pc()),
            "sp": format!("{:#x}", t.cpu.sp()),
            "gpr": (0..t.cpu.gpr_count()).map(|index| format!("{:#x}", t.cpu.gpr(index))).collect::<Vec<_>>(),
            "section_request": if open_section { Some(section_request(p,t)) } else { None },
        })).collect();
        eprintln!(
            "NATIVE_STARTUP_DIAGNOSTIC_V1 {}",
            json!({
                "arch": arch.to_string(),
                "terminal": format!("{terminal:?}"),
                "turns": turns,
                "slice_insns": 4096,
                "max_turns": 16384,
                "deadline_seconds": 60,
                "thread_count": p.threads.len(),
                "observed_thread_limit": 8,
                "threads": threads,
            })
        );
        assert_eq!(
            terminal,
            Some(ExitStatus::Exited(0)),
            "{arch}: independent native fault diagnostic"
        );
        assert!(
            p.seh.veh.is_empty(),
            "native registration must remain owned by RTL"
        );
    }
}
