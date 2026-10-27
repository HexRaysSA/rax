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

fn port_arguments(p: &Proc, t: &Thread) -> Result<[u64; 8], String> {
    let mut arguments = [0; 8];
    match p.arch {
        WinArch::Arm64 => {
            for (index, argument) in arguments.iter_mut().enumerate() {
                *argument = t.cpu.gpr(index);
            }
        }
        WinArch::X64 => {
            arguments[..4].copy_from_slice(&[
                t.cpu.gpr(10),
                t.cpu.gpr(2),
                t.cpu.gpr(8),
                t.cpu.gpr(9),
            ]);
            for (index, argument) in arguments[4..].iter_mut().enumerate() {
                *argument = read(p.space.ptr(add(t.cpu.sp(), 0x28 + index as u64 * 8)?, 8))?;
            }
        }
        WinArch::X86 => {
            for (index, argument) in arguments.iter_mut().enumerate() {
                *argument = read(p.space.ptr(add(t.cpu.sp(), 8 + index as u64 * 4)?, 4))?;
            }
        }
    }
    Ok(arguments)
}

fn preview(p: &Proc, address: u64, bytes: usize) -> Result<Value, String> {
    if address == 0 {
        return Ok(Value::Null);
    }
    add(address, bytes as u64)?;
    let bytes = read(p.space.bytes(address, bytes))?;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(json!({"address": format!("{address:#x}"), "bytes": bytes.len(), "hex": hex}))
}

fn port_name(p: &Proc, descriptor: u64) -> Result<Value, String> {
    if descriptor == 0 {
        return Ok(Value::Null);
    }
    let length = read(p.space.u16(descriptor))?;
    let maximum = read(p.space.u16(add(descriptor, 2)?))?;
    if length % 2 != 0 || length > maximum {
        return Err(format!(
            "invalid port UNICODE_STRING length={length}, maximum={maximum}"
        ));
    }
    let width = p.arch.ptr_size();
    let buffer = read(
        p.space
            .ptr(add(descriptor, if width == 4 { 4 } else { 8 })?, width),
    )?;
    let observed = usize::from(length).min(1024);
    add(buffer, observed as u64)?;
    let raw = read(p.space.bytes(buffer, observed))?;
    let units: Vec<_> = raw
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    Ok(json!({
        "descriptor": format!("{descriptor:#x}"),
        "buffer": format!("{buffer:#x}"),
        "length_bytes": length,
        "maximum_bytes": maximum,
        "observed_bytes": observed,
        "truncated": observed < usize::from(length),
        "units": units,
        "text": String::from_utf16_lossy(&units),
    }))
}

fn port_request(p: &Proc, t: &Thread) -> Result<Value, String> {
    let a = port_arguments(p, t)?;
    let client_length = if a[3] == 0 {
        Ok(None)
    } else {
        read(p.space.u32(a[3])).map(Some)
    };
    let client_bytes = if p.arch == WinArch::X86 && client_length == Ok(Some(24)) {
        24
    } else {
        48
    };
    let information_length = if a[7] == 0 {
        Ok(None)
    } else {
        read(p.space.u32(a[7])).map(Some)
    };
    let information = match &information_length {
        Ok(Some(bytes)) => Some(preview(p, a[6], (*bytes as usize).min(4096))),
        _ => None,
    };
    Ok(json!({
        "arguments": a.map(|argument| format!("{argument:#x}")),
        "port_name": port_name(p, a[1]),
        "output_handle": preview(p, a[0], p.arch.ptr_size() as usize),
        "security_qos": preview(p, a[2], 12),
        "client_view_length": client_length,
        "client_view": preview(p, a[3], client_bytes),
        "server_view": preview(p, a[4], 24),
        "maximum_message_length": preview(p, a[5], 4),
        "information_length": information_length,
        "information": information,
        "information_preview_limit_bytes": 4096,
        "information_truncated": information_length.as_ref().ok().copied().flatten().map(|bytes| bytes > 4096),
    }))
}

// Compile the diagnostic on every host; only Windows can run installed NTDLL.
#[cfg_attr(windows, test)]
#[cfg_attr(not(windows), allow(dead_code))]
fn native_entry_installed_startup_diagnostic_v2_requires_original_exit0() {
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
        let connect_port = matches!(&terminal, Some(ExitStatus::Internal(reason)) if reason.starts_with("native NTDLL service NtConnectPort (") && reason.ends_with(" is not implemented"));
        let threads: Vec<_> = p.threads.values().take(8).map(|t| json!({
            "tid": t.tid,
            "pc": format!("{:#x}", t.cpu.pc()),
            "sp": format!("{:#x}", t.cpu.sp()),
            "gpr": (0..t.cpu.gpr_count()).map(|index| format!("{:#x}", t.cpu.gpr(index))).collect::<Vec<_>>(),
            "section_request": if open_section { Some(section_request(p,t)) } else { None },
            "port_request": if connect_port { Some(port_request(p,t)) } else { None },
        })).collect();
        eprintln!(
            "NATIVE_STARTUP_DIAGNOSTIC_V2 {}",
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
