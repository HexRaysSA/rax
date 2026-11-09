//! Replay captured native buffers through the descriptor and real guest memory.
use super::*;
use crate::user::windows::arch::WinArch;
use crate::user::windows::fs::{FileIdentity, FileLifetime};
use crate::user::windows::hle::{Flow, Value};
use crate::user::windows::memory::{mem, prot};
use crate::user::windows::objects::FileObj;
use crate::user::windows::process::{WindowsConfig, WindowsProcess};
use serde_json::Value as Json;
use std::collections::BTreeMap;
use std::sync::Arc;

fn number(row: &Json, field: &str) -> u32 {
    u32::from_str_radix(row[field].as_str().unwrap(), 16).unwrap()
}

fn bytes(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn corpus() -> Json {
    serde_json::from_str(include_str!(
        "../../../../../../docs/specifications/windows/native-cached-signing-level/observations-v1.json"
    )).unwrap()
}

fn context(arch: WinArch, test: impl FnOnce(&mut Ctx, u64)) {
    let image: &[u8] = match arch {
        WinArch::X86 => {
            include_bytes!("../../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
        }
        WinArch::X64 => {
            include_bytes!("../../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
        }
        WinArch::Arm64 => {
            include_bytes!("../../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
        }
    };
    let mut config = WindowsConfig::new("signing-query-test.exe", Vec::new());
    config.seed = Some(1);
    config.arena_bytes = 64 << 20;
    let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut t = p.threads.remove(&tid).unwrap();
    let data =
        p.vm.allocate(None, 0x4000, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    let sp = t.cpu.sp();
    let api = crate::user::windows::dll::nt_service("NtGetCachedSigningLevel", arch).unwrap();
    let mut c = Ctx {
        p,
        t: &mut t,
        api,
        entry_pc: 0,
        entry_sp: sp,
        ret_addr: 0,
        cursor: sp,
    };
    test(&mut c, data);
}

fn arguments(c: &mut Ctx, values: &[u64; 6]) {
    for (index, &value) in values.iter().enumerate() {
        match c.arch() {
            WinArch::X86 => c
                .mem()
                .w32(c.entry_sp + 4 + index as u64 * 4, value as u32)
                .unwrap(),
            WinArch::X64 if index < 4 => c.t.cpu.set_gpr([1, 2, 8, 9][index], value),
            WinArch::X64 => c
                .mem()
                .w64(c.entry_sp + 8 + index as u64 * 8, value)
                .unwrap(),
            WinArch::Arm64 => c.t.cpu.set_gpr(index, value),
        }
    }
}

fn file(c: &mut Ctx, access: u32, null: bool, directory: bool) -> u64 {
    let path = std::env::current_exe().unwrap();
    let retained = std::fs::File::open(&path).unwrap();
    let id = c.p.objects.create(Object::File(FileObj {
        host: Some(retained),
        host_path: path.clone(),
        path: "C:\\fixture.exe".into(),
        access,
        share: 7,
        lifetime: Arc::new(FileLifetime::new(FileIdentity::Path(path))),
        null,
        append: false,
        delete_on_close: false,
        directory,
        overlapped: false,
    }));
    c.p.objects.open_access(id, false, access).unwrap().into()
}

fn captured(rows: &[Json], role: &str, request: Request) -> Completion {
    if matches!(role, "unsigned-file" | "owned-unsigned-program") {
        return Completion {
            status: STATUS_NOT_FOUND,
            flags: None,
            level: None,
            thumbprint: Vec::new(),
            size: None,
            algorithm: None,
        };
    }
    let role = match role {
        "signed-file" => "ntdll",
        "cmd-signed-file" => "cmd",
        other => other,
    };
    let mask = format!(
        "{:02x}",
        u8::from(!request.thumbprint) * 4
            + u8::from(!request.size) * 8
            + u8::from(!request.algorithm) * 16
    );
    let row = rows
        .iter()
        .find(|row| {
            row["kind"] == "nt"
                && row["role"] == role
                && row["access"] == "80000000"
                && row["null_mask"] == mask
                && row["capacity"] == "00000040"
                && row["flags_offset"] == "00"
        })
        .unwrap();
    assert!(matches!(
        number(row, "result"),
        STATUS_SUCCESS | STATUS_BUFFER_TOO_SMALL
    ));
    let arena = bytes(row["arena"].as_str().unwrap());
    let value = |start| u32::from_le_bytes(arena[start..start + 4].try_into().unwrap());
    let copies = request.thumbprint && request.size;
    let size = value(112);
    Completion {
        status: number(row, "result"),
        flags: Some(value(0)),
        level: Some(arena[16]),
        thumbprint: if copies {
            arena[32..32 + size as usize].to_vec()
        } else {
            Vec::new()
        },
        size: request.size.then_some(size),
        algorithm: (request.size
            && request.algorithm
            && (request.thumbprint || number(row, "result") == STATUS_BUFFER_TOO_SMALL))
            .then(|| value(128)),
    }
}

#[test]
fn cached_signing_level_native_corpora_all_abis() {
    let all = corpus();
    let mut total = 0;
    for arch in WinArch::ALL {
        let name = match arch {
            WinArch::X86 => "x86",
            WinArch::X64 => "x64",
            WinArch::Arm64 => "arm64",
        };
        let baseline: Vec<Json> = all["campaigns"][0]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["arch"] == name)
            .cloned()
            .collect();
        context(arch, |c, data| {
            let pages = data + 0x1000;
            let event = u64::from(c.p.objects.insert(Object::Event {
                manual: false,
                signaled: 0,
            }));
            let mut files = BTreeMap::new();
            for campaign in all["campaigns"].as_array().unwrap() {
                for row in campaign["rows"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|r| r["arch"] == name)
                {
                    let kind = row["kind"].as_str().unwrap();
                    if !matches!(
                        kind,
                        "nt" | "publication-v2"
                            | "publication-v3"
                            | "publication-v4"
                            | "publication-v5"
                            | "publication-v6"
                    ) {
                        continue;
                    }
                    c.p.vm.protect(pages + 4096, 4096, prot::READWRITE).unwrap();
                    c.mem().wr(data, &[0xa5; 192]).unwrap();
                    c.mem().wr(pages, &[0xa5; 8192]).unwrap();
                    let capacity = if row.get("capacity").is_some() {
                        number(row, "capacity")
                    } else {
                        64
                    };
                    c.mem().w32(data + 112, capacity).unwrap();
                    let role = row["role"].as_str().unwrap();
                    let access = if kind == "nt" {
                        number(row, "access")
                    } else if role == "limited-file" {
                        0x80
                    } else {
                        0x8000_0000
                    };
                    let handle = match role {
                        "null-handle" => 0,
                        "closed-file" => 0x7fff_fffc,
                        "process-pseudo-handle" => c.arch().ptr(CURRENT_PROCESS),
                        "event-handle" => event,
                        _ => *files
                            .entry((access, role == "null-device", role == "system-directory"))
                            .or_insert_with(|| {
                                file(c, access, role == "null-device", role == "system-directory")
                            }),
                    };
                    let mut outputs = [data, data + 16, data + 32, data + 112, data + 128];
                    if kind == "nt" {
                        outputs[0] += u64::from(number(row, "flags_offset"));
                    }
                    let page_case = row["shape"] == "page";
                    if row["shape"] == "alias" {
                        const ALIASES: [[u64; 5]; 9] = [
                            [0, 16, 32, 112, 128],
                            [0, 0, 32, 112, 128],
                            [112, 16, 32, 112, 128],
                            [0, 16, 32, 112, 112],
                            [32, 16, 32, 112, 128],
                            [0, 32, 32, 112, 128],
                            [0, 16, 32, 32, 128],
                            [0, 16, 32, 112, 32],
                            [112, 112, 32, 112, 112],
                        ];
                        outputs =
                            ALIASES[number(row, "ordinal") as usize].map(|offset| data + offset);
                        c.mem().w32(outputs[3], capacity).unwrap();
                    } else if page_case {
                        outputs[number(row, "slot") as usize] =
                            pages + u64::from(number(row, "position"));
                        c.mem()
                            .wr(
                                pages + 4096 - 32,
                                &bytes(row["pages_before"].as_str().unwrap()),
                            )
                            .unwrap();
                        c.p.vm
                            .protect(pages + 4096, 4096, number(row, "protection"))
                            .unwrap();
                    }
                    let mask = row.get("null_mask").map_or(0, |_| number(row, "null_mask"));
                    for (index, output) in outputs.iter_mut().enumerate() {
                        if mask & (1 << index) != 0 {
                            *output = 0;
                        }
                    }
                    arguments(
                        c,
                        &[
                            handle, outputs[0], outputs[1], outputs[2], outputs[3], outputs[4],
                        ],
                    );
                    let actual =
                        query_with(c, |_, request| Ok(captured(&baseline, role, request))).unwrap();
                    let Flow::Ret(Value::Int(actual)) = actual else {
                        panic!("unexpected signing flow");
                    };
                    assert_eq!(actual as u32, number(row, "result"), "{name} {row}");
                    let mut arena = [0u8; 192];
                    c.mem().rd(data, &mut arena).unwrap();
                    assert_eq!(
                        arena.as_slice(),
                        bytes(row["arena"].as_str().unwrap()),
                        "{name} {row}"
                    );
                    if page_case {
                        assert_eq!(
                            c.p.vm.query(pages + 4096).unwrap().protect,
                            number(row, "remaining_protection"),
                            "{name} {row}"
                        );
                        c.p.vm.protect(pages + 4096, 4096, prot::READWRITE).unwrap();
                        let mut window = [0u8; 96];
                        c.mem().rd(pages + 4096 - 32, &mut window).unwrap();
                        assert_eq!(
                            window.as_slice(),
                            bytes(row["pages_after"].as_str().unwrap()),
                            "{name} {row}"
                        );
                    }
                    total += 1;
                }
            }
        });
    }
    assert_eq!(total, all["modeled_nt_records"].as_u64().unwrap() as usize);
}

#[test]
fn cached_signing_level_denied_and_absent_handles_never_query_host() {
    for arch in WinArch::ALL {
        context(arch, |c, data| {
            let limited = file(c, 0x80, false, false);
            for (handle, expected) in [
                (limited, STATUS_ACCESS_DENIED),
                (0x7fff_fffc, STATUS_INVALID_HANDLE),
            ] {
                arguments(c, &[handle, data, data + 16, data + 32, 1, data + 128]);
                let actual = query_with(c, |_, _| panic!("unadmitted host query")).unwrap();
                let Flow::Ret(Value::Int(actual)) = actual else {
                    panic!("unexpected flow");
                };
                assert_eq!(actual as u32, expected);
            }
        });
    }
}

#[test]
fn cached_signing_level_private_failures_preserve_outputs_and_guards() {
    for arch in WinArch::ALL {
        context(arch, |c, data| {
            let handle = file(c, 1, false, false);
            for failure in [
                Error::NoMemory,
                Error::Inconsistent("test metadata mismatch"),
                Error::Unavailable("test metadata capability unavailable"),
            ] {
                c.p.vm.protect(data, 4096, prot::READWRITE).unwrap();
                c.mem().wr(data, &[0xa5; 192]).unwrap();
                c.p.vm
                    .protect(data, 4096, prot::READONLY | prot::GUARD)
                    .unwrap();
                arguments(c, &[handle, data, data + 16, data + 32, 1, data + 128]);
                let no_memory = matches!(failure, Error::NoMemory);
                let actual = query_with(c, |_, _| Err(failure));
                if no_memory {
                    let Flow::Ret(Value::Int(value)) = actual.unwrap() else {
                        panic!("unexpected flow");
                    };
                    assert_eq!(value as u32, STATUS_NO_MEMORY);
                } else {
                    assert!(actual.is_err());
                }
                assert_eq!(
                    c.p.vm.query(data).unwrap().protect,
                    prot::READONLY | prot::GUARD
                );
                c.p.vm.protect(data, 4096, prot::READWRITE).unwrap();
                let mut arena = [0u8; 192];
                c.mem().rd(data, &mut arena).unwrap();
                assert_eq!(arena, [0xa5; 192]);
            }
            let null = u64::from(c.p.objects.insert(Object::Null));
            arguments(c, &[null, data, data + 16, data + 32, 1, data + 128]);
            let Flow::Ret(Value::Int(value)) =
                query_with(c, |_, _| panic!("NUL host query")).unwrap()
            else {
                panic!("unexpected flow");
            };
            assert_eq!(value as u32, STATUS_INVALID_INFO_CLASS);
        });
    }
}

#[cfg(windows)]
#[test]
fn cached_signing_level_retained_host_matches_win32_control() {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCachedSigningLevel(
            file: *mut c_void,
            flags: *mut u32,
            level: *mut u32,
            thumb: *mut u8,
            size: *mut u32,
            algorithm: *mut u32,
        ) -> i32;
        fn GetLastError() -> u32;
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn RtlNtStatusToDosError(status: i32) -> u32;
    }
    let system = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32");
    for path in [system.join("ntdll.dll"), std::env::current_exe().unwrap()] {
        let file = std::fs::File::open(path).unwrap();
        let actual = host(
            &file,
            Request {
                thumbprint: true,
                size: true,
                algorithm: true,
            },
        )
        .unwrap();
        let (mut flags, mut level, mut size, mut algorithm) = (0u32, 0u32, 256u32, 0u32);
        let mut thumbprint = [0u8; 256];
        // SAFETY: an owned retained file and initialized private outputs use
        // the Win32 declaration's four-byte level field. The advertised hash
        // size equals the live array; the synchronous API retains no pointer,
        // callback or borrow and cannot unwind. No guest address is forwarded.
        let ok = unsafe {
            GetCachedSigningLevel(
                file.as_raw_handle(),
                &mut flags,
                &mut level,
                thumbprint.as_mut_ptr(),
                &mut size,
                &mut algorithm,
            )
        };
        if ok != 0 {
            assert_eq!(actual.status, STATUS_SUCCESS);
            assert!(level <= u8::MAX.into());
            assert_eq!(actual.flags, Some(flags));
            assert_eq!(actual.level, Some(level as u8));
            assert_eq!(actual.size, Some(size));
            assert_eq!(actual.algorithm, Some(algorithm));
            assert_eq!(actual.thumbprint, thumbprint[..size as usize]);
        } else {
            // SAFETY: GetLastError has no arguments or outputs; it reads this
            // thread's last Win32 error immediately after the failing call.
            let error = unsafe { GetLastError() };
            // SAFETY: the native status mapper takes one scalar and retains
            // no pointer, callback or Rust borrow; it cannot unwind.
            assert_eq!(
                unsafe { RtlNtStatusToDosError(actual.status as i32) },
                error
            );
            assert!(actual.flags.is_none() && actual.level.is_none());
        }
    }
}
