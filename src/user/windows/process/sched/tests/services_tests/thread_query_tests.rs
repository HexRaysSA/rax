//! Thread query replay uses independent Windows results, not generated statuses.
use super::{Outcome, Proc, Thread, WinArch, fixture, handle_stop, stop};
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::process::thread;

const SERVICE: u32 = 0x25;

#[path = "thread_query_tests/boundary.rs"]
mod boundary;

fn call(p: &mut Proc, t: &mut Thread, args: [u64; 5]) -> u32 {
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    match p.arch {
        WinArch::Arm64 => {
            for (index, value) in args.into_iter().enumerate() {
                t.cpu.set_gpr(index, value);
            }
        }
        WinArch::X64 => {
            for (register, value) in [
                (0, SERVICE.into()),
                (1, 0x1234_0004),
                (10, args[0]),
                (2, args[1]),
                (8, args[2]),
                (9, args[3]),
            ] {
                t.cpu.set_gpr(register, value);
            }
            p.space.w64(sp + 40, args[4]).unwrap();
        }
        WinArch::X86 => {
            for (index, value) in [0x1234_0004, 0x1234_0000]
                .into_iter()
                .chain(args)
                .enumerate()
            {
                p.space.w32(sp + index as u64 * 4, value as u32).unwrap();
            }
            t.cpu.set_gpr(0, SERVICE.into());
        }
    }
    let result = if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, SERVICE))
    };
    assert_eq!(result, Outcome::Continue, "{}/{args:?}", p.arch);
    assert_eq!(t.cpu.pc(), 0x1234_0004);
    assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
    assert!(t.frames.is_empty());
    t.cpu.set_sp(sp);
    t.cpu.gpr(0) as u32
}

fn setup(arch: WinArch) -> (super::super::super::super::WindowsProcess, Thread, u64) {
    let (mut process, current) = fixture(arch, "NtQueryInformationThread", SERVICE);
    let p = process.state_mut();
    let scratch =
        p.vm.allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    (process, current, scratch)
}

fn put(bytes: &mut [u8], at: usize, value: u64, width: usize) {
    bytes[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
}

fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn native_thread_query_replays_339_queries_from_independent_native_and_pure_wow64_captures() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-thread-query/observations-v2.json"
    ))
    .unwrap();
    let mut seen = 0;
    for arch in WinArch::ALL {
        let run = corpus["runs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|run| (run["pointer_bytes"] == 4) == (arch == WinArch::X86))
            .unwrap();
        let (mut process, mut current, scratch) = setup(arch);
        let p = process.state_mut();
        let worker = thread::create(p, 0x1234_1000, 0, 0x10000, false).unwrap();
        p.threads.get_mut(&worker).unwrap().suspend = 1;
        let worker_object = p.threads[&worker].obj;
        let worker_teb = p.threads[&worker].teb;
        let worker_handle = u64::from(p.objects.open(worker_object, false));
        // CLR's native observer has additional active threads. Preserve that
        // condition explicitly; separate tests exercise the one-thread result.
        thread::create(p, 0x1234_2000, 0, 0x10000, false).unwrap();
        let mut retired = false;
        for row in run["rows"].as_array().unwrap() {
            let label = row["case"].as_str().unwrap();
            if label == "current-handle-open" {
                assert_eq!(row["open_status"], 0xc000_0022u32);
                assert_eq!(row["handle_published"], false);
                continue; // This corpus row is NtOpenThread, not a query call.
            }
            let class = row["class"].as_u64().unwrap();
            let len = row["length"].as_u64().unwrap();
            let offset = row["output_offset"].as_u64().unwrap() as usize;
            let output = match row["output_mode"].as_u64().unwrap() {
                0 => scratch + 64 + offset as u64,
                1 => 0,
                2 => 1,
                _ => unreachable!(),
            };
            let ret_mode = row["return_mode"].as_i64().unwrap();
            let returned = match ret_mode {
                -1 => 0,
                -2 => 1,
                offset => scratch + 384 + offset as u64,
            };
            if label == "owned-exited" && !retired {
                let target = p.threads.remove(&worker).unwrap();
                thread::destroy(p, target, 0);
                retired = true;
            }
            let mut owned_alias = None;
            let handle = if label.starts_with("invalid-handle") {
                if row["handle_role"] == "null" {
                    0
                } else {
                    arch.ptr(u64::MAX)
                }
            } else if label == "current-handle-rights" {
                let access = row["desired_access"].as_u64().unwrap() as u32;
                let access = if access == 0x2000000 {
                    0x1fffff
                } else {
                    access
                };
                let handle = u64::from(p.objects.open_access(current.obj, false, access).unwrap());
                owned_alias = Some(handle);
                handle
            } else if label.starts_with("owned-") {
                worker_handle
            } else {
                arch.ptr(u64::MAX - 1)
            };
            p.space.wr(scratch, &[0xa5; 512]).unwrap();
            let status = call(p, &mut current, [handle, class, output, len, returned]);
            assert_eq!(
                u64::from(status),
                row["status"].as_u64().unwrap(),
                "{arch}/{label}/{class}/{len}"
            );
            let actual = p.space.bytes(scratch + 64, 160).unwrap();
            assert_eq!(
                actual.iter().any(|byte| *byte != 0xa5),
                row["output_changed"].as_bool().unwrap(),
                "{arch}/{label}/{class}"
            );
            let mut expected = vec![0xa5; 160];
            if row["output_changed"] == true {
                if class == 0 {
                    let width = arch.ptr_size() as usize;
                    if status == 0 {
                        let other = label.starts_with("owned-");
                        let teb = if other && retired {
                            if arch == WinArch::X86 { 0x2000 } else { 0 }
                        } else if other {
                            worker_teb
                        } else {
                            current.teb
                        };
                        for (index, value) in [
                            if retired && other { 0 } else { 259 },
                            teb,
                            u64::from(p.pid),
                            u64::from(if other { worker } else { current.tid }),
                            1,
                        ]
                        .into_iter()
                        .enumerate()
                        {
                            put(&mut expected, offset + index * width, value, width);
                        }
                        put(&mut expected, offset + 5 * width, 8, 4);
                        put(&mut expected, offset + 5 * width + 4, 0, 4);
                    } else {
                        // Failure converts undefined native scratch words;
                        // only publication extent and untouched TEB are stable.
                        assert_eq!(arch, WinArch::X86);
                        for at in [0, 8, 12, 16, 20, 24] {
                            expected[offset + at..offset + at + 4]
                                .copy_from_slice(&actual[offset + at..offset + at + 4]);
                        }
                    }
                } else if class == 9 {
                    let start = if label.starts_with("owned-") {
                        0x1234_1000
                    } else {
                        current.start
                    };
                    put(&mut expected, offset, start, arch.ptr_size() as usize);
                } else if class == 12 {
                    put(&mut expected, offset, 0, 4);
                }
            }
            assert_eq!(actual, expected, "{arch}/{label}/{class}/{len}");
            assert_eq!(
                p.space.bytes(scratch + 384, 12).unwrap(),
                hex(row["returned_hex"].as_str().unwrap()),
                "{arch}/{label}/{class}/{len}"
            );
            if let Some(handle) = owned_alias {
                p.objects.close(handle).unwrap();
            }
            seen += 1;
        }
    }
    assert_eq!(seen, 339);
}

#[test]
fn native_thread_query_retains_start_after_teardown_aliasing_and_handle_reuse() {
    for arch in WinArch::ALL {
        let (mut process, mut current, scratch) = setup(arch);
        let p = process.state_mut();
        let tid = thread::create(p, 0x1234_1000, 0, 0x10000, false).unwrap();
        let id = p.threads[&tid].obj;
        let a = u64::from(p.objects.open_access(id, false, 0x40).unwrap());
        let b = u64::from(p.objects.duplicate(a, false).unwrap());
        let target = p.threads.remove(&tid).unwrap();
        thread::destroy(p, target, 53);
        p.objects.close(a).unwrap();
        assert_eq!(
            call(p, &mut current, [b | 3, 9, scratch, arch.ptr_size(), 0]),
            0
        );
        assert_eq!(
            if arch == WinArch::X86 {
                u64::from(p.space.u32(scratch).unwrap())
            } else {
                p.space.u64(scratch).unwrap()
            },
            0x1234_1000
        );
        assert_eq!(p.objects.thread_start(id), Some(0x1234_1000));
        p.objects.close(b).unwrap();
        assert_eq!(p.objects.thread_start(id), None);
        let tid = thread::create(p, 0x1234_2000, 0, 0x10000, false).unwrap();
        let id = p.threads[&tid].obj;
        let reused = u64::from(p.objects.open_access(id, false, 0x40).unwrap());
        assert_eq!(reused, a);
        assert_eq!(
            call(p, &mut current, [reused, 9, scratch, arch.ptr_size(), 0]),
            0
        );
        assert_eq!(
            if arch == WinArch::X86 {
                u64::from(p.space.u32(scratch).unwrap())
            } else {
                p.space.u64(scratch).unwrap()
            },
            0x1234_2000
        );
    }
}

#[test]
fn native_thread_query_last_thread_ignores_handle_and_counts_suspended_guest_threads() {
    for arch in WinArch::ALL {
        let (mut process, mut current, scratch) = setup(arch);
        let p = process.state_mut();
        for handle in [0, arch.ptr(u64::MAX), arch.ptr(u64::MAX - 1), 0x12345678] {
            assert_eq!(call(p, &mut current, [handle, 12, scratch, 4, 0]), 0);
            assert_eq!(p.space.u32(scratch).unwrap(), 1);
        }
        let tid = thread::create(p, 0x1234_1000, 0, 0x10000, false).unwrap();
        p.threads.get_mut(&tid).unwrap().suspend = 1;
        assert_eq!(call(p, &mut current, [0, 12, scratch, 4, 0]), 0);
        assert_eq!(p.space.u32(scratch).unwrap(), 0);
        let target = p.threads.remove(&tid).unwrap();
        thread::destroy(p, target, 0);
        assert_eq!(call(p, &mut current, [0, 12, scratch, 4, 0]), 0);
        assert_eq!(p.space.u32(scratch).unwrap(), 1);
    }
}

#[test]
fn native_thread_query_basic_read_before_write_and_return_probes_consume_readonly_guards() {
    for arch in WinArch::ALL {
        for class in [0, 9, 12] {
            if arch == WinArch::X86 && class != 12 {
                continue; // Converted classes have separately measured stores.
            }
            for output_guard in [false, true] {
                let (mut process, mut current, scratch) = setup(arch);
                let p = process.state_mut();
                let other =
                    p.vm.allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                        .unwrap()
                        .0;
                p.space.wr(scratch, &[0xa5; 64]).unwrap();
                p.space.wr(other, &[0xa5; 64]).unwrap();
                let protected = if output_guard { scratch } else { other };
                p.vm.protect(protected, 4096, prot::READONLY | prot::GUARD)
                    .unwrap();
                let expected = if output_guard && class != 0 && arch != WinArch::X86 {
                    0xc0000005
                } else {
                    0x80000001
                };
                let size = if class == 0 {
                    48
                } else if class == 9 {
                    8
                } else {
                    4
                };
                assert_eq!(
                    call(
                        p,
                        &mut current,
                        [arch.ptr(u64::MAX - 1), class, scratch, size, other]
                    ),
                    expected,
                    "{arch}/{class}/output_guard={output_guard}"
                );
                assert_eq!(
                    p.vm.query(protected).unwrap().protect & prot::GUARD != 0,
                    output_guard && class != 0 && arch != WinArch::X86
                );
                p.vm.protect(protected, 4096, prot::READWRITE).unwrap();
                assert_eq!(p.space.bytes(scratch, 64).unwrap(), [0xa5; 64]);
                assert_eq!(p.space.bytes(other, 64).unwrap(), [0xa5; 64]);
            }
        }
    }
}
