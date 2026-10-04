//! SList semantics on every architecture, called the way a guest calls them:
//! arguments in the convention's registers or stack slots, memory in a real
//! spawned process.

use super::*;
use crate::user::windows::hle::{Item, Value};
use crate::user::windows::process::{Proc, Thread, WindowsConfig, WindowsProcess};

const MEM_COMMIT_RESERVE: u32 = 0x3000;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;

fn spawn(arch: WinArch) -> WindowsProcess {
    let image: &[u8] = match arch {
        WinArch::X86 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
        }
        WinArch::X64 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
        }
        WinArch::Arm64 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
        }
    };
    let mut config = WindowsConfig::new("slist-test.exe", vec![]);
    config.seed = Some(1);
    config.arena_bytes = 64 << 20;
    WindowsProcess::spawn_image(config, image.to_vec()).unwrap()
}

/// One committed page with `protect`.
fn page(p: &mut Proc, protect: u32) -> u64 {
    p.vm.allocate(None, 0x1000, MEM_COMMIT_RESERVE, protect)
        .unwrap()
        .0
}

/// Calls the NTDLL export `name` with `args` placed as `arch` passes them.
fn call(p: &mut Proc, t: &mut Thread, name: &str, args: &[u64]) -> ApiResult {
    let api = NTDLL_EXPORTS
        .iter()
        .find_map(|e| match &e.item {
            Item::Func(api) if api.name == name => Some(api),
            _ => None,
        })
        .unwrap();
    let sp = t.cpu.sp();
    for (i, value) in args.iter().enumerate() {
        match p.arch {
            WinArch::X86 => p.space.w32(sp + 4 + 4 * i as u64, *value as u32).unwrap(),
            WinArch::X64 => t.cpu.set_gpr([1, 2, 8, 9][i], *value),
            WinArch::Arm64 => t.cpu.set_gpr(i, *value),
        }
    }
    let mut c = Ctx {
        p,
        t,
        api,
        entry_pc: 0x1000,
        entry_sp: sp,
        ret_addr: 0,
        cursor: sp,
    };
    (api.imp)(&mut c)
}

/// What a call did, for a failure message (`Flow` has no `Debug`).
fn describe(result: &ApiResult) -> String {
    match result {
        Ok(Flow::Ret(value)) => format!("returned {value:?}"),
        Ok(_) => "a non-return flow".into(),
        Err(error) => format!("{error:?}"),
    }
}

fn returned(result: ApiResult) -> u64 {
    match result {
        Ok(Flow::Ret(Value::Int(value))) => value,
        other => panic!("expected an integer return, got {}", describe(&other)),
    }
}

fn header_bytes(p: &Proc, header: u64) -> Vec<u8> {
    let size = if p.arch == WinArch::X86 { 8 } else { 16 };
    p.space.bytes(header, size).unwrap()
}

/// Runs `body` once per architecture with a process, its first thread, and
/// one read-write page.
fn each_arch(mut body: impl FnMut(WinArch, &mut Proc, &mut Thread, u64)) {
    for arch in WinArch::ALL {
        let mut process = spawn(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let base = page(p, PAGE_READWRITE);
        body(arch, p, &mut t, base);
    }
}

#[test]
fn push_and_pop_are_last_in_first_out() {
    each_arch(|arch, p, t, base| {
        let header = base;
        let (e1, e2) = (base + 0x100, base + 0x200);
        p.space.wr(header, &[0xAA; 16]).unwrap();
        assert!(matches!(
            call(p, t, "RtlInitializeSListHead", &[header]),
            Ok(Flow::Ret(Value::None))
        ));
        assert!(
            header_bytes(p, header).iter().all(|b| *b == 0),
            "{arch}: initialized to zero"
        );
        assert_eq!(
            returned(call(p, t, "RtlQueryDepthSList", &[header])),
            0,
            "{arch}"
        );

        assert_eq!(
            returned(call(p, t, "RtlInterlockedPushEntrySList", &[header, e1])),
            0,
            "{arch}"
        );
        assert_eq!(
            returned(call(p, t, "RtlInterlockedPushEntrySList", &[header, e2])),
            e1,
            "{arch}"
        );
        assert_eq!(
            returned(call(p, t, "RtlQueryDepthSList", &[header])),
            2,
            "{arch}"
        );
        assert_eq!(
            returned(call(p, t, "RtlFirstEntrySList", &[header])),
            e2,
            "{arch}"
        );

        assert_eq!(
            returned(call(p, t, "RtlInterlockedPopEntrySList", &[header])),
            e2,
            "{arch}"
        );
        assert_eq!(
            returned(call(p, t, "RtlInterlockedPopEntrySList", &[header])),
            e1,
            "{arch}"
        );
        assert_eq!(
            returned(call(p, t, "RtlQueryDepthSList", &[header])),
            0,
            "{arch}"
        );

        // An empty list pops nothing and writes nothing.
        let before = header_bytes(p, header);
        assert_eq!(
            returned(call(p, t, "RtlInterlockedPopEntrySList", &[header])),
            0,
            "{arch}"
        );
        assert_eq!(
            header_bytes(p, header),
            before,
            "{arch}: empty pop wrote the header"
        );
    });
}

#[test]
fn flush_returns_the_whole_chain_intact() {
    each_arch(|arch, p, t, base| {
        let header = base;
        let entries = [base + 0x100, base + 0x200, base + 0x300];
        call(p, t, "RtlInitializeSListHead", &[header]).unwrap();
        for entry in entries {
            call(p, t, "RtlInterlockedPushEntrySList", &[header, entry]).unwrap();
        }
        assert_eq!(
            returned(call(p, t, "RtlInterlockedFlushSList", &[header])),
            entries[2],
            "{arch}"
        );
        assert_eq!(
            returned(call(p, t, "RtlFirstEntrySList", &[header])),
            0,
            "{arch}"
        );
        assert_eq!(
            returned(call(p, t, "RtlQueryDepthSList", &[header])),
            0,
            "{arch}"
        );
        let psize = if arch == WinArch::X86 { 4 } else { 8 };
        let next = |p: &Proc, entry: u64| p.space.ptr(entry, psize).unwrap();
        assert_eq!(next(p, entries[2]), entries[1], "{arch}");
        assert_eq!(next(p, entries[1]), entries[0], "{arch}");
        assert_eq!(next(p, entries[0]), 0, "{arch}");

        let before = header_bytes(p, header);
        assert_eq!(
            returned(call(p, t, "RtlInterlockedFlushSList", &[header])),
            0,
            "{arch}"
        );
        assert_eq!(
            header_bytes(p, header),
            before,
            "{arch}: empty flush wrote the header"
        );
    });
}

#[test]
fn a_list_of_entries_is_pushed_in_one_operation() {
    each_arch(|arch, p, t, base| {
        let header = base;
        let (e0, l1, l2, l3) = (base + 0x100, base + 0x200, base + 0x300, base + 0x400);
        let psize = if arch == WinArch::X86 { 4 } else { 8 };
        call(p, t, "RtlInitializeSListHead", &[header]).unwrap();
        call(p, t, "RtlInterlockedPushEntrySList", &[header, e0]).unwrap();
        p.space.wptr(l1, psize, l2).unwrap();
        p.space.wptr(l2, psize, l3).unwrap();
        p.space.wptr(l3, psize, 0xDEAD_BEE0).unwrap();
        assert_eq!(
            returned(call(
                p,
                t,
                "RtlInterlockedPushListSListEx",
                &[header, l1, l3, 3]
            )),
            e0,
            "{arch}"
        );
        assert_eq!(
            p.space.ptr(l3, psize).unwrap(),
            e0,
            "{arch}: the list's end links to the old first"
        );
        assert_eq!(
            returned(call(p, t, "RtlQueryDepthSList", &[header])),
            4,
            "{arch}"
        );
        for want in [l1, l2, l3, e0] {
            assert_eq!(
                returned(call(p, t, "RtlInterlockedPopEntrySList", &[header])),
                want,
                "{arch}"
            );
        }
    });
}

#[test]
fn depth_wraps_at_sixteen_bits() {
    each_arch(|arch, p, t, base| {
        let header = base;
        call(p, t, "RtlInitializeSListHead", &[header]).unwrap();
        // Depth is the low word on every layout's first 16 bits that hold it:
        // offset 0 on x64/ARM64, offset 4 on x86.
        let depth_at = if arch == WinArch::X86 {
            header + 4
        } else {
            header
        };
        p.space.w16(depth_at, 0xFFFF).unwrap();
        call(
            p,
            t,
            "RtlInterlockedPushEntrySList",
            &[header, base + 0x100],
        )
        .unwrap();
        assert_eq!(
            returned(call(p, t, "RtlQueryDepthSList", &[header])),
            0,
            "{arch}"
        );
    });
}

#[test]
fn misaligned_operations_raise_on_sixty_four_bit_windows() {
    each_arch(|arch, p, t, base| {
        let header = base + 8;
        let entry = base + 0x100;
        let before = header_bytes(p, header);
        for (name, args) in [
            ("RtlInitializeSListHead", vec![header]),
            ("RtlInterlockedPushEntrySList", vec![header, entry]),
            ("RtlInterlockedPushEntrySList", vec![base, entry + 8]),
            ("RtlInterlockedPopEntrySList", vec![header]),
            ("RtlInterlockedFlushSList", vec![header]),
        ] {
            let result = call(p, t, name, &args);
            if arch == WinArch::X86 {
                assert!(
                    result.is_ok(),
                    "x86 {name}: an 8-byte-aligned x86 header is aligned"
                );
                call(p, t, "RtlInitializeSListHead", &[header]).unwrap();
                call(p, t, "RtlInitializeSListHead", &[base]).unwrap();
            } else {
                match result {
                    Err(ApiErr::Raise(record)) => {
                        assert_eq!(record.code, STATUS_DATATYPE_MISALIGNMENT, "{arch} {name}")
                    }
                    other => panic!(
                        "{arch} {name}: expected a misalignment, got {}",
                        describe(&other)
                    ),
                }
            }
        }
        if arch != WinArch::X86 {
            assert_eq!(
                header_bytes(p, header),
                before,
                "{arch}: a refused operation wrote"
            );
            // Reading the depth is a plain read on any address.
            assert!(
                call(p, t, "RtlQueryDepthSList", &[header]).is_ok(),
                "{arch}"
            );
        }
    });
}

#[test]
fn a_fault_leaves_the_list_as_it_was() {
    each_arch(|arch, p, t, base| {
        let psize = if arch == WinArch::X86 { 4 } else { 8 };
        // A first entry whose link cannot be read: pop faults, header kept.
        let header = base;
        call(p, t, "RtlInitializeSListHead", &[header]).unwrap();
        call(
            p,
            t,
            "RtlInterlockedPushEntrySList",
            &[header, base + 0x100],
        )
        .unwrap();
        let unmapped = 0x10;
        if arch == WinArch::X86 {
            p.space.w32(header, unmapped as u32).unwrap();
        } else {
            p.space.w64(header + 8, unmapped).unwrap();
        }
        let before = header_bytes(p, header);
        assert!(
            matches!(
                call(p, t, "RtlInterlockedPopEntrySList", &[header]),
                Err(ApiErr::Fault(_))
            ),
            "{arch}"
        );
        assert_eq!(
            header_bytes(p, header),
            before,
            "{arch}: a faulting pop wrote the header"
        );

        // A header that cannot be written: push faults before the entry
        // changes.
        let read_only = page(p, PAGE_READONLY);
        let entry = base + 0x200;
        p.space.wptr(entry, psize, 0x5150).unwrap();
        assert!(
            matches!(
                call(p, t, "RtlInterlockedPushEntrySList", &[read_only, entry]),
                Err(ApiErr::Fault(_))
            ),
            "{arch}"
        );
        assert_eq!(
            p.space.ptr(entry, psize).unwrap(),
            0x5150,
            "{arch}: the entry changed"
        );

        // An unmapped header faults outright.
        assert!(
            matches!(
                call(p, t, "RtlQueryDepthSList", &[0x20]),
                Err(ApiErr::Fault(_))
            ),
            "{arch}"
        );
    });
}
