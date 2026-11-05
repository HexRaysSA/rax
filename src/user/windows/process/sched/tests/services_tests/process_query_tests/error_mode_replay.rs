//! Reuse each fixture across the native corpus; preserve all guards and bytes.
use super::error_mode::{Harness, fields, hex, number};
use super::*;

fn pointers(p: &mut Proc, base: u64, name: &str) -> (u64, u64) {
    let second = base + 3 * PAGE_SIZE;
    let mut buffer = base + PAGE_SIZE + 256;
    let mut returned = second + PAGE_SIZE + 256;
    match name {
        "buffer-null" => buffer = 0,
        "returned-null" => returned = 0,
        "both-null" => {
            buffer = 0;
            returned = 0;
        }
        "buffer-bad" => buffer = 0xdead0000,
        "returned-bad" => returned = 0xdead0000,
        "buffer-unaligned" => buffer += 1,
        "returned-unaligned" => returned += 1,
        "same" => returned = buffer,
        "returned-plus2" => returned = buffer + 2,
        "buffer-cross" => buffer = base + 2 * PAGE_SIZE - 2,
        "returned-cross" => returned = second + 2 * PAGE_SIZE - 2,
        "buffer-upper" => buffer = p.arch.ptr(u64::MAX & !3),
        "returned-upper" => returned = p.arch.ptr(u64::MAX & !3),
        // The native producer uses first address above GetSystemInfo's
        // application range; replay uses the corresponding guest boundary.
        "buffer-high" => buffer = p.vm.high(),
        "returned-high" => returned = p.vm.high(),
        _ => {}
    }
    (buffer, returned)
}

fn protections(p: &mut Proc, base: u64, name: &str) {
    let second = base + 3 * PAGE_SIZE;
    let (first, other) = match name {
        "buffer-readonly" => (Some(prot::READONLY), None),
        "returned-readonly" => (None, Some(prot::READONLY)),
        "buffer-guard" => (Some(prot::READWRITE | prot::GUARD), None),
        "returned-guard" => (None, Some(prot::READWRITE | prot::GUARD)),
        "both-guard" => (
            Some(prot::READWRITE | prot::GUARD),
            Some(prot::READWRITE | prot::GUARD),
        ),
        "buffer-readonly-guard" => (Some(prot::READONLY | prot::GUARD), None),
        "returned-readonly-guard" => (None, Some(prot::READONLY | prot::GUARD)),
        "buffer-noaccess" => (Some(prot::NOACCESS), None),
        "returned-noaccess" => (None, Some(prot::NOACCESS)),
        _ => (None, None),
    };
    for (at, mode) in [(base + PAGE_SIZE, first), (second + PAGE_SIZE, other)] {
        if let Some(mode) = mode {
            p.vm.protect(at, PAGE_SIZE, mode).unwrap();
        }
    }
    if name == "buffer-cross" {
        p.vm.protect(base + 2 * PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
            .unwrap();
    }
    if name == "returned-cross" {
        p.vm.protect(second + 2 * PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
            .unwrap();
    }
}

fn replay(arch: WinArch, text: &str, expected: usize) {
    let mut h = Harness::new(arch);
    let base = h.base;
    let second = base + 3 * PAGE_SIZE;
    let handles = h
        .process
        .state()
        .objects
        .iter()
        .map(|(id, _)| id)
        .collect::<Vec<_>>();
    let mut count = 0;
    for line in text.lines().filter(|x| x.starts_with("kind=case")) {
        let row = fields(line);
        assert_eq!(row["exception"], "00000000");
        assert_eq!(row["reset"], "00000000");
        let setter = row["op"] == "set";
        let p = h.process.state_mut();
        p.vm.protect(base, 6 * PAGE_SIZE, prot::READWRITE).unwrap();
        p.space.wr(base, &[0xa5; 6 * PAGE_SIZE as usize]).unwrap();
        p.error_mode.set_native(number(row["before"]));
        let (buffer, returned) = pointers(p, base, row["case"]);
        if setter && buffer >= base && buffer <= base + 3 * PAGE_SIZE - 4 {
            p.space.w32(buffer, 3).unwrap();
        }
        protections(p, base, row["case"]);
        let handle = h.roles[row["role"]];
        let status = h.invoke(
            setter,
            handle,
            buffer,
            row["len"].parse().unwrap(),
            returned,
        );
        assert_eq!(status, number(row["status"]), "{arch}: {line}");
        let p = h.process.state_mut();
        assert_eq!(
            p.error_mode.native(),
            number(row["after"]),
            "{arch}: {line}"
        );
        for (key, at) in [
            ("buffer-protect", base + PAGE_SIZE),
            ("returned-protect", second + PAGE_SIZE),
            ("buffer-tail", base + 2 * PAGE_SIZE),
            ("returned-tail", second + 2 * PAGE_SIZE),
        ] {
            assert_eq!(
                p.vm.query(at).unwrap().protect,
                number(row[key]),
                "{arch}/{key}: {line}"
            );
        }
        p.vm.protect(base, 6 * PAGE_SIZE, prot::READWRITE).unwrap();
        for (key, at) in [
            ("buffer", base + PAGE_SIZE + 240),
            ("returned", second + PAGE_SIZE + 240),
            ("buffer-edge", base + 2 * PAGE_SIZE - 16),
            ("returned-edge", second + 2 * PAGE_SIZE - 16),
        ] {
            let expected = hex(row[key]);
            assert_eq!(
                p.space.bytes(at, expected.len()).unwrap(),
                expected,
                "{arch}/{key}: {line}"
            );
        }
        assert_eq!(
            p.objects.iter().map(|(id, _)| id).collect::<Vec<_>>(),
            handles
        );
        count += 1;
    }
    assert_eq!(count, expected);
}

#[test]
fn native_process_error_mode_replays_all_15120_native_query_set_fault_and_handle_rows() {
    let profiles = [
        (
            WinArch::Arm64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-process-error-mode/observations-arm64-29698-v1.log"
            )),
        ),
        (
            WinArch::X64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-process-error-mode/observations-x64-29698-v1.log"
            )),
        ),
        (
            WinArch::X86,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-process-error-mode/observations-x86-29698-v1.log"
            )),
        ),
        (
            WinArch::X86,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-process-error-mode/observations-x86-laa-29698-v1.log"
            )),
        ),
    ];
    for (arch, text) in profiles {
        replay(arch, text, 3780);
    }
}

#[test]
fn native_process_error_mode_replays_all_2880_native_upper_address_rows() {
    let profiles = [
        (
            WinArch::Arm64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-process-error-mode/bounds-arm64-29698-v1.log"
            )),
        ),
        (
            WinArch::X64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-process-error-mode/bounds-x64-29698-v1.log"
            )),
        ),
        (
            WinArch::X86,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-process-error-mode/bounds-x86-29698-v1.log"
            )),
        ),
        (
            WinArch::X86,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-process-error-mode/bounds-x86-laa-29698-v1.log"
            )),
        ),
    ];
    for (arch, text) in profiles {
        replay(arch, text, 720);
    }
}
