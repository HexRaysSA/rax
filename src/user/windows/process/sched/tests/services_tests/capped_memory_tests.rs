//! Independent Windows 29704 oracle replay through the native service boundary.
use super::*;
use crate::user::windows::memory::RegionInfo;

fn native_rows(arch: WinArch) -> &'static str {
    match arch {
        WinArch::Arm64 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-capped-memory/arm64-29704-v1.txt"
        )),
        WinArch::X64 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-capped-memory/x64-29704-v1.txt"
        )),
        WinArch::X86 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-capped-memory/x86-29704-v1.txt"
        )),
    }
}
fn hex(s: &str) -> u64 {
    u64::from_str_radix(s, 16).unwrap()
}
fn bytes(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}
fn put(data: &mut [u8], at: usize, width: usize, value: u64) {
    data[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
}
fn relocate(data: &mut [u8], width: usize, source: u64, base: u64) {
    for at in [0, width] {
        let mut raw = [0; 8];
        raw[..width].copy_from_slice(&data[at..at + width]);
        let value = u64::from_le_bytes(raw);
        if (source..source + 0x800000).contains(&value) {
            put(data, at, width, value - source + base);
        }
    }
}
#[test]
fn capped_memory_replays_native_page_caps_and_input_fields_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, scratch) = setup(arch);
        let p = process.state_mut();
        let base =
            p.vm.allocate(None, 0x800000, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let width = arch.ptr_size() as usize;
        let size_at = if width == 4 { 12 } else { 24 };
        let rows = native_rows(arch);
        let mut lines = rows.lines();
        let source = hex(lines.next().unwrap().split_whitespace().nth(2).unwrap());
        let top = if width == 4 { 1u64 << 32 } else { 1u64 << 47 };
        let output = scratch + 128;
        let returned = scratch + 256;
        let mut split = false;
        let mut count = 0;
        for line in lines {
            let row: Vec<_> = line.split_whitespace().collect();
            let (address, length, status, expected_returned, mut expected, mut input) = match row[0]
            {
                "matrix" => {
                    let now_split = hex(row[1]) != 0;
                    if now_split != split {
                        p.vm.protect(
                            base + 8192,
                            4096,
                            if now_split {
                                prot::READONLY
                            } else {
                                prot::READWRITE
                            },
                        )
                        .unwrap();
                        split = now_split;
                    }
                    let offset = hex(row[2]);
                    let native_cap = hex(row[3]);
                    // Boundary cases retain their absolute exclusive endpoint;
                    // ordinary caps and deliberate pointer overflow retain size.
                    let cap = if native_cap
                        .checked_add(source)
                        .is_some_and(|end| (top - 65537..=top + 1).contains(&end))
                    {
                        native_cap + source - base
                    } else {
                        native_cap
                    };
                    let status = hex(row[5]) as u32;
                    let mut input = vec![0; 64];
                    put(&mut input, size_at, width, cap);
                    let mut expected = bytes(row[8]);
                    if status == STATUS_SUCCESS {
                        relocate(&mut expected, width, source, base);
                    } else {
                        put(&mut expected, size_at, width, cap);
                    }
                    (
                        base + offset,
                        hex(row[4]),
                        status,
                        hex(row[7]),
                        expected,
                        input,
                    )
                }
                "field" => {
                    let mut input = vec![0; 64];
                    put(&mut input, size_at, width, 8192);
                    put(&mut input, hex(row[1]) as usize * 4, 4, 1);
                    let mut expected = bytes(row[4]);
                    if hex(row[2]) == 0 {
                        relocate(&mut expected, width, source, base);
                    }
                    expected.resize(64, 0);
                    (
                        base,
                        RegionInfo::encoded_size(width as u64) as u64,
                        hex(row[2]) as u32,
                        hex(row[3]),
                        expected,
                        input,
                    )
                }
                _ => continue,
            };
            input.resize(128, 0);
            p.space.wr(output, &input).unwrap();
            p.space.wptr(returned, width as u64, 0xfeed).unwrap();
            let observed = query(p, &mut t, address, 10, output, length, returned);
            assert_eq!(observed, status, "{arch}: {line}");
            assert_eq!(
                p.space.bytes(output, 64).unwrap(),
                expected,
                "{arch}: {line}"
            );
            assert_eq!(
                p.space.ptr(returned, width as u64).unwrap(),
                expected_returned,
                "{arch}: {line}"
            );
            count += 1;
        }
        assert_eq!(
            count,
            if arch == WinArch::X86 { 1027 } else { 1032 },
            "complete oracle selection {arch}"
        );
    }
}

#[test]
fn capped_memory_replays_native_fault_priority_and_copy_bytes_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, scratch) = setup(arch);
        let p = process.state_mut();
        let base =
            p.vm.allocate(None, 0x800000, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        p.vm.protect(base + 8192, 4096, prot::READONLY).unwrap();
        let width = arch.ptr_size() as usize;
        let required = RegionInfo::encoded_size(width as u64);
        let size_at = if width == 4 { 12 } else { 24 };
        let rows = native_rows(arch);
        let source = hex(rows
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(2)
            .unwrap());
        let mut count = 0;
        for line in rows.lines().filter(|s| s.starts_with("fault ")) {
            let row: Vec<_> = line.split_whitespace().collect();
            let role = hex(row[1]);
            p.vm.protect(scratch, 0x4000, prot::READWRITE).unwrap();
            p.space.wr(scratch, &[0xa5; 0x4000]).unwrap();
            let output_base = scratch + 128;
            let returned_base = scratch + 256;
            p.space.wr(output_base, &vec![0; required]).unwrap();
            p.space
                .wptr(output_base + size_at, width as u64, 8192)
                .unwrap();
            p.space.wptr(returned_base, width as u64, 0xfeed).unwrap();
            let mut handle = arch.ptr(u64::MAX);
            let mut address = base + 1;
            let mut output = output_base;
            let mut returned = returned_base;
            let mut length = required as u64;
            match role {
                0 => {}
                1 => output = 0,
                2 => output += 1,
                3 | 4 | 16 => {
                    output = scratch + 4096;
                    p.vm.protect(
                        output,
                        4096,
                        match role {
                            3 => prot::NOACCESS,
                            4 => prot::READWRITE | prot::GUARD,
                            _ => prot::READONLY,
                        },
                    )
                    .unwrap();
                }
                5 => returned = 0,
                6 => returned = 1,
                7 => returned += 1,
                8 => handle = 0,
                9 => handle = arch.ptr(u64::MAX - 1),
                10 => address = arch.ptr(u64::MAX),
                11 => {
                    length = 0;
                    output = 0;
                }
                12 => {
                    length = 0;
                    returned = 1;
                }
                13 => {
                    handle = 0;
                    output = 0;
                }
                14 => {
                    p.space
                        .wptr(output_base + size_at, width as u64, 0)
                        .unwrap();
                    returned = 1;
                }
                15 => returned = output,
                17 => p
                    .space
                    .wptr(output_base + size_at, width as u64, 0)
                    .unwrap(),
                18 => length = 128,
                19 => {
                    handle = 0;
                    p.space
                        .wptr(output_base + size_at, width as u64, 0)
                        .unwrap();
                }
                20 => p
                    .space
                    .wptr(output_base + size_at, width as u64, 1)
                    .unwrap(),
                21 => address = 0,
                22 => address = 1,
                23 => {
                    returned = scratch + 4096;
                    p.vm.protect(returned, 4096, prot::READWRITE | prot::GUARD)
                        .unwrap();
                }
                _ => panic!("unknown native role {role}"),
            }
            arguments(p, &mut t, &[handle, address, 10, output, length, returned]);
            assert_eq!(dispatch(p, &mut t), Outcome::Continue, "{arch} role {role}");
            assert_eq!(t.cpu.gpr(0) as u32, hex(row[2]) as u32, "{arch}: {line}");
            assert_eq!(hex(row[3]), 0, "native oracle has no SEH exception");
            let mut expected = bytes(row[4]);
            if hex(row[2]) == 0 {
                // An unaligned WoW64 output starts one byte after the captured
                // region; an aliased ReturnLength overwrites only BaseAddress.
                if role == 2 {
                    relocate(&mut expected[1..], width, source, base);
                } else {
                    relocate(&mut expected, width, source, base);
                }
            }
            let actual = p.space.bytes(output_base, 64).unwrap();
            if matches!(role, 21 | 22) {
                // Host and guest have different allocation layouts. This one
                // free-extent field is tested against a controlled hole below.
                let at = size_at as usize;
                let mut raw = [0; 8];
                raw[..width].copy_from_slice(&actual[at..at + width]);
                assert!(u64::from_le_bytes(raw) >= 8192);
                expected[at..at + width].copy_from_slice(&actual[at..at + width]);
            }
            assert_eq!(actual, expected, "{arch}: {line}");
            assert_eq!(
                p.space.bytes(returned_base, 16).unwrap(),
                bytes(row[5]),
                "{arch}: {line}"
            );
            assert!(t.frames.is_empty());
            count += 1;
        }
        assert_eq!(count, 24, "complete native fault selection {arch}");
    }
}

#[test]
fn capped_memory_preserves_complete_free_holes_and_caps_allocated_runs() {
    use crate::user::mm::{AddressSpace, SpaceConfig};
    use crate::user::windows::memory::VirtualMemory;
    let space = AddressSpace::new(SpaceConfig {
        va_limit: 1 << 47,
        arena_bytes: 8 << 20,
        reserved_phys: vec![],
    })
    .unwrap();
    let mut vm = VirtualMemory::new(space, 65536, 1 << 47);
    vm.allocate(
        Some(0x40000),
        8192,
        mem::RESERVE | mem::COMMIT,
        prot::READWRITE,
    )
    .unwrap();
    let free = vm.query_capped(0x20001, 0x21000).unwrap();
    assert_eq!(
        (free.base, free.size, free.state),
        (0x20000, 0x20000, mem::FREE)
    );
    let allocated = vm.query_capped(0x40001, 0x41000).unwrap();
    assert_eq!(
        (allocated.base, allocated.size, allocated.state),
        (0x40000, 4096, mem::COMMIT)
    );
    assert_eq!(vm.query(0x40001).unwrap().size, 8192);
}
#[test]
fn capped_memory_reports_wow64_non_laa_reservation_fence_without_mapping() {
    let (mut process, mut t, scratch) = setup(WinArch::X86);
    let p = process.state_mut();
    assert_eq!(p.vm.high(), 0x7fff0000);
    let committed = p.vm.committed_bytes();
    for address in [0x7fff0000u64, 0x80000000, 0xfffeffff] {
        p.space.wr(scratch + 128, &[0; 28]).unwrap();
        p.space.w32(scratch + 140, 1).unwrap();
        assert_eq!(
            query(p, &mut t, address, 10, scratch + 128, 28, scratch + 256),
            STATUS_SUCCESS
        );
        assert_eq!(
            p.space.u32(scratch + 128).unwrap(),
            (address & !4095) as u32
        );
        assert_eq!(p.space.u32(scratch + 132).unwrap(), 0x7fff0000);
        assert_eq!(p.space.u32(scratch + 136).unwrap(), prot::READONLY);
        assert_eq!(p.space.u32(scratch + 140).unwrap(), 4096);
        assert_eq!(p.space.u32(scratch + 144).unwrap(), mem::RESERVE);
        assert_eq!(p.space.u32(scratch + 148).unwrap(), 0);
        assert_eq!(p.space.u32(scratch + 152).unwrap(), mem::PRIVATE);
        assert_eq!(p.vm.committed_bytes(), committed);
        assert!(p.space.vma_at(address).is_none());
    }
}
