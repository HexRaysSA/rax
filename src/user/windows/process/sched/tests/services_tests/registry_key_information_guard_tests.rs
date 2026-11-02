//! Complete native guarded matrix; undefined WoW64 scratch tails are retained
//! in the corpus but excluded from byte assertions, never from status/guards.
use super::*;
use serde_json::Value as Json;
use std::io::Read;

fn number(row: &Json, field: &str) -> u64 {
    row[field].as_u64().unwrap()
}
fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn protect(p: &mut Proc, base: u64, page: usize, value: u32, flags: &mut [u32; 16]) {
    p.vm.protect(base + page as u64 * PAGE_SIZE, PAGE_SIZE, value)
        .unwrap();
    flags[page] = value;
}
fn writable(base: u64, address: u64, bytes: u64, flags: &[u32; 16]) -> bool {
    let Some(offset) = address.checked_sub(base) else {
        return false;
    };
    let Some(end) = offset.checked_add(bytes) else {
        return false;
    };
    end <= 65536
        && (offset / PAGE_SIZE..(end - 1) / PAGE_SIZE + 1)
            .all(|page| flags[page as usize] == prot::READWRITE)
}
fn replay(arch: WinArch, encoded: &[u8]) {
    let (mut process, mut t, _) = setup(arch);
    let p = process.state_mut();
    super::super::super::super::native_profile::kernel_profile(p, 29698, 0xAA64);
    p.registry = p
        .registry
        .clone()
        .with_information_tree(TreeRoot::NlsCustomLocale, Some(nls_tree_fixture()))
        .unwrap();
    let key = p
        .registry
        .key(&NLS_CUSTOM_LOCALE_KEY.encode_utf16().collect::<Vec<_>>())
        .unwrap();
    let id = p
        .objects
        .create_registry_key(key.clone(), if arch == WinArch::X86 { 0x400 } else { 0 })
        .unwrap();
    let handle = p.objects.open_access(id, false, 9).unwrap() as u64;
    let reservation =
        p.vm.reserve(
            None,
            3 * 65536,
            prot::NOACCESS,
            crate::user::windows::memory::AllocKind::Private,
            false,
            None,
        )
        .unwrap();
    let base = reservation + 65536;
    assert_eq!(
        p.vm.commit(base, 65536, prot::READWRITE).unwrap(),
        (base, 65536)
    );
    let mut text = String::new();
    zstd::stream::read::Decoder::new(encoded)
        .unwrap()
        .take(96 << 20)
        .read_to_string(&mut text)
        .unwrap();
    let poisons = [vec![0xA5; 65536], vec![0x5A; 65536]];
    let mut counts = [0usize; 11];
    let mut checked_bytes = 0usize;
    let mut undefined_bytes = 0usize;
    for line in text.lines() {
        let row: Json = serde_json::from_str(line).unwrap();
        if row["kind"] != "case" {
            continue;
        }
        let class = number(&row, "class");
        let length = number(&row, "length");
        let output_role = number(&row, "output");
        let returned_role = number(&row, "returned");
        let poison = number(&row, "poison");
        assert_eq!(number(&row, "index") as usize, counts.iter().sum::<usize>());
        counts[class as usize] += 1;
        p.vm.protect(base, 65536, prot::READWRITE).unwrap();
        p.space
            .wr(
                base,
                &poisons[if poison == 0xA5 {
                    0
                } else {
                    assert_eq!(poison, 0x5A);
                    1
                }],
            )
            .unwrap();
        let mut flags = [prot::READWRITE; 16];
        let mut output_offset = 0;
        let mut output = base;
        match output_role {
            0 => {}
            1 => output = 0,
            2 => output = 1,
            3 | 4 | 13 => {
                output_offset = if output_role == 3 {
                    1
                } else if output_role == 4 {
                    4
                } else {
                    2
                };
                output += output_offset;
            }
            5 | 6 | 7 | 11 => protect(
                p,
                base,
                0,
                match output_role {
                    5 => prot::READONLY,
                    6 => prot::READWRITE | prot::GUARD,
                    7 => prot::NOACCESS,
                    _ => prot::READONLY | prot::GUARD,
                },
                &mut flags,
            ),
            8..=10 => {
                output_offset = 4092;
                output += output_offset;
                protect(
                    p,
                    base,
                    1,
                    match output_role {
                        8 => prot::NOACCESS,
                        9 => prot::READWRITE | prot::GUARD,
                        _ => prot::READONLY,
                    },
                    &mut flags,
                );
            }
            12 => output = arch.ptr(u64::MAX - 15),
            _ => panic!("uncaptured output role"),
        }
        let mut returned_offset = 8192;
        let mut returned = base + returned_offset;
        match returned_role {
            0 => {}
            1 => returned = 0,
            2 => returned = 1,
            3 => {
                returned_offset += 1;
                returned = base + returned_offset;
            }
            4 | 5 | 6 | 12 => protect(
                p,
                base,
                2,
                match returned_role {
                    4 => prot::READONLY,
                    5 => prot::READWRITE | prot::GUARD,
                    6 => prot::NOACCESS,
                    _ => prot::READONLY | prot::GUARD,
                },
                &mut flags,
            ),
            7..=10 => {
                returned_offset = output_offset
                    + match returned_role {
                        7 => 0,
                        8 => 4,
                        9 => 28,
                        _ => 32,
                    };
                returned = base + returned_offset;
            }
            11 => {
                returned_offset = 12286;
                returned = base + returned_offset;
                protect(p, base, 3, prot::NOACCESS, &mut flags);
            }
            _ => panic!("uncaptured returned role"),
        }
        let converted = arch == WinArch::X86 && output % 8 != 0 && class <= 8;
        let minimum = crate::user::windows::registry::KeyInformation::minimum(class as u32)
            .unwrap_or(0) as u64;
        let record_length = if class == 7 {
            4
        } else {
            key.information()
                .unwrap()
                .record(class as u32)
                .map_or(0, |record| record.len() as u64)
        };
        let defined_scratch = converted && writable(base, returned, 4, &flags) && length >= minimum;
        let last_error = t.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
        p.space.w32(last_error, 0x12345678).unwrap();
        let actual = call(
            p,
            &mut t,
            "NtQueryKey",
            &[handle, class, output, length, returned],
        );
        let context =
            format!("{arch}/class{class}/len{length}/out{output_role}/ret{returned_role}");
        assert_eq!(number(&row, "exception"), 0, "{context}");
        assert_eq!(u64::from(actual), number(&row, "status"), "{context}");
        assert_eq!(
            u64::from(p.space.u32(last_error).unwrap()),
            number(&row, "last_error"),
            "{context}"
        );
        for page in 0..4 {
            assert_eq!(
                u64::from(p.vm.query(base + page * PAGE_SIZE).unwrap().protect),
                row["protections"][page as usize].as_u64().unwrap(),
                "{context}/page{page}"
            );
        }
        p.vm.protect(base, 65536, prot::READWRITE).unwrap();
        for (field, address, size) in [
            ("bytes", base + output_offset, 256),
            ("returned_bytes", base + returned_offset, 8),
        ] {
            let expected = hex(row[field].as_str().unwrap());
            assert_eq!(expected.len(), size);
            let actual = p.space.bytes(address, size).unwrap();
            for index in 0..size {
                let at = address + index as u64;
                let copied = converted && (output..output.saturating_add(length)).contains(&at);
                let defined = defined_scratch
                    && (output..output.saturating_add(record_length.min(length))).contains(&at);
                if copied && !defined {
                    undefined_bytes += 1;
                    continue;
                }
                checked_bytes += 1;
                assert_eq!(actual[index], expected[index], "{context}/{field}+{index}");
            }
        }
    }
    assert_eq!(counts, [6010; 11]);
    assert!(checked_bytes > 10_000_000);
    if arch == WinArch::X86 {
        assert!(undefined_bytes > 0);
    } else {
        assert_eq!(undefined_bytes, 0);
    }
    eprintln!(
        "{arch}: 66110 native guarded cases, {checked_bytes} defined bytes, {undefined_bytes} undefined thunk bytes excluded"
    );
}

#[test]
fn native_key_information_replays_complete_guarded_native_matrix_all_abis() {
    for (arch, encoded) in [
        (
            WinArch::Arm64,
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-query-key/metadata/arm64-guards-v3.jsonl.zst"
            ))
            .as_slice(),
        ),
        (
            WinArch::X64,
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-query-key/metadata/x64-guards-v3.jsonl.zst"
            ))
            .as_slice(),
        ),
        (
            WinArch::X86,
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-query-key/metadata/x86-guards-v3.jsonl.zst"
            ))
            .as_slice(),
        ),
    ] {
        replay(arch, encoded);
    }
}
