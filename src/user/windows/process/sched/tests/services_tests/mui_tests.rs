//! All native query rows, including aliases, undersized buffers and partial clears.
use super::nls_tests::{arguments, dispatch};
use super::*;
use crate::user::windows::memory::{mem, prot};

const CORPORA: [(WinArch, &str); 3] = [
    (
        WinArch::Arm64,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-mui-query/native-mui-query-v2-arm64.log"
        ),
    ),
    (
        WinArch::X86,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-mui-query/native-mui-query-v2-x86.log"
        ),
    ),
    (
        WinArch::X64,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-mui-query/native-mui-query-v2-x64.log"
        ),
    ),
];

fn field(line: &str, key: &str, radix: u32) -> u32 {
    let prefix = format!("{key}=");
    let text = line
        .split_whitespace()
        .find_map(|word| word.strip_prefix(&prefix))
        .unwrap();
    u32::from_str_radix(text, radix).unwrap()
}

#[test]
fn native_mui_query_replays_both_measured_builds_pointer_length_and_alias_rows() {
    let mut total = 0;
    for (arch, raw, build) in CORPORA
        .into_iter()
        .flat_map(|(arch, raw)| [29683, 29695].map(|build| (arch, raw, build)))
    {
        let (mut process, mut thread) = fixture(arch, "NtGetMUIRegistryInfo", 0x12);
        let p = process.state_mut();
        Arc::make_mut(&mut p.cfg).version.build = build;
        let base =
            p.vm.allocate(None, 16384, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        p.vm.protect(base + 4096, 4096, prot::NOACCESS).unwrap();
        p.vm.protect(base + 12288, 4096, prot::NOACCESS).unwrap();
        let output_base = base + 8192;
        // Payload contents are synthetic. Native rows independently determine
        // size, result, destination effects and ordering; no desktop data is used.
        let mut payload = vec![0x53; 1232];
        payload[..4].copy_from_slice(&1024u32.to_le_bytes());
        p.nls = Some(
            crate::user::windows::nls::Nls::new(vec![])
                .unwrap()
                .with_mui(payload.clone())
                .unwrap(),
        );
        let error = thread.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
        let mut count = 0;
        let call_sp = thread.cpu.sp();
        for line in raw.lines().filter(|line| line.starts_with("row ")) {
            let flags = field(line, "flags", 16);
            let size_kind = field(line, "size-kind", 10);
            let output_kind = field(line, "output-kind", 10);
            let length = field(line, "length", 10);
            p.vm.protect(base, 4096, prot::READWRITE).unwrap();
            p.vm.protect(output_base, 4096, prot::READWRITE).unwrap();
            p.space.wr(base, &[0xa5; 4096]).unwrap();
            p.space.wr(output_base, &[0xa5; 4096]).unwrap();
            let size = match size_kind {
                0 | 4 => base + 128,
                1 => 0,
                2 => 1,
                3 => base + 129,
                5 => base + 4096,
                6 => base + 4094,
                _ => panic!("unknown size pointer class"),
            };
            if matches!(size_kind, 0 | 3 | 4) {
                p.space.w32(size, length).unwrap();
            } else if size_kind == 6 {
                p.space.w16(size, length as u16).unwrap();
            }
            let output = match output_kind {
                0 | 7 => output_base + 64,
                1 => 0,
                2 => 1,
                3 => output_base + 65,
                4 => output_base + 4096,
                5 => output_base + 4080,
                6 => size,
                _ => panic!("unknown output pointer class"),
            };
            if size_kind == 4 {
                p.vm.protect(base, 4096, prot::READONLY).unwrap();
            }
            if output_kind == 7 {
                p.vm.protect(output_base, 4096, prot::READONLY).unwrap();
            }
            p.space.w32(error, 0x1234_5678).unwrap();
            // Each row is an independent call from the same native caller.
            // The synthetic WoW64 return consumes its supplied call frame.
            thread.cpu.set_sp(call_sp);
            arguments(p, &mut thread, &[u64::from(flags), size, output]);
            assert_eq!(
                dispatch(p, &mut thread),
                Outcome::Continue,
                "{arch} build {build}: {line}"
            );
            assert_eq!(
                thread.cpu.gpr(0),
                u64::from(field(line, "status", 16)),
                "{arch} build {build}: {line}"
            );
            let after = if matches!(size_kind, 0 | 3 | 4) {
                p.space.u32(size).unwrap()
            } else if size_kind == 6 {
                u32::from(p.space.u16(size).unwrap())
            } else {
                0
            };
            assert_eq!(
                after,
                field(line, "size-after", 10),
                "{arch} build {build}: {line}"
            );
            let output_page = p.space.bytes(output_base, 4096).unwrap();
            assert_eq!(
                output_page.iter().filter(|&&byte| byte != 0xa5).count(),
                field(line, "output-changed", 10) as usize,
                "{arch} build {build}: {line}"
            );
            assert_eq!(
                p.space.u32(error).unwrap(),
                field(line, "last-error", 16),
                "{arch} build {build}: {line}"
            );
            if thread.cpu.gpr(0) == 0 && output != 0 {
                assert_eq!(
                    p.space.bytes(output, payload.len()).unwrap(),
                    payload,
                    "{arch} build {build}: {line}"
                );
                assert!(
                    p.space
                        .bytes(
                            output + payload.len() as u64,
                            length as usize - payload.len()
                        )
                        .unwrap()
                        .iter()
                        .all(|&byte| byte == 0)
                );
            }
            count += 1;
        }
        assert_eq!(count, 1680);
        total += count;
    }
    assert_eq!(total, 10080);
}

#[test]
fn mui_cache_mutations_report_unavailable_without_query_argument_side_effects() {
    for (arch, build) in WinArch::ALL
        .into_iter()
        .flat_map(|arch| [29683, 29695].map(|build| (arch, build)))
    {
        let (mut process, mut thread) = fixture(arch, "NtGetMUIRegistryInfo", 0x12);
        let p = process.state_mut();
        Arc::make_mut(&mut p.cfg).version.build = build;
        let sp = thread.cpu.sp();
        let before = p.vm.committed_bytes();
        for flags in [2, 3, 8, 9, 10, 11] {
            for size in [0, 1] {
                thread.cpu.set_sp(sp);
                arguments(p, &mut thread, &[flags, size, 1]);
                let result = dispatch(p, &mut thread);
                assert!(
                    matches!(result, Outcome::Fail(ref reason) if reason.contains("cache clear/commit is not implemented")),
                    "{arch}: {result:?}"
                );
                assert_eq!(p.vm.committed_bytes(), before);
            }
        }
    }
}

#[test]
fn mui_unmeasured_profiles_publish_no_size_or_payload() {
    for arch in WinArch::ALL {
        for (major, minor, build) in [
            (10, 0, 29682),
            (10, 0, 29684),
            (10, 0, 29694),
            (10, 0, 29696),
            (10, 1, 29695),
            (11, 0, 29695),
        ] {
            let (mut process, mut thread) = fixture(arch, "NtGetMUIRegistryInfo", 0x12);
            let p = process.state_mut();
            let cfg = Arc::make_mut(&mut p.cfg);
            cfg.version.major = major;
            cfg.version.minor = minor;
            cfg.version.build = build;
            let base =
                p.vm.allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                    .unwrap()
                    .0;
            p.space.wr(base, &[0xa5; 4096]).unwrap();
            p.space.w32(base + 128, 1232).unwrap();
            p.nls = Some(
                crate::user::windows::nls::Nls::new(vec![])
                    .unwrap()
                    .with_mui(vec![0x53; 1232])
                    .unwrap(),
            );
            let before = p.space.bytes(base, 4096).unwrap();
            let charge = p.vm.committed_bytes();
            arguments(p, &mut thread, &[0, base + 128, base + 256]);
            assert!(
                matches!(dispatch(p, &mut thread), Outcome::Fail(ref reason) if reason.contains("native build profile is unmeasured"))
            );
            assert_eq!(p.space.bytes(base, 4096).unwrap(), before);
            assert_eq!(p.vm.committed_bytes(), charge);
        }
    }
}
