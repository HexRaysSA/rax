//! Independent AMD64 kernel records, complete first-page writes and owned views.
use super::*;
use serde_json::Value;
use std::collections::BTreeSet;

fn captures() -> Value {
    serde_json::from_str(include_str!("../../../../../../../docs/specifications/windows/native-nls-amd64-initialize/profiles-v1.json")).unwrap()
}

fn field<'a>(line: &'a str, name: &str) -> &'a str {
    line.split_whitespace()
        .find_map(|value| value.strip_prefix(&format!("{name}=")))
        .unwrap()
}

fn number(line: &str, name: &str) -> i64 {
    field(line, name).parse().unwrap()
}

fn hex(line: &str, name: &str) -> u64 {
    u64::from_str_radix(field(line, name), 16).unwrap()
}

fn bytes(encoded: &str) -> Vec<u8> {
    assert_eq!(encoded.len() % 2, 0);
    (0..encoded.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).unwrap())
        .collect()
}

fn argument(base: u64, index: usize, variant: i64, arch: WinArch) -> u64 {
    match variant {
        0 => base + 256 + index as u64 * 32,
        1 => 0,
        2 => 1,
        3 => base + 4096 + 256 + index as u64 * 32,
        4 => base + 8192 + 256 + index as u64 * 32,
        5 => base + 257 + index as u64 * 32,
        6 => base + 4095,
        7 => arch.ptr(u64::MAX),
        8 => base + 384,
        9 => base + 12288 + 256 + index as u64 * 32,
        _ => panic!("unknown independent native argument variant"),
    }
}

fn page(changes: &str) -> Vec<u8> {
    let mut expected = vec![0xA5; 4096];
    let values: Vec<_> = changes
        .strip_prefix("changes")
        .unwrap()
        .split_whitespace()
        .collect();
    let mut previous = 0;
    assert_eq!(values.len() % 3, 0);
    for span in values.chunks_exact(3) {
        let offset: usize = span[0].strip_prefix("offset=").unwrap().parse().unwrap();
        let count: usize = span[1].strip_prefix("bytes=").unwrap().parse().unwrap();
        let raw = bytes(span[2].strip_prefix("hex=").unwrap());
        assert!(count > 0 && offset >= previous && offset + count <= expected.len());
        assert_eq!(raw.len(), count);
        expected[offset..offset + count].copy_from_slice(&raw);
        previous = offset + count;
    }
    expected
}

#[test]
fn native_nls_initialize_replays_all_474_amd64_kernel_calls_full_page_guards_and_lifetime() {
    let captures = captures();
    let mut cases = 0;
    let mut late_retained = 0;
    for profile in captures["initialization_projections"].as_array().unwrap() {
        let build = profile["kernel"][2].as_u64().unwrap() as u32;
        assert_eq!(profile["kernel"][0], 10);
        assert_eq!(profile["kernel"][1], 0);
        let arch = match profile["arch"].as_str().unwrap() {
            "x64" => WinArch::X64,
            "x86" | "x86-laa" => WinArch::X86,
            _ => panic!("unmeasured process view"),
        };
        let size = profile["mapping_bytes"].as_u64().unwrap();
        let locale = profile["locale"].as_u64().unwrap() as u32;
        let lines: Vec<_> = profile["stdout_utf8"].as_str().unwrap().lines().collect();
        let mut ordinal = 0;
        for (index, line) in lines
            .iter()
            .enumerate()
            .filter(|(_, s)| s.starts_with("case "))
        {
            assert_eq!(number(line, "ordinal"), ordinal);
            assert_eq!(hex(line, "seh"), 0);
            assert_eq!(number(line, "pointer-bytes") as u64, arch.ptr_size());
            let (mut process, mut thread, base) = setup(arch, build);
            let p = process.state_mut();
            p.object_namespace.native_machine = Some(0x8664);
            p.nls = Some(
                crate::user::windows::nls::Nls::new(vec![])
                    .unwrap()
                    .with_initialize(locale, vec![0x53; size as usize])
                    .unwrap(),
            );
            let args: Vec<_> = (0..4)
                .map(|i| {
                    let variant = if i as i64 == number(line, "argument") {
                        number(line, "variant")
                    } else if i as i64 == number(line, "other") {
                        number(line, "other-variant")
                    } else {
                        0
                    };
                    argument(base, i, variant, arch)
                })
                .collect();
            let before: BTreeSet<_> = p.vm.allocations().map(|a| a.base).collect();
            let charge = p.vm.committed_bytes();
            assert_eq!(
                invoke(p, &mut thread, &args),
                Outcome::Continue,
                "{build} {arch}: {line}"
            );
            let status = hex(line, "status");
            assert_eq!(thread.cpu.gpr(0), status, "{build} {arch}: {line}");
            assert_eq!(
                u64::from(p.vm.query(base + 12288).unwrap().protect),
                hex(lines[index + 1], "protect")
            );
            let native_views = lines[index + 2];
            let delta = number(native_views, "after") - number(native_views, "before");
            let new: Vec<_> =
                p.vm.allocations()
                    .filter(|a| !before.contains(&a.base))
                    .map(|a| (a.base, a.size))
                    .collect();
            assert_eq!(new.len() as i64, delta, "{build} {arch}: {line}");
            assert_eq!(p.vm.committed_bytes(), charge + new.len() as u64 * size);
            let mut expected = page(lines[index + 4]);
            assert_eq!(&expected[256..400], bytes(field(lines[index + 3], "hex")));
            if let Some(&(view, extent)) = new.first() {
                assert_eq!(extent, size);
                assert!(p.vm.is_nls_view(view));
                assert_eq!(p.vm.query(view).unwrap().protect, prot::READONLY);
                assert_eq!(
                    p.space.bytes(view, size as usize).unwrap(),
                    vec![0x53; size as usize]
                );
                if status == 0 {
                    let native = hex(native_views, "new").to_le_bytes();
                    let replacement = view.to_le_bytes();
                    let offset = args[0].checked_sub(base).unwrap();
                    assert!(offset + arch.ptr_size() <= 4096);
                    for byte in 0..arch.ptr_size() {
                        let address = args[0] + byte;
                        if arch == WinArch::X64 && (args[1]..args[1] + 4).contains(&address) {
                            continue;
                        }
                        assert_eq!(expected[(offset + byte) as usize], native[byte as usize]);
                        expected[(offset + byte) as usize] = replacement[byte as usize];
                    }
                } else {
                    late_retained += 1;
                }
            }
            assert_eq!(
                p.space.bytes(base, 4096).unwrap(),
                expected,
                "{build} {arch}: {line}"
            );
            assert!(thread.frames.is_empty());
            for (view, _) in new {
                let module = p.modules.nt_services.as_ref().unwrap().0;
                p.modules.nt_services = Some((module, table(arch, "NtUnmapViewOfSection", 0x12)));
                assert_eq!(
                    invoke(p, &mut thread, &[arch.ptr(u64::MAX), view + 4095]),
                    Outcome::Continue
                );
                assert_eq!(thread.cpu.gpr(0), 0);
                assert_eq!(p.vm.query(view).unwrap().state, mem::FREE);
            }
            assert_eq!(p.vm.committed_bytes(), charge);
            assert_eq!(p.vm.nls_view_count(), 0);
            ordinal += 1;
        }
        assert_eq!(ordinal, 79);
        cases += ordinal;
    }
    assert_eq!(cases, 474);
    assert_eq!(late_retained, 16);
}

fn write_pointer(p: &Proc, address: u64, value: u64) {
    if p.arch == WinArch::X86 {
        p.space.w32(address, value.try_into().unwrap()).unwrap();
    } else {
        p.space.w64(address, value).unwrap();
    }
}

#[test]
fn native_nls_initialize_replays_all_72_amd64_protect_free_outputs_and_unmaps_owned_views() {
    let data = captures();
    let mut cases = 0;
    for profile in data["protection_projections"].as_array().unwrap() {
        let arch = if profile["arch"] == "x64" {
            WinArch::X64
        } else {
            WinArch::X86
        };
        let build = profile["kernel"][2].as_u64().unwrap() as u32;
        let initialization = data["initialization_projections"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["kernel"] == profile["kernel"] && row["arch"] == profile["arch"])
            .unwrap();
        let size = initialization["mapping_bytes"].as_u64().unwrap();
        let mut ordinal = 0;
        for line in profile["stdout_utf8"]
            .as_str()
            .unwrap()
            .lines()
            .filter(|s| s.starts_with("case "))
        {
            assert_eq!(number(line, "ordinal"), ordinal);
            let (mut process, mut thread, base) = setup(arch, build);
            let p = process.state_mut();
            p.object_namespace.native_machine = Some(0x8664);
            p.nls = Some(
                crate::user::windows::nls::Nls::new(vec![])
                    .unwrap()
                    .with_initialize(
                        initialization["locale"].as_u64().unwrap() as u32,
                        vec![0x53; size as usize],
                    )
                    .unwrap(),
            );
            let charge = p.vm.committed_bytes();
            assert_eq!(
                invoke(p, &mut thread, &[base + 256, base + 288, 0, 0]),
                Outcome::Continue
            );
            assert_eq!(thread.cpu.gpr(0), 0);
            let view = pointer(p, base + 256);
            write_pointer(p, base + 256, view);
            write_pointer(p, base + 288, if ordinal == 10 { 0 } else { 4096 });
            p.space.w32(base + 320, 0xA5A5A5A5).unwrap();
            let module = p.modules.nt_services.as_ref().unwrap().0;
            let protect = field(line, "operation") == "protect";
            let name = if protect {
                "NtProtectVirtualMemory"
            } else {
                "NtFreeVirtualMemory"
            };
            p.modules.nt_services = Some((module, table(arch, name, 0x12)));
            let mut args = vec![
                arch.ptr(u64::MAX),
                base + 256,
                base + 288,
                hex(line, "requested"),
            ];
            if protect {
                args.push(base + 320);
            }
            assert_eq!(
                invoke(p, &mut thread, &args),
                Outcome::Continue,
                "{build} {arch}: {line}"
            );
            assert_eq!(
                thread.cpu.gpr(0),
                hex(line, "status"),
                "{build} {arch}: {line}"
            );
            let displacement = hex(line, "result-base")
                .checked_sub(hex(line, "base"))
                .unwrap();
            assert_eq!(pointer(p, base + 256), view + displacement);
            assert_eq!(pointer(p, base + 288), number(line, "result-size") as u64);
            assert_eq!(
                u64::from(p.space.u32(base + 320).unwrap()),
                hex(line, "old")
            );
            let actual = p.vm.query(view).unwrap();
            assert_eq!(u64::from(actual.state), hex(line, "state"));
            assert_eq!(u64::from(actual.protect), hex(line, "protection"));
            assert_eq!(u64::from(actual.kind), hex(line, "type"));
            assert!(p.vm.is_nls_view(view));
            p.modules.nt_services = Some((module, table(arch, "NtUnmapViewOfSection", 0x12)));
            assert_eq!(
                invoke(p, &mut thread, &[arch.ptr(u64::MAX), view + 4095]),
                Outcome::Continue
            );
            assert_eq!(thread.cpu.gpr(0), 0);
            assert_eq!(p.vm.committed_bytes(), charge);
            assert_eq!(p.vm.nls_view_count(), 0);
            ordinal += 1;
        }
        assert_eq!(ordinal, 12);
        cases += ordinal;
    }
    assert_eq!(cases, 72);
}

#[test]
fn native_nls_initialize_amd64_selection_does_not_admit_mui_or_missing_snapshot() {
    for build in [20348, 26100] {
        for arch in [WinArch::X64, WinArch::X86] {
            let (mut process, mut thread, base) = setup(arch, build);
            let p = process.state_mut();
            p.object_namespace.native_machine = Some(0x8664);
            assert!(p.nls.as_ref().unwrap().initialize().is_some());
            assert!(p.nls.as_ref().unwrap().mui().is_none());
            let charge = p.vm.committed_bytes();
            let count = p.vm.allocations().count();
            let module = p.modules.nt_services.as_ref().unwrap().0;
            p.modules.nt_services = Some((module, table(arch, "NtGetMUIRegistryInfo", 0x12)));
            assert!(matches!(invoke(p, &mut thread, &[0, base+256, base+288]),
                Outcome::Fail(ref reason) if reason.contains("native build profile is unmeasured")));
            p.modules.nt_services = Some((module, table(arch, "NtInitializeNlsFiles", 0x12)));
            p.nls = None;
            assert!(
                matches!(invoke(p, &mut thread, &[base+256, base+288, 0, 0]),
                Outcome::Fail(ref reason) if reason.contains("immutable initialization data was not selected"))
            );
            assert_eq!(p.space.bytes(base, 4096).unwrap(), vec![0xA5; 4096]);
            assert_eq!(p.vm.committed_bytes(), charge);
            assert_eq!(p.vm.allocations().count(), count);
        }
    }
}
