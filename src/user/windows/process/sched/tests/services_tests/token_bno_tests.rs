//! Native pointer-bearing token records, including private isolated children.
use super::*;
use crate::user::windows::security::token::bno::Isolation;

fn select_bno(p: &mut Proc, value: Isolation) {
    p.objects.select_wnf_catalog(
        crate::user::windows::wnf::tests::empty_subject_catalog(false)
            .with_primary_token_bno(value),
    );
}

fn bno_destinations(p: &mut Proc, base: u64, role: u32) -> (u64, u64) {
    if role < 43 {
        return destinations(p, base, role);
    }
    let (mut output, mut returned) = destinations(p, base, 0);
    match role {
        43 => {
            output += PAGE_SIZE - 8;
            p.vm.protect(base + PAGE_SIZE * 2, PAGE_SIZE, prot::NOACCESS)
                .unwrap();
        }
        44 | 45 => {
            output += PAGE_SIZE - 16;
            let protection = if role == 44 {
                prot::NOACCESS
            } else {
                prot::READONLY
            };
            p.vm.protect(base + PAGE_SIZE * 2, PAGE_SIZE, protection)
                .unwrap();
        }
        46 => returned = output + 8,
        47 => returned = output + 16,
        48 => returned = output + p.arch.ptr_size(),
        49 => {
            output += PAGE_SIZE - 1;
            p.vm.protect(base + PAGE_SIZE * 2, PAGE_SIZE, prot::NOACCESS)
                .unwrap();
        }
        _ => panic!("unrecorded BNO pointer role"),
    }
    (output, returned)
}

fn bno_cells(
    p: &Proc,
    address: u64,
    output: u64,
    cells: &str,
    case: (&serde_json::Value, usize, &serde_json::Value),
) {
    assert_eq!(cells.len(), 64);
    let pointer = (output + 2 * p.arch.ptr_size()).to_le_bytes();
    for (i, pair) in cells.as_bytes().chunks_exact(2).enumerate() {
        if pair == b"??" {
            continue;
        }
        let expected = if pair[0] == b'@' {
            let index = usize::from(pair[1] - b'0');
            assert!(index < p.arch.ptr_size() as usize);
            pointer[index]
        } else {
            u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
        };
        assert_eq!(
            p.space.u8(address + i as u64).unwrap(),
            expected,
            "byte {i} at {address:#x}; case {case:?}"
        );
    }
}

#[test]
fn native_token_bno_replays_all_66720_queries_and_isolated_children() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-token-bno-isolation/cases.json"
    ))
    .unwrap();
    assert_eq!(corpus["total-calls"], 66720);
    let runs = corpus["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 16);
    let mut total = 0;
    for run in runs {
        let (arch, laa) = match run["profile"].as_str().unwrap() {
            "arm64" => (WinArch::Arm64, false),
            "x64" => (WinArch::X64, false),
            "x86" => (WinArch::X86, false),
            "x86-laa" => (WinArch::X86, true),
            _ => panic!("unrecorded profile"),
        };
        let prefix = run["prefix"].as_array().map(|values| {
            values
                .iter()
                .map(|v| u16::try_from(v.as_u64().unwrap()).unwrap())
                .collect()
        });
        let (mut process, mut thread, base, handles) = setup(arch, laa);
        let p = process.state_mut();
        select_bno(p, Isolation::new(prefix).unwrap());
        let rows = corpus["groups"][run["group"].as_u64().unwrap() as usize]["rows"]
            .as_array()
            .unwrap();
        assert_eq!(rows.len(), 4170);
        for (index, row) in rows.iter().enumerate() {
            let field = |name: &str| row[name].as_str().unwrap();
            let (output, returned) = bno_destinations(p, base, field("role").parse().unwrap());
            let token = handle(p, field("kind"), handles);
            let length = u32::from_str_radix(field("length"), 16).unwrap();
            let expected = u32::from_str_radix(field("status"), 16).unwrap();
            let last_error =
                thread.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
            p.space.w32(last_error, 0x7e11_abcd).unwrap();
            let (sp, rng, handles_before, objects) = (
                thread.cpu.sp(),
                p.rng,
                p.objects.handle_count(),
                p.objects.iter().count(),
            );
            assert_eq!(
                invoke(
                    p,
                    &mut thread,
                    &[token, 44, output, u64::from(length), returned]
                ),
                Outcome::Continue
            );
            assert_eq!(thread.cpu.gpr(0) as u32, expected, "{run}/{index}/{row}");
            assert_eq!(
                thread.cpu.sp(),
                sp + if arch == WinArch::X86 { 4 } else { 0 }
            );
            thread.cpu.set_sp(sp);
            assert!(thread.frames.is_empty());
            assert_eq!(p.rng, rng);
            assert_eq!(
                (p.objects.handle_count(), p.objects.iter().count()),
                (handles_before, objects)
            );
            assert_eq!(p.space.u32(last_error).unwrap(), 0x7e11_abcd);
            for (address, name) in [(output, "output-protect"), (returned, "returned-protect")] {
                if (base..base + PAGE_SIZE * 8).contains(&address) {
                    assert_eq!(
                        p.vm.query(address).unwrap().protect,
                        u32::from_str_radix(field(name), 16).unwrap()
                    );
                }
            }
            bno_cells(
                p,
                output,
                output,
                field("output-bytes-cells"),
                (run, index, row),
            );
            bno_cells(
                p,
                returned,
                output,
                field("return-bytes-cells"),
                (run, index, row),
            );
            total += 1;
        }
    }
    assert_eq!(total, 66720);
}

#[test]
fn native_token_bno_missing_capture_does_not_invent_disabled_isolation() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, base, handles) = setup(arch, false);
        let p = process.state_mut();
        let (output, returned) = destinations(p, base, 0);
        let result = invoke(p, &mut thread, &[handles[1], 44, output, 288, returned]);
        assert!(format!("{result:?}").contains("primary-token BNO isolation is not captured"));
        assert_eq!(p.space.u32(returned).unwrap(), 0xa5a5_a5a5);
        assert_eq!(p.space.u32(output).unwrap(), 0xa5a5_a5a5);
    }
}

#[cfg(windows)]
#[path = "token_bno_native_tests.rs"]
mod native;

#[test]
fn native_token_bno_complete_prefix_preserves_padding_and_trailing_bytes() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, base, handles) = setup(arch, false);
        let p = process.state_mut();
        for prefix in [
            None,
            Some(vec![]),
            Some(vec![65, 0x03a9, 0x4e2d]),
            Some(vec![65; 135]),
        ] {
            select_bno(p, Isolation::new(prefix.clone()).unwrap());
            let (output, returned) = destinations(p, base, 0);
            let output = output + 4; // Valid native ULONG alignment, even with 64-bit pointers.
            let width = arch.ptr_size() as usize;
            let header = 2 * width;
            let tail = prefix.as_ref().map_or(0, |p| (p.len() + 1) * 2);
            let required = header + tail;
            let mut expected = vec![0xa5; required + 4];
            let pointer = if prefix.is_some() {
                output + header as u64
            } else {
                0
            };
            expected[..width].copy_from_slice(&pointer.to_le_bytes()[..width]);
            expected[width] = u8::from(prefix.is_some());
            if let Some(prefix) = &prefix {
                for (index, unit) in prefix.iter().copied().chain(std::iter::once(0)).enumerate() {
                    expected[header + index * 2..header + index * 2 + 2]
                        .copy_from_slice(&unit.to_le_bytes());
                }
            }
            let sp = thread.cpu.sp();
            assert_eq!(
                invoke(
                    p,
                    &mut thread,
                    &[handles[1], 44, output, (required + 4) as u64, returned]
                ),
                Outcome::Continue
            );
            thread.cpu.set_sp(sp);
            assert_eq!(thread.cpu.gpr(0), 0);
            assert_eq!(p.space.u32(returned).unwrap(), required as u32);
            assert_eq!(p.space.bytes(output, required + 4).unwrap(), expected);
        }
    }
}

#[test]
fn native_token_bno_requires_a_primary_subject_and_keeps_impersonation_explicit() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, base, _) = setup(arch, false);
        let p = process.state_mut();
        p.objects.select_wnf_catalog(
            crate::user::windows::wnf::Catalog::default()
                .with_primary_token_bno(Isolation::new(None).unwrap()),
        );
        let (output, returned) = destinations(p, base, 0);
        let sp = thread.cpu.sp();
        let result = invoke(
            p,
            &mut thread,
            &[arch.ptr(u64::MAX - 3), 44, output, 288, returned],
        );
        assert!(format!("{result:?}").contains("primary-token subject is not captured"));
        thread.cpu.set_sp(sp);
        assert_eq!(p.space.u32(returned).unwrap(), 0xa5a5_a5a5);
        select_bno(p, Isolation::new(None).unwrap());
        let subject = crate::user::windows::security::Subject {
            statistics: None,
            attributes: None,
            user_attributes: 0,
            user: vec![],
            groups: vec![],
            restricted: vec![],
            app_container: true,
            privileges: vec![],
        };
        let id = p
            .objects
            .create(Object::ImpersonationToken(std::sync::Arc::new(subject)));
        let token = u64::from(p.objects.open_access(id, false, 8).unwrap());
        let result = invoke(p, &mut thread, &[token, 44, output, 288, returned]);
        assert!(format!("{result:?}").contains("impersonation-token class 44 is not captured"));
        thread.cpu.set_sp(sp);
        assert_eq!(p.space.u32(returned).unwrap(), 0xa5a5_a5a5);
        assert_eq!(
            invoke(p, &mut thread, &[token, 29, output, 4, returned]),
            Outcome::Continue
        );
        assert_eq!(p.space.u32(output).unwrap(), 1);
    }
}

#[path = "token_bno_copy_tests.rs"]
mod copy_boundaries;
