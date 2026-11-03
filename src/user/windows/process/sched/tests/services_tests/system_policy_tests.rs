//! Independent three-ABI pointer/guard arena replay for SystemPolicyInformation.
use super::*;
use serde::Deserialize;

#[path = "system_policy_tests/basic_abi.rs"]
mod basic_abi;

#[derive(Deserialize)]
struct Profile {
    pointer_bytes: u64,
    base_hex: String,
    input_hex: String,
}
#[derive(Deserialize)]
struct Case {
    index: u32,
    roles: [u32; 4],
    length: u32,
    status: String,
    exception: String,
    protections: [u32; 8],
    changes: Vec<(usize, String)>,
}

fn decode(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

fn prepare(p: &mut Proc, base: u64, packet: &[u8], case: &Case) -> (u64, u64, Vec<u8>) {
    p.vm.protect(base, 32768, prot::READWRITE).unwrap();
    p.space.wr(base, &vec![0xA5; 32768]).unwrap();
    let [d, input, output, returned] = case.roles;
    let (mut da, mut ia, mut oa, mut ra) = (128, 8192 + 128, 16384 + 128, 24576 + 128);
    let ptr = p.arch.ptr_size();
    let size_at = 2 * ptr;
    if d == 2 {
        da += 1;
    }
    if d >= 7 {
        da = 4096 - 12;
    }
    if input >= 6 {
        ia = 8192 + 4096 - 128;
    }
    if output == 2 {
        oa += 1;
    }
    if output >= 7 {
        oa = 16384 + 4096 - 128;
    }
    if output == 10 {
        oa = ia;
    }
    match returned {
        2 => ra += 1,
        7 => ra = da + size_at + 4,
        8 => ra = da,
        9 => ra = ia,
        10 => ra = oa,
        11 => ra = 24576 + 4094,
        _ => {}
    }
    let descriptor = if d == 1 { 0 } else { base + da };
    let input_ptr = if input == 1 { 0 } else { base + ia };
    let output_ptr = if output == 1 { 0 } else { base + oa };
    let returned_ptr = if returned == 1 { 0 } else { base + ra };
    p.space.wr(base + ia, packet).unwrap();
    if ptr == 4 {
        p.space.w32(base + da, input_ptr as u32).unwrap();
        p.space.w32(base + da + ptr, output_ptr as u32).unwrap();
    } else {
        p.space.w64(base + da, input_ptr).unwrap();
        p.space.w64(base + da + ptr, output_ptr).unwrap();
    }
    p.space
        .w32(
            base + da + size_at,
            if input == 5 { 0 } else { packet.len() as u32 },
        )
        .unwrap();
    p.space.w32(base + da + size_at + 4, 512).unwrap();
    p.space.w32(base + da + size_at + 8, 0).unwrap();
    p.space.w32(base + 24576 + 128, 0xFEEDFACE).unwrap();
    let mut expected = p.space.bytes(base, 32768).unwrap();
    for (at, bytes) in &case.changes {
        let bytes = decode(bytes);
        expected[*at..*at + bytes.len()].copy_from_slice(&bytes);
    }
    let mut page = |index: u64, flags| p.vm.protect(base + index * 4096, 4096, flags).unwrap();
    match d {
        3 => {
            page(0, prot::READONLY);
        }
        4 => {
            page(0, prot::NOACCESS);
        }
        5 => {
            page(0, prot::READWRITE | prot::GUARD);
        }
        6 => {
            page(0, prot::READONLY | prot::GUARD);
        }
        7 => {
            page(1, prot::NOACCESS);
        }
        8 => {
            page(1, prot::READONLY);
        }
        _ => {}
    }
    match input {
        2 => {
            page(2, prot::NOACCESS);
        }
        3 => {
            page(2, prot::READWRITE | prot::GUARD);
        }
        4 => {
            page(2, prot::READONLY | prot::GUARD);
        }
        6 => {
            page(3, prot::NOACCESS);
        }
        7 => {
            page(3, prot::READWRITE | prot::GUARD);
        }
        _ => {}
    }
    match output {
        3 => {
            page(4, prot::READONLY);
        }
        4 => {
            page(4, prot::NOACCESS);
        }
        5 => {
            page(4, prot::READWRITE | prot::GUARD);
        }
        6 => {
            page(4, prot::READONLY | prot::GUARD);
        }
        7 => {
            page(5, prot::NOACCESS);
        }
        8 => {
            page(5, prot::READWRITE | prot::GUARD);
        }
        9 => {
            page(5, prot::READONLY);
        }
        _ => {}
    }
    match returned {
        3 => {
            page(6, prot::READONLY);
        }
        4 => {
            page(6, prot::NOACCESS);
        }
        5 => {
            page(6, prot::READWRITE | prot::GUARD);
        }
        6 => {
            page(6, prot::READONLY | prot::GUARD);
        }
        11 => {
            page(7, prot::NOACCESS);
        }
        _ => {}
    }
    (descriptor, returned_ptr, expected)
}

#[test]
fn system_policy_replays_native_pointer_alias_and_guard_effects_on_all_abis() {
    let texts = [
        (
            WinArch::Arm64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-system-policy/pointer-arm64-v1.jsonl"
            )),
        ),
        (
            WinArch::X64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-system-policy/pointer-x64-v1.jsonl"
            )),
        ),
        (
            WinArch::X86,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-system-policy/pointer-x86-v1.jsonl"
            )),
        ),
    ];
    let mut count = 0;
    for (arch, text) in texts {
        let mut lines = text.lines();
        let head: Profile = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(head.pointer_bytes, arch.ptr_size());
        let base = u64::from_str_radix(&head.base_hex, 16).unwrap();
        let packet = decode(&head.input_hex);
        let (mut process, mut t, _) = query_fixture(arch);
        let p = process.state_mut();
        native_profile::kernel_profile(p, 29698, 0xAA64);
        p.native.as_mut().unwrap().policy_catalog =
            Ok(Arc::new(crate::user::windows::policy::Catalog::fixture([
                ("Kernel-BrandingInfo", 4, 48u32.to_le_bytes().to_vec()),
            ])));
        assert_eq!(
            p.vm.allocate(
                Some(base),
                32768,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE
            )
            .unwrap()
            .0,
            base
        );
        let sp = t.cpu.sp();
        for line in lines {
            let case: Case = serde_json::from_str(line).unwrap();
            assert_eq!(case.exception, "0x00000000");
            let label = format!("{arch}/{}/{:?}/{}", case.index, case.roles, case.length);
            let (descriptor, returned, expected) = prepare(p, base, &packet, &case);
            t.cpu.set_sp(sp);
            query_arguments(p, &mut t, 134, descriptor, case.length, returned);
            assert_eq!(dispatch_query(p, &mut t), Outcome::Continue, "{label}");
            assert_eq!(
                t.cpu.gpr(0),
                u64::from(u32::from_str_radix(case.status.trim_start_matches("0x"), 16).unwrap()),
                "{label}"
            );
            assert!(t.frames.is_empty(), "{label}");
            for (page, flags) in case.protections.into_iter().enumerate() {
                assert_eq!(
                    p.vm.query(base + page as u64 * 4096).unwrap().protect,
                    flags,
                    "{label} page{page}"
                );
            }
            p.vm.protect(base, 32768, prot::READWRITE).unwrap();
            let actual = p.space.bytes(base, 32768).unwrap();
            if actual != expected {
                let at = actual
                    .iter()
                    .zip(&expected)
                    .position(|(a, b)| a != b)
                    .unwrap();
                panic!(
                    "{label}: arena offset {at:#x}: actual={:#x}, native={:#x}",
                    actual[at], expected[at]
                );
            }
            count += 1;
        }
    }
    assert_eq!(count, 2496);
}
