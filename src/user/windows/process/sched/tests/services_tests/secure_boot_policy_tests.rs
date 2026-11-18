use super::*;
use crate::user::windows::native::{
    SECURE_BOOT_POLICY_BYTES, SYSTEM_SECURE_BOOT_POLICY_INFORMATION,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Capture {
    version: [u32; 3],
    machine: String,
    cases: Vec<Case>,
    aliases: Vec<Alias>,
}

#[derive(Deserialize)]
struct Case {
    length: u32,
    output: String,
    with_return: bool,
    poison: u8,
    status: u32,
    returned: u32,
    changed_offsets: Vec<usize>,
}

#[derive(Deserialize)]
struct Alias {
    length: u32,
    delta: i64,
    poison: u8,
    status: u32,
    copy_then_length: bool,
}

fn invoke(p: &mut Proc, t: &mut Thread, output: u64, length: u32, returned: u64) -> Outcome {
    query_arguments(
        p,
        t,
        SYSTEM_SECURE_BOOT_POLICY_INFORMATION,
        output,
        length,
        returned,
    );
    dispatch_query(p, t)
}

#[test]
fn native_secure_boot_policy_replays_sizes_probes_and_alias_order() {
    let oracle: Capture = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-secure-boot-policy/arm64-29708.json"
    )))
    .unwrap();
    assert_eq!(oracle.version, [10, 0, 29708]);
    assert_eq!(oracle.machine, "ARM64");
    assert_eq!((oracle.cases.len(), oracle.aliases.len()), (120, 84));
    let (mut process, mut t, base) = query_fixture(WinArch::Arm64);
    let p = process.state_mut();
    native_profile::kernel_profile(p, 29708, 0xAA64);
    let record = [0x37; SECURE_BOOT_POLICY_BYTES];
    p.native.as_mut().unwrap().secure_boot_policy = Ok(record);
    let return_address = base + 152;
    for case in oracle.cases {
        let mut expected = [case.poison; 152];
        p.space.wr(base, &expected).unwrap();
        p.space.w32(return_address, 0xDEAD_BEEF).unwrap();
        let output = match case.output.as_str() {
            "null" => 0,
            "aligned" => base,
            "misaligned" => base + 1,
            _ => panic!("unexpected native output role"),
        };
        let returned = if case.with_return { return_address } else { 0 };
        assert_eq!(
            invoke(p, &mut t, output, case.length, returned),
            Outcome::Continue
        );
        assert_eq!(t.cpu.gpr(0), u64::from(case.status));
        let bytes = p.space.bytes(base, expected.len()).unwrap();
        let changed: Vec<_> = bytes
            .iter()
            .enumerate()
            .filter_map(|(i, value)| (*value != case.poison).then_some(i))
            .collect();
        assert_eq!(changed, case.changed_offsets);
        if case.status == STATUS_SUCCESS {
            expected[..record.len()].copy_from_slice(&record);
        }
        assert_eq!(bytes, expected);
        assert_eq!(p.space.u32(return_address).unwrap(), case.returned);
    }
    for case in oracle.aliases {
        assert!(case.copy_then_length);
        let mut expected = [case.poison; 96];
        p.space.wr(base, &expected).unwrap();
        let alias = (16 + case.delta) as usize;
        assert_eq!(
            invoke(p, &mut t, base + 16, case.length, base + alias as u64),
            Outcome::Continue
        );
        assert_eq!(t.cpu.gpr(0), u64::from(case.status));
        if case.status == STATUS_SUCCESS {
            expected[16..16 + record.len()].copy_from_slice(&record);
        }
        expected[alias..alias + 4].copy_from_slice(&(record.len() as u32).to_le_bytes());
        assert_eq!(p.space.bytes(base, expected.len()).unwrap(), expected);
    }
}

#[test]
fn native_secure_boot_policy_requires_a_captured_matching_snapshot() {
    let (mut process, mut t, base) = query_fixture(WinArch::Arm64);
    let p = process.state_mut();
    assert!(
        matches!(invoke(p, &mut t, base, 24, base + 96), Outcome::Fail(reason)
        if reason.contains("requires selected native inputs"))
    );
    native_profile::kernel_profile(p, 29708, 0xAA64);
    assert!(
        matches!(invoke(p, &mut t, base, 24, base + 96), Outcome::Fail(reason)
        if reason.contains("not captured"))
    );
    for (build, machine) in [(29704, 0xAA64), (29708, 0x8664)] {
        native_profile::kernel_profile(p, build, machine);
        p.native.as_mut().unwrap().secure_boot_policy = Ok([0x37; SECURE_BOOT_POLICY_BYTES]);
        assert!(
            matches!(invoke(p, &mut t, base, 24, base + 96), Outcome::Fail(reason)
            if reason.contains("copy profile is unmeasured"))
        );
        assert_eq!(p.space.bytes(base, 128).unwrap(), [0xA5; 128]);
    }
}
