//! Provider configuration on the measured installed 29708 ARM64 and WoW64 profiles.
use super::*;

const CANARY: u32 = 0xA5A5_A5A5;

#[derive(serde::Deserialize)]
struct Fixture {
    build: u32,
    machine: u16,
    observations: std::collections::BTreeMap<String, Observation>,
}

#[derive(serde::Deserialize)]
struct Observation {
    status: u32,
    returned: u32,
    output: Option<String>,
}

fn options(p: &Proc, handle: u64) -> (Option<u8>, Option<bool>) {
    match p.objects.get(handle) {
        Some(Object::EtwRegistration {
            binary_tracking_class,
            descriptor_type,
            ..
        }) => (*binary_tracking_class, *descriptor_type),
        other => panic!("expected ETW registration, found {other:?}"),
    }
}

#[test]
fn native_etw_provider_configuration_replays_owned_registration_controls() {
    let evidence: Fixture = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-etw-provider-configuration/requests-29708-arm64.json"
    ))
    .unwrap();
    assert_eq!(evidence.observations.len(), 37);
    replay(WinArch::Arm64, evidence);
}

#[test]
fn wow64_etw_provider_configuration_replays_owned_registration_controls() {
    let evidence: Fixture = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-etw-provider-configuration/requests-29708-wow64-x86.json"
    ))
    .unwrap();
    assert_eq!(evidence.observations.len(), 37);
    replay(WinArch::X86, evidence);
}

fn replay(arch: WinArch, evidence: Fixture) {
    let (mut process, mut thread) = fixture(arch, "NtTraceControl", SERVICE);
    let p = process.state_mut();
    super::super::native_profile::kernel_profile(p, evidence.build, evidence.machine);
    if arch == WinArch::X86 {
        for function in [26, 31, 47] {
            assert!(matches!(
                call(p, &mut thread, [function, 0, 0, 0, 0, 0]),
                Outcome::Fail(message) if message.contains(&format!("NtTraceControl function {function}"))
            ));
        }
        let version = &mut std::sync::Arc::make_mut(&mut p.cfg).version;
        version.major = 10;
        version.minor = 0;
        version.build = evidence.build;
        crate::user::windows::process::wow64::initialize_test_profile(p, evidence.machine).unwrap();
    }
    let input = scratch(p, 1);
    let output = input + 32;
    let returned = input + 64;
    let event = u64::from(p.objects.insert(Object::Event {
        manual: false,
        signaled: 0,
    }));
    for (name, observed) in evidence.observations {
        let (function, case) = name.split_once('_').unwrap();
        let function: u64 = function.parse().unwrap();
        let handle = u64::from(p.objects.register_etw_provider(Box::new(header())).unwrap());
        let width = if function == 31 { 16 } else { 8 };
        let target = match case {
            "event_handle" | "bad_boolean_with_event" => event,
            "zero_handle" | "long" => 0,
            _ => handle,
        };
        let selector = match case {
            "off" => 0,
            "noncanonical_boolean" | "bad_boolean_with_event" => 2,
            _ => 1,
        };
        let mut request = [0; 17];
        request[..8].copy_from_slice(&target.to_le_bytes());
        request[8] = selector;
        if case == "tail_padding" {
            request[9..16].fill(0xdb);
        }
        p.space.wr(input, &request).unwrap();
        p.space.w32(returned, CANARY).unwrap();
        p.space.wr(output, &[0xa5; 8]).unwrap();
        p.space.w32(returned + 4, CANARY).unwrap();
        let (out, out_len) = match case {
            "len_without_output_ptr" => (0, 8),
            "ptr_without_output_len" => (output, 0),
            "output" => (output, 8),
            _ => (0, 0),
        };
        let args = [
            function,
            if case == "null_input" { 0 } else { input },
            match case {
                "short" => width - 1,
                "long" => width + 1,
                _ => width,
            },
            out,
            out_len,
            if case == "no_return" { 0 } else { returned },
        ];
        if case == "repeat" {
            check(p, &mut thread, args, STATUS_SUCCESS.into());
            p.space.w32(returned, CANARY).unwrap();
        }
        check(p, &mut thread, args, observed.status.into());
        assert_eq!(p.space.u32(returned).unwrap(), observed.returned, "{name}");
        assert_eq!(p.space.u32(returned + 4).unwrap(), CANARY, "{name}");
        assert_eq!(p.space.bytes(input, 17).unwrap(), request, "{name}");
        let output_bytes = observed
            .output
            .as_ref()
            .map_or_else(|| vec![0xa5; 8], |s| hex(s));
        assert_eq!(p.space.bytes(output, 8).unwrap(), output_bytes, "{name}");
        let expected = match (observed.status, function) {
            (STATUS_SUCCESS, 26) => (Some(0), None),
            (STATUS_SUCCESS, 31) => (None, Some(selector == 1)),
            (STATUS_SUCCESS, 47) => (Some(4), None),
            _ => (None, None),
        };
        assert_eq!(options(p, handle), expected, "{name}");
        p.objects.close(handle).unwrap();
    }
}

#[test]
fn native_etw_provider_configuration_is_process_local_and_captures_before_copyout() {
    let (mut process, mut thread) = fixture(WinArch::Arm64, "NtTraceControl", SERVICE);
    let p = process.state_mut();
    let input = scratch(p, 1);
    let handle = u64::from(p.objects.register_etw_provider(Box::new(header())).unwrap());
    p.space.w64(input, handle).unwrap();
    p.space.w64(input + 8, 1).unwrap();
    let descriptor = [31, input, 16, 0, 0, input];
    let unsupported = call(p, &mut thread, descriptor);
    assert!(matches!(unsupported, Outcome::Fail(s) if s.contains("NtTraceControl function 31")));
    assert_eq!(options(p, handle), (None, None));
    super::super::native_profile::kernel_profile(p, 29708, 0xaa64);
    check(
        p,
        &mut thread,
        [47, input, 8, 0, 0, input + 24],
        STATUS_SUCCESS.into(),
    );
    check(p, &mut thread, descriptor, STATUS_SUCCESS.into());
    assert_eq!(p.space.u32(input).unwrap(), 0);
    assert_eq!(options(p, handle), (Some(4), Some(true)));
    p.space.w64(input, handle).unwrap();
    p.space.w64(input + 8, 0).unwrap();
    check(p, &mut thread, descriptor, STATUS_SUCCESS.into());
    assert_eq!(options(p, handle), (Some(4), Some(false)));
    p.objects.close(handle).unwrap();
    let next = u64::from(p.objects.register_etw_provider(Box::new(header())).unwrap());
    assert_eq!(options(p, next), (None, None));
}
