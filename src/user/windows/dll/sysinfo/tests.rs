use super::*;

#[test]
fn rtl_version_reports_the_configured_version_for_both_records() {
    for arch in WinArch::ALL {
        let mut process = spawn(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let out = p.peb + 0x800;
        for size in [276, 284] {
            p.space.w32(out, size).unwrap();
            p.space.w8(out + u64::from(size), 0xA5).unwrap();
            assert_eq!(returned(call(p, &mut t, "RtlGetVersion", &[out])), 0);
            for (offset, value) in [
                (0, size),
                (4, p.cfg.version.major),
                (8, p.cfg.version.minor),
                (12, p.cfg.version.build),
                (16, 2),
            ] {
                assert_eq!(p.space.u32(out + offset).unwrap(), value);
            }
            assert_eq!(p.space.u16(out + 20).unwrap(), 0);
            if size == 284 {
                assert_eq!(p.space.u8(out + 282).unwrap(), p.cfg.version.product_type);
            }
            assert_eq!(p.space.u8(out + u64::from(size)).unwrap(), 0xA5);
        }
        p.space.w32(out, 20).unwrap();
        assert_eq!(
            returned(call(p, &mut t, "RtlGetVersion", &[out])),
            u64::from(STATUS_INVALID_PARAMETER)
        );
    }
}

#[test]
fn system_info_uses_guest_abi_and_virtual_address_bounds() {
    for arch in WinArch::ALL {
        let mut process = spawn(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let out = p.peb + 0x800;
        let width = arch.ptr_size();
        let tail = out + 8 + 3 * width;
        let read_ptr = |p: &Proc, offset| {
            if width == 4 {
                u64::from(p.space.u32(out + offset).unwrap())
            } else {
                p.space.u64(out + offset).unwrap()
            }
        };
        for (name, expected_arch) in [
            ("GetSystemInfo", arch),
            (
                "GetNativeSystemInfo",
                if arch == WinArch::X86 {
                    WinArch::X64
                } else {
                    arch
                },
            ),
        ] {
            p.space.w8(tail + 16, 0xA5).unwrap();
            call(p, &mut t, name, &[out]).unwrap();
            assert_eq!(
                p.space.u32(out).unwrap(),
                u32::from(expected_arch.processor_architecture())
            );
            assert_eq!(p.space.u32(out + 4).unwrap(), PAGE_SIZE as u32);
            assert_eq!(read_ptr(p, 8), p.vm.low());
            assert_eq!(read_ptr(p, 8 + width), p.vm.high() - 1);
            assert_eq!(read_ptr(p, 8 + 2 * width), 1);
            assert_eq!(p.space.u32(tail).unwrap(), 1);
            assert_eq!(
                p.space.u32(tail + 8).unwrap(),
                ALLOCATION_GRANULARITY as u32
            );
            assert_eq!(p.space.u8(tail + 16).unwrap(), 0xA5);
        }
    }
}

#[test]
fn legacy_processor_topology_reports_the_virtual_cpu_in_guest_layout() {
    use crate::user::windows::layout::offsets;
    for arch in WinArch::ALL {
        let mut process = spawn(arch);
        let p = process.state_mut();
        let mut t = p.threads.pop_first().unwrap().1;
        let last_error = t.teb + offsets(arch).teb_last_error;
        let output = p.peb + 0x800;
        let length = output - 4;
        let (stride, relationship) = if arch == WinArch::X86 {
            (24, 4)
        } else {
            (32, 8)
        };
        p.space.w32(length, 0).unwrap();
        assert_eq!(
            returned(call(
                p,
                &mut t,
                "GetLogicalProcessorInformation",
                &[0, length]
            )),
            0
        );
        assert_eq!(p.space.u32(last_error).unwrap(), ERROR_INSUFFICIENT_BUFFER);
        assert_eq!(u64::from(p.space.u32(length).unwrap()), 3 * stride);
        p.space.w8(output + 3 * stride, 0x5a).unwrap();
        assert_eq!(
            returned(call(
                p,
                &mut t,
                "GetLogicalProcessorInformation",
                &[output, length]
            )),
            1
        );
        for (index, relation) in [0, 1, 3].into_iter().enumerate() {
            let record = output + index as u64 * stride;
            assert_eq!(p.space.u32(record).unwrap(), 1);
            assert_eq!(p.space.u32(record + relationship).unwrap(), relation);
        }
        assert_eq!(p.space.u8(output + 3 * stride).unwrap(), 0x5a);
        assert_eq!(p.space.u32(last_error).unwrap(), ERROR_INSUFFICIENT_BUFFER);
    }
}

#[test]
fn shared_processor_features_match_hle_api_for_each_guest_cpu() {
    use crate::user::windows::layout::{KUSER_SHARED_DATA, kuser};
    for arch in WinArch::ALL {
        let mut process = spawn(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let mut present = 0;
        for feature in 0..64 {
            let api = returned(call(p, &mut t, "IsProcessorFeaturePresent", &[feature]));
            let shared = p
                .space
                .u8(KUSER_SHARED_DATA + kuser::PROCESSOR_FEATURES + feature)
                .unwrap();
            assert_eq!(u64::from(shared), api, "{arch}/feature {feature}");
            present += shared;
        }
        assert!(present > 0, "baseline guest CPU features must be visible");
        for feature in [64, 65, 127, 128, 191, 192, u64::from(u32::MAX)] {
            assert_eq!(
                returned(call(p, &mut t, "IsProcessorFeaturePresent", &[feature])),
                0,
                "{arch}/{feature}"
            );
        }
        assert!(
            p.space
                .w8(KUSER_SHARED_DATA + kuser::PROCESSOR_FEATURES, 0xFF)
                .is_err()
        );
    }
}
use crate::user::windows::hle::{Item, Value};
use crate::user::windows::process::{Proc, Thread, WindowsConfig, WindowsProcess};

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
    let mut config = WindowsConfig::new("sysinfo-test.exe", vec![]);
    config.seed = Some(1);
    config.arena_bytes = 64 << 20;
    WindowsProcess::spawn_image(config, image.to_vec()).unwrap()
}

fn call(p: &mut Proc, t: &mut Thread, name: &str, args: &[u64]) -> ApiResult {
    let api = EXPORTS
        .iter()
        .chain(SYSTEM_INFO_EXPORTS)
        .chain(TOPOLOGY_EXPORTS)
        .chain(NTDLL_VERSION_EXPORTS)
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

fn returned(result: ApiResult) -> u64 {
    match result {
        Ok(Flow::Ret(Value::Int(value))) => value,
        Ok(_) => panic!("expected an integer return"),
        Err(error) => panic!("expected an integer return, got {error:?}"),
    }
}

#[test]
fn file_time_counts_from_1601_in_hundred_nanoseconds() {
    // 11644473600 s between the epochs, times 10^7.
    assert_eq!(file_time(0, 0), Some(116_444_736_000_000_000));
    // 2020-01-01T00:00:00Z is Unix 1577836800.
    assert_eq!(file_time(1_577_836_800, 0), Some(132_223_104_000_000_000));
    // Sub-tick nanoseconds truncate: 999 ns is 9 ticks.
    assert_eq!(file_time(0, 999), Some(116_444_736_000_000_009));
    // Before 1601 has no FILETIME.
    assert_eq!(file_time(-11_644_473_601, 0), None);
}

#[test]
fn x86_features_follow_the_cpuid_model() {
    // A machine with CMPXCHG8B, MMX, SSE, SSE2, RDTSC, SSE3, SSSE3,
    // CMPXCHG16B, SSE4.1/4.2, XSAVE with OSXSAVE, AVX and AVX2.
    let edx1 = (1 << 4) | (1 << 8) | (1 << 23) | (1 << 25) | (1 << 26);
    let ecx1 = 1 | (1 << 9) | (1 << 13) | (1 << 19) | (1 << 20) | (1 << 26) | (1 << 27) | (1 << 28);
    let ebx7 = 1 << 5;
    let model = |leaf: u32, _sub: u32| match leaf {
        1 => (0, 0, ecx1, edx1),
        7 => (0, ebx7, 0, 0),
        _ => (0, 0, 0, 0),
    };
    for (feature, x64, want) in [
        (2, true, true),
        (3, true, true),
        (6, true, true),
        (7, true, false),
        (8, true, true),
        (10, true, true),
        (13, true, true),
        (14, true, true),
        (14, false, false),
        (17, true, true),
        (28, true, false),
        (36, true, true),
        (37, true, true),
        (38, true, true),
        (39, true, true),
        (40, true, true),
        (41, true, false),
        (23, true, true),
        (9, false, true),
        (12, false, true),
        (0, true, false),
        (64, true, false),
        (u32::MAX, true, false),
    ] {
        assert_eq!(
            x86_feature(feature, x64, model),
            want,
            "PF {feature}, x64 {x64}"
        );
    }
    // AVX without OSXSAVE is not usable, so neither is AVX2.
    let no_os = |leaf: u32, sub: u32| {
        let (a, b, c, d) = model(leaf, sub);
        (a, b, if leaf == 1 { c & !(1 << 27) } else { c }, d)
    };
    assert!(!x86_feature(39, true, no_os) && !x86_feature(40, true, no_os));
}

#[test]
fn arm64_features_are_the_baseline_and_the_implemented_extensions() {
    for feature in [18, 19, 23, 24, 25, 27, 29, 30, 31, 34] {
        assert!(arm64_feature(feature), "PF {feature}");
    }
    for feature in [2, 6, 10, 26, 39, 43, 64] {
        assert!(!arm64_feature(feature), "PF {feature}");
    }
}

#[test]
fn every_guest_answers_from_its_own_cpu() {
    for arch in WinArch::ALL {
        let mut process = spawn(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        assert_eq!(
            returned(call(p, &mut t, "IsProcessorFeaturePresent", &[23])),
            1,
            "{arch}: fast fail"
        );
        assert_eq!(
            returned(call(p, &mut t, "IsProcessorFeaturePresent", &[64])),
            0,
            "{arch}"
        );
        if let WinCpu::X86(cpu, _) = &t.cpu {
            // The guest's own CPUID.1:EDX bit 26 is what SSE2 reports.
            let sse2 = cpu.vcpu().cpuid(1, 0).3 & (1 << 26) != 0;
            assert_eq!(
                returned(call(p, &mut t, "IsProcessorFeaturePresent", &[10])),
                u64::from(sse2),
                "{arch}: SSE2"
            );
        }

        let out = p.vm.allocate(None, 0x1000, 0x3000, 0x04).unwrap().0;
        call(p, &mut t, "GetSystemTimeAsFileTime", &[out]).unwrap();
        let first = p.space.u64(out).unwrap();
        assert!(first >= 132_223_104_000_000_000, "{arch}: before 2020");
        call(p, &mut t, "GetSystemTimeAsFileTime", &[out]).unwrap();
        assert!(
            p.space.u64(out).unwrap() >= first,
            "{arch}: the clock went back"
        );
        assert!(
            matches!(
                call(p, &mut t, "GetSystemTimeAsFileTime", &[0x10]),
                Err(ApiErr::Fault(_))
            ),
            "{arch}: an unmapped output faults"
        );
    }
}
