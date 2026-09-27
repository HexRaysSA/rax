//! All-ABI tests use real installed CRT trap origins and guest-authoritative cells.

use super::super::tests::{area, int, invoke, run, void};
use super::*;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::Item;
use crate::user::windows::memory::{mem, prot};

fn address(c: &Ctx, kind: RuntimeKind, index: usize) -> u64 {
    cell(c, kind, index).unwrap()
}
fn value(c: &Ctx, kind: RuntimeKind, index: usize) -> u64 {
    c.read_ptr(address(c, kind, index)).unwrap()
}
fn raw(c: &mut Ctx, kind: RuntimeKind, text: &str, wide: bool) -> u64 {
    let at = area(c);
    if wide {
        c.mem()
            .put_wstr(at, &text.encode_utf16().collect::<Vec<_>>())
            .unwrap();
    } else {
        c.mem().put_cstr(at, text.as_bytes()).unwrap();
    }
    c.mem()
        .wptr(
            address(c, kind, if wide { WCMDLN } else { ACMDLN }),
            c.psize(),
            at,
        )
        .unwrap();
    at
}
fn strings(c: &Ctx, base: u64, wide: bool) -> Vec<Vec<u16>> {
    let mut result = Vec::new();
    for index in 0..64 {
        let ptr = c.read_ptr(base + index * c.psize()).unwrap();
        if ptr == 0 {
            return result;
        }
        result.push(if wide {
            c.mem().wstr(ptr, 4096).unwrap()
        } else {
            c.mem()
                .cstr(ptr, 4096)
                .unwrap()
                .into_iter()
                .map(u16::from)
                .collect()
        });
    }
    panic!("test vector must terminate");
}
fn expected(values: &[&str]) -> Vec<Vec<u16>> {
    values
        .iter()
        .map(|value| value.encode_utf16().collect())
        .collect()
}

#[test]
fn binding_admission_does_not_promote_shims_or_arm_missing_data() {
    for arch in WinArch::ALL {
        let names = |exports: &[crate::user::windows::hle::Export]| -> Vec<&str> {
            exports
                .iter()
                .filter(|e| e.archs.has(arch))
                .map(|e| e.name)
                .collect()
        };
        let legacy = names(MSVCRT_STARTUP_EXPORTS);
        assert_eq!(legacy.contains(&"__p___argc"), arch == WinArch::X86);
        assert_eq!(legacy.contains(&"__p___initenv"), arch == WinArch::X86);
        assert_eq!(legacy.contains(&"_environ"), arch != WinArch::Arm64);
        assert_eq!(
            legacy.contains(&"?_query_new_mode@@YAHXZ"),
            arch != WinArch::Arm64
        );
        assert!(legacy.contains(&"?_set_new_mode@@YAHH@Z"));
        assert!(legacy.contains(&"__getmainargs"));
        assert!(
            UCRT_STARTUP_EXPORTS
                .iter()
                .all(|e| !matches!(e.item, Item::Data(_)))
        );
        assert!(!names(UCRT_STARTUP_EXPORTS).contains(&"__getmainargs"));
    }
}

#[test]
fn raw_guest_command_buffers_not_config_arguments_control_both_argv_widths() {
    run(|c| {
        let kind = RuntimeKind::Ucrt;
        raw(c, kind, r#""C:\two words\" a\\\"b "" last"#, false);
        assert_eq!(int(invoke(c, kind, "_configure_narrow_argv", &[1])), 0);
        assert_eq!(
            strings(c, value(c, kind, ARGV), false),
            expected(&[r"C:\two words\", r#"a\"b"#, "", "last"])
        );
        raw(c, kind, "wide \u{ff02}two words\u{ff02} \u{1f600}", true);
        assert_eq!(int(invoke(c, kind, "_configure_wide_argv", &[1])), 0);
        assert_eq!(
            strings(c, value(c, kind, WARGV), true),
            expected(&["wide", "\u{ff02}two", "words\u{ff02}", "\u{1f600}"])
        );
        assert_eq!(c.mem().u32(address(c, kind, ARGC)).unwrap(), 4);
    });
}

#[test]
fn configure_modes_and_same_mode_guest_mutations_are_runtime_local() {
    run(|c| {
        let kind = RuntimeKind::Ucrt;
        raw(c, kind, "p first", false);
        assert_eq!(int(invoke(c, kind, "_configure_narrow_argv", &[1])), 0);
        let original = value(c, kind, ARGV);
        let committed = c.p.vm.committed_bytes();
        c.mem().w32(address(c, kind, ARGC), 91).unwrap();
        c.mem()
            .wptr(address(c, kind, ARGV), c.psize(), 0x4321)
            .unwrap();
        assert_eq!(int(invoke(c, kind, "_configure_narrow_argv", &[1])), 0);
        assert_eq!(c.mem().u32(address(c, kind, ARGC)).unwrap(), 91);
        assert_eq!(value(c, kind, ARGV), 0x4321);
        assert_eq!(c.p.vm.committed_bytes(), committed);
        assert_eq!(int(invoke(c, kind, "_configure_narrow_argv", &[0])), 0);
        assert_eq!(value(c, kind, ARGV), 0);
        assert_eq!(c.mem().u32(address(c, kind, ARGC)).unwrap(), 0);
        raw(c, kind, "p changed tail", false);
        assert_eq!(int(invoke(c, kind, "_configure_narrow_argv", &[1])), 0);
        assert_ne!(value(c, kind, ARGV), original);
        assert_eq!(
            strings(c, value(c, kind, ARGV), false),
            expected(&["p", "changed", "tail"])
        );
        assert_eq!(
            c.mem().u32(address(c, RuntimeKind::Msvcrt, ARGC)).unwrap(),
            0
        );
    });
}

#[test]
fn initial_environment_snapshot_is_distinct_from_mutable_current_cells() {
    run(|c| {
        let kind = RuntimeKind::Ucrt;
        let initial = int(invoke(c, kind, "_get_initial_narrow_environment", &[]));
        assert_ne!(initial, 0);
        assert_eq!(initial, value(c, kind, ENVIRON));
        assert_eq!(
            int(invoke(c, kind, "_get_initial_wide_environment", &[])),
            0
        );
        assert_eq!(int(invoke(c, kind, "_initialize_wide_environment", &[])), 0);
        let wide = int(invoke(c, kind, "_get_initial_wide_environment", &[]));
        assert_ne!(wide, 0);
        assert_eq!(strings(c, initial, false), strings(c, wide, true));
        assert!(!strings(c, wide, true).is_empty());
        c.mem()
            .wptr(address(c, kind, ENVIRON), c.psize(), 0x1234)
            .unwrap();
        c.mem()
            .wptr(address(c, kind, WENVIRON), c.psize(), 0x5678)
            .unwrap();
        let committed = c.p.vm.committed_bytes();
        assert_eq!(
            int(invoke(c, kind, "_initialize_narrow_environment", &[])),
            0
        );
        assert_eq!(int(invoke(c, kind, "_initialize_wide_environment", &[])), 0);
        assert_eq!(value(c, kind, ENVIRON), 0x1234);
        assert_eq!(value(c, kind, WENVIRON), 0x5678);
        assert_eq!(
            int(invoke(c, kind, "_get_initial_narrow_environment", &[])),
            initial
        );
        assert_eq!(
            int(invoke(c, kind, "_get_initial_wide_environment", &[])),
            wide
        );
        assert_eq!(c.p.vm.committed_bytes(), committed);
        assert_ne!(initial, value(c, RuntimeKind::Msvcrt, ENVIRON));
    });
}

#[test]
fn modern_legacy_mainargs_writes_exact_widths_and_null_terminated_vectors() {
    run(|c| {
        let kind = RuntimeKind::Msvcrt;
        raw(c, kind, "different.exe \"two words\" tail", false);
        raw(c, kind, "wide.exe λ", true);
        let out = area(c);
        c.mem().wr(out, &[0xA5; 64]).unwrap();
        let info = out + 32;
        c.mem().w32(info, 1).unwrap();
        assert_eq!(
            int(invoke(
                c,
                kind,
                "__getmainargs",
                &[out, out + 8, out + 16, 0, info]
            )),
            0
        );
        assert_eq!(c.mem().u32(out).unwrap(), 3);
        assert_eq!(c.mem().u32(out + 4).unwrap(), 0xA5A5_A5A5);
        assert_eq!(
            strings(c, c.read_ptr(out + 8).unwrap(), false),
            expected(&["different.exe", "two words", "tail"])
        );
        assert_eq!(c.read_ptr(out + 16).unwrap(), value(c, kind, ENVIRON));
        assert_eq!(c.p.crt.runtimes[kind.index()].new_mode, 1);
        assert_eq!(
            int(invoke(
                c,
                kind,
                "__wgetmainargs",
                &[out, out + 8, out + 16, 0, info]
            )),
            0
        );
        assert_eq!(c.mem().u32(out).unwrap(), 2);
        assert_eq!(
            strings(c, c.read_ptr(out + 8).unwrap(), true),
            expected(&["wide.exe", "λ"])
        );
        assert_eq!(c.read_ptr(out + 16).unwrap(), value(c, kind, WENVIRON));
    });
}

#[test]
fn program_path_getters_read_current_cells_not_argv0_or_config() {
    run(|c| {
        let kind = RuntimeKind::Ucrt;
        let out = area(c);
        let initial = value(c, kind, PGMPTR);
        assert_eq!(int(invoke(c, kind, "_get_pgmptr", &[out])), 0);
        assert_eq!(c.read_ptr(out).unwrap(), initial);
        c.mem()
            .wptr(address(c, kind, PGMPTR), c.psize(), 0xA987)
            .unwrap();
        assert_eq!(int(invoke(c, kind, "_get_pgmptr", &[out])), 0);
        assert_eq!(c.read_ptr(out).unwrap(), 0xA987);
        c.mem()
            .wptr(address(c, kind, WPGMPTR), c.psize(), 0xB987)
            .unwrap();
        assert_eq!(int(invoke(c, kind, "_get_wpgmptr", &[out])), 0);
        assert_eq!(c.read_ptr(out).unwrap(), 0xB987);
    });
}

#[test]
fn winmain_tail_uses_program_quotes_and_control_padding_not_argument_reparse() {
    run(|c| {
        let kind = RuntimeKind::Ucrt;
        for wide in [false, true] {
            let text = "\"C:\\two words\\\"\t\r\n  \"arg with spaces\" tail";
            let base = raw(c, kind, text, wide);
            let suffix = "\"arg with spaces\" tail";
            let prefix = text.len() - suffix.len();
            let name = if wide {
                "_get_wide_winmain_command_line"
            } else {
                "_get_narrow_winmain_command_line"
            };
            assert_eq!(
                int(invoke(c, kind, name, &[])),
                base + (prefix * if wide { 2 } else { 1 }) as u64
            );
        }
        let page = area(c);
        c.mem().wr(page + PAGE_SIZE - 3, b"p x").unwrap();
        c.mem()
            .wptr(address(c, kind, ACMDLN), c.psize(), page + PAGE_SIZE - 3)
            .unwrap();
        assert_eq!(
            int(invoke(c, kind, "_get_narrow_winmain_command_line", &[])),
            page + PAGE_SIZE - 1
        );
    });
}

#[test]
fn checked_output_fault_precedes_mainargs_initialization_or_configuration() {
    run(|c| {
        let kind = RuntimeKind::Msvcrt;
        let info = area(c);
        c.mem().w32(info, 0).unwrap();
        let output = area(c);
        c.p.vm.protect(output, PAGE_SIZE, prot::READONLY).unwrap();
        let committed = c.p.vm.committed_bytes();
        let failure = invoke(
            c,
            kind,
            "__getmainargs",
            &[output, info + 8, info + 16, 0, info],
        );
        assert!(
            matches!(failure,Ok(Flow::RetryFault{fault:MemFault{addr,write:true},..}) if addr==output)
        );
        assert_eq!(c.p.vm.committed_bytes(), committed);
        assert_eq!(value(c, kind, ARGV), 0);
        assert_eq!(value(c, kind, WENVIRON), 0);
        assert_eq!(c.p.crt.runtimes[kind.index()].argv_modes, [None, None]);
    });
}

#[test]
fn new_mode_is_real_runtime_local_state_and_invalid_handler_is_called_once() {
    run(|c| {
        let kind = RuntimeKind::Ucrt;
        assert_eq!(int(invoke(c, kind, "_query_new_mode", &[])), 0);
        assert_eq!(int(invoke(c, kind, "_set_new_mode", &[1])), 0);
        assert_eq!(int(invoke(c, kind, "_query_new_mode", &[])), 1);
        assert_eq!(
            int(invoke(
                c,
                RuntimeKind::Msvcrt,
                "?_set_new_mode@@YAHH@Z",
                &[1]
            )),
            0
        );
        assert_eq!(int(invoke(c, kind, "_set_new_mode", &[0])), 1);
        assert_eq!(c.p.crt.runtimes[RuntimeKind::Msvcrt.index()].new_mode, 1);
        let handler = 0x1234_5678;
        assert_eq!(
            int(invoke(
                c,
                kind,
                "_set_invalid_parameter_handler",
                &[handler]
            )),
            0
        );
        let flow = invoke(c, kind, "_set_new_mode", &[u32::MAX as u64]).unwrap();
        let Flow::Call { target, args, then } = flow else {
            panic!("real guest handler continuation")
        };
        assert_eq!(target, handler);
        assert_eq!(args, [0; 5]);
        let errno = int(invoke(c, kind, "_errno", &[]));
        // Simulate callback mutation of errno permissions. The completion must
        // retain its frontier rather than recalling/clobbered-register handler.
        c.p.vm
            .protect(errno & !(PAGE_SIZE - 1), PAGE_SIZE, prot::READONLY)
            .unwrap();
        let Flow::RetryFault { fault, retry } = then(c, 0).unwrap() else {
            panic!("exact completion retry")
        };
        assert!(fault.write);
        c.p.vm
            .protect(errno & !(PAGE_SIZE - 1), PAGE_SIZE, prot::READWRITE)
            .unwrap();
        assert_eq!(int(retry(c, 0)), u64::from(u32::MAX));
        assert_eq!(c.mem().u32(errno).unwrap(), 22);
        assert_eq!(c.p.crt.runtimes[kind.index()].new_mode, 0);
    });
}

#[test]
fn invalid_configure_returns_einval_after_actual_handler_and_keeps_cells() {
    run(|c| {
        let kind = RuntimeKind::Ucrt;
        let handler = 0x1234;
        int(invoke(
            c,
            kind,
            "_set_invalid_parameter_handler",
            &[handler],
        ));
        let argc = c.mem().u32(address(c, kind, ARGC)).unwrap();
        let Flow::Call { target, then, .. } =
            invoke(c, kind, "_configure_wide_argv", &[3]).unwrap()
        else {
            panic!("handler")
        };
        assert_eq!(target, handler);
        assert_eq!(int(then(c, 0)), 22);
        assert_eq!(c.mem().u32(address(c, kind, ARGC)).unwrap(), argc);
        assert_eq!(value(c, kind, WARGV), 0);
        assert_eq!(c.p.crt.runtimes[kind.index()].argv_modes, [None, None]);
    });
}

#[test]
fn arm_void_environment_getters_do_not_manufacture_integer_return() {
    run(|c| {
        if c.arch() != WinArch::Arm64 {
            return;
        }
        let out = area(c);
        void(invoke(c, RuntimeKind::Msvcrt, "_get_environ", &[out]));
        assert_eq!(
            c.read_ptr(out).unwrap(),
            value(c, RuntimeKind::Msvcrt, ENVIRON)
        );
        void(invoke(c, RuntimeKind::Msvcrt, "_get_wenviron", &[out]));
        assert_eq!(c.read_ptr(out).unwrap(), 0);
    });
}

#[test]
fn exhausted_guest_commitment_reports_errno_and_releases_candidate_reservations() {
    run(|c| {
        // Establish both errno contexts before consuming the VM budget so the
        // expected failure is vector admission, not lazy context admission.
        let ucrt = RuntimeKind::Ucrt;
        let legacy = RuntimeKind::Msvcrt;
        let uerrno = int(invoke(c, ucrt, "_errno", &[]));
        let lerrno = int(invoke(c, legacy, "_errno", &[]));
        let out = area(c);
        c.mem().wr(out, &[0xA5; 32]).unwrap();
        let info = out + 64;
        c.mem().w32(info, 1).unwrap();
        let remaining = c.p.vm.commit_limit() - c.p.vm.committed_bytes();
        let filler =
            c.p.vm
                .allocate(None, remaining, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let allocations = c.p.vm.allocations().count();
        let committed = c.p.vm.committed_bytes();
        assert_eq!(committed, c.p.vm.commit_limit());
        assert_eq!(int(invoke(c, ucrt, "_configure_narrow_argv", &[1])), 12);
        assert_eq!(c.mem().u32(uerrno).unwrap(), 12);
        assert_eq!(value(c, ucrt, ARGV), 0);
        assert_eq!(c.p.crt.runtimes[ucrt.index()].argv_modes, [None, None]);
        assert_eq!(
            int(invoke(c, ucrt, "_initialize_wide_environment", &[])),
            u64::from(u32::MAX)
        );
        assert_eq!(value(c, ucrt, WENVIRON), 0);
        assert_eq!(
            int(invoke(
                c,
                legacy,
                "__wgetmainargs",
                &[out, out + 8, out + 16, 0, info]
            )),
            u64::from(u32::MAX)
        );
        let mut bytes = [0; 32];
        c.mem().rd(out, &mut bytes).unwrap();
        assert_eq!(bytes, [0xA5; 32]);
        assert_eq!(c.mem().u32(lerrno).unwrap(), 12);
        assert_eq!(value(c, legacy, WENVIRON), 0);
        assert_eq!(c.p.crt.runtimes[legacy.index()].new_mode, 0);
        assert_eq!(c.p.vm.committed_bytes(), committed);
        assert_eq!(c.p.vm.allocations().count(), allocations);
        assert!(c.p.failure.is_none());
        c.p.vm.release(filler).unwrap();
        assert_eq!(int(invoke(c, ucrt, "_configure_narrow_argv", &[1])), 0);
        assert_ne!(value(c, ucrt, ARGV), 0);
    });
}

#[test]
fn alternating_widths_do_not_publish_a_vector_with_the_other_widths_count() {
    run(|c| {
        for kind in [RuntimeKind::Msvcrt, RuntimeKind::Ucrt] {
            let units = "p \u{ff02}two words\u{ff02}"
                .encode_utf16()
                .collect::<Vec<_>>();
            let narrow = codepage::encode(&units);
            let a = area(c);
            let w = area(c);
            c.mem().put_cstr(a, &narrow).unwrap();
            c.mem().put_wstr(w, &units).unwrap();
            c.mem()
                .wptr(address(c, kind, ACMDLN), c.psize(), a)
                .unwrap();
            c.mem()
                .wptr(address(c, kind, WCMDLN), c.psize(), w)
                .unwrap();
            let out = area(c);
            c.mem().w32(out + 64, 0).unwrap();
            for _ in 0..4 {
                for wide in [false, true] {
                    if kind == RuntimeKind::Msvcrt {
                        let name = if wide {
                            "__wgetmainargs"
                        } else {
                            "__getmainargs"
                        };
                        assert_eq!(
                            int(invoke(
                                c,
                                kind,
                                name,
                                &[out, out + 8, out + 16, 0, out + 64]
                            )),
                            0
                        );
                    } else {
                        let name = if wide {
                            "_configure_wide_argv"
                        } else {
                            "_configure_narrow_argv"
                        };
                        assert_eq!(int(invoke(c, kind, name, &[1])), 0);
                    }
                    let argc = c.mem().u32(address(c, kind, ARGC)).unwrap();
                    let argv = value(c, kind, if wide { WARGV } else { ARGV });
                    assert_eq!(argc, if wide { 3 } else { 2 });
                    assert_eq!(
                        strings(c, argv, wide),
                        if wide {
                            expected(&["p", "\u{ff02}two", "words\u{ff02}"])
                        } else {
                            expected(&["p", "two words"])
                        }
                    );
                    assert_eq!(c.read_ptr(argv + u64::from(argc) * c.psize()).unwrap(), 0);
                }
            }
        }
    });
}

#[test]
fn raw_replaced_command_buffer_has_no_hidden_length_cap_and_faults_at_exact_frontier() {
    run(|c| {
        let kind = RuntimeKind::Ucrt;
        let length = 65_537usize;
        let command =
            c.p.vm
                .allocate(
                    None,
                    length as u64 + 3,
                    mem::RESERVE | mem::COMMIT,
                    prot::READWRITE,
                )
                .unwrap()
                .0;
        let mut bytes = vec![b'x'; length + 3];
        bytes[0] = b'p';
        bytes[1] = b' ';
        bytes[length + 2] = 0;
        c.mem().wr(command, &bytes).unwrap();
        c.mem()
            .wptr(address(c, kind, ACMDLN), c.psize(), command)
            .unwrap();
        assert_eq!(int(invoke(c, kind, "_configure_narrow_argv", &[1])), 0);
        let argv = value(c, kind, ARGV);
        assert_eq!(c.mem().u32(address(c, kind, ARGC)).unwrap(), 2);
        let argument = c.read_ptr(argv + c.psize()).unwrap();
        assert_eq!(c.mem().u8(argument + length as u64 - 1).unwrap(), b'x');
        assert_eq!(c.mem().u8(argument + length as u64).unwrap(), 0);
        // A changed mode forces a new scan. No vector is admitted when its
        // source has no terminator before an inaccessible page boundary.
        let page = area(c);
        c.mem().w16(page + PAGE_SIZE - 2, b'p' as u16).unwrap();
        c.mem()
            .wptr(address(c, kind, WCMDLN), c.psize(), page + PAGE_SIZE - 2)
            .unwrap();
        let owned = c.p.crt.runtimes[kind.index()]
            .startup
            .as_ref()
            .unwrap()
            .blocks
            .len();
        let failure = invoke(c, kind, "_configure_wide_argv", &[1]);
        assert!(
            matches!(failure,Ok(Flow::RetryFault{fault:MemFault{addr,write:false},..}) if addr==page+PAGE_SIZE)
        );
        assert_eq!(value(c, kind, WARGV), 0);
        assert_eq!(
            c.p.crt.runtimes[kind.index()]
                .startup
                .as_ref()
                .unwrap()
                .blocks
                .len(),
            owned
        );
    });
}

fn poison_formal_arguments(c: &mut Ctx) {
    for index in 0..5 {
        match c.arch() {
            WinArch::X86 => c.mem().w32(c.entry_sp + 4 + index as u64 * 4, 0).unwrap(),
            WinArch::X64 if index < 4 => c.t.cpu.set_gpr([1, 2, 8, 9][index], 0),
            WinArch::X64 => c.mem().w64(c.entry_sp + 8 + index as u64 * 8, 0).unwrap(),
            WinArch::Arm64 => c.t.cpu.set_gpr(index, 0),
        }
    }
}

#[test]
fn mainargs_output_repair_keeps_original_pointers_after_formal_args_are_clobbered() {
    run(|c| {
        let kind = RuntimeKind::Msvcrt;
        raw(c, kind, "original two", false);
        let out = area(c);
        let info = area(c);
        c.mem().w32(info, 1).unwrap();
        c.p.vm.protect(out, PAGE_SIZE, prot::READONLY).unwrap();
        let Flow::RetryFault { fault, retry } =
            invoke(c, kind, "__getmainargs", &[out, out + 8, out + 16, 0, info]).unwrap()
        else {
            panic!("captured invocation")
        };
        assert_eq!(fault.addr, out);
        assert!(fault.write);
        c.p.vm.protect(out, PAGE_SIZE, prot::READWRITE).unwrap();
        poison_formal_arguments(c);
        assert_eq!(int(retry(c, 0)), 0);
        assert_eq!(c.mem().u32(out).unwrap(), 2);
        assert_eq!(
            strings(c, c.read_ptr(out + 8).unwrap(), false),
            expected(&["original", "two"])
        );
        assert_eq!(c.read_ptr(out + 16).unwrap(), value(c, kind, ENVIRON));
        assert_eq!(c.p.crt.runtimes[kind.index()].new_mode, 1);
    });
}

#[test]
fn later_mainargs_source_repair_retains_already_read_startinfo_value() {
    run(|c| {
        let kind = RuntimeKind::Msvcrt;
        let page =
            c.p.vm
                .allocate(
                    None,
                    2 * PAGE_SIZE,
                    mem::RESERVE | mem::COMMIT,
                    prot::READWRITE,
                )
                .unwrap()
                .0;
        c.p.vm
            .protect(page + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
            .unwrap();
        c.mem().w8(page + PAGE_SIZE - 1, b'p').unwrap();
        c.mem()
            .wptr(address(c, kind, ACMDLN), c.psize(), page + PAGE_SIZE - 1)
            .unwrap();
        let out = area(c);
        c.mem().w32(out + 64, 1).unwrap();
        let Flow::RetryFault { fault, retry } = invoke(
            c,
            kind,
            "__getmainargs",
            &[out, out + 8, out + 16, 0, out + 64],
        )
        .unwrap() else {
            panic!("captured source frontier")
        };
        assert_eq!(fault.addr, page + PAGE_SIZE);
        assert!(!fault.write);
        c.p.vm
            .protect(page + PAGE_SIZE, PAGE_SIZE, prot::READWRITE)
            .unwrap();
        c.mem().w8(page + PAGE_SIZE, 0).unwrap();
        c.mem().w32(out + 64, 0).unwrap();
        poison_formal_arguments(c);
        assert_eq!(int(retry(c, 0)), 0);
        assert_eq!(c.mem().u32(out).unwrap(), 1);
        assert_eq!(
            strings(c, c.read_ptr(out + 8).unwrap(), false),
            expected(&["p"])
        );
        assert_eq!(c.p.crt.runtimes[kind.index()].new_mode, 1);
    });
}

#[test]
fn configure_checked_cell_repair_retains_nonzero_mode_after_arg_clobber() {
    run(|c| {
        let kind = RuntimeKind::Ucrt;
        raw(c, kind, "program original", false);
        let argc = address(c, kind, ARGC);
        c.p.vm
            .protect(argc & !(PAGE_SIZE - 1), PAGE_SIZE, prot::READONLY)
            .unwrap();
        let Flow::RetryFault { fault, retry } =
            invoke(c, kind, "_configure_narrow_argv", &[1]).unwrap()
        else {
            panic!("captured configure mode")
        };
        assert_eq!(fault.addr, argc);
        assert!(fault.write);
        c.p.vm
            .protect(argc & !(PAGE_SIZE - 1), PAGE_SIZE, prot::READWRITE)
            .unwrap();
        poison_formal_arguments(c);
        assert_eq!(int(retry(c, 0)), 0);
        assert_eq!(c.mem().u32(argc).unwrap(), 2);
        assert_eq!(
            strings(c, value(c, kind, ARGV), false),
            expected(&["program", "original"])
        );
    });
}

#[test]
fn later_stack_formal_repair_preserves_previously_decoded_arguments() {
    run(|c| {
        // ARM64's five formals are all register-valued; there is no analogous
        // late stack-formal read for this signature. Other repair tests cover it.
        if c.arch() == WinArch::Arm64 {
            return;
        }
        let kind = RuntimeKind::Msvcrt;
        raw(c, kind, "original two", false);
        let out = area(c);
        let info = area(c);
        c.mem().w32(info, 1).unwrap();
        // Establish the actual admitted API/trap origin at the original stack.
        assert_eq!(
            int(invoke(
                c,
                kind,
                "__getmainargs",
                &[out, out + 8, out + 16, 0, info]
            )),
            0
        );
        let old_sp = c.entry_sp;
        let stack =
            c.p.vm
                .allocate(
                    None,
                    2 * PAGE_SIZE,
                    mem::RESERVE | mem::COMMIT,
                    prot::READWRITE,
                )
                .unwrap()
                .0;
        c.entry_sp = stack + PAGE_SIZE - if c.arch() == WinArch::X86 { 20 } else { 40 };
        let inputs = [out, out + 8, out + 16, 0, info];
        for (index, &input) in inputs.iter().enumerate() {
            match c.arch() {
                WinArch::X86 => c
                    .mem()
                    .w32(c.entry_sp + 4 + index as u64 * 4, input as u32)
                    .unwrap(),
                WinArch::X64 if index < 4 => c.t.cpu.set_gpr([1, 2, 8, 9][index], input),
                WinArch::X64 => c
                    .mem()
                    .w64(c.entry_sp + 8 + index as u64 * 8, input)
                    .unwrap(),
                WinArch::Arm64 => unreachable!("register-only case returned above"),
            }
        }
        c.p.vm
            .protect(stack + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
            .unwrap();
        let Flow::RetryFault { fault, retry } = (c.api.imp)(c).unwrap() else {
            panic!("staged formal read")
        };
        assert_eq!(fault.addr, stack + PAGE_SIZE);
        assert!(!fault.write);
        c.p.vm
            .protect(stack + PAGE_SIZE, PAGE_SIZE, prot::READWRITE)
            .unwrap();
        poison_formal_arguments(c);
        // The fifth formal was inaccessible, not invented/captured. Repair its
        // real storage; earlier successful reads must retain their old values.
        c.mem().wptr(stack + PAGE_SIZE, c.psize(), info).unwrap();
        assert_eq!(int(retry(c, 0)), 0);
        assert_eq!(c.mem().u32(out).unwrap(), 2);
        assert_eq!(
            strings(c, c.read_ptr(out + 8).unwrap(), false),
            expected(&["original", "two"])
        );
        assert_eq!(c.p.crt.runtimes[kind.index()].new_mode, 1);
        c.entry_sp = old_sp;
    });
}

#[test]
fn completed_environment_stage_survives_later_argv_fault_without_duplicate_storage() {
    run(|c| {
        let kind = RuntimeKind::Msvcrt;
        let buffer =
            c.p.vm
                .allocate(
                    None,
                    2 * PAGE_SIZE,
                    mem::RESERVE | mem::COMMIT,
                    prot::READWRITE,
                )
                .unwrap()
                .0;
        c.mem().w16(buffer + PAGE_SIZE - 2, b'p' as u16).unwrap();
        c.p.vm
            .protect(buffer + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
            .unwrap();
        c.mem()
            .wptr(address(c, kind, WCMDLN), c.psize(), buffer + PAGE_SIZE - 2)
            .unwrap();
        let out = area(c);
        c.mem().wr(out, &[0xA5; 32]).unwrap();
        c.mem().w32(out + 64, 0).unwrap();
        let owned = c.p.crt.runtimes[kind.index()]
            .startup
            .as_ref()
            .unwrap()
            .blocks
            .len();
        let Flow::RetryFault { fault, retry } = invoke(
            c,
            kind,
            "__wgetmainargs",
            &[out, out + 8, out + 16, 0, out + 64],
        )
        .unwrap() else {
            panic!("source fault after environment stage")
        };
        assert_eq!(fault.addr, buffer + PAGE_SIZE);
        let env = value(c, kind, WENVIRON);
        assert_ne!(env, 0);
        assert_eq!(
            c.p.crt.runtimes[kind.index()]
                .startup
                .as_ref()
                .unwrap()
                .blocks
                .len(),
            owned + 1
        );
        let mut untouched = [0; 32];
        c.mem().rd(out, &mut untouched).unwrap();
        assert_eq!(untouched, [0xA5; 32]);
        c.p.vm
            .protect(buffer + PAGE_SIZE, PAGE_SIZE, prot::READWRITE)
            .unwrap();
        c.mem().w16(buffer + PAGE_SIZE, 0).unwrap();
        poison_formal_arguments(c);
        assert_eq!(int(retry(c, 0)), 0);
        assert_eq!(value(c, kind, WENVIRON), env);
        assert_eq!(c.read_ptr(out + 16).unwrap(), env);
        assert_eq!(
            c.p.crt.runtimes[kind.index()]
                .startup
                .as_ref()
                .unwrap()
                .blocks
                .len(),
            owned + 2
        );
        assert_eq!(
            strings(c, c.read_ptr(out + 8).unwrap(), true),
            expected(&["p"])
        );
    });
}

#[test]
fn completed_environment_stage_survives_argv_oom_without_duplicate_storage() {
    run(|c| {
        let kind = RuntimeKind::Msvcrt;
        let command = vec![b'p' as u16; 9000];
        let buffer =
            c.p.vm
                .allocate(
                    None,
                    ((command.len() + 1) * 2) as u64,
                    mem::RESERVE | mem::COMMIT,
                    prot::READWRITE,
                )
                .unwrap()
                .0;
        c.mem().put_wstr(buffer, &command).unwrap();
        c.mem()
            .wptr(address(c, kind, WCMDLN), c.psize(), buffer)
            .unwrap();
        let out = area(c);
        c.mem().wr(out, &[0xA5; 32]).unwrap();
        c.mem().w32(out + 64, 1).unwrap();
        let errno = int(invoke(c, kind, "_errno", &[]));
        let owned = c.p.crt.runtimes[kind.index()]
            .startup
            .as_ref()
            .unwrap()
            .blocks
            .len();
        // Leave one 4096-byte committed page for the small wide environment,
        // but not the 18002-byte command string plus argument-pointer header.
        let available = c.p.vm.commit_limit() - c.p.vm.committed_bytes();
        let filler =
            c.p.vm
                .allocate(
                    None,
                    available - PAGE_SIZE,
                    mem::RESERVE | mem::COMMIT,
                    prot::READWRITE,
                )
                .unwrap()
                .0;
        let allocations = c.p.vm.allocations().count();
        let mut retained_env = 0;
        for _ in 0..2 {
            assert_eq!(
                int(invoke(
                    c,
                    kind,
                    "__wgetmainargs",
                    &[out, out + 8, out + 16, 0, out + 64]
                )),
                u64::from(u32::MAX)
            );
            let env = value(c, kind, WENVIRON);
            assert_ne!(env, 0);
            if retained_env == 0 {
                retained_env = env;
            }
            assert_eq!(env, retained_env);
            assert_eq!(
                c.p.crt.runtimes[kind.index()]
                    .startup
                    .as_ref()
                    .unwrap()
                    .blocks
                    .len(),
                owned + 1
            );
            assert_eq!(c.p.vm.allocations().count(), allocations + 1);
            assert_eq!(c.p.vm.committed_bytes(), c.p.vm.commit_limit());
            assert_eq!(c.mem().u32(errno).unwrap(), 12);
            assert_eq!(value(c, kind, WARGV), 0);
            assert_eq!(c.p.crt.runtimes[kind.index()].new_mode, 0);
            let mut untouched = [0; 32];
            c.mem().rd(out, &mut untouched).unwrap();
            assert_eq!(untouched, [0xA5; 32]);
        }
        assert!(c.p.failure.is_none());
        c.p.vm.release(filler).unwrap();
        assert_eq!(
            int(invoke(
                c,
                kind,
                "__wgetmainargs",
                &[out, out + 8, out + 16, 0, out + 64]
            )),
            0
        );
        assert_eq!(value(c, kind, WENVIRON), retained_env);
        assert_eq!(c.read_ptr(out + 16).unwrap(), retained_env);
        assert_eq!(
            c.p.crt.runtimes[kind.index()]
                .startup
                .as_ref()
                .unwrap()
                .blocks
                .len(),
            owned + 2
        );
        assert_eq!(c.p.crt.runtimes[kind.index()].new_mode, 1);
    });
}
