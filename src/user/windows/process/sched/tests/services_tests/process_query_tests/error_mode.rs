//! Shared NT/public error-mode state, transport and creator-capture boundaries.
use super::*;
use crate::user::windows::hle::{Api, Ctx, Flow, Item, Value};
use crate::user::windows::nt::status::*;
use std::collections::BTreeMap;

pub(super) struct Harness {
    pub process: super::super::super::super::super::WindowsProcess,
    pub thread: Thread,
    pub base: u64,
    pub roles: BTreeMap<&'static str, u64>,
}

impl Harness {
    pub fn new(arch: WinArch) -> Self {
        let (mut process, thread) = fixture(arch, "NtQueryInformationProcess", 0x19);
        let p = process.state_mut();
        let base =
            p.vm.allocate(
                None,
                6 * PAGE_SIZE,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap()
            .0;
        let id = p.objects.create(Object::Process {
            pid: p.pid,
            exit_code: None,
        });
        let mut roles = BTreeMap::from([
            ("pseudo", arch.ptr(u64::MAX)),
            ("thread", arch.ptr(u64::MAX - 1)),
            ("invalid", 0xdead),
        ]);
        for (role, grant) in [
            ("real-zero", 0),
            ("real-query", 0x1400),
            ("real-query-limited", 0x1000),
            ("real-set", 0x2200),
            ("real-set-limited", 0x2000),
            ("real-all", 0x1fffff),
        ] {
            roles.insert(
                role,
                u64::from(p.objects.open_access(id, false, grant).unwrap()),
            );
        }
        roles.insert(
            "event",
            u64::from(p.objects.insert(Object::Event {
                manual: false,
                signaled: 0,
            })),
        );
        Self {
            process,
            thread,
            base,
            roles,
        }
    }

    pub fn invoke(
        &mut self,
        setter: bool,
        handle: u64,
        buffer: u64,
        length: u32,
        returned: u64,
    ) -> u32 {
        let p = self.process.state_mut();
        let module = p.modules.nt_services.as_ref().unwrap().0;
        let (name, number) = if setter {
            ("NtSetInformationProcess", 0x1c)
        } else {
            ("NtQueryInformationProcess", 0x19)
        };
        p.modules.nt_services = Some((module, table(p.arch, name, number)));
        let values = [handle, 12, buffer, u64::from(length), returned];
        super::super::nls_tests::arguments(
            p,
            &mut self.thread,
            &values[..if setter { 4 } else { 5 }],
        );
        if p.arch != WinArch::Arm64 {
            self.thread.cpu.set_gpr(0, number.into());
        }
        let sp = self.thread.cpu.sp();
        let outcome = if p.arch == WinArch::X86 {
            crate::user::windows::process::services::wow64(p, &mut self.thread, 0x1234_0000)
        } else {
            handle_stop(p, &mut self.thread, stop(p.arch, number))
        };
        assert_eq!(outcome, Outcome::Continue);
        assert_eq!(self.thread.cpu.pc(), 0x1234_0004);
        assert_eq!(
            self.thread.cpu.sp(),
            sp + if p.arch == WinArch::X86 { 4 } else { 0 }
        );
        assert!(self.thread.frames.is_empty());
        self.thread.cpu.set_sp(sp);
        self.thread.cpu.gpr(0) as u32
    }

    pub fn public(&mut self, dll: &str, name: &str, value: Option<u32>) -> u32 {
        let api = export(dll, name, self.process.state().arch);
        assert_eq!(api.args.len(), usize::from(value.is_some()));
        let sp = self.thread.cpu.sp();
        if let Some(value) = value {
            match self.process.state().arch {
                WinArch::X86 => self.process.state().space.w32(sp + 4, value).unwrap(),
                WinArch::X64 => self.thread.cpu.set_gpr(1, u64::from(value)),
                WinArch::Arm64 => self.thread.cpu.set_gpr(0, u64::from(value)),
            }
        }
        let mut c = Ctx {
            p: self.process.state_mut(),
            t: &mut self.thread,
            api,
            entry_pc: 0,
            entry_sp: sp,
            ret_addr: 0,
            cursor: sp,
        };
        match (api.imp)(&mut c).unwrap() {
            Flow::Ret(Value::Int(value)) => value as u32,
            _ => panic!("scalar error-mode export"),
        }
    }
}

fn export(dll: &str, name: &str, arch: WinArch) -> &'static Api {
    let module = crate::user::windows::dll::find(dll).unwrap();
    let entry = module
        .exports
        .iter()
        .flat_map(|x| x.iter())
        .find(|x| x.name == name && x.archs.has(arch))
        .unwrap();
    let Item::Func(api) = &entry.item else {
        panic!("function export")
    };
    api
}

pub(super) fn fields(line: &str) -> BTreeMap<&str, &str> {
    line.split_whitespace()
        .map(|x| x.split_once('=').unwrap())
        .collect()
}
pub(super) fn number(raw: &str) -> u32 {
    u32::from_str_radix(raw, 16).unwrap()
}
pub(super) fn hex(raw: &str) -> Vec<u8> {
    raw.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn native_process_error_mode_replays_all_136_native_and_public_transitions() {
    let profiles = [
        (
            WinArch::Arm64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-process-error-mode/observations-arm64-29698-v1.log"
            )),
        ),
        (
            WinArch::X64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-process-error-mode/observations-x64-29698-v1.log"
            )),
        ),
        (
            WinArch::X86,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-process-error-mode/observations-x86-29698-v1.log"
            )),
        ),
        (
            WinArch::X86,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-process-error-mode/observations-x86-laa-29698-v1.log"
            )),
        ),
    ];
    let mut count = 0;
    for (arch, text) in profiles {
        let mut h = Harness::new(arch);
        for line in text.lines().filter(|l| l.starts_with("kind=mode")) {
            let row = fields(line);
            let value = number(row["value"]);
            let before = number(row["before"]);
            h.process.state_mut().error_mode.set_native(before);
            let error = h.thread.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
            h.process.state().space.w32(error, 0x12345678).unwrap();
            if row["api"] == "nt" {
                h.process.state().space.w32(h.base, value).unwrap();
                assert_eq!(
                    h.invoke(true, h.roles["pseudo"], h.base, 4, 0),
                    number(row["status"])
                );
            } else {
                assert_eq!(
                    h.public("kernel32.dll", "SetErrorMode", Some(value)),
                    number(row["previous"])
                );
            }
            assert_eq!(h.process.state().error_mode.native(), number(row["after"]));
            assert_eq!(
                h.public("kernelbase.dll", "GetErrorMode", None),
                number(row["public"])
            );
            assert_eq!(
                h.process.state().space.u32(error).unwrap(),
                number(row["last"])
            );
            assert_eq!(h.invoke(false, h.roles["pseudo"], h.base, 4, h.base + 8), 0);
            assert_eq!(
                h.process.state().space.u32(h.base).unwrap(),
                number(row["after"])
            );
            count += 1;
        }
    }
    assert_eq!(count, 136);
}

#[test]
fn native_process_error_mode_state_is_process_owned_and_public_exports_append_without_shadowing() {
    use crate::user::windows::hle::{Arg, Conv, args::stdcall_bytes};
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let other = Harness::new(arch);
        assert_eq!(h.process.state().error_mode.native(), 1);
        assert_eq!(h.public("kernel32.dll", "GetErrorMode", None), 0);
        for dll in ["kernel32.dll", "kernelbase.dll"] {
            let get = export(dll, "GetErrorMode", arch);
            let set = export(dll, "SetErrorMode", arch);
            assert_eq!(get.conv, Conv::Stdcall);
            assert!(get.args.is_empty());
            assert_eq!(set.conv, Conv::Stdcall);
            assert_eq!(set.args, [Arg::I32]);
            assert_eq!(stdcall_bytes(get.args), 0);
            assert_eq!(stdcall_bytes(set.args), 4);
            let names: Vec<_> = crate::user::windows::dll::find(dll)
                .unwrap()
                .exports
                .iter()
                .flat_map(|x| x.iter())
                .filter(|x| x.archs.has(arch))
                .map(|x| x.name)
                .collect();
            assert_eq!(&names[names.len() - 2..], ["GetErrorMode", "SetErrorMode"]);
        }
        assert_eq!(h.public("kernel32.dll", "SetErrorMode", Some(0x8007)), 0);
        assert_eq!(h.public("kernelbase.dll", "SetErrorMode", Some(0)), 0x8007);
        assert_eq!(h.public("kernel32.dll", "GetErrorMode", None), 4);
        assert_eq!(other.process.state().error_mode.native(), 1);
        h.process.state().space.w32(h.base, 0).unwrap();
        assert_eq!(h.invoke(true, h.roles["real-set"], h.base, 4, 0), 0);
        assert_eq!(h.public("kernel32.dll", "GetErrorMode", None), 1);
    }
}

#[cfg(windows)]
#[test]
fn native_process_error_mode_creator_capture_is_read_only_and_matches_public_native_getter() {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetErrorMode() -> u32;
    }
    // SAFETY: this independent native getter has no pointers or side effects.
    let before = unsafe { GetErrorMode() };
    let mut state = crate::user::windows::process::error_mode::State::select(true).unwrap();
    assert_eq!(state.public(), before);
    state.set_native(0xffffffff);
    state.set_public(0);
    // SAFETY: independent host observation proves guest-state mutation isolation.
    assert_eq!(unsafe { GetErrorMode() }, before);
}
