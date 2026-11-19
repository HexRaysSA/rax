use super::{fixture, registry_tests::call};
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::layout::offsets;
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{Object, PipeEnd};
use crate::user::windows::process::family::{ChildIo, Prepared};
use crate::user::windows::process::{Proc, RunStatus};
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

struct FixtureImage(PathBuf);

impl FixtureImage {
    fn new(arch: WinArch) -> Self {
        let (name, image): (_, &[u8]) = match arch {
            WinArch::Arm64 => (
                "arm64",
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/user/windows/bin/arm64/smoke.exe"
                )),
            ),
            WinArch::X64 => (
                "x64",
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/user/windows/bin/x64/smoke.exe"
                )),
            ),
            WinArch::X86 => (
                "x86",
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/user/windows/bin/x86/smoke.exe"
                )),
            ),
        };
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        let path = std::env::temp_dir().join(format!(
            "rax-process-family-{}-{name}-{}",
            std::process::id(),
            stamp.as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        let fixture = Self(path);
        std::fs::write(fixture.0.join("smoke.exe"), image).unwrap();
        fixture
    }
}

impl Drop for FixtureImage {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.0.join("smoke.exe"));
        let _ = std::fs::remove_dir(&self.0);
    }
}

fn unicode(p: &Proc, field: u64, address: u64, text: &str) -> u64 {
    let text: Vec<_> = text.encode_utf16().collect();
    let length = (text.len() * 2) as u16;
    p.space.w16(field, length).unwrap();
    p.space.w16(field + 2, length + 2).unwrap();
    p.space.w64(field + 8, address).unwrap();
    p.space.put_wstr(address, &text).unwrap();
    u64::from(length)
}

#[test]
fn wow64_wide_memory_replays_owned_process_handles_and_count_widths() {
    let (mut process, mut thread) = fixture(WinArch::X86, "NtWow64AllocateVirtualMemory64", 0x1f7);
    let p = process.state_mut();
    let version = &mut Arc::make_mut(&mut p.cfg).version;
    version.major = 10;
    version.minor = 0;
    version.build = 29708;
    crate::user::windows::process::wow64::initialize_test_profile(p, WinArch::Arm64.machine())
        .unwrap();
    let id = p
        .objects
        .iter()
        .find_map(|(id, object)| {
            matches!(object, Object::Process { pid, .. } if *pid == p.pid).then_some(id)
        })
        .unwrap();
    let handle = p.objects.open_access(id, false, 0x38).unwrap().into();
    let denied = p.objects.open_access(id, false, 0x1000).unwrap().into();
    let current = WinArch::X86.ptr(crate::user::windows::objects::CURRENT_PROCESS);

    let scratch =
        p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    let size = scratch + 8;
    let input = scratch + 16;
    let output = scratch + 24;
    let count = scratch + 32;
    let canary = 0x1122_3344_5566_7788;
    p.space.w64(size, 0x11d8).unwrap();
    let allocate = |process| {
        [
            process,
            scratch,
            0,
            0,
            size,
            mem::COMMIT.into(),
            prot::READWRITE.into(),
        ]
    };
    let allocate_name = "NtWow64AllocateVirtualMemory64";
    for (process, status) in [
        (current, STATUS_INVALID_HANDLE),
        (denied, STATUS_ACCESS_DENIED),
    ] {
        assert_eq!(
            call(p, &mut thread, allocate_name, &allocate(process)),
            status
        );
        assert_eq!(p.space.u64(scratch).unwrap(), 0);
        assert_eq!(p.space.u64(size).unwrap(), 0x11d8);
    }
    assert_eq!(
        call(p, &mut thread, allocate_name, &allocate(handle)),
        STATUS_SUCCESS
    );
    let target = p.space.u64(scratch).unwrap();
    assert_ne!(target, 0);
    assert_eq!(p.space.u64(size).unwrap(), 2 * PAGE_SIZE);

    p.space.w64(input, 0x6174_6164_2078_6172).unwrap();
    p.space.w64(count, canary).unwrap();
    assert_eq!(
        call(
            p,
            &mut thread,
            "NtWow64WriteVirtualMemory64",
            &[handle, target, 0, input, 8, 0, count]
        ),
        STATUS_SUCCESS
    );
    assert_eq!(p.space.u64(count).unwrap(), 8);
    assert_eq!(p.space.u64(target).unwrap(), p.space.u64(input).unwrap());
    assert_eq!(
        call(
            p,
            &mut thread,
            "NtWow64ReadVirtualMemory64",
            &[handle, target, 0, output, 8, 0, count]
        ),
        STATUS_SUCCESS
    );
    assert_eq!(p.space.u64(count).unwrap(), 8);
    assert_eq!(p.space.u64(output).unwrap(), p.space.u64(input).unwrap());

    for (name, address, buffer, limited) in [
        ("NtWow64ReadVirtualMemory64", target, output, denied),
        ("NtWow64WriteVirtualMemory64", target, input, denied),
    ] {
        for (process, status) in [
            (current, STATUS_INVALID_HANDLE),
            (limited, STATUS_ACCESS_DENIED),
        ] {
            p.space.w64(count, canary).unwrap();
            assert_eq!(
                call(
                    p,
                    &mut thread,
                    name,
                    &[process, address, 0, buffer, 8, 0, count]
                ),
                status
            );
            assert_eq!(p.space.u64(count).unwrap(), 0);
        }
    }

    p.space.w64(count, canary).unwrap();
    assert_eq!(
        call(
            p,
            &mut thread,
            "NtWriteVirtualMemory",
            &[current, target, input, 8, count]
        ),
        STATUS_SUCCESS
    );
    assert_eq!(p.space.u64(count).unwrap(), 0x1122_3344_0000_0008);
}

#[test]
fn native_process_family_creates_queries_resumes_and_signals_a_guest_child() {
    for arch in [WinArch::Arm64, WinArch::X64] {
        let image = FixtureImage::new(arch);
        let (mut process, mut thread) = fixture(arch, "NtCreateUserProcess", 0x12);
        let p = process.state_mut();
        Arc::make_mut(&mut p.cfg).drives.set('C', &image.0);
        let base =
            p.vm.allocate(
                None,
                3 * PAGE_SIZE,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap()
            .0;
        let parameters = base + PAGE_SIZE;
        let layout = offsets(arch);
        for field in [layout.pp_maximum_length, layout.pp_length] {
            p.space.w32(parameters + field, 0x500).unwrap();
        }
        p.space.w32(parameters + layout.pp_flags, 1).unwrap();
        let command = r#""C:\smoke.exe" "space and a λ""#;
        let first_string = base + 2 * PAGE_SIZE;
        let image_name = first_string + 256;
        unicode(
            p,
            parameters + layout.pp_command_line,
            first_string,
            command,
        );
        unicode(
            p,
            parameters + layout.pp_current_directory,
            first_string + 128,
            "C:\\",
        );
        let image_bytes = unicode(p, base + 0x240, image_name, "\\??\\C:\\smoke.exe");
        let env: Vec<_> = "RAX_CHILD=λ\0\0".encode_utf16().collect();
        p.space.put_wunits(first_string + 384, &env).unwrap();
        p.space
            .w64(parameters + layout.pp_environment, first_string + 384)
            .unwrap();
        p.space
            .w64(
                parameters + layout.pp_environment_size,
                (env.len() * 2) as u64,
            )
            .unwrap();
        let create = base + 0x60;
        let attributes = base + 0x100;
        let cid = base + 0x200;
        let image_info = base + 0x280;
        p.space.w64(create, 0x58).unwrap();
        p.space.w32(create + 16, 0x2000_0000).unwrap();
        let rows = [
            (0x20005, image_bytes, image_name),
            (0x10003, 16, cid),
            (6, 64, image_info),
        ];
        p.space.w64(attributes, 8 + 32 * rows.len() as u64).unwrap();
        for (index, (kind, size, value)) in rows.into_iter().enumerate() {
            let offset = attributes + 8 + index as u64 * 32;
            p.space.w64(offset, kind).unwrap();
            p.space.w64(offset + 8, size).unwrap();
            p.space.w64(offset + 16, value).unwrap();
        }
        let args = [
            base,
            base + 8,
            0x200_0000,
            0x200_0000,
            0,
            0,
            0x204,
            1,
            parameters,
            create,
            attributes,
        ];
        let read_end = PipeEnd::reader(4096);
        let write_end = read_end.prepare_writer().unwrap();
        write_end.finish_writer_open();
        let read_id = p.objects.create(Object::Pipe {
            end: Some(read_end),
            write: false,
        });
        let reader = u64::from(p.objects.open_access(read_id, true, 0x120189).unwrap());
        let write_id = p.objects.create(Object::Pipe {
            end: Some(write_end),
            write: true,
        });
        let writer = u64::from(p.objects.open_access(write_id, true, 0x120196).unwrap());
        p.space
            .w64(parameters + layout.pp_std_input, reader)
            .unwrap();
        let mut alias = args;
        alias[1] = alias[0];
        let count = p.objects.handle_count();
        assert_eq!(
            call(p, &mut thread, "NtCreateUserProcess", &alias),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(p.objects.handle_count(), count);
        Arc::make_mut(&mut p.cfg).host_filesystem = false;
        assert_eq!(
            call(p, &mut thread, "NtCreateUserProcess", &args),
            STATUS_ACCESS_DENIED
        );
        assert_eq!(p.objects.handle_count(), count);
        Arc::make_mut(&mut p.cfg).host_filesystem = true;
        assert_eq!(
            call(p, &mut thread, "NtCreateUserProcess", &args),
            STATUS_SUCCESS
        );
        assert_eq!(p.objects.handle_count(), count + 2);
        let child = p.space.u64(base).unwrap();
        let primary = p.space.u64(base + 8).unwrap();
        let child_pid = p.space.u64(cid).unwrap() as u32;
        let child_tid = p.space.u64(cid + 8).unwrap() as u32;
        assert_ne!(child_pid, p.pid);
        assert_ne!(child_tid, thread.tid);
        assert_eq!(p.space.u32(create + 8).unwrap(), 6);
        assert_eq!(p.space.u32(create + 52).unwrap(), 1);
        let child_params = p.space.u64(create + 40).unwrap();
        let child_peb = p.space.u64(create + 56).unwrap();
        assert_eq!(p.space.u16(image_info + 48).unwrap(), arch.machine());
        assert!(
            p.children
                .with_process(child_pid, |target| {
                    let ptr = target
                        .space
                        .u64(child_params + layout.pp_environment)
                        .unwrap();
                    assert_eq!(target.space.wunits(ptr, env.len()).unwrap(), env);
                    assert_eq!(target.threads[&child_tid].suspend, 1);
                    assert_eq!(target.parent_pid, p.pid);
                    assert_eq!(
                        target
                            .space
                            .u64(child_params + layout.pp_std_input)
                            .unwrap(),
                        reader
                    );
                    assert_eq!(target.objects.access(reader), Some(0x120189));
                    assert_eq!(target.objects.access(writer), Some(0x120196));
                })
                .is_some()
        );
        let output = base + 0x300;
        let returned = base + 0x3c0;
        assert_eq!(
            call(
                p,
                &mut thread,
                "NtQueryInformationProcess",
                &[child, 60, 0, 0, returned]
            ),
            STATUS_INFO_LENGTH_MISMATCH
        );
        let size = p.space.u32(returned).unwrap().into();
        assert_eq!(
            call(
                p,
                &mut thread,
                "NtQueryInformationProcess",
                &[child, 60, output, size, returned]
            ),
            STATUS_SUCCESS
        );
        let units = p.space.u16(output).unwrap() / 2;
        let pointer = p.space.u64(output + 8).unwrap();
        assert_eq!(
            String::from_utf16(&p.space.wunits(pointer, units.into()).unwrap()).unwrap(),
            command
        );
        assert_eq!(
            call(
                p,
                &mut thread,
                "NtQueryInformationProcess",
                &[child, 0, output, 48, 0]
            ),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.u64(output).unwrap(), u64::from(STATUS_PENDING));
        assert_eq!(p.space.u64(output + 8).unwrap(), child_peb);
        assert_eq!(p.space.u64(output + 32).unwrap(), u64::from(child_pid));
        assert_eq!(p.space.u64(output + 40).unwrap(), u64::from(p.pid));

        let address = child_params + layout.pp_show_window_flags;
        p.space.w32(returned, 7).unwrap();
        assert_eq!(
            call(
                p,
                &mut thread,
                "NtWriteVirtualMemory",
                &[child, address, returned, 4, returned + 8]
            ),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.u64(returned + 8).unwrap(), 4);
        assert_eq!(
            p.children
                .with_process(child_pid, |target| target.space.u32(address).unwrap()),
            Some(7)
        );
        assert_eq!(
            call(
                p,
                &mut thread,
                "NtWriteVirtualMemory",
                &[child, 0, returned, 4, returned + 8]
            ),
            STATUS_PARTIAL_COPY
        );
        assert_eq!(p.space.u64(returned + 8).unwrap(), 0);
        let query_only = p
            .objects
            .open_access(p.objects.id(child).unwrap(), false, 0x1000)
            .unwrap();
        assert_eq!(
            call(
                p,
                &mut thread,
                "NtWriteVirtualMemory",
                &[query_only.into(), address, returned, 4, 0]
            ),
            STATUS_ACCESS_DENIED
        );
        assert_eq!(
            call(
                p,
                &mut thread,
                "NtQueryInformationProcess",
                &[query_only.into(), 43, output, 96, returned]
            ),
            STATUS_SUCCESS
        );
        let name_len = p.space.u16(output).unwrap() / 2;
        let name_ptr = p.space.u64(output + 8).unwrap();
        assert_eq!(
            p.space.wunits(name_ptr, name_len.into()).unwrap(),
            "C:\\smoke.exe".encode_utf16().collect::<Vec<_>>()
        );
        let duplicate = |process| [process, writer, 0, 0, 0, 0, 1];
        assert_eq!(
            call(
                p,
                &mut thread,
                "NtDuplicateObject",
                &duplicate(query_only.into())
            ),
            STATUS_ACCESS_DENIED
        );
        assert_eq!(
            p.children
                .with_process(child_pid, |target| target.objects.get(writer).is_some()),
            Some(true)
        );
        assert_eq!(
            call(p, &mut thread, "NtDuplicateObject", &duplicate(child)),
            STATUS_SUCCESS
        );
        assert_eq!(
            p.children
                .with_process(child_pid, |target| target.objects.get(writer).is_none()),
            Some(true)
        );
        assert!(p.objects.get(writer).is_some());
        let vm_base = output;
        let vm_size = output + 8;
        p.space.w64(vm_base, 0).unwrap();
        p.space.w64(vm_size, PAGE_SIZE + 1).unwrap();
        let allocate = [
            child,
            vm_base,
            0,
            vm_size,
            mem::COMMIT.into(),
            prot::READWRITE.into(),
        ];
        let mut denied = allocate;
        denied[0] = query_only.into();
        assert_eq!(
            call(p, &mut thread, "NtAllocateVirtualMemory", &denied),
            STATUS_ACCESS_DENIED
        );
        assert_eq!(p.space.u64(vm_base).unwrap(), 0);
        assert_eq!(p.space.u64(vm_size).unwrap(), PAGE_SIZE + 1);
        assert_eq!(
            call(p, &mut thread, "NtAllocateVirtualMemory", &allocate),
            STATUS_SUCCESS
        );
        let guest_allocation = p.space.u64(vm_base).unwrap();
        assert_ne!(guest_allocation, 0);
        assert_eq!(p.space.u64(vm_size).unwrap(), PAGE_SIZE * 2);
        assert_eq!(
            p.children.with_process(child_pid, |target| target
                .space
                .u64(guest_allocation)
                .unwrap()),
            Some(0)
        );
        p.space.w64(returned, 0x12345678).unwrap();
        assert_eq!(
            call(
                p,
                &mut thread,
                "NtWriteVirtualMemory",
                &[child, guest_allocation, returned, 8, 0]
            ),
            STATUS_SUCCESS
        );
        assert_eq!(
            p.children.with_process(child_pid, |target| target
                .space
                .u64(guest_allocation)
                .unwrap()),
            Some(0x12345678)
        );
        thread.suspend = 1;
        let caller = thread.tid;
        p.threads.insert(caller, thread);
        let cancelled = AtomicBool::new(false);
        assert_eq!(process.run_slice(4, &cancelled), RunStatus::Blocked);
        let p = process.state_mut();
        let mut thread = p.threads.remove(&caller).unwrap();
        assert_eq!(
            call(p, &mut thread, "NtResumeThread", &[primary, returned]),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.u32(returned).unwrap(), 1);
        p.threads.insert(caller, thread);
        assert_eq!(process.run_slice(512, &cancelled), RunStatus::Blocked);
        let p = process.state_mut();
        let mut thread = p.threads.remove(&caller).unwrap();
        assert!(matches!(
            p.objects.get(child),
            Some(Object::Process {
                exit_code: Some(0),
                ..
            })
        ));
        assert!(matches!(
            p.objects.get(primary),
            Some(Object::Thread {
                exit_code: Some(0),
                ..
            })
        ));
        assert!(p.children.with_process(child_pid, |_| ()).is_none());
        p.space.w32(returned, 0x7b7b_7b7b).unwrap();
        assert_eq!(
            call(
                p,
                &mut thread,
                "NtQueryInformationProcess",
                &[query_only.into(), 43, output, 96, returned]
            ),
            STATUS_UNSUCCESSFUL
        );
        assert_eq!(p.space.u32(returned).unwrap(), 0x7b7b_7b7b);
        assert_eq!(
            call(p, &mut thread, "NtAllocateVirtualMemory", &allocate),
            STATUS_PROCESS_IS_TERMINATING
        );
        assert_eq!(
            call(p, &mut thread, "NtWaitForSingleObject", &[child, 0, 0]),
            STATUS_SUCCESS
        );
        assert_eq!(
            call(
                p,
                &mut thread,
                "NtQueryInformationProcess",
                &[child, 0, output, 64, returned]
            ),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.u32(returned).unwrap(), 64);
        assert_eq!(p.space.u64(output + 8).unwrap(), 0);
        assert_eq!(p.space.u64(output + 16).unwrap(), child_peb);
        assert_eq!(p.space.u64(output + 56).unwrap(), 4);
    }
}

#[test]
fn wow64_child_basic_information_keeps_pid_and_clears_peb_on_exit() {
    let image = FixtureImage::new(WinArch::X86);
    let file = File::open(image.0.join("smoke.exe")).unwrap();
    let (mut process, mut thread) = fixture(WinArch::X86, "NtQueryInformationProcess", 0x12);
    let p = process.state_mut();
    let config = p.cfg.as_ref().clone();
    let prepared = Prepared::spawn(p, config, &file, &[0; 4], 0, true, ChildIo::default()).unwrap();
    let info = prepared.info;
    let parent_pid = p.pid;
    assert_ne!(info.peb, 0);
    let handles = prepared.handles(&mut p.objects, 0x1000, 2).unwrap();
    let child = u64::from(handles.process);
    let primary = u64::from(handles.thread);
    let denied = u64::from(
        p.objects
            .open_access(p.objects.id(child).unwrap(), false, 0x10)
            .unwrap(),
    );
    prepared.install(p, handles);
    let base =
        p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    let output = base + 1;
    let returned = base + 64;
    p.space.wr(base, &[0xa5; 68]).unwrap();
    assert_eq!(
        call(
            p,
            &mut thread,
            "NtQueryInformationProcess",
            &[denied, 0, output, 24, returned]
        ),
        STATUS_ACCESS_DENIED
    );
    assert_eq!(p.space.bytes(base, 68).unwrap(), [0xa5; 68]);

    let caller = thread.tid;
    let cancelled = AtomicBool::new(false);
    for (exit_status, peb, flags) in [(STATUS_PENDING, info.peb as u32, 2), (0, 0, 6)] {
        let p = process.state_mut();
        for size in [24, 32] {
            p.space.wr(base, &[0xa5; 68]).unwrap();
            assert_eq!(
                call(
                    p,
                    &mut thread,
                    "NtQueryInformationProcess",
                    &[child, 0, output, size, returned]
                ),
                STATUS_SUCCESS
            );
            assert_eq!(p.space.u32(returned).unwrap(), size as u32);
            let record = output + if size == 32 { 4 } else { 0 };
            assert_eq!(p.space.u32(record).unwrap(), exit_status);
            assert_eq!(p.space.u32(record + 4).unwrap(), peb);
            assert_eq!(p.space.u32(record + 8).unwrap(), 1);
            assert_eq!(p.space.u32(record + 12).unwrap(), 0xa5a5_a5a5);
            assert_eq!(p.space.u32(record + 16).unwrap(), info.pid);
            assert_eq!(p.space.u32(record + 20).unwrap(), parent_pid);
            if size == 32 {
                assert_eq!(p.space.u32(output).unwrap(), 32);
                assert_eq!(p.space.u32(output + 28).unwrap(), flags);
            }
            assert_eq!(p.space.u8(base).unwrap(), 0xa5);
            assert_eq!(p.space.u8(output + size).unwrap(), 0xa5);
        }
        if exit_status == STATUS_PENDING {
            assert_eq!(
                call(p, &mut thread, "NtResumeThread", &[primary, returned]),
                STATUS_SUCCESS
            );
            assert_eq!(p.space.u32(returned).unwrap(), 1);
            thread.suspend = 1;
            p.threads.insert(caller, thread);
            assert_eq!(process.run_slice(512, &cancelled), RunStatus::Blocked);
            let p = process.state_mut();
            thread = p.threads.remove(&caller).unwrap();
            assert!(p.children.with_process(info.pid, |_| ()).is_none());
        }
    }
}

fn set_close_exception(
    p: &mut Proc,
    t: &mut super::Thread,
    process: u64,
    input: u64,
    len: u64,
) -> u32 {
    call(p, t, "NtSetInformationProcess", &[process, 71, input, len])
}

fn query_close_exception(
    p: &mut Proc,
    t: &mut super::Thread,
    process: u64,
    output: u64,
    len: u64,
    returned: u64,
) -> u32 {
    call(
        p,
        t,
        "NtQueryInformationProcess",
        &[process, 71, output, len, returned],
    )
}

#[test]
fn process_close_exception_information_replays_native_scalar_and_probe_order() {
    const SENTINEL: u32 = 0x4455_6677;
    for arch in [WinArch::Arm64, WinArch::X64, WinArch::X86] {
        let (mut process, mut t) = fixture(arch, "NtSetInformationProcess", 0x12);
        let p = process.state_mut();
        let self_handle = arch.ptr(u64::MAX);
        let self_thread = arch.ptr(u64::MAX - 1);
        let page =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let output = page + 16;
        let returned = page + 32;
        let high = arch.ptr(u64::MAX - 3);
        p.space.w32(returned, SENTINEL).unwrap();
        assert_eq!(
            query_close_exception(p, &mut t, self_handle, output, 4, returned),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.u32(output).unwrap(), 0);

        for input in [0, 1, 2, 0x8000_0000, u32::MAX, 0] {
            p.space.w32(page, input).unwrap();
            assert_eq!(
                set_close_exception(p, &mut t, self_handle, page, 4),
                STATUS_SUCCESS
            );
            assert_eq!(
                query_close_exception(p, &mut t, self_handle, output, 4, returned),
                STATUS_SUCCESS
            );
            assert_eq!(p.space.u32(output).unwrap(), u32::from(input != 0));
            assert_eq!(p.space.u32(returned).unwrap(), SENTINEL);
            // In the measured standalone process, the flag leaves these two
            // ordinary NtClose statuses independent of its value.
            assert_eq!(call(p, &mut t, "NtClose", &[0]), STATUS_INVALID_HANDLE);
        }

        let id = p.objects.create(Object::Process {
            pid: p.pid,
            exit_code: None,
        });
        for (grant, set_status, query_status) in [
            (0x0200, STATUS_SUCCESS, STATUS_ACCESS_DENIED),
            (0x0400, STATUS_ACCESS_DENIED, STATUS_SUCCESS),
            (0x1000, STATUS_ACCESS_DENIED, STATUS_SUCCESS),
            (0x2000, STATUS_ACCESS_DENIED, STATUS_ACCESS_DENIED),
            (0x0010_0000, STATUS_ACCESS_DENIED, STATUS_ACCESS_DENIED),
        ] {
            let handle = p.objects.open_access(id, false, grant).unwrap().into();
            p.space.w32(page, 1).unwrap();
            assert_eq!(set_close_exception(p, &mut t, handle, page, 4), set_status);
            p.space.w32(output, SENTINEL).unwrap();
            assert_eq!(
                query_close_exception(p, &mut t, handle, output, 4, returned),
                query_status
            );
            let expected = if query_status == STATUS_SUCCESS {
                1
            } else {
                SENTINEL
            };
            assert_eq!(p.space.u32(output).unwrap(), expected);
            assert_eq!(p.space.u32(returned).unwrap(), SENTINEL);
        }
        assert_eq!(
            set_close_exception(p, &mut t, self_thread, page, 4),
            STATUS_OBJECT_TYPE_MISMATCH
        );
        assert_eq!(
            query_close_exception(p, &mut t, self_thread, output, 4, returned),
            STATUS_OBJECT_TYPE_MISMATCH
        );
        assert_eq!(
            set_close_exception(p, &mut t, 0, 0, 4),
            STATUS_ACCESS_VIOLATION
        );
        assert_eq!(
            query_close_exception(p, &mut t, 0, 0, 4, returned),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            query_close_exception(p, &mut t, 0, output, 4, high),
            STATUS_ACCESS_VIOLATION
        );
        assert_eq!(
            query_close_exception(p, &mut t, self_handle, output, 4, returned + 1),
            STATUS_SUCCESS
        );
        assert_eq!(
            set_close_exception(p, &mut t, self_handle, page + 1, 0),
            STATUS_INFO_LENGTH_MISMATCH
        );
        assert_eq!(
            set_close_exception(p, &mut t, self_handle, page + 1, 3),
            STATUS_DATATYPE_MISALIGNMENT
        );
        assert_eq!(
            query_close_exception(p, &mut t, self_handle, output + 1, 3, high),
            STATUS_DATATYPE_MISALIGNMENT
        );
        let high_before_length = if arch == WinArch::X86 {
            STATUS_INFO_LENGTH_MISMATCH
        } else {
            STATUS_ACCESS_VIOLATION
        };
        assert_eq!(
            set_close_exception(p, &mut t, self_handle, high, 3),
            high_before_length
        );
        assert_eq!(
            query_close_exception(p, &mut t, 0, high, 3, returned),
            high_before_length
        );
        let high_before_handle = if arch == WinArch::X86 {
            STATUS_INVALID_HANDLE
        } else {
            STATUS_ACCESS_VIOLATION
        };
        assert_eq!(
            query_close_exception(p, &mut t, 0, high, 4, returned),
            high_before_handle
        );
    }
}

#[test]
fn process_close_exception_information_targets_live_owned_children() {
    let image = FixtureImage::new(WinArch::X86);
    let file = File::open(image.0.join("smoke.exe")).unwrap();
    let (mut process, mut t) = fixture(WinArch::X86, "NtSetInformationProcess", 0x12);
    let p = process.state_mut();
    let page =
        p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    let output = page + 16;
    let self_handle = p.arch.ptr(u64::MAX);
    p.space.w32(page, 2).unwrap();
    assert_eq!(
        set_close_exception(p, &mut t, self_handle, page, 4),
        STATUS_SUCCESS
    );

    let prepared = Prepared::spawn(
        p,
        p.cfg.as_ref().clone(),
        &file,
        &[0; 4],
        0,
        true,
        ChildIo::default(),
    )
    .unwrap();
    let handles = prepared.handles(&mut p.objects, 0x1200, 2).unwrap();
    let child = u64::from(handles.process);
    let primary = u64::from(handles.thread);
    prepared.install(p, handles);

    assert_eq!(
        query_close_exception(p, &mut t, child, output, 4, 0),
        STATUS_SUCCESS
    );
    assert_eq!(p.space.u32(output).unwrap(), 0);
    assert_eq!(
        set_close_exception(p, &mut t, child, page, 4),
        STATUS_SUCCESS
    );
    assert_eq!(
        query_close_exception(p, &mut t, child, output, 4, 0),
        STATUS_SUCCESS
    );
    assert_eq!(p.space.u32(output).unwrap(), 1);
    p.space.w32(page, 0).unwrap();
    assert_eq!(
        set_close_exception(p, &mut t, child, page, 4),
        STATUS_SUCCESS
    );
    assert_eq!(
        query_close_exception(p, &mut t, child, output, 4, 0),
        STATUS_SUCCESS
    );
    assert_eq!(p.space.u32(output).unwrap(), 0);
    assert_eq!(
        query_close_exception(p, &mut t, self_handle, output, 4, 0),
        STATUS_SUCCESS
    );
    assert_eq!(p.space.u32(output).unwrap(), 1);

    assert_eq!(
        call(p, &mut t, "NtResumeThread", &[primary, 0]),
        STATUS_SUCCESS
    );
    let caller = t.tid;
    t.suspend = 1;
    p.threads.insert(caller, t);
    assert_eq!(
        process.run_slice(512, &AtomicBool::new(false)),
        RunStatus::Blocked
    );
    let p = process.state_mut();
    let mut t = p.threads.remove(&caller).unwrap();
    p.space.w32(output, 0x4455_6677).unwrap();
    assert_eq!(
        query_close_exception(p, &mut t, child, output, 4, 0),
        STATUS_PROCESS_IS_TERMINATING
    );
    assert_eq!(p.space.u32(output).unwrap(), 0x4455_6677);
    assert_eq!(
        set_close_exception(p, &mut t, child, page, 4),
        STATUS_PROCESS_IS_TERMINATING
    );
}
