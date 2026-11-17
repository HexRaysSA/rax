use super::{fixture, registry_tests::call};
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::layout::offsets;
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;
use crate::user::windows::process::{Proc, RunStatus};
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
            _ => unreachable!(),
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
                &[child, 0, output, 48, 0]
            ),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.u64(output).unwrap(), 0);
    }
}
