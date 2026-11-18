use super::*;
use crate::user::windows::loader::services::tests::named_table;
use crate::user::windows::nt::status::{STATUS_PIPE_BROKEN, STATUS_SUCCESS};
use crate::user::windows::objects::Object;

fn invoke(p: &mut Proc, t: &mut Thread, name: &str, args: &[u64]) -> Outcome {
    let service = 0x33;
    let module = p.modules.nt_services.as_ref().unwrap().0;
    p.modules.nt_services = Some((module, named_table(p.arch, name, service)));
    if p.arch == WinArch::X86 {
        super::nls_tests::arguments(p, t, args);
        t.cpu.set_gpr(0, service.into());
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        super::nls_tests::arguments(p, t, &args[..args.len().min(8)]);
        for (index, value) in args.iter().skip(8).enumerate() {
            p.space.w64(t.cpu.sp() + index as u64 * 8, *value).unwrap();
        }
        handle_stop(p, t, stop(p.arch, service))
    }
}

fn call(p: &mut Proc, t: &mut Thread, name: &str, args: &[u64]) -> u32 {
    let sp = t.cpu.sp();
    assert_eq!(
        invoke(p, t, name, args),
        Outcome::Continue,
        "{} {name}",
        p.arch
    );
    let pop = if p.arch == WinArch::X86 { 4 } else { 0 };
    assert_eq!(t.cpu.sp(), sp + pop);
    assert!(t.frames.is_empty());
    t.cpu.set_sp(sp);
    t.cpu.gpr(0) as u32
}

#[test]
fn anonymous_pipe_routes_installed_io_and_inherits_its_endpoint() {
    for arch in [WinArch::Arm64, WinArch::X86] {
        check_anonymous_pipe(arch);
    }
}

fn check_anonymous_pipe(arch: WinArch) {
    let (mut process, mut thread) = fixture(arch, "NtOpenFile", 0x33);
    let p = process.state_mut();
    let width = arch.ptr_size();
    let base =
        p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    let object_attributes = base;
    let name = base + 48;
    let buffer = base + 64;
    let output = base + 192;
    let io = base + 208;
    let timeout = base + 232;
    let bytes = base + 256;
    let units: Vec<u16> = "\\Device\\NamedPipe\\".encode_utf16().collect();
    p.space.w32(object_attributes, 6 * width as u32).unwrap();
    p.space
        .wptr(object_attributes + 2 * width, width, name)
        .unwrap();
    p.space.w16(name, (units.len() * 2) as u16).unwrap();
    p.space.w16(name + 2, (units.len() * 2) as u16).unwrap();
    p.space.wptr(name + width, width, buffer).unwrap();
    p.space.put_wunits(buffer, &units).unwrap();
    let sentinel = 0xabc1_2345;
    p.space.w32(output + width, sentinel).unwrap();
    p.space.w32(io + 2 * width, sentinel).unwrap();
    assert_eq!(
        call(
            p,
            &mut thread,
            "NtOpenFile",
            &[output, 0x8010_0000, object_attributes, io, 3, 0x20]
        ),
        STATUS_SUCCESS,
    );
    let directory = p.space.ptr(output, width).unwrap();
    assert!(matches!(
        p.objects.get(directory),
        Some(Object::PipeDirectory)
    ));

    p.space.w16(name, 0).unwrap();
    p.space
        .wptr(object_attributes + width, width, directory)
        .unwrap();
    p.space.w32(object_attributes + 3 * width, 0x42).unwrap();
    p.space.w64(timeout, (-500_000i64) as u64).unwrap();
    assert_eq!(
        call(
            p,
            &mut thread,
            "NtCreateNamedPipeFile",
            &[
                output,
                0x8010_0100,
                object_attributes,
                io,
                3,
                2,
                0x20,
                0,
                0,
                0,
                1,
                4,
                4,
                timeout
            ]
        ),
        STATUS_SUCCESS,
    );
    let reader = p.space.ptr(output, width).unwrap();
    assert_eq!(p.space.ptr(io + width, width).unwrap(), 2);

    p.space
        .wptr(object_attributes + width, width, reader)
        .unwrap();
    assert_eq!(
        call(
            p,
            &mut thread,
            "NtOpenFile",
            &[output, 0x4010_0080, object_attributes, io, 3, 0x60]
        ),
        STATUS_SUCCESS,
    );
    let writer = p.space.ptr(output, width).unwrap();
    let child = p.objects.inherit_pipe_and_console_handles().unwrap();
    assert!(child.get(directory).is_none());
    assert_eq!(child.access(reader), p.objects.access(reader));
    assert_eq!(child.access(writer), p.objects.access(writer));

    p.space.wr(bytes, b"abcdefghijkl").unwrap();
    let Some(Object::Pipe {
        end: Some(read_end),
        ..
    }) = child.get(reader)
    else {
        unreachable!();
    };
    let sp = thread.cpu.sp();
    assert_eq!(
        invoke(
            p,
            &mut thread,
            "NtWriteFile",
            &[writer, 0, 0, 0, io, bytes, 12, 0, 0]
        ),
        Outcome::Park,
    );
    for (expected, outcome) in [(b"abcd", Outcome::Park), (b"efgh", Outcome::Continue)] {
        let ThreadState::Waiting(wait) = &thread.state else {
            unreachable!();
        };
        let wait = wait.clone();
        let now = crate::host::time::Instant::now();
        assert_eq!(sync::poll(p, thread.tid, &wait, now, false).unwrap(), None);
        assert_eq!(read_end.read(4).unwrap().unwrap(), expected);
        let ready = sync::poll(p, thread.tid, &wait, now, false)
            .unwrap()
            .unwrap();
        sync::on_cancel(p, thread.tid, &wait).unwrap();
        thread.state = ThreadState::Ready;
        assert_eq!(dispatch::wait_complete(p, &mut thread, ready), outcome);
    }
    let pop = if arch == WinArch::X86 { 4 } else { 0 };
    assert_eq!(thread.cpu.sp(), sp + pop);
    assert!(thread.frames.is_empty());
    thread.cpu.set_sp(sp);
    assert_eq!(thread.cpu.pc(), 0x1234_0004);
    assert_eq!(thread.cpu.gpr(0) as u32, STATUS_SUCCESS);
    assert_eq!(p.space.ptr(io + width, width).unwrap(), 12);
    assert_eq!(read_end.read(4).unwrap().unwrap(), b"ijkl");

    p.space.wr(bytes, b"rax!").unwrap();
    assert_eq!(
        call(
            p,
            &mut thread,
            "NtWriteFile",
            &[writer, 0, 0, 0, io, bytes, 4, 0, 0]
        ),
        STATUS_SUCCESS,
    );
    p.objects.close(writer).unwrap();
    let mut child = child;
    child.close(writer).unwrap();
    assert_eq!(
        call(
            p,
            &mut thread,
            "NtReadFile",
            &[reader, 0, 0, 0, io, bytes + 16, 4, 0, 0]
        ),
        STATUS_SUCCESS,
    );
    assert_eq!(p.space.bytes(bytes + 16, 4).unwrap(), b"rax!");
    assert_eq!(p.space.ptr(io + width, width).unwrap(), 4);
    assert_eq!(
        call(
            p,
            &mut thread,
            "NtReadFile",
            &[reader, 0, 0, 0, io, bytes + 16, 4, 0, 0]
        ),
        STATUS_PIPE_BROKEN,
    );
    assert_eq!(p.space.ptr(io + width, width).unwrap(), 0);
    assert_eq!(p.space.u32(output + width).unwrap(), sentinel);
    assert_eq!(p.space.u32(io + 2 * width).unwrap(), sentinel);
}
