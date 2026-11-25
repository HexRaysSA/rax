use super::*;
use crate::user::windows::loader::services::tests::named_table;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_DATATYPE_MISALIGNMENT, STATUS_INFO_LENGTH_MISMATCH,
    STATUS_INVALID_PARAMETER, STATUS_PIPE_BROKEN, STATUS_SUCCESS,
};
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

fn query_pipe(
    p: &mut Proc,
    t: &mut Thread,
    handle: u64,
    io: u64,
    output: u64,
    class: u32,
    length: u32,
    expected_status: u32,
    expected_size: u32,
) -> Vec<u8> {
    let width = p.arch.ptr_size();
    let expected = [0xa5; 128];
    p.space.wr(output, &expected).unwrap();
    p.space.wr(io, &expected[..2 * width as usize]).unwrap();
    assert_eq!(
        call(
            p,
            t,
            "NtQueryInformationFile",
            &[handle, io, output, length.into(), class.into()]
        ),
        expected_status,
        "{} class {class}",
        p.arch
    );
    if expected_status != STATUS_SUCCESS {
        assert_eq!(
            p.space.bytes(io, 2 * width as usize).unwrap(),
            expected[..2 * width as usize],
        );
    } else {
        assert_eq!(p.space.u32(io).unwrap(), STATUS_SUCCESS);
        assert_eq!(
            p.space.ptr(io + width, width).unwrap(),
            u64::from(expected_size)
        );
        // NPFS uses partial-width synchronous publication, unlike a native
        // class-14 current byte offset query.
        if width == 8 && class != 14 {
            assert_eq!(p.space.u32(io + 4).unwrap(), 0xa5a5_a5a5);
        }
    }
    let result = p.space.bytes(output, expected.len()).unwrap();
    assert_eq!(
        result[expected_size as usize..],
        expected[expected_size as usize..]
    );
    result[..expected_size as usize].to_vec()
}

fn pipe_local_words(bytes: Vec<u8>) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
        .collect()
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
    let meta = base + 512;
    let meta_io = base + 672;
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
    let local = |p: &mut Proc, t: &mut Thread, handle| {
        pipe_local_words(query_pipe(
            p,
            t,
            handle,
            meta_io,
            meta,
            24,
            40,
            STATUS_SUCCESS,
            40,
        ))
    };
    assert_eq!(
        local(p, &mut thread, reader),
        [0, 2, 1, 1, 4, 0, 4, 4, 2, 1],
    );

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
    assert_eq!(
        local(p, &mut thread, writer),
        [0, 2, 1, 1, 4, 0, 4, 4, 3, 0],
    );
    assert_eq!(
        query_pipe(
            p,
            &mut thread,
            reader,
            meta_io,
            meta,
            23,
            8,
            STATUS_SUCCESS,
            8
        ),
        [0; 8],
    );
    let reader_index = query_pipe(
        p,
        &mut thread,
        reader,
        meta_io,
        meta,
        6,
        8,
        STATUS_SUCCESS,
        8,
    );
    assert_ne!(reader_index, [0; 8]);
    assert_eq!(
        reader_index,
        query_pipe(
            p,
            &mut thread,
            writer,
            meta_io,
            meta,
            6,
            8,
            STATUS_SUCCESS,
            8
        ),
    );
    let reader_id = p.objects.id(reader).unwrap();
    let no_access = u64::from(p.objects.open_access(reader_id, false, 0).unwrap());
    for (class, length) in [(4, 40), (18, 104), (23, 8), (24, 40), (25, 16)] {
        query_pipe(
            p,
            &mut thread,
            no_access,
            meta_io,
            meta,
            class,
            length,
            STATUS_ACCESS_DENIED,
            0,
        );
    }
    p.objects.close(no_access).unwrap();
    let attributes_only = u64::from(p.objects.open_access(reader_id, false, 0x80).unwrap());
    assert_eq!(
        local(p, &mut thread, attributes_only),
        [0, 2, 1, 1, 4, 0, 4, 4, 3, 1],
    );
    p.objects.close(attributes_only).unwrap();
    query_pipe(
        p,
        &mut thread,
        reader,
        meta_io,
        meta,
        24,
        39,
        STATUS_INFO_LENGTH_MISMATCH,
        0,
    );
    query_pipe(
        p,
        &mut thread,
        reader,
        meta_io,
        meta + 4,
        25,
        16,
        STATUS_INVALID_PARAMETER,
        0,
    );
    if arch == WinArch::Arm64 {
        query_pipe(
            p,
            &mut thread,
            reader,
            meta_io,
            meta + 1,
            25,
            16,
            STATUS_DATATYPE_MISALIGNMENT,
            0,
        );
    }
    let child = p.objects.inherit_pipe_and_console_handles().unwrap();
    assert!(child.get(directory).is_none());
    assert_eq!(child.access(reader), p.objects.access(reader));
    assert_eq!(child.access(writer), p.objects.access(writer));
    let read_index = |objects: &crate::user::windows::objects::Objects| {
        let Some(Object::Pipe { end: Some(end), .. }) = objects.get(reader) else {
            unreachable!();
        };
        end.information().file_index.to_le_bytes()
    };
    assert_eq!(&read_index(&child)[..], reader_index.as_slice());

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
    assert_eq!(
        local(p, &mut thread, reader),
        [0, 2, 1, 1, 4, 4, 4, 4, 3, 1],
    );
    child.close(writer).unwrap();
    assert_eq!(
        local(p, &mut thread, reader),
        [0, 2, 1, 1, 4, 4, 4, 4, 4, 1],
    );
    let standard = query_pipe(
        p,
        &mut thread,
        reader,
        meta_io,
        meta,
        5,
        24,
        STATUS_SUCCESS,
        24,
    );
    assert_eq!(&standard[..8], &8u64.to_le_bytes());
    assert_eq!(&standard[8..16], &4u64.to_le_bytes());
    assert_eq!(&standard[16..], &[1, 0, 0, 0, 1, 0, 0, 0]);
    let all = query_pipe(
        p,
        &mut thread,
        reader,
        meta_io,
        meta,
        18,
        112,
        STATUS_SUCCESS,
        100,
    );
    assert_eq!(&all[..32], &[0; 32]);
    assert_eq!(&all[32..40], &[0x80, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&all[40..64], &standard);
    assert_eq!(&all[64..72], reader_index.as_slice());
    assert_eq!(&all[72..76], &[0; 4]);
    assert_eq!(&all[76..80], &0x120189u32.to_le_bytes());
    assert_eq!(&all[80..88], &4u64.to_le_bytes());
    assert_eq!(&all[88..100], &[0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
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
    assert_eq!(
        local(p, &mut thread, reader),
        [0, 2, 1, 1, 4, 0, 4, 4, 4, 1],
    );
    assert_eq!(p.space.u32(output + width).unwrap(), sentinel);
    assert_eq!(p.space.u32(io + 2 * width).unwrap(), sentinel);
}
