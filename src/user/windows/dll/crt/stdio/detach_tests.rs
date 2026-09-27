//! Selected SDK retail `_flushall` semantics, not a native-ordering oracle.
//! Every case uses the shared x86/x64/ARM64 checked-guest-memory fixture.

use super::storage::Direction;
use super::tests::{File, attach, clobber_formals, retry};
use super::*;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::dll::crt::tests::{area, int, invoke, run};
use crate::user::windows::hle::{Flow, Value};
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::objects::Object;
use std::cell::Cell;
use std::rc::Rc;

fn finish(value: u64) -> Cont {
    Box::new(move |_, _| Flow::ret(value))
}

fn queue(c: &mut Ctx, kind: RuntimeKind, file: u64, bytes: &[u8]) {
    let source = area(c);
    c.mem().wr(source, bytes).unwrap();
    assert_eq!(
        int(invoke(
            c,
            kind,
            "fwrite",
            &[source, 1, bytes.len() as u64, file]
        )),
        bytes.len() as u64
    );
}

#[test]
fn detach_flushes_only_initialized_ucrt_and_keeps_streams_and_handles_open_all_abis() {
    run(|c| {
        let (legacy, legacy_handle) = File::new(c, &[]);
        let (_, legacy_file) = attach(
            c,
            RuntimeKind::Msvcrt,
            legacy_handle,
            (O_BINARY | 2) as u64,
            b"wb",
        );
        let (modern, modern_handle) = File::new(c, &[]);
        let (fd, modern_file) = attach(
            c,
            RuntimeKind::Ucrt,
            modern_handle,
            (O_BINARY | 2) as u64,
            b"wb",
        );
        queue(c, RuntimeKind::Msvcrt, legacy_file, b"legacy");
        queue(c, RuntimeKind::Ucrt, modern_file, b"modern");
        assert!(legacy.bytes().is_empty());
        assert!(modern.bytes().is_empty());
        assert_eq!(int(ucrt_process_detach(c, finish(71))), 71);
        assert_eq!(modern.bytes(), b"modern");
        assert!(legacy.bytes().is_empty());
        let streams = state(c, RuntimeKind::Ucrt).unwrap();
        assert!(streams.stream(modern_file).unwrap().open);
        assert!(streams.descriptor(fd).is_ok());
        assert!(c.p.objects.id(modern_handle).is_some());
        assert_eq!(int(ucrt_process_detach(c, finish(72))), 72);
        assert_eq!(modern.bytes(), b"modern"); // no replay on a repeated pass
    });
}

#[test]
fn uninitialized_runtime_detach_is_noop_without_context_or_storage_creation_all_abis() {
    run(|c| {
        let old = c.p.crt.runtimes[RuntimeKind::Ucrt.index()].stdio.take();
        let contexts = c.p.crt.runtimes[RuntimeKind::Ucrt.index()].contexts.len();
        let committed = c.p.vm.committed_bytes();
        assert_eq!(int(ucrt_process_detach(c, finish(19))), 19);
        assert!(c.p.crt.runtimes[RuntimeKind::Ucrt.index()].stdio.is_none());
        assert_eq!(
            c.p.crt.runtimes[RuntimeKind::Ucrt.index()].contexts.len(),
            contexts
        );
        assert_eq!(c.p.vm.committed_bytes(), committed);
        c.p.crt.runtimes[RuntimeKind::Ucrt.index()].stdio = old;
    });
}

#[test]
fn ordinary_input_detach_preserves_readahead_pushback_and_revision_without_buffer_access_all_abis()
{
    run(|c| {
        let (_host, handle) = File::new(c, b"abcdef");
        let (_, file) = attach(c, RuntimeKind::Ucrt, handle, O_BINARY as u64, b"rb");
        let buffer = area(c);
        let output = area(c);
        assert_eq!(
            int(invoke(
                c,
                RuntimeKind::Ucrt,
                "setvbuf",
                &[file, buffer, 0, PAGE_SIZE]
            )),
            0
        );
        assert_eq!(
            int(invoke(c, RuntimeKind::Ucrt, "fread", &[output, 1, 1, file])),
            1
        );
        let streams = state(c, RuntimeKind::Ucrt).unwrap();
        let mut stream = streams.stream(file).unwrap();
        assert_eq!(stream.last, Direction::Read);
        assert!(stream.read_end > stream.read_cursor);
        stream.pushback = Some(b'Z');
        let before = streams
            .publish(c.p, file, stream.generation, stream)
            .unwrap();
        c.p.vm.protect(buffer, PAGE_SIZE, prot::NOACCESS).unwrap();
        assert_eq!(int(ucrt_process_detach(c, finish(0))), 0);
        let after = streams.stream(file).unwrap();
        assert_eq!(after.revision, before.revision);
        assert_eq!(after.read_cursor, before.read_cursor);
        assert_eq!(after.read_end, before.read_end);
        assert_eq!(after.pushback, Some(b'Z'));
        assert_eq!(after.last, Direction::Read);
        c.p.vm.protect(buffer, PAGE_SIZE, prot::READWRITE).unwrap();
    });
}

#[test]
fn commit_read_candidate_preserves_input_but_reports_host_error_and_continues_all_abis() {
    run(|c| {
        let (_host, handle) = File::new(c, b"abc");
        let (fd, file) = attach(c, RuntimeKind::Ucrt, handle, O_BINARY as u64, b"rbc");
        let output = area(c);
        assert_eq!(
            int(invoke(c, RuntimeKind::Ucrt, "fread", &[output, 1, 1, file])),
            1
        );
        let streams = state(c, RuntimeKind::Ucrt).unwrap();
        let mut stream = streams.stream(file).unwrap();
        stream.pushback = Some(b'Q');
        let before = streams
            .publish(c.p, file, stream.generation, stream)
            .unwrap();
        let id = streams.descriptor(fd).unwrap().object.unwrap();
        let Object::File(object) = c.p.objects.obj_mut(id).unwrap() else {
            panic!("file");
        };
        object.host = None; // admitted metadata-only ownership; host commit fails
        let (next, next_handle) = File::new(c, &[]);
        let (_, next_file) = attach(
            c,
            RuntimeKind::Ucrt,
            next_handle,
            (O_BINARY | 2) as u64,
            b"wb",
        );
        queue(c, RuntimeKind::Ucrt, next_file, b"after");
        assert_eq!(int(ucrt_process_detach(c, finish(0))), 0);
        let after = streams.stream(file).unwrap();
        assert!(after.error);
        assert_eq!(after.read_cursor, before.read_cursor);
        assert_eq!(after.read_end, before.read_end);
        assert_eq!(after.last, Direction::Read);
        assert_eq!(after.pushback, Some(b'Q'));
        assert_eq!(next.bytes(), b"after");
    });
}

#[test]
fn output_host_failure_does_not_stop_later_streams_or_close_any_stream_all_abis() {
    run(|c| {
        let (bad, bad_handle) = File::new(c, &[]);
        let (bad_fd, bad_file) = attach(
            c,
            RuntimeKind::Ucrt,
            bad_handle,
            (O_BINARY | 2) as u64,
            b"wb",
        );
        let (good, good_handle) = File::new(c, &[]);
        let (_, good_file) = attach(
            c,
            RuntimeKind::Ucrt,
            good_handle,
            (O_BINARY | 2) as u64,
            b"wb",
        );
        queue(c, RuntimeKind::Ucrt, bad_file, b"failed");
        queue(c, RuntimeKind::Ucrt, good_file, b"accepted");
        let streams = state(c, RuntimeKind::Ucrt).unwrap();
        let id = streams.descriptor(bad_fd).unwrap().object.unwrap();
        let Object::File(object) = c.p.objects.obj_mut(id).unwrap() else {
            panic!("file");
        };
        object.host = Some(std::fs::File::open(&bad.0).unwrap());
        assert_eq!(int(ucrt_process_detach(c, finish(88))), 88);
        assert!(bad.bytes().is_empty());
        assert_eq!(good.bytes(), b"accepted");
        assert!(streams.stream(bad_file).unwrap().error);
        assert!(streams.stream(bad_file).unwrap().open);
        assert!(streams.stream(good_file).unwrap().open);
        let errno = int(invoke(c, RuntimeKind::Ucrt, "_errno", &[]));
        assert_ne!(c.mem().u32(errno).unwrap(), 0);
    });
}

#[test]
fn accepted_prefix_and_final_continuation_survive_fault_and_clobbered_formals_all_abis() {
    run(|c| {
        let (host, handle) = File::new(c, &[]);
        let (_, file) = attach(c, RuntimeKind::Ucrt, handle, (O_BINARY | 2) as u64, b"wb");
        let pages =
            c.p.vm
                .allocate(
                    None,
                    2 * PAGE_SIZE,
                    mem::RESERVE | mem::COMMIT,
                    prot::READWRITE,
                )
                .unwrap()
                .0;
        let buffer = pages + PAGE_SIZE - 256;
        assert_eq!(
            int(invoke(
                c,
                RuntimeKind::Ucrt,
                "setvbuf",
                &[file, buffer, 0, 768]
            )),
            0
        );
        queue(c, RuntimeKind::Ucrt, file, &[b'A'; 384]);
        c.p.vm
            .protect(pages + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
            .unwrap();
        let calls = Rc::new(Cell::new(0));
        let observed = calls.clone();
        let (fault, resume) = retry(ucrt_process_detach(
            c,
            Box::new(move |_, _| {
                observed.set(observed.get() + 1);
                Flow::ret(33)
            }),
        ));
        assert_eq!(fault.addr, pages + PAGE_SIZE);
        assert!(!fault.write);
        assert_eq!(host.bytes(), [b'A'; 256]);
        assert_eq!(
            state(c, RuntimeKind::Ucrt)
                .unwrap()
                .stream(file)
                .unwrap()
                .write_start,
            256
        );
        assert_eq!(calls.get(), 0);
        clobber_formals(c, 4);
        c.p.vm
            .protect(pages + PAGE_SIZE, PAGE_SIZE, prot::READWRITE)
            .unwrap();
        assert_eq!(int(resume(c, 0)), 33);
        assert_eq!(host.bytes(), [b'A'; 384]);
        assert_eq!(calls.get(), 1);
    });
}

#[test]
fn revised_active_stream_during_fault_repair_is_rejected_without_replaying_prefix_all_abis() {
    run(|c| {
        let (host, handle) = File::new(c, &[]);
        let (_, file) = attach(c, RuntimeKind::Ucrt, handle, (O_BINARY | 2) as u64, b"wb");
        let pages =
            c.p.vm
                .allocate(
                    None,
                    2 * PAGE_SIZE,
                    mem::RESERVE | mem::COMMIT,
                    prot::READWRITE,
                )
                .unwrap()
                .0;
        let buffer = pages + PAGE_SIZE - 256;
        assert_eq!(
            int(invoke(
                c,
                RuntimeKind::Ucrt,
                "setvbuf",
                &[file, buffer, 0, 768]
            )),
            0
        );
        queue(c, RuntimeKind::Ucrt, file, &[b'B'; 384]);
        c.p.vm
            .protect(pages + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
            .unwrap();
        let (_, resume) = retry(ucrt_process_detach(c, finish(0)));
        c.p.vm
            .protect(pages + PAGE_SIZE, PAGE_SIZE, prot::READWRITE)
            .unwrap();
        let streams = state(c, RuntimeKind::Ucrt).unwrap();
        let mut updated = streams.stream(file).unwrap();
        updated.pushback = Some(b'X');
        streams
            .publish(c.p, file, updated.generation, updated)
            .unwrap();
        assert!(matches!(resume(c, 0), Err(ApiErr::Unimplemented(_))));
        assert_eq!(host.bytes(), [b'B'; 256]);
        assert_eq!(streams.stream(file).unwrap().pushback, Some(b'X'));
    });
}

#[test]
fn new_streams_are_not_added_to_captured_snapshot_during_fault_repair_all_abis() {
    run(|c| {
        let (first, first_handle) = File::new(c, &[]);
        let (_, first_file) = attach(
            c,
            RuntimeKind::Ucrt,
            first_handle,
            (O_BINARY | 2) as u64,
            b"wb",
        );
        let (second, second_handle) = File::new(c, &[]);
        let (_, second_file) = attach(
            c,
            RuntimeKind::Ucrt,
            second_handle,
            (O_BINARY | 2) as u64,
            b"wb",
        );
        let buffer = area(c);
        assert_eq!(
            int(invoke(
                c,
                RuntimeKind::Ucrt,
                "setvbuf",
                &[second_file, buffer, 0, 1024]
            )),
            0
        );
        queue(c, RuntimeKind::Ucrt, first_file, b"first");
        queue(c, RuntimeKind::Ucrt, second_file, b"second");
        c.p.vm.protect(buffer, PAGE_SIZE, prot::NOACCESS).unwrap();
        let (_, resume) = retry(ucrt_process_detach(c, finish(42)));
        assert_eq!(first.bytes(), b"first");
        let (late, late_handle) = File::new(c, &[]);
        let (_, late_file) = attach(
            c,
            RuntimeKind::Ucrt,
            late_handle,
            (O_BINARY | 2) as u64,
            b"wb",
        );
        queue(c, RuntimeKind::Ucrt, late_file, b"late");
        c.p.vm.protect(buffer, PAGE_SIZE, prot::READWRITE).unwrap();
        assert_eq!(int(resume(c, 0)), 42);
        assert_eq!(first.bytes(), b"first");
        assert_eq!(second.bytes(), b"second");
        assert!(late.bytes().is_empty());
        assert_eq!(int(ucrt_process_detach(c, finish(0))), 0);
        assert_eq!(late.bytes(), b"late");
    });
}
