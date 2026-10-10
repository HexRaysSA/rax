//! All three guest ABIs; FILE shells/defaults are private profiles, not a
//! native private-layout oracle. External raw frees violate opaque ownership.

use super::*;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::dll::crt::tests::{area, run};
use crate::user::windows::hle::{Archs, Ctx, Export};

static LEGACY_DATA: &[Export] = &[
    Export::data("_fmode", DataSize::Bytes(4)),
    Export::data("_commode", DataSize::Bytes(4)),
    Export::data("_iob", DataSize::Bytes(640)).only(Archs::X86),
    Export::data("_iob", DataSize::Bytes(960)).only(Archs::X64),
    Export::data("_iob", DataSize::Bytes(960)).only(Archs::ARM64),
];
static DATA_DLL: BuiltinDll = BuiltinDll {
    name: "msvcrt.dll",
    display: "msvcrt.dll",
    subsystem: 3,
    exports: &[LEGACY_DATA],
};

fn fresh(c: &mut Ctx, kind: RuntimeKind) -> PreparedStdio {
    let dll = crate::user::windows::dll::find(if kind == RuntimeKind::Msvcrt {
        "msvcrt.dll"
    } else {
        "ucrtbase.dll"
    })
    .unwrap();
    prepare(c.p, dll, 0, &[]).unwrap()
}
fn checked_fault<T>(result: Result<T, StdioError>) -> MemFault {
    match result {
        Err(StdioError::Fault(f)) => f,
        _ => panic!("checked fault expected"),
    }
}
fn image(c: &mut Ctx) -> u64 {
    let base =
        c.p.vm
            .reserve(
                None,
                PAGE_SIZE,
                prot::READWRITE,
                AllocKind::Image,
                false,
                None,
            )
            .unwrap();
    c.p.vm.commit(base, PAGE_SIZE, prot::READWRITE).unwrap();
    c.mem().wr(base, &[0xA5; 4096]).unwrap();
    base
}
fn adopted(c: &mut Ctx, state: &StdioState, flags: i32) -> (u64, ObjId, i32) {
    let handle = u64::from(c.p.objects.insert(Object::Null));
    let id = c.p.objects.id(handle).unwrap();
    let fd = state.attach_descriptor(c.p, handle, flags).unwrap();
    (handle, id, fd)
}

#[test]
fn initial_profiles_have_stable_standard_files_real_cells_and_distinct_descriptors() {
    run(|c| {
        for kind in [RuntimeKind::Msvcrt, RuntimeKind::Ucrt] {
            let candidate = fresh(c, kind);
            let s = &candidate.state;
            let width = c.arch().ptr_size();
            let stride = if kind == RuntimeKind::Msvcrt {
                if width == 4 { 32 } else { 48 }
            } else {
                width
            };
            assert_eq!(s.0.borrow().file_stride, stride);
            assert_eq!(
                s.0.borrow().streams.len(),
                if kind == RuntimeKind::Msvcrt { 20 } else { 3 }
            );
            assert_eq!(c.mem().u32(s.mode_cell(0).unwrap()).unwrap(), O_TEXT as u32);
            assert_eq!(c.mem().u32(s.mode_cell(1).unwrap()).unwrap(), 0);
            let files: Vec<_> = (0..3).map(|i| s.standard_file(i).unwrap()).collect();
            assert_eq!(files[1] - files[0], stride);
            assert_eq!(files[2] - files[1], stride);
            assert!(s.standard_file(3).is_none());
            for (index, &file) in files.iter().enumerate() {
                let stream = s.stream(file).unwrap();
                let d = s.descriptor(index as i32).unwrap();
                assert_eq!(stream.descriptor, index as i32);
                assert_eq!(d.stream, Some(file));
                assert_ne!(d.handle, index as u64);
                assert!(d.object.is_some());
                assert_eq!(
                    stream.buffer,
                    if index == 2 {
                        Buffer::Unbuffered
                    } else {
                        Buffer::Automatic {
                            address: 0,
                            capacity: 4096,
                        }
                    }
                );
            }
            candidate.abort(c.p).unwrap();
        }
    });
}

#[test]
fn real_legacy_data_writes_exact_array_preserves_adjacent_bytes_and_is_not_owned_vm() {
    run(|c| {
        let base = image(c);
        let stride = if c.arch() == WinArch::X86 { 32 } else { 48 };
        let candidate = prepare(
            c.p,
            &DATA_DLL,
            base,
            &[
                ("_fmode", BuiltinSym::Rva(0)),
                ("_commode", BuiltinSym::Rva(4)),
                ("_iob", BuiltinSym::Rva(16)),
            ],
        )
        .unwrap();
        let s = &candidate.state;
        assert_eq!(s.mode_cell(0), Some(base));
        assert_eq!(s.mode_cell(1), Some(base + 4));
        assert_eq!(s.standard_file(0), Some(base + 16));
        assert!(s.0.borrow().blocks.is_empty());
        let fd_at = if stride == 32 { 16 } else { 28 };
        let flag_at = if stride == 32 { 12 } else { 24 };
        for index in 0..3 {
            let at = base + 16 + index * stride;
            assert_eq!(c.mem().u32(at + fd_at).unwrap(), index as u32);
            assert_eq!(
                c.mem().u32(at + flag_at).unwrap(),
                if index == 0 {
                    1
                } else if index == 1 {
                    2
                } else {
                    6
                }
            );
        }
        assert_eq!(c.mem().u8(base + 16 + 20 * stride).unwrap(), 0xA5);
        assert_eq!(
            c.mem()
                .bytes(base + 16 + 3 * stride, (17 * stride) as usize)
                .unwrap(),
            vec![0; (17 * stride) as usize]
        );
        candidate.abort(c.p).unwrap();
        assert!(c.p.vm.allocation(base).is_some());
        c.p.vm.release(base).unwrap();
    });
}

#[test]
fn source_fault_and_bad_data_metadata_have_no_allocation_or_pin_effects() {
    run(|c| {
        let saved = c.p.params;
        let before = c.p.vm.committed_bytes();
        c.p.params = 1;
        let dll = crate::user::windows::dll::find("ucrtbase.dll").unwrap();
        assert_eq!(
            prepare(c.p, dll, 0, &[]).err().unwrap().status,
            STATUS_ACCESS_VIOLATION
        );
        assert_eq!(c.p.vm.committed_bytes(), before);
        c.p.params = saved;
        let base = image(c);
        let before = c.p.vm.committed_bytes();
        for symbol in [
            BuiltinSym::Forward("other.symbol"),
            BuiltinSym::Rva(1),
            BuiltinSym::Rva(4096),
        ] {
            assert!(prepare(c.p, &DATA_DLL, base, &[("_fmode", symbol)]).is_err());
            assert_eq!(c.p.vm.committed_bytes(), before);
            assert_eq!(c.mem().u32(base).unwrap(), 0xA5A5_A5A5);
        }
        c.p.vm.release(base).unwrap();
    });
}

#[test]
fn late_data_preflight_fault_is_atomic_before_any_export_write() {
    run(|c| {
        let base = image(c);
        c.p.vm.protect(base, PAGE_SIZE, prot::READONLY).unwrap();
        let before = c.p.vm.committed_bytes();
        assert_eq!(
            prepare(
                c.p,
                &DATA_DLL,
                base,
                &[
                    ("_fmode", BuiltinSym::Rva(0)),
                    ("_commode", BuiltinSym::Rva(4)),
                    ("_iob", BuiltinSym::Rva(16))
                ]
            )
            .err()
            .unwrap()
            .status,
            STATUS_ACCESS_VIOLATION
        );
        assert_eq!(c.p.vm.committed_bytes(), before);
        assert_eq!(c.mem().u32(base).unwrap(), 0xA5A5_A5A5);
        c.p.vm.release(base).unwrap();
    });
}

#[test]
fn missing_standard_handles_are_unassociated_and_unsupported_pipes_still_pin() {
    run(|c| {
        let saved = c.p.params;
        c.p.params = 0;
        let candidate = fresh(c, RuntimeKind::Ucrt);
        for fd in 0..3 {
            let d = candidate.state.descriptor(fd).unwrap();
            assert!(d.object.is_none());
            assert_eq!(d.handle, c.arch().ptr(u64::MAX - 1));
        }
        candidate.abort(c.p).unwrap();
        c.p.params = saved;
        let at = area(c);
        let o = *offsets(c.arch());
        let pipe = u64::from(c.p.objects.insert(Object::Pipe {
            pipe: 1,
            write: true,
        }));
        let pipe_id = c.p.objects.id(pipe).unwrap();
        for off in [o.pp_std_input, o.pp_std_output, o.pp_std_error] {
            c.mem().wptr(at + off, o.ptr, pipe).unwrap();
        }
        c.p.params = at;
        let candidate = fresh(c, RuntimeKind::Ucrt);
        assert_eq!(candidate.state.descriptor(1).unwrap().object, Some(pipe_id));
        assert!(candidate.state.validate_descriptor(c.p, 1, true).is_ok());
        candidate.abort(c.p).unwrap();
        assert!(matches!(
            c.p.objects.close(pipe).unwrap(),
            Some(Object::Pipe { .. })
        ));
        c.p.params = saved;
        // A small synthetic params allocation contains the three source fields.
        let id = c.p.objects.create(Object::Null);
        let handle = u64::from(c.p.objects.open(id, false));
        for off in [o.pp_std_input, o.pp_std_output, o.pp_std_error] {
            c.mem().wptr(at + off, o.ptr, handle).unwrap();
        }
        c.p.params = at;
        let candidate = fresh(c, RuntimeKind::Ucrt);
        candidate.abort(c.p).unwrap();
        let last = c.p.objects.close(handle).unwrap();
        assert!(matches!(last, Some(Object::Null)));
        assert!(c.p.objects.obj(id).is_none());
        c.p.params = saved;
    });
}

#[test]
fn adoption_is_transfer_not_duplication_and_fdopen_never_opens_or_truncates() {
    run(|c| {
        let candidate = fresh(c, RuntimeKind::Ucrt);
        let s = &candidate.state;
        let (handle, id, fd) = adopted(c, s, 2 | O_TEXT);
        assert_eq!(fd, 3);
        assert_ne!(handle, fd as u64);
        assert!(matches!(
            s.attach_descriptor(c.p, handle, 2 | O_TEXT),
            Err(StdioError::Invalid)
        ));
        let file = s
            .attach_stream(c.p, fd, true, true, true, Some(O_BINARY), true)
            .unwrap();
        let d = s.descriptor(fd).unwrap();
        assert_eq!(d.handle, handle);
        assert_eq!(d.object, Some(id));
        assert_eq!(d.stream, Some(file));
        assert_eq!(d.translation, O_BINARY);
        assert!(d.append);
        assert!(s.stream(file).unwrap().commit);
        assert!(matches!(
            s.attach_stream(c.p, fd, true, false, false, None, false),
            Err(StdioError::Invalid)
        ));
        assert!(matches!(
            s.close_descriptor(c.p, fd),
            Err(StdioError::Invalid)
        ));
        s.close_stream(c.p, file).unwrap();
        assert!(c.p.objects.get(handle).is_none());
        assert!(c.p.objects.obj(id).is_none());
        assert!(matches!(s.stream(file), Err(StdioError::Invalid)));
        candidate.abort(c.p).unwrap();
    });
}

#[test]
fn rights_modes_and_generation_checks_reject_before_ownership_transfer() {
    run(|c| {
        let candidate = fresh(c, RuntimeKind::Ucrt);
        let s = &candidate.state;
        let id = c.p.objects.create(Object::Null);
        let handle = u64::from(c.p.objects.open_access(id, false, 0x8000_0000).unwrap());
        let fd = s.attach_descriptor(c.p, handle, 2 | O_TEXT).unwrap();
        assert!(s.validate_descriptor(c.p, fd, false).is_ok());
        assert!(matches!(
            s.validate_descriptor(c.p, fd, true),
            Err(StdioError::Invalid)
        ));
        assert!(matches!(
            s.attach_stream(c.p, fd, false, true, false, None, false),
            Err(StdioError::Invalid)
        ));
        assert!(s.descriptor(fd).unwrap().stream.is_none());
        assert_eq!(s.set_mode(fd, O_BINARY).unwrap(), O_TEXT);
        assert!(matches!(s.set_mode(fd, 0), Err(StdioError::Invalid)));
        let descriptor = s.descriptor(fd).unwrap();
        let mut next = descriptor;
        next.lookahead = Some(b'X');
        let published = s
            .publish_descriptor(fd, descriptor.generation, next)
            .unwrap();
        assert_eq!(published.revision, descriptor.revision + 1);
        assert!(matches!(
            s.publish_descriptor(fd, descriptor.generation, next),
            Err(StdioError::Internal(_))
        ));
        assert_eq!(s.descriptor(fd).unwrap().lookahead, Some(b'X'));
        s.close_descriptor(c.p, fd).unwrap();
        candidate.abort(c.p).unwrap();
    });
}

#[test]
fn invalid_handle_flags_and_pointer_width_cannot_add_descriptors_or_pins() {
    run(|c| {
        let candidate = fresh(c, RuntimeKind::Ucrt);
        let s = &candidate.state;
        let handle = u64::from(c.p.objects.insert(Object::Null));
        let id = c.p.objects.id(handle).unwrap();
        for flags in [3, -1, O_TEXT | O_BINARY, 0x1000] {
            assert!(matches!(
                s.attach_descriptor(c.p, handle, flags),
                Err(StdioError::Invalid)
            ));
        }
        assert!(matches!(
            s.attach_descriptor(c.p, 0, 0),
            Err(StdioError::Invalid)
        ));
        let event = u64::from(c.p.objects.insert(Object::Event {
            manual: false,
            signaled: 0,
        }));
        assert!(matches!(
            s.attach_descriptor(c.p, event, 0),
            Err(StdioError::Invalid)
        ));
        if c.arch() == WinArch::X86 {
            let f = checked_fault(s.attach_descriptor(c.p, 1 << 32, 0));
            assert!(!f.write);
            assert_eq!(f.addr, 1 << 32);
        }
        assert_eq!(s.0.borrow().descriptors.len(), 3);
        assert!(matches!(
            c.p.objects.close(handle).unwrap(),
            Some(Object::Null)
        ));
        assert!(c.p.objects.obj(id).is_none());
        candidate.abort(c.p).unwrap();
    });
}

#[test]
fn caller_buffer_is_used_real_guest_storage_and_never_freed_by_close() {
    run(|c| {
        let candidate = fresh(c, RuntimeKind::Ucrt);
        let s = &candidate.state;
        let (_, _, fd) = adopted(c, s, 1 | O_BINARY);
        let file = s
            .attach_stream(c.p, fd, false, true, false, None, false)
            .unwrap();
        let user = area(c);
        let before = c.p.vm.committed_bytes();
        s.replace_buffer(c.p, file, IOFBF, user, 9).unwrap();
        let mut stream = s.stream(file).unwrap();
        assert_eq!(
            stream.buffer,
            Buffer::User {
                address: user,
                capacity: 8
            }
        );
        assert_eq!(c.p.vm.committed_bytes(), before);
        c.mem().wr(stream.buffer.address(), b"realdata").unwrap();
        stream.write_pending = 8;
        stream.last = Direction::Write;
        s.publish(c.p, file, stream.generation, stream).unwrap();
        assert_eq!(c.mem().bytes(user, 8).unwrap(), b"realdata");
        // The I/O facade flushes before invoking storage close.
        s.close_stream(c.p, file).unwrap();
        assert!(c.p.vm.allocation(user).is_some());
        assert_eq!(c.mem().bytes(user, 8).unwrap(), b"realdata");
        candidate.abort(c.p).unwrap();
        assert!(c.p.vm.allocation(user).is_some());
    });
}

#[test]
fn owned_buffer_swap_release_and_unbuffered_ignore_invalid_size_and_pointer() {
    run(|c| {
        let candidate = fresh(c, RuntimeKind::Msvcrt);
        let s = &candidate.state;
        let file = s.standard_file(1).unwrap();
        let first = s.ensure_buffer(c.p, file).unwrap();
        let first_base = first.buffer.address();
        assert_ne!(first_base, 0);
        let user = area(c);
        s.replace_buffer(c.p, file, IOLBF, user, 7).unwrap();
        assert!(c.p.vm.allocation(first_base).is_none());
        let second = s.stream(file).unwrap();
        assert_eq!(
            second.buffer,
            Buffer::User {
                address: user,
                capacity: 6
            }
        );
        s.replace_buffer(c.p, file, IONBF, u64::MAX, u64::MAX)
            .unwrap();
        assert_eq!(s.stream(file).unwrap().buffer, Buffer::Unbuffered);
        assert!(c.p.vm.allocation(user).is_some());
        candidate.abort(c.p).unwrap();
    });
}

#[test]
fn buffer_fault_and_invalid_input_preserve_old_generation_state_and_commitment() {
    run(|c| {
        let candidate = fresh(c, RuntimeKind::Ucrt);
        let s = &candidate.state;
        let file = s.standard_file(1).unwrap();
        let old = s.ensure_buffer(c.p, file).unwrap();
        let before = c.p.vm.committed_bytes();
        for (mode, size) in [(IOFBF, 0), (IOFBF, 1), (IOFBF, i32::MAX as u64 + 1), (3, 8)] {
            assert!(matches!(
                s.replace_buffer(c.p, file, mode, 0, size),
                Err(StdioError::Invalid)
            ));
        }
        let fault = checked_fault(s.replace_buffer(c.p, file, IOFBF, 1, 2));
        assert!(fault.write);
        assert_eq!(s.stream(file).unwrap().generation, old.generation);
        assert_eq!(s.stream(file).unwrap().buffer, old.buffer);
        assert_eq!(c.p.vm.committed_bytes(), before);
        let user = area(c);
        c.p.vm.protect(user, PAGE_SIZE, prot::READONLY).unwrap();
        let f = checked_fault(s.replace_buffer(c.p, file, IOFBF, user, 2));
        assert_eq!(f.addr, user);
        assert!(f.write);
        assert_eq!(s.stream(file).unwrap().buffer, old.buffer);
        candidate.abort(c.p).unwrap();
    });
}

#[test]
fn guest_commit_exhaustion_preserves_buffer_and_fdopen_ownership() {
    run(|c| {
        let candidate = fresh(c, RuntimeKind::Ucrt);
        let s = &candidate.state;
        let file = s.standard_file(1).unwrap();
        let old = s.ensure_buffer(c.p, file).unwrap();
        let (handle, id, fd) = adopted(c, s, 2 | O_TEXT);
        let available = c.p.vm.commit_limit() - c.p.vm.committed_bytes();
        let filler =
            c.p.vm
                .allocate(None, available, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        assert!(matches!(
            s.replace_buffer(c.p, file, IOFBF, 0, 8),
            Err(StdioError::NoMemory)
        ));
        assert_eq!(s.stream(file).unwrap().buffer, old.buffer);
        assert!(matches!(
            s.attach_stream(c.p, fd, true, true, false, Some(O_BINARY), true),
            Err(StdioError::NoMemory)
        ));
        let d = s.descriptor(fd).unwrap();
        assert_eq!(d.translation, O_TEXT);
        assert!(!d.append);
        assert!(d.stream.is_none());
        assert_eq!(d.handle, handle);
        assert_eq!(d.object, Some(id));
        c.p.vm.release(filler).unwrap();
        s.close_descriptor(c.p, fd).unwrap();
        candidate.abort(c.p).unwrap();
    });
}

#[test]
fn file_readonly_guard_and_stale_revision_prevent_metadata_overwrite() {
    run(|c| {
        let candidate = fresh(c, RuntimeKind::Ucrt);
        let s = &candidate.state;
        let file = s.standard_file(1).unwrap();
        let old = s.stream(file).unwrap();
        let mut updated = old;
        updated.error = true;
        let page = file & !(PAGE_SIZE - 1);
        c.p.vm.protect(page, PAGE_SIZE, prot::READONLY).unwrap();
        assert!(checked_fault(s.publish(c.p, file, old.generation, updated)).write);
        assert!(!s.stream(file).unwrap().error);
        c.p.vm
            .protect(page, PAGE_SIZE, prot::READWRITE | prot::GUARD)
            .unwrap();
        assert!(checked_fault(s.publish(c.p, file, old.generation, updated)).write);
        assert!(!s.stream(file).unwrap().error);
        c.p.vm.protect(page, PAGE_SIZE, prot::READWRITE).unwrap();
        let published = s.publish(c.p, file, old.generation, updated).unwrap();
        assert_eq!(published.revision, old.revision + 1);
        assert!(matches!(
            s.publish(c.p, file, old.generation, old),
            Err(StdioError::Internal(_))
        ));
        assert!(s.stream(file).unwrap().error);
        candidate.abort(c.p).unwrap();
    });
}

#[test]
fn legacy_public_fields_reflect_actual_guest_buffer_cursors_and_flags() {
    run(|c| {
        let candidate = fresh(c, RuntimeKind::Msvcrt);
        let s = &candidate.state;
        let file = s.standard_file(0).unwrap();
        let user = area(c);
        s.replace_buffer(c.p, file, IOFBF, user, 10).unwrap();
        let mut stream = s.stream(file).unwrap();
        stream.last = Direction::Read;
        stream.read_cursor = 3;
        stream.read_end = 8;
        stream.eof = true;
        stream.error = true;
        let stream = s.publish(c.p, file, stream.generation, stream).unwrap();
        let (cnt, base, flags, size) = if c.arch() == WinArch::X86 {
            (4, 8, 12, 24)
        } else {
            (8, 16, 24, 36)
        };
        assert_eq!(c.mem().ptr(file, c.psize()).unwrap(), user + 3);
        assert_eq!(c.mem().u32(file + cnt).unwrap(), 5);
        assert_eq!(c.mem().ptr(file + base, c.psize()).unwrap(), user);
        assert_eq!(c.mem().u32(file + flags).unwrap(), 0x31);
        assert_eq!(c.mem().u32(file + size).unwrap(), 10);
        let mut invalid = stream;
        invalid.read_cursor = 11;
        assert!(matches!(
            s.publish(c.p, file, stream.generation, invalid),
            Err(StdioError::Internal(_))
        ));
        candidate.abort(c.p).unwrap();
    });
}

#[test]
fn external_close_and_different_object_handle_reuse_cannot_retarget_or_close_replacement() {
    run(|c| {
        let candidate = fresh(c, RuntimeKind::Ucrt);
        let s = &candidate.state;
        let (handle, id, fd) = adopted(c, s, 2 | O_BINARY);
        assert!(c.p.objects.close(handle).unwrap().is_none());
        assert!(c.p.objects.obj(id).is_some());
        let replacement = u64::from(c.p.objects.insert(Object::Null));
        assert_eq!(replacement, handle);
        let replacement_id = c.p.objects.id(replacement).unwrap();
        assert!(matches!(
            s.validate_descriptor(c.p, fd, true),
            Err(StdioError::Internal(_))
        ));
        assert!(matches!(
            s.close_descriptor(c.p, fd),
            Err(StdioError::Internal(_))
        ));
        candidate.abort(c.p).unwrap();
        assert!(c.p.objects.obj(id).is_none());
        assert_eq!(c.p.objects.id(replacement), Some(replacement_id));
    });
}

#[test]
fn raw_private_vm_free_is_detected_without_freeing_a_different_size_replacement() {
    run(|c| {
        let candidate = fresh(c, RuntimeKind::Ucrt);
        let s = &candidate.state;
        let file = s.standard_file(1).unwrap();
        let old = s.ensure_buffer(c.p, file).unwrap();
        let base = old.buffer.address();
        c.p.vm.release(base).unwrap();
        c.p.vm
            .allocate(
                Some(base),
                2 * PAGE_SIZE,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap();
        assert!(matches!(
            s.ensure_buffer(c.p, file),
            Err(StdioError::Internal(_))
        ));
        assert!(candidate.abort(c.p).is_err());
        assert!(c.p.vm.allocation(base).is_some());
    });
}

#[test]
fn generation_and_revision_exhaustion_reject_without_partial_publication() {
    run(|c| {
        let candidate = fresh(c, RuntimeKind::Ucrt);
        let s = &candidate.state;
        let file = s.standard_file(1).unwrap();
        s.0.borrow_mut().next_generation = u64::MAX;
        let before = c.p.vm.committed_bytes();
        assert!(matches!(
            s.replace_buffer(c.p, file, IONBF, 0, 0),
            Err(StdioError::GenerationExhausted)
        ));
        assert_eq!(c.p.vm.committed_bytes(), before);
        let handle = u64::from(c.p.objects.insert(Object::Null));
        assert!(matches!(
            s.attach_descriptor(c.p, handle, 0),
            Err(StdioError::GenerationExhausted)
        ));
        assert!(matches!(
            c.p.objects.close(handle).unwrap(),
            Some(Object::Null)
        ));
        s.0.borrow_mut().streams[1].revision = u64::MAX;
        let old = s.stream(file).unwrap();
        assert!(matches!(
            s.publish(c.p, file, old.generation, old),
            Err(StdioError::GenerationExhausted)
        ));
        candidate.abort(c.p).unwrap();
    });
}

#[test]
fn discard_is_idempotent_no_guest_writes_and_releases_only_owned_storage_and_pins() {
    run(|c| {
        let before = c.p.vm.committed_bytes();
        let candidate = fresh(c, RuntimeKind::Ucrt);
        let s = &candidate.state;
        let user = area(c);
        let (_, id, fd) = adopted(c, s, 2 | O_BINARY);
        let file = s
            .attach_stream(c.p, fd, true, true, false, None, false)
            .unwrap();
        s.replace_buffer(c.p, file, IOFBF, user, 8).unwrap();
        c.p.vm.protect(user, PAGE_SIZE, prot::NOACCESS).unwrap();
        for block in s.0.borrow().blocks.iter().copied() {
            c.p.vm
                .protect(block.base, block.size, prot::NOACCESS)
                .unwrap();
        }
        let d = s.descriptor(fd).unwrap();
        assert!(c.p.objects.close(d.handle).unwrap().is_none());
        s.discard(c.p).unwrap();
        s.discard(c.p).unwrap();
        assert!(c.p.objects.obj(id).is_none());
        assert!(c.p.vm.allocation(user).is_some());
        assert_eq!(c.p.vm.committed_bytes(), before + PAGE_SIZE);
        candidate.abort(c.p).unwrap();
    });
}

#[test]
fn fdopen_failure_is_atomic_and_closed_legacy_slot_reuse_changes_lifetime_generation() {
    run(|c| {
        let candidate = fresh(c, RuntimeKind::Msvcrt);
        let s = &candidate.state;
        let (_, _, fd) = adopted(c, s, 2 | O_TEXT);
        let inactive = s.0.borrow().streams[3].file;
        let page = inactive & !(PAGE_SIZE - 1);
        c.p.vm.protect(page, PAGE_SIZE, prot::READONLY).unwrap();
        let old = s.descriptor(fd).unwrap();
        let before = c.p.vm.committed_bytes();
        assert!(
            checked_fault(s.attach_stream(c.p, fd, true, true, true, Some(O_BINARY), true)).write
        );
        let unchanged = s.descriptor(fd).unwrap();
        assert_eq!(unchanged.revision, old.revision);
        assert_eq!(unchanged.translation, O_TEXT);
        assert!(!unchanged.append);
        assert!(unchanged.stream.is_none());
        assert_eq!(c.p.vm.committed_bytes(), before);
        c.p.vm.protect(page, PAGE_SIZE, prot::READWRITE).unwrap();
        let file = s
            .attach_stream(c.p, fd, true, true, true, Some(O_BINARY), true)
            .unwrap();
        assert_eq!(file, inactive);
        let old = s.stream(file).unwrap();
        s.close_stream(c.p, file).unwrap();
        let (_, _, fd) = adopted(c, s, 2 | O_TEXT);
        let reused = s
            .attach_stream(c.p, fd, true, true, false, None, false)
            .unwrap();
        assert_eq!(reused, file);
        assert_ne!(s.stream(file).unwrap().generation, old.generation);
        assert!(matches!(
            s.publish(c.p, file, old.generation, old),
            Err(StdioError::Internal(_))
        ));
        s.close_stream(c.p, file).unwrap();
        candidate.abort(c.p).unwrap();
    });
}

#[test]
fn close_preflight_failure_and_protected_handle_preserve_live_stream() {
    run(|c| {
        let candidate = fresh(c, RuntimeKind::Ucrt);
        let s = &candidate.state;
        let (handle, _, fd) = adopted(c, s, 2 | O_BINARY);
        let file = s
            .attach_stream(c.p, fd, true, true, false, None, false)
            .unwrap();
        let page = file & !(PAGE_SIZE - 1);
        c.p.vm.protect(page, PAGE_SIZE, prot::READONLY).unwrap();
        assert!(checked_fault(s.close_stream(c.p, file)).write);
        assert!(c.p.objects.get(handle).is_some());
        assert!(s.stream(file).is_ok());
        c.p.vm.protect(page, PAGE_SIZE, prot::READWRITE).unwrap();
        c.p.objects.set_flags(handle, 2, 2);
        assert!(matches!(
            s.close_stream(c.p, file),
            Err(StdioError::Host(6))
        ));
        assert!(s.stream(file).is_ok());
        assert!(s.descriptor(fd).is_ok());
        c.p.objects.set_flags(handle, 2, 0);
        s.close_stream(c.p, file).unwrap();
        candidate.abort(c.p).unwrap();
    });
}

#[test]
fn final_host_close_failure_still_closes_logical_stream_and_releases_buffer_once() {
    run(|c| {
        use crate::user::windows::fs::{FileIdentity, FileLifetime};
        use crate::user::windows::objects::FileObj;
        use std::sync::Arc;
        let candidate = fresh(c, RuntimeKind::Ucrt);
        let s = &candidate.state;
        // No host writes: Unix identity with a nonexistent delete target gives
        // a deterministic final-close error. Non-Unix identity is unsupported.
        #[cfg(unix)]
        {
            let path =
                std::path::PathBuf::from("/rax-stdio-test-path-must-not-exist/delete-target");
            let lifetime = Arc::new(FileLifetime::new(FileIdentity::Unix(u64::MAX, u64::MAX)));
            lifetime.mark_delete(path.clone(), false).unwrap();
            let handle = u64::from(c.p.objects.insert(Object::File(FileObj {
                host: None,
                host_path: path,
                path: "C:\\missing".into(),
                access: u32::MAX,
                share: 7,
                lifetime,
                null: true,
                append: false,
                delete_on_close: true,
                directory: false,
                overlapped: false,
            })));
            let id = c.p.objects.id(handle).unwrap();
            let fd = s.attach_descriptor(c.p, handle, 2 | O_BINARY).unwrap();
            let file = s
                .attach_stream(c.p, fd, true, true, false, None, false)
                .unwrap();
            let buffer = s.ensure_buffer(c.p, file).unwrap().buffer.address();
            assert!(matches!(
                s.close_stream(c.p, file),
                Err(StdioError::Host(_))
            ));
            assert!(s.stream(file).is_err());
            assert!(s.descriptor(fd).is_err());
            assert!(c.p.objects.obj(id).is_none());
            assert!(c.p.vm.allocation(buffer).is_none());
            assert!(matches!(
                s.close_stream(c.p, file),
                Err(StdioError::Invalid)
            ));
        }
        candidate.abort(c.p).unwrap();
    });
}

#[test]
fn write_prefix_cursor_and_snapshot_revisions_cannot_replay_fault_handler_progress() {
    run(|c| {
        let candidate = fresh(c, RuntimeKind::Ucrt);
        let s = &candidate.state;
        let file = s.standard_file(1).unwrap();
        let mut stream = s.ensure_buffer(c.p, file).unwrap();
        stream.last = Direction::Write;
        stream.write_pending = 7;
        let old = s.publish(c.p, file, stream.generation, stream).unwrap();
        let mut handler = old;
        handler.write_start = 3;
        let handler = s.publish(c.p, file, handler.generation, handler).unwrap();
        assert_eq!(handler.write_start, 3);
        let mut stale = old;
        stale.write_start = 1;
        assert!(matches!(
            s.publish(c.p, file, stale.generation, stale),
            Err(StdioError::Internal(_))
        ));
        assert_eq!(s.stream(file).unwrap().write_start, 3);
        let mut invalid = handler;
        invalid.write_start = 8;
        assert!(matches!(
            s.publish(c.p, file, invalid.generation, invalid),
            Err(StdioError::Internal(_))
        ));
        candidate.abort(c.p).unwrap();
    });
}
