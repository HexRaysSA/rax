use super::*;

#[test]
fn record_layouts_round_trip() {
    let k = Kev {
        ident: 7,
        filter: evfilt::READ,
        flags: ev::ADD | ev::CLEAR,
        qos: 0x21ff,
        udata: 0xdead_beef,
        fflags: 3,
        xflags: 0,
        data: -5,
        ext: [1, 2, 3, 4],
    };
    let q = Kev::decode(&k.encode(Layout::Qos), Layout::Qos);
    assert_eq!(q, k);
    let l = Kev::decode(&k.encode(Layout::Kevent64), Layout::Kevent64);
    assert_eq!(l.ext, [1, 2, 0, 0]);
    assert_eq!(
        (l.ident, l.filter, l.data, l.udata),
        (7, evfilt::READ, -5, 0xdead_beef)
    );
    let s = Kev::decode(&k.encode(Layout::Kevent), Layout::Kevent);
    assert_eq!((s.fflags, s.ext), (3, [0; 4]));
    // System flags cannot come in from user space.
    let mut sys = k;
    sys.flags |= ev::EOF | ev::ERROR;
    assert_eq!(
        Kev::decode(&sys.encode(Layout::Qos), Layout::Qos).flags,
        k.flags
    );
    assert_eq!(Layout::Kevent.size(), 32);
    assert_eq!(Layout::Kevent64.size(), 48);
    assert_eq!(Layout::Qos.size(), 72);
}

#[test]
fn filter_numbers() {
    assert!(is_fd_filter(evfilt::READ));
    assert!(is_fd_filter(evfilt::VNODE));
    assert!(!is_fd_filter(evfilt::PROC));
    assert!(!is_fd_filter(evfilt::MACHPORT));
    assert_eq!(!evfilt::WORKLOOP, 16);
}

#[test]
fn closed_vnode_watch_preserves_event_only_descriptor_semantics() {
    use crate::user::darwin::abi::DarwinAbi;
    use crate::user::darwin::arch::Rv;
    use crate::user::darwin::host::AT_FDCWD;
    use crate::user::darwin::io::{O_CLOEXEC, O_EVTONLY, O_NONBLOCK};
    use crate::user::darwin::process::bounded_tests::process;
    use crate::user::darwin::syscall::bsd::{file, path};

    for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
        let mut process = process(abi);
        let proc = &mut process.proc;
        let (_, mut thread) = proc.threads.pop_first().unwrap();
        let addr = thread.cpu.sp() - 128;
        let mut ctx = Ctx {
            proc,
            nr: 0,
            pc: thread.cpu.pc(),
            thread: &mut thread,
        };
        let queue = kqueue(&mut ctx).unwrap().0 as i32;
        let file = ctx.proc.fds.file(queue).unwrap();
        let crate::user::darwin::fd::FileKind::Kqueue(kq) = file.kind else {
            panic!("kqueue descriptor must hold a kqueue");
        };
        for (guest_path, result) in [
            (b"/bounded-test\0".as_slice(), Ok(Rv::one(1))),
            (b"/\0".as_slice(), Err(Errno::EISDIR)),
        ] {
            ctx.write(addr, guest_path).unwrap();
            let fd = path::openat(&mut ctx, AT_FDCWD, addr, O_EVTONLY | O_CLOEXEC, 0)
                .unwrap()
                .0 as i32;
            let slot = ctx.proc.fds.get(fd).unwrap();
            assert!(slot.cloexec && slot.file.host_fd().is_none());
            const F_GETFL: i32 = 3;
            const F_SETFL: i32 = 4;
            assert_eq!(
                file::fcntl(&mut ctx, fd, F_SETFL, u64::from(O_NONBLOCK)),
                Ok(Rv::one(0))
            );
            assert_eq!(
                file::fcntl(&mut ctx, fd, F_GETFL, 0),
                Ok(Rv::one(u64::from(O_EVTONLY | O_NONBLOCK)))
            );
            assert_eq!(file::read(&mut ctx, fd, addr, 1, Some(0)), result);

            let mut event = Kev {
                ident: fd as u64,
                filter: evfilt::VNODE,
                flags: ev::ADD | ev::CLEAR,
                fflags: 0x23, // NOTE_DELETE | NOTE_WRITE | NOTE_RENAME
                ..Default::default()
            };
            assert_eq!(register(&mut ctx, kq, &mut event), (0, None));
            assert_eq!(event.flags & ev::ERROR, 0);
            assert!(find(&ctx.proc.kq.kqueues[&kq], &event).is_some());
            assert!(kqueue_process(&mut ctx, kq, 0, 1, &mut DataArea::default()).is_empty());

            assert_eq!(file::close(&mut ctx, fd), Ok(Rv::one(0)));
            assert!(find(&ctx.proc.kq.kqueues[&kq], &event).is_none());
            event.flags = ev::DELETE;
            register(&mut ctx, kq, &mut event);
            assert_eq!(event.flags & ev::ERROR, ev::ERROR);
            assert_eq!(event.data, i64::from(Errno::ENOENT.0));
        }
    }
}
