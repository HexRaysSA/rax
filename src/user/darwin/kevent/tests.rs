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
