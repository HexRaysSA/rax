use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::FileExt;

use super::*;
use crate::user::mm::anonymous_file;

fn header(len: u32, count: u16) -> [u8; HEADER] {
    let mut header = [0; HEADER];
    header[..8].copy_from_slice(MAGIC);
    header[8..12].copy_from_slice(&len.to_le_bytes());
    header[12..14].copy_from_slice(&count.to_le_bytes());
    header
}

#[test]
fn empty_fragmented_and_maximum_payloads_preserve_frame_boundaries() {
    let (mut a, mut b) = Channel::pair().unwrap();
    let payload: Vec<u8> = (0..MAX_BYTES).map(|n| (n % 251) as u8).collect();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            a.send(&[], &[]).unwrap();
            // Deliberately split every header byte across stream writes.
            for byte in header(3, 0) {
                a.socket().unwrap().write_all(&[byte]).unwrap();
            }
            for byte in b"abc" {
                a.socket().unwrap().write_all(&[*byte]).unwrap();
            }
            a.send(&payload, &[]).unwrap();
            a.send(b"last", &[]).unwrap();
        });
        assert!(b.receive().unwrap().bytes.is_empty());
        assert_eq!(b.receive().unwrap().bytes, b"abc");
        let frame = b.receive().unwrap();
        assert_eq!(frame.bytes, payload);
        assert!(frame.files.is_empty());
        assert_eq!(b.receive().unwrap().bytes, b"last");
    });
}

#[test]
fn passed_file_retains_identity_contents_cursor_and_close_on_exec() {
    let (mut a, mut b) = Channel::pair().unwrap();
    let mut file = anonymous_file().unwrap();
    file.set_len(4096).unwrap();
    file.write_all_at(b"memory-owner", 7).unwrap();
    file.seek(SeekFrom::Start(17)).unwrap();
    a.send(b"backing", &[file.as_fd()]).unwrap();
    let mut frame = b.receive().unwrap();
    assert_eq!(frame.bytes, b"backing");
    assert_eq!(frame.files.len(), 1);
    let mut received = File::from(frame.files.pop().unwrap());
    assert_ne!(file.as_raw_fd(), received.as_raw_fd());
    let mut bytes = [0; 12];
    received.read_exact_at(&mut bytes, 7).unwrap();
    assert_eq!(&bytes, b"memory-owner");
    received.seek(SeekFrom::Start(29)).unwrap();
    assert_eq!(file.stream_position().unwrap(), 29);
    // SAFETY: received owns the live descriptor inspected by F_GETFD.
    let flags = unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GETFD) };
    assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
    drop(file);
    received.write_all_at(b"shared", 0).unwrap();
    assert_eq!(received.metadata().unwrap().len(), 4096);
}

#[test]
fn descriptor_batch_limit_is_exact_and_local_rejection_does_not_poison() {
    let (mut a, mut b) = Channel::pair().unwrap();
    let files: Vec<File> = (0..=MAX_FDS).map(|_| anonymous_file().unwrap()).collect();
    let borrowed: Vec<_> = files.iter().map(AsFd::as_fd).collect();
    assert_eq!(
        a.send(&[], &borrowed).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        a.send(&vec![0; MAX_BYTES + 1], &[]).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    a.send(b"maximum-descriptors", &borrowed[..MAX_FDS])
        .unwrap();
    let received = b.receive().unwrap();
    assert_eq!(received.files.len(), MAX_FDS);
    assert_eq!(received.bytes, b"maximum-descriptors");
    a.send(b"still-live", &[]).unwrap();
    assert_eq!(b.receive().unwrap().bytes, b"still-live");
}

#[test]
fn invalid_headers_poison_both_directions_before_allocating_payload() {
    let mut cases = vec![
        header((MAX_BYTES + 1) as u32, 0),
        header(0, (MAX_FDS + 1) as u16),
    ];
    let mut magic = header(0, 0);
    magic[0] ^= 1;
    cases.push(magic);
    let mut reserved = header(0, 0);
    reserved[15] = 1;
    cases.push(reserved);
    for bytes in cases {
        let (mut a, mut b) = Channel::pair().unwrap();
        a.socket().unwrap().write_all(&bytes).unwrap();
        assert_eq!(b.receive().unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(b.receive().unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(
            b.send(&[], &[]).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert!(a.send(b"after-rejection", &[]).is_err());
    }
}

#[test]
fn rejected_descriptor_count_closes_received_endpoint() {
    let (a, mut b) = Channel::pair().unwrap();
    let (transferred, mut peer) = UnixStream::pair().unwrap();
    assert_eq!(
        a.send_header(&header(0, 2), &[transferred.as_fd()])
            .unwrap(),
        HEADER
    );
    assert_eq!(b.receive().unwrap_err().kind(), io::ErrorKind::InvalidData);
    drop(transferred);
    peer.set_nonblocking(true).unwrap();
    assert_eq!(
        peer.read(&mut [0]).unwrap(),
        0,
        "rejected frame leaked its fd"
    );
}

#[test]
fn ancillary_descriptors_in_payload_are_closed_and_rejected() {
    let (a, mut b) = Channel::pair().unwrap();
    let (transferred, mut peer) = UnixStream::pair().unwrap();
    let mut raw = a.socket().unwrap();
    raw.write_all(&header(HEADER as u32, 0)).unwrap();
    assert_eq!(
        a.send_header(&header(0, 1), &[transferred.as_fd()])
            .unwrap(),
        HEADER
    );
    assert_eq!(b.receive().unwrap_err().kind(), io::ErrorKind::InvalidData);
    drop(transferred);
    peer.set_nonblocking(true).unwrap();
    assert_eq!(peer.read(&mut [0]).unwrap(), 0);
}

#[test]
fn truncated_headers_and_payloads_poison_without_reusing_partial_bytes() {
    for bytes in [&header(0, 0)[..7], &header(3, 0)[..]] {
        let (mut a, mut b) = Channel::pair().unwrap();
        a.socket().unwrap().write_all(bytes).unwrap();
        drop(a);
        assert_eq!(
            b.receive().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(b.receive().unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    }
}

#[test]
fn sending_to_closed_peer_returns_error_without_sigpipe() {
    let (mut a, b) = Channel::pair().unwrap();
    drop(b);
    assert!(a.send(b"closed", &[]).is_err());
    assert_eq!(
        a.send(b"retry", &[]).unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(a.receive().unwrap_err().kind(), io::ErrorKind::BrokenPipe);
}
