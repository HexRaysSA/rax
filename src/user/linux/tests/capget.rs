//! `capget` target-PID validation and capability projection.

use super::harness::{Harness, each_abi};
use crate::user::linux::abi::Sysno;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::children::ForkedSelf;
use crate::user::linux::host;
use crate::user::linux::signal::SIGCHLD;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering;

const V1: u32 = 0x1998_0330;
const V2: u32 = 0x2007_1026;
const V3: u32 = 0x2008_0522;
const DATA_LEN: usize = 24;

fn header(h: &Harness, at: u64, version: u32, pid: i32) {
    let mut bytes = version.to_le_bytes().to_vec();
    bytes.extend_from_slice(&pid.to_le_bytes());
    h.proc.state.space.write_raw(at, &bytes).unwrap();
}

fn get(h: &Harness, at: u64, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    h.proc.state.space.read_raw(at, &mut bytes).unwrap();
    bytes
}

fn capget(h: &mut Harness, hdr: u64, data: u64) -> i64 {
    h.call(Sysno::Capget, &[hdr, data])
}

#[cfg(target_os = "linux")]
fn native_capget(pid: i32) -> Result<Vec<u8>, i32> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    let mut header = Header { version: V3, pid };
    let mut data = [Data::default(); 2];
    // SAFETY: the syscall writes only to the live structs above.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut header as *mut Header,
            data.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()
            .raw_os_error()
            .expect("failed syscall has an errno"));
    }
    let mut bytes = Vec::with_capacity(DATA_LEN);
    for d in data {
        bytes.extend_from_slice(&d.effective.to_le_bytes());
        bytes.extend_from_slice(&d.permitted.to_le_bytes());
        bytes.extend_from_slice(&d.inheritable.to_le_bytes());
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn assert_matches_native(pid: i32, native: &Result<Vec<u8>, i32>) {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        h.proc.state.config.processes = true;
        let (hdr, data) = (h.scratch, h.scratch + 0x100);
        header(&h, hdr, V3, pid);
        match native {
            Ok(expected) => {
                assert_eq!(capget(&mut h, hdr, data), 0);
                assert_eq!(get(&h, data, DATA_LEN).as_slice(), expected.as_slice());
            }
            Err(errno) => assert_eq!(capget(&mut h, hdr, data), -(*errno as i64)),
        }
    });
}

#[cfg(target_os = "linux")]
struct BarrierRelease(std::sync::Arc<std::sync::Barrier>);

#[cfg(target_os = "linux")]
impl Drop for BarrierRelease {
    fn drop(&mut self) {
        self.0.wait();
    }
}

#[test]
fn target_pid_errors_precede_capability_copyout() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        h.proc.state.config.processes = true;
        let (hdr, data) = (h.scratch, h.scratch + 0x100);
        let sentinel = [0xa5; DATA_LEN];
        h.proc.state.space.write_raw(data, &sentinel).unwrap();

        header(&h, hdr, V3, -1);
        assert_eq!(capget(&mut h, hdr, data), -(EINVAL as i64));
        assert_eq!(get(&h, data, DATA_LEN), sentinel.to_vec());

        header(&h, hdr, V3, i32::MAX);
        assert_eq!(capget(&mut h, hdr, data), -(ESRCH as i64));
        assert_eq!(get(&h, data, DATA_LEN), sentinel.to_vec());

        // Linux skips target lookup when no output buffer was supplied.
        header(&h, hdr, V3, -1);
        assert_eq!(capget(&mut h, hdr, 0), 0);

        header(&h, hdr, V3, 0);
        assert_eq!(capget(&mut h, hdr, 1), -(EFAULT as i64));

        h.proc.state.creds.1 = 0;
        header(&h, hdr, V1, 0);
        assert_eq!(capget(&mut h, hdr, data), 0);
        let mut v1 = Vec::new();
        for word in [u32::MAX, u32::MAX, 0] {
            v1.extend_from_slice(&word.to_le_bytes());
        }
        assert_eq!(get(&h, data, 12), v1);

        header(&h, hdr, V2, 0);
        assert_eq!(capget(&mut h, hdr, data), 0);
        let mut v2 = Vec::new();
        for word in [u32::MAX, u32::MAX, 0, 0x1ff, 0x1ff, 0] {
            v2.extend_from_slice(&word.to_le_bytes());
        }
        assert_eq!(get(&h, data, DATA_LEN), v2);
    });
}

#[cfg(target_os = "linux")]
#[test]
fn another_host_task_returns_its_capability_sets() {
    assert_matches_native(1, &native_capget(1));

    // The Linux lookup accepts a visible TID as well as a process leader;
    // the general task helper intentionally recognizes fewer foreign TIDs.
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let worker_barrier = barrier.clone();
    let (send, receive) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        // SAFETY: gettid takes no pointers and returns the caller's TID.
        let tid = unsafe { libc::syscall(libc::SYS_gettid) as i32 };
        send.send(tid).unwrap();
        worker_barrier.wait();
    });
    let tid = receive.recv().unwrap();
    let release = BarrierRelease(barrier.clone());
    assert_matches_native(tid, &native_capget(tid));
    drop(release);
    worker.join().unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn guest_child_capget_uses_guest_credentials_when_pid_matches_a_host_task() {
    let mut h = Harness::embedded(crate::user::linux::abi::LinuxAbi::Riscv64);
    let guest_pid = h.ok(Sysno::Clone, &[SIGCHLD as u64, 0, 0, 0, 0]) as i32;
    let host_pids = [std::process::id() as i32, unsafe { libc::getppid() as i32 }];
    let (host_pid, host_caps) = host_pids
        .into_iter()
        .filter(|pid| *pid != h.proc.state.pid)
        .find_map(|pid| native_capget(pid).ok().map(|caps| (pid, caps)))
        .expect("a visible host PID distinct from the guest parent");
    let mut root_caps = Vec::with_capacity(DATA_LEN);
    for word in [u32::MAX, u32::MAX, 0, 0x1ff, 0x1ff, 0] {
        root_caps.extend_from_slice(&word.to_le_bytes());
    }
    let guest_euid = if host_caps == root_caps { 1000 } else { 0 };
    let expected = if guest_euid == 0 {
        root_caps
    } else {
        vec![0; DATA_LEN]
    };

    let child = h.proc.state.children.get_mut(guest_pid).unwrap();
    // Guest and host PID namespaces are independent, so these IDs may match.
    child.pid = host_pid;
    child.guest.as_mut().unwrap().state.creds.1 = guest_euid;

    let (hdr, data) = (h.scratch, h.scratch + 0x100);
    header(&h, hdr, V3, host_pid);
    assert_eq!(capget(&mut h, hdr, data), 0);
    assert_eq!(get(&h, data, DATA_LEN), expected);
}

#[cfg(unix)]
#[test]
fn host_backed_guest_children_track_effective_uid_through_exit() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        h.proc.state.config.processes = true;
        let (hdr, data) = (h.scratch, h.scratch + 0x100);
        let root_caps = {
            let mut bytes = Vec::new();
            for word in [u32::MAX, u32::MAX, 0, 0x1ff, 0x1ff, 0] {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            bytes
        };

        let expected = |euid| {
            if euid == 0 {
                root_caps.clone()
            } else {
                vec![0; DATA_LEN]
            }
        };

        for (pid, euid, changed_euid) in [(i32::MAX - 1, 0, 1000), (i32::MAX - 2, 1000, 0)] {
            let (status, write) = host::status_pipe().unwrap();
            let shared_euid = std::sync::Arc::new(host::SharedWords::new(1).unwrap());
            shared_euid.words()[0].store(u64::from(euid), Ordering::Relaxed);
            #[cfg(target_os = "linux")]
            let pipe_size = unsafe { libc::fcntl(status.as_raw_fd(), libc::F_GETPIPE_SZ) };
            h.proc.state.children.add(
                pid,
                status,
                None,
                SIGCHLD,
                h.proc.state.pid,
                0,
                Some(shared_euid.clone()),
            );

            header(&h, hdr, V3, pid);
            assert_eq!(capget(&mut h, hdr, data), 0);
            assert_eq!(get(&h, data, DATA_LEN), expected(euid));

            let forked = ForkedSelf {
                status: write,
                guest_euid: shared_euid,
                vfork: false,
            };
            #[cfg(target_os = "linux")]
            {
                assert!(pipe_size > 0);
                for uid in 0..=(pipe_size as usize / 5) {
                    forked.effective_uid((uid & 1) as u32);
                }
            }
            forked.effective_uid(changed_euid);
            header(&h, hdr, V3, pid);
            assert_eq!(capget(&mut h, hdr, data), 0);
            assert_eq!(get(&h, data, DATA_LEN), expected(changed_euid));

            h.proc.state.children.get_mut(pid).unwrap().zombie = Some((0, (0, 0, 0)));
            header(&h, hdr, V3, pid);
            assert_eq!(capget(&mut h, hdr, data), 0);
            assert_eq!(get(&h, data, DATA_LEN), expected(changed_euid));
        }
    });
}
