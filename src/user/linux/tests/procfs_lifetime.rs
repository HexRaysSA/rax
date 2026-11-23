//! Guest procfs lifetime ownership, independent of host /proc availability.

use super::harness::{Harness, each_abi};
use crate::user::linux::abi::Sysno;
use crate::user::linux::procfs;
use crate::user::linux::syscall::thread::cf::*;

const THREAD: u64 = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;

fn owned(h: &Harness, path: &str) -> bool {
    let threads: Vec<_> = h.proc.threads.iter().collect();
    procfs::owned(&h.proc.state, &threads, path)
}

fn absent_owned(h: &Harness, path: &str) {
    let threads: Vec<_> = h.proc.threads.iter().collect();
    assert!(
        procfs::lookup(&h.proc.state, threads[0], &threads, path).is_none(),
        "{path}"
    );
    assert!(procfs::owned(&h.proc.state, &threads, path), "{path}");
}

fn clone_thread_at(h: &mut Harness, tid: u32) -> u64 {
    let args = h.scratch + 0x100;
    let requested = h.scratch + 0x200;
    h.proc
        .state
        .space
        .write_raw(requested, &tid.to_le_bytes())
        .unwrap();
    let mut words = [0u64; 11];
    words[0] = THREAD;
    words[8] = requested;
    words[9] = 1;
    for (index, value) in words.into_iter().enumerate() {
        h.proc
            .state
            .space
            .write_raw(args + index as u64 * 8, &value.to_le_bytes())
            .unwrap();
    }
    // Only the guest's effective identity changes for the requested TID.
    let euid = h.proc.state.creds.1;
    h.proc.state.creds.1 = 0;
    let tid = h.ok(Sysno::Clone3, &[args, 88]);
    h.proc.state.creds.1 = euid;
    tid
}

#[test]
fn procfs_lifetime_retires_numeric_and_task_aliases_and_accepts_live_id_reuse() {
    each_abi(|abi| {
        let mut h = Harness::embedded(abi);
        let tid = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]) as i32;
        let child = h.index_of(tid);
        h.start(child, Sysno::Exit, &[0]);
        for path in [
            format!("/proc/{tid}"),
            format!("/proc/{tid}/"),
            format!("/proc/{tid}/status"),
            format!("/proc/{tid}/fd/0"),
            format!("/proc/{tid}/fdinfo/0"),
            format!("/proc/self/task/{tid}/status"),
            format!("/proc/{}/task/{tid}", h.proc.state.pid),
        ] {
            absent_owned(&h, &path);
        }
        assert!(!owned(&h, &format!("/proc/{}/status", tid + 1)));
        // A reused virtual ID is live again; history is not a negative cache.
        assert_eq!(clone_thread_at(&mut h, tid as u32), tid as u64);
        let threads: Vec<_> = h.proc.threads.iter().collect();
        assert!(matches!(
            procfs::lookup(
                &h.proc.state,
                threads[0],
                &threads,
                &format!("/proc/{tid}/status")
            ),
            Some(procfs::ProcEntry::File(_))
        ));
        let child = h.index_of(tid);
        h.start(child, Sysno::Exit, &[0]);
        absent_owned(&h, &format!("/proc/{tid}/status"));
    });
}

#[test]
fn procfs_lifetime_sparse_clone3_ids_never_claim_unassigned_gaps() {
    each_abi(|abi| {
        let mut h = Harness::embedded(abi);
        assert_eq!(clone_thread_at(&mut h, 4_000_000), 4_000_000);
        let child = h.index_of(4_000_000);
        h.start(child, Sysno::Exit, &[0]);
        absent_owned(&h, "/proc/4000000/status");
        for id in [h.proc.state.pid + 1, 3_999_999, 4_000_001] {
            assert!(!owned(&h, &format!("/proc/{id}/status")), "{abi:?}/{id}");
            assert!(!owned(&h, &format!("/proc/{id}/fd/0")), "{abi:?}/{id}");
        }
    });
}

#[test]
fn procfs_lifetime_nonleader_exec_keeps_retired_thread_identity() {
    each_abi(|abi| {
        let mut h = Harness::embedded(abi);
        let leader = h.proc.state.pid;
        let tid = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]) as i32;
        h.proc.state.space.write_raw(h.scratch, b"/prog\0").unwrap();
        let child = h.index_of(tid);
        assert_eq!(h.start(child, Sysno::Execve, &[h.scratch, 0, 0]), None);
        assert_eq!(h.proc.threads.len(), 1, "{abi:?}");
        assert_eq!(h.proc.threads[0].tid, leader, "{abi:?}");
        absent_owned(&h, &format!("/proc/{tid}/status"));
        absent_owned(&h, &format!("/proc/self/task/{tid}"));
    });
}

#[cfg(unix)]
#[test]
fn procfs_lifetime_known_process_links_keep_the_existing_numeric_root_route() {
    each_abi(|abi| {
        let mut h = Harness::embedded(abi);
        let tid = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]) as i32;
        let child = h.index_of(tid);
        h.start(child, Sysno::Exit, &[0]);
        let path = format!("/proc/{tid}");
        assert!(owned(&h, &path));
        // A known process relationship can reuse that number. Its root route
        // must retain the pre-existing behavior rather than become a tombstone.
        let (link, _remote) = crate::user::linux::ptrace::Link::pair().unwrap();
        h.proc.state.adopted.push((tid, link));
        assert!(!owned(&h, &path), "{abi:?}");
        h.proc.state.adopted.clear();
        assert!(owned(&h, &path), "{abi:?}");
    });
}
