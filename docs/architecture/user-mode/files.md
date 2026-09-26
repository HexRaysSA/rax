[← Documentation home](../../../README.md) · [User-mode overview](../user-mode.md)

# Linux files and notifications

Path resolution, open file descriptions, metadata, attributes, locks, and inotify.

Unless explicitly marked i386, Linux syscall and signal-frame coverage here
refers to x86-64, AArch64, and RV64 (`LinuxAbi::ALL`). Host and ABI
qualifications remain in [Status and limitations](../../reference/status-and-limitations.md#required-user-mode-qualifications).

## Files

Guest paths resolve through the sysroot overlay; host files are opened with `std`
and wrapped as Linux open file descriptions (shared by `dup`, with per-descriptor
close-on-exec). `/proc` entries about the process are synthesized from personality
state; `/proc/<pid>/fdinfo` (`fdinfo`) prints what `seq_show` does (position, status
flags with `O_CLOEXEC`, a mount ID per file system, the inode number) and the lines
of the pidfd, `eventfd`, `timerfd`, `signalfd`, and `epoll` `show_fdinfo`
operations.

## Nodes, times, and the umask

Implementation: `nodes`.

`mknod` and `mknodat` follow `do_mknodat`: the type, then the name, then the
privilege (device nodes need a privileged guest); FIFOs and device nodes are host
nodes, and a socket node is a bound Unix socket where the host refuses to make one
(macOS, for other users than root). `utimensat` looks the path up before it checks
the times, and `utime`, `utimes`, and `futimesat` convert to it as `fs/utimes.c`
does. The guest has its own umask, inherited from the host at start; a new file or
directory gets the mode that umask leaves even where the host's stripped more bits.

## Extended attributes

Implementation: `xattr`.

The `*xattr` calls and the `*xattrat` calls check in `fs/xattr.c`'s order (flags,
name, value, object, then the namespace's permission) and give host files the
handlers of a disk file system mounted without POSIX ACLs: `user.*` on regular files
and directories only, `trusted.*` for a privileged guest, `security.*` set only by
one, and `EOPNOTSUPP` for other names, `system.posix_acl_*` included. The attributes
are the host file's; a macOS host stores a name it cannot hold (not UTF-8, or longer
than 127 bytes) under a hashed `rax.x.` name whose value begins with the full name,
and its own names are not shown. Sockets have `sockfs`'s `system.sockprotoname`;
pipes, anonymous inodes, and synthesized `/proc` files have none.

## File locks

Implementation: `locks`.

Guest processes are host processes and each open file description owns one host
descriptor, so guest locks are host locks with Linux's owners: `flock` locks and OFD
record locks belong to the description (shared by `dup` and `fork`), POSIX record
locks to the process; they also exclude other host programs. `fs/locks.c`'s checks
come first (the command, the descriptor, then `flock64_to_posix_lock`'s range, the
type, and the access mode).

Closing any descriptor of a file releases the process's POSIX locks on it
(`locks_remove_posix`), also when the description stays open through another
descriptor; the descriptors the emulator keeps for mappings of such a file are kept
open until then, since closing one would release the locks on the host while
`munmap` releases none on Linux.

A conversion that would wait loses the old `flock` lock, as `flock_lock_inode`
removes it first (a macOS host keeps it; it is removed there).

A waiting call (`flock` without `LOCK_NB`, `F_SETLKW`, `F_OFD_SETLKW`) tries again
every 2 ms while other guest threads run, and a signal ends it with `-ERESTARTSYS`.

## Groups, read-ahead, and range sync

Implementation: `misc`.

Supplementary groups start as the host's; `setgroups` needs a privileged guest and
sorts them as `groups_sort` does, and `/proc/<pid>/status` lists them. `readahead`
checks the descriptor and the file's type as `ksys_readahead` does;
`sync_file_range` checks its flags, then the range, then the file as `fs/sync.c`
does, and writing a range (`SYNC_FILE_RANGE_WRITE`) writes the host file's data.

## File-system notification

Implementation: `fsnotify`, `syscall::inotify`, `syscall::notify`.

An inotify instance is the host's on Linux hosts (`fsnotify::Backend::Host`): the
host kernel reports what any process does to the files, `rax-user`'s own host calls
included, which follow the guest's (a vectored read that finds nothing makes a
zero-length host `readv`, `truncate` truncates by path).

Elsewhere it is emulated (`Backend::Emulated`): the file calls report what they did,
in the order of `include/linux/fsnotify.h`'s hooks, to a namespace every `rax-user`
process of the host user shares — a directory holding the watches (the marks) in a
mapped index with a hash of the watched inodes, each instance's queue in a mapped
file, and a FIFO per instance that holds a byte while its queue is not empty — so
that a child's writes reach its parent's instance.

Delivery follows `fsnotify`, `send_to_group`, and `inotify_handle_inode_event` (a
directory hears of a child before the child itself; names only for entry changes;
`IN_ISDIR`; the special-file and `IN_EXCL_UNLINK` exclusions; one-shot watches), and
the queue `fsnotify_insert_event` (merging with the last event, one `IN_Q_OVERFLOW`
past `max_queued_events`).

An open file carries a token whose last reference reports its close: its mappings
hold it (`vm_file`), a forked process shares it through a count in the namespace,
exit releases it, and an inode whose last link went while it was open ends
(`IN_DELETE_SELF`) at its last close. `execve` opens the executable and interpreter
(`IN_OPEN`, `IN_ACCESS`) for as long as the image runs. Nothing costs more than two
loads while nothing is watched.

## Evidence and related contracts

[Linux files and notifications tests](../../development/testing/user-mode.md#files-and-notifications)
record the unit, differential, and host-specific evidence for these contracts.
