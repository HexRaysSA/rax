[← Documentation home](../../../README.md) · [User-mode overview](../user-mode.md)

# Linux networking and IPC

Socket translation, netlink, interface requests, System V IPC, and POSIX message
queues.

Unless explicitly marked i386, Linux syscall and signal-frame coverage here
refers to x86-64, AArch64, and RV64 (`LinuxAbi::ALL`). Host and ABI
qualifications remain in [Status and limitations](../../reference/status-and-limitations.md#required-user-mode-qualifications).

## Sockets

Implementation: `net`, `syscall::net`.

`AF_UNIX`, `AF_INET`, and `AF_INET6` sockets are host sockets, always non-blocking
on the host; the personality keeps what Linux has and the host lacks (the name a
Unix socket was bound to, the timeouts, Linux's reported buffer sizes, the listening
state, its own shutdowns) and translates addresses, flags, options, and errors.

A call that would block sleeps on the socket (`Resume::Socket` records the bytes
transferred, the timeout's end, and a batch position), so
`SO_RCVTIMEO`/`SO_SNDTIMEO` end it with `EAGAIN` and a signal with `-ERESTARTSYS`,
or `EINTR` once a timeout is set (`sock_intr_errno`). Unix paths resolve through the
VFS to absolute host paths; a host path longer than the host's `sun_path` is reached
through its directory (a `/proc/self/fd` link on Linux, a short-lived symbolic link
on macOS). The abstract namespace is the host's on Linux; on macOS an abstract name
is a socket file in a per-user directory named by a hash, with the name recorded
beside it and a lock file the binding socket holds, so a name is taken exactly while
its socket lives. `SCM_RIGHTS` descriptors travel as host descriptors, so they reach
other processes; each send also records the description by its host object's
identity, so a receiver in the same process gets the same description (shared status
flags), and a description without a host descriptor travels as a stand-in socket
only that record resolves. Readiness is `sock_poll`'s: the host's mask on Linux; on
macOS, whose masks differ (no `POLLRDHUP`, `POLLHUP` after one shutdown, no
`POLLOUT` after a shutdown, nothing for a new stream socket), it is derived from the
`unix_poll`/`tcp_poll`/`datagram_poll` rules and the socket's state (`net::poll`).

## Netlink

Implementation: `net::netlink`.

On Linux hosts `AF_NETLINK` sockets are the host's, every protocol, with `struct
sockaddr_nl` and the `SOL_NETLINK` options and control messages passed through.
Elsewhere `NETLINK_ROUTE` is emulated: the socket's host descriptor is a readiness
level over a queue of datagrams the kernel side fills when the guest sends requests.
`route` answers them as `rtnetlink_rcv_msg` dispatches (link dumps and lookups,
address dumps by family, one IPv6 address, `-EPERM` for changes without
`CAP_NET_ADMIN`, `-EOPNOTSUPP` otherwise), from a snapshot of the host's interfaces
(`ifaces`: `getifaddrs` and the media status, translated to Linux types, flags,
operational states, and scopes). The socket side follows `af_netlink.c`: port IDs
(the process's, then negative ones), groups, acknowledgements carrying the request
unless capped, a dump paced a datagram per receive by the largest buffer seen with
`NLMSG_DONE` alone where rtnetlink splits it, one dump at a time, `MSG_TRUNC`, and
`NETLINK_PKTINFO`. A forked child gets its own readiness level over its copy of the
queue.

## Interface requests

Implementation: `net::ifreq`.

The socket `ioctl`s about interfaces (`SIOCGIFCONF`, `SIOCGIFINDEX`, `SIOCGIFNAME`,
`SIOCGIFFLAGS`, `SIOCGIFHWADDR`, `SIOCGIFADDR`, and the rest) pass through to a
Linux host with their `struct ifreq` bytes (every guest ABI is LP64, so the layout
is the host's; `SIOCGIFCONF`'s buffer goes through a host copy). Elsewhere they are
answered from the same view of the host's interfaces as netlink, routed by the
socket's family as `sock_ioctl` routes them (`inet_ioctl` takes the IPv4 address
requests, other families reach `dev_ioctl`, which does not know them), with the
kernel's name handling (an alias's `:` suffix, the 16th byte cleared) and the
argument's untouched bytes kept.

## System V IPC

Implementation: `ipc`, `syscall::ipc`.

The objects of every `rax-user` process of a host user share one namespace: a
directory (per user under the temporary directory, or `LinuxConfig::ipc_dir`)
holding each type's table as text, read and replaced whole under an exclusive
`flock`, with identifiers allocated as `ipc_idr_alloc` allocates them.

A shared memory segment's pages are a host file there, which `shmat` maps shared
(named `/SYSV<key> (deleted)`, its identifier the inode `/proc/<pid>/maps` shows),
so every process sees every store. Attaches are counted by mapping as the kernel
counts them (a split mapping counts twice and is not merged back): after the calls
that change its mappings, and at `fork`, `execve`, and exit, a process publishes how
many mappings of each segment it has, and `shm_nattch` is the sum over processes
still alive, so a segment marked for removal goes with its last attach even when its
last process was killed.

A semaphore operation list is applied all or none, in order, under the table's lock;
a caller that must wait records its blocking operation (for `GETNCNT` and `GETZCNT`)
and tries again every 2 ms until it can, its timeout passes, the set is removed
(`EIDRM`), or a signal ends it (`EINTR`). Each thread holds a reference to an undo
list, made at its first `SEM_UNDO` and shared by the threads `CLONE_SYSVSEM` makes;
the adjustments, recorded per process, apply when the last holder leaves its list
(exit, `unshare(CLONE_SYSVSEM)`) and no other thread holds one, at the process's
exit otherwise, or, for a killed process, when the table is next read after it is
gone.

A message queue keeps its messages in the table; a send that does not fit and a
receive that finds nothing wait the same way, a signal ending them with
`-ERESTARTNOHAND`.

## POSIX message queues

Implementation: `ipc::mqueue`, `syscall::mqueue`.

A queue is a host file in the IPC namespace directory holding its attributes, owner,
notification, messages, and waiting tasks, with a table of names beside it; a
description holds the file open, so an unlinked queue lives until its last
description closes in any process, and every change happens under the namespace's
lock.

Messages go highest priority first, first in first out within one (`msg_insert`,
`msg_get`). A task that must wait registers in the queue and renews its registration
as it retries every 2 ms: a send hands its message to the first waiting receiver
(`pipelined_send`), and a receive that frees a slot queues the first waiting
sender's message (`pipelined_receive`); a registration not renewed for a second is a
task that is gone.

A notification goes to its registering process when a message arrives in an empty
queue without a waiting receiver: `SI_MESGQ` with the sender's IDs and the value,
sent to another process through the host with the record `sigmail` carries, and
dropped by that process's close of any descriptor of the queue.

The queue file reads as its status line, seeks against its size, polls readable
while messages wait and writable while there is room, and stats as the kernel's
inode; `/proc/<pid>/fd` shows `/<name>`, and ` (deleted)` once unlinked.

## Evidence and related contracts

[Linux networking and IPC tests](../../development/testing/user-mode.md#networking-and-ipc)
record the unit, differential, and host-specific evidence for these contracts.
