[← Documentation home](../../../README.md) · [User-mode overview](../user-mode.md)

# Linux descriptor I/O

Event descriptors, readiness, epoll, splicing, and Linux asynchronous I/O.

Unless explicitly marked i386, Linux syscall and signal-frame coverage here
refers to x86-64, AArch64, and RV64 (`LinuxAbi::ALL`). Host and ABI
qualifications remain in [Status and limitations](../../reference/status-and-limitations.md#required-user-mode-qualifications).

## Event, timer, and signal descriptors

Implementation: `fs::anon`.

`eventfd`, `timerfd`, and `signalfd` are anonymous-inode files (mode `0600` without
a file type, `anon_inode:[name]` in `/proc/<pid>/fd`, `O_RDWR` without
`O_LARGEFILE`, `lseek` 0, no `pread`).

Their state lives in anonymous memory shared with forked processes, so a description
held by a parent and a child is one counter or timer, as on Linux; a lock word
orders changes. A condition a sleeper waits for is mirrored as a *level*: one
direction of a host socket pair holds exactly one byte while it is true (an
`eventfd` readable or writable, a `timerfd` with ticks), so the scheduler's host
`poll`, in any process, wakes on it without consuming it.

A `timerfd` fires lazily too: one tick at its expiry, the missed periods counted
when it is read or queried. A `signalfd` reports the reading thread's pending
signals; queueing a signal wakes threads sleeping on a `signalfd` of it, even while
the signal is blocked (`signalfd_notify`).

## Readiness and `epoll`

Implementation: `syscall::ready`, `fs::epoll`.

Each file reports the mask its `f_op->poll` computes (`pipe_poll` for pipes, with
the queued bytes read by `FIONREAD`, since the host's `poll` reports pipes
differently), a level (bytes queued, a counter, ticks, signals), and what a sleeper
waits on; `poll`, `select`, and `epoll` share it.

An `epoll` item is keyed by the open file description, held weakly, and the
descriptor number. Wake-ups the emulator causes itself (a pipe written, read, or
closed through the guest, an `eventfd` changed, a nested instance becoming ready)
link the watching items at once, in order, as `ep_poll_callback` does; readiness
from outside (terminal input, other processes, timer expiries, signals) is found
when an instance is polled, an edge-triggered item counting a growth of its file's
level as a wake-up.

Reporting follows `ep_send_events`: items re-polled at the head of the ready list,
level-triggered ones queued again at the tail after those there was no room for.

## Splicing

Implementation: `syscall::splice`.

`splice` and `vmsplice` move data through the pipes' host descriptors by reading and
writing, with the kernel's checks in order (a pipe's offsets before either is read,
`*off_out` before `*off_in`, the access modes, a pipe to itself, `O_APPEND`,
positions where a file has none, `rw_verify_area`, files without `splice_read` or
`splice_write`). A transfer sleeps where the kernel's does (for a pipe's data before
anything moved, for room) and then moves what there is, never taking from a pipe or
stream more than its destination takes at once (a writable host pipe has room for
`PIPE_BUF` bytes); bytes a destination then does not take are held and written
before the call returns. The offset or the file's position moves past what moved (a
device's stays, as `copy_splice_read` leaves it). `vmsplice` sleeps unless
`SPLICE_F_NONBLOCK` (a pipe's `O_NONBLOCK` does not count). `tee` copies through the
host's `tee(2)`, which Linux hosts have.

## Asynchronous I/O

Implementation: `aio`, `syscall::aio`.

A context's ring is a shared mapping of `/[aio] (deleted)`, a special mapping (never
locked, grown, or duplicated) whose header and events the kernel side writes through
its object, so the process may reap events itself; its address is the context's
identifier, and a lookup reads the ring's `id` field through the process's mapping,
as `lookup_ioctx` does. `mremap` moving a ring moves its context (`aio_ring_mremap`;
a forked child, which has no contexts, cannot move one).

Request slots are counted per CPU in batches as `__get_reqs_available` counts them,
for the one emulated CPU, and come back as the process reaps.

`io_submit` checks each request in the kernel's order and runs its read, write, or
sync at once, as the kernel does for buffered I/O: the transfer's result, error or
not, is the completion (`-EINTR` for a transfer a signal interrupts), and a transfer
that sleeps (an empty pipe) makes `io_submit` sleep with the requests before it
submitted.

`IOCB_CMD_POLL` completes at once when its file is ready; otherwise it waits and is
polled again as a thread enters each system call (a thread sleeping in any call
wakes for its file), and it completes with the key of the wake-up that readied it
(`aio_poll_wake`) where the waker passes one (pipes, sockets, `eventfd`, `timerfd`,
`epoll`), else with the events polled.

`IOCB_FLAG_RESFD` signals an `eventfd` per completion. `io_getevents` moves the
ring's head only once every event is copied out. `aio-nr` counts this process's
contexts.

## Evidence and related contracts

[Linux descriptor I/O tests](../../development/testing/user-mode.md#descriptor-io)
record the unit, differential, and host-specific evidence for these contracts.

See also [Linux processes and scheduling](processes.md).

## Captured Linux standard streams

`LinuxConfig::console` defaults to `Console::Host`, preserving inherited CLI
standard descriptors. `Console::Captured(CapturedConsole)` instead creates
three `FileObject::Console` descriptions with no host descriptor or host path.
Cloned configurations and duplicated guest descriptors share the same bounded
buffers. Closing or reassigning a descriptor does not discard queued output.

Captured stdin is finite: an empty buffer reads as EOF, and the caller can feed
more input between runs. Stdout and stderr share the configured output bound;
a descriptor write either retains all its bytes or returns `EIO`. The syscall
layer gathers ordinary vectors and may split the transfer into chunks: it
returns the retained prefix length if a later chunk fails. The unpositioned
`preadv2`/`pwritev2` forms use the same readv/writev routes, as the Linux
[`fs/read_write.c`](https://github.com/torvalds/linux/blob/master/fs/read_write.c)
`preadv2`/`pwritev2` offset −1 branches require. Input and combined output each have an
independent capacity of `C` bytes, so their aggregate queued payload is at most
`2C` bytes. Reads/writes take O(n) time for n transferred bytes; storage is O(C).

These are non-seekable character streams, not terminal emulation: positioned
I/O returns `ESPIPE`, terminal ioctls return `ENOTTY`, and input `FIONREAD`
reports the queued byte count (saturated at `INT_MAX`). `poll`/`select` observe
immediate input/EOF or output/error completion. There is no wait-queue-backed
poll operation, so epoll, AIO poll, and io_uring poll registration reject these
descriptions. Regular read/write and vectored operations use the common Linux
syscall paths, including guest-memory validation and native/compat ABI decoding.

This console route does not close the Linux host filesystem or other host
services. The Linux personality remains Unix-host-only; Windows process
capture uses the same portable `CapturedConsole`, with its existing Win32
adapter. Linux Windows-host support and the closed Linux/Darwin host profile
remain separate embedding work. No C ABI or Assist interface changes here.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| LC1 | Finite captured input and immediate bounded-output errors need no host descriptor or blocking wait. | `CapturedConsole` owns in-memory queues; `FileObject::Console` has no native handle. | Linux standard-stream routing and readiness. | Empty/refilled input, full/zero capacity, bad guest pointers, duplicates, closure, partial vectored/chunked output on all five guest ABIs. | Run `cargo test --locked --no-default-features --lib user::linux::tests::console::`; any host handle, lost bytes, blocked readiness, or incorrect prefix falsifies this contract. | Confirmed by adapter tests on macOS; native Linux validation tracked separately. |

High-impact scope boundary: console capture alone is not host isolation.
Startup, paths, process services, and asynchronous operations still require the
closed embedding profile before exposing Linux processes through the C API.
