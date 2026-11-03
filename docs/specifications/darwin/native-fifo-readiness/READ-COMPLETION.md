# Entered FIFO read completion

Readiness and read completion are separate contracts. The retained native
controls show that both Darwin and Linux can return EOF for a FIFO that has
never had a writer without reporting readiness. On the measured Darwin
kernel, the first zero-byte read also consumes its select EOF notification.

The implementation retains the original guest entry arguments, descriptor
reference, and vector array. Kernel I/O completion can release a close drain
while a Mach suspension continues to hold the thread's user return.

## Native adapters

On macOS, a pending blocking read owns a native worker, a duplicated
close-on-exec descriptor, a result buffer, and a private completion socket.
It does not change the original fileglob's flags or install signal handlers.
`thread_abort` interrupts the native read during cancellation or teardown;
the retained ARM64 and Rosetta x86-64 controls demonstrate that
`thread_abort_safely` alone did not interrupt this BSD read on the measured
kernel. Completed bytes are retained when they win a cancellation race.

Both guest `fork` and `posix_spawn` quiesce and join pending workers before
the host forks. The parent rearms unperformed reads after either a successful
or failed fork. The child drops joined resources, and exec/drop or finalized
process exit joins remaining workers. Rearming preserves an entered blocking
read if another process changes shared `O_NONBLOCK`; the caller's requested
flag change remains visible.

On Linux, a nonblocking `splice` transfers bytes into an owned private pipe.
The adapter drains that pipe and repeats the transfer until the requested
length, current data, EOF, or an error ends the operation. `EAGAIN` with no
transferred data parks the entered guest read. No pathname reopening or
shared `F_SETFL` change is required. Repeated transfers preserve data larger
than the private pipe's capacity. Zero-byte reads still check descriptor
access, including rejecting write-only and `O_PATH` descriptors.

The existing transfer limit remains `IO_MAX = 2,147,483,647` bytes. The macOS
buffer reserves the request capacity and initializes only the prefix returned
by the native read; allocator commitment is host dependent. Linux grows its
buffer in chunks of at most 1,048,576 bytes. Data-copy work is O(bytes returned),
and retained buffer capacity is O(requested bytes). A macOS worker requests a
131,072-byte stack in addition to the platform's thread bookkeeping.

## Evidence

`native-abort-fifo-control-v1.{c,json}` captures both Mach interruption calls
on ARM64 and Rosetta x86-64. `native-held-signal-read-v1.{c,json}` confirms
that a caught signal releases a close drain while the reader's user handler
and completion store remain held until `thread_resume`.

`fifo-runtime-v1.c` is a standalone program linked to the installed
libsystem/libpthread. It covers never-written FIFO EOF, zero-byte reads,
a blocked scalar/vector read, a real fork, a child changing shared flags,
completion in the parent, and repeated EOF after the last writer closes.
`fifo-runtime-records-v1.json` retains equal native/emulated stdout for all
four architecture/vector combinations. `fifo-runtime-build-v1.json` records
the source and native image hashes plus the original compiler arguments.
No separate sysroot was supplied.

The Rust native-module tests additionally cover cancellation before native
entry, 100 data/cancellation races, 1,000 early cancellations, retaining
completed bytes across a pause, and child cleanup after a real host fork.
These are bounded observations and regression cases; they do not establish
complete userland emulation or native behavior on an Intel Mac.
