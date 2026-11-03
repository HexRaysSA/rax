# Closing an entered Darwin pipe writer

An anonymous pipe writer can be parked while its pipe is full. Closing that
descriptor must finish its entered write with `EPIPE` (Darwin errno 32), post
`SIGPIPE` through the existing signal policy, and release the descriptor slot.
`F_SETNOSIGPIPE` suppresses the signal. The corresponding FIFO close retains
the slot until its entered write finishes. Read-side EOF behavior is unchanged.

The production change is confined to the anonymous-pipe close continuation.
It uses the already-entered call and readiness wait, so a later cookie or iovec
mutation does not revalidate the call. Completion proceeds while Mach
suspension holds the guest's user return. FIFO workers, fork barriers, timed
record locks, signal dispositions, and public APIs keep their existing owners.
Collecting matches costs O(T) time and O(K) temporary space for T guest threads
and K entered operations. Each completed writer also invokes the existing
SIGPIPE posting path.

## Native evidence

`native-signal-v1.json` contains 16 independent native controls: scalar/vector
guarded writes, pipe/FIFO, `F_SETNOSIGPIPE` off/on, and arm64/x86-64. Each fills
the pipe, observes an entered writer, closes its descriptor concurrently, drains
the retained reader, joins both native threads, and records signal delivery.
The x86-64 executable ran through Rosetta on the recorded ARM64 macOS host;
this is not physical Intel qualification. The native signal handler counted one
signal for a pipe with suppression disabled, and zero otherwise.

The FIFO wait-state observer sometimes returns -1 after its bounded observation
window. Descriptor reuse (5 rather than 4), the joined close result, and the
complete written payload establish reservation and completion independently.
The receipt retains that observer result without relabeling it as a detected
wait. Host pipe capacity is recorded rather than assumed.

The original 64 native cookie/iovec/close controls remain in
`../native-guarded-fd/blocked-write-records-*-v12.json`; those controls selected
`SIG_IGN`. Their exact producer and inputs are included in `bindings-v1.json`.
`native-producer-derivation-v1.json` describes the three changes used to obtain
the new signal controls. The recorded build paths identify the historical run.

Run the portable evidence verifier from the repository root:

```text
python3 docs/specifications/darwin/native-pipe-close-write/verify.py
```

Expected output is `verified: 16 native pipe/FIFO close and SIGPIPE controls`.
The verifier checks source bindings, unique case membership, native image
identities, byte counts, descriptor reservation, errno, and signal counts.
Semantic corruption controls are recorded in `qualification-v1.json`.

To collect fresh native observations on macOS with Xcode installed, use a fresh
build directory inside this worktree:

```text
python3 docs/specifications/darwin/native-pipe-close-write/collect.py target/native-pipe-close-rerun-v1
```

This creates owned arm64/x86-64 executables and `native-signal-v1.json` in that
directory. It does not overwrite the checked-in corpus. Remove that generated
directory after its results have been retained and all children have exited.
The native collector requires macOS; corpus verification works on every host.

## Model verification and boundary

`fifo_lifetime_tests::blocked_write_tests` replays all 64 original cases with
ignored SIGPIPE, eight new caught-signal cases on Unix hosts, and the eight
native no-sigpipe adapter cases on macOS. It checks entered completion, signal
queuing before the suspended guest resumes, descriptor reservation/reuse,
captured iovec payload, and absence of a guard exception. The registered owning
suite also includes FIFO lifetime, read-side pipe drain, continuation, and timed
lock tests. `qualification-v1.json` records the executed gates and their scope.

Linux model execution uses an in-worktree tmpfs for FIFO fixtures: the shared
FUSE mount loses metadata for unlinked open FIFOs, as independently recorded in
`../native-fifo-filesystem/`. Windows builds retain the existing unavailable
Darwin native-pipe adapter; this change does not introduce a Windows syscall
path, replace an adapter, or change native-library selection on any platform.

These controls establish this descriptor-lifetime contract. They do not prove
complete process emulation or qualify unrelated Windows startup services.
