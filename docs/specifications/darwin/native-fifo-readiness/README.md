# Native Darwin FIFO readiness and close state

These are native observations on Darwin 27.2.0, build
`xnu-13432.41.4~3/RELEASE_ARM64_T6041`. The ARM64 controls run directly;
the x86-64 controls run through Rosetta on that same machine. They do not
establish behavior on an Intel Mac or other kernel versions.

## Readiness and EOF

The retained `native-fifo-*.json` files distinguish readiness from an actual
read. In particular, a native zero-byte read changes subsequent readiness.

| Named FIFO state | poll readable | select readable | Native read |
|---|---|---|---|
| Empty, writer still open | No | No | Would block |
| Contains data | Yes | Yes | Returns the data |
| Drained, last writer closed, before first EOF read | No | Yes | Returns 0 |
| After the first EOF read, no writer | No | No | Still returns 0 |
| Reader has never had a writer | No | No | Returns 0 |

`kqueue` also has no read event in the measured empty EOF state. Thus,
supplementing `poll` with `select` addresses the first EOF notification;
it does not by itself implement repeated blocking reads at EOF. Caching EOF
alone is insufficient because another writer can open the FIFO later.

Run this independent observation from the repository root:

```sh
python3 docs/specifications/darwin/native-fifo-readiness/capture-readiness-v6.py
```

The command creates a uniquely owned directory under the existing in-tree
FIFO validation target. It refuses to overwrite an earlier capture. Its child
has a 30 s observation limit; a timeout is saved as a failed observation.
The receipt records the source hash, native command, kernel, output, readiness
states, and repeated nonblocking and blocking EOF reads. The final read should
return an empty byte string; there is no hard assertion on host elapsed time.

## Close drains and Mach thread state

The C probes include `../native-guarded-fd/policy-probe-v2.c`, whose original
result printer labels its third argument `errno`. For thread-state records,
that field contains the explicitly supplied Mach flags or suspend count.
It must not be interpreted as a failed system-call errno.

| Observation | run_state | Meaning |
|---|---|---|
| Entered guarded close drains a blocked FIFO write | 4 | `TH_STATE_UNINTERRUPTIBLE` |
| Close drain remains pending during a Mach user suspension | 4 | Kernel drain continues independently of user suspension |
| Kernel drain completed, user return still held | 3 | `TH_STATE_WAITING`, suspend count 1 |

The first sample immediately after suspension can transiently report state 1
on ARM64. The v3 controls retain all 32 successive samples rather than hiding
this transition. Both architectures subsequently report state 4 while the
drain remains pending. The completed held close has not yet executed its
user-space completion store.

Each C receipt retains its exact compiler arguments and image hash. To repeat
the v3 observation, compile `held-close-thread-state-v3.c` with the retained
include path and either `-arch arm64` or `-arch x86_64`. Run the resulting
image with arguments `0 1 0 fifo <fresh-in-tree-fifo-path>`. Native symbols
`guarded_write_np`, `guarded_close_np`, and `change_fdguard_np` are required;
absence is a failed prerequisite, not a passing observation.

## Primary references and evidence boundaries

`references/provenance.json` records SHA-256 for retained Apple SDK headers
and Apple's public
[FIFO implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/miscfs/fifofs/fifo_vnops.c).
The public source explains that `fifo_read` handles zero writers separately
and consumes its EOF socket state, while `fifo_select` uses socket readiness.
The public `main` snapshot is explanatory source, not an assertion that it
identifies the exact running kernel revision. Original notices are retained.

The SDK declares the unlimited `select$DARWIN_EXTSN` entry and the Mach state
constants. A bounded emulator regression also exercises descriptors above
`FD_SETSIZE` in an isolated child. Ordinary `libc::select` uses the limited
`select$1050` entry on x86-64; the production adapter must not assume a fixed
descriptor bitmap can hold every host descriptor.

These native controls do not prove full FIFO emulation, signal/cancellation
behavior, or platform parity. The repeated-EOF read path remains a separate
correctness requirement from first-EOF readiness and close-state projection.

Verify the retained observations and source/reference hashes on any host:

```sh
python3 docs/specifications/darwin/native-fifo-readiness/verify.py
```
