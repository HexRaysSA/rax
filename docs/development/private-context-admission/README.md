# Required private checkpoint records

When a bundle carries the optional private CPU context set, restoration now
requires each target producer's mandatory record. A missing row rejects during
admission, before CPU setters, resource binding, RAM or device publication.
Previously, a missing row silently selected public-only restoration for that
CPU. An actual S3C file was accepted with CPU0 CPACR `0x00f00000` instead of the
captured `0x00500000`; software AArch64, RISC-V and x86 targets also accepted
missing rows in otherwise complete producer sets.

The read-only `VCpu::required_private_checkpoint_kind` declaration identifies
these software producers:

| Producer | Kind |
| --- | ---: |
| Standalone AArch32 | 1 |
| S3C64xx | 2 |
| RISC-V | 3 |
| Software x86 | 4 |
| Software AArch64 | 5 |

Existing public/private state validation still runs first. The new presence
check precedes all restoration setters. It adds O(C) time and O(1) auxiliary
space for C CPUs, beyond existing context decoding and snapshot preparation.
There is no new wire field, tag, size limit or context format. Generic sparse
framing remains readable for producers that do not require opaque records.

Files with no private-context section retain documented projection-only
compatibility. Such files cannot recover private state they never recorded.
Standalone per-CPU APIs also keep their existing contracts. Native backends'
shared graph admission remains independent and may be stricter. Wrappers must
forward the producer declaration to preserve their wrapped admission contract.

Four predecessor regressions observed actual acceptance of missing records.
The repaired cases require a missing-private error and unchanged live target
CPU state and RAM; the S3C actual-file case also checks UART state and fresh
constructor rejection for two and four CPUs. A separate legacy file control
requires unchanged projection-only compatibility for two and four S3C CPUs.

AArch64 contexts include a naturally advancing heartbeat age. The test decodes
and round-trips the typed prefix to identify that field, compares every other
private byte, and requires before/after effective heartbeat epoch intervals
to overlap. For a capture bracket [b,e] and captured age a, the inferred epoch
is in [b-a,e-a]. The original raw-byte assertion failed only in the heartbeat
nanoseconds and was corrected without changing production code.

Final validation results and source hashes are recorded in
[qualification.json](qualification.json). The original A32-FP, C-STATE, C-SMP
and C-HVF findings remain open. This group does not resolve historical/missing
section completeness, arbitrary native/setter rollback, the known native
streaming FPSR issue, broader IRQ/clocks/replay or physical Intel validation.

Final root library: 11,614 passed, zero failed, 35 ignored. C API: 225 passed.
The selected signed Apple Silicon native file continuation passed one test
covering one, two and four CPUs. Fresh C/C++: 19 runtime programs and seven ABI
compilation checks. Workspace formatting, all-target check/build and Clippy
passed. Doctests ran zero examples with five ignored. These results do not
qualify the full ignored native CPU-profile module or physical Intel execution.
