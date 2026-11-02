# Native guarded descriptor controls

This directory contains acquisition inputs for the missing Darwin guarded
descriptor family. It does not add an emulator implementation.

The measured host is ARM64 Darwin 27.2.0, kernel
`xnu-13432.41.4~3/RELEASE_ARM64_T6041`. The ARM64 producer executed directly;
the x86-64 producer executed through Rosetta on the same kernel. The latter
is not a physical Intel execution claim. Each producer completed 33 cases,
and their captured result sequences were identical.

`references/provenance-v1.json` identifies the preserved Apple source inputs.
Those references are revision `xnu-12377.121.6`, which is older than the
measured kernel. Native observations own the measured behavior; the reference
revision does not establish exact behavior of the newer kernel.

The successful cases exercise guarded open, write, pwrite, writev, ordinary
pread, and matching-cookie guarded close. Writes produce the five bytes
`61 5a 63 21 3f`. All 16 accepted attribute combinations contain `GUARD_DUP`.
Every observed guarded open initially reports descriptor flags `3`, including
the `GUARD_DUP`-only case: both `FD_CLOEXEC` and `FD_CLOFORK` are set. This
does not establish that both flags are immutable for every attribute set.

The remaining cases cover missing required attributes, unsupported attribute
bits, a missing `O_CLOEXEC`, zero/null/inaccessible guard cookies, and invalid
descriptors. With otherwise valid flags, inaccessible cookies return `EFAULT`;
without `O_CLOEXEC`, validation returns `EINVAL` before reading the cookie.
The records retain exact results and error numbers rather than deriving them
from emulator code.

The source was compiled with the Xcode compiler and SDK recorded in
`build-v2.json`, using `-std=c11 -O0 -Wall -Wextra` and separate `-arch arm64`
and `-arch x86_64` selections. Each invocation has four arguments: operation,
owned fixture path, decimal guard attributes, and decimal open flags. Exact
argument vectors and results are in the two `records-*-v1.json` files. The
earlier unqualified compiler attempt failed before any native case ran.

`policy-probe-v2.c` and `capture-policy-v2.py` add 113 policy cases per ABI.
They register an exception receiver for the producer's own `EXC_GUARD`, retain
its exact Mach exception codes, reply, and observe the producer's termination.
Core dumps are disabled for these producer processes. The ARM64 campaign
observed 35 terminations and 35 synchronous guard packets; the Rosetta campaign
observed the same 35 terminations and 21 synchronous packets. The reason for
the missing Rosetta packets is unknown. A termination without a packet does
not establish its exception code. Excluding optional exception/reply packets,
the two campaigns' operation results and file contents agree in all 113 cases.

| Operation | Selected guard | Measured result |
|---|---|---|
| Ordinary close | `GUARD_CLOSE` | Fatal guard flavor `0x1`. |
| `dup` and the three tested `F_DUPFD` commands | Any accepted guard | Fatal guard flavor `0x2`. |
| Open through `/dev/fd/3` | Any accepted guard | `EPERM`, without an observed exception or termination. |
| Ordinary write, pwrite, writev | `GUARD_WRITE` | Fatal guard flavor `0x40`, before reading an invalid write buffer. |
| Clear `FD_CLOEXEC` | Any accepted guard | Fatal guard flavor `0x4`. |
| Clear `FD_CLOFORK` while retaining `FD_CLOEXEC` | `GUARD_CLOSE` | Success, but `FD_CLOFORK` remains set. |
| Clear `FD_CLOFORK` while retaining `FD_CLOEXEC` | No `GUARD_CLOSE` | Success; fork inherits the guarded descriptor and exec closes it. |
| Send the descriptor with `SCM_RIGHTS` | `GUARD_SOCKET_IPC` | Fatal guard flavor `0x8`. |
| `fileport_makeport` | `GUARD_FILEPORT` | Fatal guard flavor `0x10`. |
| Guarded close/write with a different cookie | Any tested guard | `EPERM`; the descriptor remains open and matching-cookie cleanup succeeds. |

The received exceptions have type `12`, two codes, and the producer's descriptor
number in the low 32 bits of the first code. For example, duplicating descriptor
3 yields code `0x4000000200000003` and subcode `0x1122334455667788`, the producer's
guard cookie. These numbers are native observations, not emulator-generated
expectations. `policy-records-*-v2.json` retains the full operation sequences,
including guarded kqueue creation, removing/replacing a guard, adding a guard
to an ordinary descriptor, returned previous descriptor flags, and inheritance.

Reproduce either campaign in a new directory within this checkout:

```text
python3 docs/specifications/darwin/native-guarded-fd/capture-v1.py --output target/guarded-positive-capture
python3 docs/specifications/darwin/native-guarded-fd/capture-policy-v2.py --output target/guarded-policy-capture
python3 docs/specifications/darwin/native-guarded-fd/verify-v2.py
```

The capture commands require macOS, Xcode's compiler/SDK, and Rosetta for the
x86-64 producer. The verifier reads the frozen records and works without those
native dependencies. The first strict policy collection completed ARM64 but
stopped on an absent Rosetta packet. The final collection preserves absent
packets instead of assuming synchronous delivery is guaranteed.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| GF1 | The private function signatures remain compatible with the preserved header. | Both producers resolve all five symbols and complete the observed calls. | Captured ABI interpretation. | Both CPU ABIs and validation errors. | Incompatible results, missing symbols, or process failure. | Confirmed for this measured host. |
| GF2 | Initial flags alone do not establish inheritance or immutability policy. | The first campaign had no inheritance cases. | Limits on a future implementation. | Fork, exec, and independent flag changes. | Policy-v2 inheritance and flag controls. | Revised: measured cases are recorded above; spawn actions remain unmeasured. |
| GF3 | A registered native handler always receives a synchronous packet before a fatal guard termination. | This held in the initial ARM64 controls. | Completeness of exception-code capture. | Rosetta and fatal descriptor close. | Termination with no packet. | Falsified on Rosetta; missing packets remain explicit. |

Validation precedence for the full `change_fdguard_np` pointer/flag matrix,
guarded data-protected opens, spawn file actions, pending-I/O lifetime, and
other kernel versions remain high-impact gaps. These controls do not establish
an emulator implementation or complete guarded-descriptor conformance.
