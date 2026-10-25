# Native NtRaiseException argument observations

The build-26100 x86/WoW64 second-chance control returns
`STATUS_DATATYPE_MISALIGNMENT` for context pointer 1. Build 20348 and the three
views of the local ARM64 build-29683 kernel return `STATUS_ACCESS_VIOLATION`.
One value does not determine the alignment threshold or copy-fault priority.

`run.py` builds an SDK-based control with MSVC and executes 36 argument pairs
per compiler ABI. The pointer inputs are 0, 1, 2, 3, 4, 7, 8, 12, 15, 16, 32
and 4096. Modes select an unreadable record, an unreadable context, or both.
All calls have `FirstChance=FALSE`. The supplied low addresses are fixed test
inputs; no guest pointer is forwarded to a host syscall.

Only compiler/source/executable hashes, machine identities, input identifiers,
returned status and exception/return markers are exported. No context or stack
bytes are emitted. The native source and its raw statuses remain independent
of the model under test. The projection test verifies all pairs, scalar bounds
and rejection of extra fields; it does not assert that different kernels have
the same status. Failure to return an error or an unexpected user-mode exception
still fails the driver after its bounded observation has been printed.

```text
python docs/specifications/windows/native-raise-arguments/run.py
```

On ARM64 Windows, select `--architectures arm64 x64 x86`; `--environment` accepts
the existing private compiler-environment format. All compiler outputs and
temporaries stay within the owning worktree and are removed after each view.
The child deadline is 15 seconds; compiler invocations have a 60-second limit.
Status collection is O(1) time and storage for the fixed 36-case matrix, apart
from compiler and process costs.

The exact public producer completes all 108 local cases: ARM64, x64 and WoW64
views of the same build-29683 ARM64 kernel. Every call returns
`STATUS_ACCESS_VIOLATION`, with no user-mode exception. Source/compiler/binary
identities and all scalar rows are in
[local-29683-v1.json](local-29683-v1.json). The three projection tests pass on
macOS, Linux and native Windows. These views do not supply an independent x64
kernel observation; the existing two-runner workflow collects those separately.

Assumption RA1: these fixed low addresses are unreadable in the fresh control
process. Basis: the original pointer-1 controls and Windows low-address layout.
Dependent result: interpreting statuses as argument-copy failures. Stress test:
all address/alignment residues and both-invalid pairs. Falsification probe:
successful calls or user-mode exception delivery. Status: confirmed for the
local matrix; retained pending the independent-kernel matrix.

High impact: the kernel/view distinction must be incorporated into the model
before claiming exact argument-failure parity. This collector changes no model,
public or private ABI, permission, feature default, or execution budget. Its
C++ source is required for the MSVC structured-exception boundary; the runtime
implementation remains Rust.
