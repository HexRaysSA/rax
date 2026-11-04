# Relocatable Windows process parameters

Process construction now places its four initialized Unicode strings inside one
zeroed allocation. `Length` and `MaximumLength` cover the whole allocation,
including terminators. Parameter readers resolve `PEB.ProcessParameters`, since
installed RTL can replace that pointer during startup. The environment remains
a separate allocation, as in the captured RTL continuation.

This corrects two observed data-layout failures. It does not establish complete
CMD execution. Both corrected command controls stop explicitly at unsupported
`NtQueryDirectoryFileEx`, before their requested command completes.

## Evidence and arithmetic

The independent native children use installed `System32\cmd.exe`, private pipes
with finite input EOF, and explicit argument vectors. Native `exit 37` returns
37; native `echo RAX_PROCESS_MATRIX_A7F3C2` returns zero and the sentinel plus
CRLF. The production engine uses installed DLLs without a separate sysroot,
the same arguments, and a private captured console. The native host environment
and the emulator's configured default environment are distinct.

At the parent revision, the initial 64-bit parameter block declared only
`0x448 = 1096` bytes. The command buffer began at offset `0x5C0 = 1472` and
occupied `82 + 2 = 84` bytes including its terminator. The missing span was
`1472 + 84 - 1096 = 460` bytes. Interpreted installed RTL copied the declared
span and rebased the pointer, leaving the replacement command buffer empty.
Both emulated commands consequently returned zero with a prompt instead of
performing the requested operation. Zero exit alone was insufficient evidence.

An intermediate contiguous allocation placed its first string at `+0x448`.
The installed ARM64 NTDLL reads a pointer at that offset. Its exact instruction
chain in the retained one-instruction diagnostic is:

```text
LDR X22, [X18, #0x60]  -> TEB.ProcessEnvironmentBlock
LDR X8,  [X22, #0x20]  -> PEB.ProcessParameters
LDR X10, [X8, #0x448]  -> UTF-16 "C:\U" interpreted as a pointer
LDR X8,  [X10]        -> access violation at 0x0055005C003A0043
```

The semantic name of this additional private runtime field is unknown. The
latest retrieved PHNT declaration remains the same pinned declaration used by
the original prefix correction. It ends before this load. Microsoft explicitly
permits changes to this private structure; its retained public declaration does
not specify these internal tail fields.

The corrected construction preserves ordinary heap-alignment padding after the
known prefix, before placing any string:

| Guest ABI | Known PHNT prefix, bytes | Zero padding, bytes | First possible string offset, bytes |
|---|---:|---:|---:|
| x86 | 708 (`0x2C4`) | 4 | 712 (`0x2C8`) |
| x64 | 1096 (`0x448`) | 8 | 1104 (`0x450`) |
| ARM64 | 1096 (`0x448`) | 8 | 1104 (`0x450`) |

For pointer width `w`, construction starts strings at
`align_up(prefix_size, 2*w)`. Each string starts at pointer alignment and
contributes `2*UTF16_units + 2` bytes. Final extent is rounded to `w` bytes and
checked before conversion to `ULONG`. Each `UNICODE_STRING.MaximumLength`
includes its two-byte terminator; lengths above 65532 bytes are rejected before
allocation. Time and space remain O(U + E), for initialized string units U and
environment units E. No new host kernel operation is introduced.

## Observed continuation

| Phase | Emulator result | Interpretation |
|---|---|---|
| Parent, separate strings | Both commands exit zero; prompt replaces requested output | Command text was lost during relocation |
| Intermediate, strings at `+0x448` | Access violation, then unsupported process class 63 | Header/payload collision; crash notification is not the cause |
| Corrected, padded contiguous block | All observed command/image/current-directory bytes survive relocation; no sampled exception | Parameter correction is exercised by installed RTL |
| Corrected `exit 37` | Unsupported directory service at sample 209758, instruction bound 13424576 | Requested exit has not completed |
| Corrected `echo` | Same service at sample 209790, instruction bound 13426624 | Sentinel output has not completed |

These are Windows ARM64-host observations. Interpreted installed-DLL execution
is distinct from the independent native child controls. Portable tests exercise
all three guest layouts; this capture is not an independent AMD64-kernel oracle.
The precise-fault collector uses one-instruction slices. Its old informational
configuration banner still says 64; the executed source and actual counters use
one, and the capture metadata records that distinction.

`captures-v1.json` retains all seven original stdout/stderr records, exact DLL,
collector, executable and core-archive identities, and native command results.
`collector-sources-v1.json` retains the three executed diagnostic sources.
`implementation-source-v1.json` and `implementation-v1.patch` bind the final
seven implementation/test files to the parent revision. No Microsoft executable
or DLL is redistributed. Primary references, pinned revisions and licenses are
retained under `primary/`; the byte-identical PHNT header/license are reused from
the parent directory.

Run `python3 -B verify.py` from this directory to verify frozen evidence. Add
`--rax-root PATH` to check the live implementation against the frozen source
frame. Evidence replay validates identities and recorded distinctions; running
the regression tests and ordinary process controls is a separate gate.

## Regression and representation coverage

The owning library regressions check all guest ABIs, non-ASCII/supplementary
UTF-16, argument quoting, length boundaries, zero modern tail/padding, and bounds
for every initialized string. A relocation regression copies exactly the
declared span, rebases all four pointers, publishes the new PEB pointer and
poisons the original block. Separate regressions check command-line/standard
handle APIs, CRT startup inputs and CRT stdio initialization against the live
pointer, including invalid metadata and allocation/handle-pin atomicity.

| Plane | Effect |
|---|---|
| Windows process construction | Contiguous declared string extent and preserved zero padding |
| Built-in Win32, CRT startup, CRT stdio | Read the live PEB parameter pointer; initial allocation identity remains available |
| Installed RTL | Existing instructions consume corrected guest data; no DLL bytes are patched |
| ISA, CPU, SMIR, JIT, backend, devices | No implementation or admission change; this correction supplies process data |
| C ABI, permissions, persistence, packaging | Existing interfaces and policies remain unchanged |
| macOS/Linux personalities | No source edits; parent-revision ordinary echo/nonzero-shell comparisons are retained with their scope |
| Windows/macOS/Linux compilation | The same Rust allocation/readers supply all guest layouts; native host adapters are unchanged |
| Assist consumers | Existing process/emulation consumers must qualify the actual updated submodule/archive before pin publication |

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| A1 | Relocation must preserve initialized strings within the declared span | Parent trace loses command bytes; captured RTL rebases pointers | Contiguous allocation | Copy only declared bytes and poison original storage across guest ABIs | Any initialized string escapes the copied span or changes after relocation | confirmed for captured runtime and portable cases |
| A2 | Default padding consumed by the captured runtime must stay zero | Exact ARM64 load at `+0x448` and intermediate access violation | Header/payload separation | Distinct command lengths, supplementary UTF-16 and all guest layouts | Corrected runtime dereferences payload as the private tail pointer | confirmed for captured ARM64 runtime; other native kernels remain unqualified |
| A3 | Live parameter fields are owned by the pointer in the PEB | Installed RTL publishes a replacement; direct consumer regressions | Reader correction | Poison old block, replace handles/inputs, malformed live pointer | A consumer still reads initial storage or silently falls back after a real PEB fault | confirmed |
| A4 | The two native controls provide stable acceptance values for these commands | Native exit37 and sentinel-output observations | Comparison of the corresponding emulated commands | Nonzero exit, exact output bytes and empty stderr | A fresh native control disagrees with its retained exit/output assertions | confirmed on the captured host; emulated command acceptance remains unmet |

## Bounded findings

| Impact | Finding | Evidence | Blocks parameter correction? |
|---|---|---|---|
| High | Directory enumeration prevents completion of both ordinary CMD controls | Final source-bound captures stop at `NtQueryDirectoryFileEx` | No; blocks the full process goal and is the next changeset |
| Medium | Private tail semantics and other native-kernel layouts are not established by PHNT | Captured load lies beyond the unchanged public reference prefix | No for the captured default; blocks broader native-layout claims |
| Medium | Broader async/pipe/APC and native fault-ordering work remains separate | Existing retained-read profile and the explicit runtime stop | No; full userland support remains active work |

## Qualification snapshot

`qualification-v1.json` records all 16 successful build/host gates, including
Windows ARM64/x64, macOS ARM64 and Linux amd64 configurations, strict library
Clippy, workspace checks and the 244-case C API run. The selected Windows
regressions pass134 cases on macOS/Linux and133 distinct cases on native Windows.
Windows initially lacked three cross-compiled test fixture paths;130 cases passed,
then all three remaining cases passed with verified fixture inputs and the
identical executable. Neither assertions nor test selection were weakened.
Both macOS and Linux pass544 executable-fixture cases and8 actual CLI cases.
Linux amd64 runs through translation on an ARM64 host.

The complete final-source unoptimized macOS library run records9972 passed,
2 failed,2 opt-in cases ignored and0 filtered. Both failures are Unix socket
cases under the long in-tree temporary path. The identical binary reproduces
both failures there and passes both under a short in-tree temporary path.
This is not an unconditional all-suite-green result.

An additional complete checked-optimized campaign is still running at this
snapshot. It has reported one Darwin FIFO readiness failure, whose exact
same-binary rerun passes; its cause is unknown. Its final result is not counted
as passed here. This remains a full-goal investigation, separate from the
parameter correction. No native command-completion claim follows from any
collector wrapper success.
