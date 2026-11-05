# Private ARM64EC reserve/commit and instruction routing

`NtAllocateVirtualMemoryEx` accepts attribute type 5, value `0x40`
(`MEM_EXTENDED_PARAMETER_EC_CODE`) in the measured AMD64 process view on
Windows ARM64 when protection includes an execute base bit. Native ARM64 and
WoW64 x86 process views reject it. Admission describes the process view, not
the currently active interpreter of a paired AMD64/ARM64EC thread.

The independent observations use Windows 11 Pro Insider Preview kernel
`10.0.29698`, ARM64. AMD64 and x86 observers run under Windows translation;
these are not physical x86 CPU results. The exact NTDLL, KernelBase and Kernel32
file identities, observer source/image hashes, and output hashes are retained
in `native-controls-v1.json`.

| Control | Allocation cases | Validation controls | Private calls |
| --- | ---: | ---: | ---: |
| Native ARM64 | 168 | 8 | 0 |
| Translated AMD64 | 168 | 8 | 0 |
| WoW64 x86 | 168 | 0 | 0 |
| AMD64 protection modifiers | 104 | 8 | 0 |
| AMD64 attribute bits and EC combinations | 129 | 8 | 0 |
| AMD64 private leaf / installed EC thunk | 0 | 0 | 2 |
| Total | 737 | 32 | 2 |

The observers link the Windows APIs directly, without RAX. They write only
their own private reservations and release those reservations on qualified
completion. The original output logs and source files are retained verbatim.

## Authoritative contracts

- The retained Microsoft ABI specification describes the four-byte entry
  prefix, stack alignment and register conversion, call checkers, and dynamic
  EC allocation:
  [`../native-arm64ec-bridge/arm64ec-abi.md`](../native-arm64ec-bridge/arm64ec-abi.md).
- Its pinned provenance and license are in the adjacent bridge directory.
- The original seven-argument NT allocation declaration and native capture,
  guard, output-publication and NUMA oracles remain in
  [`../native-allocate-ex/`](../native-allocate-ex/).

## Observed behavior

Process-handle access validation precedes EC process/protection admission.
Invalid or duplicate parameter types and complete array capture retain their
existing earlier validation order. Attribute values `0x80` and `0xC0` return
`STATUS_NOT_SUPPORTED`; the other measured unsupported single bits and their
EC combinations return `STATUS_INVALID_PARAMETER`.

Reserve-only requests publish EC bits for the entire returned reservation.
Commit-only requests tag the returned page-rounded interval, including commits
into ordinary reservations. Bits persist after release and ordinary reuse.
Each bit describes 4,096 bytes; eight pages share one bitmap byte. Thus the
byte is `bitmap_base + (VA >> 15)` and its bit is `(VA >> 12) & 7`.

Sparse bitmap pages are guest-owned READONLY mappings. The VM preflights the
combined guest-page and bitmap-page commitment before changing existing data
or protection. Failed new reservations are removed. Bitmap writes update
`ceil(P / 8)` bytes for P guest pages with constant temporary storage.

Decoder selection also requires a live private allocation and its actual page
state. Reported executable protection does not turn an NX trap into executable
code. Retired bitmap ownership returns an explicit error; it never reads a
replacement allocation at the old bitmap address.

The native private-call oracle follows the canonical 14-byte AMD64
fast-forward export stub to the EC body before reading its prefix. The
`RtlRunOnceExecuteOnce` compiler entry thunk is then shared by two private leaf
functions, one below and one above the installed thunk. Both return their
distinct expected values. This confirms signed relative offsets and entry
thunks outside the private allocation. The guest Windows regression executes
the selected installed thunk and checks both values, restored stack position,
and unchanged thunk bytes.

Earlier hand-written thunk probes terminated with
`STATUS_WX86_INTERNAL_ERROR`. An intermediate probe treated an AMD64 export
stub as an EC body and failed its bounded-read assertion. These are retained
as failed controls and are not included in the passing totals.

## Assumption register

| ID | Assumption / dependent result | Basis | Stress test / falsification probe | Status |
| --- | --- | --- | --- | --- |
| PA1 | EC attributes require the selected kernel/process capability and execute protection. | Three native process views, reserve/commit and protection matrices. | Other kernel versions, invalid handles, modifier and flag combinations; a successful ARM64/x86 EC request falsifies the measured admission rule. | Confirmed for kernel 29698 and recorded file identities. |
| PA2 | The documented entry ABI applies to generated private code and shared external thunks. | Native v6 uses an installed compiler thunk with positive and negative offsets and exact distinct returns. | Different signatures, nested calls, nonvolatiles, stale owners and cross-allocation targets; a native offset/return mismatch falsifies the corresponding route. | Confirmed for the recorded scalar control; broader signatures remain separate validation. |
| PA3 | Bitmap mutation cannot race another guest VM mutation during preflight and commit. | Windows guest threads share the scheduler host thread; the VM owns the address space. | Reentrant mutation or a second host thread changing mappings between preflight and commit would falsify this ownership contract. | Retained scheduler invariant. |

## Remaining full-process requirements

| Impact | Item | Effect |
| --- | --- | --- |
| High | General registry permission/API choice remains pending. | This changeset does not activate host registry reads; full loader startup still encounters that separate boundary. |
| High | Full mixed unwind/asynchronous dispatch and CFG target admission remain incomplete. | These controls do not prove arbitrary generated functions or full process startup. `PAGE_TARGETS_INVALID` is still outside the VM protection contract. |
| High | EC reset and reset-undo are not implemented. | They return an explicit unsupported result rather than succeeding without establishing a code-classification contract. |
| Medium | Private classification validates bitmap ownership/state on each instruction lookup. | Cost includes allocation lookup and bitmap state runs; large fragmented JIT workloads need performance qualification. Does not block these semantic controls. |

Final shared Rust builds/runs, installed guest comparisons, C API checks and
the actual Assist archive plus its 22 consumers are separate publication gates;
native observer success alone does not satisfy them or the full process goal.
