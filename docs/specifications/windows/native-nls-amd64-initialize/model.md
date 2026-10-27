# Finite AMD64 NLS initialization admission

Initialization admits native AMD64 kernels10.0.20348 and10.0.26100 for x64 and
x86 guest views. Selection and guest dispatch use the same predicate, receiving
the already captured native-machine identity. Missing/foreign machines, ARM64
guest views on those AMD64 profiles, adjacent builds and other major/minor
versions remain unavailable. The existing29683/29695 behavior remains intact.
MUI snapshot acquisition, dispatch and generation retain their prior predicate;
these initialization controls do not qualify MUI.

The new path reuses fixed native initialization capture, immutable bytes,
checked native memory-query geometry, bounded RPM copy and RAII unmap. No guest
pointer, path, handle or length enters host acquisition. Guest calls retain the
existing native64 base-before-locale and WoW64 locale-before-base copy order,
including ignored outputs, guard consumption, readonly faults and retained
mapped views. Native argument counts remain four for native64 and three for
x86. A mapping remains guest-owned, sealed readonly and charged until native
unmap or process teardown.

Independent AMD64 controls in run40565964224 record474 initialization calls
and72 protection/free calls:79+12 for each x64/x86/x86-LAA process view on two
kernels. Raw reports and bytes remain in profiles-v1.json. All compared status,
guard, view-delta and output bytes match the prior contract. Comparison verifies
each actual returned-base byte before relocating its exact output span; every
other changed byte in the complete4096-byte scratch page remains exact.
Native mapping extents are selected from installed data, not a fixed build size:

| Native kernel | locale.nls file bytes | Mapping bytes | Zero padding bytes |
| --- | ---: | ---: | ---: |
| 10.0.20348 | 819456 | 823296 | 3840 |
| 10.0.26100 | 862800 | 864256 | 1456 |

For file extent F and page extent4096 bytes, M=ceil(F/4096)*4096 and padding=M-F.
The existing8 MiB initialization bound,64 MiB combined snapshot bound and guest
VM budget remain unchanged. Capture and initialization cost O(M) time and own
O(M) immutable/mapped bytes; profile checks and fixed output work cost O(1).
The fixture payload uses declared synthetic bytes to test copy/lifetime rules;
installed leaves independently compare all actual file bytes and padding.
x86-LAA observations qualify these calls, not high-address allocation policy.

The native driver's executed CRLF bytes have SHA-256
`57147c3fe5586b3de4fd5caa6b809aa3b5eabc4751c4edfd5774d57ddd92ec7a`.
Replacing every LF in the canonical9158-byte source with CRLF reproduces that
9374-byte identity exactly. The frozen C++ producers retain their original
identities. No executed native producer is edited or substituted.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| NM1 | The two measured AMD64 kernels retain the initialization call/copy contract. | All474 native initialization records agree, including complete first-page changes. | Finite initialization admission. | Invalid/readonly/guarded/unaligned/aliased outputs and retained mappings. | Replay raw native corpus, exact guard/status/output bytes and VM charges. | Native controls and complete model replay confirmed; installed AMD64 leaf pending. |
| NM2 | Mapping extent and bytes come from the selected host snapshot. | Native readonly geometry and independent file extents differ across the two kernels. | Correct payload, bounds and lifetime. | Different file sizes, padded tail, missing snapshot and resource exhaustion. | Full installed-file/padding comparison, native leaf, actual mapped extent and unmap. | Native controls and existing ARM64/x86 installed leaves confirmed; new AMD64 installed leaf pending. |
| NM3 | Initialization qualification cannot extend MUI implicitly. | Source consumer audit; independent admission and tests. | Preserved unavailable MUI behavior. | AMD64 initialization admitted while MUI remains unavailable. | Exact predicate matrix plus installed snapshot and MUI regressions. | Confirmed by exact admission, unavailable MUI and missing-snapshot tests. |

High impact: the unchanged full startup/fault fixture remains an independent
gate and may expose another unmeasured service. Full Linux/macOS/Windows
process emulation, linked shipping artifacts, packages and installed Assist
runtime remain incomplete. Public/private ABIs, dependencies, optional features
and package layout do not change. Original fault source, PE binaries, whole
Rust test, assertions and execution limits remain unchanged.


Combined-candidate validation passes26 NLS,10 MUI and191 C API tests on macOS
and Linux, with zero failures or ignored cases. Native Windows passes34 NLS and15 MUI tests with zero failures or ignored cases.
Its C API compilation and unchanged original ARM64/x86 hardware-fault fixture
remain pending: guest receipt observation timed out; the producer is unchanged. These results include the separate native
exception-entry candidate. This is a validation candidate. Native scratch remains for its active producer;
it must be archived after positive exit evidence. Clean-master and installed AMD64 qualification remain
separate gates; the original AMD64 fixture outcome is not presumed to pass.

The initial new aggregate assertion expected8 late mappings. Every per-call
comparison and all72 protection/free cases passed; direct counting of the frozen
native rows proves4 late mappings per x86/x86-LAA profile per kernel,16 total.
The corrected aggregate assertion and its passing run supersede that retained
failed result. No original test, native producer or execution budget changed.
