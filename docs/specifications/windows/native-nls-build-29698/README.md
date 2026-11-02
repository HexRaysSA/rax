# NLS initialization and query-only MUI on Windows 29698

The finite startup profile adds Windows 10.0.29698 only when the independently
captured native machine is ARM64 (`0xAA64`). ARM64, x64 compatibility, x86 and
x86 with large-address awareness were observed on that kernel. Unknown native
machines and AMD64/i386 native kernels with this build remain unavailable.
The existing 29683/29695 admission and independent AMD64 20348/26100
initialization profile retain their contracts.

After the measured CSR extension, both installed CLI fixtures reached
`NtInitializeNlsFiles native build profile is unmeasured`. The captured CLI
suite had 8 passes and 2 failures. Its actual CLI/test executables, logs and
source frame were preserved before changing NLS admission.

Six unchanged C++ producers from the prior qualification were compiled with
MSVC, C++20, static CRT, `/Od /EHsc /utf-8 /W4 /WX` and SDK 10.0.26100.0.
Native64 uses the original four-argument initialization declaration; x86 uses
the retained corrected three-argument producer. The x86-LAA controls add
`/LARGEADDRESSAWARE`. Sources, compiler and executable identities were checked
before and after execution. Build intermediates stayed inside the task tree.
The first collector stopped at a missing reference file before any native
control ran; the successful collector carries verified source copies.

| Observation | Fresh 29698 evidence | Comparison |
| --- | ---: | --- |
| Initialization | 79 cases per process profile; 316 total | Exact prior statuses, guards, view deltas and output bytes after relocating only returned base bytes |
| Protection/free | 12 cases per profile; 48 total | Exact prior statuses, protection, type and ownership outcomes |
| Query-only MUI | 1680 rows per profile; 6720 total | Exact prior pointer, length, alias, partial-write and last-error rows |
| Installed exports | 3 per profile; 12 total | Current x86 initialization leaf ends with `C2 0C 00` (`RET 12`) |
| Generation | 3 fresh scalar captures | Shared-before, payload and shared-after counters all equal 1 |

All four MUI payloads contain 1232 bytes and have SHA-256
`845ec214cfa8cdafe3c6cac5d86923e8429c9093e4641094879d2e53be7ceaef`.
The independent generation captures have the same bytes. The installed
`locale.nls` has 862808 bytes, requiring
`ceil(862808 / 4096) * 4096 = 864256` mapped bytes and 1448 zero padding bytes.
Native64 publishes base then locale; WoW64 publishes locale then base. A late
WoW64 pointer-copy fault retains the owned mapping. No native cache mutation
was executed, and guest cache clear/commit remains explicitly unavailable.

The actual DLL binding was checked before and after each architecture's
controls. ARM64 and compatibility x64 use `System32/ntdll.dll`; compatibility
x86 uses `SyChpe32/ntdll.dll`. The producer's logical `System32` string is not
used to hash the x86 provider from a native ARM64 process.

`profile-29698-v1.json` retains the semantic signatures, all sixteen executable
and stdout identities, frozen source hashes, actual providers, leaves,
generation and installed-file identity. The separately retained archive
`nls-29698-native-artifacts-v1.zip` has 23462028 bytes and SHA-256
`1a408d63fc0fed369abec8bda84dd738ae6df24a4b134a77e612359414c53f4d`.
Its 678 payloads include the failed CSR CLI artifacts, observer binaries,
source copies, CMake input, build records, actual providers and raw stdout.

Verify the retained sources and semantic signatures:

```sh
python3 -I -B docs/specifications/windows/native-nls-build-29698/check.py
```

With the archive available, regenerate the projection and compare its bytes
with the checked-in JSON:

```sh
python3 -I -B docs/specifications/windows/native-nls-build-29698/check.py \
  path/to/nls-29698-native-artifacts-v1.zip > profile-29698-rebuilt.json
```

The projector verifies every archive payload, source and image identity before
comparing native semantics with the original corpus. Only actual base-output
bytes are relocated; native addresses cannot conceal other output differences.
The scalar generation observer changed only its output directory. These
commands require no native execution; the archive retains exact compiler and
execution commands for native reproduction.

Shared regressions exercise the three admitted builds: 948 initialization
cases, including 24 late retained mappings, and 15120 MUI query rows across
three process ABIs. The separate native controls additionally cover x86-LAA.
Refusal matrices cover adjacent builds, changed major/minor versions, missing
selected data and unknown/foreign native machines without mapping or output
publication. Installed Windows tests separately check actual leaves, independent
file bytes, read-only mappings, explicit unmap and shared-page generation.
Full platform qualification of the amended source is recorded separately;
native observations alone do not establish emulator completion.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| N98-1 | The measured ARM64 kernel retains initialization and query-only MUI semantics. | Fresh frozen controls and exact normalized prior-corpus equality. | Admit exactly build 29698 on native machine 0xAA64. | All recorded guards, aliases, faults, late mappings and protection/free cases across four process profiles. | Any native semantic, leaf cleanup or ownership mismatch. | Confirmed for the recorded native controls. |
| N98-2 | Query payload and shared language generation agree across process ABIs. | Four payload identities and three independent scalar captures. | Reuse immutable snapshot acquisition and guest shared-page initialization. | Live repeated acquisition at different buffer addresses. | A differing payload or shared/payload generation. | Confirmed for the recorded observations; runtime stability checks remain active. |

High-impact remaining scope: independent AMD64 build 29698, MUI mutation,
other builds and full installed-process startup. This profile does not admit
any of those paths. Initialization still takes O(N) time and O(N) guest mapping
storage; MUI publication takes O(L + P) time and one 4096-byte scratch page,
with bounded immutable payload P. No guest-directed host operation is added.
