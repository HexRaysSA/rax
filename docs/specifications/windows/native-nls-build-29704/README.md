# NLS initialization and query-only MUI on Windows 29704

This finite profile extends startup admission to Windows 10.0.29704 only when
the independently captured native machine is ARM64 (`0xAA64`). Observations
come from update revision 1010 on that kernel, using native ARM64, AMD64
compatibility, x86 compatibility and x86-LAA processes. Unknown native machines
and independent AMD64/i386 kernels are not qualified by these controls.
The existing 29683/29695/29698 and independent AMD64 initialization profiles
retain their contracts. Runtime acquisition still validates mapping geometry,
ignored outputs, bounded bytes, repeated MUI acquisition and actual installed
leaf signatures; this is not a blanket admission of other native services.

The unchanged ARM64 startup fixture passed the independently measured CSR
profile and stopped at `NtInitializeNlsFiles native build profile is unmeasured`.
Fresh native observations preceded the NLS admission change. The regression
matrix then failed on the original predicate before that predicate was extended.
No ordinary program completion is inferred from the native observer exits.

| Observation | Fresh native extent | Result |
| --- | ---: | --- |
| Initialization | 79 calls per process profile; 316 total | Exact retained statuses, guards, view deltas and output bytes, relocating only actual returned base bytes |
| Protection/free | 12 calls per profile; 48 total | Exact retained statuses, protection, type and ownership outcomes |
| Query-only MUI | 1680 rows per profile; 6720 total | Exact retained pointer, length, alias, partial-write and last-error rows |
| Installed exports | Three per profile; 12 total | x86 initialization retains `RET 12` |
| Generation | Three captures; two distinct live payload buffers each | Shared-before, both payloads and shared-after agree; generation 1 |
| Provider identity | Before and after each profile; eight observations | Stable physical provider and code identity |

All four MUI payloads have 1232 bytes and SHA-256
`845ec214cfa8cdafe3c6cac5d86923e8429c9093e4641094879d2e53be7ceaef`.
The installed `locale.nls` has 862808 bytes and SHA-256
`00d972d678db02525b731e1286e8daf53e87e5cbc58edcaf90de4222470a639a`.
Its mapping extent is `ceil(862808 / 4096) * 4096 = 864256` bytes, including
1448 padding bytes. Native64 publishes base before locale; WoW64 publishes
locale before base and retains the owned view after a late pointer-copy fault.
The emulator keeps those mappings guest-owned and explicitly unmaps them.

ARM64 and compatibility AMD64 map `System32/ntdll.dll`, SHA-256
`62f49d5ba98285e9997cc47c7710ab1d1390506c0a3fda96736783aefd42b3b1`.
Compatibility x86 and x86-LAA map `SyChpe32/ntdll.dll`, SHA-256
`0c8ad1faabdc67afad52c037897a1edbe8c69733aede303c0fa9d1dd6ccde0f7`.
The logical `System32` path reported to the x86 process is not treated as its
physical provider. The archive retains both actual provider files.

The six retained C++ NLS producers were cross-compiled with Clang CL, C++20,
static CRT, `/Od /EHsc /utf-8 /W4 /WX`, then executed natively. Four producers
remain byte-identical. Two x86 copies add one explicit `SIZE_T` to `size_t`
printing cast each; their API calls, observations and assertions are unchanged.
The original three-argument x86 declaration remains intact. A separate fixed
read-only generation observer keeps both payload buffers live for comparison.
Exact source copies, compiler/linker identities, arguments, build failures and
successful images are retained. All scratch directories are inside the task
tree. There are no deadlines, process termination calls or MUI cache mutations.

The first preparation rejected an OS-version/revision field mismatch before
any probe ran. A subsequent start RPC failed; the authoritative task state
proved it had never run. The same registration and bound inputs were then
started once. All 25 native processes completed with exit 0 and empty stderr;
input and installed-image identities were unchanged. The temporary task
registration and XML were removed after completion.

`profile-29704-v1.json` retains finite semantic signatures, sources, 25 image
identities, providers, generation and installed-file identity. The canonical
archive `nls-29704-native-artifacts-v2.zip` has 9081555 bytes, 82 payloads and
SHA-256 `849615ebc07095d6aa6face0f4316a5f311179230ab33d160f56259b77b86573`.
It includes native stdout, executable inputs, frozen and derived sources,
compiler/linker receipts, provider files, locale bytes and the native observer
template. Its manifest checks every payload before projection.

Verify retained sources, exact derivations and semantic signatures:

```sh
python3 -I -B docs/specifications/windows/native-nls-build-29704/check.py
```

With the archive, regenerate the projection and compare it byte-for-byte with
the checked-in JSON:

```sh
python3 -I -B docs/specifications/windows/native-nls-build-29704/check.py \
  path/to/nls-29704-native-artifacts-v2.zip > profile-29704-rebuilt.json
```

The shared emulator matrices now cover four admitted builds: 1264 initialization
rows, including 32 late retained views, and 20160 MUI query rows. Adjacent builds,
changed major/minor versions, missing data and unknown/foreign native machines
must fail without output or mapping publication. Native installed-leaf tests
separately check actual file bytes and mapping lifetime. Platform compilation
and runtime qualification of the emulator are separate from these observations.

The amended source passes 88 distinct focused CSR/NLS/MUI tests on native
macOS ARM64, 88 on native Linux x86-64 and 104 on native Windows ARM64, with
zero failures or ignores in those selections. The full macOS core binary
passes 10265 tests, with zero failures, two existing microkernel ignores and
zero filtered tests. Full core runs on Linux and Windows are additional gates;
their results are not inferred from the focused selections.

Unfiltered C API binaries pass 245, 245 and 244 tests respectively, with zero
failures, ignores or filtered tests. All three production C API configurations
compile with default features disabled. The public C API header is unchanged.

The unchanged ARM64 startup fixture, SHA-256
`9548e6b4c98e12569ab24adb28b0d5b2ce705416dcbb4fbda30482bef46bbb15`,
now reaches guest `Exited(0)` with no remaining threads under the installed
29704 libraries. This is a startup-fixture result, not complete hardware-fault
or command-processor qualification. The corresponding x64 fixture still stops
at AMD64 dispatcher-frame qualification; x86 still stops at its independently
gated WoW64 BASE CSR connection. Those failures remain explicit.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| N704-1 | The measured ARM64 kernel retains initialization and query-only MUI semantics. | Twelve fresh canonical profiles exactly equal the retained controls. | Admit exactly build 29704 on native machine 0xAA64. | Guards, aliases, faults, retained mappings and protection/free across four process profiles. | Any differing canonical row or leaf cleanup. | Confirmed for recorded observations. |
| N704-2 | Query bytes and shared language generation agree across the measured process profiles. | Four equal payload identities and three independent repeated captures. | Retain immutable acquisition and shared-page initialization. | Two live buffers per capture and before/after provider checks. | Differing payload, generation or physical provider. | Confirmed; runtime stability checks remain active. |

High-impact remaining scope: independent AMD64/i386 kernels for this build,
MUI mutations, WoW64 BASE CSR qualification, AMD64 dispatcher qualification and
full installed-process completion. These observations do not resolve those
barriers. No public C ABI, dependency pin or guest-directed host operation
changes. Initialization remains O(N) time and O(N) guest mapping storage;
MUI publication remains O(L + P) time with one 4096-byte scratch page and a
bounded immutable payload P.
