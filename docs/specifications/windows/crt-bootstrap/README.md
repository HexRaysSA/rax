# CRT bootstrap provenance

This archive records primary contracts, genuine binding names and scoped static
publisher observations for `_set_app_type`, `_query_app_type`,
`_configthreadlocale`, `__setusermatherr`, `_fpreset` and `__pxcptinfoptrs`.
It is not a native Windows execution oracle, complete locale/math support, or
evidence that ordinary compiler startup has completed. The acquisition baseline
is `9bc8ccdca85a5b0c9c74a7c446c85194efdc780d`.

The exact input index is [sources.json](sources.json). It contains 65 inputs:
44 retained/reused path-and-hash inputs and 21 metadata-only SDK inputs. The
16 inspected SDK source/header/DLL receipts are also enumerated in
[sdk-inputs.json](sdk-inputs.json). The five additional SDK receipts reuse the
prior package, license, PTD implementation/header and signal-header evidence.
Raw proprietary SDK source, header, license and DLL bytes are not retained here.

## Acquisition and verification

```sh
ruby docs/specifications/windows/crt-bootstrap/acquire.rb
ruby docs/specifications/windows/crt-bootstrap/acquire.rb --verify
ruby docs/specifications/windows/crt-bootstrap/acquire.rb --verify-network
```

[acquire.rb](acquire.rb) uses the hash-pinned SDK ZIP extraction functions from
the prior termination archive, never its driver. The full-package SHA-512 receipt
is reused rather than recomputed from a second 155,613,545-byte package download.
The fresh central directory and each selected uncompressed member are checked
against their exact ZIP metadata, CRC-32, length and SHA-256. SDK bytes remain in
the printed temporary inspection directory. Reproduction is content-addressed;
temporary paths are not archive identities.

The network verifier replays public input acquisition, SDK members, publisher
EAT/disassembly and the ZIP member survey. The offline verifier checks all
retained inputs, prior-manifest identities, installed input/tool hashes, exact
source copies, four import-archive observations and six ordinary-producer IAT
observations. Missing installed inputs/tools are reported, not counted as native
coverage. [verification.json](verification.json) records the frozen executions.
SDK NuGet signature verification was not performed; package integrity and
publisher authenticity are separate claims.

Public Microsoft Markdown is pinned to CPP-docs revision
`f2355df9f7136d8a2097193fc507882a7caeb5f5`. The exact prose/sample licenses are
reused from [LICENSE](../crt-initializers/microsoft/LICENSE) and
[LICENSE-CODE](../crt-initializers/microsoft/LICENSE-CODE). Installed MinGW
inputs retain their notices and the owning
[COPYING](../crt-initializers/mingw14/COPYING),
[DISCLAIMER.PD](../crt-initializers/mingw14/DISCLAIMER.PD) and
[Zig-bundled COPYING](../crt-initializers/zig/COPYING). The inspected proprietary
SDK license is a hash-only receipt, not a redistributed license file.

## Binding evidence

| Function | Genuine UCRT publisher EAT | Installed API-set definition | Legacy evidence boundary |
|---|---|---|---|
| `_set_app_type` | x86, x64, native ARM64 | runtime; `__set_app_type` is an alias to this PE spelling | Genuine legacy `__set_app_type`; no inference that its body equals modern UCRT |
| `_query_app_type` | x86, x64, native ARM64 | runtime | No selected legacy import evidence |
| `_configthreadlocale` | x86, x64, native ARM64 | locale | No selected legacy import evidence; combined public `api_location` is not an architecture-specific inventory |
| `__setusermatherr` | x86, x64, native ARM64 | math | Genuine legacy import; legacy implementation not inspected |
| `_fpreset` | x86, x64, native ARM64 | runtime | Genuine legacy import; legacy implementation not inspected |
| `__pxcptinfoptrs` | x86, x64, native ARM64 | runtime | Selected genuine import objects also recorded; no legacy body-equivalence claim |

The complete selected publisher names/ordinals/RVAs are in
[x86 EAT](publisher/ucrtbase-x86-exports.json),
[x64 EAT](publisher/ucrtbase-x64-exports.json) and
[ARM64 EAT](publisher/ucrtbase-arm64-exports.json). `__set_app_type` and
`_matherr` are absent from these exact three UCRT publisher DLLs. This is not a
claim about every Windows release or other DLL. The ARM64 file is ARM64X;
the secondary ARM64EC EAT is preserved separately and is not AArch64 instruction
evidence.

The pinned runtime definition is reused from
[crt-startup](../crt-startup/zig/api-ms-win-crt-runtime-l1-1-0.def.in).
The selected [locale](zig/api-ms-win-crt-locale-l1-1-0.def) and
[math](zig/api-ms-win-crt-math-l1-1-0.def.in) definitions are retained here.
The `_fpreset F_LD80(DATA)` producer annotation does not override the publisher
EAT and executable function-body evidence. An `I __imp_` archive member is an
import object; a `T` function plus `D __imp_` is a local compatibility shim.
Actual DEF aliases and emitted IAT spellings decide the imported name.

The six reused ordinary GCC/Zig main/wmain IAT receipts are genuine compiler
startup outputs, not these semantic probes. They retain their PE input hashes
and exact observer command. x86/x64 ordinary MinGW images import modern UCRT
app/locale/math setters; their FP initialization is a local producer wrapper.
The inspected ARM64 producer image imports `_fpreset` but does not import
`_configthreadlocale`. The retained MinGW and Zig startup versions must not be
conflated: [MinGW crtexe.c](../crt-initializers/mingw14/crtexe.c) and
[Zig crtexe.c](../crt-initializers/zig/crtexe.c) have different startup bodies.

## App and locale state

The SDK app source has a 32-bit application-type cell initialized to enum value
0; the selected setter stores without validation and the getter reads it. SDK
header values are unknown=0, console=1 and GUI=2. The runtime-error reporter
actually consumes that cell with report-mode state when selecting stderr versus
GUI reporting; a setter is not a no-op. The inspected source and modern/legacy
name distinction supplement the obsolete
[public app-type page](microsoft/internal-set-app-type.md).

The selected locale source and publisher bodies return the previous current
thread mode: enabled=1 when the PTD bit `0x2` is set, otherwise disabled=2.
Input 0 queries, 1 sets bit `0x2`, and 2 clears it. Input -1 stores -1 into the
global locale synchronization policy without changing that thread's bit.
PTD construction initializes its own-locale field with global-locale bit `0x1`.
The inspected synchronization predicate uses the intersection of this field and
the global policy; therefore -1 has a material global effect even if a query
still returns 2. Declared header constants are not proof of accepted flags.

Two source/public-document conflicts are intentionally preserved:

- The [public locale page](microsoft/configthreadlocale.md) lists only 0/1/2 as
  valid and describes other values as invalid. SDK source and all three selected
  DLL bodies accept -1; the retained MinGW startup uses it. No blanket validation
  rule may discard that source-specific startup path.
- The public prose describes errno assignment after a returning invalid handler.
  The selected DLLs assign 22 before calling the invalid handler and do not
  overwrite it afterward. A callback can therefore observe 22 and replace it.
  The exact observable instruction order, not a guessed macro expansion,
  establishes this source-version behavior.

In the [x64 instruction receipt](publisher/ucrtbase-x64-disassembly.json),
VA `0x18008443D` calls `_errno`, `0x180084442` stores 22 and `0x180084448`
calls `_invalid_parameter_noinfo`. Equivalent x86 and ARM64 branches are retained
in their receipts. The SDK internal header includes `internal_shared.h`, but
that header's member name is absent from the selected full SDK ZIP directory.
The `_VALIDATE_RETURN` definition is consequently unknown. The
[member survey](publisher/member-survey.json) records the exact negative probe.

The SDK PTD uses its own two-state/FLS machinery. This evidence does not establish
that an emulator's thread-keyed state is the native fiber identity or that the
locale setters alone implement `setlocale`, `_wsetlocale`, NLS or code-page
consumers. Those dependencies remain outside this provenance group.

## Math callback registration

[Public registration documentation](microsoft/setusermatherr.md) declares a
`__cdecl int(struct _exception*)` callback. The three selected bodies encode and
store the supplied callback in current-state-indexed process state; they neither
invoke it eagerly nor validate its code address. No inspected native math
consumer is claimed. The ZIP
[survey](publisher/member-survey.json) finds no member in the `math/` source
directory and no filename matching `fpreset` or `matherr`; this is not proof
that equivalent code cannot exist under another name.

[Zig usermatherr.c](zig/usermatherr.c) is a producer compatibility implementation
with its own stored callback and helper; it is not the Microsoft DLL body.
[Public `_matherr`](microsoft/matherr.md) documents consumer return/result
semantics but does not prove that the selected UCRT DLL exports `_matherr`.
Raw proprietary mathematical source was not recovered or retained.

## Architecture-specific `_fpreset`

All addresses below are preferred-image virtual addresses; the observations
retain image base, half-open disassembly ranges, input hashes and exact LLVM
command argv. Nearest-export labels on internal helper ranges are annotations,
not recovered genuine helper symbols.

| Guest ABI | Selected publisher reset body | State not reset by this body |
|---|---|---|
| x86 | `_fpreset` at `0x10058180`: establish PTD, snapshot PTD+4 exception pointer, `FNINIT`, change x87 precision to 53 bits, reset MXCSR to `0x1F80` if SSE availability permits, conditionally clear saved-context status/tags | Physical x87 80-bit payloads and XMM payloads; saved-context control word/payloads; no `_fpecode` assignment observed |
| x64 | `0x18008AC80`: load MXCSR=`0x1F80` | x87 state and XMM/vector payloads |
| native ARM64 | `0x180153800`: write FPCR=0 and FPSR=0 | V0–V31 payloads |

The scoped evidence is in [x86](publisher/ucrtbase-x86-disassembly.json),
[x64](publisher/ucrtbase-x64-disassembly.json) and
[ARM64](publisher/ucrtbase-arm64-disassembly.json). The x86 availability branch
skips MXCSR when the inspected availability value is below 1; with the reset
operand's DAZ bit clear, the selected path directly loads `0x1F80`. This is not
an unconditional claim about non-SSE x86 systems.
The mapping from CPU/OS features to that publisher availability global was not
established by the selected source/body inputs. Admitting the reset branch for
the emulator's fixed SSE2-enabled guest CPU is a named implementation profile;
downlevel CPU/OS availability behavior remains unknown rather than being inferred
from the branch threshold.

The x86 first reset instruction is `FNINIT`, not a waiting reset of old pending
exceptions. Waiting instructions occur later in the precision-control helper.
The existing unmodified [Intel SDM](../../x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf)
revision 086 defines `FNINIT` as clearing environment/status/tags while preserving
physical data-register payloads; it does not reset XMM/MXCSR. `FLDCW` loads its
16-bit operand and leaves condition codes C0–C3 undefined.

Exact x86 control-word operand derivation, in bits:

1. `FNINIT` initializes FCW=`0x037F` (64-bit precision, all six exception masks).
2. `_controlfp_s(NULL,0x10000,0x30000)` replaces the abstract precision field:
   reset abstract state `0x8001F` becomes `0x9001F`.
3. The inspected converter maps the exception masks to `0x003F` and abstract
   53-bit precision to architectural `0x0200`; it does not OR reserved bit 6.
4. The actual `FLDCW` memory operand is therefore `0x023F`, not `0x027F`.

Intel Vol. 1 Section 8.1.5/Figure 8-6 defines masks at bits 0–5, precision at
8–9, rounding at 10–11 and obsolete infinity control at 12. Section 1.3.2
forbids dependence on reserved-bit values/retention; the defined-field comparison
mask is `0x1F3F`. A conventional `0x027F` readback differs only in reserved bit 6
and is not proven by this archive. Native readback of that bit is unknown.
Choosing a raw CPU field value is an implementation profile, not new native
evidence. Independent guest assertions must not turn reserved readback into an
oracle. The existing SDM
[provenance](../../x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.provenance.md)
records the unknown original historical download URL/date separately.

### Exposed saved exception-context plane

The SDK signal header declares `void** __cdecl __pxcptinfoptrs(void)`;
the macro dereferences that accessor. Its EAT presence is independently confirmed
on all three UCRT publisher DLLs. x86 ordinal 132/RVA `0x887B0` returns PTD+4;
x64 ordinal 98/RVA `0xC1790` and native ARM64 ordinal 92/RVA `0x7AE40` return
PTD+8. The result is the address of a thread-state pointer cell, not an
`EXCEPTION_POINTERS*` value itself. This is genuine externally writable state,
not an invented helper export.

Only the inspected x86 `_fpreset` reads this pointer cell. If non-NULL it reads
the saved-context pointer from `EXCEPTION_POINTERS+4`. If the 32-bit saved
`ContextFlags & 0x10008` is nonzero, it clears the 32-bit StatusWord at offset
`0x20` and writes TagWord=`0x0000FFFF` at offset `0x24`. This is the actual
nonzero-intersection test, not equality to the full combined mask. Saved-context
control word and floating register bytes are unchanged by this path. These
private helper dependencies are included in the receipt rather than inferred
from the public `_fpreset` description.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| B1 | Exact SDK package/member hashes identify the inspected bytes, but do not authenticate the publisher signature | Full-package digest and ZIP metadata reuse; signature not checked | All publisher/static-source conclusions are version-bound | Replaced member with same basename | Replay package central-directory/member checks; verify NuGet signature separately | retained |
| B2 | First ARM64X EAT/body represents native AArch64, not the secondary ARM64EC table | LLVM file headers, separate EAT records and AArch64 instructions | ARM64 accessor/reset conclusions | Selecting secondary ordinal/RVA | Replay native ranges and inspect machine/header/secondary records | confirmed for selected file |
| B3 | Installed import/source observations apply only to their exact producer versions and inputs | Input hashes, actual aliases/IAT receipts; bundled MinGW commit unknown | Conservative named admission and ordinary-startup graph | Local shim masquerading as native import | Compare `I` vs `T+D`, DEF alias and exact emitted IAT spelling | retained |
| B4 | Public prose and inspected publisher bytes can differ; neither is silently generalized to every release | Locale -1/errno-order and legacy/modern name conflicts | Source-version behavior and explicit unknown native comparisons | Handler mutates errno; caller passes -1 | Run the same probes on a native Windows installation with exact DLL hashes | confirmed conflict; generalization unknown |
| B5 | Reserved x87 FCW readback is not a golden native value | Intel Sections 1.3.2/8.1.5 and actual converter operand | `0x023F` operand derivation and masked field assertions | Hardware forces reserved bit 6 | Compare defined bits and separately record full native FCW on identified hardware/DLL | revised; raw native readback unknown |
| B6 | The emulator's fixed SSE2 guest profile admits the inspected MXCSR reset branch | Publisher helper checks its availability global; initialization mapping not inspected | Selected x86 MXCSR reset profile, not general CPU/OS discovery | Downlevel CPU or OS without enabled SSE state | Identify and inspect `__isa_available_init` for this exact DLL, then probe native CPUID/CR4 combinations | retained; native mapping unknown |

## Bounded scope and quality gates

High-impact non-blocking limits: native Windows execution remains unknown;
locale consumers and mathematical error dispatch are not implemented by these
observations; private PTD/FLS identity and dual-state details must not be inferred
from an accessor alone; scoped disassembly is not recovered mathematical source.
Medium-impact limits: producer versions differ, original bundled MinGW revision
and historical SDM download provenance are unknown, and no SDK macro-definition
header was found. Low-impact scope: legacy publisher bodies are not inspected.

Only archive inputs and reproducibility receipts are changed. Direct ISA, SMIR,
JIT, backend, scheduler, loader and C/Rust public ABI code are unaffected; this
archive supplies evidence to their separately owned implementation/tests. The
algorithmic acquisition cost is O(S + D + R + P) time for total selected/reused
bytes S, ZIP-directory bytes D, observed instruction/output bytes R and installed
producer inputs P; SDK memory is O(S + D), without retaining the complete package
in memory. Offline verification reads one input at a time; observer tools have
their own input-memory costs. No total-host-OOM guarantee is claimed.

QG1–QG7: no normative judgment; explicit assumption/falsification register;
all six selected bindings/contracts and 16 SDK inputs covered; byte/bits/address
derivations reproducible; source-policy conflicts and unknowns preserved;
primary hashes/licenses/tool commands verified; bounded additional risks named.
Actual verification counts and unavailable-input status are in the adjacent
receipt, not inferred from command exit status.
