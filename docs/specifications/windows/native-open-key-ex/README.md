# Native extended key opens and fixed System policy

`NtOpenKeyEx` now has an appended four-slot `[Ptr, I32, Ptr, I32]` service
family, sharing snapshot-backed key opens with `NtOpenKey`. Installed x86
leaf checks require RET16 and unchanged callback stack/frame state. All prior
synthetic names, ordinals and trap addresses retain their positions. Guest
names, handles, access masks and options never reach a host registry call.

The host adapter additionally selects the fixed
`Software\Policies\Microsoft\Windows\System` subtree under the captured primary
SID. It retains the existing Safer selection. Both selections distinguish
known absence from uncaptured paths, attach to the primary SID and captured
native hive alias, survive catalog disposal through owned key objects, and
share the existing aggregate value/byte budgets. Acquisition order does not
change the result. An absent or childless primary hive cannot contain a present
selected child. No guest pathname expands host acquisition authority.

## Native observations

The frozen controls were collected on Windows10.0.29695 ARM64. ARM64 is the
physical native ISA; x64 and x86 are compatibility personalities on that kernel.
Each capture includes ARM64, x64, x86 and x86 with LARGEADDRESSAWARE. Separate
Windows2022/2025 CI observations provide independent AMD64 kernel evidence as
described below; the original failed CI replay remains part of that evidence.

| Version | Purpose | Rows per ABI |
|---|---|---:|
| v1 | Paired opens, options, pointer/attribute roles and policy absence; NLS parent | 1393 |
| v2 | Exact selected NLS CodePage key, grant query and address/handle identities | 1393 |
| v3 | Output/failure ordering, aliases, guards and per-call handle deltas | 6625 |
| v4 | Private duplicated token with all four backup/restore privilege profiles | 2565 |
| v5 | Grants and tags plus an isolated application-hive link diagnostic | 4689 native64; 4161 x86 |
| v6 | Handle validity, Win32 options and native `OBJ_OPENLINK` distinction | 80 |
| v7 | Conflicting views crossed with all30 pointer/attribute roles and options0/1/4 | 1441 |

Each `capture-vN.zip` is the original verified archive, including raw producer
stdout, the runner receipt, compiler logs and an archive manifest. v5/v6 also
retain generated private application-hive files; these are created from fresh
absent paths and contain only the producer's diagnostic keys/values. They are
not copies of an existing user/system hive. Executables and object/PDB files
were excluded after their before/after hashes and PE identities were recorded.
Executed `probe-vN.cpp` and `run-vN.py` are byte-for-byte frozen. The v3/v5/v7
replay inputs use Zstandard compression of the unchanged JSONL bytes; decoded
sizes and SHA256 values are in `provenance.json`. The complete retained set is
1.27 MB before the documentation/reference copies, avoiding a
15.20 MB plaintext duplication. No new compression dependency is introduced.

## Independent AMD64 key-name validation

The unchanged v3/v5/v6/v7 producers also completed on native AMD64 kernels
10.0.20348 and10.0.26100 in [run40689391666](https://github.com/HexRaysSA/rax/actions/runs/40689391666).
The two jobs' acquisition artifacts are retained as `amd64-20348-capture-v1.zip`
and `amd64-26100-capture-v1.zip`. `amd64-provenance.json` records their hashes,
source commit, jobs and18 compressed v3/v5/v7 replay inputs. The20 additional
immutable files occupy1189291 bytes. Original receipt, compiler log and JSONL
bytes are preserved; no emulator result supplies an expected native status.

The initial fresh replay failed on odd `UNICODE_STRING.Length` for an open
key name. Both AMD64 kernels return `STATUS_OBJECT_NAME_INVALID` (0xC0000033),
where the retained ARM64 profile returns `STATUS_INVALID_PARAMETER`
(0xC000000D). Comparing v3 statuses isolates72 native64 and144 per x86 view
differences on each kernel to odd-name roles16/26. Other statuses agree.

Open validation now selects this result from the captured native machine and
kernel version, independently of the guest-visible version and compilation
host. Native64 retains rejection before name-buffer probing; WoW64 retains its
earlier widening, output, root, view and option checks. `NtQueryValueKey` keeps
its existing descriptor validation. Captured AMD64 builds20348/26100 and ARM64
builds29683/29695 are explicit profiles. An unknown native identity produces
`registry odd key-name kernel profile is not captured` when this distinction is
required. The built-in personality retains its original ARM64-derived result.

The retained replay selects each capture's actual kernel identity. The fresh
replay selects the identity in its receipts and requires matching receipts.
All six AMD64 ABI matrices remain enabled alongside the four ARM64-kernel
views. They add27772 native-equality calls and68 explicit namespace frontiers;
192 additional sibling calls remain exploratory. Full CMD execution remains
outside the result established by these controls.

Native64 rejects invalid options before probing caller memory. The legal
measured mask is0x1C. For valid options it probes/zeroes output before capturing
attributes and name. WoW64 first widens attributes/name, probes nonnull output,
then checks absolute rooted syntax, conflicting view bits and a nonzero
relative root handle before native option validation. Its successful open with a
null output reports access violation and leaks one handle; an earlier key/access
failure with null output preserves that failure without allocation. Nonnull
faulting output can override a prior native failure. Guard consumption is
one-shot. Caller LastError remains unchanged.

Backup/restore bit4 uses enabled privileges17 (`SeBackupPrivilege`) and18
(`SeRestorePrivilege`) from the captured effective subject. The current
thread-token attachment boundary makes that the captured primary subject;
missing subject data produces an explicit frontier. Native controls adjust only
a separately duplicated private token and verify that the original token's
privileges remain unchanged. Measured grants are0x01020019 for backup,
0x010F0006 for restore and0x010F001F for both, independent of requested access.
Neither enabled privilege yields access denied. The contradictory x86 view
request0x300 remains invalid. Key-body view tags retain native64 zero and x86
default0x400/explicit64 0x100/explicit32 0x600.

The private application-hive diagnostic separates two interfaces:
Win32 `RegOpenKeyExW` option8 opens the source, while direct user-mode
`NtOpenKeyEx` requires `OBJECT_ATTRIBUTES.Attributes` bit0x100 (`OBJ_OPENLINK`)
for that result. Direct OpenOptions bit8 alone retains ordinary resolved-key
behavior in these controls. An ordinary link-following attempt into the private
application-hive absolute namespace is denied by that namespace's restriction;
this is not evidence that ordinary global link following is unavailable.
Source-node metadata is not captured by this implementation, so `OBJ_OPENLINK`
returns an explicit unsupported frontier. It must not be treated as an invalid
native flag or silently resolve to the target.

## Replay boundaries

The retained v3 replay handles3312 native calls per ABI. Per ABI it keeps32
exploratory sibling-name calls outside the selected snapshot as raw evidence.
For native64,24 additional output/path alias cases mutate a selected relative
name into an uncaptured one: these assert the exact unsupported frontier rather
than inventing native absence for a wider namespace. Thus13072 calls across
four ABIs assert native status, defined writes, guards, LastError, tags and
handle deltas;48 assert the namespace frontier;128 remain exploratory.

The v7 replay adds2860 native-equality cases and20 explicit namespace frontiers
across the four ABIs. Together v3/v5/v7 execute18492 native-equality cases and68
frontier assertions;128 exploratory v3 calls remain outside the selected routes.

The v5 replay additionally checks640 backup/restore calls per ABI, including
all four privilege profiles, four option combinations, ten desired masks and
four view masks. It reads the separate `profile_tags` record paired with each
successful open. Returned handle bytes are volatile: the replay independently
checks the actual object, grant, tags, close and count, and compares all other
captured bytes relative to separately reconstructed native/guest initial
images. Native pointer values are not guest addresses.

The existing ordinary `MAXIMUM_ALLOWED` grant disparity is explicit: native
returns0xF003F for these keys while the bounded ordinary read policy grants
0x20019. The replay asserts that known difference, rather than claiming grant
parity for it. Other key metadata, link-source capture and arbitrary registry
writes are outside this change. Full process emulation and CMD completion are
not established by these controls.

## Reproduce

From the repository root, retained provenance and shared semantic checks run
without a Windows host:

```sh
mkdir -p .t target/native-open-key-build
export TMPDIR="$PWD/.t" TMP="$PWD/.t" TEMP="$PWD/.t"
export CARGO_TARGET_DIR="$PWD/target/native-open-key-build"
umask 022
python3 -B -m unittest discover -s docs/specifications/windows/native-open-key-ex
cargo +1.95.0 test --locked --no-default-features --lib native_open_key_ex -- --nocapture --test-threads=1
cargo +1.95.0 test --locked --no-default-features --lib registry -- --test-threads=1
```

For fresh native Windows controls, use an in-tree output directory and the
MSVC environment accepted by the existing compiler adapter. Example PowerShell
commands for physical AMD64:

```powershell
New-Item -ItemType Directory -Force .t | Out-Null
$env:TEMP = Join-Path $PWD '.t'
$env:TMP = $env:TEMP
$env:TMPDIR = $env:TEMP
$env:SystemTemp = $env:TEMP
$env:CARGO_TARGET_DIR = Join-Path $PWD 'target/native-open-key-build'
python -B docs/specifications/windows/native-open-key-ex/run-v3.py --require-native-machine 0x8664 --output target/native-open-key-order-v3
python -B docs/specifications/windows/native-open-key-ex/run-v5.py --require-native-machine 0x8664 --output target/native-open-key-grants-v5
python -B docs/specifications/windows/native-open-key-ex/run-v6.py --require-native-machine 0x8664 --output target/native-open-key-link-v6
python -B docs/specifications/windows/native-open-key-ex/run-v7.py --require-native-machine 0x8664 --output target/native-open-key-views-v7
$env:RAX_NATIVE_OPEN_KEY_EX_ORDER = Join-Path $PWD 'target/native-open-key-order-v3/receipt.json'
$env:RAX_NATIVE_OPEN_KEY_EX_GRANTS = Join-Path $PWD 'target/native-open-key-grants-v5/receipt.json'
$env:RAX_NATIVE_OPEN_KEY_EX_VIEWS = Join-Path $PWD 'target/native-open-key-views-v7/receipt.json'
cargo test --locked --no-default-features --lib native_open_key_ex -- --nocapture --test-threads=1
```

Use0xAA64 on a native ARM64 Windows host. Each runner requires a fresh output
path, checks compiler/adapter/source/executable hashes, machine identities,
optional-header width, x86 LAA state, process result and SEH exceptions. The
fresh replay validates both receipts and reports executed ABI/case counts.
Without the three environment variables, only retained observations run; the
optional fresh test does not establish a fresh native result. The installed
NTDLL leaf test is Windows-only. Shell commands above assume the normal
in-tree build/temp/cache configuration; no external sysroot is needed.

The complete library gate additionally uses native filesystem semantics for its
scratch data. A macOS-backed bind mount is not equivalent to a Linux filesystem
for xattrs, special nodes or retained inode metadata. The qualification ledger
retains the failed bind-mount run, the unchanged-executable checks on native
Linux scratch, and the process-local umask022 setting. On macOS, short in-tree
temporary paths keep unrelated Unix-socket fixtures within native path limits.
No product source was changed to conceal those environment failures.

Selected-route lookup normalizes n UTF16 code units in O(n) time and O(n)
scratch, checking only two fixed policy routes. Shared snapshot records are
charged once. The replay indexes immutable grant/tag tuples in a BTreeMap;
building that index is O(r log r) for r captured tag records.

## Assumption register and bounded findings

| ID | Assumption and basis | Dependent result | Stress/falsification probe | Status |
|---|---|---|---|---|
| KO1 | Option0 shares ordinary open semantics; paired native observations | Shared `open_checked` | Any paired status/defined-write/guard mismatch across pointer roles and ABIs | Confirmed for captured controls |
| KO2 | System policy requires a fixed route under the captured subject; actual CMD stopped there | Second immutable policy selection | Present/absent roots, six acquisition orders, both aliases, SID mismatch, budget limits | Confirmed within these bounds |
| KO3 | WoW64 view/root checks precede native option checks after widening/output probes | Validation placement | v7 crosses conflicting views with all30 roles, options0/1/4 and present/missing paths; any mismatch falsifies placement | Confirmed on captured29695 ABIs |
| KO4 | The current personality has no impersonation-token attachment service (`dll/native/token.rs`) | Backup/restore reads the captured primary subject | Introducing a successful thread-token attachment requires replacing this effective-subject assumption | Confirmed for the current personality |
| KN1 | Odd key-name status depends on captured kernel identity; independent AMD64 controls disagree with the ARM64 controls only at odd-name roles | Open-only status selection | Replay every retained matrix, spoof guest version, reject unknown native identity, retain value-query errors; any byte/guard/handle mismatch falsifies placement | Confirmed by retained replay on macOS, Linux and Windows |

The corrected retained replay checks46264 native-equality calls and136 explicit
namespace frontiers across ten captured ABI/kernel views. It keeps320 sibling
calls exploratory. Five provenance tests pass on all three hosts. Focused
extended-key tests pass9/9/10 on macOS/Linux/Windows; registry tests pass
141/138/169, CLI tests pass8/8/10, C API tests pass191 on each, and all-target
compilation passes on each.
The macOS complete library gate passes8775 tests and the Linux gate8765, each
with zero failures, two existing ignored tests and zero filtered tests. macOS
strict production Clippy passes. Native Windows complete-library validation
and fresh physical AMD64 CI remain running or pending at this source frame;
neither is represented as completed by the retained replay.

High: an instrumented prototype identifies an uncaptured AppModel Lookaside
machine key. The final CLI independently stops at an uncaptured `NtOpenKey`;
its exact key name has not been independently re-inspected. Full CMD/process
execution remains incomplete.
Medium: link-source metadata and the ordinary `MAXIMUM_ALLOWED` grant disparity
remain explicit boundaries. Neither is concealed by a native-parity claim.

## Primary references

Original Microsoft documents, URLs, retrieval date and SHA256 values are retained
under `references/`. Kernel `ZwOpenKeyEx` documentation and the remote registry
protocol provide interface context; user-mode capture order is established by
the native producers. The general registry-value page describes `REG_LINK` as
null-terminated, while MS-RRP3.1.1.11 explicitly requires a non-null-terminated
Object Name. The isolated diagnostic stores both variants but cannot resolve
that conflict for ordinary link following because the application-hive absolute
namespace rejects that operation. No representation assumption is inferred from
that failed control.
