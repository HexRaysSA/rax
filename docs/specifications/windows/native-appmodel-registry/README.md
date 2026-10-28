# AppModel registry-view acquisition controls

These controls investigate the measured current CMD frontier at
`\Registry\Machine\SOFTWARE\Microsoft\AppModel\Lookaside\machine`.
Qualified runtime 864523b5 observes an ordinary open with access0x80000100,
attributes48bytes/root0/flags0x40 and name Length126/Maximum128bytes. Native
opens return STATUS_OBJECT_NAME_NOT_FOUND; the emulator reports an uncaptured
snapshot. Full process emulation remains the active objective.

The original acquisition commit changes no guest runtime behavior. Its two existing
Windows 2022/2025 qualification jobs additionally acquire these read-only controls.
Fresh physical AMD64 captures from run40713596189 are retained as the original
`amd64-20348-capture-v1.zip` and `amd64-26100-capture-v1.zip`; their API digests,
archive CRCs and acquisition identities are verified by `test_amd64_provenance.py`.
Each host executes three ABI views and192 opens. Together with ARM64 this is
640 query-only opens across ten executable/kernel views.

## Measured controls

`probe-v1.cpp` and `run-v1.py` are frozen after native execution. The original
verified `capture-v1.zip` retains receipt, compiler logs, raw JSONL and an archive
manifest. Compiler/executable/producer identity, PE machine, optional-header
width and x86 LAA state are recorded. Executables and object/PDB files are
excluded after their identities are retained. `provenance.json` binds the three
immutable files; reference copies have their own URL/date/hash manifest.

Windows 10.0.29695 ARM64 runs four executable views: native ARM64, compatible
x64, x86 and x86-LAA. Each records 64 ordinary/extended opens, plus machine and
completion rows. The 256 calls use fixed AppModel and CurrentVersion paths,
private descriptors/buffers and query-only handles. No key, value, override or
process-wide setting is changed. Handle counts balance in all four runs.

The CurrentVersion control is present in both physical views and supplies
canonical native names through NtQueryKey class3. Each absolute/relative case
crosses flags 0/0x100/0x200/0x300, ordinary NtOpenKey and NtOpenKeyEx option0.
Relative cases use self/Run names and roots opened with three view requests.
The private name-information buffer is 65536 bytes; its length, returned size and
UTF16 byte parity are checked before reading units. User-mode scratch is O(1);
emitted/parsing work is O(U) in the number of recorded name units.

On this ARM64 kernel, direct native64 NtOpenKey does not redirect the logical
CurrentVersion name when view flags are set. The WoW64 thunk redirects absolute
default/0x200 requests to Wow6432Node and 0x100 requests to the 64-bit path;
conflicting 0x300 fails with STATUS_INVALID_PARAMETER. Relative opens retain the
root handle's physical path except that an explicit32 request from a root
opened in the64-bit view switches to Wow6432Node. An explicit64 request from
a32-bit root retains the32-bit physical path. NtOpenKeyEx
option0 agrees with ordinary opens in every paired status/name/tag observation.

Key-body tags depend on the open context. Absolute redirected x86 opens report
0/0x100/0x200 for default/64/32 requests. Relative self/child opens also expose
0x400/0x800 bits in some contexts. The existing shared-snapshot formula cannot
be applied universally. Raw values remain preserved; no meaning for those
additional bits is inferred here. AppModel absence alone proves no present-key
sharing, view-tag or value behavior.

## Reproduce

Retained input verification is portable:

```sh
python3 -B -m unittest discover -s docs/specifications/windows/native-appmodel-registry
```

Fresh physical AMD64 acquisition from an MSVC developer environment:

```powershell
New-Item -ItemType Directory -Force .t | Out-Null
$env:TEMP = Join-Path $PWD '.t'
$env:TMP = $env:TEMP
$env:TMPDIR = $env:TEMP
$env:SystemTemp = $env:TEMP
python -B docs/specifications/windows/native-appmodel-registry/run-v1.py --require-native-machine 0x8664 --output target/native-appmodel-registry-v1
```

Use 0xAA64 for a native ARM64 host. The output path must be new and inside the
source tree. Expected receipt: state finished, exit_code 0, three AMD64-host
views or four ARM64-host views; each producer ends with calls 64 and equal
handles_before/handles_after. Preserve failed records separately from retries.

## Assumption register and scope

| ID | Basis and dependent result | Stress/falsification probe | Status |
|---|---|---|---|
| AM1 | SOFTWARE redirection documentation motivates separate AppModel views | Cross all view flags and ABI personalities; compare canonical native names | Revised: direct native64 NT opens ignore these flags on all three captured kernels; WoW64 absolute opens redirect |
| AM2 | A relative open may retain its root handle view | Self/Run under default/32/64 roots, all requests and both APIs; a changed physical prefix falsifies retention | Falsified as a universal rule: explicit32 from a64-bit root switches physical view on ARM64 and both AMD64 kernels |
| AM3 | Present AppModel data inherits SOFTWARE redirection; absolute and relative routing depend on this | A real present AppModel root with distinct native32/64 names or values contradicting the selected mapping falsifies it; controlled distinct-value fixtures and native IFEO acquisition exercise present snapshot mechanics separately | Retained: native present-AppModel parity is unknown because every captured real AppModel root is absent |

High: all measured AppModel roots are absent. The present-root view mapping is
inferred from the documented inherited SOFTWARE redirection and the measured
CurrentVersion control; a present AppModel native-name observation can falsify
that inference. Context-sensitive WoW64 key-body tags remain explicitly
uncaptured for this namespace. Prior grant/link metadata boundaries and installed
Assist/GUI/real-IDB/package qualification remain separate open work.

## Primary references

Microsoft's [registry-view table](https://learn.microsoft.com/en-us/windows/win32/winprog64/shared-registry-keys)
classifies SOFTWARE as redirected and describes inheritance by subkeys.
[Alternate-view documentation](https://learn.microsoft.com/en-us/windows/win32/winprog64/accessing-an-alternate-registry-view)
describes Win32 view flags and child-open guidance. The native NT observations
above are distinct from those Win32 rules. Original copies and their provenance
are retained under `references/`.

## Independent acquisition CI

Both AppModel observe/upload steps pass in
[run40713596189](https://github.com/HexRaysSA/rax/actions/runs/40713596189).
The Windows2025 job passes in full. The first Windows2022 attempt fails in the existing
`run-dispatch-v4.py` native exception observer: the fault is observed, its
dispatcher entry breakpoint is missed, child exit97 and observer error25 are
retained. That observer and the exception runtime source are unchanged by the
acquisition commit. This is a failed broader gate, not a complete green run;
its independently completed AppModel controls are the archived evidence above.
One targeted retry subsequently passes; the latest attempt records success for
both jobs (122923458376/122923461472). The original failure is preserved, and
its cause remains unknown; the retry does not establish a fix to that observer.

## Snapshot implementation

The installed-runtime selector acquires independent64/32 snapshots through
fixed read-only Win32 `RegOpenKeyExW` calls with flags0x100/0x200. Only the
compile-time AppModel root and bounded native-enumerated children reach host
registry calls. Root error2 establishes absence independently in each view;
other errors and child disappearance abort capture. Handles close before
descendant opens. Values, key names, child topology and raw UTF16 data are
immutable after selection.

Guest native64 NT opens ignore view flags, as the retained controls show.
WoW64 absolute opens select32 by default or0x200, and64 with0x100;0x300 remains
invalid. Relative default/64 opens retain their physical root; explicit32
from a64-bit root resolves through its original32 snapshot. Handles retain
the immutable pair after catalog replacement and duplicate/close operations,
without reference cycles or guest-driven native access. Lookup uses registry
separator semantics and exact component boundaries. The object-manager prefix
requires one leading separator; malformed prefixes, parents and neighbors remain
uncaptured rather than being normalized into the selected root. Global malformed
object-path status parity remains a separate namespace boundary.

Both AppModel views share the global4096-value/16MiB raw-value budget with
existing roots, and share1024 keys/1MiB path metadata between themselves.
Depth32 and component255 UTF16-unit limits remain enforced before publication.
Capture and construction take O(K+V+B) time and space for keysK, valuesV and
retained bytesB; lookup takes O(U log K) time and O(U) scratch in the numberU
of requested UTF16 units, with case folding from the selected native table.

Existing shared-key body tags are unchanged. Native64 AppModel handles retain
zero body tags. WoW64 AppModel handles retain an explicit uncaptured state;
`NtQueryKey` class7 stops with that explanation after the established probes
and typed-handle checks, without publishing invented return bytes, including
the conversion-buffer path. Other unimplemented key information classes remain
explicit boundaries. This is not proof of complete process emulation.

## Current Unix qualification

The prefix-corrected candidate passes8783 macOS and8773 Linux complete-library
tests, with zero failures, two existing ignored tests per host and zero filtered
tests. Focused/registry/object/CLI/CAPI checks pass8/149/8/8/191 on macOS and
8/146/8/8/191 on Linux. Both all-target checks pass; strict production library
Clippy and all12 workflow-policy checks pass on macOS. These are combined-tree
results for the16-file runtime manifest, with no unrelated worktree edits.

Separate real CLI/native comparisons use the installed `true`, UTF8 `printf`,
a shell built-in and a shell executing `/usr/bin/printf`. All four cases per
host match native stdout and exit0 without a separate sysroot. The CLI uses
its default host-service mode; the existing closed-runtime unit tests separately
exercise installed glibc/libm or the dyld shared cache. Linux runs an x86-64
container through translation on an ARM64 physical host. This is finite program
coverage, not physical x86 proof or complete syscall/GUI qualification.

The macOS unoptimized CLI shell runs take36.84/40.24s. Earlier30s observation
deadlines expired and are retained as such; a longer untraced replay succeeds.
The Windows unchanged installed-library CLI test also retains its first60s
child failure and the exact successful retry (51.18s test execution). Neither
existing test limits nor assertions are changed. Corrected-source ARM64 Windows
qualification now passes; current CMD observations are recorded below. Installed Assist and final-package qualification remain open.

## Current native Windows gates and CMD boundary

The prefix-corrected ARM64 Windows candidate passes11 focused,180 registry,
8 object,10 CLI and191 C API tests; all-target checking and the actual CLI
build pass. The whole library gate passes8092 tests, with zero failures,
two existing ignored tests and zero filtered tests, in991.78s of test execution.
The first CLI failure and exact unchanged successful retry remain separate evidence rather than being replaced by the later full10-test pass.

The current CLI has SHA256
`acb37a7b351b4ae5f437923578f7890639111db41eede415de483fa2b9a8a8d5`.
Unchanged installed ARM64 CMD has SHA256
`d0f47e2d32ab33e593e5b49592d3dcfa3c8c5f9f9b345d512ef7269bca6b481a`.
Native `/d /c "echo RAX_APPMODEL_SNAPSHOT"` exits0; emulation exits125 with
empty stdout at the next uncaptured `NtOpenKey`. A current-source inspector
linked to core archive SHA256
`3bef76cff4ff19ac892b292a2df897d94f03a2ea9694290306602464b2d8a9f1`
directly observes
`\Registry\Machine\SOFTWARE\Microsoft\AppModel\Lookaside\user`,
access0x80000100, attributes48bytes/root0/flags0x40, and name
Length120/Maximum122bytes. Its frozen Rust source has SHA256
`0572e7fc80b0b301fc8beb897e2e800d5131613d33c326a9fd1579a9e11d0788`;
compiler SHA256 is
`ea26a23a11ced22cd6ff064da71bf8f39fc07d0768343fb1e719a8268b49244d`
and inspector executable SHA256 is
`309ee73544d8cf4f130890f26772330e7d13f2fbaf450afd0f8cb3847fa992de`.
The inspector's own successful exit means diagnosis completed; its recorded
guest result is an internal unsupported-service failure. Selected source,
core archive, producer, inspector and CMD hashes remain unchanged after the
inspection.

Independent query-only controls on kernel10.0.29695 ARM64 return
STATUS_OBJECT_NAME_NOT_FOUND for both machine/user leaves with all four
native64 NT view masks. Explicit Win32 default/64/32 queries each return
ERROR_FILE_NOT_FOUND. All14 query outcomes are recorded and the process
handle count remains117 before/after. No root, value, override, privilege or
setting is changed. The sibling user root is the next implementation boundary;
this machine-root snapshot does not claim that root or complete CMD execution.
