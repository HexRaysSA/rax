# Native Windows image extension owners

The later [reserved-tail qualification](../native-image-view-reserved-tail/README.md)
adds the trailing uncommitted owner pages observed on build29695. Executable
extension bytes, logical image size and complete allocation extent are separate.
Historical measurements below retain their original source and scope.

The controlled image-ownership contract is implemented and validated. This
semantic group does not establish successful ordinary Windows application execution.

The ordinary smoke and whoami observers first faulted at an unmapped fetch,
0x7ff82ff430c0. The preceding ARM64 B at KernelBase RVA 0x306030 targets
NTDLL base 0x7ff82fad0000 + declared image size 0x473000 + 0xc0. Native memory
at that address belongs to an executable image-extension page. The later cyclic
SEH diagnostic remains a separate observation; no SEH recovery is established.

Native owned-view controls distinguish the PE size, returned logical view size,
and total image allocation. Ordinary full views add an executable extension;
partial views do not. Native ARM64 large-page views omit the extension, while compatibility callers retain ordinary page geometry. NtProtectVirtualMemory rejects the
extension with STATUS_NOT_COMMITTED even though class 0 reports MEM_COMMIT.
Unmapping any address in the extension releases its image owner.

| Image | Declared image size / type-0 RVA | Extension bytes |
| --- | --- | --- |
| NTDLL | 0x473000 | 0x1000 |
| KernelBase | 0x6e6000 | 0x1000 |
| Kernel32 | 0x171000 | 0x1000 |

The native rebase flag changes guard thunks as well as ordinary PE base
relocations. Two concurrent alternate-base views normalize identically for all
three images. Relative to the ordinary template, the normalized rebase changes
32 bytes in NTDLL, 12 in KernelBase, and 8 in Kernel32. The implementation
captures that native transformation instead of synthesizing branch targets.

The initial selected NTDLL path and basic PE identity (machine, image size,
NT-header offset and timestamp) must match the immutable KnownDll template.
This is not a cryptographic disk-file equivalence check. That image must occupy
the same preferred-address contract as the immutable KnownDll image. An occupied
range is an explicit conflict.
Supplied images and installed images without extensions retain their existing
mapping policy. The image's logical size excludes the extension; one allocation
owns both and publishes their class-6/class-14 metadata together. Host signing
levels are not copied into guest trust state.

Primary declaration provenance remains in the preceding native-image-extension
specification's references/phnt-ntmmapi.h and references/sources.json. Private
API declaration names do not establish runtime ordering; the newly captured
native records establish the current build's observed behavior. Physical x64
kernel behavior and other Windows builds remain separate validation surfaces.

The native acquisition retains only private byte copies. It maps selected
section handles into independently owned current-process views, bounds every
copy with native metadata and VirtualQuery, and closes each view. Guest pointers
and arbitrary paths never enter the native mapping interface. Capture compares
two independently rebased templates before admitting their transformation.

Native evidence is bound by native-inputs.json. Full mapped Windows DLL bytes
stay in the task-owned capture cache; external-images.json records their
identities without redistributing them. Run the full check with
`python3 check-native.py --image-cache <capture-cache>`. Complete validation
results, source epochs, ordinary program outcomes and
quality-gate evidence are in `validation/` and `quality-gates.json`.


## Final validation and remaining runtime boundary

| Host | Full library passed/failed/ignored | Focus | C API | Windows integration |
| --- | --- | --- | --- | --- |
| macOS ARM64 | 7878/0/2 | 18 | 168 | 544; native-memory adapter excluded |
| Linux x86-64 container | 7872/0/2 | 18 | 168 | 544; native-memory adapter excluded |
| Windows ARM64 | 7309/5/2 | 20 | 168 | 4 native-memory cases; Unix corpus excluded |

All-target checks pass on all three hosts. The five Windows failures are the
unchanged four BZHI and one FP16 lowerer tests; exact names are checked. The two
ignored microkernel tests are retained. Full suites and shipping archives
describe frozen epoch5. Epoch6 changes only
one Windows test to handle older kernels without class14/IsWow64Process2 and
passed a fresh 20-case focus plus all-target compilation. All shipping Rust
inputs are identical. The Unix-only integration corpus registers zero cases on
Windows; its 544 cases are not claimed as native Windows execution.

Scoped Assist validation passed seven CTests and two protected-command scans on
macOS, and five C++ consumers on Linux and Windows. Each host's actual empty-feature
core and static carrier passed a complete archive member walk, with 342 selected
source/fixture identities. The nine relevant C++ inputs still match root commit
57cd6cc5d6ffd8c36f1948a1386b71d145e79139 after its provider migration. The frozen
Assist contract is ABI minor184; that current root is minor187. No claim of a
whole-current-root, GUI/plugin or package validation follows from this scope.

Source epochs record the initial private-helper compilation error and two old
absence assertions that had used NTDLL. The latter now use the EXE as an absent
image, while dedicated NTDLL controls verify actual extension presence. A first
native runner's single-step PowerShell array error is preserved separately.
The Windows-only leaf portability correction is separately bound as epoch6.
The Unix final driver's historical receipt filename is normalized only after
matching every actual command, log path and digest; raw receipts are retained.

The unchanged non-test observer now stops smoke at turn97964 and whoami at
turn98028, both at unimplemented `NtQuerySystemTime` (0x5a). These runs use the
selected NTDLL bootstrap, an earlier path than the preceding disk-image runs.
The smaller turn counts are not forward-progress measurements, and neither
application exits normally. Image ownership is demonstrated by the focused and
native-leaf controls; no ordinary-program success or SEH repair is inferred.

`check-native.py --image-cache <capture-cache>` verifies the native contract.
`check-validation.py` verifies the final source, selected tests, archive records
and incomplete ordinary outcomes. Six altered/incomplete native proof sets and
six altered/incomplete final-validation proof sets are rejected by the paired
stress checkers. The full process-userland goal remains incomplete.
