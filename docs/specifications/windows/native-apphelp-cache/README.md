# Installed compatibility-cache name lookup

[The executable process-cache profile](executable-process-29708-arm64.md) records
operation 11 for installed executable lookups on Windows ARM64 build 29708.

This group implements `NtApphelpCacheControl` operation 6 (`LookupCdb`) from an
immutable snapshot of the selected Windows installation's base
`AppPatch/sysmain.sdb`. Guest requests inspect guest memory and this catalog.
They do not call a host NT service, retain host pointers, or change the installed
cache. Other operation numbers stop explicitly.

The original ARM64 loader call reached service 0x4C at PC 0x180001500, with
`KERNELBASE.dll` as its counted name. Its native return was `STATUS_SUCCESS`.
The unchanged parent production observer stopped at that service after
2,111,498 turns. Advancing that observer and obtaining ordinary guest exits are
separate acceptance criteria; a successful lookup alone does not prove startup.

## Inputs and file format

Native runtime selection reads a regular file under the canonical selected
Windows root and canonical AppPatch directory. An escaping target is refused.
The read and parse are bounded to 67,108,864 bytes. This extends the existing
explicit installed-runtime input grant; general host filesystem access remains
independent. Replacement between canonicalization and open is not made atomic.

The parser accepts the measured version 3/minor 0 `sdbf` format. Every tag is
checked against its owning extent. Byte and odd-length binary payloads retain
their payload length and consume the following alignment byte; the next tag
starts on a 2-byte boundary. Padding is not required to be zero. A 17-byte
`TAG_TEXT` payload with pad 0xDB exposed the first implementation's missing
alignment rule. Full walks of both installed database files and three accepted
versus three rejected installed-API synthetic controls verify the correction.
The earlier undersized synthetic controls are retained separately and are not
counted as proof of byte-tag behavior.

Names use `TAG_NAME` 0x6001 in direct `TAG_EXE` 0x7007 records and flags use
0x4032. Nested matching-file flags are not promoted to executable flags.
String references are relative to the string-table tag's start, not its payload
and not an API-returned opaque `TAGID`. References must identify complete
0x8801 items with even-sized, terminated UTF-16 data. Duplicate name records
merge their flags with bitwise OR after folding through the selected installed
NLS upcase table. Unknown counted names produce 0.

Limits are 1,000,000 tags, 32 nested lists, 65,536 flagged records,
4,194,304 aggregate encoded name bytes, and 65,534 bytes per table name including
its terminator. Bounds violations fail selection. For B input bytes, S strings,
E flagged records and maximum L name units, work is
`O(B + E log(S) + E L log(E+1))`; storage is `O(B + E L)`.

## Guest packet and ordering

All offsets and sizes below are bytes. These measured build 29683 layouts differ
from the historical PHNT declaration; PHNT identifies operation 6 and its name,
while executable native observations own these offsets.

| Field | Native64 | WoW64 |
|---|---:|---:|
| Captured fixed extent |392|204|
| Name.Length |248|132|
| Name.MaximumLength |250|134|
| Name.Buffer |256|136|
| DriverStatus |368|192|
| ParamsOut |376|196|
| ParamsOutSize |384|200|

The complete fixed packet is read before validating inner fields; the packet
itself may be unaligned and need not be writable on Native64. Zero name length,
null name/output pointers, or an output size other than 4 return
`STATUS_INVALID_PARAMETER` before dereferencing the name or output. A name
length of 65,534 or 65,535 returns `STATUS_INTEGER_OVERFLOW` after these checks.
MaximumLength is ignored. Exactly Length name bytes are captured, without a
terminator read; complete UTF-16 units participate in counted comparison. Odd
lengths are accepted. A captured leading zero unit is invalid. Case folding
does not strip paths or embedded/trailing NUL units.

Name capture precedes output alignment and write probing. The output requires
4-byte alignment and exactly 4 writable bytes. The service publishes the actual
catalog flags; the tested `apphelp.dll` and `msvcrt.dll` values are 0x80, while
`KERNELBASE.dll` is 0. Name/output/packet overlap preserves this capture order.

WoW64 then writes only the captured DriverStatus and ParamsOutSize back, in that
order, including after a kernel error. A later copyback fault overrides the
kernel status while retaining a completed output write. Output aliasing
DriverStatus or ParamsOutSize is therefore overwritten by their captured
values. Other packet aliases retain their result writes. Reached guard pages
are consumed with the native error precedence recorded by the raw controls.

## Evidence and validation boundaries

The independent native inspector verifies 28 actual producer binaries, source and
stdout hashes, PE machine/LAA fields, recorded terminal exits and 1,874 native
calls. Of these, 1,316 are replayed through ARM64, x64 and WoW64 argument
transports: 548 buffer/ordering cases and 768 counted-name cases. The 167 distinct
flagged names match across all four native profiles and both actual file
catalogs. The corpus stores metadata, control sources and outputs; it contains
no installed Windows DLL or SDB image.

`native-apphelp-identities.json` is a post-run file inspection. Its physical
NTDLL/KERNEL32 identities match the preceding TLS controls. Four profiles on
one ARM64 Windows 11 build 29683 kernel do not prove a physical AMD64 kernel or
another Windows release. Installed service-leaf tests execute the actual host
and x86 NTDLL stubs and assert their caller cleanup and copyback behavior.

Final gate counts, owning-source scope, archive identities and the ordinary
startup result are recorded in `validation-summary.json`. Initial compilation, replay-harness padding/relocation failures and the
first installed-database parser failure are retained as excluded attempts.

The unchanged 3,000,000-turn observer now reaches `NtOpenSection` at turn
2,114,258. A separate read-only name trace identifies `\Windows\SharedSection`,
requested with `SECTION_MAP_READ`. The three ordinary CRT samples stop at this
same unsupported section namespace; `whoami.exe` retains its `NtTraceEvent`
boundary. No ordinary guest exit has been proved. The original 1,000,000-turn
observer still exhausts its budget and is retained separately from the
two-literal budget extension.

| Full library | Passed | Failed | Ignored |
|---|---:|---:|---:|
| macOS ARM64 |7,784|0|2|
| Linux amd64 container |7,778|0|2|
| Windows ARM64 |7,202|5|2|

The five Windows failures are the unchanged four BZHI lowerer cases and FP16
host-feature case. No new case is skipped. C API tests pass 168 per host;
all-target builds pass. Unix Windows-personality integration tests pass 544;
the separate memory executable selects 0 tests there. Windows selects 0 in the
user integration executable and passes 4 memory cases. The full Windows library
and final 148-test focused run include the installed-leaf and live 168-name
kernel comparator. Seven scoped macOS CTests, both protected-text checks and
five C++ consumers on each of Linux and Windows pass. Owning archives select
empty core features and bind 219 exact scoped Rust sources and 9 matching current
C++ consumer files; this does not prove a whole-current-root plugin or package.

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
|H1|Operation 6 is this loader continuation boundary|Original entry/return and unchanged production observer|Adapter selection|Different installed service numbering|Decode selected NTDLL and rerun original observer|Confirmed on this installation|
|H2|Original entry capture preserves the owned child's call|Original arguments/status preserved and natural exit 41|Native baseline|True return and restored breakpoint|Compare entry/return and complete child event log|Confirmed for original captures; controlled termination cases are separate|
|H3|The selected immutable base catalog describes this installation's tested lookup names|167 file/API/kernel matches per four profiles|Returned flags|Duplicate/case/unknown names and database replacement|Compare actual file catalog and native outputs again|Confirmed for tested base catalog; custom/updated cached state remains unverified|
|H4|Build 29683 packet/copyback rules apply to the selected profile|Raw native buffer, boundary, alias and guard controls|Guest memory semantics|RO packet and conflicting faults|Full raw status/byte/protection replay|Confirmed by recorded replay; other builds remain unverified|
|H5|Canonical input is not replaced before read-only open|Existing installed-runtime trust boundary|Containment|Reparse/symlink replacement race|Replace target between check and open|Retained; no atomic filesystem sandbox claim|
|H6|Conflicting duplicate name flags merge by OR|Captured duplicates have equal flags; synthetic tests cover the chosen merge policy|Unobserved conflicting duplicates|Distinct flag bits on one folded name|A controlled native cache disagrees with OR; no installed cache was changed for this probe|Retained; native equivalence for conflicting duplicates is unknown|

## Change-surface map

| Plane | Status and basis |
|---|---|
|Direct decode|Unaffected; existing admitted NTDLL service encodings|
|Direct execute|Unaffected; existing SVC/SYSCALL/WoW64 stop path|
|CPU state|Unaffected layout; existing status register/resume contract|
|Memory/MMU|Affected checked packet/name/output accesses and guard handling|
|SMIR lift|Unaffected; no instruction or graph change|
|SMIR IR|Unaffected; no new operation|
|SMIR interpreter|Unaffected; personality service dispatch owns behavior|
|Optimizer|Unaffected; no optimization policy change|
|Native lowering|Unaffected; no emitted opcode change|
|JIT runtime|Unaffected; no admission/helper ABI change|
|Backend|Unaffected; existing personality entry/return seam|
|Machine/device|Unaffected; no machine or device state|
|Oracle/analysis|Unaffected; no ISA discovery contract change|
|C ABI|Unaffected layout, version, enum values and ownership|
|Targets/platforms|Shared service/parser compile on all three hosts; native selection is Windows-only, as before; CAPI and owning embedding gates cover the selected sources|
|Tests/docs|Affected raw native replay, parser/file bounds, installed leaves and this evidence record|

## Bounded findings

|Impact|Finding and evidence|Blocks full goal?|
|---|---|---|
|High|Ordinary guest exits require a fresh full observer result; lookup success is insufficient|Yes until exits and remaining continuations are verified|
|High|Other Apphelp operations remain explicit unsupported operations|If reached by a required program|
|Medium|Custom SDBs and concurrent kernel-cache updates are not established by the two base-file matches|Broader equivalence remains unverified|
|Medium|No captured duplicate name has conflicting flag bits; OR equivalence is unverified for such a database|Broader duplicate semantics remain unverified|
|Medium|Physical AMD64 kernel, other Windows releases, whole current shared-root/plugin/GUI/package validation are outside the scoped gates|Broader parity/packaging claims remain unverified|
|Medium|Shared root history diverges around concurrent cluster work; no foreign commit has been replayed or merged|Root main-worktree reconciliation remains pending|

The full Linux/macOS/Windows objective remains active. This group does not
replace it with lookup compatibility alone.

## Primary references

The pinned [PHNT operation declaration](https://github.com/winsiderss/phnt/blob/53fbbdc5b5d2b08761db1c7b26bfa8c820924356/ntmisc.h)
identifies the service class. Microsoft's [database API documentation](https://learn.microsoft.com/en-us/windows/win32/devnotes/application-compatibility-database)
and [child iteration contract](https://learn.microsoft.com/en-us/windows/win32/devnotes/sdbgetnextchild)
describe the installed reader used by the controls. Raw installed-file and
native kernel observations above determine the measured private layout, flag
values and alignment behavior; historical declarations do not override them.
