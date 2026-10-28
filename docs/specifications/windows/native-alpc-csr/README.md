# Installed CSR USER connection exchange

This change admits the measured `NtAlpcSendWaitReceivePort` CSR USER
client-connect exchange in the existing installed Windows runtime profile.
The selected profile is Windows 10.0.29683, ARM64, session 0. It uses installed
NTDLL and USER metadata without a separately supplied sysroot. Generic ALPC,
other CSR operations, other Windows builds/sessions, and complete ordinary
process execution remain outside this semantic group. These are remaining
requirements of the full same-host userland objective, not platform exceptions.

The actual retained Assist Rust caller and `RaxProcess` C++ caller both pass the
new exchange. `smoke.exe` exits with status 0; installed `whoami.exe` subsequently
stops at `NtOpenKey: registry key outside selected runtime snapshot`. The C API
failure reason is 5, with an unused zero exit-code field: this is not a guest
exit. The current Assist ABI274 root and the retained ABI184 validation consumer
are separate source and build surfaces. C API version 1.14.0 is unchanged.

## Contract and primary evidence

The primary evidence is the native producer source, original compiler/run logs,
before/after image hashes, and execution receipts under [native](native).
[native-producers.json](native-producers.json) binds eleven accepted producers
and nine rejected controls. Four execution views (ARM64, x64, x86 WoW64, and
x86 WoW64 with large-address awareness) share one ARM64 Windows kernel. They
do not establish behavior on an independent physical x64 kernel.

The accepted observations include 480 private-port ALPC calls, 33 successful
USER queries, and 41 executed probe images. The debugger trace observes only
its owned ARM64 child: it restores entry/return instruction bytes and verifies
two matched calls and child exit status 41. Malformed-message matrices use
private ports. No guest ALPC request is forwarded to host CSRSS.

| Contract | Native source and observation |
| --- | --- |
| `CsrClientConnectToServer` fourth argument is scalar `ULONG` | CSR client-connect v4 through v7; v1 through v3 used the falsified historical pointer declaration |
| USER result is 584 bytes; trailing 440-byte canary is preserved | Two repeated queries per view in v4 through v7 |
| Reply bytes 8..88 match current `user32!gSharedInfo` | CSR client-connect v7, all four views |
| Read-only mapped USER data and reserved tail | CSR client-connect v5/v6: 2 MiB allocation, 8192 committed bytes; 32768-byte second allocation, all committed |
| Native request/reply is 88 bytes, with 48-byte data | CSR trace v1: API 0, DLL index 3, information length 584, flags `0x20000` |
| Shared capture is 628 bytes with one pointer | CSR trace v1: pointer-offset 72, payload at capture+40; related-buffer word at capture+8 cleared on reply |
| Receiver requires 4-byte alignment on every measured ABI | Private alignment v7: +2 rejected, +4 and +8 accepted |
| Handle type precedes access; `PORT_CONNECT` bit 1 precedes native flags/pointers | Private limits v9 and priority v12; SDK `PUBLIC_OBJECT_BASIC_INFORMATION` is 56 bytes |
| WoW64 reads caller `SIZE_T` before native handle/access checks | Combined faults in priority v6/v12 |
| WoW64 constructs the native total in 16 bits | Limits v9: `65535 + 40 = 65575`, truncated modulo 65536 to 39; native total below 40 returns `STATUS_INVALID_PARAMETER` |

Native private limit probes use a 512-byte legacy port. They establish access,
conversion, and failure ordering; they are not a positive oracle for a
952-byte maximum. The selected CSR connection independently advertises 952
bytes. Unmeasured ports, flags, attributes, timeouts, message schemas, or profiles
return explicit unsupported results.

## Ownership and algorithms

Before creating a guest process, the narrow installed-runtime adapter performs
a fixed current-process USER query. It snapshots the two bounded read-only
mapped allocations, including committed/reserved run state. The shared
representation validates eighteen typed pointer slots and preserves all opaque
scalar bytes. It does not scan for address-looking integers or relocate them.
The complete selected allocations are mapped at the captured addresses in the
guest's own address space; collisions fail admission.

The original captures contain `8192 + 32768 = 40960` committed bytes. Later
captures from the same frozen producer observe a 12288-byte handle-table prefix
in the same 2 MiB allocation, with the second 32768-byte view unchanged. The
prefix may grow in pages; it is not an ABI-sized field. The
[geometry contract](../native-csr-client-data-geometry/README.md) retains the
native receipts and bounds. At most `2097152 + 32768 = 2129920` bytes are
retained, while the owning VM still enforces its commitment budget. Validation and copy
cost is O(B + R), where B is that bounded byte extent and R is the number of
mapping runs. Space is O(B). Mapping both allocations is transactional. Reuse
requires the same `Arc` identity and matching current protection/commitment for
every run; the allocation's original protection alone is insufficient.

Each connection owns a virtual server address space, process/thread records,
and a 64 KiB shared backing with an identity token. A guest unmap/replacement
cannot redirect server writes. One private 4096-byte server capture page is
reused per peer. Message identifiers increase with checked overflow. The reply
contains a virtual server identity and opaque virtual cookie; the returned
capture address belongs to the server's private guest address space.

```text
fixed host USER query -> bounded immutable snapshots
                                  |
guest NTDLL -> kernel capture -> owned CSR peer -> guest-owned USER views
                                  |
                            shared reply bytes
```

## Assumption register

| ID | Assumption and basis | Dependent result | Stress test / falsification probe | Status |
| --- | --- | --- | --- | --- |
| A1 | The selected build/session has the measured fixed USER layout; current native queries and map observations agree | Installed profile admission | Change build/session, layout, typed pointer, run state, or correlation; adapter must refuse. Re-run native checker against changed input hashes | Retained, explicitly bounded |
| A2 | The two captured allocations provide the read-only metadata needed by this client-connect exchange | Typed guest snapshots | Reserved/foreign pointers, overlapping allocations, collision rollback, altered current protection, distinct same-byte `Arc`; five metadata tests and native proof mutations reject these cases | Confirmed for this exchange; mutable USER operations remain unknown |
| A3 | The private-port access/conversion observations apply to argument capture before this selected CSR dispatch | Access and capture order | Zero-grant ports with simultaneous bad flags/pointers; event type mismatch; WoW64 guard/length and 16-bit overflow; both independent red tests fail before the fix | Confirmed for measured cases; other operations remain unknown |
| A4 | Exercised consumers contain the frozen RAX source rather than stale artifacts | Three-host consumer result | 28357-input source ledger; 3918 owning inputs; Cargo artifact selection; full archive member walks; before/after hashes; final native audit and four independent retained copies | Confirmed for recorded consumers |

## Change-surface map

| Plane | Effect and evidence |
| --- | --- |
| Windows service dispatch | Eight-argument native ALPC entry, shared capture rules, typed CSR peer handler |
| Memory and object lifecycle | Unnamed read-only data views, current run/identity checks, owned server capture and process/thread records |
| Installed runtime | Narrow ARM64 adapter captures fixed USER metadata; no dynamic guest-directed host operation |
| Guest architectures | Capture/conversion failures replayed for ARM64, x64, and x86; positive installed CSR exchange remains the explicit ARM64 profile |
| Linux/macOS hosts | Shared model and replay tests compile/run; installed Windows capture remains behind the existing Windows adapter |
| Direct ISA, SMIR, optimizer, lowerers, JIT, backends, devices | Unchanged: this group changes Windows syscall services and namespace/memory data only; five existing native lowerer failures remain separately classified |
| Public C ABI, permissions, schemas, persistence, discovery, packaging | No public layouts, dependency pins, host-access policy, schemas, discovery names, package inputs, or defaults changed |
| Assist consumers | Retained ABI184 shipping Rust carrier, native C++ tests, macOS CLI/MCP and seven CTests; current ABI274 GUI/plugin/package behavior not established by these gates |
| Tests and documentation | Six ALPC tests, five client-data tests, native primary evidence, independent pre-fix reproduction, reproducible proof checkers |

## Validation and reproduction

| Host | Unfiltered library suite | C API | Windows integration | Additional gates |
| --- | --- | --- | --- | --- |
| macOS ARM64 | 8168 passed, 0 failed, 2 existing ignored | 183 passed | 544 passed | all targets; actual carrier, eight links, seven CTests |
| Linux x64 container | 8162 passed, 0 failed, 2 existing ignored | 183 passed | 544 passed | all targets; actual carrier and five C++ consumers |
| Windows ARM64 | 7634 passed, 5 existing failed, 2 existing ignored | 183 passed | 4 passed; other integration binary has zero tests under its native cfg | all targets; actual static carrier and five C++ consumers; ordinary Rust/C++ callers |

The five Windows failures are the four existing AArch64 BZHI flag-lowering tests
and the existing FP16 vector-lowering runtime test, named exactly in the native
receipt. Canonical Linux Clippy and Rustfmt 1.95 pass. Both Windows MSVC cross
checks pass using `cargo xwin` and the cached SDK. The initial plain-cross
attempt lacked SDK C headers; the initial native candidate1 link exhausted
disk space. Those setup failures are retained and do not constitute test runs.
Candidate1 was subsequently rejected on semantic grounds: both independent
pre-fix access/overflow tests fail (0 passed, 2 failed). Candidate2 passes.

Run from this repository:

```sh
python3 -B docs/specifications/windows/native-alpc-csr/check_native_evidence.py --source .
python3 -B docs/specifications/windows/native-alpc-csr/check_complete_gates.py
```

`--live-native` additionally hashes the original native inputs on Windows.
The source checker verifies every frozen input, not newly added documentation.
To reconstruct those inputs without the local development materialization,
check out the public baseline in `validation/alpc-final-compiled-overrides-v2.json`
and overlay its 44 individually hashed archive members. This avoids embedding
the earlier 39 MB development archive, which contained older published evidence.
Apply `alpc-prefixed-red-kernel-overrides-v2.tar.gz` over the final source to
reproduce the two failing pre-fix semantic tests. The red ledger excludes four
later raw V12 logs that were not compiler inputs in that run.

Original compiler transcripts remain local. `validation/public-projections.json`
declares exactly six publication projections: five Cargo logs retain only
compiler-artifact messages, and the private Assist build transcript is withheld.
Original and published byte lengths and SHA-256 identities are explicit.
All native evidence logs preserve their original bytes, including CRLF.

The native proof checker rejects six independently corrupted, rehashed evidence
sets: bypassed access, two consumed guards, wrong WoW64 overflow status, wrong
export correlation, readable reserved pages, and uncleared related-buffer word.
Every mutation is bracketed by positive checks and a fresh restored positive.

## Bounded findings and quality gates

| Impact | Finding / evidence | Blocking scope |
| --- | --- | --- |
| High | Ordinary `whoami.exe` next reaches an unselected registry key; both actual owning callers agree | Blocks full process execution; separate next semantic group |
| High | Positive CSR exchange remains one build/session/guest profile; mutable USER services and generic ALPC are not modeled | Blocks full same-host objective; no generalized support claim |
| Medium | Five native ARM64 lowerer failures and environment-sensitive existing RAX Windows CI assertions remain separately recorded | No new failure in this group; full CI acceptance remains open |
| Medium | Current Assist ABI274 whole-root GUI/plugin/packages are separate from retained ABI184 consumer evidence | No whole-current-root validation claim |
| Low | Private-port global handle counts fluctuate despite exact owned handle/page cleanup | Raw counts retained; global-count equality is not asserted as leak proof |

The group-level quality gates reconcile assumptions, capture source/consumer
requirements, verify byte-width arithmetic, preserve rejected evidence, bind
primary native provenance, and confine edits to the owned paths. Full-goal
acceptance remains open. No normativity judgment is required. The original
shared Assist checkout and unrelated host builds/configuration are untouched.
