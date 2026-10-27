# AMD64 current-session WoW64 CSR bridge

The bridge uses the immutable selected CSR owner for captured AMD64 kernels
10.0.20348 and 10.0.26100. Its directory and port names come from the same
metadata as the selected shared section. The captured process session is
stored before guest execution, separately from the primary token session and
mutable guest PEB fields. Native and x86 identity pages must match it. Existing
ARM64 kernel 29695, session 0 behavior remains admitted under its prior gate.
Foreign machines, kernel mismatches, guest architecture changes, mismatched
sessions and retired connection or view identities remain unavailable.

The five x86 stdcall arguments, scalar byte count, installed leaf and its own
`RET 20` remain unchanged. Shared callers make no host CSR request. The bridge
owns its port peer, writable view, readonly selected section and both PEB
publication phases. Current-session selection changes no copy, guard, probe,
resource-retention or readonly-writeback policy. The existing 80-byte capture
bound and 4096-character directory bound remain in force.

Independent native [startup controls](https://github.com/HexRaysSA/rax/actions/runs/40578893965)
observe the unchanged original x86 fault executable through natural exit status
0 on both kernels. Both calls use `\Sessions\2\Windows`, server 1, an 8-byte
capture and session 2. The five-argument x86 stack frame and actual
return are retained without input or output substitution.

The [fresh/retry controls](https://github.com/HexRaysSA/rax/actions/runs/40580006317)
reuse frozen native producers. Each kernel contributes 31 cases and 38 returns.
`matrix-profiles-v1.json` retains complete raw reports, compiler/executed PE and
source identities, artifact digests and typed projections. `project-matrix-v1.py`
checks stdout digests, terminal state, counts, PE machines, memory extents and
source/output lifecycle proofs. Damaged-record tests cover missing returns,
invalid byte counts, PEB and mapping boundaries, foreign kernels/machines and
incomplete lifecycle records. No native status or pointer byte is replaced.

The replay seeds actual readable caller bytes and compares every recorded
buffer and Boolean result, unreadable/guard state, status, retained handles,
shared committed bytes and mapped region geometry. It follows the six specific
CSR fields rather than treating any native PEB change as a connection. Owned
peer coherence, selected readonly identity and reserved tails are checked by
the common publication assertions. Synthetic tests additionally cover session
0, 2, 7 and UINT32_MAX, independent token sessions, private identity mutations,
foreign kernels/machines and retired owners. Those synthetic session values
are model tests; native observations cover the captured session 2.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| WM1 | The measured AMD64 kernels retain the shared first/connected CSR contract. | All 62 cases and 76 returns agree with prior status, retained-handle and shared-commit observations; complete raw bytes remain available. | Shared bridge implementation. | Readonly and guarded inputs, Boolean faults, invalid roots, rejected lengths, retry publication and output bytes. | Replay the complete native corpus and run installed leaves; retain every mismatch. | Native controls and complete portable model replay confirmed; installed runtime qualification pending. |
| WM2 | Captured process session and selected CSR metadata identify one owner independently of guest/token mutations. | Independent native process/session/namespace controls and host snapshot ownership. | Current-session selection and native/x86 PEB identity. | Session 0 and maximum u32 fixtures, conflicting token session, spoofed private kernel and PEB session, retired views/ports. | Admission and lifetime tests, actual native leaf and unchanged startup fixture. | Confirmed by portable admission, session, owner and lifetime tests; native installed leaves pending. |
| WM3 | The bounded native identity page is sufficient for the original x86 program's CSR startup path. | Original child observations and the existing absence of a guest native 64-bit RTL instance. | Whole original emulation test. | Native 64-bit PEB heap/loader introspection and further CSR messages. | Run the unchanged original test and observers with their original budgets. | Retained; no full native 64-bit PEB equivalence claim. |

| Plane | Effect |
| --- | --- |
| Windows process/runtime | Captured process-session identity and measured AMD64 CSR selection; installed x86 leaf runs on both native host architectures. |
| macOS/Linux shared model | Identical Rust state machine, corpus replay, admission and lifetime semantics compile and run; no host Windows API is invoked. |
| Tool/UI/permission/transport | No schema, approval, UI, SDK, external IPC or host-directed operation change. |
| ABI/persistence/package | No public C layout, private Assist ABI, persisted format, optional feature, dependency pin or package-layout change. |
| Tests/evidence | Native raw corpus and projection checks; existing three-platform C API and Windows observation jobs are extended, with no new jobs. |

Native shared resources are 65536 writable bytes and a 1048576-byte readonly
reservation: 5 * 4096 = 20480 committed bytes plus 1028096 reserved bytes.
Thus the shared committed delta is 86016 bytes. Capture/copy work is O(B),
with B bounded by the capture limit; owned mapping work is O(V log V) for V
VM spans. Corpus projection and verification take O(N) time and space for N
raw output bytes. ABI, guest execution limits and the original source, binaries,
whole Rust test and assertions remain unchanged.

High impact, blocks full-goal completion: native kernel 20348 additionally
changes native PEB byte 0xE8 from 1 to 2 during connection. Repository layout
identifies that field as NumberOfHeaps. The existing native identity page has
no native 64-bit RTL heap or loader instance; its heap fields remain outside
this bridge's modeled contract. The full raw change is retained and tested by
the projector. It must not be mistaken for CSR pointer publication or hidden
by a claim of complete native PEB equivalence. Complete Linux/macOS/Windows
host-library-backed process emulation, broader CSR messages, packages and
installed Assist runtime qualification remain incomplete.


The existing two Windows observation jobs additionally build and execute the
installed pure x86 CSR leaf through RAX on both independent AMD64 kernels.
Their job wall-clock ceiling is 45 minutes to include Rust compilation; the
native producer deadlines, per-test execution budgets and original hardware-
fault fixture limits remain unchanged. No runner or matrix instance is added.


Candidate qualification (2026-10-27 UTC): macOS ARM64 and the Linux x86-64
container on an ARM64 host each pass 103 selected `csr` tests, 55 selected
`wow64` tests, all 191 C API semantic tests and all six projection tests. There
are zero failures or ignored cases in those selected final gates. The native
Windows ARM64 source frame has passed preflight and is compiling its own gates;
installed AMD64 leaf and unchanged whole original-fixture results remain pending.
No shipping or master-promotion claim follows from this candidate commit.

The retained first local attempt failed compilation because an extracted test
helper diagnostic still named its former local variable. The next run retained
10 passes and four new-fixture setup failures: synthetic PID 1234 violated the
existing multiple-of-four server-PID guard. Correcting that fixture to PID 1236
preserved the guard and every original assertion. The subsequent narrow run
passes 14 tests, including all 62 native cases and 76 returns, followed by the
complete selected platform gates above. Failed logs and their source identities
remain separate. Compiler errors do not qualify runtime behavior.
