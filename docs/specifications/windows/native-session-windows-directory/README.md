# Current-session Windows directory selection

The unchanged AMD64 fault fixture in CI run40532335883/job122288239778 stops at
`NtOpenSection` for `\Sessions\2\Windows\SharedSection`, access4,
OBJ_CASE_INSENSITIVE and null root. The independent terminal observer retains
the complete 66-byte UTF-16 name and original register state. The process ends
with an explicit unselected-namespace failure; it does not reach exception
delivery. Original fixture bytes, assertions and execution budgets are unchanged.

`run-v2.py` measures only the current primary-token session's Windows directory
and shared section. It opens fixed paths, compares native object identities,
queries canonical names/types/grants, and records exact-case and altered-case
opens with flags0/0x40/0x1000/0x1040. Thirty-two rows retain native statuses,
including absent names. An unlike-type comparison is a negative control.
Owned handles close before the final handle-count check. Source, Python
executable/runtime DLL and NTDLL hashes are bound before and after execution;
PE machine and native process/kernel machine identities remain explicit.

The executed v1 source is retained unchanged. Its 128-byte basic-information
buffer was rejected. V2 uses the same 56-byte OBJECT_BASIC_INFORMATION contract
as the installed acquisition adapter and reports native status/extent on error.
`verify.py` checks complete matrix coverage, fixed session selection, raw UTF-16
versus rendered names, source/runtime identity and handle cleanup. Portable
tests reject altered projections and unknown source/ABI inputs. LF and CRLF
compiler/interpreter inputs are bound separately, without changing source text.

Run from the repository root on native Windows:

```text
python docs/specifications/windows/native-session-windows-directory/run-v2.py
python docs/specifications/windows/native-session-windows-directory/verify.py target/native-session-windows-directory-v2.json
```

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| SW1 | The current-session path may identify the already captured Windows directory and CSR section. | Actual AMD64 startup request; existing fixed Windows/SharedSection acquisition. | Candidate alias selection design only. | Session0/nonzero, canonical names, case flags and DONT_REPARSE. | Compare pinned native handles and canonical query results for both names; reject a different identity. | Falsified on AMD64 builds20348/26100: nonzero-session directories and sections are distinct. Session0 alias confirmed only for the recorded ARM64 cohort. |

High impact: these observations alone do not qualify guest acquisition or process startup.
This observation group changes no guest behavior, public API, ABI, permission
policy or shipping package. It adds no CI job. Full Linux/macOS/Windows process
userland support and AMD64 exception delivery remain incomplete.

The native ARM64 build29695/session0 control passes32 observations with equal
handle counts (110 before/after). Both qualified names compare equal to their
fixed references. Canonical names retain Windows/SharedSection under the root
Windows directory; qualified DONT_REPARSE opens return0xC000050B. This does not
qualify the nonzero-session AMD64 relationship. Eight integrity tests pass on macOS, Linux and native Windows; the actual
32-row native capture also passes the verifier.


## Separate current-session section implementation under validation

Both native AMD64 controls use primary-token session2. Their qualified Windows
folders and SharedSection objects compare different from the global references
(NtCompareObjects0xC00001AC). Qualified names remain canonical, and DONT_REPARSE
succeeds. The raw captures from builds20348 and26100 are retained beside the
ARM64 build29695/session0 capture; all96 open rows are replayed without rebasing.
The artifact identities and source/runtime hashes remain separate from model
execution proof.

Selection now includes the captured primary token's session parents and Windows
entry. A real directory is captured independently. A Windows symbolic link keeps
its captured link metadata and ordinary reparse semantics; fixed-target identity,
grants and refreshed link metadata must agree before it can resolve globally.
The global readonly CSR section remains selected. A distinct current-session
section is acquired separately, with its own canonical name, grants, bytes and
handle/view identity. Only the process's current section is considered for
initialized CSR client metadata. The existing ARM64/session0 CSR bridge profile
is unchanged; other connection profiles remain unqualified.

Host acquisition uses fixed primary-session paths before guest execution. No
guest name, PEB session field, pointer or rights request enters a host open/map.
Each immutable section keeps the existing64 MiB virtual-size and16 MiB committed-
byte bounds, with at most two section captures. Directory selection retains at
most ten handles. Namespace construction remains O(E log E + U) for E entries
and U UTF-16 units; section copying costs O(B) time/storage for B retained bytes.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| SW2 | The current section can be captured through the existing bounded readonly mapping contract. | Native successful read-only opens, fixed-name/canonical identity controls and existing global capture adapter. | Process-owned separate session snapshot. | Session0 link, nonzero distinct directory, changed grants/bytes, inaccessible or oversized mappings. | Native acquisition, region/identity checks, installed Native64/WoW64 leaves and the unchanged complete fault fixture. | Confirmed for the clean ARM64/session0 model and native AMD64/session2 installed leaves; full ordinary-process coverage remains incomplete. |

The initial shared macOS model passed44 namespace tests and7 selected section-open tests, including the existing access/fault/duplicate corpora. Final combined-candidate results follow below. These results do not
qualify native AMD64 startup, a new CSR connection profile, linked Assist shipping
artifacts or the full host-library-backed process objective.


Final combined-candidate gates pass44 namespace tests and7 section-open tests
on both macOS and Linux, plus all191 C API tests per host. Native ARM64 Windows
passes46 namespace tests,9 section-open tests including installed ARM64/WoW64
leaves, and all191 C API tests. The unchanged original hardware-fault fixture
separately passes1 test across ARM64/x86 with its original assertions and
60 s/16384-turn/4096-instruction budgets. These selected gates have zero failures
or ignored cases. The candidate includes the separate native-entry feature;
clean master publication qualification excludes that feature. Native AMD64 acquisition and installed Native64/WoW64 session-section leaves also pass in CI run40546497102. The unchanged AMD64 full fixture advances past the original section failure and stops at unimplemented NtConnectPort (0xA2); native exception delivery there remains unqualified.


Clean master-publication gates exclude the separate exception-entry feature.
They pass44 namespace,7 section-open and191 C API tests on macOS and Linux,
and46 namespace,9 section-open and191 C API tests on native ARM64 Windows.
All selected gates have zero failures or ignored cases. No public C API,
ABI version, dependency/default feature or package layout changes. This is
current-session namespace support, not complete ordinary-process qualification
or an expansion of the existing ARM64/session0 CSR connection profile.
