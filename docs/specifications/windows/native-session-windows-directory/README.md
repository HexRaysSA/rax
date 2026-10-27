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
| SW1 | The current-session path may identify the already captured Windows directory and CSR section. | Actual AMD64 startup request; existing fixed Windows/SharedSection acquisition. | Candidate alias selection design only. | Session0/nonzero, canonical names, case flags and DONT_REPARSE. | Compare pinned native handles and canonical query results for both names; reject a different identity. | Confirmed for ARM64 session0 only; nonzero AMD64 pending. |

High impact: native alias, canonical-name and reparse results remain unqualified.
This observation group changes no guest behavior, public API, ABI, permission
policy or shipping package. It adds no CI job. Full Linux/macOS/Windows process
userland support and AMD64 exception delivery remain incomplete.

The native ARM64 build29695/session0 control passes32 observations with equal
handle counts (110 before/after). Both qualified names compare equal to their
fixed references. Canonical names retain Windows/SharedSection under the root
Windows directory; qualified DONT_REPARSE opens return0xC000050B. This does not
qualify the nonzero-session AMD64 relationship. Eight integrity tests pass on macOS, Linux and native Windows; the actual
32-row native capture also passes the verifier.
