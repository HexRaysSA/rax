# Native current-session CSR startup connection observations

The unchanged AMD64 fault fixture in CI run40550812639/job122354686568 stops
at missing `NtConnectPort` after391 turns. Independent terminal observer2
retains the exact `\Sessions\2\Windows\ApiPort` name, eight arguments,
48-byte client view,24-byte server view and48-byte information buffer.
The current ARM64/session0 model implements a different measured
`NtSecureConnectPort` call with nine arguments and a required server SID.

`startup-v1.cpp` separately observes the two original exports in owned native
children. It restores the entry instruction before the call, records the
original arguments and reply, then restores the caller instruction. It never
rewrites arguments, result registers, protocol buffers or the child exit code.
A TLS-bearing child must exit naturally with41. An unused export may produce
zero calls; the pair must observe at least one connection. Entry/return counts,
statuses, raw pointer-width values and bounded byte dumps remain explicit.
Native control deadlines are120 s; at most15 calls can complete successfully.
The driver's150 s process bound is independent of the immutable emulation
fixture's60 s deadline,16384 turns and4096-instruction slices.

`metadata-v1.cpp` reads only its initialized process: the PEB, current session,
readonly CSR prefix and allocation-region geometry. It records64 bytes of the
`CsrGetProcessId` export without invoking it on an unqualified cohort. It does
not dereference another process's server pointers. The connection reply and
own-process section metadata are separate native observations; equality and
layout admission remain to be established from their actual outputs.

`run-v1.py` requires matching native64 Python, PE and kernel machines. Builds,
objects and compiler temporary files remain inside this worktree and are
removed on exit. Raw stdout/stderr is base64-encoded without newline rewriting;
compiler, executable, source, Python and installed NTDLL identities are checked
before/after use. The result is `target/native-session-csr-connect-v1.json`.
Only the existing two observation jobs gain a step and artifact upload.

The eight/nine argument declarations and view structures are recorded in the
primary [System Informer header](https://github.com/winsiderss/phnt/blob/53fbbdc5b5d2b08761db1c7b26bfa8c820924356/ntlpcapi.h).
Private layout claims require the native observations, not this declaration.
The existing original source, binaries, Rust test, assertions and budgets are
unchanged. No guest request is forwarded to a host port by the emulator; this
group adds native controls only and changes no shipping runtime, ISA or ABI.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| SC1 | An owned same-architecture child reaches the installed connection export before its entry point. | Existing ARM64 debug control; actual AMD64 guest request. | Independent original-call/reply capture. | Zero calls to one export, multiple calls, early child exception, changed entry bytes. | Require verified entry bytes, at least one captured connection across both exports, complete returns and natural child41. | Retained pending native capture. |
| SC2 | The initialized parent's readonly CSR metadata describes the same session protocol as its child. | Same primary session and installed NTDLL, separate current-session namespace controls. | Later process-owned server profile. | ASLR, changed section extents, different statics offsets, session0 versus nonzero. | Compare captured reply pointers/PID and independently read prefix/geometry; reject mismatches. | Retained; no new runtime admission claimed. |

High impact, blocking runtime extension: actual AMD64 reply fields and readonly
geometry remain unknown until these controls execute. Medium impact, separate:
WoW64 startup on an AMD64 kernel still requires its own original-call proof.
All three platforms remain in the full process-emulation objective.

Portable projection validation accepts the retained original ARM64 first-call2
log with a synthetic protocol-identification header, and rejects a failed
status, wrong argument count, missing entry and non41 child exit. This checks
projection integrity only; it does not substitute for new native execution.
The C++ observers and new cohort outputs remain unqualified until the existing
observation jobs execute this candidate.

The first native Windows2022 build retains its failed v1 source and artifact
from run40554175446: MSVC `/W4 /WX` rejects C4127 (constant condition) and C4505
(an unused inherited TLS inspection helper). No observer executed in that
failed build. `startup-v2.cpp` uses `if constexpr` and removes the unused helper;
`run-v2.py` preserves the warning policy, original-call semantics and source
identity checks, with a separate v2 output. V1 remains unchanged.
