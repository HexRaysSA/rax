# Original WoW64 CSR startup on independent AMD64 kernels

The unchanged original x64 fault fixture exits with status 0 in CI run
40570458704. The same whole test stops in x86 at
`NtWow64CsrClientConnectToServer`, after 415 turns at PC `0x140000`: the
current bridge requires the selected server and shared-section profile from
ARM64 kernel 29695, session 0. AMD64 x86 startup remains unqualified.

The native 64-bit observer derives from the frozen, 433-line `initial-v4.cpp`
control. Its five-argument x86 entry frame, `RET 20` check, breakpoint
restoration and natural original-child completion remain unchanged. This
version additionally records a bounded 256-byte directory window and both
native 64-bit and x86 CSR PEB fields before and after the call.
`ReadProcessMemory` bounds remote reads. The observer patches only the owned
child's entry and return instruction bytes; it does not rewrite API inputs,
results, buffers or fixture bytes. Natural child exit status 0 is required.
Original source, binaries, assertions and emulation budgets remain fixed.

The existing Windows 2022 and 2025 observation jobs compile and run the native
64-bit observer on AMD64 kernels 20348 and 26100. No job or runner is added.
Source, compiler, executed PE, Python, both installed NTDLLs and original child
identities must remain stable. Raw stdout is retained without status, pointer
or argument substitution. Build and temporary outputs stay within the source
worktree and are removed after termination. Non-Windows and non-AMD64 hosts
return explicit unavailable errors. This native observation is separate from
the shipping platform adapters.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| WA1 | The original AMD64 x86 startup call may use a current-session root and metadata different from ARM64, session 0. | Actual emulated failure and independent native session 2 namespace identity controls. | Future finite bridge admission. | Directory bytes, five argument values, native and x86 PEB publication and actual return. | Observe the unmodified native original child through natural exit; compare exact fields before implementing. | Confirmed on both kernels: the current-session root is \Sessions\2\Windows; no runtime admission change. |
| WA2 | The five-argument RET 20 observer can run on independent native 64-bit AMD64. | WOW64_CONTEXT and fixed NT/debug APIs; the predecessor was qualified on ARM64. | New native observation method. | Actual export bytes, original argument cleanup and all returns. | Strict leaf check, matched entry and return counts and natural exit status 0; failures remain explicit. | Confirmed by both complete native jobs and natural original-child exit status 0. |

All capture sizes and iteration bounds remain fixed: at most 64 calls,
1024 bytes per dump, 256 directory bytes, 2048 native PEB bytes, 1280 x86 PEB
bytes and 120 s of native observation. PE export enumeration visits at most
8192 names per discovered image. Work is linear in the enumerated exports and
debug events; per-event buffers have fixed bounds. The controller retains the
bounded observation output. High impact, non-blocking for this observation:
the complete WoW64 CSR protocol and full process-emulation objective remain
unqualified; these observations do not establish runtime or package support.


The independent jobs in [run 40578893965](https://github.com/HexRaysSA/rax/actions/runs/40578893965)
both succeeded. `startup-profiles-v1.json` preserves their complete raw reports,
artifact identities and projections. Both original child calls use
`\Sessions\2\Windows`, BASE server 1, an 8-byte buffer and session 2.
Native and x86 CSR fields start at zero; the local bases agree on return,
statics equal local base + `0x750`, and both views publish the same 64-bit
server base. The first buffer is unchanged, the Boolean becomes zero and the
owned child completes its original access violation and exits naturally with
status 0. These are observations of installed kernels 20348 and 26100.

`run-matrix-v1.py` next reuses the frozen `initial-v8.cpp`, `initial-v9.cpp`
and minimal `initial-child-v1.cpp` sources without editing them. It compiles
native AMD64 observers and a separate x86 diagnostic child, verifies actual PE
machines, then runs the 31 original fresh/retry cases and 38 API returns per
kernel. The cases cover invalid and guarded pointers, readonly buffers,
Boolean faults, lookup order, rejected sizes, case-sensitive roots and retries.
The frozen observer terminates only its owned diagnostic child with status 70
after matched return snapshots. That status denotes control completion; the
original child's natural exit proof remains separate. Raw statuses, handle and
mapping deltas, PEB changes and copybacks remain unmodified.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| WA3 | AMD64 fresh and connected calls retain the ARM64 copy, resource and fault-order contract. | The successful original call agrees on root-independent output and PEB publication; failure cases still require native evidence. | Any finite runtime bridge extension. | All 31 fresh/retry cases, 38 returns per kernel, guards, readonly data, bad roots and Boolean faults. | Compare complete native raw rows with the existing model and preserve every disagreement before implementation. | Retained pending matrix results. |

The matrix compiles three PEs and bounds each native child observation to the
unchanged 120 s deadline and 64-call limit. Controller compile waits are 120 s;
observation waits are 150 s. Work is linear in the fixed cases and bounded
handle, mapping and export enumerations; retained space is proportional to raw
output. Build outputs remain contained and are removed after termination.
Medium impact, non-blocking for observation: kernel 20348 also changes native
PEB byte `0xE8` from 1 to 2 during the successful call; kernel 26100 does not.
This side effect remains in the raw record and is not inferred to be a CSR
pointer or silently normalized. Its relevance to later runtime behavior is
unknown. No shipping adapter or full process-emulation completion is claimed.
