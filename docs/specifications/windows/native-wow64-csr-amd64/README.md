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
| WA1 | The original AMD64 x86 startup call may use a current-session root and metadata different from ARM64, session 0. | Actual emulated failure and independent native session 2 namespace identity controls. | Future finite bridge admission. | Directory bytes, five argument values, native and x86 PEB publication and actual return. | Observe the unmodified native original child through natural exit; compare exact fields before implementing. | Retained pending native observations; no runtime admission change. |
| WA2 | The five-argument RET 20 observer can run on independent native 64-bit AMD64. | WOW64_CONTEXT and fixed NT/debug APIs; the predecessor was qualified on ARM64. | New native observation method. | Actual export bytes, original argument cleanup and all returns. | Strict leaf check, matched entry and return counts and natural exit status 0; failures remain explicit. | Unconfirmed until both native jobs finish. |

All capture sizes and iteration bounds remain fixed: at most 64 calls,
1024 bytes per dump, 256 directory bytes, 2048 native PEB bytes, 1280 x86 PEB
bytes and 120 s of native observation. PE export enumeration visits at most
8192 names per discovered image. Work is linear in the enumerated exports and
debug events; per-event buffers have fixed bounds. The controller retains the
bounded observation output. High impact, non-blocking for this observation:
the complete WoW64 CSR protocol and full process-emulation objective remain
unqualified; these observations do not establish runtime or package support.
