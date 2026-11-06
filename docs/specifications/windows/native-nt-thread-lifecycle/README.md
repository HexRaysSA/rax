# Native thread controls and creation

`NtSuspendThread` and `NtResumeThread` operate on guest thread objects and
the guest scheduler. No request opens or controls a host peer thread. The
current-thread pseudo handle, granted handle rights, optional previous-count
output, maximum count, and retained exited objects are covered by independent
native observations and raw x86, x64, and ARM64 guest service replays.

The native observer creates only its own threads in its own process and closes
them after restoring suspend counts. `observations-arm64-v1.json` contains 322
observations from Windows 11 ARM64, kernel 10.0.29698.0. Initial creation flags
0 and 1 establish the native starting counts; the guest replay seeds those
counts through the existing guest factory. That control corpus alone does not
establish an implementation of `NtCreateThreadEx`.

`thread-alignment-observations-v1.json` additionally records native ARM64 and
x86/WoW64 stores at accessible offsets 0, 1, 2, 3, 4, and 7. Each suspend
publishes zero and each following resume publishes one. Invalid pointer 1
instead produces `STATUS_ACCESS_VIOLATION` before handle visitation.

Native count-limit failure publishes zero. Resume of an exited thread succeeds
and publishes zero; suspend of that object returns
`STATUS_THREAD_IS_TERMINATING` and publishes zero. Handle/type/access failures
leave an accessible output sentinel unchanged. These are measured behavior of
the recorded kernel, rather than a claim about all Windows revisions.

The pinned primary declarations are in
[`phnt-ntpsapi.h`](../native-test-alert/primary/phnt-ntpsapi.h), revision
`53fbbdc5b5d2b08761db1c7b26bfa8c820924356`; its source URL, checksum and license
are retained in that directory's `sources.json` and `phnt-LICENSE`. PHNT is an
independent native API reference. Status constants also agree with the retained
Windows SDK `ntstatus.h`. Native corpus records identify kernel, NTDLL checksum,
observer source binding and raw receipt checksum.

Unfiltered owning suites, native Windows execution, and affected product builds
remain distinct qualification gates. Focused replay success is not full
process-emulation completion.

## Native thread creation

The raw `NtCreateThreadEx` service creates guest scheduler objects, stack/TEB
mappings, static TLS and the existing installed-loader startup context. It
does not call host thread creation with guest arguments. The admitted scope is
anonymous default-security creation in the current guest process, creation
flags 0/1 and the observed reserved bit 0x8, inherited handles, and optional
`PS_ATTRIBUTE_CLIENT_ID`/`PS_ATTRIBUTE_TEB_ADDRESS` outputs. Other known flag
bits, custom security, named threads, additional attributes and cross-process
creation remain explicit unsupported paths.

`native-create-thread-oracle-v2.cs` and
`create-thread-sizing-observations-v2.json` retain 18 observations per native
ARM64 and x86/WoW64 profile on kernel 10.0.29698.0. The process PE headers
independently supply reserve/commit defaults: 524,288/8,192 bytes on ARM64 and
262,144/8,192 bytes on WoW64. Zero arguments select those fields independently.
Commit is rounded up to 4,096 bytes. If that commitment is at least the
requested reservation, reserve is rounded up from commitment to 1,048,576
bytes; otherwise reserve is rounded up to 65,536 bytes. The 22 successful
zero-`ZeroBits` stack measurements are consumed directly by the allocation test.
Two further successful calls omit TEB outputs and do not measure stack sizes.
The retained Microsoft [Thread Stack Size](../services/thread-sync/thread-stack-size.md)
reference and its [source ledger](../services/thread-sync/sources.json) specify
the documented rounding policy.

`native-create-thread-validation-v4.cs` and
`create-thread-validation-observations-v4.json` retain 75 cases per native
ARM64 and WoW64 profile. The service replay checks 53 state-independent cases
for each of three guest ABIs, yielding 159 comparisons. It excludes 21
`ZeroBits` cases, which have a separate controlled-VM allocation test, and one
arbitrary handle whose native object type depends on the observer's handle
namespace. Guest x64 uses the native64 observations; this is not an independent
native AMD64-kernel measurement.

Native64 output probes and `ReturnLength` stores preserve sequential partial
publication. WoW64 structural OA/list conversion failures leave the handle
sentinel unchanged; subsequent kernel rejections publish the thunk's null
handle even when the attribute list is null. WoW64 ignores the incoming sizes
of the two admitted output attributes and publishes their normalized sizes.
A caller-copy fault can leave a stale, already-closed handle word. The V4
observer checks that word with `NtQueryObject`, independently reopens newly
owned threads, and resumes/joins/closes retained control handles. Its observation
does not distinguish a thread already terminating during rollback from a
thread resumed normally by that control. The guest completes deterministic
rollback while retaining the observed caller bytes; failure-side lifetime
timing equivalence remains unknown.

For the recorded image reserve, nonzero `ZeroBits` uses the placement ceiling
2^(32 - ZeroBits), including native64 callers. A controlled guest address
space with lower bound 65,536 bytes reproduces success for bits 1 through 12,
`STATUS_CONFLICTING_ADDRESSES` at 13, and `STATUS_INVALID_PARAMETER` at 14
through 21. This finite profile does not establish every nonzero value or
combined-invalid-input precedence on other kernels.

Complete owning-library runs, cross-platform builds and actual installed-DLL
thread execution remain required for this new creation path. Native process
creation is separate and remains incomplete.
