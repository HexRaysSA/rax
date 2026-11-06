# Native thread suspend and resume

`NtSuspendThread` and `NtResumeThread` operate on guest thread objects and
the guest scheduler. No request opens or controls a host peer thread. The
current-thread pseudo handle, granted handle rights, optional previous-count
output, maximum count, and retained exited objects are covered by independent
native observations and raw x86, x64, and ARM64 guest service replays.

The native observer creates only its own threads in its own process and closes
them after restoring suspend counts. `observations-arm64-v1.json` contains 322
observations from Windows 11 ARM64, kernel 10.0.29698.0. Initial creation flags
0 and 1 establish the native starting counts; the guest replay seeds those
counts through the existing guest factory. This does not establish an
implementation of `NtCreateThreadEx`.

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
