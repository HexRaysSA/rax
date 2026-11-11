# Native thread creation flags and hidden-state queries

These independent probes call installed Windows APIs on owned threads in the
current process. No emulator implementation is linked. The retained observations
use Windows 10.0.29704.0 on an ARM64 host; installed-library hashes, executable
hashes, output hashes, process creation identities and natural exit codes are in
`provenance-v1.json`.

## Initial kernel state

`native-create-flags-v2.cpp` creates suspended workers with every combination of
`CREATE_SUSPENDED` (0x1), `SKIP_THREAD_ATTACH` (0x2), `HIDE_FROM_DEBUGGER` (0x4),
and `SKIP_LOADER_INIT` (0x20). Each worker is terminated without being resumed.
All 24 creations succeed across ARM64, AMD64 and x86/WoW64 callers. Flag 0x2 sets
`SameTebFlags.SkipThreadAttach` (0x0008); flag 0x20 sets
`SameTebFlags.SkipLoaderInit` (0x4000). Both the 32-bit TEB and its native64
companion contain matching bits under WoW64. The offsets are 0xFCA and 0x17EE.
Class17 reports the hidden flag independently of TEB contents. Object attribute
0x200 still yields an ordinary user handle with no inherited handle flags.

The declarations are retained in the primary PHNT headers under
`../native-process-tls/phnt-ntpsapi.h` and
`../native-arm64ec-bridge/phnt-ntpebteb.h`. In particular, `LOADER_WORKER` is
0x10. The previously accepted creation bit0x8 is not assigned that name here.

Initial rows contain 24 hexadecimal integer fields after `case`, followed by
64-byte ordinary/companion TEB snapshots. The integers are index, creation flags,
creation status, handle, basic status, basic length, basic exit status, TEB,
read success, bytes read, read offset, hidden query status, hidden byte, hidden
length, handle-query success, handle flags, termination status, wait result,
exit-query success, exit code, close success, companion-read success,
companion bytes read, and companion base. Only the relevant flag bits are
compared when replaying TEB state; native addresses are not guest addresses.

## Hidden-state query boundary

`native-thread-hide-query-v2.cpp` records 768 queries per caller ABI, 2304 total.
The normalized rows match across all three ABIs. Cases cover live and terminated
owned threads, duplicate and tagged handles, query rights, pseudo handles,
lengths0/1/2/3/4/8/4096, null/unaligned pointers, output/return aliases,
read-only/no-access/guard pages and page boundaries. Every query returns a status
without escaping an exception. The exact accepted output length is one byte;
`THREAD_QUERY_INFORMATION` (0x40) is required, and limited query rights (0x800)
do not suffice. The hidden state survives thread termination.

Rows contain 15 hexadecimal integers followed by two64-byte hex snapshots:
index, creation flags, life phase, handle kind, length, output mode, return mode,
output displacement, return displacement, status, exception, output protections
0/1, return protections0/1, output snapshot and return snapshot. The source owns
mode definitions. ReturnLength is probed before length/handle validation. Output
alignment is checked for lengths of at least four bytes. The one-byte output
store rejects a read-only guard without consuming it on every ABI; the
ReturnLength probe consumes such a guard. The output store precedes the final
four-byte ReturnLength store, as demonstrated by alias cases.

## Resumed owned TLS fixture and evidence limits

`native-flags-tls-dll.cpp` plus `native-flags-tls-process-v2.cpp` independently
observe an owned DLL's callbacks and the worker's static TLS availability.
Each flag runs in a separate process. On ARM64, ordinary workers receive attach
and detach callbacks and a copied TLS template. Flag0x2 suppresses TLS allocation
and both notifications. Flag0x20 suppresses allocation and attach but still
receives detach when flag0x2 is absent. All five ARM64 processes exit naturally0.

On this ARM64 host the baseline AMD64 and WoW64 runs observe DllMain attach and
detach, but do not observe the custom TLS callbacks/template. Their0x2 workers
have no observed TLS vector or notifications. Resuming flags0x21/0x23/0x27 faults:
AMD64 exits0xC0000005; WoW64 exits0xC0000409. The fixture does not establish the
fault's instruction or cause. It does not prove a valid resumed cross-ISA
SkipLoaderInit lifecycle or ordinary static-TLS equivalence there. Kernel
creation, both TEB views, and the full hidden-query matrix remain independently
qualified for all three caller ABIs. Installed loaders own their execution after
the runtime supplies measured initial kernel state.

These are userland observations on one exact kernel/library set, not a claim
about debugger event delivery, external-process threads or every Windows build.

## Loader-lock contention

`native-loader-skip-lock.cpp` holds the parent thread's loader lock while
resuming an owned suspended worker. The parent waits500ms, captures whether
user entry was reached, releases the lock, then joins without a time limit.
The worker uses raw self `NtTerminateThread`, so detach does not introduce a
second loader-lock dependency. All16 observations complete naturally0 with
unchanged installed-library identities.

Ordinary and hidden-only workers do not reach user entry before unlock and
complete after it. `SKIP_THREAD_ATTACH` workers enter and terminate while the
parent still owns the lock on all three caller ABIs. All ARM64
`SKIP_LOADER_INIT` combinations also enter and terminate under that contention.
Cross-ISA `SKIP_LOADER_INIT` is deliberately excluded from this resumed probe
because the separate controls already establish native faults there. Positive
entry/termination while the foreign lock is held demonstrates the bypass; the
500ms absence observations alone are not a general timing guarantee.

After `case`, rows contain flags, lock status, lock disposition, create status,
resume status, previous suspend count, wait result while locked, entry marker
while locked, unlock status, final wait result, exit-query success, exit code
and close success. `0x102` is timeout; zero is successful wait completion.

## Initial process-attach gate

The statically imported DLL in `native-initial-gate-dll.cpp` creates and resumes
an owned worker from its initial `DLL_PROCESS_ATTACH`, waits500ms, then returns
to the loader. `native-initial-gate-process.cpp` joins and closes the worker
after executable entry. All7 native processes exit0, with unchanged libraries.
Both ordinary and SkipThreadAttach workers wait for initial process attachment
on ARM64, AMD64 and WoW64. The ARM64 SkipLoaderInit worker enters and terminates
before the DLL callback returns. Consequently the scheduler retains its initial
gate for SkipThreadAttach but permits SkipLoaderInit without marking the worker
attached before its startup code runs. Cross-ISA SkipLoaderInit remains outside
this resumed native probe for the previously documented fault reason.

Rows after `case` contain pointer bytes, flags, create status, resume status,
previous suspend count, callback-time wait result, callback-time entry marker,
post-entry wait result, exit-query success, exit code and close success.
