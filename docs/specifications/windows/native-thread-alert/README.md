# Native thread-ID alerts (Windows 29704)

This directory records independent own-process `NtAlertThreadByThreadId` and
`NtWaitForAlertByThreadId` measurements on kernel 10.0.29704.0 with the exact
ARM64, AMD64 and WoW64 DLL identities in `provenance-v1.json`. The standalone
C++ probes link no emulator. Both complete naturally with exit status zero on
all three ABIs. Sources, compiler commands, image hashes and raw outputs are
retained for reproduction. The selected ABI/kernel observations, rather than
contradictory informal API descriptions, own this implementation profile.

`native-thread-alert-pair.cpp` captures 1,152 boundary rows per ABI: six
diagnostic Address values, zero/one/two pending self alerts, eight timeout
pointer protection/layout modes, and eight byte offsets. It also captures
exact/tagged current and owned worker IDs, process/zero IDs, a high-bit current
ID on native64, and an exited worker whose full handle remains open. The worker
performs eight polls before normal exit. A final row separates this latch from
ordinary `NtAlertThread`/`NtTestAlert` state.

`native-thread-alert-timing.cpp` captures 18 deadline rows and 32 finite blocked
worker waits per ABI. The deadline rows include prequeued NULL, signed extremes,
zero, past absolute time and short relative timeouts. The blocked matrix varies
Address, a relative or absolute 500 ms deadline and all four low CID tag values.
Only owned current/worker IDs and guaranteed-invalid forms are used. The first
128 installed entry bytes of each export are also retained; they bind ordinary
service leaves, including the measured WoW64 thunk metadata.

The resulting contract is:

- Address is not dereferenced or used as the wake key.
- A pending per-thread alert coalesces repeated sends and produces
  `STATUS_ALERTED` (`0x101`) once. A zero/expired wait without one produces
  `STATUS_TIMEOUT` (`0x102`).
- All eight timeout bytes are captured before consuming the latch, with no
  alignment restriction. Access faults preserve it. A reached guarded page is
  consumed and returns `STATUS_GUARD_PAGE_VIOLATION`. Read-only capture works.
- Native64 CID lookup ignores two low tag bits; invalid IDs return
  `STATUS_INVALID_CID`. WoW64 accepts exact IDs and returns success even for
  the measured invalid IDs. Its tagged IDs do not wake their untagged thread.
- Alerts sent before a wait remain pending; alerts sent to an owned blocked
  thread wake it. Retained exited owned thread IDs return success.
- Ordinary user alerts and queued user APCs are separate. This wait is
  nonalertable. LastError remains unchanged in the capture matrix.

RAX keys pending state by the exact guest thread object and clears it on
retirement. Native services and synthetic exports share the same implementation
and scheduler continuation. No guest request invokes these APIs on host
threads. External process/thread objects remain an explicit unsupported owner
boundary. The corpora describe this selected Windows build, not every Windows
release or arbitrary cross-process alert policy.

The Rust regression suite replays the boundary, identity/lifetime, deadline and
blocked-wait captures across all three guest ABIs on each native host. Separate
tests cover ordinary alert/APC independence, cancellation, object retirement,
reused IDs and exact raw-kernel return handling. Windows-only tests execute the
installed NTDLL leaves through their actual return instruction, including the
WoW64 two-argument `ret 8` stack adjustment. These focused checks do not by
themselves establish complete NativeXTA process initialization or shutdown.

## Extended thread-ID alerts

`NtAlertThreadByThreadIdEx` adds an optional SRW-lock pointer to the thread ID.
The retained PHNT declaration names that parameter; `extended-provenance-v1.json`
binds independent measurements on the selected Windows29704 kernel and exact
installed DLLs. The standalone probes link no emulator.

The extended captures contain2,880 pointer/lifetime/prequeued-alert rows,
72 confirmed blocked-wait rows, and36 rows with genuinely acquired shared or
exclusive SRW locks, distributed equally across ARM64, AMD64 and WoW64.
NULL, inaccessible, read-only, guarded, unaligned and cross-page hint addresses
produce the same delivery and status behavior. Guard bits and captured storage
remain unchanged. Acquired lock words remain intact; the API does not release
those locks in these observations. NULL, matching and unrelated hints do not
filter wakeup by the wait's Address value. Native64 CID masking and the WoW64
exact-ID/success behavior match the plain alert captures.

The blocked probe reads system process information, filters it to its own
process and thread, and requires ThreadState5 together with an atomic flag that
the logical wait has not returned. Its recorded kernel reason is37 on native64
and6 on WoW64. An earlier oracle that over-specified reason37 for every ABI
stopped before x86 alerts; those incomplete rows are excluded. The final probe
runs every ABI. Only owned threads are signaled.

RAX treats Lock as an opaque scheduler hint and shares the existing object-owned
alert channel and retirement policy. It does not probe the pointed-to memory,
acquire or release a lock, or fork guest alert policy by host operating system.
The new export is appended after the two existing thread-ID exports. Corpus
replays cover storage/guards, pending-state consumption and retained targets;
blocked and acquired-lock replays preserve the native observations. The
installed-leaf test additionally executes the two-argument NTDLL entry and its
actual return, including WoW64 stack cleanup. These observations do not claim
kernel-internal priority/autoboost equivalence or complete NativeXTA startup.
