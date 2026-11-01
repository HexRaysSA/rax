# Native ARM64 MMIO load retirement

A trapped scalar load now retains its faulting PC while its device input is
absent or incomplete. A complete reply writes the destination register and then
the absolute next PC. A setter failure retains the obtained input and the saved
PC, so retry neither reads the device again nor increments PC a second time.
An XZR/WZR destination still requires complete input and PC retirement.

Native private CPU records now use producer tag RAXHVA05 and store an optional
absolute retirement PC. RAXHVA04 records remain readable through an explicit
V4 schema: their PC was advanced at the original trap, so their imported pending
read has no additional retirement write. Their public projection, staged input,
saved error and other private fields are preserved. Unknown versions and
trailing or truncated payloads remain rejected within the existing byte limit.
A new deferred record admits the fault PC before input, or the absolute next PC
with obtained input after a setter may have mutated PC before returning error.
No public C layout or outer checkpoint version changes.

The trapped AArch64 instruction must be four bytes. Next PC is computed once as
(PC + 4) modulo 2^64. Data-abort reconstruction, scalar load value computation
and completion use O(1) time/storage (at most eight input bytes); context
serialization remains O(n) in its bounded encoded size.

The physical regression first observed PC=4 where PC=0 was required before
input. The initial corrected signed Apple M4 binary passed all 16 state cases,
including unchanged PC/registers after a seven-byte reply to an eight-byte load
and one retirement after full input. All 15 MMIO policy cases passed. Final
owning validation is recorded in [qualification.json](qualification.json).

Four small V4 wire fixtures (11,398 bytes total) were emitted by the retained
pre-fix producer and codec, with read, reply, error and terminal phases. They are
synthetic profile fixtures, not physical checkpoint captures. Their producer,
hashes and exact commands appear in qualification.json.

The native coordinator test helper also accepts None host turns while checking
selection and peer memory conservation. Native stores still use the existing
advance-before-dispatch convention; complete store acknowledgement retirement,
native streaming FPSR, general IRQ/clock/replay, complete checkpoint profiles and
physical Intel qualification remain open.

Primary contracts: retained Arm 2025-12
[shared pseudocode](../../specifications/arm/pauth/shared_pseudocode-2025-12.xml),
AArch64_DataAbort uses ThisInstrAddr as its preferred exception return, and
[Apple SDK hv_vcpu_types.h](../../specifications/apple/hypervisor-sdk-27.2/hv_vcpu_types.h)
defines native PC register identity. The specific ARM64 C SDK assertion and
synthetic setter-failure tests do not constitute physical SDK fault injection.

Register overlays and set_current_pc reject a changed PC before mutation while
a new deferred read is pending. Equal-PC overlays remain available. Explicit
set_state replacement cancels the transaction after successful publication;
legacy already-retired records retain their previous PC-overlay behavior.

Post-I/O WFI test payloads include a real branch at the expected park PC. WFI
can resume at the implementation boundary; falling into zero bytes is an
exception path, not a completed waiting test. Existing input/register/PC
assertions are retained.

Final complete owning root: 11548 passed, 34 ignored; C API225 passed.
Complete debug/no-debug state targets each passed16 cases, MMIO policy targets
each passed15. Workspace format/check/build/clippy passed. Complete native
checkpoint module:26 passed, one existing streaming-FPSR failure retained.
The corrected park fixtures preserve every input/register/PC assertion.
No full four-finding completion is claimed. Exact receipts and feature scopes
are in qualification.json.
