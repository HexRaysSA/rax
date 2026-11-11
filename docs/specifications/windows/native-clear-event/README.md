# Native event clear

`NtClearEvent(HANDLE)` resets an event without a previous-state destination.
Its declaration is retained in the [PHNT executive header](../native-wnf-query/primary/phnt-ntexapi.h)
and [upstream PHNT](https://github.com/winsiderss/phnt/blob/master/ntexapi.h).
The implementation shares the existing `NtResetEvent` object operation with
an absent previous-state pointer. Guest requests never call a host event API.

The selected Windows 10.0.29704.0 control has 278 rows per ABI, 834 total,
from independent ARM64, AMD64 and WoW64 executables with no emulator linked.
The source and raw outputs are retained here; `provenance-v2.json` binds the
compiler inputs, executable identities, natural native exits and exact
installed DLL identities before and after capture, including NativeXTA.

The cases cover manual/auto events and both initial states, explicit and
generic access grants, low handle tags, repeated calls, closed duplicates,
wrong owned object types, and own process/thread pseudo handles. Successful
calls clear state to zero; access failures preserve the original state.
Type checking precedes modify-access checking. LastError remains unchanged.
The service has one argument and no guest output-memory capture.

The first probe stopped at its auxiliary ObjectBasicInformation query before
any event row. Its 256-byte query was rejected; the exact status was not
recorded. The final probe uses 56 bytes and completes every ABI. The failed
capture contributes no qualification rows.

Portable regressions replay all retained rows, check unused guarded arguments
and preserve every earlier synthetic ordinal and trap address. The export is
appended after the existing thread-alert family. Windows-only coverage executes
the installed leaf through its actual return, including WoW64 `ret 4` cleanup.
The earlier thread-alert regression checks its own family so later append-only
families do not invalidate its ordering assertion.

This qualifies the event service on this measured profile. The separate CHPE
context-ownership work remains unfinished and is not part of this changeset.
