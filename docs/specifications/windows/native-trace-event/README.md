# Native no-registration trace events

`NtTraceEvent` supports the `ETW_NT_FLAGS_TRACE_EVENT_NOREG` mode (`0x700`)
inside the guest tracing namespace. The implementation captures guest arguments;
it does not forward guest addresses or events to a host tracing API.

The current guest kernel has no enabled tracing sessions. Its existing
`NtTraceControl` implementation retains dormant provider registrations and
notification state, and rejects controller operations it does not implement.
After successful no-registration argument capture, `NtTraceEvent` therefore
returns `STATUS_WMI_ALREADY_DISABLED` (`0xC0000302`). Native observations confirm
that registering a provider without enabling a session does not change this
result. `RtlNtStatusToDosError` converts it to `ERROR_WMI_ALREADY_DISABLED`
(`4212`, `0x1074`).

## Measured contract

The four parameters are `TraceHandle`, `Flags`, `FieldSize`, and `Fields`.
For no-registration mode, `TraceHandle` addresses a 16-byte provider GUID.

1. Dispatch on `Flags & 0xFF00`. The low byte and high word do not affect the
   measured no-registration result. Mode zero and modes `0xA00` through `0xFF00`
   return `STATUS_INVALID_PARAMETER`. WoW64 also rejects mode `0x900`.
2. A null provider returns `STATUS_INVALID_PARAMETER` before visiting fields.
3. Both provider and fields addresses must be aligned to 4 bytes. Alignment
   checks precede either data capture.
4. Read the complete 120-byte fields record, then the complete 16-byte GUID.
   `FieldSize` does not alter these reads, including when zero or `UINT32_MAX`.
5. Consume a reached guard page and return `STATUS_GUARD_PAGE_VIOLATION`.
   An earlier null/alignment/fields failure leaves an unreached provider guard
   unchanged. Inaccessible spans return `STATUS_ACCESS_VIOLATION`.
6. Return `STATUS_WMI_ALREADY_DISABLED`. Dormant validation does not visit
   nested descriptor pointers, write caller buffers, or create guest objects.

The fixed captures take O(1) time and O(1) auxiliary space, independent of
`FieldSize`. The synthetic export is appended after the existing families;
earlier ordinals and trap addresses remain unchanged. The implementation is
shared by Windows guest execution on Windows, macOS, and Linux hosts.

## Independent observations

[`native-oracle-v4.c`](native-oracle-v4.c) measures a private provider before
registration, after `EtwEventRegister` without an enabled session, and after
explicit `EtwEventUnregister`. It varies every mode byte, every flag bit,
provider/fields alignments, mutually invalid pointers, exact page boundaries,
guard effects, caller lengths, and malformed nested descriptors. Each call
also records the native RTL conversion and a checksum of the complete
131,072-byte fields buffer before and after the call.

[`observations-v4.json`](observations-v4.json) contains 2,337 observations per
caller ABI, 7,011 total. The native kernel is `10.0.29698.0`. Source, executable,
NTDLL, WoW64 NTDLL, and private receipt hashes bind the capture. ARM64 runs
natively; x64 and x86 run through Windows translation on that ARM64 machine.
This is not physical x64 execution evidence. Earlier oracle revisions and
the initial unregistered-provider capture remain available for reproduction.

The regression test replays 6,849 no-registration and invalid-mode observations,
including their RTL results, continuation state, retained objects, and guard
effects. The remaining 162 observations exercise recognized other modes; the
test requires an explicit unsupported result for these modes. It does not claim
their native semantics are implemented.

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| A1 | No guest controller has enabled a tracing session. | Existing `NtTraceControl` supports only functions 15, 27, and 30. | Disabled-session result after valid capture. | Native private registration and explicit unregistration. | A new guest controller enables a session; extend event delivery in that same change. | Confirmed for the current guest controller surface. |
| A2 | No-registration capture reads 120-byte fields and a 16-byte GUID with 4-byte alignment. | Independent captures across all three caller ABIs. | Read bounds, alignment and guard behavior. | Zero/maximum length; every alignment; aligned page crossings; conflicting faults. | A native capture on another supported kernel differs. | Confirmed on the identified kernel. |

## Remaining scope

* **High:** Enabled guest tracing sessions and delivery require their own
  controller/session implementation. No enabled-session success is inferred
  from a dormant result.
* **Medium:** Recognized modes other than `0x700` remain explicitly unsupported,
  except the independently measured WoW64 rejection of `0x900`.
* **High:** This API does not establish complete ordinary process execution or
  guest child-process supervision. Those remain separate acceptance gates.

## Primary references

* [PHNT `ntwmi.h`](https://github.com/winsiderss/phnt/blob/master/ntwmi.h):
  four-argument declaration, trace-type mask, and no-registration mode constant.
* [Microsoft MS-ERREF NTSTATUS values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55):
  `STATUS_WMI_ALREADY_DISABLED` is `0xC0000302`.
* [Microsoft system error codes](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--4000-5999-):
  `ERROR_WMI_ALREADY_DISABLED` is `4212`.

The independent native capture, rather than a header declaration, establishes
the validation order, fixed record size, flag handling, and RTL conversion.
