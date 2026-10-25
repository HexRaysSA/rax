# WoW64 context-alignment failure order

On the measured Windows 10.0.26100 x64 kernel, the WoW64
`NtRaiseException` conversion rejects a context address not divisible by four
with `STATUS_DATATYPE_MISALIGNMENT` (`0x80000002`). Record capture precedes
this check; a bad record still returns access violation when both pointers
are bad. The original 36-pointer matrix establishes the same order for
`FirstChance=FALSE` and `FirstChance=TRUE`. The readable-buffer matrix confirms
all tested second-chance alignment residues.

The model applies this measured correction only to an x86 guest with captured
native version 10.0.26100 and native machine `IMAGE_FILE_MACHINE_AMD64`
(`0x8664`). It reads that identity from the selected installation. A different
configured guest version does not select or suppress the correction. The
record is read first; a failing alignment check returns before any context
copy, CPU change or handler dispatch. Other measured kernel profiles retain
their existing behavior. This check has O(1) time and additional space.

The before-change regression returns a memory fault at address 1 instead of
the measured status. New tests cover unreadable and readable context residues,
both chance values, record-error priority, register preservation, contradictory
configured versions and the other measured profiles. Existing Boolean-low-byte
and explicit-context dispatch checks remain enabled. All five raise unit tests
pass on macOS, Linux and Windows. The three service-integration checks and
clock selections also pass (four clock checks per Unix host, six on Windows).
All 191 C API tests also pass on each of the three hosts.

The fresh `run-second-chance-v6.py` uses the unchanged versioned native
producer with strict expected statuses for the three original cases. It
selects one exact expectation by actual kernel and executable view, rejects
unqualified profiles, and preserves the original failed control versions.
Two profile-validation tests pass on macOS, Linux and Windows; nine native
local child controls pass. Hosted qualification follows publication.

| ID | Assumption | Basis | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|---|
| RA3 | Captured version and native machine identify the selected installation. | Native runtime selection and object-namespace snapshot. | Profile selection. | Set the configured guest version to a contradictory build and verify selection still follows captured identity. | Confirmed by the capture path and regression design |
| RA4 | The observed pre-copy alignment check also rejects readable first-chance misalignments. | Both chance values agree for every low invalid pointer; readable second-chance residues agree. | Returning the same alignment status before context capture for either chance value. | Repeat readable first-chance misalignments in a fresh owned native child. | Retained inference; not a separate native readable-first-chance result |

High impact: complete context reads, selected register groups, native64
alignment checks and partial-buffer failure order remain separate gaps.
The readable-buffer controls show that a complete legacy context is not
always required for second-chance termination. One WoW64 prefix probe exceeded
its 15 s deadline; its native result remains unknown. This correction does
not qualify those paths or complete native exception delivery. Public C API
1.15.0 and private Assist ABI275 remain unchanged.
