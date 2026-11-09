# Native processor power information

`NtPowerInformation` level11 (`ProcessorInformation`) returns six DWORD fields
per logical processor: `Number`, `MaxMhz`, `CurrentMhz`, `MhzLimit`,
`MaxIdleState` and `CurrentIdleState`. Clock fields retain MHz units.
The 24-byte record has no pointer-size-dependent fields.

The existing guest topology describes one processor in its PEB, system-basic,
group and NUMA queries. Installed-library mode samples the host's processor0
through a fixed read-only native query and publishes one record. The host
processor count controls only a bounded native scratch buffer; guest pointers,
classes and lengths never enter that call. Sampling occurs after guest argument
and destination checks. Changes to host frequency/idle state are sampled on
later valid calls, without retaining a host pointer or adding checkpoint state.
Built-in mode reports virtual processor0: x86 frequencies come from CPUID16;
the synthetic ARM64 profile has nominal 3GHz frequency. Neither virtual profile
models idle states. These virtual values do not claim physical host identity.

## Measured buffer contract

Independent native ARM64, translated AMD64 and x86 callers ran 755 cases each
on Windows `10.0.29698.0`. All three 102,776-byte output records contain identical
755-row case data; each retains its own machine header and image identity.
The measured host had two processors, with two 24-byte records. The retained
observation source records the native 3,200MHz values, not a hard-coded guest
frequency. Physical x64-host execution retains its separate evidence boundary.

* A nonnull input with nonzero size is read/probed before output. A null input
  ignores its size; a nonnull input of size zero is not accessed.
* A nonnull, nonempty output span is checked in full, with byte alignment,
  before the processor-array length check. Extra capacity can therefore fault
  even if the records themselves would fit.
* After those probes, nonempty input or an absent/zero-size output is invalid.
  A valid short output returns `STATUS_BUFFER_TOO_SMALL`.
* A cross-page output fault or guard publishes no partial record. A reached
  writable guard is consumed and returns `STATUS_GUARD_PAGE_VIOLATION`.
* Success publishes the records and leaves excess capacity, resource counts
  and Win32 last-error unchanged.

`observations-v1.json` deduplicates the identical case rows only after raw byte
equality is proved. Status/DOS-error and observed-byte palettes retain every
case outcome. Shared tests exercise the production buffer contract at the
native two-record count through all three argument ABIs. Separate actual guest
syscall tests check the modeled one-record count, byte alignment, tail canaries,
excess-capacity faults, continuation state and append-only exports. These two
scopes must not be conflated: the two-CPU native corpus is not a native capture
of a one-CPU machine. Native Windows also exercises real metadata acquisition.

The fixed host scratch is 64 records (1,536 bytes) for the documented processor
group bound. Service work is O(input pages + output pages + processor records);
no allocation scales with a guest-supplied buffer length. Other information
levels remain explicit unsupported requests, never host power-policy forwards.

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| A1 | The observed startup request is level11 with 24 output bytes. | Published-runtime register/stack postmortem and ARM64EC mapping. | Service selection. | Three native caller ABIs and actual handler dispatch. | Handler sees different arguments. | Retained until the new startup diagnostic runs. |
| A2 | The guest keeps one logical processor and maps native processor0. | Existing PEB, basic/group/NUMA contracts. | One 24-byte record. | Two-record native corpus and one-record dispatch checks. | A guest topology query reports a different count or native sample has a different Number. | Retained for qualification. |
| A3 | Native query11 buffer rules apply on another admitted kernel. | Stable public layout; private ordering is independently measured only here. | Other-kernel compatibility. | Corresponding native controls. | A native case changes probe order, status or publication. | Not established by the layout declaration alone. |

## Remaining scope

* **High:** Complete ordinary-process startup, child supervision and full current
  source native validation remain separate acceptance gates.
* **Medium:** Other native kernel/profile controls remain distinct from these
  ARM64-host captures; ABI translation does not establish physical x64 parity.

## Primary references

* [Microsoft CallNtPowerInformation](https://learn.microsoft.com/en-us/windows/win32/api/powerbase/nf-powerbase-callntpowerinformation).
* [Microsoft PROCESSOR_POWER_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/power/processor-power-information-str).
* [PHNT NtPowerInformation declaration](https://github.com/winsiderss/phnt/blob/master/ntpoapi.h).

Those declarations establish argument/layout contracts. Native captures establish
private probe ordering and failure publication.
