# Native processor-information views

```text
python docs/specifications/windows/native-system-processor-information/test_projection.py
python docs/specifications/windows/native-system-processor-information/run-v1.py
```

The installed x86 exception fixture now requests
`NtWow64GetNativeSystemInformation(1, output, 12, NULL)` during startup. RAX
currently reports that service as unimplemented. This control observes the
native contract needed for that adapter, together with the ordinary system
query, compatibility record, native basic record and shared processor metadata.

The C++ observer calls Windows directly. Each query receives two private
8192-byte allocations. It records status, raised exception, output bytes,
return length and the output/return-length guard state before inspecting data.
The processor campaign covers classes 1 and 63, six lengths including
`ULONG_MAX`, and 16 pointer/protection/alias modes. Basic classes 0, 62 and 114
and four additional class-rejection controls complete 225 calls per API.
Live memory is bounded by these allocations; output is bounded to 512 KiB per
architecture by the driver. Runtime is O(number of calls).

The portable driver selects native AMD64 or ARM64 kernel identity through
`IsWow64Process2`. An AMD64 kernel runs x64 and x86 observers; an ARM64 kernel
also runs an x64 compatibility observer. Source, driver, compiler, helper and
pre/post executable hashes bind each capture. PE machine checks establish the
compiled ABI. Temporary builds stay inside the worktree and are removed after
each sample. The default output is a fresh
`target/native-system-processor-information-v1.json`; `--output` selects another
fresh path below `target`. Existing captures are preserved. `--environment`
accepts the existing private compiler-environment snapshot format.

The existing Windows exception-profile jobs run this control on Windows 2022
and 2025 and preserve its JSON artifact, including partial capture data if
validation fails. They add no new jobs. Console output uses individual JSON
lines so a long observation set does not depend on one oversized log line.

[The original build-29683 capture](local-29683-v1.json) contains 900 query rows
from three compiled ABIs on one ARM64 kernel. It binds the original local
controller and binaries. `run-v1.py` supplies a separately versioned portable
reproduction of the same frozen C++ source. Its initial observation is:

| Caller | Ordinary class 1: architecture / level / revision / feature bits | Native WoW64 class 1 |
| --- | --- | --- |
| ARM64 | `12 / 0 / 0 / 0xA0000000` | Export absent |
| x64 compatibility view | `9 / 21 / 0x0001 / 0xA0000000` | Export absent |
| x86 compatibility view | `0 / 15 / 0x040A / 0` | `12 / 0 / 0 / 0xA0000000` |

The measured machine has eight logical processors. The 12-byte processor
record contains four 16-bit fields followed by a 32-bit feature mask. Both
classes accept output lengths at least 12 bytes. Nonzero output lengths require
four-byte alignment and probe the entire supplied extent before the optional
four-byte return length and class-length handling. The 12-byte record is copied
after these probes. A 13-byte span crossing an inaccessible page fails even
though only 12 bytes would be returned. A bad return-length pointer leaves the
output untouched. A read-only guarded output returns the guard status and
consumes the reached guard; with two guarded destinations, only the first
visited guard is consumed. A zero-length query leaves the output guard armed.
The portable reproduction passes on all three local views, with unchanged
producer/compiler/executable hashes. Five projection checks pass on Windows,
macOS and Linux. Independent AMD64-kernel results remain pending.

The ordinary x86 classes 1 and 63 agree. The native class-63 record instead
reports architecture 5 (ARM) on this ARM64 kernel, including from the x64 view.
That legacy descriptor does not establish ARM32 executable availability.
Class 114 is rejected by the ordinary x86 query but returns the native 64-byte
basic record through the WoW64 native query. These observed class and view
differences require distinct handling.

Shared-data architecture is 12 in all three views. Compatibility
`GetNativeSystemInfo` reports architecture 9 in the x86 process and retains its
emulated level/revision. The x64 observer has an AMD64 PE machine but
`IsWow64Process2` reports process machine zero. Neither API value alone
identifies the executed instruction set or physical kernel.

The raw shared processor-feature page contains both native ARM and emulated
x86 capabilities. ARM64 `IsProcessorFeaturePresent` filters x86-only features;
the x86 API filters ARM-only features. The x64 view observes both sets. The
x86 API reports compare-exchange-128 availability even though its current
instruction mode is 32-bit. RAX's existing direct-CPU feature policy, shared
data initialization and native processor records therefore need a coordinated
runtime update. The private processor-mask bit names remain unresolved; the
capture preserves the mask independently from CPUID and PF indices.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| CP1 | Ordinary and native-WoW64 processor views require separate selection. | Native x86 record is ARM64; ordinary x86 is Intel; class 63 reports legacy ARM through native entries. | Adapter view selection. | Native ARM64, emulated x64/x86, independent AMD64 kernels. | Matching records across every view on a claimed equivalent profile. | Confirmed locally; AMD64 kernels pending. |
| CP2 | Advertised emulator values describe its virtual CPU and topology. | Existing guest CPUID and one-processor topology policy; captured host values differ. | Future CPU-level/revision/feature derivation. | Native ARM64 with x86 guest; CPU-state changes. | A reported capability contradicts its owning CPU or API view. | Retained; runtime implementation outstanding. |
| CP3 | Process-machine zero and processor descriptors are insufficient availability checks. | AMD64 PE reports process-machine zero; class 63 reports ARM on a current ARM64 kernel. | Capture identification and capability boundaries. | Hybrid/emulated callers and removed execution subsystems. | Independent kernel/executable evidence contradicts the inferred availability. | Confirmed distinction; no execution availability inferred. |

High impact, outstanding: the missing adapter and the existing shared/API
processor-view inconsistencies block full Windows qualification. The original
hardware-fault fixture, its assertions and execution budgets remain in place.
Medium impact, separate: the unchanged owned-child dispatcher control failed
on Windows 2022 in workflow 40263904511. The startup/resource steps passed on
both hosted kernels. Public C API 1.15.0 and production Rust/Cargo sources are
unchanged by this observation-only changeset.
