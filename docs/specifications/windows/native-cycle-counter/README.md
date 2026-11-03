# Windows ARM64 user cycle counter

Windows guest CPUs bind a read-only source for `MRS Xt, PMCCNTR_EL0`
(`0xd53b9d00 | Rt`). Native ARM64 Windows uses the processor counter exposed
to the hosting Windows process. Other hosts use the emulated AArch64 core's
existing one-cycle-per-retired-instruction model, with a per-core zero origin
and modulo-2^64 arithmetic. These are cycle counts, not QPC ticks or wall time.

The binding runs in the existing MRS execution path, after instruction-entry
checks. It preserves ordinary destination handling (including X18 and XZR),
flags, exclusive reservations and instruction retirement. Fresh Windows
threads reapply the personality binding. Default OS-neutral CPUs, including
Linux and Darwin user CPUs, retain their existing EL0 access restrictions.
Other PMU reads and all PMU writes retain their existing restrictions.

The binding is trusted host execution policy. Reset and a fresh `enter_el0`
remove it. Machine checkpoints reject a bound CPU on capture and reject a
bound destination before restore mutation: that format does not represent a
process personality or its host callback. The format itself is unchanged.
Windows register-context operations use Windows CPU/thread construction,
not machine checkpoints.

Each read and its retained per-CPU metadata cost O(1) time and space. No guest
address, selector or value is forwarded to the native counter instruction.

## Sources and native observations

Microsoft's [ARM64 Windows ABI](https://learn.microsoft.com/en-us/cpp/build/arm64-windows-abi-conventions)
specifies user-readable, 64-bit PMCCNTR_EL0 and distinguishes it from QPC.
The [saved source](references/arm64-windows-abi-conventions.md),
[license](references/MicrosoftDocs-LICENSE.txt), and
[retrieval metadata](references/provenance.json) preserve that reference.
The page's use of `MSR` in its cycle-counter paragraph is a wording error:
the actual read instruction assembled by LLVM and executed by the control
is `MRS`, with word `0xd53b9d08` for X8.

[The C control](native-pmccntr-read-v1.c) and its
[native receipt](native-read-arm64-v1.json) record 16 permitted, nonzero reads
on Windows ARM64 build 29698 under Parallels. The producer alternates a
10 ms sleep with a fixed 100000-iteration busy loop, and independently records
QPC and calling-thread cycle counts. The QPC frequency was 24000000 Hz.
The three quantities have different units/ownership; none is substituted
for another by this implementation.

One PMCCNTR pair decreased after sleep. Processor identity and affinity were
not captured in that control, so migration is an unproved explanation. The
receipt proves neither a globally monotonic epoch nor a calibrated processor
frequency. Native ARM64 Windows execution retains the counter as exposed by
Windows, without smoothing or replacing its values.

`native-pmccntr-registers.cpp` is an additional all-destination control derived
from the existing CurrentEL producer. It restores each destination before
returning, checks the caller's TEB, and includes four privileged negative
controls. Its [ordinary-user native receipt](native-registers-arm64-v1.json)
records all 32 destinations and four denied privileged reads, with unchanged
instruction bytes and caller TEB, 36 allocations, 36 releases and no failures.
X18 receives the counter; the producer restores the caller's X18 before
returning. XZR discards the value. This does not grant other PMU registers.

The [native Rust receipt](native-rust-arm64-v1.json) records six passing cases
against the actual RAX release library, including a hardware bracket of the
interpreted read on one pinned processor. The
[build-source manifest](native-rust-build-source-v1.json) joins the producer,
actual regression source and executable hashes. Its captured wrapper's
absolute include path documents that historical build; it is not required
to run the in-tree tests. Both ordinary-user controls captured the same
installed NTDLL hash as the earlier read control. Their receipts do not
independently record the kernel version or establish behavior on other
Windows versions or processor implementations.

```sh
python3 -B docs/specifications/windows/native-cycle-counter/verify-evidence.py
cargo +1.95.0 test --locked --offline --no-default-features --lib cycle_counter -- --test-threads=1 --nocapture
```

## Validation boundary

The pre-fix portable regression run observed four failures and two passes:
valid reads, new-thread inheritance, retirement and an exclusive-load/read/
exclusive-store sequence failed; default-core and unrelated-register denial
passed. The new cases also cover full-width values, retirement wrap, XZR
sampling, breakpoint priority, reset and checkpoint ownership. The native
Windows test brackets the interpreted read with independent hardware reads
on a dedicated, temporarily pinned helper thread. The test runner's affinity,
including an unrestricted multi-group default, is unchanged.

The first post-fix compile found an exhaustive checkpoint-field pattern that
needed an explicit policy decision; that failed invocation is retained in
the task evidence. Subsequent macOS checks passed 18 counter regressions
(13 added cases and five existing cases), and all 244 C API tests. The actual
public Windows-CPU regression source passed six cases on native Windows
ARM64 and six on native Linux, with no ignored or filtered cases. The Windows
run uses the hardware source; Linux uses the virtual source. Workspace
all-target checks passed for macOS, Linux, Windows ARM64 and Windows x64.
The full macOS run has completed all 436 AArch64 CPU cases and all 1688
Windows cases without failure or omission. Its remaining, broader VM cases
are still in progress at this snapshot.

These results qualify the counter contract. They do not establish complete
installed Windows process startup. A separate ordinary-user CMD startup
attempt exits with host error 5 (`PermissionDenied`) during process
construction, before guest execution; the failing acquisition operation is
not yet identified. Class 63 reached during the original exception-reporting
path is not given a success stub here.
