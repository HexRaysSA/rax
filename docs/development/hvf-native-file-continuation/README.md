# Native Intel checkpoint-file continuation controls

The [native consumer](../../../tools/hvf/intel_mmio_native_guest.rs) adds three
whole-file continuation cases to the previously qualified 149 controls. Cases
149-151 use 1, 2 and 4 CPUs. Each first boots the actual HVF VMM, starts its
secondary CPUs through INIT/SIPI and verifies two acknowledged IPIs per AP.

```text
source VMM -> two IPIs/AP -> save .rxc -> destroy VMM and kernel
                                |
                                v
                           load .rxc -> fresh VMM -> two more IPIs/AP
```

The observer places the [second-phase guest](phase2.S) at the stopped BSP's next
instruction before capture. It changes no PC or register after restoration.
The file must contain every native CPU record, shared state, physical RAM and
the complete online CPU set. After saving, the source VMM is destroyed and its
kernel is deleted. A newly loaded `SnapshotBundle` supplies the destination
configuration and all represented state; the source kernel must remain absent.
Every restored public CPU projection must match its saved counterpart before
entry. Guest execution must then change the completion marker and advance
every AP's interrupt counter from two to four. A CPU-0-only continuation cannot
satisfy those assertions for the multi-CPU cases.

| Case | CPUs | Required AP counters before/after restore |
|---|---|---|
| 149 | 1 | No AP; BSP must execute the new completion marker |
| 150 | 2 | `2 -> 4` |
| 151 | 4 | `2, 2, 2 -> 4, 4, 4` |

The 109-byte second-phase program was assembled by LLVM 23.0.0git and separately
decoded by NDISASM. It sends vector `0x41`, waits through bounded port-output
polls, and requests ACPI shutdown with a distinct marker. Its source and emitted
byte checksums are in [qualification.json](qualification.json). The precise LLVM
build revision is unknown; the recorded version and emitted bytes identify this
control. Each VM requests 134,217,728 bytes (128 MiB) of RAM through normal
configuration validation. Capture/load work and storage grow with the represented
RAM and CPU records; the guest has two interrupt rounds
and at most 1000 wait polls per round.

The actual 152-case consumer compiles, links, signs and passes strict signature
verification on Apple Silicon, with the non-debug/non-JIT HVF library profile.
The native workflow uses its separate debug/JIT-enabled library profile. All
31 Python tooling tests pass. These local checks execute zero native Intel
guests. Native run `42019439797` passed cases 0-148 but failed case 149 before fresh
VM creation: the observer had reduced RAM after validation to 64 MiB, below the
128 MiB configuration minimum. The corrected observer supplies 128 MiB to
`VmConfig::from_sources` and never mutates the validated memory size.
The [baseline result](native-fail-42019439797.json),
[panic](native-fail-42019439797.stderr),
[ordered observations](native-fail-42019439797.jsonl) and
[verified archive receipt](native-fail-42019439797-archive.json) preserve the
failure. A new 152-case native run is still required to qualify whole-file
continuation.

A failed post-save case leaves its generated `.rxc` file in the execution
artifact for diagnosis. A successful case removes that file. The temporary
source kernel is always owned by the observer and is removed on unwinding.

| ID | Assumption | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| F1 | The file carries the native CPU, controller, RAM and clock graph | Source-free continuation | Strict save/load admission, all CPU records, online set, deleted source VMM/kernel and identical restored CPU projections | Native execution pending |
| F3 | The source configuration meets the resume memory minimum | Configuration admission | The 64 MiB baseline was rejected; the observer now requests the 128 MiB minimum through validation | Falsified for baseline; corrected native run pending |
| F2 | Restored halted APs can accept and acknowledge fresh work | Multi-CPU continuation | New guest counters must advance from two to four on every AP, with a distinct completion marker | Native execution pending |

High-impact remaining gates include execution of these native cases, complete
KVM private state, remaining MMIO/control profiles and the wider A32-FP scope.
These programs do not qualify every in-flight I/O, timer, failure/rollback or
firmware-discovery partition. Medium impact: the hosted Intel runner is itself
a hypervisor guest; no bare-metal qualification follows.
