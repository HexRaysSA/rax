# Completed native Intel checkpoint and MSR controls

[Run 42006230493](https://github.com/HexRaysSA/rax/actions/runs/42006230493)
completed all 130 ordered guest cases through the actual RAX Intel HVF backend.
The [result](native-pass-42006230493.json) and
[observations](native-pass-42006230493.jsonl) retain the source fingerprint,
executable checksum, host admission and per-case outcomes. The execution ZIP's
SHA-256 and all 18 downloaded files were independently checked against the
published artifact; [verification](native-pass-42006230493-archive.json) records
the artifact identity. The single workflow job retained the signed build before
guest entry and the execution observations afterward.

| Cases | Executed controls |
|---|---|
| 0-113 | RAM entry, scalar MMIO loads/stores/extensions, denied malformed replies |
| 114-117 | Guest PAT writes and reads |
| 118-121 | PAT readback after private CPU capture and restore into fresh native owners |
| 122-129 | Reserved-MSR reads/writes deliver guest #GP(0), preserving fault PC and operands |

The native private capture and continuation that failed in earlier runs now
complete. Constructor initialization retains the SDK's exception defaults, and
the producer still checks exact exception and mask policy. The result does not
come from weakening that admission. Native CPU records include the pending
deadline format, but the 130 programs do not arm a deadline timer.

The tested engine SHA-256 is
`81682891f1a3775815a2f860f64e4b7026ac5d51ad7df9341fa1a0327e2b8a87`;
the signed executable SHA-256 is
`84385c93e9adb9b1ccb0b70c5488e4f28ce33ab7c9c300345586201eb33ecdd1`.
The pinned candidate was built from workflow commit
`097c57f0bbb5401a7f5f1d663dec3d22906b98ea`. The engine identity matches the
complete 65-test SDK-owner qualification. The new 146-case consumer adds
[deadline and TSC programs](../hvf-tsc-deadline/implementation.md); those cases
require separate native execution.

| ID | Assumption | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| A1 | The artifact represents all registered native controls | Existing 130-case qualification | Verify exact ordered IDs 0-129, Boolean passes, successful guest result, host/source admission and archive digest | Confirmed |
| A2 | The corrected constructor permits private continuation | Exception-policy correction | Capture and restore into fresh native owners; retain exact producer-policy checks | Confirmed in four native PAT restoration cases |

High-impact scope limits: these programs do not establish native deadline/IRQ
delivery, complete multi-CPU VMM startup, all MMIO forms or the complete KVM
producer. The four parent audit findings remain open. Medium impact: the hosted
Intel runner reports itself as a hypervisor guest; no bare-metal result is
claimed.
