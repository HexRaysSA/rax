# SDK control-register write and readback probes

The earlier SDK observation from
[run 41954251789](https://github.com/HexRaysSA/rax/actions/runs/41954251789)
reported mandatory bits in the write masks for guest CR4 and the CR0/CR4
guest/host masks. The [primary SDK header](../../specifications/apple/hypervisor-sdk-27.2/hv_vmx.h)
defines a bit set in both returned masks as mandatory one. It says an
incompatible write may fail. That does not establish the effective value
after an accepted write.

The [probe](../../../tools/hvf/intel_vmcs_native.c) now records six ordered
write/readback operations on its unentered vCPU, after its existing field/MSR
observations. It destroys that vCPU and VM afterward. It executes no guest
instruction and does not modify RAX's CPU-transfer implementation.

| Probe | Write interface | VMCS field read back | Requested value |
|---|---|---|---|
| cr0-vmcs | VMCS | `0x6800` | `0x80010033` |
| cr4-vmcs | VMCS | `0x6804` | `0x220` |
| cr0-mask | VMCS | `0x6000` | `0x20` |
| cr4-mask | VMCS | `0x6002` | `0` |
| cr0-register | Register API | `0x6800` | `0x80010033` |
| cr4-register | Register API | `0x6804` | `0x220` |

The four CR0/CR4 probes also read the architectural register API. Each operation
retains its write status, raw VMCS read status/value, and register read
status/value where applicable. An API error is an observed result, not a
successful write. The wrapper requires the complete ordered probe inventory;
its success flag identifies a completed observation, without asserting that
the requested values were accepted or that a guest could enter.

The existing manual `native-intel-hvf-availability.yml` workflow collects this
probe. [Qualification](sdk-control-write-qualification.json) retains the earlier
mask records and the changed probe's compile/link/signature checks. The local
Apple Silicon negative control returned before VM creation, so it made none of
the six writes. Native write/readback results remain unknown.

| ID | Assumption | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| A1 | The earlier mask constraints apply to the current Intel SDK host | Candidate explanation for the first RAM-control failure | Capture current masks and compare both write interfaces with their readbacks; differing masks or normalization can disprove that explanation | Retained pending native measurement |

High impact: this is a constraint/normalization investigation, not proof of the
native failure's cause. The [first-frontier failure](README.md) remains open.
The added six operations take constant time/storage; the existing complete
probe remains linear in its field and MSR inventories.
