# Powered-off native checkpoint banks

The internal owner envelope version 4 records VM-wide power-off together with
one optional terminal native I/O record per CPU. This supplements the
[deferred direct-result records](../kvm-deferred-checkpoint/README.md).
Older internal owner versions are rejected. This envelope predates the
[public KVM checkpoint producer](../kvm-native-owner.md#public-vmm-checkpoint-records).

A power-off reply can acknowledge the first element of a native REP output
batch while later elements remain unserviced. Other CPUs may already own input
requests, input replies awaiting kernel completion, or unserviced MMIO writes.
The terminal record preserves their exact ownership without another callback.

| Transfer | Retained metadata |
|---|---|
| Port input | Port, element width, count, absent or complete reply |
| MMIO input | Address, width, absent or complete reply |
| Port output | Port, element width, count, complete payload, acknowledged byte prefix |
| MMIO output | Address, payload, zero or fully acknowledged byte prefix |

Each transfer is bounded to 65,536 bytes. Port element widths are 1/2/4 bytes;
native MMIO lengths are 1 through 8 bytes. Strict admission rejects noncanonical
fields, short replies, partial-element output prefixes, oversized requests,
unknown versions/kinds and oversized byte sequences. Healthy idle CPUs have no
terminal record. Sticky protocol failures and active device callbacks remain
ineligible for capture.

```text
native exit -> device power-off reply -> VM-wide entry fence
                                      -> retain acknowledged prefix and peers
                                      -> encode / destroy source / decode
                                      -> fresh native owner, still powered off
                                      -> Shutdown; no callback or native entry
```

Terminal records contain no pointer to a source run mapping. Restoring them
does not reconstruct a kernel userspace-I/O continuation. The restored
VM-wide power-off flag prevents every CPU from entering KVM or servicing the
retained request. Native CPUs separately retain whether a real KVM I/O exit
has been observed complete. Replacing terminal records, including replacing
them with an idle powered-off image, does not clear that native-instance marker.
An active import into such an unsettled owner requires fresh native VM/CPU
owners. A fresh destination that holds only restored logical records can
replace them with an active image: it has no old kernel completion to resume.
Only observed KVM_RUN completion clears the marker. Device acknowledgements
alone do not clear it. Idle powered-off owners that have never issued native
I/O can have their power-off flag replaced in either direction.

The native sequence control found that the earlier record-only guard admitted
an active import after a terminal-to-idle replacement. The following
immediate-exit KVM_RUN changed RIP from `0x1000` to `0x1001` and RAX from `0x21`
to zero in both controller profiles, without executing a guest instruction.
The separate native-instance marker blocks that sequence; the paired fresh
owner must retain its active register bank across immediate exit.

All record/profile checks and owned transfer construction precede native
setters. The raw installer retains its disposable-target or enclosing-rollback
requirement. The public producer coordinates rollback and physical RAM with
the terminal records. Private kernel timer fidelity remains a separate
requirement.

The owner-level tests cover both codecs, all port/MMIO lengths, selected
output prefixes, malformed records, actual native REP output with peer
input/MMIO frontiers, source-free 1/2/4-CPU graphs in both controller profiles,
no callbacks after restoration, and active-import rejection.

## Power-off accepted by the running VMM

The running VMM publishes the same KVM power-off latch when it accepts ACPI
S5, a native shutdown exit, or a system event that ends the run. It fences
all managed entries before acknowledging the accepted S5 element. A later
element or a peer's pending input can remain in the terminal I/O record.
Restoring the file into a fresh VM keeps those requests stopped. A subsequent
`Vmm::run` observes the latch before polling the console or selecting a CPU.

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| Ordinary VMM dispatch establishes the terminal frontier. | High | Run 1-, 2- and 4-vCPU KVM guests through a REP OUTSW S5 request. The next vCPU call must return `Shutdown`, even with a second output element ready. |
| A direct KVM shutdown fences peers that already acquired I/O. | High | Dispatch the shutdown of a CPU with no usable interrupt vector table while a second CPU has a pending UART read. Check that capture and detached restore leave the serial byte queued and both CPUs return `Shutdown`. |

On a physical Intel Xeon E5-1650 v3 running Linux 6.8.0-138-generic, the
baseline returned a second output to port `0x604`, with value `0x1234`,
after `Vmm::run` had returned. In the direct-shutdown control, checkpoint
settlement reported an ordinary completion at the stopped CPU.

Both regressions passed on the same host after the change. The 128 MiB
fixtures wrote `.rxc` files, destroyed their source VMs, and loaded the
files into fresh KVM owners. Every vCPU reported `Shutdown`, the UART byte
was still queued, and entering the restored VMM left its scheduling cursor
at the saved position. These tests use userspace interrupt-controller
ownership.
