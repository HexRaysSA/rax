# Powered-off native checkpoint banks

The internal owner envelope version 4 records VM-wide power-off together with
one optional terminal native I/O record per CPU. This supplements the
[deferred direct-result records](../kvm-deferred-checkpoint/README.md).
Older internal owner versions are rejected. These records still do not enable
the complete public KVM checkpoint producer.

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
requirement. Complete rollback, physical RAM publication, private kernel timer
state and activation of the public producer remain separate required work.

Qualification is pending. Tests cover both codecs, all port/MMIO lengths,
selected output prefixes, malformed records, actual native REP output with
peer input/MMIO frontiers, source-free 1/2/4-CPU graphs in both controller
profiles, no callbacks after restoration, and active-import rejection.
