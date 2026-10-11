# NUMA processor map planning record

Baseline: RAX da90b59312b971e3b0d06862eb41a335771516e2 and root fe3155bb1446b067dcacf10b1c8834db929c083c, both worktrees clean. Prospective owned paths in owned-paths.json. Before editing, inspect each modified path and preserve concurrent content.

Acceptance: implement NtQuerySystemInformation class55 with one guest NUMA node/processor/group consistent with current topology; use independently pinned PHNT layouts and selected native buffer ordering; reproduce lengths, nulls, alignment, output/ReturnLength faults, aliases, field/page boundaries, guards and upper user range for all guest ABIs; meaningful portable plus installed-leaf coverage; three-host library/CAPI/all-target/integration and owning consumer gates; fresh byte-identical owning continuation and ordinary probes; evidence replay/rejection gates; publish exact owned paths using red, then root Gitlink/two records to both remotes. No host topology/VA/kernel forwarding.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| A1 |Guest has one NUMA node and one processor/group |Existing one-CPU PEB/basic/group model and configured VM NUMA node0 |Guest highest node0/mask1/group0 |All guest ABIs and native consumers |Find a conflicting guest NUMA contract |retained pending trace |
| A2 |Selected native class55 contract applies to current installed runtime |Fresh unchanged NTDLL identities; native probe in progress |Fault/store/length semantics |Null, oversize, aliases, guards, exact boundaries |Native observation disagrees |retained pending capture |
| A3 |PHNT structure extent is architecture dependent |Pinned MAXIMUM_NODE_COUNT and GROUP_AFFINITY/Pad union |Explicit width/layout sizing |x86 versus native64 plus conversion |Native returned lengths/fields disagree |retained pending capture |
| A4 |Private startup diagnostic measures kernel-query continuation only |It clears PEB heap and manually invokes LdrInitializeThunk |Limit on progression claim |Ordinary native programs |Ordinary programs complete independently |confirmed limitation |

Change surface: Windows guest query dispatch/shared model and registered tests affected; compiled on macOS/Linux/Windows. Owning Assist/RAX archives and C++ consumers, root Gitlink and engineering records affected. Plugin lifecycle/UI/conversation/agent backend/prompt/tool schema/permission/main-thread dispatch/Mesh/MCP/transport/crypto/persistence/SDK public ABI/optional engines/update/package metadata unchanged if source inspection confirms no class55 consumers. No new service name/capability/host forwarding or ISA/default change.

Bounded findings: high - production native Ldr/heap/CRT startup and ordinary programs still fail; blocks full goal. Medium - retained Linux timer and five Windows lowering failures constrain broad validation; physical native x64 kernel proof absent from translated/compatibility environments. Class55 captures and portable tests must resolve the query-specific unknowns before implementation. QG1 no normative content; QG2 register; QG3-6 pending final acceptance/native/source/artifact checks; QG7 scope recorded.

A3 revised to distinguish declaration size from query return extent: PHNT full declared structs are264/1032 bytes, but the selected native kernel returns4 bytes for L4..23 and24 bytes for L>=24 on the one-node host, preserving Reserved. WoW64 passes the original output/length to native query with a private ReturnLength, converts16-byte affinity records in place into12-byte records, preserves the leftover native tail, and publishes min(nativeReturned,8+12*count) only after success (4 or20 here). DLL/PDB class55 caseRVA0x1A3A4 directly confirms all arithmetic. Guest node0/group0/mask1 output uses this shape; does not expose host mask0xFF. ULONG_MAX output guards are consumed before later extent failure on all caller profiles, without temporary allocation. Native64 user upper-range checks remain distinct from WoW64's widened original-address native probes.

Additional high-impact production-bootstrap evidence, no adjacent mutation: process/start.rs publishes the HLE process heap into PEB.ProcessHeap even in native-library mode. heap.rs::Heaps::create reserves a placeholder first0x100-byte header and keeps allocator metadata in host Rust maps rather than constructing a native RTL heap. process/lifecycle.rs::start invokes host-managed DLL/TLS notifications and the executable through synthetic RtlUserThreadStart; it does not enter installed LdrInitializeThunk. Whether this exact path owns the observed ordinary first fault is unknown until the prepared unmodified production trace runs against the fresh owning core. This blocks the full goal and belongs to the next semantic group, not a speculative change to class55.


Final production observation revises the previous unknown: the first ordinary
exception occurs at1459, saved PC0x180026528/SP0xABF9C0, with X19 equal to the
published0x10000 HLE heap handle and X8=0x80006 loaded from handle+312. The next
LDR W9,[X8,#8] faults at0x8000E; terminal1500 is STATUS_ACCESS_VIOLATION.
The exact internal NTDLL routine remains unknown. Class55 private continuation
succeeds at33566 and reaches class107/relationship6 at40500, a6934 scheduler-call
delta. All22 recorded gates and current native paired archive walks are final.
QG1-7 pass for this bounded query group with the documented full-goal blockers;
no assertion of complete native startup, universal suite success or native x64
kernel proof is made. README.md contains the final acceptance/register/matrix.
