# NUMA-node topology primary contracts

Retrieved2026-10-11.

Microsoft NUMA_NODE_RELATIONSHIP documentation (winnt.h, updated2024-11-19):
https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-numa_node_relationship
NodeNumber is DWORD; Reserved is18 bytes; GroupCount is WORD; one or more GROUP_AFFINITY records follow. GroupCount was introduced in Windows20H2; earlier values are0. This layout alone does not establish private NtQuerySystemInformationEx probe order or partial output publication.

Microsoft GetLogicalProcessorInformationEx documentation:
https://learn.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getlogicalprocessorinformationex
RelationNumaNodeEx input6 requests full affinity. Modern NUMA-node records can include affinities for several processor groups; the public API documents variable record sizes. The WoW64 affinity conversion folds high32(mask) into the 32-bit mask, so guest node0/group0/mask1 must remain consistent with the guest processor policy rather than copying host topology. Source declarations and independent private-query captures own exact NT status/probe/output contracts.

Pinned PHNT ntexapi.h at53fbbdc5b5d2b08761db1c7b26bfa8c820924356 (retained ../native-processor-features) declares class107 and comments the extended NUMA-node layout. Existing native-processor-groups captures already observe input6 producing output Relationship1, with48 native64 bytes and44 WoW64 bytes. New349-case/profile sweeps expand exact boundary and alias evidence. Current selected host isWindows11 ARM64 build10.0.29683.1000; compatibility/native-platform limits remain explicit. No production NUMA-node edit has been made yet.
