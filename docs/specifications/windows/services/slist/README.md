# Windows SList, processor-feature, system-time and CRT handler references

These Microsoft pages were consulted for the interlocked singly linked list
functions (`InitializeSListHead`, `InterlockedPushEntrySList`,
`InterlockedPopEntrySList`, `InterlockedFlushSList`, `QueryDepthSList`,
`InterlockedPushListSListEx`, `RtlFirstEntrySList`), for
`IsProcessorFeaturePresent`, `GetSystemTimeAsFileTime` and
`RtlCaptureContext`, and for the CRT's `_callnewh`. They were retrieved on
2026-10-04 from the official MicrosoftDocs `sdk-api` repository at commit
`c12073e417d5780fe796278ada21b90cef1b0568` and `cpp-docs` at commit
`f2355df9f7136d8a2097193fc507882a7caeb5f5`. The raw Markdown pages are
retained byte-for-byte; their front matter includes Microsoft's titles and
`ms.date` fields. Canonical rendered pages and immutable raw URLs are recorded
in [sources.json](sources.json).

Microsoft documentation prose is licensed under Creative Commons Attribution
4.0 International; code samples are subject to each repository's MIT
`LICENSE-CODE`. The sdk-api notices are retained as
[SDK-API-LICENSE](SDK-API-LICENSE) and
[SDK-API-LICENSE-CODE](SDK-API-LICENSE-CODE) (the files kept beside the VCH
references), the cpp-docs notices as [CPP-DOCS-LICENSE](CPP-DOCS-LICENSE) and
[CPP-DOCS-LICENSE-CODE](CPP-DOCS-LICENSE-CODE).

## What the pages establish, and what they do not

- The SList pages specify the operations, the LIFO order, the depth query,
  `NULL` for an empty pop, that flushing returns the former first entry, and
  that entries and headers are `MEMORY_ALLOCATION_ALIGNMENT`-aligned (16 bytes
  on 64-bit Windows). They do not specify the header's bit layout, how the
  sequence number advances, or what a misaligned operation does.
- The header layout comes from the Windows SDK 10.0.26100 `winnt.h`
  (`SLIST_HEADER`): on x64 and ARM64 a 16-byte union whose low quadword holds
  `Depth:16` then `Sequence:48` and whose high quadword holds `Reserved:4`
  then `NextEntry:60` ("last 4 bits are always 0's"); on x86 an 8-byte header
  with `Next`, `Depth` and `CpuId`. The SDK header is Microsoft software under
  the SDK license and is not retained here; it was read from an xwin download
  outside the repository.
- RAX's policy where the sources are silent: `Sequence` increments on every
  change except a flush, x86 `CpuId` is written only by initialization, a
  misaligned 64-bit operation raises `STATUS_DATATYPE_MISALIGNMENT`, and every
  operation validates before it writes so a fault leaves the list unchanged.
  Built-in calls run inside one scheduler turn, so each operation is atomic
  with respect to the guest's other threads. Native equivalence of these
  choices is unknown.
- The `IsProcessorFeaturePresent` page lists the `PF_*` indices. Four indices
  RAX answers are not on it and come from the same `winnt.h`:
  `PF_ARM_NEON_INSTRUCTIONS_AVAILABLE` (19), `PF_RDRAND_INSTRUCTION_AVAILABLE`
  (28), `PF_RDTSCP_INSTRUCTION_AVAILABLE` (32) and
  `PF_RDPID_INSTRUCTION_AVAILABLE` (33). x86 answers are read from the guest
  vCPU's CPUID model; an index RAX cannot vouch for answers FALSE.
- `GetSystemTimeAsFileTime` returns 100-nanosecond intervals since
  1601-01-01 UTC; RAX samples the host's wall clock.
- KERNEL32's `RtlCaptureContext` is a forwarder to NTDLL on Windows; RAX
  forwards it the same way.
- `_callnewh` reports whether a new handler ran. `_set_new_handler` is not
  exported by RAX, so none can. `_seh_filter_exe` is not documented on Microsoft
  Learn; RAX returns `EXCEPTION_CONTINUE_SEARCH` because the CRT signal actions
  for exception classes cannot leave their defaults in this runtime.

Integrity check from the repository root:

```sh
jq -r '.sources[] | [.sha256, ("docs/specifications/windows/services/slist/" + .path)] | join("  ")' docs/specifications/windows/services/slist/sources.json | shasum -a 256 -c -
```
