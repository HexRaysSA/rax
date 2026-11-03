# Complete fixed NLS snapshot controls

These read-only native controls cover the installed
`HKLM\System\CurrentControlSet\Control\Nls` subtree on Windows 10.0.29698,
ARM64. Each of the ARM64, x64 PE, and x86 producers opens the same fixed root
in the default, 64-bit, and 32-bit SYSTEM views. Every view contains 16 keys,
584 values, 21,492 bytes of raw value names/data, and 4,990 bytes of immutable
`NtQueryKey` records. Ordered child names and FILETIMEs are retained separately.

Each producer records 33,000 query cases: minimum-header and full-record length
boundaries, odd UTF-16 name cuts, two output poisons, and aligned `ResultLength`
aliases within and after each record. The opposite-poison full records agree.
Classes 0, 1, 2, 3, 4, 5, 6, and 8 are immutable captured metadata; class 7 is
mutable per-key-body state and retains the separately qualified implementation.
The existing metadata guard and Unicode fixture corpora remain applicable.

The producer enumerates names and raw values with Win32 APIs, queries metadata
through `NtQueryKey`, checks the key's summary before/after capture, and closes
each parent before opening descendants. A warm traversal precedes the measured
traversal. Process handle tables are identical before/after: ARM64 51/51,
x64 PE 73/73, x86 88/88. The acquisition receipt records exact table entries,
source and executable hashes, build commands, and provider identity before/after.
The x64 PE uses ARM64 NTDLL on this host; this corpus does not qualify physical
AMD64 execution.

`records-v1.json` contains raw values, records, ordered children, logical paths,
and calibrated odd-name copy plans. `*-v1.jsonl.zst` preserves the complete
native output. The portable guest test replays all 99,000 cases through
`NtOpenKey`/`NtQueryKey` for the corresponding guest architecture, after dropping
the original registry snapshot. The Windows acquisition test independently
compares every selected key's raw records, values, and ordered children in all
three SYSTEM views.

Verify the committed frozen payloads from any platform:

```text
python3 docs/specifications/windows/native-query-key/nls-tree/verify-v1.py
```

For complete archive payload verification, add `--native-archive PATH`. The
original acquisition archive is 6,668,240 bytes, SHA-256
`714de11a095fde6b2408952d4d02f83bb007f08305e6452f72cadd94712c9992`.
It contains 83 independently checked payloads, including mapped provider files
and all build/measurement logs. `capture-v1.py` is the exact acquisition
controller used with the task-owned Windows MSVC build trees; its numbered
attempt is v3. Earlier attempts stopped at compilation/header ordering and
identity-schema verification, before any measured campaign, and remain in
private task evidence.

The runtime selects the whole fixed NLS subtree once and preserves required
CodePage presence, existing aggregate budgets, logical/canonical/MACHINE aliases,
and retained-key lifetime. It rejects overlapping legacy partial selections.
No guest-supplied root is forwarded to the host. These controls qualify this
measured subtree and query profile; whole Windows startup and the overall
Linux/macOS/Windows native-library objective require separate runtime evidence.
