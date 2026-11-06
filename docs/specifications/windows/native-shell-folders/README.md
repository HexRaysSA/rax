# Installed creator Shell Folders capture

The Windows installed-library path captures the fixed creator-SID subtree
`\Registry\User\<creator SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`.
The values supply installed profile paths to the guest Windows libraries. Capture
preserves the native value names, types and bytes; it does not substitute paths
from a separate runtime sysroot.

## Acquisition and replay

`src/user/windows/registry/installed/primary_hive.rs` adds this subject to primary
user acquisition. The shared capture machinery opens both registry views and
checks that they identify the same canonical key and access result before
traversing one physical subtree. Both logical views receive that immutable
capture, including ordered child metadata and original access grants.

The model accepts the logical creator-SID name and the captured primary-hive
canonical alias. It rejects a foreign SID, an unrelated canonical name,
incomplete metadata and inconsistent shared-view captures. The existing aggregate
startup limits also cover this subtree; adding the subject does not increase
those limits. Name-not-found and path-not-found remain distinct results, while
other acquisition errors fail the capture.

Retained primary-hive handles keep the selected routes after the owning registry
is dropped. Sibling paths remain unselected. Guest registry mutations and guest
handles are not forwarded to the host registry.

## Independent native observation

`native-oracle-v2.cs` directly uses Windows registry enumeration, `NtQueryKey`
and `NtQueryObject`; it does not use RAX's capture implementation. Compile and run
it on the Windows installation being measured. The observer requests exactly
56 bytes for `ObjectBasicInformation`. `native-oracle-v1.cs` is retained to
reproduce the initial oversized-buffer failure (`STATUS_INFO_LENGTH_MISMATCH`,
`0xC0000004`); use version 2 for the successful observation.

The observation recorded in `observations-v1.json` used an ARM64 process on
Windows kernel `10.0.29698.0`. Both `KEY_WOW64_64KEY` (`0x100`) and
`KEY_WOW64_32KEY` (`0x200`) opened the same canonical creator key, with
maximum access `0x000F003F`, no children, and 31 identical value names, types
and byte sequences. The last-write timestamp also matched. NTDLL hashes before
and after acquisition were identical. The observation records source and NTDLL
SHA-256 identities. It retains value lengths and digests while the local raw
receipt retains the creator SID and original data.

These are observations of the stated installation. Key presence, value count,
paths and grants remain native capture results, rather than constants assumed
for other installations.

## Primary references

Unmodified Microsoft Learn copies and retrieval metadata are under `primary/`:

- [Registry Keys Affected by Windows Installations That Include Windows on Windows](primary/shared-registry-keys.html):
  the `HKEY_CURRENT_USER\SOFTWARE` row is shared; descendants inherit their
  parent's behavior except where explicitly listed. The page also specifies
  the current-user link to `HKEY_USERS\[SID]`.
- [Accessing an Alternate Registry View](primary/alternate-registry-view.html):
  the two WOW64 registry view flags and their use when opening keys.
- [Source URLs, retrieval dates and checksums](primary/sources.json).

## Validation boundaries

Portable model tests cover raw values, both views, logical and canonical aliases,
retained-handle lifetime, unselected siblings, foreign subjects, incomplete
metadata, absence classes, inconsistent captures and the aggregate startup value
budget. The generic acquisition test also includes this shared subject and
checks one physical traversal without leaking a partial capture.

Windows-only tests compare isolated acquisition with a fresh native subtree and
verify selection through complete primary-user acquisition. The installed CMD
comparison separately uses the shipping `rax-user` executable and the actual
Windows DLLs. Cross-compilation and portable model tests alone do not establish
that those Windows-only tests ran. This capture does not implement thread or
process creation; those services require their own runtime validation.
