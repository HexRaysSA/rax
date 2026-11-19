# Installed certificate autoenrollment registry

On Windows 10.0.29708.1003 ARM64, installed `certutil -hashfile` opens
`Software\Microsoft\Cryptography\AutoEnrollment` relative to the machine hive
with query-value access and later with `KEY_READ`. It queries `Debug`, `RawHex`,
and `Unicode` as `KeyValuePartialInformation` with a 16-byte buffer. All three
queries return `STATUS_OBJECT_NAME_NOT_FOUND` on the observed installation.
Independent Win32 reads agree and native `NtQueryKey` identifies distinct
physical keys for the native and WOW32 views. The
[native observations](observed-29708.json) record the results.

Installed selection captures each root header and its values through a fixed
bounded, read-only capture. The two views keep their own data and access
profiles. A guest can look up the selected root by its logical name or the
explicit physical WOW32 spelling. Descendant key bodies and neighboring
Cryptography keys stay outside this selection. The captured header keeps
the root's native child metadata, including the one child observed in each
view on this installation.
