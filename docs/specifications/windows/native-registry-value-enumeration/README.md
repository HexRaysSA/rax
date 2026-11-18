# Installed Windows registry value enumeration

`NtEnumerateValueKey` reads immutable guest-owned registry values acquired
from the fixed `HKLM\SYSTEM\CurrentControlSet\Control\MUI` subtree. Both guest
registry views use the shared SYSTEM snapshot. The bounded capture keeps
native value ordinals independently from folded-name lookup. It opens no
additional host paths during a guest call.

The selected information classes are Basic (0), Full (1), and Partial (2).
The entry checks the class, query access, nonempty output alignment, and the
mandatory result-length destination, in that order. A missing ordinal
returns `STATUS_NO_MORE_ENTRIES` without changing either output. A present
ordinal writes the required byte count, then the defined record prefix
when the destination fits the fixed header. The value query and enumeration
entries use the same record encoder.

## Native evidence

On Windows ARM64 10.0.29708.1003, the fixed language-configuration key had
no values, and the installed `UILanguages\en-US` key exposed `LCID` followed
by `Type`. An independent ARM64 call matrix matched 1,272 x86 compatibility
observations byte-for-byte in both views. The x86 probe makes repeatable
observations over both read-only keys, positive and exhausted indexes,
classes 0 through 5, and bounded aligned and unaligned buffers.

Compile `probe-v1.c` as an i686 Windows executable with an x86 C toolchain
and link Advapi32. Run it from a standard user session on the specified
Windows build. Its CSV contains the status, returned length and raw
destination bytes for each case. `profile-29708-arm64.json` identifies the
host and the observed artifacts. The Windows test compares both keys
against an independent native invocation at runtime when the keys exist.
