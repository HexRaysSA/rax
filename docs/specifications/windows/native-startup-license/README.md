# Installed startup license values

On Windows ARM64 build 29708, SysWOW64 CMD calls the installed x86
`NtQueryLicenseValue` leaf with an 8-byte `UNICODE_STRING` and five
32-bit arguments. The leaf removes 20 argument bytes on return. The
[stock CMD observation](wow64-cmd-29708-arm64.json) records 11 queries
for six names. Independent fixed queries on the native ARM64 host
returned the same statuses, lengths, types and successful data bytes.

The WoW64 handler reads these names from the immutable host policy catalog.
The AppServerMode and MUI language-count values are DWORDs, and the MUI
language-list values are UTF-16 strings. A capacity query reports the type
and required size. The observed missing WindowsExcludedProcs value clears
the size and leaves the type undisturbed. The guest ABI and captured
host identity select the profile. The captured values describe one host
and are evidence for replay. Each installed run captures its own values.

An AMD64 process on Windows ARM64 build 29708 uses the native64
`NtQueryLicenseValue` contract for `Kernel-OneCore-DeviceFamilyID` and
`TerminalServices-RemoteConnectionManager-AllowAppServerMode`. The
[native64 replay](native64-29708-arm64.json) records byte-identical results
from translated AMD64 and native ARM64 probes for these names at capacities of
0, 3, 4 and 16 bytes, with and without the optional type output. Successful
queries publish one DWORD from the installed host policy snapshot. Short
buffers leave the data unchanged and publish the required size.

AMD64 guest dispatch selects this contract on a measured ARM64 installation
and uses the existing read-only host policy snapshot. The ABI replay checks
the fifth parameter in the AMD64 stack argument area and the returned status,
type, size and adjacent output bytes.

The standalone AMD64 comparator produced the same 512 bytes as Windows for
the 16 replay cases. The original CRT-linked probe also matched all 144 bytes
of expected output, empty standard error and exit code 0 with the installed
Windows libraries.

The [native64 producer](probe-native64.rs) measures these two names on native
x64 and ARM64. It checks each exact and lowercase spelling with both
counted-string maximum lengths, with and without the type output, and with
capacities of 0, 3, 4, and 16 bytes. The zero-capacity cases use both a null
and a valid data pointer. Each of the 80 rows records the status, type,
required size, and guarded destination bytes. Run the installed-process
workflow with `measure_startup_queries` to record the kernel version and
hashes of the producer, executable, and NTDLL.

The native AMD64 observations on Windows Server builds 20348 and 26100
each cover the full 80-query matrix. Both installed names are DWORDs. A
short buffer reports four required bytes and optionally publishes type 4,
including a null or nonnull output at capacity zero. Exact spellings return
the installed values. Lowercase spellings return `STATUS_OBJECT_NAME_NOT_FOUND`
and preserve the length, type and data outputs for both names. The emulator
selects this profile for an AMD64 guest on those two AMD64 kernels and
uses the selected host policy snapshot. [Capture identities](amd64-inputs.json)
bind the native results.

Windows 11 ARM64 build 26200 returns the same status, type, length and
guarded-output behavior for these two names across the 80 native64 cases.
The selected host's DWORDs were 3 for DeviceFamilyID and 0 for AppServerMode.
Lowercase names preserve every output. The emulator uses each installation's
snapshot for the matching native ARM64 guest profile.
[Native observations](arm64-26200-native.json).
[Runner and NTDLL identity](https://github.com/HexRaysSA/rax/actions/runs/45117962053/job/137505031615).

## WoW64 on Windows Server 2022 and 2025 and Windows 11 ARM64

The [installed matrix](https://github.com/HexRaysSA/rax/actions/runs/45149678732)
measured Windows Server 2022 build 20348 and Server 2025 build 26100 on AMD64,
and Windows 11 build 26200 on ARM64. Each runner returned identical results
for all 448 queries through the x86 and native64 leaves. Missing
`WindowsExcludedProcs` and lowercase names preserve the type, length and
destination. Short buffers for present names return the required length and
optional type, with the entire destination preserved. The successful calls
write one DWORD or one counted number of UTF-16 bytes, including the measured
770-byte SKU language string.

The build and machine must agree with the installed-runtime and WoW64
metadata. The query reads the installation's immutable startup policy
snapshot. The [replay fixture](wow64-release-profiles.json) contains the
captured values and the digests of the native inputs and output streams.

The [producer](probe-startup-matrix.rs) checks its execution architecture
through `IsWow64Process2`. It measures both spellings, both counted-string
maximum lengths, optional type output, null and valid zero-capacity
pointers and capacities up to 1,024 bytes. Eight guard bytes surround the
output. Each row stores the changed span and its offset in the initialized
buffer. Download the three `startup-policy-windows-*` artifacts from the
installed matrix into one directory and project them with:

```sh
python3 -B docs/specifications/windows/native-startup-license/project-wow64-release.py path/to/artifacts
```
