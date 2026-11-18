# SideBySide registry query during WoW64 child creation

Windows ARM64 build 10.0.29708.1003, current user, installed x86 CMD:

```text
cmd /d /c "echo rax pipe|cmd /d /v:on /c (set /p value=^&echo !value!)"
```

The native pipeline returned exit code 0 and stdout bytes
`72 61 78 20 70 69 70 65 0d 0a`. Two observed
`NtOpenKeyEx` requests opened the machine
`Software\WOW6432Node\Microsoft\Windows\CurrentVersion\SideBySide` key
with access `0x00020019`. On each returned handle, the immediately
following `NtQueryValueKey` for `PreferExternalManifest` used
information class 2 and returned `0xC0000034`. An instrumented emulator
run observed the guest's logical path without `WOW6432Node` at the
corresponding failed open.

An independent ARM64 native probe opened the logical and physical
spellings with default, native64 and x86 view flags. On this build,
`RegOpenKeyExW` maps the logical x86 spelling to the physical x86 key.
Native `NtOpenKeyEx` opens the supplied absolute physical name even
when the caller passes a view flag. Both keys granted `0x00020019`
for the measured read request and maximum-access probe.

| Logical view | Root values | Immediate child names |
| --- | --- | --- |
| Native64 | Four values, including `MaintenanceFlags` | Configuration, IsolatedSxSAssemblies, Winners |
| x86 | Zero | Configuration |

The native64 `Winners` child reported 19,960 immediate subkeys. The
snapshot stores each root's native access profile, value bytes and
immediate enumeration metadata within the existing startup bounds.
Child bodies remain outside this selection. The guest view selects the
logical root, and the explicit x86 physical spelling selects the x86
record. The registry snapshot retains no host handles.

The native debugger trace SHA-256 was
`705184e99d7876820b87f17af30de1946354f9045bdbfa1ae0268bee97ebbbe0`.
The installed x86 CMD SHA-256 was
`e44c6777f63982211eb0ac7d6a2a6d53b46bff1928e5005c84b2847a25761002`.
