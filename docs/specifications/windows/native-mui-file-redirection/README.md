# WoW64 installed message-resource file selection

Released Windows Server 2022 x64 (20348), Server 2025 x64 (26100), and
Windows 11 ARM64 (26200) store the thread's WoW64 filesystem-redirection
state in native companion TEB TLS slot 8 at offset 0x14c0. A native x86
probe recorded zero, one, and zero before disabling, while disabled, and
after reverting. With redirection disabled, an open of the installed
System32 command resource used the physical System32 file.
[Native observations](https://github.com/HexRaysSA/rax/actions/runs/45177069108)

Windows 11 ARM64 build 29708.1003 uses the same companion offset and TLS
slot. A native x86 process observed the companion at −8192 bytes, then read
`0 → 1 → 0` from slot `0x14c0` across disable and revert.
Opening the System32 command resource with redirection enabled returned
Win32 error 2. The same path with redirection disabled opened
`C:\Windows\System32\en-US\cmd.exe.mui`.
[Native x86 control](mui-redirection-x86.c).

A closed guest interprets this state for locale satellites belonging to a
selected installed executable or DLL. An explicit SysWOW64 path retains
its usual directory. The ordinary constraints on locale names, owner
selection and read-only access apply to both directories.

| Assumption | Dependent result | Falsification probe | Status |
| --- | --- | --- | --- |
| The measured slot belongs to the calling x86 thread on each selected build | A value of one selects native System32 for a resource open | Toggle and restore on that thread, compare native physical paths, and replay both values and the explicit SysWOW64 path | Confirmed on the selected builds |

The installed x86 command compared byte-for-byte through the closed C ABI
on both x64 Windows Server releases. On the Windows 11 ARM64 qualification
it reached a subsequent device-open boundary. The native-architecture
command comparison passed on all three releases.
[Hosted command comparison](https://github.com/HexRaysSA/rax/actions/runs/45179833620)
