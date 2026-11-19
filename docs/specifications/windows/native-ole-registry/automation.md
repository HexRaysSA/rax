# Installed OLE Automation startup registry key

On Windows 10.0.29708.1003 ARM64, the installed `certutil -hashfile`
path requests the machine-relative `SOFTWARE\Microsoft\OLEAUT`
key before checking setup state. The stock `NtOpenKeyEx` uses
`KEY_QUERY_VALUE`, case-insensitive object attributes, and zero options.
Native Windows returned `STATUS_OBJECT_NAME_NOT_FOUND`. Independent
Win32 opens returned `ERROR_FILE_NOT_FOUND` in the default view and in
both explicit views. The [recorded observation](automation-29708.json)
contains the call and native comparison.

The installed registry snapshot captures only the fixed OLE Automation
subject. OLE Automation inherits the WOW64 redirection of
`HKEY_LOCAL_MACHINE\SOFTWARE`. The adjacent OLE subject is shared.
Each OLE Automation registry view retains its own present or missing
result. A guest lookup of the explicit `WOW6432Node` spelling selects
the captured 32-bit view. Other names with a common prefix keep their
ordinary lookup behavior. If present, each selected view uses the
existing bounded subtree acquisition and stores an immutable copy.

The positive and mixed-presence cases are tested with synthetic maps.
Native positive presence was unavailable on this installation.

- [Registry Keys Affected by WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/shared-registry-keys), [archived source](../native-loader-registry/shared-registry-keys.html).
