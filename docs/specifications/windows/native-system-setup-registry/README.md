# Installed system setup state

On Windows 10.0.29708.1003 ARM64, installed `certutil -hashfile` opens
`SYSTEM\Setup` relative to the machine hive with query-value access,
case-insensitive object attributes, and zero options. It then queries
`SystemSetupInProgress` with `KeyValuePartialInformation` in a 16-byte
buffer. Independent Win32 queries returned the DWORD value zero in the
default and both explicit registry views. The [native evidence](observed-29708.json)
records the query shape and results.

Installed selection reads this one value from a fixed path and closes the
native handle before guest execution. The guest sees the captured DWORD or
the captured absence of that value. Other values, enumeration, and
unselected key information remain outside the snapshot. The installed
comparison covers the tested ARM64 Windows revision. Service tests also
exercise guest x64 and x86 layouts and both values of the setup predicate.
