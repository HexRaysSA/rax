# Installed Win32u window class services

The native ARM64 control used Windows build 29708.1003. It called the installed
Win32u entry points with TEB last-error and last-status sentinels. The registration
records contain inputs, relative success, and function-ID fault precedence.
Absolute native USER atom IDs and image pointers are process and session data.

The native 64-bit service takes an 80-byte class record, primary and versioned
16-byte counted class-name descriptors, a 32-byte menu record, a function ID,
registration flags and an optional WOW argument. The raw kernel entry preserves
the caller's size field when returning class information. It returns the primary
atom but looks up the versioned name. Class and message registration use a shared
USER atom namespace. Class-only references are released on removal and process
exit. Local classes are scoped to their module. A USER32 local class can supply
a fallback before an application-global class.

The replay tests select the Win32u entry by its name and exercise ARM64 and x64
guest argument layouts. The emulator keeps the caller's records, class state and
identities inside the guest. Installed stock cursor and icon handles are resolved
in the guest resource cache. Class callback invocation, procedure-encoding thunks
and paired WoW64 GUI layouts need additional services.
