# Executable backing-name fixture

The freestanding x86, x64 and ARM64 programs query class 2 for their own image,
validate `UNICODE_STRING` bounds, and write a marker followed by the exact UTF-16
filename bytes. They have no CRT or SDK dependency. The Windows CLI regression
copies each selected program to a path containing spaces and a Greek character,
then compares native execution with both native and automatic CLI selection.
No `--sysroot` option is used. This catches a CLI accidentally passing raw image
bytes to `spawn_image`, which has no acquired executable-file identity.

Rebuild with `python3 -B tests/fixtures/user/windows/native_mapped_filename/build.py`.
The generator records tool, source and PE SHA-256 identities in `manifest.json`;
all scratch output and compiler temporary files stay under the owning worktree's
`target` and are removed after generation. The PE timestamp is zero, the entry
point is `entry`, and the loader imports only KERNEL32 and NTDLL functions.
The existing CLI metadata fixture and original hardware-fault fixtures are unchanged.
