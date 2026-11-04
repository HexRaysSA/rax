# Native file-read profile

`NtReadFile` is registered after the earlier NTDLL export families, preserving
existing synthetic ordinals. Installed service numbers and the actual x86
nine-argument return ABI select the same implementation as direct HLE imports.
The [Microsoft NtReadFile contract](https://learn.microsoft.com/en-us/windows/win32/devnotes/ntreadfile)
owns the nine arguments, read grants, offsets, IOSB byte count and completion
event. `primary-sources-v1.json` records the source check.

The production path reads retained guest-owned files and caller-configured
console input. Duplicate handles share the retained descriptor and per-open
cached-I/O state; independent opens keep separate positions and initialization.
NUL returns EOF, console input has a distinct zero-length status, console output
is not an input stream, and directory reads return invalid-device-request.
Explicit offsets, partial EOF, empty regular reads, access failures, full IOSB
bytes and unchanged LastError are represented in the independent corpus.

On Windows, only an owned retained descriptor and private initialized aligned
storage reach `NtReadFile`. Guest addresses, events, keys and callbacks are not
forwarded. A private owned event synchronizes a pending host request; every
file, offset, IOSB and data allocation stays live until completion. This host
lifetime rule does not implement asynchronous guest scheduling.

On Linux/macOS, the mounted Windows disk adapter retains the original file and
models the observed cached-read transition. A cold open's first nonempty read
initializes its per-open cached-I/O state. Cached EOF does not perform an
explicit seek; an uncached EOF can update the cursor. Successful nonempty Win32/native writes and reads, and accepted CRT write
prefixes and successful CRT reads, update the same state. Portable unbuffered
requests retain the mounted-disk 512 B sector and alignment-mask 1 contract.

`observations-v1.json` contains 1980 completed native calls: 540 scalar calls
and 120 repeated-read calls per ABI. ARM64, x64 and x86 ran on one Windows ARM64
build 29698 kernel. This establishes three process ABIs, not independent AMD64
kernel equivalence. The header archives actual installed leaf bytes. All six
control runs exited 0, had empty stderr and unchanged warmed handle counts.
The frozen `source-*.json` snapshots bind source, compile configuration and
image hashes to those captures. Their original CMake snapshots include an
unrelated target declaration; the public CMake file below builds only the
normal scalar and transition controls included here.

The replay explicitly selects 1692 synchronous observations. The remaining 288
observations describe asynchronous file requests or pipe reads; those calls
remain evidence for unfinished work. No test counts them as synchronous
success. Tests also cover actual installed native/WoW64 leaves and bounded
caller-memory errors entirely inside the emulator.

A separate native fault-capture attempt was interrupted by an unexpected guest
reboot and bugcheck. Its results are unqualified: no individual triggering call
or native fault-order equivalence is established. Those probes are not part of
this public capture or its rerun instructions.

To rebuild the normal controls on Windows with an installed MSVC-compatible
compiler, choose a new in-repository output directory:

```text
cmake -S docs/specifications/windows/native-file-read -B target/native-read-new -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build target/native-read-new --target file_read_scalars file_read_transitions
python docs/specifications/windows/native-file-read/verify.py
```

Run each control in its own new task-owned working directory, with stdout
redirected to a regular file or pipe. The scalar control creates a fresh private
console and injects its own input; it rejects inherited console stdout and does
not consume input from an inherited console. Both controls create only their
own regular-file/directory fixtures. Preserve source/image/DLL hashes, stdout,
exit status and warmed handle counts with a new capture.

The implementation bounds each request at 16 MiB. For N requested bytes it uses
O(N) copying/initialization and O(N) scratch; the Windows adapter also owns an
aligned host buffer and a copied result. Host I/O latency is additional.
Asynchronous guest completions, pipes, APC delivery, requests above the bound,
additional device/kernel profiles and unqualified fault ordering remain active
work. This increment does not establish full process-emulation completeness.
