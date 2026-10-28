# Native exception entry fixture

This SDK/CRT-free PE registers one vectored exception handler, writes to the
unmapped low address `0x1000`, and resumes at an address-taken label in the same
function. The handler requires an access violation, a continuable record, and
matching exception address and saved PC. The program then requires exactly one
handler call, removes its registration and exits with code zero.

The saved-PC offsets use the Windows SDK context layouts independently checked
by the native entry controls in
`docs/specifications/windows/native-exception-entry-profile/`. The address-taken
label preserves the interrupted function's stack and calling convention;
continuation does not synthesize a return address or enter a different C frame.

Rebuild all three small binaries from the repository root:

```text
python tests/fixtures/user/windows/native_exception_entry/build.py
```

The generator accepts `--clang`, `--linker` and `--dlltool`. It uses an owned
temporary directory below the repository's `target` directory and removes
compiler intermediates. LLVM tool basenames are preserved because its
multi-call binaries select their mode from `argv[0]`. The manifest binds the
source, tool images and generated PE files. PE timestamps are zero. The total
fixture payload is 6,656 bytes.

The exact three binaries were executed on the native build-29683 ARM64 Windows
kernel. ARM64, x64 and WoW64 views all exited zero; pre/post executable hashes
matched the manifest. These are three views of one kernel, not independent
x64-kernel observations. The Windows-only library test uses the same fixture
with selected installed NTDLL/Kernel32, no general host filesystem grant, a
60-second deadline and at most `2^26` guest instruction attempts. It checks
process completion and keeps native registration out of the HLE handler list.

An older public VCH fixture assumes an exception-flag value that does not hold
on the measured native 64-bit views. It was preserved unchanged; this fixture
uses a hardware fault and checks only the flag relevant to continuation.
