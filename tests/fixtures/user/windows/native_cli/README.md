# Windows CLI fixture

`probe.exe` uses a freestanding entry point with no SDK or CRT. It writes
`RAXCLI\n` followed by eight binary bytes: the loaded KERNEL32 PE timestamp
and `SizeOfImage`, both little endian. It then calls `ExitProcess(0x87654321)`.
The signature distinguishes installed DLL loading from synthetic built-in DLLs.
The Windows CLI test compares this output and all 32 exit-status bits with a
native execution of the same executable. Unix hosts test the built-in provider
and the corresponding low-eight-bit exit status, `0x21`.

Rebuild all three guest ABIs with LLVM tools:

```text
python3 tests/fixtures/user/windows/native_cli/build.py --clang clang --linker lld-link --dlltool llvm-dlltool
```

The builder keeps temporary objects under the repository's `target` directory,
removes them on exit, and records source, tool, and output hashes in the manifest.
These fixtures do not establish arbitrary Windows program or loader equivalence.

On Windows ARM64, the existing x86 profile selects pure x86 SysWOW64 DLLs;
the native x86 control may load CHPE modules with different PE metadata.
That case compares status and the output marker with native execution, and
checks the DLL signature against the installed pure x86 KERNEL32 file.
Host-ABI cases compare the complete output with native execution. CHPE execution
remains a separate, incomplete capability.
