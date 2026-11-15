# Native CHPE context ownership, Windows 29704 and 29708

The installed ARM64 Windows runtime uses a thread's CHPE `CONTEXT` and simulation
flag as scratch state during save construction. Importing each store into the CPU
can replace the live ARM64 stack with an intermediate AMD64 save; publishing at
an instruction or quantum boundary can overwrite the native save.

`ContextOwner::NativeRtl` applies to the already selected native ARM64 29704 or 29708
profile of an AMD64 process. Binding publishes the initial context once. Later
synchronization checks the allocation identity and physical backing and preserves
the scratch bytes and flag. Explicit kernel/API context transfers retain their
validated application path. The builtin interpreter keeps its existing full,
partial and same-value store handling. Selection uses the native image identity,
not the requested guest version.

The six portable ownership regressions cover partial or temporarily invalid
saves at instruction and quantum boundaries, explicit accepted/rejected context
transfers, allocation replacement, cloned carriers, rebinds, and main/child
selection. Synchronization uses O(sizeof(CONTEXT)) time and fixed scratch space;
native preservation retains the same allocation/backing preflight.

The [29708 startup profile](../native-chpe-creation/profile-29708-v1.json)
retains a fresh native run of the unchanged active-context source in ARM64,
x64 compatibility and x86 process ABIs. Each completes four context cycles,
78 assertions and one callback with natural status 0; all three compilers and
the acquisition controller also exit 0. The 50-payload
`chpe-active-native-29708-v1.zip` archive is verified with the combined
[portable checker](../native-chpe-creation/check-29708.py). Main/child owner and
cloned-carrier tests exercise both admitted native builds independently of the
reported guest version. Native controls remain distinct from installed
emulator execution and full-binary qualification.

`native-active-context-v2.cpp` owns every event and worker it exercises. It runs
four suspended-worker Get/SetThreadContext and resume/wait cycles, calls
RtlCaptureContext, preserves worker last-error state, and checks a single
InitOnce callback. Its exported 64-word state contains the completed count at
index 1, failure stage at index 6, assertion count at index 10, and callback count
at index 12. A passing run has 4, 0, 78 and 1 respectively and exits naturally
with status 0. `installed-observer.rs` executes the fixture with the installed
Windows libraries and reports the guest terminal result separately from its own
process exit. The termination fixture is retained at
`../native-thread-termination/installed-thread-termination.cpp`.

The provenance file binds source, executable, native DLL, output and build-source
identities. Passing finite fixtures qualify these context and lifecycle paths;
they do not establish general XTA execution or CPU hardware breakpoint/watchpoint
execution. The separate native WoW64 nonzero-YMM resume failure remains unknown.
