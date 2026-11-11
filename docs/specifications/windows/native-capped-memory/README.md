# MemoryBasicInformationCapped

`NtQueryVirtualMemory` class 10 now queries guest virtual memory using the selected Windows 29704 contract. It does not forward a guest address or handle into the host kernel. Public C API 1.16.0 and optional-feature defaults are unchanged.

The [PHNT enum](https://raw.githubusercontent.com/winsiderss/phnt/master/ntmmapi.h) names class 10. The retained native probes establish the input, output and fault contract; the declaration alone does not specify it.

## Measured contract

Native 64-bit callers supply a 48-byte `MEMORY_BASIC_INFORMATION` with every byte except `RegionSize` zero. WoW64 extracts the cap from the 28-byte caller structure and ignores its other input fields. The cap must be nonzero. An invalid cap span and a zero cap have different WoW64 `ReturnLength` publication paths.

For requested address A and cap C, the exclusive scan bound is `align_up(A + C, 4096)` bytes. Overflow or an endpoint above `0x7fffffff0000` (64-bit) or `0xffff0000` (WoW64) is rejected. The result begins at `align_down(A, 4096)` and stops at the first allocation, state, reported-protection or private-copy boundary. Free holes retain their complete extent. A non-LAA WoW64 image reports its upper reservation fence without mapping or committing it.

The allocated-region scan uses O(log A + log R + r + S) time for A allocations, R page-state boundaries, r visited boundaries within the cap, and S populated private-copy page-table slots within the cap. Absent subtrees are skipped. Input handling uses at most 48 bytes of scratch; guest-controlled lengths do not allocate proportional host storage. Existing uncapped queries retain their behavior.

## Validation

macOS 248, native Linux 248, and native Windows 252 focused checks passed with no failures or ignored tests. The four new checks replay 3,091 native cap/field cases and 72 fault cases per host, plus controlled free-hole and WoW64-fence assertions. Two free-hole fault roles normalize only `RegionSize` because the native and guest allocation layouts differ. All 35,487 compiled input hashes held.

The no-default-features C API cross-checks passed for Linux and Windows. The production Windows core uses no optional features. `capped-guest.cpp` independently validates 26 queries through installed NTDLL. All three native controls exited zero. Under RAX, ARM64 and x86 completed all 26 queries and exited zero; AMD64 completed all 26 without an assertion failure and then reached the existing native shutdown wait.

`qualification-29704.json` records exact source/image hashes, native DLL identities, endpoint observations, assumptions, falsification probes and the bounded finding. The C++ probes use a custom `entry` and require `/ENTRY:entry /SUBSYSTEM:CONSOLE`; build and temporary outputs belong in an owned directory inside the checkout.

## Remaining boundary

High impact for the full process-emulation goal: AMD64 had no terminal guest exit after 2,000 observed scheduler turns. Its remaining thread waited on shutdown event object 45. The context-exchange experiments are separate and do not form part of this implementation. Other Windows kernel builds have not been newly qualified by this change.
