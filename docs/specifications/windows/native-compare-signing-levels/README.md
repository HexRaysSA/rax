# Native signing-level comparison

`NtCompareSigningLevels` compares two scalar `SE_SIGNING_LEVEL` arguments in the
guest kernel. It performs no host call, changes no signing cache, creates no
object, and visits no guest pointer. Earlier synthetic export ordinals and trap
addresses are preserved by appending a separate export family.

The measured kernel uses the low nibble of each byte-sized argument. Its
16-class dominance relation is represented by 16 `u16` masks (32 bytes): row is
the first class and bit is the second. An admitted pair returns
`STATUS_SUCCESS`; every other pair returns `STATUS_INVALID_IMAGE_HASH`
(`0xC0000428`). Native RTL conversion returns error 577 for the latter.
Comparison takes O(1) time and O(1) space.

This relation is not numeric ordering. There are 66 disagreements with numeric
`>=` in the 16-by-16 class domain. Classes 9, 10, 13 and 15 are non-reflexive in
the measured relation. These are observable class-policy results, not evidence
that a file signature or host trust policy was changed.

## Independent capture

`native-oracle-v1.c` calls the real NTDLL export for every one of the 65,536 byte
pairs, records its native RTL result, then measures 256 pairs of deliberately
wide machine argument carriers. The latter test the binary ABI boundary; the
normal matrix uses the declared byte-sized prototype. It writes a fixed
530,504-byte binary record. All output and build scratch stays in the owning
worktree. The source and executable hashes, NTDLL identities, kernel, raw-output
hashes and private receipt bind each capture.

The independent ARM64, x64 and x86 runs used kernel `10.0.29698.0`. The x64 and
x86 programs ran through Windows translation on that ARM64 machine. Physical
x64-host execution is a separate gate. Each matrix contains 22,016 successes
and 43,520 image-hash failures. All three raw matrices have SHA-256
`cf39ecfecf259e08398ae54ef7fd726beeaeecbc8d8b3f651d822e8a4adf72d9`.
All 768 wider-carrier results agree with the corresponding byte-matrix result;
the sentinel Win32 last-error value remains unchanged.

`observations-v1.json` retains all 256-by-256 outcomes as palette-index rows,
shared only after byte-for-byte equality of the three independent matrices was
verified. Each profile retains its own raw hash, executable identity, entry
bytes and complete carrier cases. Tests replay all 197,376 observations through
real guest syscall dispatch across the three guest ABIs. They also check RTL
conversion, continuation state, retained objects and untouched guard/canary
memory. A Windows-only native control compares all byte pairs against the live
host kernel. It fails on a changed or unavailable relation instead of skipping.

The earlier trace-event export test now compares the prefix through its own
family, allowing later appended families while still checking its original
ordinal and trap-address invariant.

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| A1 | The captured kernel uses a relation of the two low-nibble signing classes. | Exhaustive byte matrices and wide carrier captures in all three caller ABIs. | Constant-size guest relation. | All 65,536 pairs per ABI; reserved classes and high argument bits. | Any observed byte pair or carrier differs from the relation. | Confirmed on the identified kernel. |
| A2 | The relation remains applicable on another admitted native kernel. | Not inferred from a header declaration. | Native-host compatibility outside the captured kernel. | Exhaustive Windows live control. | Any live-host pair differs or the native export is unavailable. | Retained pending that native kernel's control result. |

## Remaining scope

* **High:** Complete ordinary-process startup and guest child-process supervision
  remain separate acceptance gates. The service resolves one observed startup
  frontier; the capture alone does not prove whole-program completion.
* **Medium:** Other kernel/profile relations require their own native evidence.
  The exhaustive native control detects drift; no unsupported-kernel success
  is claimed from compilation alone.

## Primary references

* [PHNT `NtCompareSigningLevels` declaration](https://github.com/winsiderss/phnt/blob/master/ntseapi.h).
* [Microsoft `SE_SIGNING_LEVEL` typedef and constants](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/winnt.h).
* [Microsoft NTSTATUS values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55).
* [Microsoft system errors 500–999](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--500-999-).

The native capture establishes the comparison relation and masking. Header
names and numerical level constants do not establish those semantics.
