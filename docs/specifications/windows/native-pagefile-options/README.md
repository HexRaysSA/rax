# Pagefile section view options on ARM64 Windows 29704

The independent control creates one unnamed 65,536-byte `SEC_COMMIT`,
`PAGE_READWRITE` section in its own process. Four producer images cover native
ARM64, translated AMD64, i386 and i386 with `LARGEADDRESSAWARE`. Each producer
records 138 mapping calls and one pair of writable/read-only alias views.
All four original producers exit 0, release all 66 mapped views and return to
their initial handle count. Thus 4 × 138 = 552 mapping observations and
4 × 66 = 264 mapped/released views are retained.

The controls use `NtCreateSection`, `NtMapViewOfSection`, `NtUnmapViewOfSection`
and `NtClose` on owned current-process resources. They do not attach a debugger,
patch instructions, edit another process, terminate a process or impose a
validation deadline. Eight installed DLL identities hold before/after execution.
All six executed package inputs also hold in an independent post-capture check.
The physical host kernel is `10.0.29704.0` on ARM64; physical x86-64 kernel
behavior is unknown. The input PE machine and LAA bit are checked independently
of the process-machine API's reported value.

The original AMD64 guest startup requests a committed 65,536-byte cache section
with `CommitSize=16384`, zero `ViewSize`, `MEM_TOP_DOWN=0x00100000`,
`ViewUnmap=2` and `PAGE_READWRITE=4`. This exact mapping succeeds in all four
native profiles. A read-only alias observes writes through the writable alias
and retains the bytes after the writable view and section handle close.

The scalar observations agree across all four profiles after native addresses
are represented by alignment, preservation and placement properties:

| Boundary | Observed result |
| --- | --- |
| Zero view size | Remaining 65,536-byte section extent |
| Nonzero successful view size | Rounded upward to 4,096 bytes |
| Requested view size 65,537 | `STATUS_INVALID_VIEW_SIZE` (`0xc000001f`) |
| Commit size beyond the raw caller view extent | `STATUS_INVALID_PARAMETER` (`0xc000000d`) |
| Commit 4,096 with requested view 1 or 4,095 | Invalid parameter before page rounding |
| Misaligned base or section offset | `STATUS_MAPPED_ALIGNMENT` (`0xc0000220`) |
| Explicit base inside an owned reservation | `STATUS_CONFLICTING_ADDRESSES` (`0xc0000018`) |
| Top and ordinary simultaneous views | Top view above the ordinary view |

The owning shared-pagefile mapper retains its existing read/write section
profile, access checks, inherited-view validation, offset/extent checks and
real shared backing. The increment admits flags 0 and `MEM_TOP_DOWN`, with
`ZeroBits=0`; commitment is bounded by the caller's raw view extent before
rounding. Both pointer outputs continue through the existing common transport,
including early native64 preflight and late WoW64 copy-back ownership.
All storage, addresses, handles and alias lifetimes remain guest-owned.

The literal regression selects the 124 zero-`ZeroBits` records per profile:
4 × (138 − 14) = 496 exact status/scalar/geometry observations. The remaining
56 native `ZeroBits` observations are retained acquisition evidence. Nonzero
`ZeroBits` remains an explicit unsupported operation in this increment.
Separate regressions cover alias lifetime and early/late output-copy faults;
Windows additionally exercises installed native/WoW64 export leaves.
Their execution results require source- and image-bound validation separately.

Scalar checks add O(1) time and space. The existing shared-view allocator owns
placement, mapping and commitment accounting; its documented bound is
O(P log R + M log M) time and O(P + M) metadata/scratch for P object pages,
R charged pages and M allocation/mapping runs. The control corpus does not
establish arbitrary section attributes, protections or child inheritance.

Verify the frozen source, profile and independent projector:

```text
python3 -I -B docs/specifications/windows/native-pagefile-options/verify-v1.py
```

Supply `native-pagefile-options-29704-v1.zip` as the next argument to verify the
raw archive, builds, PE identities, executed input package, original returns,
stdout and independent projections. On Windows use `python`. The retained
archive has 589,463 bytes, SHA-256
`04f1c5c9ca3690bcefded99e58cd1b1c45eb59c4f01ca224fc5379e95af1d798`,
and contains 16 payloads plus a manifest. No-argument verification does not
inspect this separate archive. Archive verification takes O(B + U) time and
space for B compressed bytes and U total uncompressed bytes.

| ID | Assumption and basis | Dependent result | Stress test / falsification probe | Status |
| --- | --- | --- | --- | --- |
| PF1 | The observed request uses a committed 65,536-byte read/write cache section; typed source and completed guest frontier agree. | Native case selection. | Exact request fails in a native profile or typed section identity differs. | Confirmed for this source/capture. |
| PF2 | Existing guest shared views can express the measured ownership without native pointer/handle forwarding. | Narrow mapper and ownership regressions. | Aliases lose bytes, retained views or final references after handle/view close. | Requires emulator execution evidence separately. |
| PF3 | Commitment can be checked against the rounded view extent. | Discarded initial arithmetic candidate. | Native commit 4,095/4,096 against raw view 1/4,095. | Falsified by 24 of 448 original auto-base/absent-offset observations. |
| PF4 | View range is checked before raw commitment, followed by page rounding in the selected zero-bits profile. | Literal replay and mapper order. | Any original selected row or a new adversarial boundary disagrees. | Confirmed within these recorded observations. |

High-impact remaining scope includes complete AMD64 translator startup, later
work-list/callback state, hybrid exception qualification and the separately
recorded Windows full-suite failures, including unresolved file-read IOSB
padding. This section-view increment does not establish complete process
emulation. Broader section modes and nonzero `ZeroBits` remain separate.

The [Microsoft API contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection)
documents the mapping parameters and allocation/protection model. Exact status
precedence, raw commitment bounds and recorded lifetime results above derive
from the original native controls.
