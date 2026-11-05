# Native PC RAM and boot layout

Configured RAM is a quantity. Its physical layout excludes this board's
existing device window; the backing allocation remains larger for historical
software CPU accesses and native ownership.

| Configured RAM quantity | Low RAM | High RAM |
| --- | --- | --- |
| At most 3 GiB | `[0, rounded_quantity)` | Empty |
| More than 3 GiB | `[0, 0xc0000000)` | `[0x100000000, 0x100000000 + rounded_quantity - 3 GiB)` |

`machine::pc::ram::Layout` validates the existing allocation cap and page
rounding, then supplies both native mappers and firmware metadata. Layout
construction and extent admission take O(1) time and storage. High RAM consumes
its physical-address offset in the existing backing; it does not alias low RAM.
KVM preserves historical lower padding, leaves the complete 3..4 GiB window
unmapped, and registers only configured high RAM. HVF subtracts actual device
extents from both RAM intervals and retains its page exclusion and transactional
mapping behavior.

Direct-kernel E820 now describes the same low/high intervals. The existing
16 KiB reservation and initrd stay below the low-RAM endpoint. The boot protocol
fields currently used for the initrd are 32 bits; this group keeps placement
representable and does not introduce an above-4-GiB initrd protocol. Placement
honors the inclusive `initrd_addr_max`. See the unmodified primary Linux v6.8
boot protocol under `references/`, fields `ramdisk_image`, `ramdisk_size` and
`initrd_addr_max`.

ELF admission validates every loadable segment before publishing any segment
bytes. Device-hole, reserved-low-RAM, wrapping, truncated-file and
`p_filesz > p_memsz` extents reject. High data and BSS remain possible while the
initrd stays above the occupied low kernel. BSS uses bounded 64 KiB chunks.
Validation uses O(P) time/storage for P program headers; publication is O(B) for
B initialized bytes. A linked virtual `e_entry` resolves through its admitted
`PT_LOAD` segment to the loaded physical payload. A legacy entry already within
a loaded physical segment remains accepted. Uncontained or ambiguously
translated entries reject before segment writes. This board starts at the
resolved physical entry; it does not install arbitrary ELF virtual mappings.
See gABI 4.3 sections 2.1 and 7.1/7.2 under `references/`.

Bootstrap identity and direct mappings cover the complete configured cap:
64 GiB RAM + 1 GiB device gap = 65 GiB physical extent. The existing one-GiB
page mechanism needs 65 of the 512 PDPT entries, within its existing 4096-byte
table. Legacy BIOS E820 also excludes the hole, and E801 no longer wraps the
above-16-MiB block count for large configured RAM.

Native MMIO collateral RAM uses the same two intervals. Read/write chunks split
at each RAM/device boundary; an RMW must fit wholly within one admitted RAM
interval. The retained device-window backing and after-capacity padding remain
open bus. PCI routes retain priority over collateral RAM.

A 64-bit PCI memory BAR now derives its base from both dwords. Unpaired,
overlapping or wrapping windows remain unrouted. Capture and restore preserve
the independently cached route: replacing a function can change BAR/COMMAND
configuration without refreshing existing routing. The existing `RAXPCI01`
wire representation already stores a 64-bit route. Historical truncated
64-bit routes remain compatible and retain their saved behavior until a
configuration write recomputes routing. Unaligned or wrapping cached extents
reject before publication. Linux v6.8 `__pci_read_base` in the retained
`references/linux-pci-probe-v6.8.c` is the independent full-width decoding
reference.

Raw `GuestMemoryWrapper::register(&VmFd)` is unsafe: a borrowed native VM does
not retain the mapping owner. Safe managed registration retains a backing clone
before any slot mutation, including partial failure. The raw helper documents
the caller's lifetime and access obligations. Managed CPU/VM ownership remains
the normal safe path.

Intel HVF shared records now use `RAXHVG02`. Explicit `RAXHVG01` input remains
accepted through 3 GiB, where its historical flat physical geometry is
identical. Larger legacy records reject rather than reinterpret their physical
RAM positions. RAM versioning is independent of the accompanying software-PAT CPU format
`RAXHVI02`.

The original complete native library reproduces five failures in the expanded
nine-case `kvm_minimal` owning target, with four controls passing. Separate
native observations capture high read/write MMIO, overlapping E820 and a
5-GiB initrd pointer that does not address its payload. The first changed
production library passes those nine cases and all 18 mapping cases.

Further complete-library baselines retain 10 pass / 4 fail across the expanded
14-case ELF/boot target, 5 pass / 3 fail across the collateral RAM module, and
an initial 2 pass / 4 fail across six public PCI routing/checkpoint contracts.
One assertion in that initial PCI baseline incorrectly required cache/config
equality. The unchanged owning checkpoint target disproved that requirement;
its 16 pass / 1 fail result remains recorded. With the corrected eight-case
profile suite, the historical full library gives 3 pass / 5 fail. The strict
intermediate PCI component gives 33 pass / 3 fail; the corrected component
gives 36 pass / 0 fail, including all 17 unchanged owning cases. Complete
production validation remains in progress. These are actual observations, with nested child summaries distinguished from owning
target totals. Final combined native production, canonical Cargo and macOS SDK
checks are tracked in `qualification.json`; physical Intel execution remains
separate.

The earlier V5 source passed its first 14 canonical gates, but its unfiltered
library run observed four host-dependent socket/netlink fixture failures. Later
inspection also found that overlapping logical source views could reuse Cargo
artifacts without binding them to the declared source. Those qualifications
were superseded; their partial results remain diagnostic evidence.

The combined replacement uses the corrected fixtures, an immutable source view,
a source-bound compiler cfg and retained test executables. Its native owning,
SMP, mapping, boot, PCI, oracle and C API gates passed. Complete frozen unfiltered roots subsequently passed: Apple Silicon
12408 passed / 0 failed / 36 ignored, Linux Intel 13330 passed / 0 failed /
82 ignored. Their exact source boundaries and byte comparisons are retained
in the current-source section of `qualification.json`; older live-controller
fields are historical observations. These results do not qualify the entire
current checkout after later Intel and remote Windows changes. The
[managed native owner](../kvm-native-owner.md) documents the accompanying CPU,
I/O, quiescence and restore-construction changes. The final source identity and
results are recorded in `qualification.json`.

The same qualification file contains the assumption register, falsification
probes and bounded findings. Full backend/private/in-flight checkpoint capture,
coordinated restoration, clock/replay behavior, remaining A32/HVF profiles and
physical Intel validation remain requirements of the original audit goal.
