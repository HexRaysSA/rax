# S5L8900 private checkpoints

New S5L bundles carry a required private producer alongside the public AArch32
register table. The represented CPU, bridge, devices, pending transactions,
logical elapsed clocks and guest-affecting diagnostic controls now restore into
detached owners and publish with the matching physical RAM and shared S3C UART.
Saved producer identity selects S5L before construction even when `RAX_MACHINE`
selects another family at the destination. Restoration does not reopen source
kernel or NAND files.

The image preserves the complete modeled ARM core (banked registers, FP/MMU,
halt and exception state), exclusive monitor, instruction and timer counters,
NOR command phase, VIC stacks and daisy state, timer phase, I2C/SPI protocol
progress, USB endpoints/FIFOs/maps, pending DMA/ADM/crypto work and all remaining
runtime/bridge fields. Exhaustive destructuring makes a newly added owner field
a compile-time review point. Decoder construction is stateless. RAM, UART host
ownership, source preparation capability and publication guards are rebound
rather than serialized. NAND state and unread media use the separate
[resource-closed NAND component](../s5l-nand-checkpoints/README.md).

Source and destination follow these boundaries:

```text
stopped source -> prepare immutable NAND -> lock shared devices and RAM
               -> capture one common clock epoch + private/public records

admit all records/resources -> construct detached CPUs -> admit shared bindings
                           -> publish RAM/UART and common clock epoch
                           -> activate prepared CPUs
```

Media preparation occurs before UART/device/RAM locks. A source-bound token
carries immutable NAND bytes and a CPU/controller witness; foreign or changed
sources reject. Scoped S5L capture without this token rejects. External media
writers must remain quiescent: the NAND component compares two observations,
not an atomic filesystem snapshot. Dynamic guest-affecting environment settings
must also remain stable across source capture. Controlled UART and RAM writers remain
excluded during scoped capture/publication.

All CPU candidates and shared UART images must admit before publication.
Conflicting images for one UART owner reject. Compatible images publish once,
preserving the current host owner and queued saved input. Failed preparation
leaves the live CPU vector, UART and RAM unchanged. A detached candidate cannot
execute or recapture before its matching RAM scope publishes. Repeated permits
do not reactivate it or reset its elapsed clocks.

The deterministic timer retains its attempt/idle progression and existing
nondecreasing device counter. The elapsed diagnostic branch stores elapsed
`(seconds, nanoseconds)` rather than a host `Instant`; its source follows the selected VM clock. Target preparation and
downtime are excluded, and all restored CPU clocks resume at the common publication
epoch, including time before first CPU entry. Timer scaling uses multiplication
modulo `2^64` in checked and release builds. This fixes the large-multiplier
host panic without changing the existing counter's nondecreasing update rule.

Normal host-backed execution retains dynamic guest diagnostic options. Capture
freezes GID key, logical-page override, sparse-VFL/security seeding switches and
GUID probe score; NAND freezes its five media controls separately. Restored
execution uses the saved effective controls. Dynamic logging reads and output
paths remain host controls; represented trace flags and budgets travel with the
private image. GID parsing now rejects invalid ASCII hex, UTF-8, unsupported
lengths and oversized inputs without slicing inside UTF-8 code points. Public
S5L register setters/getters now preserve FPSCR, S/D registers, SPSR and CP15
fields through the shared AArch32 projection helpers.

The versioned descriptor is private kind 11, `RAXS5L01`, followed by CPU identity
and two complete resource keys. New state kind 5 begins with `RAXSLI02` and is capped
at 64 MiB. NAND kind 6 begins with `RAXNND01`. Resource keys include kind, size and
SHA-256; existing bundle integrity and aggregate RAM/media admission apply.
Framing rejects trailing/truncated bytes, noncanonical booleans/options,
invalid topology/index/priority/protocol shapes and excessive collection counts.
USB maps serialize in sorted key order and reject duplicates or disorder.
Legacy bundles without private state retain their existing projection-only
contract; a descriptor cannot be imported through an unprepared raw setter.

The previous large device module is split into core, interrupts, USB, crypto,
I2C, SPI, display and SDIO modules. Original public re-exports remain. All 130
original function bodies were compared after removing comments/formatting and
retained exactly. The shared S3C UART decoder now enforces its existing 16 MiB
checkpoint queue bound before allocation; its serialization layout is unchanged.
No ISA admission, SMIR, JIT, C ABI, dependency, firmware or cold secondary-startup
contract changes are claimed.

| Validation | Passed | Failed | Ignored |
| --- | ---: | ---: | ---: |
| Complete focused S5L selection | 69 | 0 | 0 |
| Collection admission | 2 | 0 | 0 |
| Shared UART regression | 1 | 0 | 0 |
| Unfiltered root library | 11898 | 0 | 35 |
| Unfiltered C API library | 240 | 0 | 0 |
| CI workflow regression binary | 12 | 0 | 0 |

Validation counts, commands, baseline failures, source hashes and assumption
probes are recorded in [qualification.json](qualification.json). Focused counts
overlap the complete root binary. Ignored tests remain ignored. Test media and
kernel placeholders are owned synthetic inputs; user firmware/NAND directories,
other repositories and the live primary executable remain untouched. Each
tested group is committed directly to `master` using exact `git add` paths and
`red -m --staged --run` over the same paths. Idle owned build/scratch directories
are removed afterward. No branch/worktree is created and no push is performed.

| Impact | Evidence boundary |
| --- | --- |
| High | Wall-mode PMU RTC remains host-local; Retired PMU UTC calendar binding is qualified by the selected-calendar follow-up. General external-input replay remains open. |
| High | Prepared 1/2/4-context transport and continuation do not establish architectural S5L secondary startup; cold policy remains CPU0 only. |
| High | Full A32-FP, C-STATE, C-SMP and C-HVF findings remain open, including native streaming-FPSR and physical Intel validation. |
| High | External NAND media must remain stable throughout source capture. |
| Medium | Logical byte budgets are not resident-memory ceilings. |
| Medium | Synthetic model continuation does not establish physical ARM1176/device or proprietary firmware conformance. |

The follow-up [selected-clock qualification](../s5l-selected-clock/README.md)
binds elapsed clocks to their VM owner and prepares incoming retired publication
epochs before clock commit. The validation table above describes the original
private-producer group; current follow-up counts are recorded separately.

The [selected-calendar follow-up](../rtc-selected-clock/README.md) adds retained
PMU calendar ownership and source-free pre/post guest I2C read continuations.
Legacy RAXSLI01 imports retain Wall-only admission; selected RAXSLI02 follows
the complete saved VM clock. The earlier validation table is historical.
