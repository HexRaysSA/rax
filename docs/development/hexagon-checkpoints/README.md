# Hexagon private checkpoints

Hexagon public registers show the packet-entry image while work is pending;
they omit counters, local reservations, forwarding, queued input/output and
deferred RAM writes. Three actual parent VMM-file regressions observed counter
reset, discarded input completion and lost modeled LL/SC rights. A controlled
local reversal of the C writer reproduced three exported-ABI state losses.
The intended writer was restored exactly before final validation. Raw evidence,
source hashes and the reversal/restoration receipt are in
[qualification.json](qualification.json).

Producer kind 9 (`RAXHX001`) retains represented working and packet-entry
registers, pending packet/input, deferred stores, undelivered outputs, finished
state, GPR/predicate/HVX forwarding, temporary/gather state, profile, packet
counter and current/rollback local rights. A pending duplex slot keeps its
original word and decodes against the admitted ISA at resume, preserving it
even if guest code changes after suspension. Target ISA and byte order must
match; private/public registers and phase/cursor/index/range invariants are
checked before publication. Retained duplex parse bits must classify a duplex
word; all three normal-word parse values reject before target mutation. An
adversarial public-API probe observed acceptance before this extra guard.
Target memory ownership is retained. Idle PC/register overlays preserve private
state. During a pending packet, identical-state and same-public-PC retries
are no-ops; destructive register or PC changes reject before mutation. These
non-reset paths also preserve restored local reservations in the C API.

CPU preparation is detached. Capture and guest entry reject before a matching
RAM publication permit is committed; cancellation and foreign scopes do not
enable execution or change the live CPU. A malformed or missing final CPU
record rejects before any CPU or RAM changes. Deferred stores remain private
until the packet's remaining outputs have been returned and the next step
commits. A previously returned CPU output counts as delivered under the
existing interface and is not replayed.

The C API writes format 10 with this producer, after preparing/copying the
complete offside memory image. Raw packet counts survive; public
`rax_emu_icount` restarts at zero. Mapping changes invalidate both current and
rollback reservation rights, while preserving other represented phase. A map
that cannot bind pending RAM rejects before replacing the engine. Legacy VMM
files without private sections and C formats 1/2 retain projection-only
semantics and cannot reconstruct omitted state.

| Resource | Bound |
| --- | ---: |
| Private record including tag | 16 MiB |
| Deferred store entries | 4,096 |
| Bytes in one deferred store | 65,536 |
| Undelivered MMIO outputs | 16 |
| Bytes in one MMIO output | 4 |
| GPR producers | 8 |
| Guest words in a packet | 4 |

Collection bounds precede decoded allocation; aggregate payload and RAM ranges
are admitted separately. For C CPUs, B encoded bytes and N collection entries,
framing/decode and collection transfer take O(C+B+N) time and O(B+N)
auxiliary space, excluding address-map admission. Reservation/store admission
also incurs memory-map lookup and region-visitation costs. RAM transfer moves
O(R) bytes, with mapping costs separate. These are algorithmic bounds.

Twenty-five focused tests passed. Basic counter and exact-image preservation covers
ten ISA variants times both byte orders. V68 little-endian packet tests cover
buffered GPR/HVX results, mutable-code duplex resume, returned output
conservation, deferred RAM and cancellation. Actual 1/2/4-CPU files retain
counts, pending input and disjoint local reservations. The complete owning
machine binary passed 175 tests, and the complete SMIR lift binary passed 313.
The complete root library passed 11,643 with zero failures and 35 ignored;
the C API passed 239. The selected signed Apple Silicon native-file case passed
1/2/4-CPU scenarios. Fresh C/C++ passed 19 programs and seven ABI compilation
checks. Workspace formatting, all-target check/build and Clippy passed.
Doctests executed zero examples with five ignored.

| ID | Assumption and dependent result | Falsification probe | Qualification |
| --- | --- | --- | --- |
| HX1 | Counters require private bytes | Actual files and C restore | Parent/reversal failures and repaired continuation |
| HX2 | Read completion/forwarding is pending packet state | Complete saved input without another read or early GPR commit | File/unit/C ABI cases passed |
| HX3 | Checkpoints retain modeled local rights; maps may invalidate them | LL/save/restore/SC and reserved-range removal/readdition | Passed; no conflicting-writer assertion |
| HX4 | Pending duplex decoding uses its original word | Modify code after slot1 suspends | Original slot0 resumed |
| HX5 | RAM/output/forwarding have distinct publication phases | Return one output, preserve the remainder and deferred RAM/HVX state | Passed |
| HX6 | Admission is bounded and detached | Oversized field counts, cancellation/foreign scope, corrupt final CPU, legacy input | Passed |

| Impact | Remaining boundary |
| --- | --- |
| High | All four original full findings remain open, including native in-flight/IRQ/clock/replay, SMP and physical Intel requirements |
| High | Local monitor preservation does not establish all-writer/global coherence or physical Hexagon conformance |
| High | Existing unsupported ordered MMIO write/read packets are not enabled by this checkpoint work |

Instruction words were checked with the installed LLVM 23 Hexagon assembler;
state-preservation expectations compare actual modeled execution and
file/exported-C continuation. No physical Hexagon qualification was performed.
The full ignored native CPU-profile module was not rerun, and its independent
streaming FPSR reentry failure remains unresolved. No physical Intel execution
or Intel cross-target compilation is claimed.
