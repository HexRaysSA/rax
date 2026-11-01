# Cortex-M private checkpoints

Public Cortex-M registers omit counters, sleep/events and internal controller
phase. Three parent VMM-file regressions and three exported C ABI regressions
observed the resulting counter reset, unsolicited WFI continuation and lost SEV.
The retained raw failures are linked in [qualification.json](qualification.json).

Producer kind 8 (`RAXCM001`) retains the represented core registers, active and
pending exceptions, instruction/cycle counters, sleep/event/halt state, execution
scratch, NVIC/SCB/SysTick images, local reservation and bridge fault. Readonly
model/profile fields must match the target. Import uses admitted raw images,
so restoring COUNTFLAG or a reset request does not consume it through MMIO.
The private record is at most 16 MiB including its tag; pending core exceptions
are bounded to 262,144 entries before allocation, and 496 priority bytes use a
fixed tuple. Raw counters wrap at their unsigned 64-bit boundary.

VMM restoration prepares replacement CPUs without modifying live CPU or RAM
state. A memory-binding-checked publication permit enables entry only after
restored RAM is published. Dropping the candidate or permit leaves the live
CPU unchanged; a corrupted or missing final CPU record rejects before any
CPU or RAM mutation. The target memory owner and current debugger controls
are retained. This follows the user's current-session preservation policy.

The exported C API writes format 9 with this producer. A complete offside
engine memory image is copied before standalone CPU publication. The raw
backend counter survives while public `rax_emu_icount` restarts at zero.
Mapping changes preserve core/controller phase and invalidate local exclusive
rights. LDREX/save/restore/STREX and removal/readdition of a reserved range are
covered through exported C functions. Historical VMM files without a private
section and C formats 1/2 retain their limited public-register contract.

All eleven modeled variants passed controller/adaptor preservation tests.
Actual 1/2/4-CPU files retain per-CPU counters, WFI sleep and SEV/WFE phase.
Eighteen focused tests passed. The complete root binary passed 11,626 tests,
with zero failures and 35 ignored; the C API binary passed 231. The selected
signed Apple Silicon native-file case passed with 1/2/4-CPU scenarios. Fresh
C/C++ validation passed 19 runtime programs and seven ABI compilation checks.
Workspace formatting, all-target check/build and Clippy passed. Doctests ran
zero examples, with five ignored; they provide no executed-example coverage.

| ID | Assumption and dependent result | Falsification probe | Result |
| --- | --- | --- | --- |
| CM1 | Public registers cannot reconstruct execution phase | Actual VMM and C continuation without private bytes | Six observed failures, repaired |
| CM2 | Raw controller state includes consumable side effects | Reset request, COUNTFLAG, pending state, reservation consumption on all variants | Passed |
| CM3 | Entry waits for matching RAM publication | Cancellation, foreign memory, corrupt/missing final CPU | Passed |
| CM4 | Debug controls belong to the current session | Distinct source/target controls and actual GDB file-restore lifecycle | Passed in modeled software scope |
| CM5 | Absent private bytes retain legacy projection behavior | Actual 1/2/4-CPU legacy files and C versions 1/2 | Passed |
| CM6 | Decode must bound pending storage and preserve counter boundaries | Oversized queue and maximum raw counters with overflow checks | Passed |

For C CPUs, B encoded bytes and Q pending entries, framing/preparation takes
O(C+B+Q) time and O(B+Q) auxiliary space within the fixed caps. Controller
installation is fixed size plus queue ownership transfer; RAM copy is O(R).
These are algorithmic bounds, not measured performance claims.

| Impact | Remaining boundary |
| --- | --- |
| High | All four original full findings remain open, including native in-flight/IRQ/clock/replay, SMP and physical Intel requirements |
| High | Preserving modeled state does not implement the absent FPE, MPU enforcement, external SCS MMIO wiring or additional interrupt execution semantics |
| High | Cortex-M keeps its existing local-only exclusive monitor; shared-writer invalidation/coherence is not established |
| Medium | Legacy files cannot recover execution state they never recorded; raw independent RAM writers require caller quiescence |

Primary provenance is the represented core/controller implementation and actual
VMM/exported C execution. This group makes no additional physical MCU fidelity
claim. The complete ignored native CPU-profile module was not rerun; its known
streaming FPSR failure remains open. There was no physical Intel qualification.
