# ARM64 instruction comparators

The AArch64 execution core checks the implemented DBGBCR/DBGBVR pairs after a successful instruction fetch and before entry checks, decode, effects or retirement. A match reports `ArmError::ArchitecturalException`, EC `0x30` from a lower EL or `0x31` at the same EL, ISS `0x22`, with the unchanged faulting PC. System stepping vectors that exception with the original PC/PSTATE. Embedder breakpoints keep their separate stop contract.

The base debug matcher follows the existing Arm shared ASL 2025-12 functions `AArch64_CheckDebug`, `AArch64_BreakpointMatch`, `AArch64_BreakpointValueMatch`, `AArch64_StateMatch`, `AArch64_GenerateDebugExceptionsFrom` and `AArch64_FaultSyndrome`. It checks monitor enable, comparator enable, address and context matching, linking, privilege/security controls, double lock, secure debug disable, and EL2 routing. Reserved combinations choose the permitted disabled behavior. Without LVA/LVA3, comparisons use address bits [48:2]; RESS bits are consistently excluded from the architecturally unpredictable comparison. The existing represented debug profile has no BWE/ABLE, extra comparator banks, halting state, OS software lock or Root/Realm security state.

MDSCR.MDE enables instruction matching. MDSCR.KDE and PSTATE.D gate same-EL debug; PSTATE.D does not mask an EL0 event routed to a higher EL. Interpreter execution owns the complete boundary. Enabled implemented comparators defer native regions, including already compiled bounded, PAuth and legacy test regions. Native code cannot bypass a comparator installed after compilation.

A comparator at a call target saves the preceding branch's PSTATE: direct `B`
and `BL` leave BTYPE zero; indirect `BLR` sets BTYPE to two. The core and SMIR
instruction boundaries apply that distinction before the target executes. Exact
Arm 2025-12 `BL`/`BLR` definitions are retained in the
[PAuth provenance](../../specifications/arm/pauth/PROVENANCE.md). The regression
checks link state, retirement and the unchanged target PSTATE saved on a debug
exception. CPU-profile differences remain explicit: the native Linux control
advertises DebugVer `0xa` and SSBS, while the represented base core advertises
DebugVer `6` and no SSBS in ID_AA64PFR1_EL1. Saved BTYPE must match even when
the SSBS bit differs.

The default core has six breakpoint and four watchpoint register pairs. BRPs/WRPs advertise count minus one and follow configured counts after construction/reset. Construction normalizes both counts to 2..16, the represented bank range. Arm ARM DDI0487B.a, D7-2325, reserves the zero count-field encoding. The existing CTX_CMPs field selects one context-aware comparator at the highest implemented index. No SBSA or native comparator-count qualification is asserted. Malformed private checkpoints with counts outside the represented range fail before installation. The existing checkpoint carries monitor and bank state without a new serialized field, public C ABI layout or version.

| OS personality | Installation and exception behavior |
| --- | --- |
| Windows | Selected CONTEXT debug group shares the existing sanitizer and maintains privileged monitor enable. Direct ARM64 and paired AMD64-to-ARM64 execution return a hardware breakpoint stop. Dispatch uses STATUS_BREAKPOINT, faulting PC and parameter 7, matching the recovered native Windows 29704 instruction control. |
| Darwin | ARM_DEBUG_STATE64 installs the sanitized PCB image in the core. Clearing the last comparator removes it. A general-context validation copy restores this thread's PCB debug image; ordinary new-thread cloning retains fresh initialization. EC 0x30/FSC 0x22 maps to EXC_BREAKPOINT, EXC_ARM_BREAKPOINT and PC. |
| Linux | EC 0x30/FSC 0x22 maps to SIGTRAP/TRAP_HWBKPT with the faulting address and unchanged saved fault record. The native A64 NT_ARM_HW_BREAK regset installs thread-owned perf-style instruction comparators as described below. |

The own-thread [native Darwin control](../../specifications/darwin/native-instruction-debug/README.md) records exact matching, disabled and non-matching cases on Darwin 27.3.0 arm64. That process exits naturally only after checking each result. Its scope is comparator 0, not native comparator counts or watchpoints.

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| A1 | The represented debug profile is the base bank without BWE/ABLE, OS software lock or Root/Realm execution state. | Existing system-register/security-state representation and DebugVer; the general RME feature flag does not establish Realm execution. | Matching and routing | Reserved types, secure disable, VHE/EL2 contexts, linked comparator | A represented extension adds one of these states or matching fields | Confirmed for this represented path |
| A2 | An OS debug-bank installation owns privileged monitor enable from enabled implemented comparators. | Arm CheckDebug requires MDE; Windows/Darwin setters expose user banks without user MDSCR writes. | EL0 comparator execution | Disable the last comparator, unimplemented high slots, context restore, fresh thread | Native or owning OS evidence changes the effective monitor policy | Retained, covered by focused controls and native Darwin probe |
| A3 | The represented comparator counts are 2..16, with ID fields encoding count minus one. | Arm DDI0487B.a D7-2325 and sixteen register slots | ID publication, constructor normalization, checkpoint bounds | Requested 0/1/6/16/255 and malformed checkpoint counts | Owning base profile permits zero field encoding or needs extended banks | Confirmed |

Tests cover all implemented slots, precise PC/retirement/state, enabled/disabled/address/security/privilege controls, same/higher EL routing and D masking, fetch/decode/illegal-state priority, linked contexts, mismatch intersection, VMID/host contexts, checkpoint roundtrip/rejection, warm native paths, OS signal/exception mapping, fresh-thread initialization, context preservation and clearing. Matching uses O(B) time with B <= 16 and O(1) auxiliary space; a linked context adds a bounded single lookup per comparator.

## Linux instruction regset

NT_ARM_HW_BREAK has 4-byte elements and a 264-byte layout: resource information,
padding, then sixteen address/control/padding entries. Information reports the
actual configured breakpoint count and represented DebugVer. A thread owns its
logical comparator objects; even a disabled object consumes one of the configured
hardware slots. Installation packs those objects into the implemented core bank
without altering watchpoint state or unrelated registers.

The setter follows the kernel's field order, including partial failure. Resource
and padding fields are ignored. Each complete address is committed before its
control is processed. Allocated default objects and earlier fields remain after
EINVAL or ENOSPC. Disabled controls ignore non-enable fields. Enabled controls
require a contiguous byte-selection run and execute type; native A64 normalizes
its instruction length to four bytes, adds the byte-selection offset and derives
EL0 privilege from the user address. PTRACE_CONT preserves the armed comparator,
so the same fault repeats until the debugger disarms or moves it. Fork/clone and
exec discard the thread's comparator objects and installed bank.

The [own-child Linux control](../../specifications/linux/native-arm-ptrace/README.md)
records ten native cases and exact partial-write/resource behavior. Its hardware
DebugVer differs from this emulator's base profile; only common semantic rules
are used as expectations. The core capability accessor is private and introduces
no public C ABI field, version or serialized state. A transfer visits at most
sixteen entries, using O(1) time and O(1) auxiliary storage.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| LARM1 | Native A64 ptrace commits addresses/default objects before later control errors, normalizes enabled execute controls, and retains comparators across CONT. | Pinned v6.19 ptrace/hardware paths and ten-case A64 Linux control. | Regset state, installation, error behavior. | Partial address/control, invalid BAS, six-slot exhaustion, repeated fault and disarm. | Controlled native output contradicts field order, normalization or repeated faults. | Confirmed in primary source and native control; model validation recorded separately. |
| LARM2 | Linux fork/clone and exec discard ARM ptrace objects. | ptrace_hw_copy_thread and flush_ptrace_hw_breakpoint in pinned source. | Thread/process/image lifetime. | Armed parent, new thread, in-place process fork reset and exec. | A native child retains its parent's comparator or replacement image retains the bank. | Confirmed in source, focused model lifecycle tests and the own-child native fork/exec control. |

High-impact remaining full-goal boundaries include ARM64 and x86 data
watchpoints, Linux NT_ARM_HW_WATCH and AArch32 debug installation/execution,
and ordinary installed-library Windows process startup. The watch regset remains
unavailable rather than accepting enabled watchpoints without execution support.

Native Windows continuation and installed-NTDLL fault/VEH execution have run on
Windows build 29704.1010. The combined implementation executes the fault fixture
for ARM64, AMD64 and x86 guest ABIs on one ARM64 Windows kernel. The corrected
C API context suite also runs there; its complete packet checks include the ten
normalized ARM64 debug-control words. These results do not qualify independent
physical x64 Windows hardware or complete installed-library process execution.
The AMD64-on-ARM64 native exception-entry frame retains its separate profile.
