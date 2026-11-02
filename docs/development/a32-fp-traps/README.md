# Optional synchronous floating-point trapping

RAX's default scalar profile remains `MVFR0.FPTrap=0`. Trusted host metadata
can select `FPTrap=1`; guest ID-register writes do not select a profile.
The selected profile now implements writable exception enables and synchronous
whole-instruction FP exception collection. It uses the private support-code
FPSID subarchitecture `0x41`; the restricted nontrapping profile uses `0x40`.
These identifiers do not assert a physical vendor assignment.

The controls are represented by existing CPU/context fields; no serialized
register field or public C record layout is added. Architectural and complete
private checkpoint APIs retain their existing distinction.

| Field | Selected trapping profile | Default nontrapping profile |
|---|---|---|
| FPSCR exception enables | `0x00009f00` writable | RES0 |
| FPEXC writable bits | `0x6000009f` | `0x40000000` |
| FPEXC TFV | status/WI; RAO/WI without short vectors | RAZ/WI |
| FPEXC fixed bits | `0x00000700` RES1 | `0x00000700` RES1 |
| FPSID subarchitecture | private `0x41` | existing profile-dependent view |
| A64 FPCR enables | retained for selected profile | existing RES0 view |

## Instruction boundary

The exception flag mask is `M=0x9f` (IOC, DZC, OFC, UFC, IXC, IDC).
Collection keeps the enable controls active: exact subnormal arithmetic can
raise trapped underflow even without inexact rounding. Previously sticky flags
are excluded from this instruction's newly raised causes.

Let `S` be previous cumulative flags, `C` the newly collected status, and `T`
the enabled exceptions actually trapped. Output flushing sets cumulative UFC
without trapping, so it is excluded from `T` even when UFE is set.

- If `T == 0`, commit destinations and retain cumulative flags `S | C`.
- Otherwise, preserve destinations, retain `S | (C & ~T)`, report `T`, and
  retire zero instructions.

A64 status producers retain their operand/result precision during underflow
collection. The interpreter uses a host-thread-local, scoped accumulator that
is restored on return or unwind. It is absent from architectural/private
checkpoint records because it exists only inside one synchronous pure
computation. System/memory transfers never enter it. Ordinary half arithmetic
shares the controlled binary16 rounding core, including output flushing and
fused rounding. Exact SVE binary64 scaling compares integer significands and
exponents rather than assuming every subnormal result is inexact.

Predication and capability/access admission keep their earlier priority.
Memory and system-register transfers keep their own access count and permitted
partial completion; they do not process stored IEEE operands.

```text
predicate/access admission -> collect newly raised flags
                                  |
                     +------------+------------+
                     |                         |
                no enabled cause          enabled cause
                     |                         |
              commit destinations      preserve destinations
              merge sticky flags       retain unenabled flags
              retire once              report trap; retire zero
```

A32 local delivery sets FPEXC.DEX/TFV and exception flags, with VECITR=`111`,
then enters Undefined using the existing local/Hyp routing rules. A32 execution
under an A64 handler reports EC=`0x28`; A64 computation reports EC=`0x2c`.
The valid syndrome reports TFV=1 and the enabled trapped causes. A32-to-A64
VECITR is `111`; A64 VECITR is the
permitted zero choice for architecturally UNKNOWN bits. EL1/TGE delivery targets
EL2; exceptions at EL2/EL3 remain at that EL. Fault PC and IT are not retired.

The mixed-width state bridge preserves enables and unenabled cumulative status.
Native compilation and every cached/native entry reject execution while the
selected profile has active enables; interpretation supplies the trap semantics.
This deliberately also rejects integer-only regions in that selected context.
No native optional-trap execution claim follows from this fallback.

The Linux personality models arm64 and its A32 CONFIG_COMPAT ABI. Both adapters
send SIGFPE using the pinned kernel handler's ordered syndrome flags and leave
the existing per-thread fault record untouched. The C adapter uses its existing
exception record, with the faulting PC and syndrome; its public default profile
is unchanged.

## Evidence and bounds

See [qualification.json](qualification.json) for exact baseline failures,
commands, executable/source identities, actual test counts, assumptions,
excluded failed build attempts, and limitations. The 1/2/4-CPU tests write and
load actual complete S3C files before and after trap delivery, execute guest
acknowledgment/exception return/retry, and compare uninterrupted continuation.
They use explicitly prepared CPU contexts, not architectural AP startup.

Primary architectural sources are the retained Arm ASL functions
`FPProcessException`, `AArch32.GeneralExceptionsToAArch64`,
`AArch32.FPTrappedException`, `AArch64.FPTrappedException`, and
`ExceptionSyndrome` in `docs/architecture/arm/asl/arm_defs.asl`, together with
DDI0406C.d B4.1.59 for the private FPSID support-code view and DDI0487B.a
G6.2.49 / D7.2.32 for FPEXC / FPEXC32_EL2 status and write masks. The retained
[Linux v6.19 source](linux-v6.19-fpsimd.c) and [provenance](linux-primary.json)
identify `do_fpsimd_exc`. LLVM verifies the instruction bytes only.

The transaction uses fixed represented register storage: O(1) extra space and
O(L) arithmetic time for L executed lanes; the selected fixed register/vector
limits bound L. The default nontrapping path takes no register snapshot.

Newer FP8/BF16/FPMR and streaming profiles are outside this classic IEEE
16/32/64 and selected non-streaming SVE qualification. Physical optional A32/A64
trapping hardware, physical Intel HVF, arbitrary native
private state, full architectural CPU startup/interrupt coherence, and complete
external-input/entropy replay remain unverified or unfinished as recorded in the
main audit ledger. This component does not close A32-FP, C-STATE, C-SMP, or C-HVF.
