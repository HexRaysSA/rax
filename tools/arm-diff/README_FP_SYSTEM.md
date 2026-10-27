# A32/T32 floating-point system oracle

This standalone oracle executes selected instructions in a bare-metal QEMU guest
and compares exact state with RAX. It requires Python3.10+, stable Rust, LLVM
(`llvm-mc`/`ld.lld`), and `qemu-system-arm`; no ARM libc/sysroot is required.

```sh
python3 tools/arm-diff/fp_system_oracle.py \
    --llvm-bin /path/to/llvm/bin \
    --work-dir /Users/int/dev/rax-audit-work/rax-a32-fp-system-v4 \
    --target-dir /Users/int/dev/rax-audit-work/rax-a32-fp-system-target
```

Cargo builds with stable Rust, `--locked --offline`, and
`--no-default-features --features x86_64-suite,smir-jit`. The runner links the
exact library artifact identified by Cargo. `--repo`, `--qemu` and `--timeout`
are available; `--llvm-bin` can also be supplied through `LLVM_BIN` or PATH.

Version4 executes231 instruction pairs in both states with32 operand samples
and64 RM/FZ/DN/AHP/FZ16 control profiles:946176 complete comparisons. Samples
include edge bits, seeded operands and initially sticky status. A32/T32 receive
identical inputs. The original144-pair register/numerical corpus is retained. The87 added pairs
cover scalar selection and additional scalar/vector floating operations.
GPR samples have a separate seed stream so prior D/FPSCR inputs remain intact.

Every case must execute and match. Missing tools, timeouts, guest failure,
missing completion markers, short output, source mutation or any mismatch fail
the command. The work directory retains the ELF, input/reference records,
per-instruction counts, mismatch details, command/version/timing records,
source fingerprints, tool hashes and linked-library SHA. A version4 ownership
marker prevents overwriting unrelated directories or older evidence.

The little-endian wire format is fixed:

| Record | Offset (bytes) | Field | Size (bytes) |
| --- | ---: | --- | ---: |
| Input | 0 | State:0 A32,1 T32 | 4 |
| Input | 4 | Instruction word; T32 high halfword first in the word | 4 |
| Input | 8 | FPSCR | 4 |
| Input | 12 | D0-D31 | 256 |
| Input | 268 | R0 | 4 |
| Input | 272 | R1 | 4 |
| Input | 276 | APSR.NZCVQ bits31:27; other bits zero | 4 |
| Result | 0 | D0-D31 | 256 |
| Result | 256 | FPSCR | 4 |
| Result | 260 | R0 | 4 |
| Result | 264 | R1 | 4 |
| Result | 268 | APSR.NZCVQ bits31:27; other bits zero | 4 |

Inputs/results are280/272 bytes, respectively:264929280/257359872 bytes for the
complete corpus. Guest RAM is512MiB. Generation streams input records; the
comparator uses O(N) host buffer memory and O(N) time for N cases with a fixed
register count. All sources and artifact hashes are recorded for reproduction.

The listed operations use registers only. The captured state is complete
D0-D31, FPSCR, R0/R1 and APSR.NZCVQ; other GPRs, PC, memory and exception delivery are not
covered. Exception enables remain clear. This is independent system emulation;
physical A32 hardware, unlisted instructions/profiles and other architectures
require separate validation. The existing Linux user-mode ARM oracle is unchanged.

A separate probe checks the default non-trapping FPSCR register contract:

```sh
python3 tools/arm-diff/fpscr_profile_oracle.py \
    --llvm-bin /path/to/llvm/bin \
    --work-dir /Users/int/dev/rax-audit-work/rax-fpscr-register-oracle
```

It independently checks MVFR0.FPTrap=0 and all32768 combinations of A32/T32
access,64 supported controls and256 exception/reserved-byte values. Bits15:8
read zero; rounding, DN, FZ, AHP, FZ16, NZCV, QC and sticky status remain intact.
Every command must succeed with the exact guest completion marker. Commands,
versions, timings and source/ELF hashes are retained. Optional trapped profiles
and physical A32 hardware are separate validation.

Version4 supplies condition flags independently of FPSCR. Each sample covers one
of the32 NZCVQ combinations; the guest writes APSR before the instruction and
captures it immediately afterward. This is required for VSEL, whose conditions
use APSR. The previous144 instruction pairs do not consume APSR condition flags;
removing the appended fields and new groups preserves their original records.
The version4 ownership marker prevents reuse of older protocol work directories.

## System-register profile probe

`fp_register_profile.py` checks FPSCR and FPEXC through A32/T32 VMSR/VMRS,
using every single bit, every complementary single-bit pattern, boundary values
and4096 seeded random values per state (8328 cases). Run with the same repository,
target and LLVM paths as the numerical oracle:

```sh
python3 tools/arm-diff/fp_register_profile.py --repo . \
    --work-dir /path/to/empty/register-evidence \
    --target-dir /path/to/cargo-target --llvm-bin /path/to/llvm/bin
```

The local selected non-trapping/non-short-vector profile uses FPSCR mask
`0xffc8009f` and FPEXC `(value & 0x40000000) | 0x700`, following Arm
Cortex-A55 FP TRM100446_0200_01 sections4.4/4.8. This specifies register semantics;
it does not identify the entire emulated CPU as a Cortex-A55. The existing
software default keeps FPEXC.EN set, rather than adopting the hardware EN reset.
Raw public `Fpscr` helpers and direct `fpexc` storage remain unmasked; architectural
reads canonicalize their view and guest writes store canonical values.

QEMU11.1.2 `max` retains FPSCR.Len/Stride and returns zero for FPEXC bits10:8.
The tool retains its unmodified binary output and reports these raw profile
differences. Independent comparison projects out precisely FPSCR bits21:20/18:16
and FPEXC bits10:8; every other bit must match. RAX is separately checked against
the complete primary-source profile mask. A passing projected comparison is
not evidence of full QEMU/register-profile equivalence. Physical A32 validation
and other processor profiles remain separate. The QEMU MVFR values are reported
as evidence and do not certify RAX's capability declarations.

The version2 register probe adds ID_ISAR6 to a16-byte capability header. It
requires MVFR0=`0x10110222`, MVFR1=`0x13211111`, MVFR2=`0x43`, and
ID_ISAR6.FHM=`1` from independent QEMU execution, and checks RAX's corresponding
A32/T32 guest reads. RAX ID_ISAR6 advertises only FHM (`0x100`); other optional
ISAR6 extensions are not inferred from the QEMU `max` model. The8328 register
records and prior12-byte capability header remain byte-identical after removal
of the new header word. The projected register-profile limitations above still
apply; feature bits do not certify unlisted instructions or an entire CPU model.

## CPACR access-control probe

`fp_access_oracle.py` runs48 cases of scalar arithmetic, Advanced SIMD integer
arithmetic, FPSCR reads and FPEXC reads in A32/T32, User/Supervisor modes, and
CPACR.cp10 values0/1/3. The bare-metal guest installs Undefined/SVC vectors,
captures actual denial, returns past the32-bit faulting instruction and verifies
each expected result plus the exact final counter. It produces26 denied and22
permitted controls; the comparator also requires denied RAX cases to preserve
registers, FP state and CPSR. Use the same `--repo`, `--work-dir`, `--target-dir`
and `--llvm-bin` arguments as the register-profile probe.

The direct executor checks CPACR.cp10 after a failed instruction predicate can
skip execution and before any FP handler can modify state or access memory.
Value0 denies access;1 permits privileged access;3 permits User and privileged
access. Reserved value2 takes an explicit Undefined policy, tested locally
rather than equated to a specific physical outcome. In the selected modern
AArch32 FP profile, cp11 is not a second permission gate. FPEXC.EN and the
privilege restrictions on non-FPSCR system registers retain their separate checks.

`Armv7Cpu::new()` preserves its effective enabled-FP software default by enabling
CPACR.cp10/cp11 alongside FPEXC.EN. `Cp15State::new()` retains reset permission
bits0. This is a software-context default, not a hardware reset claim. The
control probe does not establish NSACR/HCPTR/CPTR_EL3, unmodelled Hyp state,
CPACR.ASEDIS/D32DIS or every reserved coprocessor encoding.

The AArch32 vCPU backend delivers architectural Undefined faults through the
guest vector without retiring the faulting instruction. SPSR preserves the old
CPSR; LR uses A32+4/T32+2, and handler state applies SCTLR.TE/EE while clearing
IT. Explicit unsupported decoded results retain their `InvalidInstruction` host
error. Local backend regressions cover24 permission/enable cases and48 complete
frames; the independent48-case probe covers actual default-handler exception
delivery. Handler TE/EE variants rely on the pinned Arm EnterMode contract and
are not claimed as separately executed independent hardware cases.


## ASEDIS and FPEXC access probe

`fp_simd_access_oracle.py` uses the same repository, target, work-directory and
LLVM arguments as the CPACR probe. It executes336 actual instructions in QEMU
Cortex-A15 TCG:11 Advanced SIMD and10 VFP operations in A32/T32,
User/Supervisor, ASEDIS0/1 and FPEXC.EN0/1. Each24-byte input record holds six
little-endian u32 fields: Thumb, User, ASEDIS, FPEXC.EN, instruction word and
observed Undefined outcome (8064 bytes total). The guest records336 outcome
bytes and requires an exact completion marker. Time and host storage are O(N)
for N fixed-size cases; guest RAM is128MiB.

The primary-source contract, Arm `AArch32.CheckAdvSIMDOrFPEnabled`, requires212
Undefined outcomes and124 permitted outcomes. QEMU11.1.2 reads ASEDIS back but
ignores it during these44 enabled SIMD cases: its raw output has168 Undefined
and168 permitted outcomes. The tool retains all44 differences and requires
exactly this partition. It separately requires RAX to satisfy the full primary
contract and preserve GPRs, D0-D31, FPSCR, FPEXC and CPSR on denial. Thus292
reference outcomes agree; the44 ASEDIS cases are primary-source checks, not
independent matches. A changed reference partition fails for review.

The selected modern FP profile implements CPACR.ASEDIS and cp10/cp11; other
CPACR fields read zero and ignore writes. D32DIS bit30 is RES0 in the pinned
Cortex-A75 CPACR register diagram, so D16-D31 accesses remain permitted when
other controls allow them. The raw `Cpacr` utility remains unmasked. This is a
selected FP-register profile, not an identification of the whole CPU model.
Local tests additionally cover FP16/FHM, failed predicates, memory denial before
any access and the reserved-bit mask. The Cortex-A15 probe cannot confirm the
modern D32DIS policy or FP16/FHM execution. NSACR, virtualization/security traps,
unmodelled Hyp state and physical A32 execution remain separate requirements.
