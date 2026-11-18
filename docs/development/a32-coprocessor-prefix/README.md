# Unconditional coprocessor routing and FP transfer admission

Unconditional coprocessor words previously passed through ordinary FP transfer
or SVC decoding. `fc410b10` selected VMOV instead of rejecting the FP pair
prefix; `fe000a10` and `fef10a10` selected VMOV and VMRS. `fd900b00`
selected SVC. Generic `fc410010` selected MCR instead of the two-core MCRR
family. The complete baseline target passed 135 tests and failed all four
new regressions, with no ignored or filtered cases.

The correction routes allocated unconditional memory and paired transfers
with bits 27:25 = `110` to the memory/pair decoder. The reserved op1 values
`0xc0` and `0xc1` select Undefined. Unconditional data/core transfers use bits
27:24 = `1110`. Ordinary A32 SVC requires condition bits other than `1111`,
while the Thumb SVC encoding is 16 bits wide. Unconditional ordinary FP
transfer fields select Undefined before the FP core/system handler. The
explicitly allocated VSEL, min/max, directed rounding/conversion and
VMOVX/VINS paths keep priority.
Generic CDP2/MCR2/MRC2 select their existing mnemonic variants. Generic
coprocessor execution remains outside the supported execution profile.

The primary references are archived [Arm ASL](../../architecture/arm/asl/arm_instrs.asl),
entries VMOV_s/d/ss, VMRS, VMSR, VDUP_r, VLDR/VSTR and SVC; and
[Arm DDI0406C.d ID040418](../../specifications/arm/aarch32-fp-profile/armv7ar-ddi0406cd.pdf),
A5.7, Table A5-23, printed page A5-214. The current ASL and DDI0597 manual
also define the ordinary FP prefix exclusions. Extracted
[encoding witnesses](primary-encoding-witnesses.json) and [provenance](provenance.json)
retain source identities. Generic LDC/STC and paired transfers retain the
existing public family representation; no new state format or ABI is added.

The routing predicates use constant time and space. Four regression tests
cover selected invalid pair/core/system/duplication/load/store prefixes over
both instruction sets, every pair of four-bit core/register fields and every
low four-bit field; FP enabled/CPACR denied/Hyp TCP10/FPEXC disabled; unchanged
registers/status on rejection; mixed-width non-retirement; and exact SMIR
unsupported frontiers. Generic non-FP coprocessors 0–7 and 12–15 exercise
all seven allocated memory/pair/data/core family controls and both reserved
memory prefixes. The SVC controls cover A32 conditions 0–15 and 16-bit Thumb.
The existing complete target checks explicitly
allocated unconditional FP extensions independently of these new tests.

The independent Cortex-A15 guest rejects all 18 invalid A32/T32 cases and
completes all eight legal VMOV/VNEG controls, checking exact D0/D1/FPSCR.
[Observations](qemu-observations.json) and the [oracle receipt](qemu-result.json)
record QEMU guest execution. Physical AArch32 execution is unverified.

```sh
python3 docs/development/a32-coprocessor-prefix/qemu-controls.py --out /tmp/rax-coprocessor-prefix-results
```

The destination must not exist. LLVM MC, LLD and QEMU are required; missing
tools fail explicitly. Temporary compilation artifacts are removed.
The [qualification receipt](qualification.json) records the completed decoder
and library runs and their source hashes.

| ID | Assumption and dependent result | Stress test / falsification probe | Status |
|---|---|---|---|
| U1 | Ordinary FP transfer prefixes exclude the unconditional space | Primary fixed fields and 18 QEMU rejections. A primary-defined ordinary FP transfer rejected by the guard falsifies this result. | Confirmed within the represented encodings |
| U2 | Coprocessor families use distinct opcode fields, and SVC requires its allocated prefix | Table A5-23, the SVC encoding guard, both reserved memory prefixes and seven generic family controls. A valid pair, memory, data or core encoding routed to another family falsifies this result. | Confirmed for the stated routing |

High-impact full profile/security/debug, backend/private/in-flight checkpoint,
configured SMP/startup/IRQ/clock/replay and remaining native Intel/ARM
requirements remain open. Generic unsupported coprocessor execution and other
unimplemented encoding classes are outside this correction. The four original
findings remain partial.
