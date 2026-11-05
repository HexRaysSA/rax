# x87 native-reference register constraints

The optimized x86-64 library test exposed a lifetime error in the native x87
reference helper. `FNSTSW AX` executes before the output-buffer pointers are
consumed by `FSTP`. A `lateout("ax")` operand permitted the compiler to put the
pushed-result pointer in RAX. The status write then changed that pointer's low
16 bits before the memory store.

`baseline.disassembly` captures that sequence for both FPTAN and FSINCOS from
the actual failing executable. `baseline.stdout` and `baseline.stderr` record
the isolated failure: the interpreter's pushed value has exponent 16383 while
the native output buffer retains exponent zero. The test source is unchanged
from the published parent; this defect predates PC firmware discovery.

All eight status operands now use `out("ax")`. This reserves AX, including its
overlapping aliases, before the assembly starts. No result tolerance, comparison
mask, interpreter behavior, or admitted guest instruction changes.

The primary contract is [The Rust Reference, inline assembly operand
types](https://doc.rust-lang.org/reference/inline-assembly.html#r-asm.operand-type.supported-operands.lateout):
an early output cannot overlap an input; a late output may overlap only when
inputs are consumed before the output is written. The retrieved local primary
copy and SHA-256 are recorded in `qualification.json`.

Validation is recorded in `qualification.json`. The failing owning target was
compiled for x86-64 macOS and executed through Rosetta on Apple Silicon. This
identifies a compiler-constraint defect; it is not evidence of a physical Intel
arithmetic discrepancy. The separate PC firmware work remains uncommitted.

The complete repaired x86 library run passed 13,412 tests, with five ignored
and one unrelated PC checkpoint diagnostic failure. Its x87 comparisons pass.
The PC failure is corrected in the separate firmware group, whose 22-test PC
target and complete Apple Silicon library run pass. The final firmware x86
run remains independent evidence and is not reported as passed here.

Publication follows the disjoint upstream Windows ARM64EC commit `551302a7`.
The qualification retains the actual compiled source digest and executable
identity; it does not attribute that upstream work to this component.
