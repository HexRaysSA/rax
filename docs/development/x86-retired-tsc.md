# x86 timestamp-counter retirement domain

An explicitly selected retirement clock supplies its exact wrapping retirement
unit count to the existing x86 TSC helper. Previously the helper reconstructed
cycles from integer nanoseconds, dropping one or two fractional cycles. Wall-bound
and unbound execution retain the previous elapsed-nanoseconds times three
conversion. IA32_TSC_ADJUST remains a wrapping cycle offset.

The helper is shared by direct RDTSC/RDTSCP, TSC MSR reads/writes, the existing
legacy PMC profile and the x86 native JIT callback. It now lives in the focused
`cpu_timing.rs` module. Instruction privilege, register-destination, AUX, MSR
validation and PMC-width logic are unchanged. The PMC profile remains independent
of the per-vCPU TSC adjustment. This is a virtual clock policy; retirement units
are not a claim about physical processor cycle counts.

Intel SDM revision 086, December 2024, Volume 2B pages 4-558 through 4-561,
specifies RDTSC/RDTSCP destinations, zero extension and privilege checks. Volume 3B
section 19.17.3 specifies the TSC-adjustment relationship. The archived unmodified
PDF and provenance are under `docs/specifications/x86_64/`; local extraction and
section receipts are retained with the audit evidence. The 3,000,000,000-unit/s
virtual clock is the selected execution policy, not an Intel hardware guarantee.

| ID | Assumption and dependent result | Basis; stress and falsification probe |
|---|---|---|
| X1 | Exact retirement units are the selected cycle domain. | Existing immutable Retired mode and exact unit accessor; read cycles at 0/1/2/1000, above 32 bits and u64 maximum. A fractional loss falsifies routing. |
| X2 | Adjustment stays a wrapping cycle offset. | The existing final wrapping addition is retained; positive and negative offsets and WRMSR rebasing must give exact integer results. |
| X3 | All existing timestamp entry paths share the helper. | Direct instruction/MSR/PMC calls and native JIT callback already call it. Actual guest execution and the callback destination-state regression check these paths. |
| X4 | Wall/unbound policy and instruction controls remain unchanged. | Conditional exact-source selection; previous conversion is byte-identical and the rest of the moved helper's callers are unchanged. Bracketed wall reads and inherited privilege/decoder suites can falsify compatibility. |
| X5 | This evidence does not establish native hardware timing. | The native callback test uses the existing emulator state ABI. Rosetta and local interpreter results do not prove KVM/HVF exact budgets or physical Intel behavior. |

Nine instruction regressions and one library regression cover fractional reads,
AUX and zero extension, TSC MSRs, adjustment/wrap, PMC independence, nested contexts,
wall compatibility and existing JIT callback destinations. An independent integer
model verifies 72 instruction observations and 4,032 exact bytes and rejects a
one-bit mutation in each of the 504 words. The same consumer executes against
actual predecessor/current libraries to expose the old fractional loss.

Counter selection is O(1) time and space, adding a bound-context lookup and clock
mutex read in Retired mode. No physical latency or throughput bound is claimed.

High impact: deterministic default coordination, all architecture timer routing,
full private-state checkpointing and native exact retirement remain open. Medium
impact: the generic SMIR interpreter retains its explicitly supplied `cycle_count`
contract, and the standalone lowering tests retain caller-supplied callbacks.
Low impact: direct and unbounded execution still require explicit clock ownership.
