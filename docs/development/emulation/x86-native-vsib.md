# Native EVEX gather/scatter boundaries

## Implemented contract

The x86-64 native backend recognizes the complete EVEX `66.0F38`
`90`–`93` and `A0`–`A3` VSIB families at 128-, 256-, and 512-bit vector
lengths. This is 16 mnemonic/data-index combinations times three vector
lengths. VEX gather, prefetch, and compatibility-mode native execution are
not part of this implementation.

Admission binds exact instruction bytes to the complete lifted instruction
graph. Internal virtual registers cannot escape into another instruction,
block, phi, or terminator. Neither a predicated memory node nor a partial
mask-update sequence is admitted independently. The lowerer requires the
full vector/mask helper bridge; pure VSIB code needs host AVX512F, not a host
gather/scatter instruction. Additional instructions in a region may require
additional host features.

For vector length `VL` bits and element sizes `D` and `I` bits, the lane
count is `min(VL / D, VL / I)`, at most 16. RAX processes active lanes in
ascending order. Each active lane invokes one ordinary checked MMU helper;
successful gather data and the cleared mask bit commit before the next lane.
Scatter stores commit before their mask bits clear. A later failed helper
returns at the same guest instruction PC with all earlier commits retained.
An empty active mask performs no data-memory access. Completion clears the
whole mask and the architecturally unused gather destination bits.

Address calculation uses wrapping two’s-complement arithmetic:

```text
effective = base + sign_extend(index[lane]) * scale + displacement
linear    = (effective mod 2^32) + segment_base   [address size 32 bits]
linear    = (effective mod 2^64) + segment_base   [address size 64 bits]
```

The segment addition also wraps to 64 bits; the checked guest MMU then
validates the resulting linear access. A disp8 displacement is sign-extended
and multiplied by the data-element size in bytes. FS/GS addition follows
address-size truncation. APX B4 extends a used general-purpose base, not the
vector index; unused extension bits do not create a feature requirement.
The per-instruction CS.L guard and any required APX guard run before mask,
destination, or memory changes.

## Verification and self-modifying code

The scalar store helper defers code-page writes before modifying memory.
The direct interpreter resumes using the remaining mask and normal
decode-cache invalidation, including an instruction that overwrites itself.
In verification mode, an unreadable pre-store snapshot likewise defers that
unperformed store while retaining the undo log for earlier stores.
The owning CPU run loop consumes a one-shot direct-restart PC after a
deferred VSIB helper or mode/feature guard. A cached region whose entry is
the deferred instruction cannot repeatedly re-enter without delivering the
guest fault or completing the interpreter-side code-page store. Ordinary
native backward-edge yields do not request this direct step.

The append-only `GuestRegs` fields `x86_vsib_frontier_lane_plus_one` and
`x86_vsib_instruction_ordinal` identify the terminal lane and its dynamic
instruction occurrence. Zero in the lane field denotes an ordinary frontier.
The ordinal counts native VSIB entries, including empty-mask completions;
direct interpreter callouts do not increment it. Repeated visits to one PC
therefore do not collapse to the first visit during verification.

The verifier restores the entry state, replays preceding instructions, and
validates the terminal cached bytes, current bytes, mode, active mask bit,
and lane range. A verification-only direct-execution marker stops before the
terminal active lane. All earlier lane values, addresses, and mask updates
are reconstructed by the direct semantics, not copied from native results.
At a partial VSIB frontier, flags-only differences are fatal, and MXCSR and
all 32 general-purpose registers participate in the comparison.

The expected partial-prefix access values/order are compared with the native
trace suffix. This is not a general proof of the total dynamic access count:
an extra duplicate access before that suffix can evade this trace comparison.
Separate emitted-code and execution tests check the generated per-lane
helper counts. Missing or overflowed verification evidence at a partial
frontier is reported as unverifiable instead of silently adopting that result.

## Ownership and validation

The byte classifier is under `smir/ir/x86_native_replay/classifiers/`;
the exact graph and virtual-closure checks are under
`smir/lower/runtime/trampolines/`. Host emission is in
`smir/lower/x86_64/evex_vsib_memory.rs` and `jit_scalar_memory.rs`.
CPU verification and scalar store logging are separated into
`isa/x86_64/cpu_jit_verify.rs` and `cpu_jit_mem_store.rs`; the owning run
loop is in `isa/x86_64/cpu_run.rs`.

Focused commands, followed by the full affected binaries and CI gates:

```sh
cargo +stable test --locked --no-default-features --features x86_64-suite,smir-jit --lib vsib -- --nocapture
cargo +stable test --locked --no-default-features --features x86_64-suite,smir-jit --test x86_64_avx512_inventory report_evex_spec_forms_ -- --ignored --nocapture
```

Native tests must run on a supporting x86-64 host. A cfg-empty target or an
explicit host-feature skip is compilation evidence, not native execution
evidence. The existing all-masked-MXCSR region policy remains a conservative
admission restriction even for integer-only VSIB regions.

## Architectural sources

- [Intel SDM](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf),
  Volume 2, gather/scatter instruction descriptions and Type E12 exception
  class: partial completion, mask updates, VSIB address calculation, and
  fault ordering. Ascending-lane completion is RAX’s repeatable legal order.
- [Intel APX specification, revision 7.0](../../specifications/x86_64/355828-007-intel-apx-spec.pdf),
  section 3.1.2.3.3 and Table 3.3: existing EVEX memory-base extension.
  [Archive provenance](../../specifications/x86_64/355828-007-intel-apx-spec.provenance.md)
  records the original URL, date, size, and checksum.
