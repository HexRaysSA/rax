# Scalar VFP memory operand admission

This change selects Undefined for three unpredictable scalar forms described
by the Arm VLDR and VSTR encodings:

| Form | Selected behavior |
|---|---|
| T32 VSTR with PC as its base | Decode as Undefined for 16-, 32- and 64-bit operands |
| A32 VLDR/VSTR with a 16-bit operand and a non-AL condition | Decode as Undefined, subject to the A32 predicate |
| T32 VLDR/VSTR with a 16-bit operand in an IT block | A failed predicate skips the instruction. A passing predicate selects Undefined before an FP access trap. |

T32 literal VLDR, A32 PC-relative VLDR and VSTR, and general-register
transfers retain their allocated behavior. The decoder and execution checks
use O(1) time and space. No checkpoint or C ABI representation changes.

The standalone baseline linked the production library and ran five
regressions. The legal control passed and four cases failed. At instruction
words `ed8f0902` and `ed800902`, the rejected T32 PC-base and passing-IT
stores both changed the observed 8-byte RAM value from
`0xaabbccdd01020304` to `0xaabbccdd01027788`. The FP16 payload was
`0x7788`. The two decoder regressions observed VSTR before the guard.

Arm's VLDR and VSTR entries specify the condition, IT-block, and base
constraints in decode before `CheckVFPEnabled`.
[Pinned Arm ASL, VLDR](../../architecture/arm/asl/arm_instrs.asl#L65648)
[Pinned Arm ASL, VSTR](../../architecture/arm/asl/arm_instrs.asl#L71577)

Two independent QEMU 11.1.2 guests ran 24 cases. The 10 legal Cortex-A15
controls and 4 legal FP16 controls agreed on the register, RAM, and FPSCR
values. QEMU performed the two unpredictable T32 PC-base stores and all four
unpredictable FP16 transfers with passing predicates. Its four failed
predicate cases left RAM and registers unchanged. These results record
another implementation's choices for the unpredictable forms.

| ID | Assumption and dependent result | Falsification probe | Outcome |
|---|---|---|---|
| S1 | The T32 PC-base restriction applies to scalar stores across the three widths. | Check 960 raw register and offset combinations against A32 stores, T32 literal loads and T32 general-register stores. | Confirmed by decoder tests and the Arm encoding. |
| S2 | The FP16 predicate restrictions apply after predicate evaluation and before access traps and effects. | Exercise both directions under passing and failing predicates and check RAM, D0 and FPSCR. PC-base rejection also checks competing access controls. | Confirmed within the tested profile. |
| S3 | Allocated literal and general-register forms retain exact width and value. | Compare register and RAM masks for 16-, 32- and 64-bit transfers in the RAX tests and the independent QEMU executable. | Confirmed for the recorded controls. |

Remaining A32 profile and admission work is high impact. QEMU's unpredictable
execution choices and physical AArch32 execution remain separate validation
questions. [Qualification](qualification.json)
