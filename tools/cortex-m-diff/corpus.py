"""ARMv7E-M (Cortex-M4) integer Thumb corpus for the QEMU differential oracle.

Each entry is one case: one or more instructions executed from a known
register/flag/memory state until the fall-through end of the case.
Register conventions: r1/r2/r4 sources, r3/r4 destinations, r5 = DATA+0x80,
r6 = small index.
"""

CORPUS = []


def add(*items):
    CORPUS.extend(items)


# --- data processing, modified immediate --------------------------------------
add(
    "and.w r3, r1, #0xff00ff00", "ands.w r3, r1, #0x80000000", "ands.w r3, r1, #0xff",
    "tst.w r1, #0x00ff00ff", "tst.w r1, #0x80000000",
    "bic.w r3, r1, #0x3fc", "bics.w r3, r1, #0xf0000000",
    "orr.w r3, r1, #0x55555555", "orrs.w r3, r1, #0x40000000",
    "orn r3, r1, #0xff", "orns r3, r1, #0xf0000000",
    "mov.w r3, #0x00ab00ab", "movs.w r3, #0x80000000", "movs.w r3, #0", "movs.w r3, #0xff",
    "mvn.w r3, #0xff", "mvns.w r3, #0x3fc00000",
    "eor.w r3, r1, #0x7f800000", "eors.w r3, r1, #0x80000000",
    "teq.w r1, #0x80000000",
    "add.w r3, r1, #0xff000000", "adds.w r3, r1, #0x80000000", "adds.w r3, r1, #1",
    "cmn.w r1, #0x10000", "cmn.w r1, #0x80000000",
    "adc r3, r1, #0xff", "adcs r3, r1, #0x80000000",
    "sbc r3, r1, #1", "sbcs r3, r1, #0x7f000000",
    "sub.w r3, r1, #0x100", "subs.w r3, r1, #0x80000000", "subs.w r3, r1, #1",
    "cmp.w r1, #0x80000000", "cmp.w r2, #0x13",
    "rsb.w r3, r1, #0", "rsbs.w r3, r1, #0x100",
    "add.w r3, sp, #0x100", "sub.w r3, sp, #16", "adds.w r3, sp, #4",
)

# --- data processing, plain binary immediate ----------------------------------
add(
    "addw r3, r1, #0xfff", "addw r3, sp, #4", "subw r3, r1, #0xabc", "subw r3, sp, #0x10",
    "addw r3, pc, #0x123", "subw r3, pc, #0x21",
    "movw r3, #0xffff", "movw r3, #0", "movw r3, #0x1234",
    "movt r3, #0xabcd", "movt r1, #0",
    "ssat r3, #1, r1", "ssat r3, #32, r1, lsl #4", "ssat r3, #16, r1, asr #8", "ssat r3, #8, r2",
    "ssat r3, #8, r1, asr #31",
    "usat r3, #0, r1", "usat r3, #31, r1", "usat r3, #8, r1, asr #31", "usat r3, #16, r2, lsl #3",
    "ssat16 r3, #8, r1", "ssat16 r3, #1, r2", "usat16 r3, #4, r1", "usat16 r3, #15, r2",
    "sbfx r3, r1, #0, #32", "sbfx r3, r1, #31, #1", "sbfx r3, r1, #4, #12",
    "ubfx r3, r1, #0, #1", "ubfx r3, r1, #28, #4", "ubfx r3, r1, #0, #32",
    "bfi r3, r1, #0, #32", "bfi r3, r1, #31, #1", "bfi r3, r1, #8, #12",
    "bfc r3, #0, #32", "bfc r3, #31, #1", "bfc r3, #4, #8",
)

# --- data processing, shifted register ----------------------------------------
add(
    "and.w r3, r1, r2, lsl #7", "ands.w r3, r1, r2, lsr #1", "ands.w r3, r1, r2, lsr #32",
    "bic.w r3, r1, r2, asr #32", "bics.w r3, r1, r2, ror #4",
    "orr.w r3, r1, r2, rrx", "orrs.w r3, r1, r2, rrx",
    "orn r3, r1, r2, lsl #16", "orns r3, r1, r2, asr #1",
    "eor.w r3, r1, r2", "eors.w r3, r1, r2, asr #3",
    "teq.w r1, r2, lsl #1", "tst.w r1, r2, ror #31",
    "lsl.w r3, r1, #5", "movs.w r3, r1", "mvn.w r3, r2, asr #7", "mvns.w r3, r1",
    "lsls.w r3, r1, #1", "lsrs.w r3, r1, #32", "asrs.w r3, r1, #32", "rors.w r3, r1, #16",
    "rrxs r3, r1", "rrx r3, r1",
    "add.w r3, r1, r2, lsl #31", "adds.w r3, r1, r2", "adds.w r3, r1, r1",
    "adc.w r3, r1, r2, lsr #2", "adcs.w r3, r1, r2",
    "sbc.w r3, r1, r2", "sbcs.w r3, r1, r2",
    "sub.w r3, r1, r2, asr #4", "subs.w r3, r1, r2", "subs.w r3, r2, r1",
    "rsb r3, r1, r2, lsl #2", "rsbs r3, r1, r2",
    "cmn.w r1, r2", "cmp.w r1, r2, lsl #1", "cmp.w r2, r1",
    "pkhbt r3, r1, r2, lsl #8", "pkhbt r3, r1, r2", "pkhtb r3, r1, r2, asr #8",
    "pkhtb r3, r1, r2, asr #32",
    "add.w r3, sp, r1, lsl #2", "sub.w r3, sp, r2",
)

# --- register-controlled shifts -------------------------------------------------
add(
    "lsl.w r3, r1, r2", "lsls.w r3, r1, r2", "lsr.w r3, r1, r2", "lsrs.w r3, r1, r2",
    "asr.w r3, r1, r2", "asrs.w r3, r1, r2", "ror.w r3, r1, r2", "rors.w r3, r1, r2",
    "lsls.w r3, r1, r10", "lsrs.w r3, r1, r9", "asrs.w r3, r7, r9", "rors.w r3, r1, r7",
)

# --- extend ---------------------------------------------------------------------
add(
    "sxtb.w r3, r1, ror #8", "sxth.w r3, r1, ror #16", "uxtb.w r3, r1, ror #24", "uxth.w r3, r1",
    "sxtb16 r3, r1, ror #8", "uxtb16 r3, r1", "sxtb16 r3, r2",
    "sxtab r3, r2, r1, ror #8", "sxtah r3, r2, r1", "uxtab r3, r2, r1, ror #16", "uxtah r3, r2, r1",
    "sxtab16 r3, r2, r1", "uxtab16 r3, r2, r1, ror #24",
)

# --- parallel add/subtract --------------------------------------------------------
for prefix in ("s", "q", "sh", "u", "uq", "uh"):
    for op in ("add16", "asx", "sax", "sub16", "add8", "sub8"):
        add(f"{prefix}{op} r3, r1, r2")

# --- miscellaneous ----------------------------------------------------------------
add(
    "qadd r3, r1, r2", "qsub r3, r1, r2", "qdadd r3, r1, r2", "qdsub r3, r1, r2",
    "qadd r3, r7, r7", "qsub r3, r7, r8",
    "rev.w r3, r1", "rev16.w r3, r1", "revsh.w r3, r1", "rbit r3, r1",
    "sel r3, r1, r2", "clz r3, r1", "clz r3, r0", "clz r3, r3",
)

# --- multiply ---------------------------------------------------------------------
add(
    "mul r3, r1, r2", "muls r2, r1, r2", "mla r3, r1, r2, r4", "mls r3, r1, r2, r4",
    "smulbb r3, r1, r2", "smulbt r3, r1, r2", "smultb r3, r1, r2", "smultt r3, r1, r2",
    "smlabb r3, r1, r2, r4", "smlabt r3, r1, r2, r4", "smlatb r3, r1, r2, r4", "smlatt r3, r1, r2, r4",
    "smlabb r3, r7, r7, r8",
    "smulwb r3, r1, r2", "smulwt r3, r1, r2", "smlawb r3, r1, r2, r4", "smlawt r3, r1, r2, r4",
    "smuad r3, r1, r2", "smuadx r3, r1, r2", "smusd r3, r1, r2", "smusdx r3, r1, r2",
    "smlad r3, r1, r2, r4", "smladx r3, r1, r2, r4", "smlsd r3, r1, r2, r4", "smlsdx r3, r1, r2, r4",
    "smuad r3, r11, r11",
    "smmul r3, r1, r2", "smmulr r3, r1, r2", "smmla r3, r1, r2, r4", "smmlar r3, r1, r2, r4",
    "smmls r3, r1, r2, r4", "smmlsr r3, r1, r2, r4",
    "usad8 r3, r1, r2", "usada8 r3, r1, r2, r4",
    "smull r3, r4, r1, r2", "umull r3, r4, r1, r2", "smlal r3, r4, r1, r2", "umlal r3, r4, r1, r2",
    "smlalbb r3, r4, r1, r2", "smlalbt r3, r4, r1, r2", "smlaltb r3, r4, r1, r2", "smlaltt r3, r4, r1, r2",
    "smlald r3, r4, r1, r2", "smlaldx r3, r4, r1, r2", "smlsld r3, r4, r1, r2", "smlsldx r3, r4, r1, r2",
    "umaal r3, r4, r1, r2",
    "sdiv r3, r1, r2", "udiv r3, r1, r2", "sdiv r3, r7, r9", "udiv r3, r9, r2",
)

# --- 16-bit data processing (outside IT: flag-setting forms) --------------------------
add(
    "lsls r3, r1, #4", "lsrs r3, r1, #32", "lsrs r3, r1, #1", "asrs r3, r1, #1", "asrs r3, r1, #32",
    "lsls r3, r1, #0",
    "adds r3, r1, r2", "subs r3, r1, r2", "adds r3, r1, #7", "subs r3, r1, #7",
    "movs r3, #0xff", "movs r3, #0", "cmp r1, #0x13", "cmp r2, #0x13", "adds r3, #200", "subs r3, #200",
    "ands r3, r1", "eors r3, r1", "lsls r3, r2", "lsrs r3, r2", "asrs r3, r2", "adcs r3, r1",
    "sbcs r3, r1", "rors r3, r2", "tst r3, r1", "rsbs r3, r1, #0", "cmp r3, r1", "cmn r3, r1",
    "orrs r3, r1", "muls r3, r1, r3", "bics r3, r1", "mvns r3, r1", "movs r3, r1",
    "add r3, r8", "add r8, r3", "mov r3, r8", "mov r8, r3", "cmp r3, r8", "cmp r8, r3",
    "add r3, sp, #16", "add sp, #16", "sub sp, #16", "add r3, sp",
    "adr r3, #8", "mov r3, pc", "add r3, pc",
    "sxtb r3, r1", "sxth r3, r1", "uxtb r3, r1", "uxth r3, r1",
    "rev r3, r1", "rev16 r3, r1", "revsh r3, r1",
)

# --- 16-bit loads/stores ----------------------------------------------------------
add(
    "ldr r3, [pc, #4]", "ldr r3, [sp, #4]", "str r1, [sp, #8]",
    "ldr r3, [r5, #4]", "ldrb r3, [r5, #31]", "ldrh r3, [r5, #2]",
    "str r1, [r5, #4]", "strb r1, [r5, #3]", "strh r1, [r5, #6]",
    "ldr r3, [r5, r6]", "ldrb r3, [r5, r6]", "ldrh r3, [r5, r6]",
    "ldrsb r3, [r5, r6]", "ldrsh r3, [r5, r6]",
    "str r1, [r5, r6]", "strb r1, [r5, r6]", "strh r1, [r5, r6]",
    "push {r1, r2, lr}", "pop {r1, r2}", "push {r3}", "pop {r3, r4}",
    "stm r5!, {r1, r2, r3}", "ldm r5!, {r1, r2}", "ldm r5, {r1, r5}",
)

# --- 32-bit loads/stores ----------------------------------------------------------
add(
    "ldr.w r3, [r5, #0x7c]", "ldr r3, [r5, #-0x80]", "ldr r3, [r5, #4]!", "ldr r3, [r5], #-8",
    "ldrb.w r3, [r5, #0x7f]", "ldrb r3, [r5, #-1]", "ldrsb.w r3, [r5, #-0x80]",
    "ldrh.w r3, [r5, #0x10]", "ldrsh.w r3, [r5, #0x11]", "ldrsh r3, [r5], #2", "ldrsb r3, [r5, #-3]!",
    "ldr.w r3, [r5, r6, lsl #2]", "ldrb.w r3, [r5, r6, lsl #1]", "ldrsh.w r3, [r5, r6, lsl #1]",
    "ldrh.w r3, [r5, r6]", "ldrsb.w r3, [r5, r6]",
    "ldr.w r3, [pc, #-8]", "ldrb.w r3, [pc, #3]", "ldrh.w r3, [pc, #-2]", "ldrsh.w r3, [pc, #6]",
    "ldrt r3, [r5, #4]", "strt r1, [r5, #8]", "ldrbt r3, [r5, #1]", "ldrsht r3, [r5, #2]",
    "strbt r1, [r5, #5]", "strht r1, [r5, #6]", "ldrsbt r3, [r5, #7]", "ldrht r3, [r5, #9]",
    "str.w r1, [r5, #0x7c]", "str r1, [r5, #-4]!", "str r1, [r5], #4",
    "strb.w r1, [r5, #0x33]", "strh r1, [r5, #-0x11]", "strb r1, [r5], #-1", "strh r1, [r5, #2]!",
    "str.w r1, [r5, r6, lsl #1]", "strb.w r1, [r5, r6]", "strh.w r1, [r5, r6, lsl #3]",
    "ldrd r3, r4, [r5, #-8]", "ldrd r3, r4, [r5, #16]!", "ldrd r3, r4, [r5], #-16",
    "strd r1, r2, [r5, #8]", "strd r1, r2, [r5, #-8]!", "strd r1, r2, [r5], #24",
    "ldrd r3, r4, [pc, #-4]",
    "ldm.w r5, {r1, r2, r3, r4}", "ldm.w r5!, {r1, r2, r3, r4}", "ldmdb r5, {r1, r2}",
    "ldmdb r5!, {r1, r2, r3}", "stm.w r5, {r1, r2, r3}", "stm.w r5!, {r1, r2, r3, r4}",
    "stmdb r5!, {r1, r2}", "stmdb r5, {r1, r2, r3, r4, r6}",
    "push.w {r1, r2, r4, r8, lr}", "pop.w {r1, r2, r3, r4}", "push.w {r8}", "pop.w {r8}",
    "ldr r3, [sp, #-4]",
    "ldrex r3, [r5, #4]", "ldrexb r3, [r5]", "ldrexh r3, [r5]", "strex r4, r1, [r5]",
    "ldrex r3, [r5]\nstrex r4, r1, [r5]", "ldrexb r3, [r5]\nstrexb r4, r1, [r5]",
    "ldrexh r3, [r5]\nstrexh r4, r1, [r5]", "ldrex r3, [r5, #8]\nstrex r4, r2, [r5, #8]",
    "ldrex r3, [r5]\nclrex\nstrex r4, r1, [r5]",
    "pld [r5, #4]", "pld [r5, r6]", "pli [r5, #8]",
)

# --- hints, barriers, special registers ------------------------------------------------
add(
    "nop", "nop.w", "yield", "dmb sy", "dsb sy", "isb sy",
    "mrs r3, apsr", "msr apsr_nzcvq, r1", "msr apsr_g, r2", "msr apsr_nzcvqg, r10",
    "mrs r3, xpsr", "mrs r3, ipsr", "mrs r3, epsr", "mrs r3, iapsr",
    "mrs r3, primask", "mrs r3, faultmask", "mrs r3, basepri", "mrs r3, control",
    "mrs r3, msp", "mrs r3, psp",
    "msr basepri, r1\nmrs r3, basepri", "msr basepri, r2\nmrs r3, basepri",
    "msr basepri_max, r9\nmrs r3, basepri",
    "cpsid i\nmrs r3, primask", "cpsid i\ncpsie i\nmrs r3, primask",
    "cpsid f\nmrs r3, faultmask\ncpsie f", "msr primask, r0\nmrs r3, primask",
    "msr psp, r1\nmrs r3, psp",
)

# --- IT blocks -----------------------------------------------------------------------
add(
    "ite eq\naddeq r3, r1, r2\nsubne r3, r1, r2",
    "itt ne\nmovne r3, #1\nmovne r4, #2",
    "it cs\nlslcs r3, r1, #2",
    "itete mi\naddmi r3, r1, r2\nsubpl r3, r1, r2\nandmi r4, r1\norrpl r4, r1",
    "it eq\naddseq.w r3, r1, r2",
    "cmp r1, r2\nit gt\nmovgt r3, #5",
    "cmp r1, r2\nite lt\nmovlt r3, r1\nmovge r3, r2",
    "ittt hi\naddhi.w r3, r1, #1\nldrhi r4, [r5]\nstrhi r1, [r5, #4]",
    "it vs\nmovvs r3, #7",
    "it al\nmovs r3, #7",
    "itttt ge\nmovge r3, #1\naddge r3, r3, #2\nmulge r3, r3, r3\nlslge r3, r3, #1",
    "ite ls\nmvnls r3, r1\nrsbhi r3, r1, #0",
)

# --- branches --------------------------------------------------------------------------
add(
    "b.w 1f\nmovs r3, #1\n1:",
    "b 1f\nmovs r3, #1\n1:",
    "bl 1f\nmovs r3, #1\n1:",
    "cbz r0, 1f\nmovs r3, #1\n1:",
    "cbnz r0, 1f\nmovs r3, #1\n1:",
    "cmp r1, r2\nbgt.w 1f\nmovs r3, #1\n1:",
    "cmp r1, r2\nblt 1f\nmovs r3, #1\n1:",
    "beq 1f\nmovs r3, #1\n1:",
    "bne.w 1f\nmovs r3, #1\n1:",
    "adr r3, 1f\nadds r3, #1\nblx r3\nmovs r4, #1\n.p2align 2\n1:",
    "adr r3, 1f\nadds r3, #1\nbx r3\nmovs r4, #1\n.p2align 2\n1:",
    "adr r3, 1f\nadds r3, #1\nmov pc, r3\nmovs r4, #1\n.p2align 2\n1:",
    "movs r6, #1\ntbb [pc, r6]\n.byte 0, 2\nmovs r3, #1\nmovs r4, #2",
    "movs r6, #1\ntbh [pc, r6, lsl #1]\n.hword 0, 2\nmovs r3, #1\nmovs r4, #2",
    "it eq\nbeq 1f\nmovs r3, #9\n1:",
)

# --- exceptions -----------------------------------------------------------------------
# The SVCall handler adds 1 to the stacked R0, clobbers R1-R3 and the flags,
# and returns through BX LR (SVC #0), POP {..., PC} (#1), or LDR PC (#2).
add(
    "svc #0", "svc #1", "svc #2",
    "sub sp, #4\nsvc #0\nadd sp, #4",
    "itt ne\nsvcne #0\nmovne r3, #9",
    "ite eq\nsvceq #1\nsvcne #2",
    "ldr r0, =0x20007000\nmsr psp, r0\nmovs r0, #2\nmsr control, r0\nisb\nsvc #1\n"
    "mrs r4, psp\nmrs r6, control\nmovs r0, #0\nmsr control, r0\nisb",
)
# Faults: every other exception records its state instead of returning.
add(
    "cpsid i\nsvc #0",
    "bkpt #1",
    "adds r5, #2\nldrd r3, r4, [r5]",
    "adds r5, #1\nldm r5, {r1, r2}",
    "adds r5, #1\nldrexh r3, [r5]",
    "movs r0, #0\nbx r0",
    "movs r0, #0\nblx r0",
    "adr r3, 1f\nbx r3\n.p2align 2\n1: nop",
    "udf #0",
    "udf.w #0",
)
