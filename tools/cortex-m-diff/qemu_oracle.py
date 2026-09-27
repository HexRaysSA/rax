#!/usr/bin/env python3
"""Cortex-M4 Thumb differential oracle.

Assembles every case of `corpus.py` into one firmware image with LLVM, runs
it on QEMU's `mps2-an386` board (Cortex-M4), and writes the post-state of
each case as JSON for `src/backend/emulator/cortex_m_oracle_tests.rs`.

Each case loads R0-R12, LR, APSR, SP, a 256-byte data area and a 256-byte
stack window from known values, executes its instructions, and reports the
registers and the changed memory over semihosting. A fault (any exception
other than SVCall) reports the fault status registers, EXC_RETURN, MSP and
the stacked frame instead, and resumes at the next case. The SVCall handler
returns through `bx lr`, `pop {pc}` or `ldr pc` (SVC #0, #1, #2), after
adding 1 to the stacked R0 (on the stack EXC_RETURN selects) and changing
the flags.

Usage: qemu_oracle.py OUTPUT.json
Requires llvm-mc, llvm-objcopy and llvm-nm (LLVM >= 17) and
qemu-system-arm; set LLVM_BIN to their directory.
"""
import json
import os
import struct
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True  # keep tools/ free of __pycache__
from corpus import CORPUS  # noqa: E402

LLVM = os.environ.get("LLVM_BIN", "/opt/homebrew/opt/llvm/bin")

RAM = 0x2000_0000
STATE = RAM + 0x000       # [case id, resume address, console handle]
PARAMS = RAM + 0x040      # semihosting parameter block
OUT = RAM + 0x100         # output record
DATA = RAM + 0x1000       # 256 data bytes; r5 = DATA + 0x80
STACK = RAM + 0x8000      # SP at case entry
STACKWIN = STACK - 0x80   # the 256 stack bytes compared
CODE_MARGIN = 16          # code bytes kept around a case for PC-relative loads

VECTORS = [
    # r0..r12, lr
    [0, 0x87654321, 0x00000013, 0xDEADBEEF, 0x11112222, DATA + 0x80, 3,
     0x80000000, 0x7FFFFFFF, 0xFFFFFFFF, 0x0000FFFF, 0x00008000, 0x7FFF8001, 0x0BADC0DE],
    [1, 0x7FFF8000, 0x80017FFF, 0x00000000, 0xFFFFFFFF, DATA + 0x80, 31,
     0x00000020, 0x00000021, 0x000000FF, 0xFF00FF00, 0x01020304, 0xFEDCBA98, 0x12345679],
    [0x10, 0x00000000, 0x00000000, 0x80000000, 0x80000000, DATA + 0x80, 0,
     0xFFFFFFFF, 0x80000001, 0x00000001, 0x00000100, 0x7FFF7FFF, 0x00000000, 0xFFFFFFFE],
]
# (vector, APSR): NZCVQ and GE[3:0].
VARIANTS = [(0, 0x0000_0000), (1, 0xA805_0000), (2, 0x500A_0000)]

CASE_WORDS = 16           # sp, apsr, r0..r12, lr
FAULT_WORDS = 13          # cfsr, hfsr, ipsr, msp, exc_return, frame[8]


def pattern(i, a, b):
    return (i * a + b) & 0xFF


DATA_PATTERN = bytes(pattern(i, 37, 11) for i in range(256))
STACK_PATTERN = bytes(pattern(i, 53, 7) for i in range(256))


def build(cases):
    a = []
    w = a.append
    w(".syntax unified\n.cpu cortex-m4\n.thumb\n.text\n")
    # Labels are not .thumb_func: without a link step, a relocation against
    # a section-relative label keeps its address (and the explicit +1).
    w("vectors:\n.word 0x20010000\n.word reset+1\n")
    for exception in range(2, 16):
        w(".word svc_handler+1\n" if exception == 11 else ".word fault+1\n")
    w(".org 0x100\nreset:\n")
    w(f"  ldr r1, ={PARAMS:#x}\n  ldr r0, =ttname\n  str r0, [r1]\n  movs r0, #4\n  str r0, [r1, #4]\n"
      "  movs r0, #3\n  str r0, [r1, #8]\n  movs r0, #1\n  bkpt 0xab\n"
      f"  ldr r1, ={STATE:#x}\n  str r0, [r1, #8]\n  b case_0\n.p2align 2\nttname: .asciz \":tt\"\n"
      ".p2align 2\n.ltorg\n")
    for i, (text, vec, flags) in enumerate(cases):
        w(f"case_{i}:\n")
        w(f"  ldr r0, ={STATE:#x}\n  ldr r1, ={i}\n  str r1, [r0]\n  ldr r1, =case_{i + 1}\n  str r1, [r0, #4]\n")
        w(f"  ldr r0, ={DATA:#x}\n  ldr r1, =data_pattern\n  bl copy256\n")
        w(f"  ldr r0, ={STACKWIN:#x}\n  ldr r1, =stack_pattern\n  bl copy256\n")
        # Special registers start at their reset values in every case.
        w("  movs r0, #0\n  msr primask, r0\n  msr faultmask, r0\n  msr basepri, r0\n"
          "  msr control, r0\n  msr psp, r0\n  isb\n")
        w(f"  ldr r0, ={STACK:#x}\n  mov sp, r0\n  ldr r0, ={flags:#x}\n  msr apsr_nzcvqg, r0\n")
        w(f"  ldr r0, =vector_{vec}\n  ldm.w r0, {{r0-r12, lr}}\n")
        w(f"start_{i}:\n")
        for line in text.split("\n"):
            w(f"  {line}\n")
        w(f"end_{i}:\n")
        w("  stmdb sp, {r0-r12, lr}\n  mrs r0, apsr\n  mov r1, sp\n  sub sp, #64\n"
          "  str r1, [sp]\n  str r0, [sp, #4]\n")
        w(f"  ldr r0, ={i}\n  bl dump\n  b.w case_{i + 1}\n.p2align 2\n.ltorg\npool_end_{i}:\n")
    n = len(cases)
    w(f"case_{n}:\n  movs r0, #0x18\n  ldr r1, =0x20026\n  bkpt 0xab\n  b .\n.ltorg\n")
    # copy256: r0 = dst, r1 = src (word aligned); clobbers r0-r3.
    w("copy256:\n  movs r2, #64\n1: ldr r3, [r1], #4\n  str r3, [r0], #4\n"
      "  subs r2, #1\n  bne 1b\n  bx lr\n")
    # dump: r0 = case id; [sp_after, apsr, r0..r12, lr] at sp.
    w("dump:\n  push {r4-r7, lr}\n  add r4, sp, #20\n"
      f"  ldr r5, ={OUT:#x}\n  ldr r6, =0x45534143\n  str r6, [r5], #4\n  str r0, [r5], #4\n"
      f"  movs r6, #{CASE_WORDS}\n1: ldr r7, [r4], #4\n  str r7, [r5], #4\n  subs r6, #1\n  bne 1b\n"
      f"  ldr r4, ={DATA:#x}\n  movs r6, #64\n1: ldr r7, [r4], #4\n  str r7, [r5], #4\n  subs r6, #1\n  bne 1b\n"
      f"  ldr r4, ={STACKWIN:#x}\n  movs r6, #64\n1: ldr r7, [r4], #4\n  str r7, [r5], #4\n  subs r6, #1\n  bne 1b\n"
      f"  ldr r0, ={OUT:#x}\n  ldr r1, ={8 + 4 * CASE_WORDS + 512}\n  bl write_out\n  pop {{r4-r7, pc}}\n.ltorg\n")
    # write_out: r0 = buffer, r1 = length.
    w(f"write_out:\n  ldr r2, ={STATE:#x}\n  ldr r2, [r2, #8]\n  ldr r3, ={PARAMS:#x}\n"
      "  str r2, [r3]\n  str r0, [r3, #4]\n  str r1, [r3, #8]\n  movs r0, #5\n  mov r1, r3\n"
      "  bkpt 0xab\n  bx lr\n.ltorg\n")
    # svc_handler: stacked r0 += 1, flags changed, then return by SVC #imm.
    # The frame is on the stack EXC_RETURN bit 2 selects.
    w("svc_handler:\n  tst lr, #4\n  ite eq\n  mrseq r0, msp\n  mrsne r0, psp\n"
      "  ldr r1, [r0, #24]\n  ldrb r1, [r1, #-2]\n  ldr r2, [r0]\n  adds r2, #1\n"
      "  str r2, [r0]\n  movs r3, #0\n  cmp r1, #1\n  beq 1f\n  cmp r1, #2\n  beq 2f\n  bx lr\n"
      "1: push {r4, lr}\n  pop {r4, pc}\n2: push {lr}\n  ldr pc, [sp], #4\n")
    # fault: record the fault state and resume at the next case in Thread
    # mode with a fresh frame.
    w("fault:\n  mrs r11, msp\n  mov r10, lr\n"
      f"  ldr r4, ={OUT:#x}\n  ldr r0, =0x544c4146\n  str r0, [r4]\n  ldr r0, ={STATE:#x}\n  ldr r0, [r0]\n"
      "  str r0, [r4, #4]\n  ldr r1, =0xE000ED28\n  ldr r0, [r1]\n  str r0, [r4, #8]\n  str r0, [r1]\n"
      "  ldr r1, =0xE000ED2C\n  ldr r0, [r1]\n  str r0, [r4, #12]\n  str r0, [r1]\n"
      "  mrs r0, ipsr\n  str r0, [r4, #16]\n  str r11, [r4, #20]\n  str r10, [r4, #24]\n"
      "  add r5, r4, #28\n  mov r6, r11\n  movs r7, #8\n1: ldr r0, [r6], #4\n  str r0, [r5], #4\n"
      "  subs r7, #1\n  bne 1b\n"
      f"  mov r0, r4\n  movs r1, #{8 + 4 * FAULT_WORDS}\n  bl write_out\n"
      f"  ldr r0, ={STATE:#x}\n  ldr r0, [r0, #4]\n  str r0, [r11, #24]\n  ldr r0, =0x01000000\n  str r0, [r11, #28]\n"
      "  ldr r10, =0xFFFFFFF9\n  bx r10\n.ltorg\n")
    w(".p2align 2\ndata_pattern:\n" + "".join(f".byte {b}\n" for b in DATA_PATTERN))
    w(".p2align 2\nstack_pattern:\n" + "".join(f".byte {b}\n" for b in STACK_PATTERN))
    for v, regs in enumerate(VECTORS):
        w(f".p2align 2\nvector_{v}:\n" + "".join(f".word {r:#x}\n" for r in regs))
    return "".join(a)


def diff(actual, expected):
    """The bytes of `actual` that differ from `expected`, as [offset, byte]."""
    return [[i, b] for i, (b, e) in enumerate(zip(actual, expected)) if b != e]


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    output = os.path.abspath(sys.argv[1])
    with tempfile.TemporaryDirectory() as work:
        generate(output, work)


def generate(output, work):
    cases = [(text, vec, flags) for text in CORPUS for (vec, flags) in VARIANTS]
    asm = os.path.join(work, "fw.s")
    obj = os.path.join(work, "fw.o")
    binf = os.path.join(work, "fw.bin")
    with open(asm, "w") as f:
        f.write(build(cases))
    subprocess.run([f"{LLVM}/llvm-mc", "-triple=thumbv7em-none-eabi", "-mcpu=cortex-m4",
                    "-filetype=obj", asm, "-o", obj], check=True)
    subprocess.run([f"{LLVM}/llvm-objcopy", "-O", "binary", obj, binf], check=True)
    syms = {}
    for line in subprocess.run([f"{LLVM}/llvm-nm", obj], capture_output=True, text=True,
                               check=True).stdout.splitlines():
        parts = line.split()
        if len(parts) == 3:
            syms[parts[2]] = int(parts[0], 16)
    # Semihosting console writes (the ":tt" handle) go to QEMU's stdout.
    blob = subprocess.run(["qemu-system-arm", "-M", "mps2-an386", "-cpu", "cortex-m4", "-display",
                           "none", "-monitor", "none", "-serial", "none", "-kernel", binf,
                           "-semihosting-config", "enable=on,target=native"],
                          check=True, timeout=300, capture_output=True).stdout
    results = {}
    pos = 0
    while pos < len(blob):
        magic = blob[pos:pos + 4]
        cid, = struct.unpack_from("<I", blob, pos + 4)
        if magic == b"CASE":
            words = struct.unpack_from(f"<{CASE_WORDS}I", blob, pos + 8)
            body = pos + 8 + 4 * CASE_WORDS
            # Stack bytes below the final SP are the dump's own spill area.
            live = max(0, words[0] - STACKWIN)
            stack = [d for d in diff(blob[body + 256:body + 512], STACK_PATTERN) if d[0] >= live]
            results[cid] = {"sp": words[0], "apsr": words[1], "r": list(words[2:15]),
                            "lr": words[15],
                            "data": diff(blob[body:body + 256], DATA_PATTERN),
                            "stack": stack}
            pos = body + 512
        elif magic == b"FALT":
            words = struct.unpack_from(f"<{FAULT_WORDS}I", blob, pos + 8)
            results[cid] = {"fault": {"cfsr": words[0], "hfsr": words[1], "ipsr": words[2],
                                      "msp": words[3], "exc_return": words[4],
                                      "frame": list(words[5:13])}}
            pos += 8 + 4 * FAULT_WORDS
        else:
            raise SystemExit(f"bad record at {pos}: {magic!r}")
    missing = [i for i in range(len(cases)) if i not in results]
    if missing:
        raise SystemExit(f"cases without a result: {missing[:10]}")
    code = open(binf, "rb").read()
    handler_start, handler_end = syms["svc_handler"], syms["fault"]
    version = subprocess.run(["qemu-system-arm", "--version"], capture_output=True,
                             text=True).stdout.splitlines()[0]
    doc = {
        "oracle": f"{version}, machine mps2-an386, cpu cortex-m4",
        "data_base": DATA, "stack_base": STACKWIN, "stack_top": STACK,
        "data_pattern": DATA_PATTERN.hex(), "stack_pattern": STACK_PATTERN.hex(),
        "vector_table": code[:64].hex(),
        "svc_handler": {"base": handler_start, "code": code[handler_start:handler_end].hex()},
        "fault_handler": syms["fault"],
        "vectors": VECTORS,
        "cases": [],
    }
    for i, (text, vec, flags) in enumerate(cases):
        start, end = syms[f"start_{i}"], syms[f"end_{i}"]
        lo, hi = max(0, start - CODE_MARGIN), end + CODE_MARGIN
        if "=" in text:
            # `ldr rN, =value` reads the literal pool after the case.
            hi = syms[f"pool_end_{i}"]
        doc["cases"].append({"text": text, "vector": vec, "apsr": flags, "start": start,
                             "end": end, "code_base": lo, "code": code[lo:hi].hex(),
                             "expect": results[i]})
    with open(output, "w") as f:
        json.dump(doc, f, separators=(",", ":"))
        f.write("\n")
    faults = sum("fault" in r for r in results.values())
    print(f"{len(cases)} cases ({len(CORPUS)} forms x {len(VARIANTS)} states), {faults} faults")


if __name__ == "__main__":
    main()
