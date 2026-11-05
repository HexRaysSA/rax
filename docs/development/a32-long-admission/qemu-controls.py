"""Execute fixed-selector controls independently on QEMU Cortex-A15."""

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path


CASES = [
    ("poly", 0xF2800E00, 0x0005000400010000, 0x0015001400110010),
    ("qdmlal16", 0xF2900900, 0x07181D0C03040100, 0x9B1F87381266A698),
    ("qdmlsl16", 0xF2900B00, 0x06F3ECFC03000100, 0x9A5A36A812020658),
    ("qdmull16", 0xF2900D00, 0x0012180800020000, 0x0062A84800325020),
    ("qdmlal32", 0xF2A00900, 0x07181D180B040100, 0x9B1F87C4FAC6A698),
    ("qdmlsl32", 0xF2A00B00, 0x06F3ECEFFB000100, 0x9A5A361B29A20658),
    ("qdmull32", 0xF2A00D00, 0x0012181408020000, 0x0062A8D4E8925020),
]


def register_text(value):
    # The UART guest prints the low 32-bit word before the high word.
    return f"{value & 0xFFFFFFFF:08x}{value >> 32:08x}"


def run(out, assembler, linker, qemu):
    here = Path(__file__).resolve().parent
    template = (here / "guest-template.S").read_text()
    linker_script = (here / "guest.ld").read_bytes()
    out.mkdir(parents=True, exist_ok=False)
    results = []
    with tempfile.TemporaryDirectory(prefix="rax-long-qemu-") as temporary:
        scratch = Path(temporary)
        script = scratch / "guest.ld"
        script.write_bytes(linker_script)
        for family, base, low, high in CASES:
            for thumb in [False, True]:
                for selector in [0, 1]:
                    raw = base | (selector << 24)
                    if thumb:
                        raw = (raw & 0xFFFFFF) | 0xEF000000 | (selector << 28)
                    label = f"{family}-{'thumb' if thumb else 'arm'}-u{selector}"
                    mode = (
                        "ldr r0, =case\n bx r0\n .thumb\n .thumb_func" if thumb else "nop"
                    )
                    instruction = (".inst.w " if thumb else ".inst ") + hex(raw)
                    source = template.replace("ENTER_MODE", mode).replace(
                        "CASE_INSTRUCTION", instruction
                    )
                    assembly = scratch / f"{label}.S"
                    obj = scratch / f"{label}.o"
                    elf = scratch / f"{label}.elf"
                    assembly.write_text(source)
                    (out / f"{label}.S").write_text(source)
                    commands = [
                        [
                            assembler, "-triple=armv7a-none-eabi", "-filetype=obj",
                            str(assembly), "-o", str(obj),
                        ],
                        [linker, "-T", str(script), str(obj), "-o", str(elf)],
                        [
                            qemu, "-machine", "virt", "-cpu", "cortex-a15",
                            "-m", "128M", "-nographic", "-monitor", "none",
                            "-serial", "stdio", "-semihosting", "-kernel", str(elf),
                        ],
                    ]
                    steps = []
                    for index, command in enumerate(commands):
                        started = time.monotonic()
                        result = subprocess.run(command, capture_output=True, timeout=15)
                        (out / f"{label}-{index}.stdout").write_bytes(result.stdout)
                        (out / f"{label}-{index}.stderr").write_bytes(result.stderr)
                        steps.append({
                            "argv": command,
                            "exit_code": result.returncode,
                            "seconds": time.monotonic() - started,
                        })
                        if result.returncode:
                            raise RuntimeError(f"{label}: {command}: {result.stderr.decode()}")
                    observation = result.stdout.decode()
                    if selector:
                        expected = (
                            "U" + register_text(0x0706050403020100)
                            + register_text(0x9ABCDEF012345678) + "\n"
                        )
                    else:
                        expected = "L" + register_text(low) + register_text(high) + "\n"
                    if observation != expected:
                        raise AssertionError((label, expected, observation))
                    results.append({
                        "label": label,
                        "raw": hex(raw),
                        "stdout": observation,
                        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
                        "elf_sha256": hashlib.sha256(elf.read_bytes()).hexdigest(),
                        "steps": steps,
                    })
                    print(label, observation.strip(), flush=True)
    record = {
        "results": results,
        "owned_compilation_directory_removed": True,
        "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "template_sha256": hashlib.sha256(template.encode()).hexdigest(),
        "linker_script_sha256": hashlib.sha256(linker_script).hexdigest(),
        "scope": "QEMU Cortex-A15 allocation and register controls; no physical AArch32 qualification.",
    }
    (out / "results.json").write_text(json.dumps(record, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--assembler", default=shutil.which("llvm-mc"))
    parser.add_argument("--linker", default=shutil.which("ld.lld"))
    parser.add_argument("--qemu", default=shutil.which("qemu-system-arm"))
    arguments = parser.parse_args()
    if not all([arguments.assembler, arguments.linker, arguments.qemu]):
        parser.error("llvm-mc, ld.lld and qemu-system-arm are required")
    run(arguments.out, arguments.assembler, arguments.linker, arguments.qemu)


if __name__ == "__main__":
    main()
