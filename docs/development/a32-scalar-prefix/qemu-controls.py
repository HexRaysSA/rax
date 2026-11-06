"""Independent Cortex-A15 scalar-FP prefix rejection and legal move controls."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time


CASES = [
    ("cp13-vmls-alias", 0xee020d44, "undefined"),
    ("cp14-vmls-alias", 0xee020e44, "undefined"),
    ("cp14-vdiv-alias", 0xee810e02, "undefined"),
    ("nv-vneg-alias", 0xfeb10b42, "undefined"),
    ("nv-vsqrt-alias", 0xfeb10bc1, "undefined"),
    ("nv-vabs-alias", 0xfeb00bc1, "undefined"),
    ("legal-vneg-f64", 0xeeb10b41, "neg64"),
    ("legal-vmov-f64", 0xeeb00b41, "move64"),
    ("legal-vmov-f32", 0xeeb00a41, "move32"),
    ("legal-vneg-f32", 0xeeb10a41, "neg32"),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    support = Path(__file__).resolve().parent.parent / "a32-immediate-shifts/qemu-controls.py"
    spec = importlib.util.spec_from_file_location("scalar_prefix_transport", support)
    reference = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reference)
    cases = [dict(name=name, raw=raw, kind=kind, thumb=thumb)
             for name, raw, kind in CASES for thumb in [False, True]]
    source, initialized = reference.program([
        (10, 0, 8, 0, case["thumb"], 0, True) for case in cases
    ])
    instructions = iter(f" .inst{'.w' if c['thumb'] else ''} {c['raw']:#x}" for c in cases)
    source = re.sub(r"^ \.inst(?:\.w)? 0x[0-9a-f]+$",
                    lambda _: next(instructions), source, flags=re.MULTILINE)
    assert next(instructions, None) is None
    for case, initial in zip(cases, initialized, strict=True):
        expected = initial["expected"][:]
        if case["kind"] != "undefined":
            expected[0] = "L"
            # The transport independently initializes D1 to negative minimum
            # subnormal64, with S2=1; moves and negations have exact bit results.
            expected[1] = {"neg64": 1, "move64": 0x8000000000000001,
                           "move32": 0x9abcdef000000001,
                           "neg32": 0x9abcdef080000001}[case["kind"]]
        case["expected"] = expected
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / "cases.json").write_text(json.dumps(cases, indent=2) + "\n")
    steps = []
    with tempfile.TemporaryDirectory(prefix="rax-scalar-prefix-qemu-") as temporary:
        scratch = Path(temporary)
        assembly, obj, elf, script = [scratch / name for name in
                                      ["guest.S", "guest.o", "guest.elf", "guest.ld"]]
        assembly.write_text(source)
        script.write_text("ENTRY(_start)\nSECTIONS { . = 0x40010000; .text : { *(.text*) } }\n")
        commands = [
            [shutil.which("llvm-mc"), "-triple=armv7a-none-eabi", "-filetype=obj",
             str(assembly), "-o", str(obj)],
            [shutil.which("ld.lld"), "-T", str(script), str(obj), "-o", str(elf)],
            [shutil.which("qemu-system-arm"), "-machine", "virt", "-cpu", "cortex-a15",
             "-m", "128M", "-nographic", "-monitor", "none", "-serial", "stdio",
             "-semihosting", "-kernel", str(elf)],
        ]
        if any(command[0] is None for command in commands):
            raise RuntimeError("llvm-mc, ld.lld and qemu-system-arm are required")
        for index, command in enumerate(commands):
            started = time.monotonic()
            result = subprocess.run(command, capture_output=True, timeout=30)
            (args.out / f"phase-{index}.stdout").write_bytes(result.stdout)
            (args.out / f"phase-{index}.stderr").write_bytes(result.stderr)
            steps.append(dict(argv=command, exit_code=result.returncode,
                              seconds=time.monotonic() - started))
            if result.returncode:
                raise RuntimeError(result.stderr.decode(errors="replace"))
        lines = result.stdout.decode().splitlines()
        assert len(lines) == len(cases), (len(lines), len(cases))
        for line, case in zip(lines, cases, strict=True):
            assert len(line) == 41, line
            words = [int(line[1 + i * 8:9 + i * 8], 16) for i in range(5)]
            actual = [line[0], words[0] | words[1] << 32,
                      words[2] | words[3] << 32, words[4]]
            case["observed"] = actual
            assert actual == case["expected"], case
        elf_sha = hashlib.sha256(elf.read_bytes()).hexdigest()
    receipt = dict(cases=len(cases), reserved=12, legal=8, all_agree=True,
                   guest_execution_performed=True,
                   scope="QEMU Cortex-A15, FP enabled, A32/T32 rejection and exact D0/D1/FPSCR; no physical A32 claim.",
                   source_sha256=hashlib.sha256(source.encode()).hexdigest(),
                   harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   transport_sha256=hashlib.sha256(support.read_bytes()).hexdigest(),
                   elf_sha256=elf_sha, commands=steps,
                   owned_compilation_directory_removed=not scratch.exists())
    (args.out / "observations.json").write_text(json.dumps(cases, indent=2) + "\n")
    (args.out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
