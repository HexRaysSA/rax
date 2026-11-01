#!/usr/bin/env python3
"""Check or regenerate LLVM encodings for the restricted scalar FP cases.

The assembly and control-dependency metadata in cases.json are reviewed inputs.
This tool checks instruction bytes only; it is not a semantic oracle for the
selected support-code subarchitecture or for restricted physical hardware.
"""

import argparse
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HEADERS = ".syntax unified\n.arch armv8.2-a\n.fpu neon-fp-armv8\n.arch_extension fp16\n"
DEFAULT_CASES = ROOT / "docs/development/a32-restricted-fp/cases.json"


def load_cases(path):
    document = json.loads(path.read_text())
    cases = document["cases"]
    if len(cases) != 149 or len({case["name"] for case in cases}) != 149:
        raise ValueError("expected 149 uniquely named qualified cases")
    for case in cases:
        if not case["assembly"] or "\n" in case["assembly"] or "\r" in case["assembly"]:
            raise ValueError("one instruction per case is required")
        if case["rounding"] not in {
            "none", "nearest", "convert_zero", "fpscr", "away", "plus", "minus", "zero"
        }:
            raise ValueError("unknown rounding dependency")
        if type(case["nan"]) is not bool and case["nan"] != "unless_ahp":
            raise ValueError("unknown NaN dependency")
        if case["flush"] not in {"none", "base", "half"}:
            raise ValueError("unknown flush dependency")
        if case["kind"] not in {"scalar", "independent", "helper"}:
            raise ValueError("unknown case kind")
    counts = {kind: sum(case["kind"] == kind for case in cases)
              for kind in ["scalar", "independent", "helper"]}
    if counts != dict(scalar=135, independent=12, helper=2):
        raise ValueError("qualified case categories changed")
    return document


def assemble(document, llvm_mc):
    words = dict(arm=[], thumb=[])
    instructions = "\n".join(case["assembly"] for case in document["cases"]) + "\n"
    sources = []
    for mode in ["arm", "thumb"]:
        source = HEADERS + "." + mode + "\n" + instructions
        sources.append(source)
        argv = [llvm_mc, "-triple=armv8.2a-none-eabi",
                "-mattr=+neon,+vfp4,+fullfp16", "-show-encoding"]
        run = subprocess.run(argv, input=source, text=True, capture_output=True, check=True)
        encoded = re.findall(r"encoding: \[([^\]]+)\]", run.stdout)
        if len(encoded) != len(document["cases"]):
            raise ValueError("LLVM did not encode every case exactly once")
        for raw in encoded:
            data = bytes(int(byte.strip(), 16) for byte in raw.split(","))
            if len(data) != 4:
                raise ValueError("expected one four-byte instruction")
            word = ((int.from_bytes(data[:2], "little") << 16)
                    | int.from_bytes(data[2:], "little")) if mode == "thumb" else int.from_bytes(data, "little")
            words[mode].append(word)
    assembly = HEADERS + ".arm\n" + instructions + ".thumb\n" + instructions
    return words, assembly


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--llvm-mc", default="llvm-mc")
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    document = load_cases(args.cases)
    words, assembly = assemble(document, args.llvm_mc)
    assembly_path = args.cases.with_suffix(".s")
    if args.write:
        for mode, encoded in words.items():
            for case, word in zip(document["cases"], encoded):
                case[mode] = word
        args.cases.write_text(json.dumps(document, indent=2) + "\n")
        assembly_path.write_text(assembly)
    else:
        for mode, encoded in words.items():
            for case, word in zip(document["cases"], encoded):
                if case[mode] != word:
                    raise ValueError(f"stale {mode} encoding for {case['name']}")
        if assembly_path.read_text() != assembly:
            raise ValueError("stale assembly fixture")
    print("Verified 149 ARM and 149 Thumb encodings; semantic metadata is reviewed input.")


if __name__ == "__main__":
    main()
