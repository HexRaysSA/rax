#!/usr/bin/env python3
"""Compare RAX's QARMA primitive against the pinned QEMU implementation."""

import argparse
import hashlib
import os
from pathlib import Path
import random
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "docs/specifications/arm/pauth/qemu-pauth_helper.c"
REFERENCE_SHA256 = "b63fa12bfb96f37822c8b7e595b23b445662392cc56341c34865f4aea1e86c70"


def run(command, **kwargs):
    result = subprocess.run(command, text=True, capture_output=True, **kwargs)
    if result.returncode:
        raise SystemExit(f"command failed: {command!r}\n{result.stderr}")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=int, default=4096)
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=0xA64_20261024)
    parser.add_argument("--known-key-vectors", action="store_true",
                        help="also compare and print fixed vectors for all five distinct key slots")
    args = parser.parse_args()
    if args.cases <= 0:
        parser.error("--cases must be positive")

    digest = hashlib.sha256(REFERENCE.read_bytes()).hexdigest()
    if digest != REFERENCE_SHA256:
        raise SystemExit(f"reference hash mismatch: {digest}")
    source = REFERENCE.read_text()
    # Compile the reference's unmodified, self-contained primitive routines.
    start = source.index("static uint64_t pac_cell_shuffle")
    end = source.index("static uint64_t pauth_computepac_impdef")
    header = """#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <inttypes.h>
#define MAKE_64BIT_MASK(s,n) (((UINT64_C(1) << (n))-1) << (s))
static uint64_t extract64(uint64_t x,int s,int n) {
    return (x>>s)&((UINT64_C(1)<<n)-1);
}
#define extract32 extract64
typedef struct { uint64_t lo, hi; } ARMPACKey;
"""
    driver = """
int main(void) {
    unsigned q;
    uint64_t data, modifier, lo, hi;
    while (scanf("%u %" SCNx64 " %" SCNx64 " %" SCNx64 " %" SCNx64,
                 &q, &data, &modifier, &lo, &hi) == 5) {
        ARMPACKey key = {lo, hi};
        printf("%016" PRIx64 "\\n", pauth_computepac_architected(data, modifier, key, q));
    }
}
"""
    rust_module = (ROOT / "src/isa/arm/aarch64/pauth.rs").as_posix()
    rust = f'#[path = "{rust_module}"] mod pauth;\n' + """
use std::io::{self, BufRead};
use pauth::{PauthAlgorithm, PauthKey};
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let fields: Vec<_> = line.split_whitespace().collect();
        let algorithm = if fields[0] == "1" { PauthAlgorithm::Qarma3 } else { PauthAlgorithm::Qarma5 };
        let values: Vec<_> = fields[1..].iter().map(|v| u64::from_str_radix(v, 16).unwrap()).collect();
        println!("{:016x}", algorithm.compute(values[0], values[1], PauthKey { lo: values[2], hi: values[3] }));
    }
}
"""
    rng = random.Random(args.seed)
    cases = []
    for algorithm in [0, 1]:
        for _ in range(args.cases):
            values = [rng.getrandbits(64) for _ in range(4)]
            cases.append(str(algorithm) + " " + " ".join(f"{value:016x}" for value in values))
    known_start = len(cases)
    if args.known_key_vectors:
        for algorithm in [0, 1]:
            for index in range(5):
                cases.append(f"{algorithm} 0000000000000000 0000000000000001 {index * 2 + 1:016x} {index * 2 + 2:016x}")
    inputs = "\n".join(cases) + "\n"
    with tempfile.TemporaryDirectory(prefix="rax-pauth-") as temporary:
        directory = Path(temporary)
        c_path = directory / "reference.c"
        rust_path = directory / "rax.rs"
        c_path.write_text(header + source[start:end] + driver)
        rust_path.write_text(rust)
        reference = directory / "reference"
        candidate = directory / "rax"
        run([os.environ.get("CC", "cc"), "-O2", str(c_path), "-o", str(reference)])
        run(["rustc", "+stable", "--edition", "2024", "-O", str(rust_path), "-o", str(candidate)])
        expected = run([str(reference)], input=inputs).stdout.splitlines()
        actual = run([str(candidate)], input=inputs).stdout.splitlines()
    if len(expected) != len(cases) or len(actual) != len(cases):
        raise SystemExit(f"case count mismatch: expected={len(expected)} actual={len(actual)} inputs={len(cases)}")
    for index, (left, right) in enumerate(zip(expected, actual)):
        if left != right:
            raise SystemExit(f"mismatch at {index}: input={cases[index]} QEMU={left} RAX={right}")
    print(f"PASS: {len(cases)} cases, seed={args.seed:#x}, QARMA3/QARMA5, no skips")
    print(f"reference_sha256={hashlib.sha256(REFERENCE.read_bytes()).hexdigest()}")
    if args.known_key_vectors:
        for index in range(known_start, len(cases)):
            print(f"known: {cases[index]} -> {expected[index]}")


if __name__ == "__main__":
    main()
