#!/usr/bin/env python3
"""Regenerate Darwin ABI signing fixtures using the pinned, unchanged QEMU C.

The XNU ABI selects keys and discriminators. Clang's arm64e builtins independently
check the string discriminators and address blending used by the personality.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile

from verify import REFERENCE, REFERENCE_SHA256, ROOT, run
from verify_architecture import HEADER, COMPUTE, DRIVER


FIXTURE = ROOT / "docs/specifications/arm/pauth/darwin-vectors.json"
DISCRIMINATORS = {"pc": 0x7481, "lr": 0x77D3, "sp": 0xCBED,
                  "fp": 0x4517, "nonce": 0xB743, "uctx": 0xD4A6}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if hashlib.sha256(REFERENCE.read_bytes()).hexdigest() != REFERENCE_SHA256:
        raise SystemExit("reference hash mismatch")
    source = REFERENCE.read_text()
    primitive = source[source.index("static uint64_t pac_cell_shuffle"):
                       source.index("static uint64_t pauth_computepac_impdef")]
    architecture = source[source.index("static uint64_t pauth_addpac"):
                          source.index("static G_NORETURN\nvoid pauth_trap")]
    intrinsic_source = "\n".join(
        f'unsigned long d_{name}(void) {{ return __builtin_ptrauth_string_discriminator("{name}"); }}'
        for name in DISCRIMINATORS
    )
    assembly = run([os.environ.get("CLANG", "clang"), "-target", "arm64e-apple-macos",
                    "-S", "-O2", "-x", "c", "-o", "-", "-"], input=intrinsic_source).stdout
    for name, value in DISCRIMINATORS.items():
        body = assembly.split(f"_d_{name}:", 1)[1].split("\tret", 1)[0]
        if f"#{value}" not in body:
            raise SystemExit(f"compiler discriminator mismatch: {name}: {body}")
    inputs = [
        ("pc", 0x100001000, "ia", DISCRIMINATORS["pc"]),
        ("lr", 0x100002000, "ia", DISCRIMINATORS["lr"]),
        ("sp", 0x7000001000, "da", DISCRIMINATORS["sp"]),
        ("fp", 0x7000002000, "da", DISCRIMINATORS["fp"]),
        ("uctx", 0x7000003000, "da", DISCRIMINATORS["uctx"]),
        ("cache_code", 0x180000040, "ia", 0x77),
        ("cache_data", 0x180000080, "da", (0x66 << 48) | 0x180004018),
        ("function", 0x100004000, "ia", 0),
    ]
    vectors = []
    with tempfile.TemporaryDirectory(prefix="rax-darwin-pauth-") as temporary:
        directory = Path(temporary)
        path = directory / "reference.c"
        binary = directory / "reference"
        path.write_text(HEADER + primitive + COMPUTE + architecture + DRIVER)
        run([os.environ.get("CC", "cc"), "-O2", str(path), "-o", str(binary)])
        for q in [0, 1]:
            current = list(inputs)
            for name, pointer, kind, modifier in current:
                lo, hi = (1, 2) if kind == "ia" else (5, 6)
                data = int(kind == "da")
                line = f"{q} 3 48 {data} {data} 0 0 0 {pointer:x} {modifier:x} {lo:x} {hi:x} 0\n"
                result = run([str(binary)], input=line).stdout.strip().split()
                if len(result) != 2 or result[0] != "ok":
                    raise SystemExit(f"unexpected oracle result: {line!r}: {result!r}")
                signed = int(result[1], 16)
                vectors.append({"algorithm": q, "name": name, "pointer": f"{pointer:016x}",
                                "modifier": f"{modifier:016x}", "key": kind,
                                "signed": f"{signed:016x}"})
                if name in ["pc", "lr"]:
                    current.append((f"{name}_nonce", signed ^ 0x0123456789ABCDEF,
                                    "da", DISCRIMINATORS["nonce"]))
    document = {"reference_sha256": REFERENCE_SHA256,
                "profile": "FpacCombine", "address_bits": 48,
                "ia_key_lo_hi": [1, 2], "da_key_lo_hi": [5, 6], "vectors": vectors}
    output = json.dumps(document, indent=2) + "\n"
    if args.check:
        if FIXTURE.read_text() != output:
            raise SystemExit("Darwin oracle fixture is stale")
    else:
        FIXTURE.write_text(output)
    print(f"PASS: {len(vectors)} QEMU signing vectors; six Clang arm64e discriminators; no skips")


if __name__ == "__main__":
    main()
