"""Independent integer model for complete native AArch64 scalar MMIO replies."""

import argparse
import hashlib
import json
import os
import struct
import subprocess
import time
import tempfile
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def expected():
    rows = bytearray()
    configurations = [
        (1, 0, 0),
        (1, 1, 0),
        (1, 1, 1),
        (2, 0, 0),
        (2, 1, 0),
        (2, 1, 1),
        (4, 0, 0),
        (4, 1, 1),
        (8, 0, 1),
    ]
    for case, (size, signed, wide) in enumerate(configurations):
        modulus = 256**size
        sign = modulus // 2
        for rt in [0, 31]:
            for pattern, value in enumerate(
                [0, 1, modulus - 1, sign, sign - 1, 0x8877665544332211 % modulus]
            ):
                for length in list(range(size + 1)) + [size + 3]:
                    accepted = length >= size
                    result = value - modulus if signed and value >= sign else value
                    result %= 2 ** (64 if wide else 32)
                    rows.extend(
                        struct.pack(
                            '<9Q',
                            case,
                            rt,
                            pattern,
                            length,
                            size,
                            signed,
                            wide,
                            accepted,
                            result if accepted else (1 << 64) - 1,
                        )
                    )
    assert len(rows) == 37152
    return bytes(rows)


def verify(directory):
    assert (directory / 'rows.bin').read_bytes() == expected()
    return {
        'configurations': 9,
        'destination_registers': 2,
        'patterns': 6,
        'observations': 516,
        'observation_bytes': 37152,
        'failed': 0,
    }


def run_probe(a, temporary):
    root, out = a.repo.resolve(), a.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    names = [
        'src/backend/hvf/arm64_mmio.rs',
        'tests/suites/backend/hvf_arm64_mmio.rs',
        'tools/hvf/arm64_mmio_guest.rs',
        'tools/hvf/arm64_mmio_oracle.py',
    ]
    before = {n: sha(root / n) for n in names}
    commands = []
    for name, args in [
        (
            'build',
            [
                'rustc',
                '+stable',
                '--edition=2024',
                str(root / names[2]),
                '-o',
                str(temporary / 'publish'),
            ],
        ),
        ('publish', [str(temporary / 'publish'), str(out / 'rows.bin')]),
    ]:
        start = time.monotonic()
        r = subprocess.run(
            args,
            cwd=root,
            env=os.environ.copy(),
            capture_output=True,
            check=False,
            timeout=60,
        )
        (out / (name + '.stdout')).write_bytes(r.stdout)
        (out / (name + '.stderr')).write_bytes(r.stderr)
        commands.append(
            {
                'name': name,
                'args': args,
                'code': r.returncode,
                'seconds': time.monotonic() - start,
            }
        )
        assert r.returncode == 0, (name, r.stderr)
    report = verify(out)
    assert before == {n: sha(root / n) for n in names}
    (out / 'manifest.json').write_text(
        json.dumps(
            {
                'result': 'native_arm64_mmio_complete_reply_policy_matches',
                'report': report,
                'commands': commands,
                'source_sha256': before,
                'producer_executable_sha256': sha(temporary / 'publish'),
                'artifacts': {
                    n: sha(out / n)
                    for n in ['rows.bin']
                },
                'scope': 'Portable product policy only. Native vCPU transaction lifecycle is validated separately.',
            },
            indent=2,
        )
        + '\n'
    )
    print(json.dumps(report))


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--work-dir', type=Path, required=True)
    p.add_argument('--target-dir', type=Path)
    a = p.parse_args()
    temporary_path = None
    try:
        with tempfile.TemporaryDirectory(prefix='rax-arm64-mmio-policy-') as name:
            temporary_path = Path(name)
            run_probe(a, temporary_path)
    finally:
        a.work_dir.mkdir(parents=True, exist_ok=True)
        (a.work_dir / 'cleanup.json').write_text(json.dumps({
            'temporary_directory': str(temporary_path),
            'removed': temporary_path is not None and not temporary_path.exists(),
        }, indent=2) + '\n')


if __name__ == '__main__':
    main()
