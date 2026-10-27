"""Independent bigint model of fixed-frequency clock phase across u64 wraps."""

from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import time

MASK = (1 << 64) - 1


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def expected():
    seed = 0x7261785F636C6F63
    total = 0
    rows = []
    for i in range(10000):
        seed = (seed ^ (seed << 13)) & MASK
        seed ^= seed >> 7
        seed = (seed ^ (seed << 17)) & MASK
        delta = [0, 1, 2, 1000, MASK, seed, seed][i % 7]
        total += delta
        rows.extend([delta, (total // 3) & MASK, total & MASK, total % 3])
    return struct.pack('<40000Q', *rows)


def verify(directory):
    assert (directory / 'trace.bin').read_bytes() == expected()
    return dict(
        events=10000, complete_trace_bytes=320000, state_resume_boundaries=104, failed=0
    )


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--work-dir', type=Path, required=True)
    p.add_argument('--target-dir', type=Path, required=True)
    a = p.parse_args()
    root = a.repo.resolve()
    out = a.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    names = [
        'src/vm/timing.rs',
        'src/vm/timing/context.rs',
        'src/vm/timing/retired.rs',
        'tests/suites/vm/retired_clock.rs',
        'tools/execution/retired_clock_guest.rs',
        'tools/execution/retired_clock_oracle.py',
    ]
    before = {n: sha(root / n) for n in names}
    e = os.environ.copy()
    e.update(
        CARGO_TARGET_DIR=str(a.target_dir),
        CARGO_BUILD_JOBS='1',
        CARGO_MANIFEST_DIR=str(root),
    )
    commands = []

    def run(name, args, timeout):
        start = time.monotonic()
        r = subprocess.run(args, cwd=root, env=e, capture_output=True, timeout=timeout)
        (out / (name + '.stdout')).write_bytes(r.stdout)
        (out / (name + '.stderr')).write_bytes(r.stderr)
        commands.append(
            dict(
                name=name,
                args=args,
                code=r.returncode,
                seconds=time.monotonic() - start,
            )
        )
        assert r.returncode == 0, (name, r.stderr[-4000:])

    run(
        'library',
        [
            'cargo',
            '+stable',
            'build',
            '--locked',
            '--offline',
            '--no-default-features',
            '--features',
            'x86_64-suite,smir-jit,hvf',
            '--lib',
            '--bin',
            'rax',
        ],
        600,
    )
    shutil.copyfile(a.target_dir / 'debug/librax.rlib', out / 'librax.rlib')
    run(
        'build',
        [
            'rustc',
            '+stable',
            '--edition=2024',
            str(root / 'tools/execution/retired_clock_guest.rs'),
            '--extern',
            'rax=' + str(out / 'librax.rlib'),
            '-L',
            'dependency=' + str(a.target_dir / 'debug/deps'),
            '-o',
            str(out / 'publish'),
        ],
        60,
    )
    run('publish', [str(out / 'publish'), str(out / 'trace.bin')], 60)
    report = verify(out)
    original = (out / 'trace.bin').read_bytes()
    indices = list(range(16)) + [9999 - i * 617 for i in range(16)]
    assert len(set(indices)) == 32
    probes = []
    for row in indices:
        for field in range(4):
            mutant = bytearray(original)
            mutant[row * 32 + field * 8] ^= 1
            (out / 'trace.bin').write_bytes(mutant)
            try:
                try:
                    verify(out)
                except AssertionError:
                    pass
                else:
                    raise RuntimeError(
                        f'Verifier accepted mutated row{row}/field{field}'
                    )
            finally:
                (out / 'trace.bin').write_bytes(original)
            probes.append(
                dict(
                    row=row,
                    field=field,
                    rejected=True,
                    mutant_sha256=hashlib.sha256(mutant).hexdigest(),
                )
            )
    assert len(probes) == 128 and verify(out) == report
    (out / 'fault-injection.json').write_text(
        json.dumps(dict(cases=128, rejected=128, failed=0, probes=probes), indent=2)
        + '\n'
    )
    assert before == {n: sha(root / n) for n in names}
    (out / 'manifest.json').write_text(
        json.dumps(
            dict(
                result='all_bigint_clock_phase_rows_match',
                report=report,
                commands=commands,
                source_sha256=before,
                library_sha256=sha(out / 'librax.rlib'),
                artifacts={
                    n: sha(out / n) for n in ['trace.bin', 'fault-injection.json']
                },
                scope='10000 full-u64-delta events with320000 exact trace bytes and104 resumed instances;independent Python bigint model;no coordinator/native/replay proof.',
            ),
            indent=2,
        )
        + '\n'
    )
    print(json.dumps(report))


if __name__ == '__main__':
    main()
