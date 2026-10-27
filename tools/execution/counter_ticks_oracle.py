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
    mask = (1 << 64) - 1
    seed = 0x7261785F66726571
    words = []
    for i in range(10000):
        seed = (seed ^ (seed << 13)) & mask
        seed ^= seed >> 7
        seed = (seed ^ (seed << 17)) & mask
        nanos = 0 if i % 7 == 0 else 1 if i % 7 == 1 else mask if i % 7 == 2 else seed
        phase = i % 3
        rotated = ((seed << 17) | (seed >> 47)) & mask
        frequency = [
            0,
            1,
            10_000_000,
            62_500_000,
            3_000_000_000,
            mask,
            rotated,
            rotated,
        ][i % 8]
        ticks = (((3 * nanos + phase) * frequency) // 3_000_000_000) & mask
        words.extend([nanos, phase, frequency, ticks])
    return struct.pack('<40000Q', *words)


def verify(directory):
    assert (directory / 'trace.bin').read_bytes() == expected()
    return dict(
        events=10000, observation_bytes=320000, frequency_domain_bits=64, failed=0
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
        'src/vm/timing/context.rs',
        'src/vm/timing/retired.rs',
        'tests/suites/vm/counter_ticks.rs',
        'tools/execution/counter_ticks_guest.rs',
        'tools/execution/counter_ticks_oracle.py',
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
        return r

    library = run(
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
            '--message-format=json',
            '--lib',
            '--bin',
            'rax',
        ],
        600,
    )
    artifacts = {}
    for line in library.stdout.splitlines():
        row = json.loads(line)
        if row.get('reason') == 'compiler-artifact' and row['target']['name'] in [
            'rax',
            'vm_memory',
        ]:
            for name in row['filenames']:
                if name.endswith('.rlib'):
                    artifacts[row['target']['name']] = Path(name)
    assert set(artifacts) == {'rax', 'vm_memory'}
    for name, path in artifacts.items():
        shutil.copyfile(path, out / ('lib' + name + '.rlib'))
    run(
        'build',
        [
            'rustc',
            '+stable',
            '--edition=2024',
            str(root / 'tools/execution/counter_ticks_guest.rs'),
            '--extern',
            'rax=' + str(out / 'librax.rlib'),
            '--extern',
            'vm_memory=' + str(out / 'libvm_memory.rlib'),
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
    sampled_rows = list(range(8)) + list(range(9992, 10000))
    indices = [row * 4 + field for row in sampled_rows for field in range(4)]
    assert len(set(indices)) == 64
    probes = []
    for word in indices:
        mutant = bytearray(original)
        mutant[word * 8] ^= 1
        (out / 'trace.bin').write_bytes(mutant)
        try:
            try:
                verify(out)
            except AssertionError:
                pass
            else:
                raise RuntimeError(f'Verifier accepted mutated word{word}')
        finally:
            (out / 'trace.bin').write_bytes(original)
        probes.append(
            dict(
                word=word,
                rejected=True,
                mutant_sha256=hashlib.sha256(mutant).hexdigest(),
            )
        )
    assert len(probes) == 64 and verify(out) == report
    (out / 'fault-injection.json').write_text(
        json.dumps(dict(cases=64, rejected=64, failed=0, probes=probes), indent=2)
        + '\n'
    )
    assert before == {n: sha(root / n) for n in names}
    (out / 'manifest.json').write_text(
        json.dumps(
            dict(
                result='all_exact_frequency_counter_observations_match',
                report=report,
                commands=commands,
                source_sha256=before,
                libraries_sha256={
                    n: sha(out / ('lib' + n + '.rlib')) for n in artifacts
                },
                artifacts={
                    n: sha(out / n) for n in ['trace.bin', 'fault-injection.json']
                },
                scope='10000 complete full-u64 frequency/time cases with exact third-nanosecond phase and independent Python arbitrary-precision numerator;320000 observation bytes;conversion primitive only,no guest timer routing/coordinator/native-hypervisor proof.',
            ),
            indent=2,
        )
        + '\n'
    )
    print(json.dumps(report))


if __name__ == '__main__':
    main()
