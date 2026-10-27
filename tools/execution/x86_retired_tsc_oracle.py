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


def expected(*, predecessor=False):
    mask = (1 << 64) - 1
    words = []
    for kind in range(4):
        for units in [0, 1, 2, 1000, 0x1_0000_0001, mask]:
            for adjust in [0, 1, mask]:
                base = units // 3 * 3 if predecessor else units
                value = base & ((1 << 40) - 1) if kind == 3 else (base + adjust) & mask
                rcx = 0xA5A5_1234 if kind == 1 else 0x10 if kind == 2 else 0
                pc = 4096 + (3 if kind == 1 else 2)
                words.extend([kind, units, adjust, value, rcx, (units + 1) & mask, pc])
    return struct.pack('<504Q', *words)


def verify(directory):
    assert (directory / 'trace.bin').read_bytes() == expected()
    return dict(counter_paths=4, observations=72, observation_bytes=4032, failed=0)


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
        'src/isa/x86_64/cpu.rs',
        'src/isa/x86_64/cpu_timing.rs',
        'src/isa/x86_64/cpu_jit_tsc.rs',
        'src/isa/x86_64/execute/system/timing.rs',
        'src/isa/x86_64/execute/system/msr.rs',
        'tests/suites/backend/x86_retired_tsc.rs',
        'tools/execution/x86_retired_tsc_guest.rs',
        'tools/execution/x86_retired_tsc_oracle.py',
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
            str(root / 'tools/execution/x86_retired_tsc_guest.rs'),
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
    indices = list(range(72 * 7))
    assert len(set(indices)) == 504
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
    assert len(probes) == 504 and verify(out) == report
    (out / 'fault-injection.json').write_text(
        json.dumps(dict(cases=504, rejected=504, failed=0, probes=probes), indent=2)
        + '\n'
    )
    assert before == {n: sha(root / n) for n in names}
    (out / 'manifest.json').write_text(
        json.dumps(
            dict(
                result='all_selected_x86_timestamp_observations_match',
                report=report,
                commands=commands,
                source_sha256=before,
                libraries_sha256={
                    n: sha(out / ('lib' + n + '.rlib')) for n in artifacts
                },
                artifacts={
                    n: sha(out / n) for n in ['trace.bin', 'fault-injection.json']
                },
                scope='Actual RDTSC,RDTSCP,RDMSR(TSC),RDPMC paths;72 selected-counter observations/4032 bytes with independent integer model;no physical native-hypervisor,coordinator,SMP or complete timer/replay proof.',
            ),
            indent=2,
        )
        + '\n'
    )
    print(json.dumps(report))


if __name__ == '__main__':
    main()
