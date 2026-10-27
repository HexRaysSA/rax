"""Independent counter/notification model and actual VM clock isolation bounds."""

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


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def verify(directory):
    expected = [37, 111000, 1, 11, 33000, 0, 37, 1, 0, 0, 0, 11]
    assert (directory / 'contexts.bin').read_bytes() == struct.pack('<12Q', *expected)
    base, before, other, resumed = struct.unpack(
        '<4Q', (directory / 'restore.bin').read_bytes()
    )
    assert base == 1_000_000_000_000_000
    assert before <= other < base <= resumed < 2 * base
    return dict(
        contexts=2,
        exact_counter_notification_bytes=96,
        wall_observation_bytes=32,
        isolated_vm_restores=1,
        failed=0,
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
        'src/vm/runtime.rs',
        'tests/suites/vm/vm_timing.rs',
        'tools/execution/timing_guest.rs',
        'tools/execution/timing_restore_guest.rs',
        'tools/execution/timing_oracle.py',
    ]
    before = {n: sha(root / n) for n in names}
    e = os.environ.copy()
    e['CARGO_TARGET_DIR'] = str(a.target_dir)
    e['CARGO_BUILD_JOBS'] = '1'
    e['CARGO_MANIFEST_DIR'] = str(root)
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
            str(root / 'tools/execution/timing_guest.rs'),
            '--extern',
            'rax=' + str(out / 'librax.rlib'),
            '-L',
            'dependency=' + str(a.target_dir / 'debug/deps'),
            '-o',
            str(out / 'publish'),
        ],
        60,
    )
    run('publish', [str(out / 'publish'), str(out)], 60)
    report = verify(out)
    contexts = (out / 'contexts.bin').read_bytes()
    wall = (out / 'restore.bin').read_bytes()
    probes = []
    for i in range(12):
        mutant = bytearray(contexts)
        mutant[8 * i] ^= 1
        probes.append(('contexts.bin', 'word' + str(i), bytes(mutant)))
    base = struct.unpack_from('<Q', wall)[0]
    for label, word, value in [
        ('wrong-base', 0, base ^ 1),
        ('contaminated-other', 2, base),
        ('unrestored-target', 3, base - 1),
        ('invalid-before', 1, base),
    ]:
        mutant = bytearray(wall)
        struct.pack_into('<Q', mutant, word * 8, value)
        probes.append(('restore.bin', label, bytes(mutant)))
    receipts = []
    for name, label, mutant in probes:
        (out / name).write_bytes(mutant)
        try:
            try:
                verify(out)
            except AssertionError:
                pass
            else:
                raise RuntimeError('Verifier accepted ' + label)
        finally:
            (out / 'contexts.bin').write_bytes(contexts)
            (out / 'restore.bin').write_bytes(wall)
        receipts.append(
            dict(
                artifact=name,
                label=label,
                rejected=True,
                mutant_sha256=hashlib.sha256(mutant).hexdigest(),
            )
        )
    assert verify(out) == report and len(receipts) == 16
    (out / 'fault-injection.json').write_text(
        json.dumps(dict(cases=16, rejected=16, failed=0, probes=receipts), indent=2)
        + '\n'
    )
    assert before == {n: sha(root / n) for n in names}
    (out / 'manifest.json').write_text(
        json.dumps(
            dict(
                result='counter_notification_model_and_vm_clock_isolation_match',
                report=report,
                commands=commands,
                source_sha256=before,
                library_sha256=sha(out / 'librax.rlib'),
                artifacts={
                    n: sha(out / n)
                    for n in ['contexts.bin', 'restore.bin', 'fault-injection.json']
                },
                scope='96modeled counter/notification bytes;32runtime timestamp bytes checked by isolation/monotonicity bounds,not exact wall-time values.No retirement clock/native/SMP/replay proof.',
            ),
            indent=2,
        )
        + '\n'
    )
    print(json.dumps(report))


if __name__ == '__main__':
    main()
