"""Independent PCI record layout and routing expectations; no product decoder."""

from __future__ import annotations
import argparse
import hashlib
import json
import shutil
import struct
import subprocess
import time
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def config(host=False, io=False, base=0x100000, command=2):
    data = bytearray(256)
    struct.pack_into('<HH', data, 0, 0x8086, 0x1237 if host else 0x1234)
    data[9:12] = bytes([0, 0, 6] if host else [2, 8, 1])
    if not host:
        struct.pack_into('<H', data, 4, command)
        struct.pack_into('<I', data, 16, base)
    return bytes(data)


def decode(data):
    assert data[:8] == b'RAXPCI01'
    latch, count, endpoints = struct.unpack_from('<III', data, 8)
    assert len(data) == 20 + 307 * count + 21 * endpoints
    at, functions, routing = 20, [], []
    for _ in range(count):
        key = tuple(data[at : at + 3])
        raw = data[at + 3 : at + 259]
        bars = []
        at += 259
        for _ in range(6):
            present, size, io, prefetch, bits64 = struct.unpack_from('<BIBBB', data, at)
            assert all(v in [0, 1] for v in [present, io, prefetch, bits64])
            bars.append((present, size, io, prefetch, bits64))
            at += 8
        functions.append((key, raw, bars))
    for _ in range(endpoints):
        key = tuple(data[at : at + 3])
        index, size, io, base = struct.unpack_from('<BQBQ', data, at + 3)
        assert io in [0, 1]
        routing.append((key, index, size, io, base))
        at += 21
    assert at == len(data)
    return latch, functions, routing


def expected(index):
    io = index == 5
    base = (
        0xD001
        if io
        else 0x300000
        if index in [1, 4]
        else 0xFFFFFFFF
        if index == 3
        else 0x100000
    )
    latch = 0x80000810 if index in [1, 3, 5] else 0x80000804 if index == 2 else 0
    empty = [(0, 0, 0, 0, 0)] * 6
    bars = [(1, 32 if io else 4096, int(io), 0, 0)] + empty[1:]
    functions = [
        ((0, 0, 0), config(host=True), empty),
        (
            (0, 1, 0),
            config(io=io, base=base, command=0 if index == 2 else 1 if io else 2),
            bars,
        ),
    ]
    route_base = (
        0 if index in [2, 3] else 0xD000 if io else 0x300000 if index == 1 else 0x100000
    )
    routes = [((0, 1, 0), 0, 32 if io else 4096, int(io), route_base)]
    if index == 6:
        functions.append(((0, 2, 0), config(), bars))
        routes.append(((0, 2, 0), 0, 4096, 0, 0x100000))
    values = [None, None, None, None]
    if index in [0, 4, 6]:
        values[0] = 1 if index == 6 else 0x5A
    elif index == 1:
        values[1] = 0x5A
    elif index == 5:
        values[3] = 0x69
    trace = bytes(v for value in values for v in [int(value is not None), value or 0])
    return (latch, functions, routes), trace


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--target-dir', type=Path, required=True)
    args = parser.parse_args()
    root, out = args.repo.resolve(), args.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    sources = [
        'src/devices/pci.rs',
        'src/devices/pci/checkpoint.rs',
        'src/devices/checkpoint_wire.rs',
        'tests/suites/devices/pci_checkpoint.rs',
        'tools/checkpoint/pci_guest.rs',
        'tools/checkpoint/pci_oracle.py',
    ]
    before = {p: sha(root / p) for p in sources}
    library = out / 'librax.rlib'
    shutil.copyfile(args.target_dir / 'debug/librax.rlib', library)
    commands = []
    for name, command in [
        (
            'build',
            [
                'rustc',
                '+stable',
                '--edition=2024',
                str(root / 'tools/checkpoint/pci_guest.rs'),
                '--extern',
                'rax=' + str(library),
                '-L',
                'dependency=' + str(args.target_dir / 'debug/deps'),
                '-o',
                str(out / 'publish'),
            ],
        ),
        ('publish', [str(out / 'publish'), str(out)]),
    ]:
        start = time.monotonic()
        with (
            (out / (name + '.stdout')).open('w') as stdout,
            (out / (name + '.stderr')).open('w') as stderr,
        ):
            result = subprocess.run(command, cwd=root, stdout=stdout, stderr=stderr)
        commands.append(
            dict(
                name=name,
                args=command,
                code=result.returncode,
                seconds=time.monotonic() - start,
            )
        )
        assert result.returncode == 0, name
    cases, control_bytes, routing_bytes = [], 0, 0
    for index in range(7):
        artifacts = {}
        state, trace = expected(index)
        for name in [
            'source.bin',
            'restored.bin',
            'source-routes.bin',
            'restored-routes.bin',
        ]:
            path = out / f'case-{index}' / name
            data = path.read_bytes()
            if 'routes' in name:
                assert data == trace, (index, name, data, trace)
                routing_bytes += len(data)
            else:
                assert decode(data) == state, (index, name)
                control_bytes += len(data)
            artifacts[name] = sha(path)
        cases.append(dict(index=index, artifacts=artifacts))
    assert before == {p: sha(root / p) for p in sources}
    report = dict(
        cases=7, control_bytes=control_bytes, routing_bytes=routing_bytes, failed=0
    )
    (out / 'manifest.json').write_text(
        json.dumps(
            dict(
                source_sha256=before,
                library_sha256=sha(library),
                commands=commands,
                cases=cases,
                report=report,
                result='independent_pci_configuration_and_routing_match',
            ),
            indent=2,
        )
        + '\n'
    )
    print(json.dumps(report))


if __name__ == '__main__':
    main()
