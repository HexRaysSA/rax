"""Independently predict runtime PCI records, media and every guest-RAM byte."""

from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import shutil
import struct
import subprocess
import time
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def bridge(index):
    functions = [(0, 0x1237, 0x060000, 0, [], False)]
    if index:
        functions += [
            (1, 0x100E, 0x020000, 6, [(0, 0xFC000000, 0x20000, False)], True),
            (2, 0x7020, 0x0C0300, 1, [(4, 0xC001, 32, True)], False),
            (
                3,
                0x5845,
                0x010802,
                6,
                [(0, 0xE0000000 if index == 3 else 0xFC100000, 8192, False)],
                False,
            ),
            (4, 0x2922, 0x010601, 6, [(5, 0xFC200000, 8192, False)], False),
            (
                5,
                0x2415,
                0x040100,
                1,
                [
                    (0, 0xE001 if index == 3 else 0xD001, 256, True),
                    (1, 0xE101 if index == 3 else 0xD101, 64, True),
                ],
                False,
            ),
        ]
    out = bytearray(b'RAXPCI01') + struct.pack(
        '<III',
        0x80002814 if index == 3 else 0 if index else 0xA5,
        len(functions),
        6 if index else 0,
    )
    routes = []
    for key, device, kind, command, bars, pin in functions:
        data = bytearray(256)
        struct.pack_into('<HHH', data, 0, 0x8086, device, command)
        data[9:12] = kind.to_bytes(3, 'little')
        data[0x3D] = int(pin)
        metadata = [bytes(8) for _ in range(6)]
        for slot, base, size, io in bars:
            struct.pack_into('<I', data, 0x10 + slot * 4, base)
            metadata[slot] = struct.pack('<BIBBB', 1, size, int(io), 0, 0)
            routes.append(
                (
                    (0, key, 0),
                    slot,
                    size,
                    io,
                    base & (-size) & (0xFFFFFFFC if io else 0xFFFFFFF0),
                )
            )
        out += bytes([0, key, 0]) + data + b''.join(metadata)
    for key, slot, size, io, base in routes:
        out += bytes(key) + struct.pack('<BQBQ', slot, size, int(io), base)
    return bytes(out)


def nvme(index, continued):
    active = index == 4
    out = bytearray(b'RAXNVM01') + struct.pack(
        '<QQB4IQQHB',
        0,
        16384 if active else 0,
        0,
        0x00460001 if active else 0,
        int(active),
        0x42 if index == 2 else 0,
        0x00070007 if active else 0,
        0x1000 if active else 0,
        0x2000 if active else 0,
        4,
        int(active),
    )
    queues = [(0, 0, 0, 0, 0, 0, 0)] * 12
    if active:
        queues[0] = (0x1000, 8, 2, 2, 0, 0, 1)
        queues[1] = (0x2000, 8, 2, 2 if continued else 0, 1, 0, 1)
        queues[3] = (0x3000, 8, 1, 1, 0, 1, 1)
        queues[8] = (0x4000, 8, 1, 1 if continued else 0, 1, 1, 1)
    for queue in queues:
        out += struct.pack('<QIIIBHB', *queue)
    out += bytes([0, int(active), 0, 0, 0])
    return bytes(out)


def ahci(index, continued):
    active = index == 4
    ghc = 0x80000002 if index in [2, 4] else 0x80000000
    pending = active and not continued
    out = bytearray(b'RAXAHC01') + struct.pack(
        '<QQBIIIBQQ',
        0,
        16384 if active else 0,
        0,
        ghc,
        int(pending),
        32,
        int(pending),
        0xA000 if active else 0,
        0xB000 if active else 0,
    )
    port = (
        [33 if pending else 0, 0xFFFFFFFF, 17, 0x40, 0x101, 0x133, 0, 0, 0, 0]
        if active
        else [0, 0, 0, 0x7F, 0, 0, 0, 0, 0, 0]
    )
    out += struct.pack('<10I', *port)
    out += struct.pack(
        '<6BQI',
        int(active),
        0,
        0,
        0,
        0x35 if active else 0,
        0x40 if active else 0,
        int(active),
        0,
    )
    return bytes(out)


def ram(index):
    data = bytearray(0x20000)
    if index != 4:
        return bytes(data)
    for slot, op, buffer, flags in [(0, 5, 0x4000, 3), (1, 1, 0x3000, 0x10001)]:
        at = 0x1000 + slot * 64
        data[at] = op
        struct.pack_into('<Q', data, at + 24, buffer)
        struct.pack_into('<II', data, at + 40, 0x00070001, flags)
        struct.pack_into('<IIHHHH', data, 0x2000 + slot * 16, 0, 0, slot + 1, 0, 0, 1)
    data[0x3000] = 1
    struct.pack_into('<H', data, 0x3002, 1)
    struct.pack_into('<I', data, 0x3004, 1)
    struct.pack_into('<Q', data, 0x3018, 0x8000)
    struct.pack_into('<IIHHHH', data, 0x4000, 0, 0, 1, 1, 1, 1)
    data[0x8000:0x8200] = bytes([0x27]) * 512
    struct.pack_into('<IIQ', data, 0xA000, 0x00010045, 512, 0xC000)
    fis = bytearray(20)
    fis[0], fis[1], fis[2], fis[7], fis[12] = 0x27, 0x80, 0x35, 0x40, 1
    data[0xC000:0xC014] = fis
    struct.pack_into('<QII', data, 0xC080, 0xF000, 0, 0x800001FF)
    fis = bytearray(20)
    fis[0], fis[1], fis[2], fis[4], fis[7] = 0x34, 0x40, 0x40, 1, 0x40
    data[0xB040:0xB054] = fis
    data[0xF000:0xF200] = bytes([0x39]) * 512
    return bytes(data)


def expected(index, continued, models):
    result = {'bridge.bin': bridge(index), 'ram.raw': ram(index)}
    if not index:
        return result
    net = bytearray(models.net(0, False))
    usb = bytearray(models.usb(3, False))
    audio = bytearray(models.audio(6, False))
    struct.pack_into('<H', usb, 8, 0)
    if index == 2:
        struct.pack_into('<II', net, 167, 4, 4)
        struct.pack_into('<HH', usb, 10, 1, 0)
        usb[22] = 0xFF
        struct.pack_into('<H', audio, 10, 0x3412)
    if index == 3:
        struct.pack_into('<H', audio, 10, 0x8016)
    result.update(
        {
            'e1000.bin': bytes(net),
            'uhci.bin': bytes(usb),
            'ac97.bin': bytes(audio),
            'nvme.bin': nvme(index, continued),
            'ahci.bin': ahci(index, continued),
            'nvme.raw': bytes([0x27]) * 512 + bytes([0xA3]) * (16384 - 512)
            if index == 4
            else b'',
            'ahci.raw': bytes([0x39]) * 512 + bytes([0xB9]) * (16384 - 512)
            if index == 4
            else b'',
        }
    )
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--target-dir', type=Path, required=True)
    args = parser.parse_args()
    root, out = args.repo.resolve(), args.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    sources = [
        'src/vm/runtime.rs',
        'src/vm/runtime/pci_state.rs',
        'src/devices/bus.rs',
        'src/devices/pci.rs',
        'src/devices/pci/checkpoint.rs',
        'src/devices/checkpoint_wire.rs',
        'src/devices/virtio/block_image.rs',
        'src/config/storage.rs',
        'tests/suites/vm/runtime_pci_checkpoint.rs',
        'tools/checkpoint/runtime_pci_guest.rs',
        'tools/checkpoint/runtime_pci_oracle.py',
        'tools/checkpoint/pci_endpoint_oracle.py',
    ] + [
        f'src/devices/{n}{suffix}'
        for n in ['e1000', 'uhci', 'ac97', 'nvme', 'ahci']
        for suffix in ['.rs', '/checkpoint.rs']
    ]
    before = {n: sha(root / n) for n in sources}
    models = load(root / 'tools/checkpoint/pci_endpoint_oracle.py')
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
                str(root / 'tools/checkpoint/runtime_pci_guest.rs'),
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
    cases, totals = [], dict(control_bytes=0, media_bytes=0, ram_bytes=0, host_bytes=0)
    for index in range(5):
        artifacts = {}
        for continued in [False, True]:
            for name, wanted in expected(index, continued, models).items():
                name = ('continued-' if continued else '') + name
                path = out / f'case-{index}' / name
                actual = path.read_bytes()
                assert actual == wanted, (
                    index,
                    name,
                    len(actual),
                    len(wanted),
                    next(
                        (
                            i
                            for i, pair in enumerate(zip(actual, wanted))
                            if pair[0] != pair[1]
                        ),
                        None,
                    ),
                )
                totals[
                    'control_bytes'
                    if name.endswith('.bin')
                    else 'ram_bytes'
                    if 'ram.raw' in name
                    else 'media_bytes'
                ] += len(actual)
                artifacts[name] = sha(path)
        if index == 4:
            for name, value in [('host-n.raw', 0xA3), ('host-a.raw', 0xB9)]:
                path = out / f'case-{index}' / name
                assert path.read_bytes() == bytes([value]) * 16384
                totals['host_bytes'] += 16384
                artifacts[name] = sha(path)
        cases.append(dict(index=index, artifacts=artifacts))
    assert before == {n: sha(root / n) for n in sources}
    report = dict(cases=5, continuation_events=4, **totals, failed=0)
    (out / 'manifest.json').write_text(
        json.dumps(
            dict(
                source_sha256=before,
                library_sha256=sha(library),
                commands=commands,
                cases=cases,
                report=report,
                result='independent_runtime_pci_state_media_and_ram_match',
            ),
            indent=2,
        )
        + '\n'
    )
    print(json.dumps(report))


if __name__ == '__main__':
    main()
