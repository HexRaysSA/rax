"""Independent endpoint wire, continuation-event and guest-RAM expectations."""

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


def net(index, continued):
    mac = (
        bytes([2, 3, 4, 5, 6, 7])
        if index == 2
        else bytes([0x52, 0x54, 0, 0x12, 0x34, 0x56])
    )
    eeprom = [0] * 64
    eeprom[:3] = struct.unpack('<3H', mac)
    eeprom[3] = 0x100E
    eeprom[63] = (0xBABA - sum(eeprom)) & 0xFFFF
    out = bytearray(b'RAXE1K01')
    out += struct.pack('<II64HII', 0, 3, *eeprom, 3 if index == 2 else 0, 0)
    phase = (
        (
            0 if continued else 0x180,
            0 if continued else 9,
            int(not continued),
            0x0302,
            16 if continued else 5,
            1,
            0,
        )
        if index == 2
        else (0, 0, 0, 0, 0, 0, 0)
    )
    out += struct.pack('<HBBHBBB', *phase)
    out += mac
    registers = [0] * 16
    registers[14] = int.from_bytes(mac[:4], 'little')
    registers[15] = int.from_bytes(mac[4:], 'little') | 0x80000000
    if index == 1:
        registers[0:2] = [1, 1]
        registers[8:14] = [
            2,
            0x100,
            0,
            128,
            3 if continued else 2,
            3 if continued else 2,
        ]
    out += struct.pack('<16I', *registers)
    out += bytes(128 * 4)
    partial = b'part' if index == 1 and not continued else b''
    frames = ([b'first', b'partial'] if continued else [b'first']) if index == 1 else []
    out += struct.pack('<I', len(partial)) + partial + struct.pack('<I', len(frames))
    for frame in frames:
        out += struct.pack('<I', len(frame)) + frame
    return bytes(out)


def usb(index, continued):
    out = bytearray(b'RAXUHC01')
    out += struct.pack(
        '<5HIB',
        0xC000,
        0 if index == 3 else 1,
        0x20 if index == 3 else 0,
        15 if index == 4 else 0,
        (0 if continued else 2047) if index == 4 else int(continued and index == 5),
        0x1000 if index == 5 else 0,
        0xFF if index == 4 else 0x40,
    )
    out += (
        bytes([1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0])
        if index == 4
        else bytes(16)
    )
    return bytes(out)


def audio(index, continued):
    mixer = [0] * 128
    for off, value in [
        (0, 0x11),
        (2, 0x8000),
        (4, 0x8000),
        (6, 0x8000),
        (0x18, 0x8000),
        (0x26, 0xF000),
        (0x7C, 0x5241),
        (0x7E, 0x5801),
    ]:
        mixer[off // 2] = value
    out = bytearray(b'RAXAC901') + struct.pack('<128H', *mixer)
    finished = index == 8 or (index == 7 and continued)
    for channel in range(3):
        active = index in [7, 8] and channel == 1
        out += struct.pack(
            '<IBBHHBB',
            0x100 if active else 0,
            0,
            0,
            (15 if finished else 0) if active else 1,
            0,
            0,
            0x11 if active else 0,
        )
    out += struct.pack('<IIQ', 0, 0x100, 8 if finished else 0)
    return bytes(out)


def descriptor(ram, index, address, payload, end):
    at = 0x100 + index * 16
    struct.pack_into('<QH', ram, at, address, len(payload))
    ram[at + 11] = 8 | int(end)
    ram[address : address + len(payload)] = payload


def ram(index, continued):
    if index == 1:
        data = bytearray(0x4000)
        descriptor(data, 0, 0x1000, b'first', True)
        descriptor(data, 1, 0x1100, b'part', False)
        data[0x10C] = data[0x11C] = 1
        if continued:
            data[0x1000:0x1005] = b'xxxxx'
            descriptor(data, 2, 0x1200, b'ial', True)
            data[0x12C] = 1
        return bytes(data)
    if index == 5:
        data = bytearray(0x2000)
        struct.pack_into('<I', data, 0x1000, 1)
        return bytes(data)
    if index in [7, 8]:
        data = bytearray(0x3000)
        struct.pack_into('<II', data, 0x100, 0x1000, 0x80000004)
        data[0x1000:0x1008] = b'samples!'
        return bytes(data)
    return b''


def event(index):
    if index == 1:
        return struct.pack('<I', 5) + b'first' + struct.pack('<I', 7) + b'partial'
    if index == 2:
        return struct.pack('<H', 0x0302)
    if index == 4:
        return struct.pack('<H', 0)
    if index == 5:
        return struct.pack('<QH', 0, 1)
    if index in [7, 8]:
        return struct.pack('<QQB', int(index == 7), 8, 1)
    return b''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--target-dir', type=Path, required=True)
    args = parser.parse_args()
    root, out = args.repo.resolve(), args.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    sources = [
        f'src/devices/{name}{suffix}'
        for name in ['e1000', 'uhci', 'ac97']
        for suffix in ['.rs', '/checkpoint.rs']
    ] + [
        'src/devices/checkpoint_wire.rs',
        'tests/suites/devices/pci_endpoint_checkpoint.rs',
        'tools/checkpoint/pci_endpoint_guest.rs',
        'tools/checkpoint/pci_endpoint_oracle.py',
    ]
    before = {n: sha(root / n) for n in sources}
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
                str(root / 'tools/checkpoint/pci_endpoint_guest.rs'),
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
    cases, totals = [], dict(control_bytes=0, ram_bytes=0, event_bytes=0)
    for index in range(9):
        control = net if index < 3 else usb if index < 6 else audio
        expected = {
            'control.bin': control(index, False),
            'continued-control.bin': control(index, True),
            'ram.raw': ram(index, False),
            'continued-ram.raw': ram(index, True),
            'event.bin': event(index),
        }
        artifacts = {}
        for name, wanted in expected.items():
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
                if 'control' in name
                else 'ram_bytes'
                if 'ram' in name
                else 'event_bytes'
            ] += len(actual)
            artifacts[name] = sha(path)
        cases.append(dict(index=index, artifacts=artifacts))
    assert before == {n: sha(root / n) for n in sources}
    report = dict(cases=9, continuation_events=6, **totals, failed=0)
    (out / 'manifest.json').write_text(
        json.dumps(
            dict(
                source_sha256=before,
                library_sha256=sha(library),
                commands=commands,
                cases=cases,
                report=report,
                result='independent_endpoint_state_ram_and_continuation_match',
            ),
            indent=2,
        )
        + '\n'
    )
    print(json.dumps(report))


if __name__ == '__main__':
    main()
