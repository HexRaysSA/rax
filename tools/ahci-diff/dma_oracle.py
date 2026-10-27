"""Capture independent QEMU AHCI register/FIS/DMA/media records."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import subprocess
import time
from pathlib import Path


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def initial_disk():
    return bytes((i * 37 ^ (i >> 9) ^ 0xA5) & 255 for i in range(64 * 512))


def make_input(index):
    writes = []
    steps = []
    outputs = []
    expected = []

    def put(addr, data):
        assert len(data) % 4 == 0
        writes.extend(
            (addr + i, struct.unpack_from('<I', data, i)[0])
            for i in range(0, len(data), 4)
        )

    def add(op, lba=0, blocks=1, segments=(), slot=0):
        table = 0x01002000 + len(steps) * 0x1000
        fis = bytearray(128)
        fis[:3] = bytes([0x27, 0x80, op])
        fis[7] = 0x40
        for n, off in enumerate([4, 5, 6, 8, 9, 10]):
            fis[off] = (lba >> (8 * n)) & 255
        struct.pack_into('<H', fis, 12, blocks)
        for addr, length, ioc in segments:
            fis += struct.pack('<QII', addr, 0, (length - 1) | (int(ioc) << 31))
        put(table, fis)
        header = struct.pack(
            '<IIQ16x', 5 | ((op == 0x35) << 6) | (len(segments) << 16), 0, table
        )
        steps.append(struct.pack('<I', slot) + header)
        expected.append(
            {'op': op, 'lba': lba, 'blocks': blocks, 'segments': segments, 'slot': slot}
        )

    a, b = 0x02000000, 0x02002000
    if index == 0:
        put(a, bytes([0xEE]) * 1024)
        add(0x25, 3, 2, [(a, 1024, True)])
        outputs = [(a, 1024)]
    elif index == 1:
        put(a, bytes([0xEE]) * 256)
        put(b, bytes([0xEE]) * 768)
        add(0x25, 7, 2, [(a, 256, True), (b, 768, True)], 31)
        outputs = [(a, 256), (b, 768)]
    elif index == 2:
        put(a, bytes((i * 11 + 9) & 255 for i in range(256)))
        put(b, bytes((i * 13 + 7) & 255 for i in range(768)))
        add(0x35, 11, 2, [(a, 256, True), (b, 768, True)], 4)
        add(0x25, 11, 2, [(a + 0x4000, 1024, True)], 8)
        outputs = [(a + 0x4000, 1024)]
    elif index == 3:
        add(0xE7, slot=17)
        add(0xEA, slot=31)
    elif index == 4:
        put(a, bytes([0xEE]) * 512)
        add(0xEC, segments=[(a, 512, True)])
        outputs = [(a, 512)]
    elif index == 5:
        put(a, bytes([0xEE]) * 512)
        add(0x25, 64, 1, [(a, 512, True)])
        outputs = [(a, 512)]
    elif index == 6:
        add(0xFF, slot=31)
        add(0x25, 1, 1, [(a, 512, False)])
        outputs = [(a, 512)]
    elif index == 7:
        put(a, bytes([0xEE]) * 1536)
        add(0x25, 61, 3, [(a, 1536, False)], 31)
        outputs = [(a, 1536)]
    elif index == 8:
        a += 4094
        put(a, bytes([0xEE]) * 1024)
        add(0x25, 4, 2, [(a, 2, True), (b + 2, 1022, True)], 13)
        outputs = [(a, 2), (b + 2, 1022)]
    elif index == 9:
        put(a, bytes([0xEE]) * 768)
        add(0x25, 8, 2, [(a, 512, True), (a + 256, 512, False)], 5)
        outputs = [(a, 768)]
    elif index == 10:
        put(a, bytes((i * 29 + 3) & 255 for i in range(1024)))
        add(0x35, 63, 1, [(a, 512, False)], 31)
        add(0xEA, slot=0)
        add(0x35, 0, 1, [(a + 512, 512, True)], 17)
        add(0x25, 0, 1, [(b, 512, True)], 1)
        add(0x25, 63, 1, [(b + 512, 512, False)], 31)
        outputs = [(b, 1024)]
    else:
        raise ValueError(index)
    raw = struct.pack('<III', len(steps), len(writes), len(outputs)) + b''.join(steps)
    raw += b''.join(struct.pack('<II', *x) for x in writes + outputs)
    return raw, expected, outputs


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[2])
    p.add_argument('--work-dir', type=Path, required=True)
    p.add_argument('--llvm-bin', type=Path, required=True)
    p.add_argument('--qemu', default='qemu-system-x86_64')
    p.add_argument('--reference-only', action='store_true')
    p.add_argument('--target-dir', type=Path)
    a = p.parse_args()
    repo = a.repo.resolve()
    here = Path(__file__).resolve().parent
    out = a.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    marker = out / '.rax-ahci-dma'
    if any(out.iterdir()) and (
        not marker.is_file() or marker.read_text() != 'version=1\n'
    ):
        raise ValueError('Use empty or owned evidence directory')
    marker.write_text('version=1\n')
    sources = [
        'src/devices/ahci.rs',
        'src/devices/ahci/dma.rs',
        'src/devices/ahci/command.rs',
        'tests/suites/devices/ahci_dma.rs',
        'tools/ahci-diff/dma_oracle.py',
        'tools/ahci-diff/dma_guest.s',
        'tools/ahci-diff/dma_compare.rs',
    ]
    bound = {n: sha(repo / n) for n in sources}
    manifest = {
        'version': 1,
        'product_source_sha256': bound,
        'tool_sha256': sha(Path(__file__)),
        'guest_source_sha256': sha(here / 'dma_guest.s'),
        'commands': [],
        'cases_completed': [],
    }

    def run(name, cmd, cwd=out, expected=0):
        start = time.monotonic()
        try:
            r = subprocess.run(
                cmd, cwd=cwd, capture_output=True, timeout=60, check=False
            )
        except subprocess.TimeoutExpired as e:
            (cwd / (name + '.stdout')).write_bytes(e.stdout or b'')
            (cwd / (name + '.stderr')).write_bytes(e.stderr or b'')
            raise
        (cwd / (name + '.stdout')).write_bytes(r.stdout)
        (cwd / (name + '.stderr')).write_bytes(r.stderr)
        manifest['commands'].append(
            {
                'name': name,
                'args': [str(x) for x in cmd],
                'code': r.returncode,
                'seconds': time.monotonic() - start,
            }
        )
        (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        if r.returncode != expected:
            raise RuntimeError(
                f'{name}: {r.returncode}, expected {expected}; diagnostics retained'
            )

    run('qemu-version', [a.qemu, '--version'])
    run('llvm-version', [str(a.llvm_bin / 'llvm-mc'), '--version'])
    for index in range(11):
        case = out / f'case-{index}'
        case.mkdir(exist_ok=True)
        raw, commands, outputs = make_input(index)
        (case / 'input.bin').write_bytes(raw)
        (case / 'initial.raw').write_bytes(initial_disk())
        (case / 'disk.raw').write_bytes(initial_disk())
        shutil.copyfile(here / 'dma_guest.s', case / 'guest.s')
        (case / 'link.ld').write_text(
            'ENTRY(_start)\nSECTIONS {. = 0x100000; .multiboot : {*(.multiboot)} .text : {*(.text*)} .rodata : {*(.rodata*)} .data : {*(.data*)} .bss : {*(.bss*) *(COMMON)}}\n'
        )
        run(
            'assemble',
            [
                str(a.llvm_bin / 'llvm-mc'),
                '-triple=i386-none-elf',
                '-filetype=obj',
                'guest.s',
                '-o',
                'guest.o',
            ],
            case,
        )
        run(
            'link',
            [
                str(a.llvm_bin / 'ld.lld'),
                '-m',
                'elf_i386',
                '-T',
                'link.ld',
                'guest.o',
                '-o',
                'guest.elf',
            ],
            case,
        )
        run(
            'qemu',
            [
                a.qemu,
                '-machine',
                'pc',
                '-cpu',
                'max',
                '-accel',
                'tcg,thread=single',
                '-m',
                '128M',
                '-nodefaults',
                '-display',
                'none',
                '-monitor',
                'none',
                '-serial',
                'none',
                '-debugcon',
                'file:' + str(case / 'records.bin'),
                '-drive',
                'if=none,id=disk,format=raw,file=' + str(case / 'disk.raw'),
                '-device',
                'ich9-ahci,id=ahci',
                '-device',
                'ide-hd,drive=disk,bus=ahci.0',
                '-device',
                'isa-debug-exit,iobase=0xf4,iosize=0x04',
                '-no-reboot',
                '-kernel',
                str(case / 'guest.elf'),
            ],
            case,
            33,
        )
        data = (case / 'records.bin').read_bytes()
        assert (
            data[:8] == b'RAXAHCI1'
            and data[8:20] == raw[:12]
            and data[-8:] == b'AHCIDONE'
        )
        assert len(data) == 28 + 288 * len(commands) + sum(n for _, n in outputs)
        # Independent byte-addressed expected memory/media model. The actual
        # reference output must meet these contracts before product comparison.
        memory = {}
        n, writes, _ = struct.unpack_from('<III', raw)
        at = 12 + 36 * n
        for _ in range(writes):
            address, value = struct.unpack_from('<II', raw, at)
            at += 8
            memory.update(
                (address + i, b) for i, b in enumerate(struct.pack('<I', value))
            )
        media = bytearray(initial_disk())
        for command in commands:
            op, lba, blocks = command['op'], command['lba'], command['blocks'] or 65536
            segments = command['segments']
            start = lba * 512
            length = blocks * 512
            if op == 0x25 and start + length <= len(media):
                offset = 0
                for address, count, _ in segments:
                    chunk = media[start + offset : start + offset + count]
                    offset += len(chunk)
                    memory.update((address + i, b) for i, b in enumerate(chunk))
            elif op == 0x35 and start + length <= len(media):
                chunk = bytes(
                    memory.get(address + i, 0)
                    for address, count, _ in segments
                    for i in range(count)
                )
                assert len(chunk) == length
                media[start : start + length] = chunk
        assert (case / 'disk.raw').read_bytes() == media, (index, 'independent media')
        payload_at = 20 + 288 * len(commands)
        for address, length in outputs:
            got = data[payload_at : payload_at + length]
            if index == 4:
                assert len(got) == 512 and struct.unpack_from('<I', got, 120)[0] == 64
                assert struct.unpack_from('<Q', got, 200)[0] == 64
            else:
                assert got == bytes(
                    memory.get(address + i, 0) for i in range(length)
                ), (index, 'independent payload')
            payload_at += length
        records = []
        for n, command in enumerate(commands):
            offset = 20 + 288 * n
            regs = struct.unpack_from('<8I', data, offset)
            error = command['op'] == 0xFF or (
                command['op'] in [0x25, 0x35]
                and (command['lba'] + (command['blocks'] or 65536)) * 512
                > len(initial_disk())
            )
            assert regs[2] == (1 << command['slot'] if error else 0), (
                index,
                n,
                'CI',
                regs,
            )
            assert regs[6] == (
                0
                if error or command['op'] in [0xE7, 0xEA]
                else 512
                if command['op'] == 0xEC
                else (command['blocks'] or 65536) * 512
            ), (index, n, 'PRDBC', regs)
            assert bool(regs[0] & (1 << 30)) == error and regs[1] & 1 == 1
            assert regs[3] & 0x89 == (1 if error else 0)
            records.append(
                {
                    'command': command,
                    'registers': list(regs),
                    'fis': data[offset + 32 : offset + 288].hex(),
                }
            )
        manifest['cases_completed'].append(
            {
                'index': index,
                'commands': records,
                'outputs': outputs,
                'artifact_sha256': {
                    n: sha(case / n)
                    for n in [
                        'input.bin',
                        'initial.raw',
                        'disk.raw',
                        'guest.s',
                        'guest.elf',
                        'records.bin',
                    ]
                },
            }
        )
        (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    assert bound == {n: sha(repo / n) for n in sources}
    if not a.reference_only:
        if here.parents[1] != repo or a.target_dir is None:
            raise ValueError(
                'Use selected checkout tool and --target-dir containing built current library'
            )
        library = a.target_dir.resolve() / 'debug/librax.rlib'
        digest = sha(library)
        shutil.copyfile(library, out / 'librax.rlib')
        run(
            'product-build',
            [
                'rustc',
                '+stable',
                '--edition=2024',
                str(here / 'dma_compare.rs'),
                '--extern',
                'rax=' + str(out / 'librax.rlib'),
                '-L',
                'dependency=' + str(a.target_dir.resolve() / 'debug/deps'),
                '-o',
                str(out / 'compare'),
            ],
        )
        run('product-compare', [str(out / 'compare'), str(out)])
        manifest['report'] = json.loads((out / 'product-compare.stdout').read_text())
        manifest['library_sha256'] = digest
        differences = []
        for case in manifest['cases_completed']:
            path = out / f"case-{case['index']}"
            reference = (path / 'records.bin').read_bytes()
            product = (path / 'product-records.bin').read_bytes()
            for step, command in enumerate(case['commands']):
                at = 20 + 288 * step
                r = struct.unpack_from('<8I', reference, at)
                v = struct.unpack_from('<8I', product, at)
                fields = {
                    name: {'reference': a, 'product': b}
                    for name, a, b in zip(
                        [
                            'PxIS',
                            'IS',
                            'PxCI',
                            'PxTFD',
                            'PxCMD',
                            'PxSSTS',
                            'PRDBC',
                            'PxSERR',
                        ],
                        r,
                        v,
                    )
                    if a != b
                }
                fis = [
                    {
                        'offset': i,
                        'reference': reference[at + 32 + i],
                        'product': product[at + 32 + i],
                    }
                    for i in range(256)
                    if reference[at + 32 + i] != product[at + 32 + i]
                ]
                differences.append(
                    {
                        'case': case['index'],
                        'step': step,
                        'registers': fields,
                        'fis_bytes': fis,
                    }
                )
            case['artifact_sha256'].update(
                {n: sha(path / n) for n in ['product-records.bin', 'product-disk.raw']}
            )
        (out / 'profile-differences.json').write_text(
            json.dumps(differences, indent=2) + '\n'
        )
        manifest['profile_differences_sha256'] = sha(out / 'profile-differences.json')
        assert sha(library) == digest
        manifest['result'] = (
            'shared_result_payload_media_match_with_explicit_profile_differences'
        )
    else:
        manifest['result'] = 'independent_reference_capture_only'
    assert bound == {n: sha(repo / n) for n in sources}
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(
        json.dumps(
            manifest.get(
                'report',
                {
                    'cases': 11,
                    'commands': sum(
                        len(x['commands']) for x in manifest['cases_completed']
                    ),
                    'reference_only': True,
                },
            )
        )
    )


if __name__ == '__main__':
    main()
