#!/usr/bin/env python3
"""Reproduce scalar MOV operand records and run the full native MMIO plan tests.

Direct TCG RAM instructions establish register/data effects. Product fixtures
present the same operand as an MMIO hole; native VMX/device delivery is separate.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def instructions():
    result = []
    for index in range(16):
        for size in [1, 2, 4, 8]:
            rex = (8 if size == 8 else 0) | (4 if index >= 8 else 0)
            prefix = ([0x66] if size == 2 else [])
            if rex or (size == 1 and index in range(4, 8)):
                prefix += [0x40 | rex]
            for write in [False, True]:
                opcode = (0x88 if write else 0x8a) + (size != 1)
                result.append(bytes(prefix + [opcode, ((index & 7) << 3) | 7]))
    for high in range(4, 8):
        for opcode in [0x8a, 0x88]:
            result.append(bytes([opcode, (high << 3) | 7]))
    for signed in [False, True]:
        for source in [1, 2]:
            for destination in [2, 4, 8]:
                if destination <= source:
                    continue
                for index in range(16):
                    prefix = [0x66] if destination == 2 else []
                    rex = (8 if destination == 8 else 0) | (4 if index >= 8 else 0)
                    if rex:
                        prefix.append(0x40 | rex)
                    opcode = (0xbe if signed else 0xb6) + (source == 2)
                    result.append(bytes(prefix + [0x0f, opcode, ((index & 7) << 3) | 7]))
    result += [bytes.fromhex(x) for x in ['c607a5', '66c707a55a', 'c70778563412', '48c707ffffffff', '48c70700000080']]
    assert len(result) == 301 and len(set(result)) == len(result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--llvm-bin', type=Path, required=True)
    parser.add_argument('--qemu', default='qemu-system-x86_64')
    parser.add_argument('--capture', action='store_true', help='Create absent owned reference fixture files')
    parser.add_argument('--reference-only', action='store_true', help='Generate reference only; no product-validation claim')
    args = parser.parse_args()
    repo = args.repo.resolve()
    out = args.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    owner = out / '.rax-hvf-mmio'
    if any(out.iterdir()) and (not owner.is_file() or owner.read_text() != 'version=1\n'):
        raise ValueError('Use an empty or owned version1 directory')
    owner.write_text('version=1\n')
    cases = bytearray()
    for instruction in instructions():
        for data in [0x123456788080ff80, 0xfedcba987f7f007f]:
            for flags in [2, 0x8d7]:
                registers = [0x123456789abcdef0 ^ (index * 0x0101010101010101) for index in range(16)]
                registers[4] = 0x400000
                registers[7] = 0x200000
                opcode = next(byte for byte in instruction if byte != 0x66 and not 0x40 <= byte <= 0x4f)
                write = int(opcode in [0x88, 0x89, 0xc6, 0xc7])
                cases += struct.pack('<16QQQI16sI', *registers, data, flags, len(instruction), instruction, write)
    count = len(cases) // 168
    assert count == 1204 and len(cases) == count * 168
    (out / 'cases.bin').write_bytes(cases)
    guest = Path(__file__).with_name('mmio_guest.s')
    (out / 'guest.s').write_text(guest.read_text().replace('@CASE_COUNT@', str(count)))
    (out / 'link.ld').write_text('ENTRY(_start)\nSECTIONS {. = 0x100000; .multiboot : {*(.multiboot)} .text : {*(.text*)} .rodata : {*(.rodata*)} .data : {*(.data*)} .bss : {*(.bss*) *(COMMON)}}\n')
    manifest = {'version': 1, 'cases': count, 'tool_sha256': sha(Path(__file__)),
                'guest_source_sha256': sha(guest), 'commands': [],
                'scope': '1204 actual CPL0 long-mode RAM MOV/MOVSX/MOVZX executions;16 GPRs, high-byte aliases, partial/zero/sign extension and immediates. Product plans expose the same operand as an MMIO hole. Not native VMX/device delivery.'}
    def run(name, command, expected=0, timeout=60):
        start = time.monotonic()
        try:
            result = subprocess.run(command, cwd=repo if name == 'product-owning' else out,
                                    text=True, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            manifest['commands'].append({'name': name, 'args': command, 'code': 'timeout', 'seconds': time.monotonic()-start})
            (out/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
            raise RuntimeError(f'{name} timed out; no passing result') from None
        (out/(name+'.stdout')).write_text(result.stdout)
        (out/(name+'.stderr')).write_text(result.stderr)
        manifest['commands'].append({'name': name, 'args': command, 'code': result.returncode, 'seconds': time.monotonic()-start})
        (out/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
        if result.returncode != expected:
            raise RuntimeError(f'{name}:code{result.returncode}; see retained diagnostics')
        return result
    llvm = args.llvm_bin.resolve()
    run('qemu-version', [args.qemu, '--version'])
    run('llvm-version', [str(llvm/'llvm-mc'), '--version'])
    run('assemble', [str(llvm/'llvm-mc'), '-triple=i386-none-elf', '-filetype=obj', 'guest.s', '-o', 'guest.o'])
    run('link', [str(llvm/'ld.lld'), '-m', 'elf_i386', '-T', 'link.ld', 'guest.o', '-o', 'guest.elf'])
    run('qemu', [args.qemu, '-machine', 'pc', '-cpu', 'Haswell-noTSX', '-accel', 'tcg,thread=single', '-m', '64M', '-nodefaults', '-display', 'none', '-monitor', 'none', '-serial', 'none', '-debugcon', 'file:'+str(out/'records.bin'), '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04', '-no-reboot', '-kernel', str(out/'guest.elf')], 33)
    raw = (out/'records.bin').read_bytes()
    assert len(raw) == 20+count*152 and raw[:8] == b'RAXMM001' and struct.unpack_from('<I',raw,8)[0] == count and raw[-8:] == b'MM_DONE!'
    for index in range(count):
        flags = struct.unpack_from('<Q',cases,index*168+136)[0]
        before, after = struct.unpack_from('<QQ',raw,12+index*152+136)
        assert before == after == flags, (index,flags,before,after)
    fixture = repo/'tests/fixtures/hvf/mmio-v1'
    if args.capture:
        fixture.mkdir(parents=True, exist_ok=True)
        for name in ['cases.bin','records.bin','manifest.json']:
            if (fixture/name).exists():
                raise ValueError('Capture requires absent fixture files; do not overwrite existing evidence')
        for name in ['cases.bin','records.bin']:
            (fixture/name).write_bytes((out/name).read_bytes())
        (fixture/'manifest.json').write_text(json.dumps({'version':1,'cases':count,'case_bytes':168,'record_bytes':152,'framing_bytes':20,'guest_ram_bytes':64<<20,'scope':manifest['scope'],'tool_sha256':manifest['tool_sha256'],'guest_source_sha256':manifest['guest_source_sha256'],'artifact_sha256':{name:sha(out/name)for name in ['cases.bin','records.bin','guest.s','guest.elf']},'reference_commands':manifest['commands']},indent=2)+'\n')
    for name in ['cases.bin','records.bin']:
        assert (fixture/name).read_bytes() == (out/name).read_bytes(), f'Immutable {name} differs from fresh actual guest records'
    pinned = json.loads((fixture/'manifest.json').read_text())
    assert pinned['tool_sha256'] == manifest['tool_sha256'] and pinned['guest_source_sha256'] == manifest['guest_source_sha256']
    if not args.reference_only:
        product_sources = ['src/backend/hvf/mmio.rs','src/backend/hvf/guest_translation.rs','src/isa/x86_64/decode/metadata.rs','src/isa/x86_64/decode/metadata_legacy.rs','tests/suites/backend/hvf_mmio.rs']
        before = {name:sha(repo/name) for name in product_sources}
        result = run('product-owning', ['cargo','+stable','test','--locked','--offline','--no-default-features','--features','x86_64-suite,smir-jit,hvf','--test','hvf_mmio','--','--test-threads=4'], timeout=600)
        match = re.search(r'test result: ok\. (\d+) passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;', result.stdout)
        assert match and int(match.group(1)) >= 13
        assert before == {name:sha(repo/name) for name in product_sources}
        manifest['product_source_sha256'] = before
        manifest['complete_product_owning_passed'] = int(match.group(1))
    manifest['artifact_sha256'] = {name:sha(out/name)for name in ['cases.bin','records.bin','guest.s','guest.elf']}
    manifest['result'] = 'reference_only' if args.reference_only else 'reference_and_product_match'
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'cases':count,'result':manifest['result']}))


if __name__ == '__main__':
    main()
