#!/usr/bin/env python3
"""Build the foreign code of the tests, and say what is in it.

    python3 -B build_guest.py            # compile guest.c; rewrite guest-*.elf and guest.json
    python3 -B build_guest.py --check    # fail if guest.json is not of the committed guest-*.elf

`guest.c` is compiled for x86-64 and for AArch64 into `guest-x86_64.elf` and
`guest-aarch64.elf`: static executables at fixed addresses, with no library,
which nothing ever starts at their entry. `guest.json` says of each its
SHA-256, by which a module names the image, and of each bridge in it, of each
entry of a callback, and of the personality function, where in the file its
code is and how long: the byte range a module's native symbol names.

Compiling needs `zig` (its `cc`, which has both targets); checking needs
nothing but the committed files, and is what the tests do.
"""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
MACHINES = ('x86_64', 'aarch64')
FLAGS = ['-std=c11', '-O1', '-ffreestanding', '-fno-stack-protector', '-fno-pic', '-nostdlib', '-static',
         '-Wl,--entry=bridge_scale', '-Wl,--build-id=none', '-Wall', '-Werror']


def functions(image):
    """The functions of an ELF image that a module names: `personality`, and
    those whose names begin with `bridge_` or `callback_`. For each, by its
    name, the offset of its code in the file and its size."""
    def take(layout, at):
        return struct.unpack_from('<' + layout, image, at)
    assert image[:6] == b'\x7fELF\x02\x01', 'a 64-bit little-endian ELF file'
    program_at, section_at = take('QQ', 32)
    program_size, program_count, section_size, section_count = take('HHHH', 54)
    loads = []
    for index in range(program_count):
        kind, _, offset, address, _, in_file = take('IIQQQQ', program_at + index * program_size)
        if kind == 1:
            loads.append((address, offset, in_file))
    found = {}
    for index in range(section_count):
        at = section_at + index * section_size
        kind, = take('I', at + 4)
        if kind != 2:
            continue
        offset, size, link = take('QQI', at + 24)
        names_at, = take('Q', section_at + link * section_size + 24)
        for symbol in range(offset, offset + size, 24):
            name, info, _, _, value, length = take('IBBHQQ', symbol)
            text = image[names_at + name:image.index(b'\0', names_at + name)].decode()
            if info & 15 == 2 and (text == 'personality' or text.startswith(('bridge_', 'callback_'))):
                segment = next((address, at_file) for address, at_file, in_file in loads
                               if address <= value and value + length <= address + in_file)
                found[text] = {'offset': value - segment[0] + segment[1], 'size': length}
    return dict(sorted(found.items()))


def described(images):
    return json.dumps({machine: {'sha256': hashlib.sha256(image).hexdigest(), 'bytes': len(image),
                                 'functions': functions(image)}
                       for machine, image in images.items()}, indent=1) + '\n'


def main():
    check = sys.argv[1:] == ['--check']
    if sys.argv[1:] and not check:
        sys.exit(__doc__)
    if not check:
        with tempfile.TemporaryDirectory(prefix='smir-guest-') as scratch:
            cache = {'ZIG_GLOBAL_CACHE_DIR': scratch, 'ZIG_LOCAL_CACHE_DIR': scratch}
            for machine in MACHINES:
                built = Path(scratch) / f'guest-{machine}.elf'
                subprocess.run(['zig', 'cc', '-target', f'{machine}-freestanding-none', *FLAGS, '-o', str(built),
                                str(HERE / 'guest.c')], check=True, env={**os.environ, **cache})
                (HERE / f'guest-{machine}.elf').write_bytes(built.read_bytes())
    images = {machine: (HERE / f'guest-{machine}.elf').read_bytes() for machine in MACHINES}
    text = described(images)
    if check:
        if (HERE / 'guest.json').read_text() != text:
            sys.exit('build_guest.py: guest.json is not of the committed guest-*.elf')
    else:
        (HERE / 'guest.json').write_text(text)


if __name__ == '__main__':
    main()
