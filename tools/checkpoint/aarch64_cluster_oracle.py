"""Real QEMU/RAX AArch64 CPU startup, SGI, power-off and file continuation."""
import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rax', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--llvm-bin', type=Path, required=True)
    parser.add_argument('--qemu', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).with_name('aarch64_cluster_guest.s')
    producer = {'rax': sha(args.rax), 'guest_source': sha(source), 'tool': sha(Path(__file__))}
    commands, cases = [], []

    def run(name, command, timeout=60):
        command = list(map(str, command))
        start = time.monotonic()
        try:
            result = subprocess.run(command, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            (args.out / (name + '.stdout')).write_bytes(error.stdout or b'')
            (args.out / (name + '.stderr')).write_bytes(error.stderr or b'')
            commands.append({'name': name, 'command': command, 'timeout': timeout})
            (args.out / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
            raise
        (args.out / (name + '.stdout')).write_bytes(result.stdout)
        (args.out / (name + '.stderr')).write_bytes(result.stderr)
        commands.append({'name': name, 'command': command, 'code': result.returncode,
                         'seconds': time.monotonic() - start})
        (args.out / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        assert result.returncode == 0, (name, result.returncode, result.stderr[-2000:])
        return result.stdout

    try:
        run('qemu-version', [args.qemu, '--version'])
        for count in [1, 2, 4]:
            assembly = args.out / f'guest-{count}.s'
            obj, elf = args.out / f'guest-{count}.o', args.out / f'guest-{count}.elf'
            assembly.write_text(f'.equ NR_CPUS, {count}\n' + source.read_text())
            run(f'assemble-{count}', [args.llvm_bin / 'llvm-mc', '--triple=aarch64',
                '--filetype=obj', assembly, '-o', obj])
            run(f'link-{count}', [args.llvm_bin / 'ld.lld', '-m', 'aarch64elf',
                '-Ttext=0x40080000', '--entry=_start', obj, '-o', elf])
            for repeat in range(3):
                reference = run(f'qemu-{count}-{repeat}', [args.qemu, '-machine',
                    'virt,gic-version=3', '-cpu', 'cortex-a57', '-smp', count, '-m',
                    '128M', '-display', 'none', '-monitor', 'none', '-serial',
                    'stdio', '-kernel', elf, '-no-reboot'], 30)
                assert reference == b'S', (count, repeat, reference)
            command = [args.rax, '--arch', 'aarch64', '--backend', 'emulator',
                       '--vcpus', count, '--memory', '128M', '--kernel', elf]
            directory = args.out / f'cpu-{count}'
            directory.mkdir()
            if count > 1:
                command.extend(['--snapshot-at', 1500, '--snapshot-dir', directory])
            actual = run(f'rax-{count}', command, 90)
            assert actual == b'S', (count, actual)
            record = {'cpus': count, 'qemu_repetitions': 3, 'rax': 'S', 'elf_sha256': sha(elf)}
            if count > 1:
                snapshots = list(directory.glob('snapshot_*.rxc'))
                assert len(snapshots) == 1, snapshots
                retained = elf.with_name(f'retained-{elf.name}')
                elf.rename(retained)
                assert not elf.exists()
                resumed = run(f'resumed-{count}', [args.rax, '--checkpoint', snapshots[0]], 90)
                assert resumed == b'S', (count, resumed)
                record.update(resumed='S', snapshot_sha256=sha(snapshots[0]),
                              original_kernel_removed=True)
            cases.append(record)
        assert producer == {'rax': sha(args.rax), 'guest_source': sha(source), 'tool': sha(Path(__file__))}
        result = {'status': 'passed', 'cases': cases, 'producer_sha256': producer,
                  'scope': 'Actual QEMU/RAX software VMM startup, context ID, per-PE priority masks, SGI delivery/EOI, masked WFI, CPU_OFF and fresh file continuation. Full private CPU state, native SMP and deterministic clock equivalence remain separate.'}
    except BaseException as error:
        (args.out / 'result.json').write_text(json.dumps({'status': 'failed', 'error': repr(error),
            'cases': cases, 'producer_sha256': producer}, indent=2) + '\n')
        raise
    (args.out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
