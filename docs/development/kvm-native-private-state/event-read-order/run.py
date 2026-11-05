"""Run the pending-exception setter/getter control on Linux x86-64 KVM."""

import hashlib
import json
import os
import platform
import subprocess
import tempfile
import time
from pathlib import Path


def main():
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise SystemExit('requires Linux x86-64 and usable /dev/kvm')
    here = Path(__file__).resolve().parent
    source = here / 'probe.c'
    source_bytes = source.read_bytes()
    with tempfile.TemporaryDirectory(prefix='rax-kvm-event-order-') as temporary:
        scratch = Path(temporary)
        executable = scratch / 'probe'
        build = subprocess.run(
            ['gcc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
             str(source), '-o', str(executable)],
            capture_output=True, text=True, timeout=30,
        )
        if build.returncode:
            raise SystemExit(build.stderr)
        started = time.monotonic()
        result = subprocess.run(
            [str(executable)], capture_output=True, text=True, timeout=15,
        )
        seconds = time.monotonic() - started
        if result.returncode:
            raise SystemExit(result.stderr)
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        assert len(rows) == 4
        assert [(row['payload_enabled'], row['vector']) for row in rows] == [
            (0, 1), (0, 14), (1, 1), (1, 14),
        ]
        for row in rows:
            enabled = row['payload_enabled']
            expected_cr2 = (0xFEED123456789ABC
                            if not enabled and row['vector'] == 14
                            else 0x1111222233334444)
            expected_dr6 = (0xFFFF4FF2
                            if not enabled and row['vector'] == 1
                            else 0xFFFF0FF0)
            assert int(row['cr2_before'], 16) == expected_cr2
            assert int(row['cr2_after'], 16) == expected_cr2
            assert int(row['dr6_before'], 16) == expected_dr6
            assert int(row['dr6_after'], 16) == expected_dr6
            assert row['pending'] == 1
            assert row['injected'] == 1 - enabled
            assert row['payload_retained'] == enabled
            assert row['event_flags'] & 16 == enabled << 4
        executable_digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    record = {
        'status': 'no_current_host_counterexample',
        'all_four_cells_match': True,
        'observations': rows,
        'seconds': seconds,
        'uname': list(os.uname()),
        'compiler': subprocess.check_output(['gcc', '--version'], text=True).splitlines()[0],
        'source_sha256': hashlib.sha256(source_bytes).hexdigest(),
        'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'executable_sha256': executable_digest,
        'owned_temporary_directory_removed': not scratch.exists(),
        'scope': 'Independent native setter/getter control; no RAX checkpoint or guest-handler execution.',
        'production_change': 'none',
        'exact_kernel_patch_provenance': 'unknown',
    }
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
