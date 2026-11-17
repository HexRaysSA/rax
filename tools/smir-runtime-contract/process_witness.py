#!/usr/bin/env python3
"""Fresh host-process restore witness for the local model, not RAX fork."""
import argparse
import json
import os
from pathlib import Path

from process import child_state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    parser.add_argument('shared_file', type=Path)
    args = parser.parse_args()
    snapshot = json.loads(args.snapshot.read_text())
    restored = child_state(snapshot, 200, 201)
    private = bytearray.fromhex(restored['backings'][0]['bytes'])
    private[0] ^= 0xff
    # The test owns this file and passes its exact absolute path.
    with args.shared_file.open('r+b') as shared:
        shared.write(b'child')
        shared.flush()
    print(json.dumps({'host_pid': os.getpid(), 'guest_process': restored['source_process'],
                      'threads': [restored['thread']['thread']],
                      'position': restored['thread']['frames'][-1]['position'],
                      'private_first_byte': private[0], 'pending_signals': restored['pending_signals']}))


if __name__ == '__main__':
    main()
