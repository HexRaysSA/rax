#!/usr/bin/env python3
"""Capture native Darwin FIFO readiness without running the emulator."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time


def capture(directory):
    library = ctypes.CDLL(None, use_errno=True)

    class PollFd(ctypes.Structure):
        _fields_ = [('fd', ctypes.c_int), ('events', ctypes.c_short),
                    ('revents', ctypes.c_short)]

    library.poll.argtypes = [ctypes.POINTER(PollFd), ctypes.c_uint, ctypes.c_int]
    library.poll.restype = ctypes.c_int

    def observe(name, fd):
        item = PollFd(fd, 1, 0)
        ctypes.set_errno(0)
        count = library.poll(ctypes.byref(item), 1, 0)
        error = ctypes.get_errno()
        queue = select.kqueue()
        try:
            event = select.kevent(fd, filter=select.KQ_FILTER_READ,
                                 flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE)
            events = queue.control([event], 1, 0)
        finally:
            queue.close()
        return {'state': name, 'poll_result': count, 'poll_events': item.revents,
                'poll_errno': error,
                'select_readable': bool(select.select([fd], [], [], 0)[0]),
                'kqueue': [{'flags': e.flags, 'data': e.data, 'filter': e.filter}
                           for e in events]}

    records = []
    path = directory / 'never-written.fifo'
    os.mkfifo(path, 0o600)
    reader = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        os.unlink(path)
        item = observe('never_had_writer', reader)
        item['read_result'] = list(os.read(reader, 1))
        records.append(item)
    finally:
        os.close(reader)

    path = directory / 'writer-lifetime.fifo'
    os.mkfifo(path, 0o600)
    reader = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    writer = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
    try:
        os.unlink(path)
        records.append(observe('empty_with_writer', reader))
        assert os.write(writer, b'Q') == 1
        records.append(observe('data_with_writer', reader))
        os.close(writer)
        writer = None
        records.append(observe('data_after_writer_close', reader))
        assert os.read(reader, 1) == b'Q'
        records.append(observe('empty_before_first_eof_read', reader))
        assert os.read(reader, 1) == b''
        records.append(observe('empty_after_first_eof_read', reader))
        for iteration in range(3):
            item = observe('repeated_nonblocking_eof', reader)
            item.update(iteration=iteration, read_result=list(os.read(reader, 1)))
            records.append(item)
        os.set_blocking(reader, True)
        started = time.monotonic()
        item = observe('repeated_blocking_eof', reader)
        item['read_result'] = list(os.read(reader, 1))
        item['seconds'] = time.monotonic() - started
        records.append(item)
    finally:
        if writer is not None:
            os.close(writer)
        os.close(reader)
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--worker', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if sys.platform != 'darwin':
        parser.error('This native observation requires Darwin poll/select/kqueue.')
    if args.worker:
        print(json.dumps(capture(args.worker)))
        return
    root = Path(__file__).resolve().parents[4]
    directory = (args.output or root / 'target/guarded-fd-runtime-v1/fifo-native-v1/readiness-v6').resolve()
    if not directory.is_relative_to(root / 'target'):
        parser.error('Output must be inside this checkout\'s target directory.')
    directory.mkdir(parents=True, exist_ok=False)
    (directory / '.owner').write_text('native-fifo-readiness-v6\n')
    temporary = directory / 'tmp'
    temporary.mkdir()
    source_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    command = [sys.executable, '-I', '-B', str(Path(__file__).resolve()),
               '--worker', str(temporary)]
    environment = dict(os.environ, TMPDIR=str(temporary), TMP=str(temporary),
                       TEMP=str(temporary))
    state = {'source_sha256': source_hash, 'host': list(os.uname()), 'argv': command}
    try:
        result = subprocess.run(command, env=environment, text=True,
                                capture_output=True, timeout=30)
        state.update(exit_code=result.returncode, stderr=result.stderr)
        state['records'] = json.loads(result.stdout) if result.returncode == 0 else []
        state['stdout'] = result.stdout
    except subprocess.TimeoutExpired as error:
        state.update(timeout_seconds=30, exit_code=None,
                     stdout=str(error.stdout), stderr=str(error.stderr))
    (directory / 'receipt.json').write_text(json.dumps(state, indent=2) + '\n')
    assert state['exit_code'] == 0, state
    assert hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == source_hash
    print(directory / 'receipt.json')


if __name__ == '__main__':
    main()
