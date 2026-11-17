"""Internal clone, setjmp/longjmp and termination reference protocols."""
import copy
import struct

from link import admit_code_token, storage_size
from memory import check_range
from protocols import verify_state
from schema import require, unique_by, validate

JMP_MAGIC = b'SMIRJMP\0'
JMP_BUFFER = struct.Struct('<8s7Q')


def verify_clone(snapshot, max_storage_bytes=16 * 1024 * 1024):
    validate(snapshot, 'clone')
    thread = snapshot['thread']
    require(thread['thread'] == snapshot['caller_thread'], 'CLONE_CALLER')
    require(thread['owner_worker'] is None, 'CLONE_NOT_QUIESCENT')
    require(thread['safepoint_epoch'] == snapshot['safepoint_epoch'], 'CLONE_EPOCH')
    require(all(frame['ticket'] is None for frame in thread['frames']), 'CLONE_PENDING_EFFECT')
    require(snapshot['foreign_leases'] == [], 'CLONE_FOREIGN_UNSUPPORTED')
    modules = unique_by(snapshot['modules'], 'identity', 'DUPLICATE_MODULE')
    require(all(m['generation'] > 0 for m in modules.values()), 'MODULE_GENERATION')
    verify_state(thread, module_generations={i: m['generation'] for i, m in modules.items()})
    backings = unique_by(snapshot['backings'], 'identity', 'DUPLICATE_BACKING')
    require(sum(storage_size(b) for b in backings.values()) <= max_storage_bytes,
            'CLONE_STORAGE_LIMIT')
    for backing in backings.values():
        storage_size(backing)
        require((backing['sharing'] == 'shared') == (backing['broker'] is not None),
                'CLONE_BACKING_BROKER')
    mappings = unique_by(snapshot['mappings'], 'identity', 'DUPLICATE_MAPPING')
    intervals = []
    for mapping in mappings.values():
        require(mapping['generation'] > 0, 'MAPPING_GENERATION')
        a, b = check_range(mapping['address'], mapping['length'])
        require(all(b <= c or d <= a for c, d in intervals), 'CLONE_MAPPING_OVERLAP')
        intervals.append((a, b))
        require(mapping['backing'] in backings, 'CLONE_BACKING')
        require(mapping['backing_offset'] + mapping['length'] <=
                storage_size(backings[mapping['backing']]), 'CLONE_BACKING_BOUNDS')
    unique_by(snapshot['handles'], 'identity', 'DUPLICATE_HANDLE')
    require(all(h['version'] > 0 for h in snapshot['handles']), 'HANDLE_ADAPTER_VERSION')
    leaf = thread['frames'][-1]
    require(leaf['position']['next_operation'] == snapshot['fork_operation'], 'CLONE_FRONTIER')
    expected = {**leaf['position'], 'next_operation': snapshot['fork_operation'] + 1}
    require(snapshot['normal'] == expected, 'CLONE_CONTINUATION')
    return snapshot


def child_state(snapshot, child_process, child_thread):
    """Fresh-host restore model. Handle adapter payload validation is external."""
    verify_clone(snapshot)
    require(type(child_process) is int and 0 < child_process < 2**64 and
            child_process != snapshot['source_process'], 'CLONE_PROCESS_ID')
    require(type(child_thread) is int and 0 < child_thread < 2**64, 'CLONE_THREAD_ID')
    result = copy.deepcopy(snapshot)
    result['source_process'] = child_process
    result['caller_thread'] = child_thread
    result['thread']['thread'] = child_thread
    leaf = result['thread']['frames'][-1]
    leaf['position'] = copy.deepcopy(snapshot['normal'])
    leaf['status'] = 'suspended'
    result['handles'] = [h for h in result['handles'] if h['inherit'] != 'close']
    # Parent pending process signals are not copied; dispositions/mask remain.
    result['pending_signals'] = ''
    return result


def verify_nonlocal(record):
    validate(record, 'nonlocal')
    require(record['capture_sequence'] > 0 and record['snapshot_token'] > 0 and
            record['module_generation'] > 0, 'JMP_IDENTITY')
    locals_by_id = unique_by(record['locals'], 'id', 'LOCAL_DUPLICATE')
    require(record['result_id'] in locals_by_id and
            len(locals_by_id[record['result_id']]['bits']) == 8, 'JMP_RESULT_LOCAL')
    require(record['stack_height'] > 0, 'JMP_STACK_HEIGHT')
    require(record['save_signal_mask'] or record['signal_mask'] == '', 'JMP_SIGNAL_MASK')
    return record


def encode_jmp_buffer(record):
    verify_nonlocal(record)
    return JMP_BUFFER.pack(JMP_MAGIC, record['process'], record['thread'],
                           record['activation'], record['capture_sequence'],
                           record['module_generation'], record['snapshot_token'], 0)


def longjmp(record, buffer, current_process, current_thread, live_frames, value):
    verify_nonlocal(record)
    require(len(buffer) == JMP_BUFFER.size and buffer == encode_jmp_buffer(record),
            'JMP_BUFFER_MISMATCH')
    require(current_process == record['process'] and current_thread == record['thread'],
            'JMP_WRONG_THREAD')
    require(type(value) is int and -2**31 <= value < 2**31, 'JMP_VALUE')
    height = record['stack_height']
    require(0 < height <= len(live_frames), 'JMP_DEAD_FRAME')
    target = live_frames[height - 1]
    require(target['activation'] == record['activation'] and target['module'] == record['module']
            and target['module_generation'] == record['module_generation'], 'JMP_DEAD_FRAME')
    require(all(frame['ticket'] is None for frame in live_frames[height - 1:]),
            'JMP_PENDING_EFFECT')
    result = value if value != 0 else 1
    restored = copy.deepcopy(live_frames[:height])
    restored[-1]['position'] = copy.deepcopy(record['position'])
    restored[-1]['locals'] = copy.deepcopy(record['locals'])
    restored[-1]['ticket'] = None
    for local in restored[-1]['locals']:
        if local['id'] == record['result_id']:
            local['bits'] = (result & 0xffffffff).to_bytes(4, 'little').hex()
    return restored, result


def verify_termination(document):
    validate(document, 'termination')
    unique_by(document['registrations'], 'sequence', 'TERMINATION_SEQUENCE')
    running = set()
    for entry in document['registrations']:
        require(entry['sequence'] > 0 and entry['module_generation'] > 0,
                'TERMINATION_IDENTITY')
        admit_code_token(entry['function_token'])
        require((entry['kind'] == 'tls') == (entry['thread'] is not None),
                'TERMINATION_THREAD')
        require(entry['kind'] in {'cxa', 'tls'} or entry['object'] == 0,
                'TERMINATION_OBJECT')
        if entry['state'] == 'running':
            key = ('tls', entry['thread']) if entry['kind'] == 'tls' else ('module', entry['module'])
            require(key not in running, 'TERMINATION_CONCURRENT')
            running.add(key)
    return document


class Termination:
    def __init__(self, document):
        verify_termination(document)
        self.document = copy.deepcopy(document)

    def claim(self, module=None, thread=None):
        records = self.document['registrations']
        require(module is None or thread is None, 'TERMINATION_CONTEXT')
        if thread is not None:
            active = any(r['state'] == 'running' and r['kind'] == 'tls' and
                         r['thread'] == thread for r in records)
        elif module is not None:
            active = any(r['state'] == 'running' and r['kind'] != 'tls' and
                         r['module'] == module for r in records)
        else:
            active = any(r['state'] == 'running' and r['kind'] != 'tls' for r in records)
        require(not active, 'TERMINATION_REENTRY')
        phase = self.document['phase']
        require(phase != 'failed', 'TERMINATION_FAILED')
        if phase == 'immediate_exit':
            return None
        eligible = []
        for record in records:
            if record['state'] != 'pending':
                continue
            if thread is not None:
                matches = record['kind'] == 'tls' and record['thread'] == thread
            elif module is not None:
                matches = record['kind'] == 'cxa' and record['module'] == module
            elif phase == 'normal_exit':
                matches = record['kind'] in {'atexit', 'cxa'}
            elif phase == 'quick_exit':
                matches = record['kind'] == 'quick_exit'
            else:
                matches = False
            if matches:
                eligible.append(record)
        if not eligible:
            return None
        selected = max(eligible, key=lambda r: r['sequence'])
        selected['state'] = 'running'
        return copy.deepcopy(selected)

    def register(self, entry):
        require(self.document['phase'] not in {'immediate_exit', 'failed'},
                'TERMINATION_CLOSED')
        records = self.document['registrations']
        next_sequence = max((r['sequence'] for r in records), default=0) + 1
        require(next_sequence < 2**64, 'TERMINATION_EXHAUSTED')
        candidate = {**entry, 'sequence': next_sequence, 'state': 'pending'}
        proposed = copy.deepcopy(self.document)
        proposed['registrations'].append(candidate)
        verify_termination(proposed)
        self.document = proposed
        return next_sequence

    def complete(self, sequence):
        records = [r for r in self.document['registrations'] if r['sequence'] == sequence]
        require(len(records) == 1 and records[0]['state'] == 'running', 'TERMINATION_COMPLETION')
        records[0]['state'] = 'done'
