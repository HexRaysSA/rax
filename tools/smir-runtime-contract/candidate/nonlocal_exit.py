"""Registry-bound 32-byte portable setjmp cookies; no native stack copying."""
from copy import deepcopy
import struct
from threading import Lock

from .errors import option, require


class Registry:
    def __init__(self, process):
        self.process, self.next_id = process, 1
        self.items = {}
        self.lock = Lock()

    def capture(self, document, *, activation, continuation, result, sequence, signal_mask=None):
        """Input is a previously validated private runtime checkpoint, not a file.

        O(live state bytes). The runtime additionally pins snapshot/module leases;
        this oracle retains Python values and cannot create executable admission.
        """
        with self.lock:
            thread = document['thread']
            require(thread['process'] == self.process and thread['worker'] is None, 'RT_JMP_CAPTURE_OWNER')
            frames = {f['activation']: f for f in thread['frames']}
            require(activation in frames and result >= 0 and sequence >= 0, 'RT_JMP_CAPTURE_FRAME')
            require(thread['frames'][-1]['activation'] == activation, 'RT_JMP_CAPTURE_FRAME')
            require(signal_mask is None or type(signal_mask) is bytes and len(signal_mask) == 128,
                    'RT_JMP_SIGNAL_MASK')
            identity = self.next_id
            require(identity < 2**64-1, 'RT_JMP_RESOURCE')
            self.next_id += 1
            self.items[identity] = {'generation': 1, 'thread': thread['thread'], 'activation': activation,
                'module': frames[activation]['module'], 'module_generation': frames[activation]['generation'],
                'binding_generation': frames[activation]['binding_generation'], 'frames': deepcopy(thread['frames']),
                'continuation': deepcopy(continuation), 'result': result, 'sequence': sequence,
                'signal_mask': signal_mask, 'live': True}
            return struct.pack('<IIQQQ', 1, 0, self.process, identity, 1)

    def invalidate_activation(self, thread, activation):
        with self.lock:
            for fact in self.items.values():
                if (fact['thread'], fact['activation']) == (thread, activation):fact['live'] = False

    def restore(self, cookie, document, value, *, active_nontrivial, objects, current_signal_mask):
        """Validate completely, then return private restore plan and revocations.

        Restores concrete saved SSA state (permitted refinement of indeterminate
        changed nonvolatile automatic values), no memory/fenv/errno rollback.
        Dead source lifetimes remain dead; newer stack allocations are revoked.
        A cookie is reusable while its original activation/generation stays live.
        O(frames + allocations + active journal obligations).
        """
        require(type(cookie) is bytes and len(cookie) == 32, 'RT_JMP_COOKIE')
        revision, reserved, process, identity, generation = struct.unpack('<IIQQQ', cookie)
        require(revision == 1 and reserved == 0 and process == self.process, 'RT_JMP_COOKIE')
        require(type(value) is int and -2**31 <= value < 2**31, 'RT_JMP_VALUE')
        with self.lock:
            fact = self.items.get(identity)
            require(fact is not None and fact['live'] and generation == fact['generation'], 'RT_JMP_STALE')
            thread = document['thread']
            require((thread['process'], thread['thread']) == (self.process, fact['thread']), 'RT_JMP_WRONG_THREAD')
            current = {f['activation']: f for f in thread['frames']}
            require(fact['activation'] in current, 'RT_JMP_DEAD_ACTIVATION')
            frame = current[fact['activation']]
            require((frame['module'], frame['generation'], frame['binding_generation']) ==
                    (fact['module'], fact['module_generation'], fact['binding_generation']), 'RT_JMP_STALE')
            saved_ids = [f['activation'] for f in fact['frames']]
            current_ids = [f['activation'] for f in thread['frames']]
            require(current_ids[:len(saved_ids)] == saved_ids, 'RT_JMP_STACK_ANCESTRY')
            # Callback supplies actual source C++ cleanup obligations, including
            # objects constructed after setjmp in the SAME activation.
            require(not active_nontrivial(fact, document), 'RT_JMP_NONTRIVIAL_CLEANUP')
            result = deepcopy(document)
            result['thread']['frames'] = deepcopy(fact['frames'])
            restored = {f['activation']: f for f in result['thread']['frames']}
            revocations = []
            for active in thread['frames']:
                for allocation in active['allocations']:
                    if active['activation'] not in restored or allocation['created_sequence'] > fact['sequence']:
                        if allocation['lifetime'] == 'live':revocations.append((allocation['object'], allocation['generation']))
            for restored_frame in result['thread']['frames']:
                for allocation in restored_frame['allocations']:
                    actual = objects.get(allocation['object'])
                    require(actual is not None and actual['generation'] == allocation['generation'], 'RT_JMP_STACK_OBJECT')
                    if not actual['live']:allocation['lifetime'] = 'ended'
            target = restored[fact['activation']]
            target['position'] = deepcopy(fact['continuation'])
            target['ticket'] = None
            target['progress'] = None
            # Return insertion uses the admitted setjmp i32 result declaration;
            # the caller's actual Flow verifies this value ID/type at continuation.
            return {'state': result, 'activation': fact['activation'], 'result': fact['result'],
                    'value': 1 if value == 0 else value, 'revoke': tuple(revocations),
                    'signal_mask': fact['signal_mask'] if fact['signal_mask'] is not None else current_signal_mask}
