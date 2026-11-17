"""Deterministic executable protocol models, independent of production RAX.

Transitions are individually atomic in this schedule model. They do not prove
weak-memory implementation correctness or OS progress on a real host.
"""
from dataclasses import dataclass, field

from schema import require, unique_by, unique_list, validate


@dataclass
class Mapping:
    backing: str
    generation: int = 1
    state: str = 'open'
    guards: set = field(default_factory=set)


class MemoryLifetime:
    def __init__(self):
        self.mappings = {}
        self.guards = {}
        self.reclaimed = set()

    def map(self, name, backing):
        require(name not in self.mappings, 'MAPPING_EXISTS')
        require(backing not in self.reclaimed, 'BACKING_REUSED_ID')
        self.mappings[name] = Mapping(backing)

    def acquire(self, name, generation, guard):
        require(name in self.mappings, 'MAPPING_UNKNOWN')
        mapping = self.mappings[name]
        require(mapping.state == 'open', 'MAPPING_CLOSED')
        require(generation == mapping.generation, 'STALE_GENERATION')
        require(guard not in self.guards, 'GUARD_EXISTS')
        self.guards[guard] = name
        mapping.guards.add(guard)

    def revoke(self, name):
        require(name in self.mappings, 'MAPPING_UNKNOWN')
        mapping = self.mappings[name]
        require(mapping.state == 'open', 'MAPPING_CLOSED')
        require(mapping.generation < 2**64 - 1, 'GENERATION_EXHAUSTED')
        mapping.state = 'closing'
        mapping.generation += 1

    def release(self, guard):
        require(guard in self.guards, 'GUARD_UNKNOWN')
        name = self.guards.pop(guard)
        self.mappings[name].guards.remove(guard)

    def unmap(self, name):
        require(name in self.mappings, 'MAPPING_UNKNOWN')
        mapping = self.mappings[name]
        require(mapping.state == 'closing', 'MAPPING_NOT_REVOKED')
        require(not mapping.guards, 'GUARDS_ACTIVE')
        mapping.state = 'unmapped'

    def reclaim(self, backing):
        aliases = [m for m in self.mappings.values() if m.backing == backing]
        require(aliases and backing not in self.reclaimed, 'BACKING_UNKNOWN')
        require(all(m.state == 'unmapped' and not m.guards for m in aliases),
                'BACKING_REFERENCED')
        self.reclaimed.add(backing)


class ModuleLifetime:
    KINDS = {'frame', 'callback', 'tls', 'object', 'exception', 'code', 'import', 'descriptor'}

    def __init__(self):
        self.state = 'live'
        self.leases = {}

    def acquire(self, identity, kind, parent=None):
        require(kind in self.KINDS, 'LEASE_KIND')
        require(identity not in self.leases, 'LEASE_EXISTS')
        require(self.state == 'live' or
                (self.state == 'retiring' and parent in self.leases), 'MODULE_CLOSED')
        self.leases[identity] = kind

    def release(self, identity):
        require(identity in self.leases, 'LEASE_UNKNOWN')
        del self.leases[identity]

    def retire(self):
        require(self.state == 'live', 'MODULE_STATE')
        self.state = 'retiring'

    def finalize(self):
        require(self.state == 'retiring', 'MODULE_STATE')
        require(not self.leases, 'LEASES_ACTIVE')
        self.state = 'finalizing'

    def reclaim(self, finalizers_succeeded=True):
        require(self.state == 'finalizing', 'MODULE_STATE')
        self.state = 'retired' if finalizers_succeeded else 'failed_pinned'


class EffectFrontier:
    """Exactly one effect winner and next-op update, including late completions."""
    def __init__(self):
        self.next_operation = 0
        self.sequence = 0
        self.ticket = None
        self.effects = 0
        self.result = None

    def begin(self):
        require(self.ticket is None, 'TICKET_ACTIVE')
        require(self.sequence < 2**64 - 1, 'TICKET_EXHAUSTED')
        require(self.next_operation < 2**32 - 1, 'FRONTIER_EXHAUSTED')
        self.sequence += 1
        self.ticket = {'sequence': self.sequence, 'state': 'pending',
                       'operation': self.next_operation}
        return self.sequence

    def reserve(self, sequence):
        require(self.ticket is not None and sequence == self.ticket['sequence'],
                'TICKET_UNKNOWN')
        if self.ticket['state'] != 'pending':
            return False
        self.ticket['state'] = 'irrevocable'
        return True

    def complete(self, sequence, value):
        require(self.ticket is not None and sequence == self.ticket['sequence'],
                'TICKET_UNKNOWN')
        if self.ticket['state'] not in {'pending', 'irrevocable'}:
            return False
        self.ticket['state'] = 'completed'
        self.effects += 1
        self.result = value
        self.next_operation += 1
        return True

    def cancel(self, sequence):
        require(self.ticket is not None and sequence == self.ticket['sequence'],
                'TICKET_UNKNOWN')
        if self.ticket['state'] != 'pending':
            return False
        self.ticket['state'] = 'cancelled'
        self.result = 'CANCELLED'
        self.next_operation += 1
        return True

    def resume(self):
        require(self.ticket is not None and self.ticket['state'] in {'completed', 'cancelled'},
                'TICKET_PENDING')
        self.ticket = None
        return self.next_operation, self.result


class WaitQueue:
    """Check/register and update/wake each take the SAME backing-word lock."""
    def __init__(self, value=0):
        self.value = value
        self.waiters = set()
        self.ready = set()

    def wait(self, identity, expected):
        require(type(expected) is int and 0 <= expected < 2**32, 'WAIT_VALUE')
        require(identity not in self.waiters and identity not in self.ready, 'WAITER_EXISTS')
        if self.value != expected:
            return False
        self.waiters.add(identity)
        return True

    def store_wake(self, value, count):
        require(type(value) is int and 0 <= value < 2**32, 'WAIT_VALUE')
        require(type(count) is int and 0 <= count < 2**32, 'WAKE_COUNT')
        self.value = value
        wake = sorted(self.waiters)[:count]
        self.waiters.difference_update(wake)
        self.ready.update(wake)
        return len(wake)

    def cancel(self, identity):
        if identity not in self.waiters:
            return False
        self.waiters.remove(identity)
        self.ready.add(identity)
        return True


def verify_state(state, memory_generation=None, module_generations=None):
    validate(state, 'state')
    if memory_generation is not None:
        require(state['memory_generation'] == memory_generation, 'STALE_MEMORY_GENERATION')
    frames = state['frames']
    activations = unique_by(frames, 'activation', 'ACTIVATION_DUPLICATE')
    require(bool(frames), 'EMPTY_STACK')
    unique_list(state['fenv']['flags'], 'FENV_FLAGS_DUPLICATE')
    for index, frame in enumerate(frames):
        require(frame['module_generation'] > 0, 'MODULE_GENERATION')
        if module_generations is not None:
            require(module_generations.get(frame['module']) == frame['module_generation'],
                    'STALE_MODULE_GENERATION')
        unique_by(frame['locals'], 'id', 'LOCAL_DUPLICATE')
        for continuation in (frame['continuation'], frame['unwind']):
            if continuation is not None:
                require(index > 0 and continuation['activation'] == frames[index - 1]['activation'],
                        'CONTINUATION_PARENT')
                unique_list(continuation['results'], 'CONTINUATION_RESULTS')
        if index == 0:
            require(frame['continuation'] is None and frame['unwind'] is None, 'ROOT_CONTINUATION')
        else:
            require(frame['continuation'] is not None, 'CALL_CONTINUATION')
        if index < len(frames) - 1:
            require(frame['status'] in {'suspended', 'unwinding'}, 'CALLER_NOT_SUSPENDED')
        ticket = frame['ticket']
        if ticket is not None:
            require(ticket['sequence'] > 0, 'TICKET_SEQUENCE')
            pending = ticket['state'] in {'pending', 'irrevocable'}
            require(ticket['committed'] == (ticket['state'] == 'completed'), 'TICKET_COMMIT')
            if pending:
                require(frame['status'] in {'blocked', 'suspended', 'unwinding'}, 'PENDING_NOT_BLOCKED')
                require(frame['position']['next_operation'] == ticket['operation'], 'PENDING_FRONTIER')
                require(ticket['results'] == [], 'PENDING_RESULTS')
            else:
                require(frame['position'] == ticket['normal'], 'COMPLETED_FRONTIER')
                if ticket['state'] == 'completed':
                    local_values = {v['id']: v for v in frame['locals']}
                    require(all(local_values.get(v['id']) == v for v in ticket['results']),
                            'COMPLETED_RESULTS')
            require(ticket['normal']['block'] == frame['position']['block'], 'TICKET_BLOCK')
            require(ticket['normal']['next_operation'] == ticket['operation'] + 1,
                    'TICKET_CONTINUATION')
        require(frame['exception'] is None or frame['status'] == 'unwinding', 'EXCEPTION_STATE')
    require(state['owner_worker'] is None or
            frames[-1]['status'] in {'running', 'unwinding'}, 'WORKER_OWNERSHIP')
    return activations


class CodeRegistry:
    """Process-local callable tokens; never reuse or deserialize a host address."""
    def __init__(self):
        self.next_sequence = 1
        self.entries = {}

    def publish(self, module, generation, signature, entry, kind='function'):
        require(type(self.next_sequence) is int and 1 <= self.next_sequence < 2**63,
                'CODE_TOKEN_EXHAUSTED')
        require(type(generation) is int and 1 <= generation < 2**64, 'MODULE_GENERATION')
        require(type(module) is str and len(module) == 64 and
                all(c in '0123456789abcdef' for c in module), 'CODE_MODULE_IDENTITY')
        require(type(signature) is str and len(signature) == 64 and
                all(c in '0123456789abcdef' for c in signature), 'CODE_SIGNATURE_IDENTITY')
        require(type(entry) is int and 0 <= entry < 2**32, 'CODE_ENTRY_ID')
        require(kind in {'function', 'import', 'callback'}, 'CODE_ENTRY_KIND')
        token = 2 * self.next_sequence
        self.next_sequence += 1
        self.entries[token] = (module, generation, signature, entry, kind)
        return token

    def lookup(self, token, module_generations, signature):
        from link import admit_code_token
        admit_code_token(token)
        require(token in self.entries, 'CODE_TOKEN_UNKNOWN')
        module, generation, expected, entry, kind = self.entries[token]
        require(module_generations.get(module) == generation, 'CODE_TOKEN_STALE')
        require(expected == signature, 'CODE_SIGNATURE')
        return module, generation, entry, kind


class Workers:
    """Exclusive thread ownership and safepoint acknowledgements, in a model."""
    def __init__(self, threads):
        unique_list(threads, 'THREAD_DUPLICATE')
        self.threads = {thread: {'state': 'runnable', 'owner': None, 'epoch': 0}
                        for thread in threads}
        self.epoch = 0
        self.stop_active = False

    def start(self, thread, worker):
        require(not self.stop_active, 'SAFEPOINT_ACTIVE')
        require(thread in self.threads, 'THREAD_UNKNOWN')
        current = self.threads[thread]
        require(current['state'] == 'runnable', 'THREAD_NOT_RUNNABLE')
        require(all(t['owner'] != worker for t in self.threads.values()), 'WORKER_BUSY')
        current.update(state='running', owner=worker)

    def publish(self, thread, state):
        require(thread in self.threads, 'THREAD_UNKNOWN')
        current = self.threads[thread]
        require(current['state'] == 'running', 'THREAD_NOT_RUNNING')
        require(state in {'runnable', 'blocked', 'stopped', 'exited'}, 'THREAD_STATE')
        # Caller must have materialized the logical frontier before this event.
        if self.stop_active and state == 'runnable':
            state = 'stopped'
        current.update(state=state, owner=None, epoch=self.epoch)

    def wake(self, thread):
        require(thread in self.threads, 'THREAD_UNKNOWN')
        current = self.threads[thread]
        if current['state'] != 'blocked':
            return False
        current['state'] = 'stopped' if self.stop_active else 'runnable'
        return True

    def request_stop(self):
        require(not self.stop_active, 'SAFEPOINT_ACTIVE')
        require(self.epoch < 2**64 - 1, 'SAFEPOINT_EXHAUSTED')
        self.epoch += 1
        self.stop_active = True
        for current in self.threads.values():
            if current['state'] != 'running':
                current['epoch'] = self.epoch
                if current['state'] == 'runnable':
                    current['state'] = 'stopped'
        return self.epoch

    def all_stopped(self, epoch):
        require(epoch == self.epoch, 'SAFEPOINT_STALE')
        return self.stop_active and all(t['epoch'] == epoch and t['owner'] is None
                                        for t in self.threads.values())

    def resume(self, epoch):
        require(self.all_stopped(epoch), 'SAFEPOINT_INCOMPLETE')
        self.stop_active = False
        for current in self.threads.values():
            if current['state'] == 'stopped':
                current['state'] = 'runnable'


class CodePublication:
    """Private cache lifecycle witness; never allocates executable memory."""
    def __init__(self, generation=1):
        require(type(generation) is int and 1 <= generation < 2**64, 'CODE_GENERATION')
        self.generation = generation
        self.compiling_generation = generation
        self.state = 'writable'
        self.readers = set()

    def seal(self, relocated, maps_valid, host_supported, readonly, executable, icache_synced):
        require(self.state == 'writable', 'CODE_STATE')
        require(all(type(flag) is bool for flag in
                    (relocated, maps_valid, host_supported, readonly, executable, icache_synced)),
                'CODE_FLAG_TYPE')
        require(relocated and maps_valid and host_supported and readonly and executable and
                icache_synced, 'CODE_NOT_SEALED')
        self.state = 'sealed'

    def publish(self):
        require(self.state == 'sealed', 'CODE_STATE')
        require(self.compiling_generation == self.generation, 'CODE_COMPILE_STALE')
        self.state = 'published'

    def enter(self, reader):
        require(self.state == 'published' and self.compiling_generation == self.generation,
                'CODE_ENTRY_CLOSED')
        require(reader not in self.readers, 'CODE_READER_DUPLICATE')
        self.readers.add(reader)

    def invalidate(self):
        require(self.state not in {'retiring', 'retired'}, 'CODE_STATE')
        require(self.generation < 2**64 - 1, 'CODE_GENERATION_EXHAUSTED')
        self.generation += 1
        self.state = 'retiring'

    def leave(self, reader):
        require(reader in self.readers, 'CODE_READER_UNKNOWN')
        self.readers.remove(reader)

    def reclaim(self):
        require(self.state == 'retiring', 'CODE_STATE')
        require(not self.readers, 'CODE_READERS_ACTIVE')
        self.state = 'retired'
