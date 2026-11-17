"""Foreign-return conversion/cleanup frontiers, independent of native execution."""
import copy

from schema import require, unique_by, validate


def verify_bridge(document):
    validate(document, 'bridge')
    require(document['transition'] > 0 and document['generation'] > 0, 'BRIDGE_IDENTITY')
    require(document['native_calls'] in {0, 1} and document['normal_publications'] in {0, 1},
            'BRIDGE_COUNTS')
    unique_by(document['source_result'], 'id', 'BRIDGE_DUPLICATE_RESULT')
    stage = document['stage']
    complete = stage == 'portable_call_complete'
    unwound = stage == 'unwind_ready'
    require(document['normal_publications'] == int(complete), 'BRIDGE_PREMATURE_PUBLICATION')
    require(document['native_calls'] == int(stage != 'ready'), 'BRIDGE_NATIVE_REPLAY')
    if complete:
        require(document['position'] == document['normal'] and document['cleanup'] == 'done',
                'BRIDGE_NORMAL_FRONTIER')
        require(document['exception'] is None, 'BRIDGE_NORMAL_EXCEPTION')
    elif unwound:
        require(document['position'] == document['unwind'] and document['cleanup'] == 'done' and
                document['exception'] is not None, 'BRIDGE_UNWIND_FRONTIER')
    else:
        require(document['position'] == document['call_position'], 'BRIDGE_PREMATURE_FRONTIER')
    if stage in {'foreign_returned', 'conversion_pending', 'converted', 'portable_call_complete'}:
        require(document['foreign_result'] is not None, 'BRIDGE_TARGET_STORAGE')
    if stage in {'exception_cleanup', 'unwind_ready'}:
        require(document['exception'] is not None, 'BRIDGE_EXCEPTION_REQUIRED')
    if not complete and stage != 'converted':
        require(document['source_result'] == [], 'BRIDGE_SOURCE_RESULT')
    if document['suspended']:
        require(stage in {'foreign_call_started', 'conversion_pending', 'converted',
                          'exception_cleanup'} and document['suspension_sequence'] > 0 and
                document['adapter_frontier'] is not None, 'BRIDGE_SUSPENSION')
    leases = unique_by(document['leases'], 'id', 'BRIDGE_DUPLICATE_LEASE')
    for lease in leases.values():
        require(lease['id'] > 0 and lease['generation'] > 0, 'BRIDGE_LEASE_IDENTITY')
    foreign_result = document['foreign_result']
    if foreign_result is not None and foreign_result['bytes'] > 0:
        require(foreign_result['address'] > 0 and foreign_result['backing_generation'] > 0 and
                foreign_result['address'] + foreign_result['bytes'] <= 2**64,
                'BRIDGE_TARGET_RANGE')
    if stage in {'conversion_pending', 'converted'}:
        require(document['adapter_frontier'] is not None, 'BRIDGE_ADAPTER_FRONTIER')
    exception = document['exception']
    if exception is not None:
        require(exception['lease'] > 0 and exception['retention'] in leases,
                'BRIDGE_EXCEPTION_RETENTION')
        retention = leases[exception['retention']]
        require(retention['kind'] == 'exception' and retention['module'] == exception['owner'] and
                retention['generation'] == exception['generation'], 'BRIDGE_EXCEPTION_RETENTION')
        if stage == 'unwind_ready':
            require(retention['state'] in {'transferred', 'released'}, 'BRIDGE_EXCEPTION_RETENTION')
        else:
            require(retention['state'] == 'held', 'BRIDGE_EXCEPTION_RETENTION')
    if complete:
        require(all(lease['state'] == 'released' for lease in leases.values()),
                'BRIDGE_TERMINAL_LEASES')
    if stage not in {'portable_call_complete', 'unwind_ready'}:
        held = {(lease['module'], lease['kind']) for lease in leases.values()
                if lease['state'] == 'held'}
        for module in (document['source_module'], document['target_module']):
            require(all((module, kind) in held for kind in ('code', 'object', 'descriptor')),
                    'BRIDGE_EARLY_LEASE_RELEASE')
    return document


class BridgeCall:
    """One foreign call, resumable conversion, one whole-transition commit.

    All methods model serialized transition events. Real foreign code, adapter
    execution, typed results and exception identity admission remain external.
    """
    def __init__(self, document, lifetimes):
        verify_bridge(document)
        require(document['stage'] == 'ready', 'BRIDGE_INITIAL_STAGE')
        self.document = copy.deepcopy(document)
        self.lifetimes = lifetimes
        self.held = {}
        acquired = []
        try:
            for lease in self.document['leases']:
                require(lease['module'] in lifetimes, 'BRIDGE_MODULE')
                name = f"bridge:{document['transition']}:{lease['id']}"
                module = lifetimes[lease['module']]
                module.acquire(name, lease['kind'])
                acquired.append((module, name))
                self.held[lease['id']] = (module, name)
        except Exception:
            for module, name in reversed(acquired):
                module.release(name)
            raise

    def _at(self, stages):
        require(not self.document['suspended'], 'BRIDGE_SUSPENDED')
        require(self.document['stage'] in stages, 'BRIDGE_STAGE')

    def start(self):
        self._at({'ready'})
        self.document['native_calls'] = 1
        self.document['stage'] = 'foreign_call_started'

    def foreign_returned(self, storage):
        self._at({'foreign_call_started'})
        candidate = copy.deepcopy(self.document)
        candidate.update(stage='foreign_returned', foreign_result=copy.deepcopy(storage))
        verify_bridge(candidate)
        self.document = candidate

    def begin_conversion(self, frontier):
        self._at({'foreign_returned'})
        candidate = copy.deepcopy(self.document)
        candidate.update(stage='conversion_pending', adapter_frontier=copy.deepcopy(frontier))
        verify_bridge(candidate)
        self.document = candidate

    def converted(self, results):
        self._at({'conversion_pending'})
        candidate = copy.deepcopy(self.document)
        candidate.update(stage='converted', source_result=copy.deepcopy(results))
        verify_bridge(candidate)
        self.document = candidate

    def suspend(self, frontier):
        self._at({'foreign_call_started', 'conversion_pending', 'converted', 'exception_cleanup'})
        require(self.document['suspension_sequence'] < 2**64 - 1, 'BRIDGE_SEQUENCE_EXHAUSTED')
        candidate = copy.deepcopy(self.document)
        candidate['suspension_sequence'] += 1
        candidate['adapter_frontier'] = copy.deepcopy(frontier)
        candidate['suspended'] = True
        verify_bridge(candidate)
        self.document = candidate
        return self.document['suspension_sequence']

    def resume(self, thread, generation, sequence):
        require(thread == self.document['thread'], 'BRIDGE_WRONG_THREAD')
        require(generation == self.document['generation'], 'BRIDGE_STALE_GENERATION')
        require(self.document['suspended'] and sequence == self.document['suspension_sequence'],
                'BRIDGE_STALE_RESUME')
        self.document['suspended'] = False
        return self.document['stage'], copy.deepcopy(self.document['adapter_frontier'])

    def request_cancel(self):
        require(self.document['stage'] not in {'ready', 'portable_call_complete',
                                             'unwind_ready', 'terminated'}, 'BRIDGE_CANCEL_STAGE')
        # Foreign entry passed the outer irreversible-effect reservation already.
        # Keep one recorded deferred decision, even if completion races this call.
        previous = self.document['cancellation']
        self.document['cancellation'] = 'deferred'
        return previous == 'none'

    def raise_exception(self, lease, owner):
        self._at({'foreign_call_started', 'conversion_pending', 'converted', 'exception_cleanup'})
        if self.document['stage'] == 'exception_cleanup':
            self.document['stage'] = 'terminated'
            return
        require(type(lease) is int and 0 < lease < 2**64, 'BRIDGE_EXCEPTION_LEASE')
        require(owner in self.lifetimes and owner in
                {self.document['source_module'], self.document['target_module']}, 'BRIDGE_EXCEPTION_OWNER')
        parent = next((name for identity, (module, name) in self.held.items()
                       if module is self.lifetimes[owner]), None)
        require(parent is not None, 'BRIDGE_EXCEPTION_OWNER')
        identity = max(self.held, default=0) + 1
        require(identity < 2**64, 'BRIDGE_LEASE_EXHAUSTED')
        owner_generation = next(item['generation'] for item in self.document['leases']
                                if item['module'] == owner and item['state'] == 'held')
        name = f"bridge:{self.document['transition']}:exception:{lease}"
        self.lifetimes[owner].acquire(name, 'exception', parent=parent)
        self.held[identity] = (self.lifetimes[owner], name)
        self.document['leases'].append({'id': identity, 'kind': 'exception', 'module': owner,
                                       'generation': owner_generation, 'state': 'held'})
        self.document.update(stage='exception_cleanup', source_result=[],
                             exception={'lease': lease, 'owner': owner,
                                        'generation': owner_generation, 'retention': identity})

    def cleanup_complete(self):
        self._at({'converted', 'exception_cleanup'})
        exceptional = self.document['stage'] == 'exception_cleanup'
        self.document['cleanup'] = 'done'
        if exceptional:
            self.document['stage'] = 'unwind_ready'
            self.document['position'] = copy.deepcopy(self.document['unwind'])
        else:
            self.document['stage'] = 'portable_call_complete'
            self.document['normal_publications'] = 1
            self.document['position'] = copy.deepcopy(self.document['normal'])
        for lease in self.document['leases']:
            if exceptional and lease['kind'] == 'exception':
                lease['state'] = 'transferred'
                continue
            module, name = self.held.pop(lease['id'])
            module.release(name)
            lease['state'] = 'released'
        verify_bridge(self.document)

    def release_exception(self):
        self._at({'unwind_ready'})
        for lease in self.document['leases']:
            if lease['kind'] == 'exception':
                require(lease['state'] == 'transferred', 'BRIDGE_EXCEPTION_RELEASE')
                module, name = self.held.pop(lease['id'])
                module.release(name)
                lease['state'] = 'released'
                return
        require(False, 'BRIDGE_EXCEPTION_RELEASE')
