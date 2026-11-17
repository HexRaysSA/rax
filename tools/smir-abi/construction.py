"""Typed partial-subobject/array construction, cleanup and exception leases.

Reference state transitions only: no constructors, native destructors or runtime
threads are executed. All effect completion tickets are explicit and replay-safe.
"""

from copy import deepcopy

from layout import MAX_OBJECT, alignment, integer, require
from nominal import option, unique


def verify_program(program):
    slots = unique(program['slots'], 'SLOT')
    require(len(slots) <= 4096, 'ABI_CC_JOURNAL_LIMIT')
    for slot in slots.values():
        alignment(slot['align'])
        require(slot['offset'] % slot['align'] == 0 and slot['stride'] > 0,
                'ABI_CC_SUBOBJECT_ALIGNMENT')
        require(slot['role'] in ('root', 'base', 'virtual_base', 'member', 'union_member',
                                 'array', 'vla', 'allocation', 'catch_object'), 'ABI_CC_SLOT_ROLE')
        parent = option(slot['parent'])
        require(parent is None or parent in slots and parent != slot['id'], 'ABI_CC_SLOT_PARENT')
        if parent is not None:
            require(slots[parent]['count'] == 1 and slots[parent]['count_source'] is None,
                    'ABI_CC_ARRAY_PARENT_REQUIRES_INSTANCE')
        require(set(slot['dependencies']) <= slots.keys() and slot['id'] not in slot['dependencies'],
                'ABI_CC_SLOT_DEPENDENCY')
        require(parent not in slot['dependencies'], 'ABI_CC_SLOT_DEPENDENCY')
        require(len(set(slot['dependencies'])) == len(slot['dependencies']), 'ABI_CC_SLOT_DEPENDENCY')
        require(slot['destructor_kind'] in ('none', 'leaf', 'base', 'complete'), 'ABI_CC_DESTRUCTOR_KIND')
        require((slot['destructor'] is None) == (slot['destructor_kind'] == 'none'),
                'ABI_CC_DESTRUCTOR_KIND')
        require(len(set(slot['covers'])) == len(slot['covers']) and
                set(slot['covers']) <= slots.keys() and slot['id'] not in slot['covers'],
                'ABI_CC_DESTRUCTOR_COVERAGE')
        require(not slot['covers'] or slot['destructor_kind'] in ('base', 'complete'),
                'ABI_CC_DESTRUCTOR_COVERAGE')
    # All ordering/parent edges are checked, independent of source ordering.
    done, active = set(), set()

    def visit(identifier):
        if identifier in done:
            return
        require(identifier not in active, 'ABI_CC_SLOT_CYCLE')
        active.add(identifier)
        parent = option(slots[identifier]['parent'])
        for dependency in slots[identifier]['dependencies'] + ([] if parent is None else [parent]):
            visit(dependency)
        active.remove(identifier)
        done.add(identifier)

    for identifier in slots:
        visit(identifier)
    for slot in slots.values():
        for child in slot['covers']:
            cursor, ancestors = child, set()
            while option(slots[cursor]['parent']) is not None:
                cursor = option(slots[cursor]['parent'])
                ancestors.add(cursor)
            require(slot['id'] in ancestors, 'ABI_CC_DESTRUCTOR_COVERAGE')
    for name in ('normal_order', 'exception_order'):
        order = program[name]
        require(len(order) == len(set(order)) and set(order) == slots.keys(), 'ABI_CC_CLEANUP_ORDER')
    return slots


class ConstructionJournal:
    """Per-element state; O(slots+live elements), cleanup O(committed elements).

    Transition identity and generation are fixed runtime facts, never derived
    from a file ticket. Dynamic counts are captured once from admitted values.
    """

    def __init__(self, program, *, transition, thread, activation, generation, instance,
                 counts=None, parent_instance=None, registry=None, program_key=None, resolve_program=None,
                 destruction=False):
        self.program = deepcopy(program)
        self.program_key = ('local', program['id']) if program_key is None else program_key
        def local_program(reference):
            require(reference['module']['kind'] == 'self', 'ABI_CC_UNBOUND_PROGRAM')
            return self.program_key[0], reference['id']
        self.resolve_program = local_program if resolve_program is None else resolve_program
        self.slots = verify_program(program)
        self.identity = transition, thread, activation, generation, instance
        require(all(type(value) is int and value > 0 for value in self.identity), 'ABI_CC_JOURNAL_IDENTITY')
        self.counts = {}
        self.states = {}
        self.entries = []
        self.ordinal = 0
        self.tickets = set()
        self.stage = 'constructing'
        self.exception_lease = None
        self.instance = instance
        self.registry = {} if registry is None else registry
        require(instance not in self.registry, 'ABI_CC_JOURNAL_INSTANCE_REPLAY')
        self.parent_instance = parent_instance
        self.children = {}
        for identifier, slot in self.slots.items():
            source = option(slot['count_source'])
            count = slot['count'] if source is None else (counts or {}).get(source)
            integer(count, 1 if slot['role'] == 'vla' else 0, MAX_OBJECT, 'ABI_CC_ARRAY_COUNT')
            require(count * slot['stride'] <= slot['extent'] <= MAX_OBJECT,
                    'ABI_CC_ARRAY_EXTENT')
            require(count <= 100000, 'ABI_CC_JOURNAL_RESOURCE')
            self.counts[identifier] = count
            for element in range(count):
                self.states[identifier, element] = {'phase': 'empty', 'ticket': None, 'ordinal': None}
        for identifier, slot in self.slots.items():
            parent = option(slot['parent'])
            if parent is not None:
                require(slot['offset'] + slot['extent'] <= self.slots[parent]['extent'],
                        'ABI_CC_SUBOBJECT_EXTENT')
        if parent_instance is not None:
            parent = self.registry.get(parent_instance['journal'])
            require(parent is not None and parent.identity[1] == thread, 'ABI_CC_PARENT_INSTANCE')
            key = parent_instance['slot'], parent_instance['element']
            parent_state = parent._state(*key)
            require(parent_state['phase'] == ('destroying' if destruction else 'constructing') and key not in parent.children and
                    parent.slots[key[0]]['child_program'] is not None and
                    parent.resolve_program(option(parent.slots[key[0]]['child_program'])) == self.program_key, 'ABI_CC_PARENT_INSTANCE')
            parent.children[key] = instance
        self.registry[instance] = self

    def _identity(self, identity):
        require(tuple(identity) == self.identity, 'ABI_CC_STALE_JOURNAL')

    def _state(self, slot, element):
        require((slot, element) in self.states, 'ABI_CC_SUBOBJECT_REFERENCE')
        return self.states[slot, element]

    def _event(self, slot, element, ticket, phase, ordinal=None):
        self.entries.append({'instance': self.instance, 'transition': self.identity[0], 'thread': self.identity[1],
                             'activation': self.identity[2], 'generation': self.identity[3],
                             'slot': slot, 'element': element, 'ticket': ticket,
                             'phase': phase, 'ordinal': self.ordinal if ordinal is None else ordinal,
                             'owner': self.slots[slot]['owner'], 'exception_lease':
                             None if self.exception_lease is None else {'some': self.exception_lease}})

    def begin(self, slot, element, ticket, identity):
        self._identity(identity)
        require(self.stage == 'constructing', 'ABI_CC_JOURNAL_STAGE')
        state = self._state(slot, element)
        require(state['phase'] == 'empty' and ticket not in self.tickets, 'ABI_CC_CONSTRUCTION_REPLAY')
        require(element == 0 or self._state(slot, element - 1)['phase'] == 'alive',
                'ABI_CC_ARRAY_PREFIX')
        for dependency in self.slots[slot]['dependencies']:
            require(all(self._state(dependency, index)['phase'] == 'alive'
                        for index in range(self.counts[dependency])), 'ABI_CC_CONSTRUCTION_ORDER')
        parent = option(self.slots[slot]['parent'])
        if parent is not None:
            require(any(self._state(parent, index)['phase'] == 'constructing'
                        for index in range(self.counts[parent])), 'ABI_CC_CONSTRUCTION_PARENT')
        if self.slots[slot]['role'] == 'union_member':
            for sibling, other in self.slots.items():
                if sibling != slot and other['role'] == 'union_member' and other['parent'] == self.slots[slot]['parent']:
                    require(all(self._state(sibling, index)['phase'] == 'empty'
                                for index in range(self.counts[sibling])), 'ABI_CC_UNION_LIFETIME')
        self.tickets.add(ticket)
        state.update(phase='constructing', ticket=ticket)
        self._event(slot, element, ticket, 'construct_begin')

    def commit(self, slot, element, ticket, identity):
        self._identity(identity)
        state = self._state(slot, element)
        require(self.stage == 'constructing' and state['phase'] == 'constructing'
                and state['ticket'] == ticket, 'ABI_CC_CONSTRUCTION_REPLAY')
        if self.slots[slot]['child_program'] is not None:
            child_id = self.children.get((slot, element))
            require(child_id in self.registry and self.registry[child_id].stage in ('alive','published'),
                    'ABI_CC_CHILD_CONSTRUCTION')
        for child, descriptor in self.slots.items():
            if option(descriptor['parent']) == slot:
                require(all(self._state(child, index)['phase'] == 'alive' or
                            descriptor['role'] == 'union_member' and
                            self._state(child, index)['phase'] == 'empty'
                            for index in range(self.counts[child])), 'ABI_CC_INCOMPLETE_CONSTRUCTION')
        self.ordinal += 1
        state.update(phase='alive', ordinal=self.ordinal)
        self._event(slot, element, ticket, 'construct_commit')

    def construction_throws(self, slot, element, ticket, exception, identity):
        self._identity(identity)
        state = self._state(slot, element)
        require(state['phase'] == 'constructing' and state['ticket'] == ticket
                and self.stage in ('constructing', 'unwinding') and exception > 0,
                'ABI_CC_CONSTRUCTION_REPLAY')
        require(self.exception_lease is None or self.exception_lease == exception, 'ABI_CC_EXCEPTION_IDENTITY')
        state['phase'] = 'failed'
        self.exception_lease = exception
        self.stage = 'unwinding'
        self._event(slot, element, ticket, 'construct_failed')

    def finish_construction(self):
        require(self.stage == 'constructing', 'ABI_CC_JOURNAL_STAGE')
        for (slot, _), state in self.states.items():
            require(state['phase'] == 'alive' or self.slots[slot]['role'] == 'union_member'
                    and state['phase'] == 'empty', 'ABI_CC_INCOMPLETE_CONSTRUCTION')
        self.stage = 'alive'

    def cleanup_plan(self):
        require(self.stage in ('alive', 'unwinding', 'cleanup'), 'ABI_CC_JOURNAL_STAGE')
        live = [(state['ordinal'], slot, element) for (slot, element), state in self.states.items()
                if state['phase'] == 'alive']
        covered = {child for _, slot, _ in live for child in self.slots[slot]['covers']}
        plan=[(slot, element) for _, slot, element in sorted(live, reverse=True) if slot not in covered]
        order=self.program['exception_order' if self.stage=='unwinding' else 'normal_order']
        ranks={slot:index for index,slot in enumerate(order)}
        selected=[ranks[slot] for slot,_ in plan]
        require(selected==sorted(selected),'ABI_CC_CLEANUP_ORDER')
        return plan

    def destroy_begin(self, slot, element, ticket, identity):
        self._identity(identity)
        plan = self.cleanup_plan()
        require(plan and plan[0] == (slot, element), 'ABI_CC_CLEANUP_ORDER')
        require(ticket not in self.tickets, 'ABI_CC_CLEANUP_REPLAY')
        state = self._state(slot, element)
        self.tickets.add(ticket)
        state.update(phase='destroying', ticket=ticket)
        for child in self.slots[slot]['covers']:
            for index in range(self.counts[child]):
                child_state = self._state(child, index)
                if child_state['phase'] == 'alive':
                    child_state['phase'] = 'delegated'
        self._event(slot, element, ticket, 'destroy_begin')

    def destroy_commit(self, slot, element, ticket, identity, *, throws=False, exception=None):
        self._identity(identity)
        state = self._state(slot, element)
        require(state['phase'] == 'destroying' and state['ticket'] == ticket, 'ABI_CC_CLEANUP_REPLAY')
        child_id = self.children.get((slot, element))
        require(child_id is None or self.registry[child_id].stage == 'destroyed', 'ABI_CC_CHILD_CLEANUP')
        if throws:
            if self.stage == 'unwinding':
                self.stage = 'terminated'
                self._event(slot, element, ticket, 'terminate')
                return
            require(exception is not None and exception > 0, 'ABI_CC_EXCEPTION_IDENTITY')
            self.exception_lease = exception
            self.stage = 'unwinding'
        state['phase'] = 'destroyed'
        for child in self.slots[slot]['covers']:
            for index in range(self.counts[child]):
                child_state = self._state(child, index)
                if child_state['phase'] == 'delegated':
                    child_state['phase'] = 'destroyed'
        self._event(slot, element, ticket, 'destroy_raised' if throws else 'destroy_commit')

    def nonlocal_abandon(self):
        require(self.stage not in ('terminated', 'abandoned'), 'ABI_CC_JOURNAL_STAGE')
        require(not any(state['phase'] in ('alive', 'constructing', 'destroying')
                        and self.slots[slot]['destructor'] is not None
                        for (slot, _), state in self.states.items()), 'ABI_CC_LONGJMP_NONTRIVIAL')
        self.stage = 'abandoned'

    def finish_cleanup(self):
        require(self.stage in ('alive', 'unwinding', 'cleanup') and
                all(state['phase'] in ('empty', 'failed', 'destroyed') for state in self.states.values()),
                'ABI_CC_INCOMPLETE_CLEANUP')
        self.stage = 'destroyed'


class ExceptionLease:
    """One owner payload, counted active throws/catches and exception_ptr handles."""

    def __init__(self, identity, owner, module_generation, destructor):
        require(identity > 0 and module_generation > 0, 'ABI_CC_EXCEPTION_IDENTITY')
        self.identity, self.owner = identity, owner
        self.module_generation, self.destructor = module_generation, destructor
        self.active = 1
        self.pointers = 0
        self.catches = {}
        self.pending = {None:1}
        self.destroyed = False
        self.events = []

    def begin_catch(self, thread, *, copy_throws=False):
        require(not self.destroyed and self.active > 0, 'ABI_CC_EXCEPTION_LIFETIME')
        pending=thread if self.pending.get(thread,0) else None
        require(self.pending.get(pending,0)>0,'ABI_CC_EXCEPTION_CATCH_REPLAY')
        if copy_throws:
            self.events.append(('terminate', 'catch_copy_throw'))
            return 'terminated'
        self.pending[pending]-=1
        self.catches[thread] = self.catches.get(thread, 0) + 1
        self.events.append(('catch', thread))
        return 'caught'

    def retain_pointer(self):
        require(not self.destroyed, 'ABI_CC_EXCEPTION_LIFETIME')
        self.pointers += 1

    def rethrow_pointer(self, thread, attached):
        require(not self.destroyed and self.pointers > 0 and attached,
                'ABI_CC_EXCEPTION_LIFETIME')
        self.active += 1
        self.pending[thread]=self.pending.get(thread,0)+1
        self.events.append(('rethrow', thread, self.identity))

    def rethrow_current(self, thread):
        require(not self.destroyed and self.catches.get(thread,0)>0,'ABI_CC_EXCEPTION_LIFETIME')
        self.active+=1
        self.pending[thread]=self.pending.get(thread,0)+1
        self.events.append(('rethrow_current',thread,self.identity))

    def end_catch(self, thread):
        require(not self.destroyed and self.catches.get(thread, 0) > 0, 'ABI_CC_EXCEPTION_LIFETIME')
        self.catches[thread] -= 1
        self.active -= 1
        self._destroy()

    def release_pointer(self):
        require(not self.destroyed and self.pointers > 0, 'ABI_CC_EXCEPTION_LIFETIME')
        self.pointers -= 1
        self._destroy()

    def _destroy(self):
        require(self.active>=0 and self.pointers>=0,'ABI_CC_EXCEPTION_LIFETIME')
        if self.active == self.pointers == 0:
            self.destroyed = True
            self.events.append(('destroy', self.owner, self.module_generation, self.destructor))
