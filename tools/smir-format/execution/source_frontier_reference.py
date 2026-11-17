"""Unconsumed synthetic ABI038 REV2 progress witness, never runtime admission.

Single-controller logical transactions only: no host locks, actual C++ source
truth, native execution, allocator-failure atomicity or private runtime facts.
Effect/claim_effect are synthetic probe commands, not new ABI phase events.
Physical incoming lifecycle ticket authority is outside this model and is an
explicit refusal boundary, never replaced by an outside/root selector.
"""
from dataclasses import dataclass, field

CONTRACT_SHA256 = 'de788d9ede798275e800d4d988398daf790833f92fd19c63804cf465e4eb925f'


class ProtocolError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class Resource(ProtocolError):
    def __init__(self):
        super().__init__('MODEL_RESOURCE')


def require(condition, code):
    if not condition:
        raise ProtocolError(code)


class Budget:
    """Non-resettable logical work/edge/copied-byte units, not host capacity."""
    __slots__ = ('_limits', '_used', 'max_depth')

    def __init__(self, *, work, edges, copied_bytes, max_depth):
        if hasattr(self, '_limits'):
            raise AttributeError('non-resettable model budget')
        require(all(type(x) is int and x >= 0 for x in (work, edges, copied_bytes)), 'MODEL_BUDGET')
        require(type(max_depth) is int and 1 <= max_depth <= 32, 'MODEL_BUDGET')
        object.__setattr__(self, '_limits', (work, edges, copied_bytes))
        object.__setattr__(self, '_used', (0, 0, 0))
        object.__setattr__(self, 'max_depth', max_depth)

    def __setattr__(self, name, value):
        raise AttributeError('non-resettable model budget')

    def __delattr__(self, name):
        raise AttributeError('non-resettable model budget')

    @property
    def used(self):
        return self._used

    def charge(self, work=0, edges=0, copied_bytes=0):
        require(all(type(x) is int and x >= 0 for x in (work, edges, copied_bytes)), 'MODEL_BUDGET')
        next_used = tuple(a + b for a, b in zip(self._used, (work, edges, copied_bytes)))
        if any(a > b for a, b in zip(next_used, self._limits)):
            raise Resource()
        object.__setattr__(self, '_used', next_used)


@dataclass(frozen=True, slots=True, eq=False, init=False)
class SyntheticHandle:
    issuer: object
    kind: str
    serial: int
    generation: int
    synthetic: bool = True

    def __init__(self, issuer, kind, serial, generation, synthetic=True):
        if hasattr(self, 'issuer'):
            raise AttributeError('immutable synthetic handle')
        for name, value in (('issuer', issuer), ('kind', kind), ('serial', serial),
                            ('generation', generation), ('synthetic', synthetic)):
            object.__setattr__(self, name, value)


@dataclass(frozen=True, slots=True, init=False)
class Event:
    op: str
    scope: str = ''
    within: str = 'outside'
    subject: str = 'source_object'
    journal: object = None
    anchor: object = None
    attachment: object = None
    wait: bool = False
    outcome: str = 'normal'
    exception: object = None

    def __init__(self, op, scope='', within='outside', subject='source_object', journal=None,
                 anchor=None, attachment=None, wait=False, outcome='normal', exception=None):
        if hasattr(self, 'op'):
            raise AttributeError('immutable static event')
        for name, value in (('op', op), ('scope', scope), ('within', within), ('subject', subject),
                            ('journal', journal), ('anchor', anchor), ('attachment', attachment),
                            ('wait', wait), ('outcome', outcome), ('exception', exception)):
            object.__setattr__(self, name, value)


@dataclass
class _Activation:
    stack: list = field(default_factory=list)
    scopes: dict = field(default_factory=dict)
    frontier: object = None


@dataclass
class _Scope:
    label: str
    subject: str
    journal: object = None
    anchor: object = None


@dataclass
class _Anchor:
    state: str
    claimed: object = None


@dataclass
class _Frontier:
    activation: SyntheticHandle
    locator: str
    candidates: tuple
    arguments: tuple
    results: tuple
    exception: object
    instruction: str
    cursor: int = 0
    pending: object = None
    finished: bool = False


@dataclass
class _Ticket:
    frontier: SyntheticHandle
    ready: bool
    outcome: tuple
    consumed: bool = False


class Controller:
    """All handles and claims are SYNTHETIC; one budget for this entire model."""
    def __init__(self, *, budget):
        if hasattr(self, '_issuer'):
            raise AttributeError('controller already initialized')
        require(type(budget) is Budget, 'MODEL_BUDGET')
        budget.charge(4, 4, 128)
        self.budget = budget
        self._issuer = object()
        self._records = {}
        self._next = 0
        self.effect_count = 0
        self.claim_count = 0
        self.argument_evaluations = 0
        self.anchor_count = 0
        self.scope_count = 0

    def _new(self, kind, payload):
        # Callers reserve the entire publication before entering this commit.
        self._next += 1
        handle = SyntheticHandle(self._issuer, kind, self._next, 1)
        self._records[handle.serial] = [handle, 1, True, payload]
        return handle

    def _get(self, handle, kind=None):
        require(type(handle) is SyntheticHandle, 'MODEL_FORGED_HANDLE')
        require(handle.issuer is self._issuer, 'MODEL_WRONG_CONTROLLER')
        require(type(handle.serial) is int and 0 < handle.serial <= self._next and
                type(handle.generation) is int and handle.generation > 0 and
                handle.synthetic is True, 'MODEL_FORGED_HANDLE')
        row = self._records.get(handle.serial)
        require(row is not None and row[0] is handle, 'MODEL_FORGED_HANDLE')
        require(row[1] == handle.generation and row[2], 'MODEL_STALE_HANDLE')
        require(kind is None or handle.kind == kind, 'MODEL_HANDLE_KIND')
        return row[3]

    def _invalidate(self, handle):
        row = self._records[handle.serial]
        row[1] += 1
        row[2] = False

    def activation(self):
        self.budget.charge(4, 4, 128)
        return self._new('activation', _Activation())

    def journal(self, activation):
        self._get(activation, 'activation')
        self.budget.charge(4, 3, 96)
        return self._new('journal', {'activation': activation, 'used': False})

    def existing_anchor(self):
        self.budget.charge(4, 3, 96)
        self.anchor_count += 1
        return self._new('anchor', _Anchor('published'))

    def attachment(self, activation, anchor, *, mode):
        self._get(activation, 'activation')
        require(self._get(anchor, 'anchor').state == 'published', 'MODEL_UNPUBLISHED')
        require(mode in ('incoming', 'returned'), 'MODEL_ATTACHMENT_MODE')
        self.budget.charge(4, 4, 128)
        return self._new('attachment', {'activation': activation, 'anchor': anchor, 'mode': mode, 'used': False})

    def exception(self, activation):
        self._get(activation, 'activation')
        self.budget.charge(4, 3, 96)
        return self._new('exception', activation)

    def retire(self, activation):
        actor = self._get(activation, 'activation')
        require(not actor.stack and actor.frontier is None, 'MODEL_BUSY')
        self.budget.charge(2, 1, 0)
        self._invalidate(activation)

    def _text(self, value):
        require(type(value) is str, 'MODEL_TEXT')
        self.budget.charge(len(value) + 1, 0, len(value))
        require(len(value) <= 128 and value.isascii(), 'MODEL_TEXT')

    def _values(self, values, depth=0):
        if depth > self.budget.max_depth:
            raise Resource()
        self.budget.charge(1, 1, 8)
        if type(values) is tuple:
            self.budget.charge(len(values), len(values), 8 * len(values))
            for value in values:
                self._values(value, depth + 1)
        elif type(values) is SyntheticHandle:
            self._get(values)
        elif type(values) is str:
            self._text(values)
        else:
            require(values is None or type(values) is int and -(1 << 63) <= values < (1 << 64), 'MODEL_VALUE')

    def frontier(self, activation, *, locator, events, arguments=(), results=(), exception=None, instruction='site'):
        actor = self._get(activation, 'activation')
        require(actor.frontier is None, 'MODEL_FRONTIER_PENDING')
        self._text(locator)
        self._text(instruction)
        require(locator in ('entry', 'pre_op', 'normal_post', 'pre_terminator', 'invoke_normal',
                            'invoke_unwind', 'return_exit', 'unwind_exit'), 'MODEL_LOCATOR')
        require(type(events) is tuple and type(arguments) is tuple and type(results) is tuple, 'MODEL_VECTOR')
        self.budget.charge(len(events), len(events), 8 * len(events))
        for event in events:
            require(type(event) is Event, 'MODEL_EVENT')
            for text in (event.op, event.scope, event.within, event.subject, event.outcome):
                self._text(text)
            require(event.op in ('enter', 'begin', 'bind', 'attach', 'publish', 'exit', 'effect', 'claim_effect'), 'MODEL_EVENT')
            require(type(event.wait) is bool and event.outcome in ('normal', 'unwind'), 'MODEL_EVENT')
            for value, kind in ((event.journal, 'journal'), (event.anchor, 'anchor'),
                                (event.attachment, 'attachment'), (event.exception, 'exception')):
                if value is not None:
                    self._get(value, kind)
            # Static locator/subject checks also cover dynamically skipped sites.
            if event.op == 'enter':
                require(event.subject in ('physical_lifecycle', 'inline_lifecycle'), 'MODEL_SCOPE_SUBJECT')
                if event.subject == 'physical_lifecycle':
                    require(event.within == 'incoming', 'MODEL_INCOMING_SELECTOR_REQUIRED')
                allowed = ('entry',) if event.subject == 'physical_lifecycle' else ('pre_op', 'pre_terminator')
            elif event.op == 'begin':
                require(event.subject == 'source_object', 'MODEL_SCOPE_SUBJECT')
                allowed = ('normal_post',)
            elif event.op == 'bind':
                require(event.subject in ('physical_lifecycle', 'inline_lifecycle'), 'MODEL_SCOPE_SUBJECT')
                allowed = ('normal_post',)
            elif event.op == 'attach':
                require(event.subject == 'existing_object', 'MODEL_SCOPE_SUBJECT')
                mode = self._get(event.attachment, 'attachment')['mode']
                allowed = ('entry',) if mode == 'incoming' else ('normal_post', 'invoke_normal')
            elif event.op == 'publish':
                require(event.subject in ('source_object', 'physical_lifecycle', 'inline_lifecycle'), 'MODEL_SCOPE_SUBJECT')
                allowed = ('normal_post',)
            elif event.op == 'exit':
                require(event.subject in ('source_object', 'existing_object', 'physical_lifecycle', 'inline_lifecycle'), 'MODEL_SCOPE_SUBJECT')
                if event.subject == 'physical_lifecycle':
                    allowed = ('return_exit',) if event.outcome == 'normal' else ('unwind_exit',)
                else:
                    allowed = ('pre_op', 'pre_terminator', 'normal_post') if event.outcome == 'normal' else ('invoke_unwind', 'unwind_exit', 'pre_op', 'pre_terminator')
            else:
                allowed = ('pre_op', 'normal_post', 'invoke_normal')
            require(locator in allowed, 'MODEL_EVENT_LOCATOR')
        self._values(arguments)
        self._values(results)
        if exception is not None:
            require(self._get(exception, 'exception') is activation, 'MODEL_EXCEPTION_OWNER')
        self.budget.charge(4, 4, 256)
        handle = self._new('frontier', _Frontier(activation, locator, events, arguments,
                                               results, exception, instruction))
        actor.frontier = handle
        self.argument_evaluations += 1  # Model evaluation at publication, never replay.
        return handle

    def _selected(self, actor, event):
        if event.within == 'incoming':
            raise ProtocolError('MODEL_INCOMING_TICKET_REQUIRED')
        if event.within == 'outside':
            return not actor.stack
        return bool(actor.stack) and self._get(actor.stack[-1], 'scope').label == event.within

    def _scope(self, actor, event):
        handle = actor.scopes.get(event.scope)
        require(handle is not None, 'MODEL_SCOPE_MISSING')
        scope = self._get(handle, 'scope')
        require(actor.stack and actor.stack[-1] is handle, 'MODEL_SCOPE_CURRENT')
        return handle, scope

    def _new_scope_check(self, actor, event):
        require(event.scope not in ('', 'outside', 'incoming'), 'MODEL_SCOPE_LABEL')
        if len(actor.stack) >= self.budget.max_depth:
            raise Resource()
        previous = actor.scopes.get(event.scope)
        require(previous is None or not self._records[previous.serial][2], 'MODEL_SCOPE_DUPLICATE')

    def _journal(self, receipt, journal):
        require(journal is not None, 'MODEL_RETURNED_J_REQUIRED')
        data = self._get(journal, 'journal')
        require(data['activation'] is receipt.activation, 'MODEL_JOURNAL_OWNER')
        self.budget.charge(len(receipt.results), len(receipt.results), 0)
        require(any(value is journal for value in receipt.results), 'MODEL_RETURNED_J_REQUIRED')
        require(not data['used'], 'MODEL_JOURNAL_REPLAY')
        return data

    def _preflight(self, receipt, actor, event):
        phase = receipt.locator
        if event.op == 'enter':
            require(event.subject in ('physical_lifecycle', 'inline_lifecycle'), 'MODEL_SCOPE_SUBJECT')
            require(phase in (('entry',) if event.subject == 'physical_lifecycle' else ('pre_op', 'pre_terminator')), 'MODEL_EVENT_LOCATOR')
            self._new_scope_check(actor, event)
        elif event.op in ('begin', 'bind'):
            require(phase == 'normal_post', 'MODEL_EVENT_LOCATOR')
            self._journal(receipt, event.journal)
            if event.op == 'begin':
                require(event.subject == 'source_object', 'MODEL_SCOPE_SUBJECT')
                self._new_scope_check(actor, event)
            else:
                _, scope = self._scope(actor, event)
                require(event.subject == scope.subject, 'MODEL_SCOPE_SUBJECT')
                require(scope.subject in ('physical_lifecycle', 'inline_lifecycle') and scope.journal is None, 'MODEL_BIND_DUPLICATE')
        elif event.op == 'attach':
            require(event.subject == 'existing_object', 'MODEL_SCOPE_SUBJECT')
            self._new_scope_check(actor, event)
            ticket = self._get(event.attachment, 'attachment')
            require(ticket['activation'] is receipt.activation and ticket['anchor'] is event.anchor, 'MODEL_ATTACHMENT_OWNER')
            require(not ticket['used'], 'MODEL_ATTACHMENT_REPLAY')
            require(phase in (('entry',) if ticket['mode'] == 'incoming' else ('normal_post', 'invoke_normal')), 'MODEL_EVENT_LOCATOR')
            values = receipt.arguments if ticket['mode'] == 'incoming' else receipt.results
            self.budget.charge(len(values), len(values), 0)
            require(any(value is event.anchor for value in values), 'MODEL_ATTACHMENT_COORDINATE')
            require(self._get(event.anchor, 'anchor').state == 'published', 'MODEL_UNPUBLISHED')
        elif event.op == 'publish':
            require(phase == 'normal_post', 'MODEL_EVENT_LOCATOR')
            _, scope = self._scope(actor, event)
            require(event.subject == scope.subject, 'MODEL_SCOPE_SUBJECT')
            require(scope.subject != 'existing_object' and scope.journal is event.journal, 'MODEL_JOURNAL_REQUIRED')
            require(scope.anchor is not None and self._get(scope.anchor, 'anchor').state == 'constructing', 'MODEL_PUBLISH_DUPLICATE')
        elif event.op == 'exit':
            _, scope = self._scope(actor, event)
            require(event.subject == scope.subject, 'MODEL_SCOPE_SUBJECT')
            if event.outcome == 'normal':
                require(phase in (('return_exit',) if scope.subject == 'physical_lifecycle' else ('pre_op', 'pre_terminator', 'normal_post')), 'MODEL_EVENT_LOCATOR')
                require(scope.anchor is not None and self._get(scope.anchor, 'anchor').state == 'published', 'MODEL_UNPUBLISHED')
            else:
                require(phase in (('unwind_exit',) if scope.subject == 'physical_lifecycle' else ('invoke_unwind', 'unwind_exit', 'pre_op', 'pre_terminator')), 'MODEL_EVENT_LOCATOR')
                require(receipt.exception is not None, 'MODEL_EXCEPTION_REQUIRED')
                require(event.exception is receipt.exception or phase == 'unwind_exit' and event.exception is None, 'MODEL_EXCEPTION_REQUIRED')
            if event.journal is not None:
                require(event.journal is scope.journal, 'MODEL_JOURNAL_REQUIRED')
        else:
            # Synthetic effect/claim probes, not an ABI phase-event grammar.
            require(phase in ('pre_op', 'normal_post', 'invoke_normal'), 'MODEL_EVENT_LOCATOR')
            if event.op == 'claim_effect':
                require(self._get(event.anchor, 'anchor').claimed is None, 'MODEL_CLAIM_DUPLICATE')

    def _create_scope(self, actor, event, *, journal=None, anchor=None):
        scope = self._new('scope', _Scope(event.scope, event.subject, journal, anchor))
        actor.scopes[event.scope] = scope
        actor.stack.append(scope)
        self.scope_count += 1

    def _commit(self, receipt, actor, event):
        if event.op == 'enter':
            self._create_scope(actor, event)
        elif event.op in ('begin', 'bind'):
            anchor = self._new('anchor', _Anchor('constructing'))
            self.anchor_count += 1
            self._get(event.journal)['used'] = True
            if event.op == 'begin':
                self._create_scope(actor, event, journal=event.journal, anchor=anchor)
            else:
                _, scope = self._scope(actor, event)
                scope.journal, scope.anchor = event.journal, anchor
        elif event.op == 'attach':
            self._get(event.attachment)['used'] = True
            self._create_scope(actor, event, anchor=event.anchor)
        elif event.op == 'publish':
            _, scope = self._scope(actor, event)
            self._get(scope.anchor).state = 'published'
        elif event.op == 'exit':
            scope, _ = self._scope(actor, event)
            actor.stack.pop()
            self._invalidate(scope)  # Object anchor remains alive, no object_end.

    def _advance(self, handle, receipt, actor):
        receipt.cursor += 1
        receipt.pending = None
        if receipt.cursor == len(receipt.candidates):
            receipt.finished = True
            actor.frontier = None
            return 'done'
        return 'progress'

    def step(self, handle):
        receipt = self._get(handle, 'frontier')
        actor = self._get(receipt.activation, 'activation')
        require(not receipt.finished and actor.frontier is handle, 'MODEL_FRONTIER_REPLAY')
        if receipt.pending is not None:
            ticket = self._get(receipt.pending, 'effect')
            if not ticket.ready:
                self.budget.charge(1, 1, 0)
                return 'waiting'
            self.budget.charge(3, 1, 64)  # May refuse AFTER durable effect commit.
            ticket.consumed = True
            return self._advance(handle, receipt, actor)
        self.budget.charge(2, 1, 0)  # Evaluate CURRENT selector, never PRE-filter.
        if receipt.cursor == len(receipt.candidates):
            receipt.finished, actor.frontier = True, None
            return 'done'
        event = receipt.candidates[receipt.cursor]
        if not self._selected(actor, event):
            return self._advance(handle, receipt, actor)
        self.budget.charge(4, 4, 256)
        self._preflight(receipt, actor, event)
        if event.op in ('effect', 'claim_effect'):
            ticket = self._new('effect', _Ticket(handle, not event.wait, ('synthetic_committed', self.effect_count + 1)))
            receipt.pending = ticket
            self.effect_count += 1
            if event.op == 'claim_effect':
                self._get(event.anchor, 'anchor').claimed = ticket
                self.claim_count += 1
            # Pending ticket/outcome survives Resource. Never rerun this branch.
            return self.step(handle)
        self._commit(receipt, actor, event)
        return self._advance(handle, receipt, actor)

    def release(self, ticket):
        pending = self._get(ticket, 'effect')
        receipt = self._get(pending.frontier, 'frontier')
        self._get(receipt.activation, 'activation')
        require(not pending.ready and not pending.consumed and receipt.pending is ticket,
                'MODEL_TICKET_REPLAY')
        self.budget.charge(2, 1, 0)
        pending.ready = True

    def cancel(self, frontier):
        receipt = self._get(frontier, 'frontier')
        actor = self._get(receipt.activation, 'activation')
        require(not receipt.finished and actor.frontier is frontier, 'MODEL_FRONTIER_REPLAY')
        self.budget.charge(1, 1, 0)
        # No source-aware cleanup producer exists in this local model. Refuse
        # without dropping any cursor, claim, ticket, J or anchor obligation.
        raise ProtocolError('MODEL_CANCEL_REQUIRES_OWNER_CLEANUP')

    def progress(self, frontier):
        receipt = self._get(frontier, 'frontier')
        self.budget.charge(2, 2, 48)
        return receipt.cursor, receipt.finished, receipt.pending
