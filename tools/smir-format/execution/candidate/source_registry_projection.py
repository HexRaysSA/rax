"""Draft SPI1+3+4 views and genuine reference-Machine execution receipts.

Private receipt membership authenticates actual construction and successful
verification calls. These are reference capabilities, not production or native
issuers. Trusted Python implementation/private-table mutation is outside this
reference threat model. Queries use charged frozen wire records.
"""
from dataclasses import dataclass
from pathlib import Path
import sys
from threading import RLock, get_ident
import weakref

if __name__ != '_rax_smir_source_registry_v1':
    raise ImportError('SOURCE_REGISTRY_MODULE_IDENTITY')

ROOT = Path(__file__).resolve().parents[4]
_TOKEN = object()
_CONTEXTS = {}  # id(context) -> weak context, immutable construction associations
_ISSUED = {}    # id(view) -> weak view and original associations
_CACHE = {}     # (id(context), id(budget)) -> weak view; no equality-based keys
_MACHINES = {}
_FRAMES = {}
_FACTS = {}
_ISSUER_LOCK = RLock()
_PUBLICATION_LOCK = RLock()
_PUBLIC_ROOTS = frozenset((2, 3, 4, 5, 6, 7, 9))
_TABLES = {'function': (3, 'functions'), 'symbol': (2, 'symbols'),
           'import': (6, 'imports'), 'export': (2, 'exports')}


def _machine_class(machine, token=None):
    cls = type(machine)
    module = sys.modules.get(cls.__module__)
    if (module is None or getattr(module, '__file__', None) is None or
            Path(module.__file__).resolve() != ROOT / 'tools/smir-format/execution/candidate/machine.py' or
            getattr(module, 'Machine', None) is not cls):
        _error(detail='actual Machine required')
    if token is not None and token is not getattr(module, '_SOURCE_MACHINE_ISSUER', None):
        _error(detail='private Machine issuer required')
    return module


def _note_machine(machine, original, token):
    _machine_class(machine, token)
    identity = id(machine)
    def discard(reference):
        row = _MACHINES.get(identity)
        if row is not None and row['machine'] is reference:
            del _MACHINES[identity]
    _MACHINES[identity] = dict(machine=weakref.ref(machine, discard), original=original,
        admitted=machine.admitted, types=machine.types, functions=machine.functions,
        original_functions=dict(machine.functions), thread=object(), source=None,
        registry=None, attachment=None, stack=machine.stack, frame_stack=[], dispatch=None, epoch=None, ssa={}, frames={},
        legacy={}, observations={}, pending_completion=None, pending_result=None, value_lanes={},
        completed={}, entries={}, block_index={id(fn): {b['id']: b for b in fn['blocks']}
                                            for fn in machine.functions.values()})


def _machine(machine):
    _machine_class(machine)
    row = _MACHINES.get(id(machine))
    if (row is None or row['machine']() is not machine or row['admitted'] is not machine.admitted or
            row['types'] is not machine.types or row['functions'] is not machine.functions or
            row['stack'] is not machine.stack or type(machine.stack) is not list):
        _error(detail='original issued Machine association')
    return row


def validate_source_machine(machine, *, source, budget):
    validate_source_registry_context(source, budget=budget)
    row = _machine(machine)
    budget.charge(work=len(row['original_functions']) + 4, edges=len(row['original_functions']))
    if (len(machine.functions) != len(row['original_functions']) or any(
            machine.functions.get(k) is not v for k, v in row['original_functions'].items())):
        _error(detail='original admitted function association')
    if row['original'] is not source._context.execution_checked:
        _error(detail='Machine original verified input is not this source verification')
    if row['source'] is not None and row['source'] is not source:
        _error(detail='Machine already associated with another source')
    projection = source._projection
    schema, digest = projection._schema(budget)
    if digest != source._stamp.schema_digest:
        projection._fail('SOURCE_DATA_SCHEMA')
    for section, actual in ((1, machine.admitted.types_root), (3, machine.admitted.functions_root),
                            (8, machine.admitted.exceptions_root)):
        walk = projection._WireCapture(schema, budget, False)
        walk.visit(projection.ROOT_NAMES[section], actual)
        expected = dict(source._stamp.root_digests)[section]
        if projection._digest(walk.hasher, budget) != expected:
            _error(detail='Machine reverified program snapshot changed')
    validate_source_registry_context(source, budget=budget)


def _associate_machine(machine, source, registry, attachment, budget, token):
    _machine_class(machine, token)
    validate_source_machine(machine, source=source, budget=budget)
    row = _machine(machine)
    if row['registry'] is not None:
        _error(detail='Machine source attachment already published')
    api = _registry_api()
    if type(registry) is not api.CodeRegistry or type(attachment) is not api.MachineAttachment:
        _error(detail='actual canonical registry attachment required')
    row.update(source=source, registry=weakref.ref(registry), attachment=weakref.ref(attachment))


def _registry_api():
    module = sys.modules.get('_rax_smir_code_addresses_v1')
    path = ROOT / 'tools/smir-runtime-contract/source_roles/code_addresses.py'
    if (module is None or getattr(module, '__file__', None) is None or
            Path(module.__file__).resolve() != path or getattr(module, '_CODE_ADDRESSES_READY', False) is not True):
        _error('SOURCE_REGISTRY_EVIDENCE_UNAVAILABLE', 'actual canonical code registry required', 'unavailable')
    return module


def _note_frame(machine, frame, token):
    module = _machine_class(machine, token)
    row = _machine(machine)
    if type(frame) is not module.Frame or row['original_functions'].get(frame.function['id']) is not frame.function:
        _error(detail='actual admitted frame function required')
    identity = id(frame)
    def discard(reference):
        entry = _FRAMES.get(identity)
        if entry is not None and entry['frame'] is reference:
            del _FRAMES[identity]
    _FRAMES[identity] = dict(frame=weakref.ref(frame, discard), machine=weakref.ref(machine),
        function=frame.function, activation=frame.activation, generation=object(), values=frame.values,
        fact=None, active=False, depth=None, version=0)
    _note_values(machine, frame, tuple(frame.values), tuple(frame.values.values()), token)


def _note_values(machine, frame, identifiers, values, token):
    _machine_class(machine, token)
    row = _machine(machine)
    for identifier, value in zip(identifiers, values):
        row['ssa'][id(frame), identifier] = weakref.ref(value)
    _FRAMES[id(frame)]['version'] += 1


def _enter_frame(machine, frame, token):
    _machine_class(machine, token)
    row = _machine(machine)
    issued = _FRAMES.get(id(frame))
    if (issued is None or issued['frame']() is not frame or issued['active'] or
            len(machine.stack) != len(row['frame_stack']) + 1 or machine.stack[-1] is not frame):
        _error(detail='actual frame push required')
    issued['active'], issued['depth'] = True, len(row['frame_stack'])
    row['frame_stack'].append(weakref.ref(frame))


def _leave_frame(machine, frame, token):
    _machine_class(machine, token)
    row, issued = _frame(machine, frame)
    if row['frame_stack'][-1]() is not frame:
        _error(detail='actual top frame pop required')
    row['frame_stack'].pop()
    issued['active'] = False


def _frame(machine, frame):
    row = _machine(machine)
    issued = _FRAMES.get(id(frame))
    if (issued is None or issued['frame']() is not frame or issued['machine']() is not machine or
            issued['function'] is not frame.function or issued['activation'] != frame.activation or
            issued['values'] is not frame.values or not issued['active'] or
            len(machine.stack) != len(row['frame_stack']) or issued['depth'] >= len(row['frame_stack']) or
            row['frame_stack'][issued['depth']]() is not frame or machine.stack[issued['depth']] is not frame):
        _error(detail='original live frame required')
    return row, issued


def _dispatch(machine, frame, node, token):
    _machine_class(machine, token)
    row, issued = _frame(machine, frame)
    if machine.stack[-1] is not frame:
        _error(detail='dispatch requires current frame')
    block = row['block_index'][id(frame.function)][frame.block]
    actual = block['ops'][frame.position] if frame.position < len(block['ops']) else block['term']
    if actual is not node:
        _error(detail='original admitted current operation required')
    row['dispatch'] = (weakref.ref(frame), frame.block, frame.position, node)
    pending = row['pending_result']
    if pending is not None:
        fields = _fact_fields(pending, _SourcePendingResult)
        row['source']._budget.charge(work=len(fields['operands']) + 4, edges=len(fields['operands']))
        if fields['frame']() is not frame or fields['node'] is not node:
            _error(detail='pending source result cannot change operation')
        row['epoch'] = fields['epoch']
    else:
        row['epoch'] = object()
    row['dispatch_thread'] = get_ident()
    row['observations'].clear()


def _current(machine, frame):
    row, issued = _frame(machine, frame)
    dispatch = row['dispatch']
    if (dispatch is None or dispatch[0]() is not frame or machine.stack[-1] is not frame or
            dispatch[1:3] != (frame.block, frame.position) or row.get('dispatch_thread') != get_ident()):
        _error(detail='current private dispatch required')
    if row['source'] is None:
        _error('SOURCE_REGISTRY_EVIDENCE_UNAVAILABLE', 'actual source attachment required', 'unavailable')
    return row, dispatch[3]


class _SourceFact:
    __slots__ = ('_fields', '__weakref__')
    def __new__(cls, token=None, *args):
        if token is not _TOKEN or cls not in _FACT_CLASSES:
            _error(detail='no public source fact constructor')
        return object.__new__(cls)
    def __init__(self, token, fields):
        if hasattr(self, '_fields'):
            _error(detail='source fact already initialized')
        object.__setattr__(self, '_fields', fields)
    def __setattr__(self, key, value):
        raise AttributeError('immutable source fact')
    def __delattr__(self, key):
        raise AttributeError('immutable source fact')


class SourceActivation(_SourceFact):
    __slots__ = ()


class SourceOrdinaryCall(_SourceFact):
    __slots__ = ()
    context = property(lambda self: self._fields['context'])
    plan = property(lambda self: self._fields['plan'])
    execution = property(lambda self: self._fields['execution'])


class LegacyCodeSource(_SourceFact):
    __slots__ = ()


class SourceEntryOutcome(_SourceFact):
    __slots__ = ()


class SourceEntryCommit(_SourceFact):
    __slots__ = ()


class _SourcePendingResult(_SourceFact):
    __slots__ = ()


_FACT_CLASSES = frozenset((SourceActivation, SourceOrdinaryCall, LegacyCodeSource, SourceEntryOutcome,
                           SourceEntryCommit, _SourcePendingResult))


def _fact(cls, **fields):
    from types import MappingProxyType
    public = MappingProxyType(fields)
    value = cls(_TOKEN, public)
    identity = id(value)
    def discard(reference):
        old = _FACTS.get(identity)
        if old is not None and old[0] is reference:
            del _FACTS[identity]
    _FACTS[identity] = (weakref.ref(value, discard), fields, public)
    return value


def _fact_fields(value, cls):
    if type(value) is not cls:
        _error(detail='canonical source fact required')
    row = _FACTS.get(id(value))
    if row is None or row[0]() is not value or row[2] is not value._fields:
        _error(detail='original issued source fact required')
    return row[1]


def _begin_result(machine, frame, node, output, token):
    _machine_class(machine, token)
    row, actual = _current(machine, frame)
    if actual is not node:
        _error(detail='actual result-producing node required')
    pending = row['pending_result']
    if pending is not None:
        fields = _fact_fields(pending, _SourcePendingResult)
        if (fields['frame']() is not frame or fields['node'] is not node or fields['epoch'] is not row['epoch'] or
                any(_ssa(machine, frame, identifier) is not original() for identifier, original in fields['operands'])):
            _error(detail='original pending result association')
        return pending
    row['source']._budget.charge(work=8 + len(node['operands']), edges=8, copied_bytes=384)
    operands = tuple((identifier, weakref.ref(_ssa(machine, frame, identifier))) for identifier in node['operands'])
    pending = _fact(_SourcePendingResult, machine=weakref.ref(machine), frame=weakref.ref(frame),
        node=node, output=output, epoch=row['epoch'], operands=operands, lane=None,
        root=None, borrowed=None, value=None)
    row['pending_result'] = pending
    return pending


def _pending_result_fields(machine, pending, token):
    _machine_class(machine, token)
    row = _machine(machine)
    fields = _fact_fields(pending, _SourcePendingResult)
    if row['pending_result'] is not pending or fields['machine']() is not machine:
        _error(detail='original pending source result required')
    return fields


def _finish_result(machine, frame, token):
    _machine_class(machine, token)
    row = _machine(machine)
    pending = row['pending_result']
    if pending is None:
        return
    fields = _pending_result_fields(machine, pending, token)
    result = fields['node']['results'][0]['id']
    if fields['frame']() is not frame or _ssa(machine, frame, result) is not fields['value']:
        _error(detail='actual pending result SSA publication required')
    row['pending_result'] = None


def _source_activation(machine, frame, *, budget):
    row, issued = _frame(machine, frame)
    source = row['source']
    if source is None:
        _error('SOURCE_REGISTRY_EVIDENCE_UNAVAILABLE', 'actual source attachment required', 'unavailable')
    validate_source_machine(machine, source=source, budget=budget)
    cached = issued['fact']
    if cached is not None and cached() is not None:
        return validate_source_activation(cached(), source=source, budget=budget)
    budget.charge(work=4, edges=4, copied_bytes=192)
    result = _fact(SourceActivation, machine=weakref.ref(machine), frame=weakref.ref(frame),
                   source=source, generation=issued['generation'], thread=row['thread'])
    issued['fact'] = weakref.ref(result)
    return result


def validate_source_activation(value, *, source, budget):
    fields = _fact_fields(value, SourceActivation)
    if fields['source'] is not source:
        _error(detail='activation original source context')
    machine, frame = fields['machine'](), fields['frame']()
    row, issued = _frame(machine, frame)
    if fields['generation'] is not issued['generation'] or fields['thread'] is not row['thread']:
        _error(detail='activation generation/thread')
    validate_source_machine(machine, source=source, budget=budget)
    return value


def source_activation_context(source, *, budget):
    fields = _fact_fields(source, SourceActivation)
    validate_source_activation(source, source=fields['source'], budget=budget)
    return fields['source']


def _source_call(machine, frame, *, budget):
    row, node = _current(machine, frame)
    if node['op'] not in {'call', 'invoke', 'tailcall'} or node['source_plan'] is None:
        _error(detail='actual current source call required')
    activation = _source_activation(machine, frame, budget=budget)
    call = row['source'].call_context(budget=budget)
    api = row['source']._projection.source_api()
    schema, _ = row['source']._projection._schema(budget)
    walk = row['source']._projection._WireCapture(schema, budget, True)
    plan = _call()._wrap(walk.visit('entity_ref', node['source_plan']['some']), api, budget)
    walk = row['source']._projection._WireCapture(schema, budget, True)
    execution = _call()._wrap(walk.visit('entity_ref', node['target']['signature']), api, budget)
    # Verify every actual argument's identity against privately observed SSA.
    budget.charge(work=len(node['operands']) + 5, edges=len(node['operands']) + 1, copied_bytes=256)
    for identifier in node['operands']:
        _ssa(machine, frame, identifier)
    if node['target']['kind'] == 'indirect':
        _ssa(machine, frame, node['target']['value'])
    return _fact(SourceOrdinaryCall, machine=weakref.ref(machine), frame=weakref.ref(frame),
                 activation=activation, context=call, plan=plan, execution=execution,
                 epoch=row['epoch'], node=node, source=row['source'])


def validate_source_ordinary_call(value, *, activation, budget):
    fields = _fact_fields(value, SourceOrdinaryCall)
    active = _fact_fields(activation, SourceActivation)
    validate_source_activation(activation, source=fields['source'], budget=budget)
    machine, frame = fields['machine'](), fields['frame']()
    row, node = _current(machine, frame)
    if (fields.get('entry_committed', False) or active['machine']() is not machine or active['frame']() is not frame or
            fields['epoch'] is not row['epoch'] or fields['node'] is not node or
            fields['context'] is not row['source'].call_context(budget=budget)):
        _error(detail='original current source call association')
    budget.charge(work=len(node['operands']) + 1, edges=len(node['operands']) + 1)
    for identifier in node['operands']:
        _ssa(machine, frame, identifier)
    if node['target']['kind'] == 'indirect':
        _ssa(machine, frame, node['target']['value'])
    return value


def validate_source_call_operand(call, code, *, activation, budget):
    validate_source_ordinary_call(call, activation=activation, budget=budget)
    fields = _fact_fields(call, SourceOrdinaryCall)
    node = fields['node']
    if node['target']['kind'] != 'indirect':
        _error('SOURCE_REGISTRY_EVIDENCE_UNAVAILABLE', 'actual indirect bound call required', 'unavailable')
    value = _ssa(fields['machine'](), fields['frame'](), node['target']['value'])
    if getattr(value.data, 'authority', None) is not code:
        _error(detail='actual original call operand handle required')
    validate_source_ordinary_call(call, activation=activation, budget=budget)


def _ssa(machine, frame, identifier):
    row, issued = _frame(machine, frame)
    if type(identifier) is not int or not 0 <= identifier < 2**32:
        _error(detail='SSA value id')
    original = row['ssa'].get((id(frame), identifier))
    value = frame.values.get(identifier)
    if original is None or original() is not value:
        _error(detail='original actual SSA value required')
    return value


def validate_source_observation(activation, operation, value, *, plan=None, budget):
    fields = _fact_fields(activation, SourceActivation)
    validate_source_activation(activation, source=fields['source'], budget=budget)
    machine, frame = fields['machine'](), fields['frame']()
    row, node = _current(machine, frame)
    expected = {'bind': 'code_bind', 'erase': 'code_erase', 'expose': 'ptrtoint', 'recover': 'inttoptr'}
    if operation not in expected or node['op'] != expected[operation]:
        _error(detail='actual observing operation required')
    operand = _ssa(machine, frame, node['operands'][0])
    if getattr(operand.data, 'authority', None) is not value:
        observed = row['observations'].get(id(value))
        published = row['value_lanes'].get(id(operand))
        legacy = _FACTS.get(id(value))
        if not (published is not None and published[0]() is operand and published[1]() is value) and not (
                observed is not None and observed[0]() is value and observed[1]() is operand and
                observed[2] is row['epoch']) and (operation != 'erase' or legacy is None or
                type(value) is not LegacyCodeSource or legacy[1].get('value') is None or
                legacy[1]['value']() is not operand):
            _error(detail='original observing SSA opaque value association')
    if operation == 'bind':
        original, _, _, _ = _call()._reference(row['source'], plan, budget)
        source_plan = node['plan']
        if (original.field('id') != source_plan['id'] or
                original.field('module').field('kind') != source_plan['module']['kind'] or
                (source_plan['module']['kind'] == 'dependency' and
                 original.field('module').field('slot') != source_plan['module']['slot'])):
            _error(detail='actual current bind plan required')


def _note_observation(machine, frame, value, operand, token):
    _machine_class(machine, token)
    row, node = _current(machine, frame)
    if _ssa(machine, frame, node['operands'][0]) is not operand:
        _error(detail='actual observing operand required')
    row['observations'][id(value)] = (weakref.ref(value), weakref.ref(operand), row['epoch'])


def _note_entry(machine, caller, callee, continuation, entry, call, token):
    _machine_class(machine, token)
    row, node = _current(machine, caller)
    fields = _fact_fields(call, SourceOrdinaryCall)
    if fields['epoch'] is not row['epoch'] or fields.get('entry_committed', False):
        _error(detail='original source call entry required')
    api = _registry_api()
    if type(entry) is not api.EntryRef or entry.source is not row['source']:
        _error(detail='actual same-source entry required')
    frame = _FRAMES.get(id(callee))
    if frame is None or frame['frame']() is not callee:
        _error(detail='actual prepared callee required')
    row['entries'][id(continuation)] = dict(continuation=continuation, entry=weakref.ref(entry),
        caller=weakref.ref(caller), callee=weakref.ref(callee), call=call, returned=None)
    fields['entry_committed'] = True


def _returning(machine, frame, values, token):
    _machine_class(machine, token)
    row, node = _current(machine, frame)
    if node['op'] != 'return':
        _error(detail='actual return dispatcher required')
    expected = tuple(_ssa(machine, frame, identifier) for identifier in node['values'])
    if len(values) != len(expected) or any(v is not e for v, e in zip(values, expected)):
        _error(detail='actual result SSA relation')
    if frame.continuation is None:
        return
    entry = row['entries'].get(id(frame.continuation))
    if entry is None:
        return
    if entry['callee']() is not frame or entry['returned'] is not None:
        _error(detail='original callee return required')
    entry['returned'] = expected


def _seal_completed(machine, caller, continuation, values, token):
    _machine_class(machine, token)
    row = _machine(machine)
    pending = row['entries'].get(id(continuation))
    if pending is None:
        return None
    if (pending['continuation'] is not continuation or pending['caller']() is not caller or
            pending['returned'] is None or len(values) != len(pending['returned']) or
            any(v is not e for v, e in zip(values, pending['returned']))):
        _error(detail='actual sealed completion relation')
    entry = pending['entry']()
    if entry is None or row['pending_completion'] is not None:
        _error(detail='original live entry completion required')
    outcome = _fact(SourceEntryOutcome, machine=weakref.ref(machine), entry=weakref.ref(entry),
        source=row['source'], continuation=continuation, caller=weakref.ref(caller),
        result=pending['returned'], used=False, prepared=None, epoch=row['epoch'],
        caller_version=_FRAMES[id(caller)]['version'],
        caller_frontier=(caller.block, caller.position))
    row['pending_completion'] = outcome
    row['completed'][id(entry)] = weakref.ref(outcome)
    del row['entries'][id(continuation)]
    return outcome


def _source_entry_outcome(machine, entry, *, budget):
    row = _machine(machine)
    validate_source_machine(machine, source=row['source'], budget=budget)
    reference = row['completed'].get(id(entry))
    if reference is None or reference() is None:
        _error('SOURCE_REGISTRY_EVIDENCE_UNAVAILABLE', 'no actual completed outcome', 'unavailable')
    value = reference()
    return validate_source_entry_outcome(value, entry=entry, budget=budget)


def validate_source_entry_outcome(value, *, entry, budget):
    fields = _fact_fields(value, SourceEntryOutcome)
    if fields['entry']() is not entry or fields['used']:
        _error(detail='original unconsumed entry outcome required')
    machine = fields['machine']()
    row = _machine(machine)
    if row['pending_completion'] is not value:
        _error(detail='actual pending completion barrier required')
    _validate_completion_frontier(fields, row)
    validate_source_machine(machine, source=fields['source'], budget=budget)
    return value


def _validate_completion_frontier(fields, row):
    caller = fields['caller']()
    issued = _FRAMES.get(id(caller))
    if (issued is None or issued['frame']() is not caller or not issued['active'] or
            issued['values'] is not caller.values or issued['version'] != fields['caller_version'] or
            (caller.block, caller.position) != fields['caller_frontier'] or
            row['epoch'] is not fields['epoch'] or row['source'] is not fields['source'] or
            not row['frame_stack'] or row['frame_stack'][-1]() is not caller or
            row['stack'] is not row['machine']().stack or row['stack'][-1] is not caller):
        _error(detail='original normal completion frontier required')


def prepare_source_entry_commit(outcome, *, entry, budget):
    validate_source_entry_outcome(outcome, entry=entry, budget=budget)
    fields = _fact_fields(outcome, SourceEntryOutcome)
    prepared = fields['prepared']
    if prepared is not None and prepared() is not None:
        return prepared()
    budget.charge(work=8, edges=8, copied_bytes=256)
    commit = _fact(SourceEntryCommit, outcome=outcome, entry=weakref.ref(entry), lock=_ISSUER_LOCK,
                   used=False, fields=fields, machine=fields['machine'])
    fields['prepared'] = weakref.ref(commit)
    return commit


def source_entry_commit_lock(commit):
    return _fact_fields(commit, SourceEntryCommit)['lock']


def validate_source_entry_commit_locked(commit, *, entry):
    fields = _fact_fields(commit, SourceEntryCommit)
    outcome = fields['fields']
    machine = fields['machine']()
    row = _MACHINES.get(id(machine))
    if (fields['used'] or fields['entry']() is not entry or outcome['used'] or
            row is None or row['pending_completion'] is not fields['outcome']):
        _error(detail='normal completion replay/state')
    _validate_completion_frontier(outcome, row)


def consume_source_entry_commit_locked(commit):
    fields = _fact_fields(commit, SourceEntryCommit)
    outcome = fields['fields']
    # The registry calls the locked validation before either consumption. No
    # traversal, budget charging, guest callback or new logical state follows.
    fields['used'] = True
    outcome['used'] = True
    _MACHINES[id(fields['machine']())]['pending_completion'] = None


def _note_registration(machine, pointer, registration, reservation, kind, reference, token):
    _machine_class(machine, token)
    row = _machine(machine)
    if pointer.lineage is None:
        _error(detail='private legacy lineage required')
    row['legacy'][pointer.lineage] = dict(pointer=weakref.ref(pointer), registration=registration,
        reservation=weakref.ref(reservation), kind=kind, reference=reference)


def _source_legacy(machine, frame, value_id, *, budget):
    row, node = _current(machine, frame)
    if node['op'] != 'code_erase' or node['operands'][0] != value_id:
        _error(detail='actual current erase operand required')
    value = _ssa(machine, frame, value_id)
    typ = machine.types.get(value.type)
    if typ['kind'] != 'code_ptr':
        _error(detail='actual SSA CodePtr required')
    activation = _source_activation(machine, frame, budget=budget)
    pointer = value.data if value.state == 'concrete' else None
    invalid, reservation = None, None
    domain = 'code' if pointer is None else pointer.domain
    bits = None if pointer is None else pointer.address
    if pointer is not None and bits:
        origin = row['legacy'].get(pointer.lineage)
        if pointer.domain == 'label':
            invalid = 'label'
        elif pointer.domain != 'code':
            invalid = 'wrong_domain'
        elif origin is None:
            invalid = 'originless'
        else:
            original = origin['pointer']()
            registration = machine.code_pointers.get(bits)
            if (original is None or pointer != original or registration is not origin['registration']):
                invalid = 'originless'
            else:
                reservation = origin['reservation']()
                if reservation is None:
                    _error('SOURCE_REGISTRY_EVIDENCE_UNAVAILABLE', 'original reservation unavailable', 'unavailable')
    budget.charge(work=4, edges=8, copied_bytes=256)
    return _fact(LegacyCodeSource, machine=weakref.ref(machine), frame=weakref.ref(frame),
        value=weakref.ref(value), value_id=value_id, activation=activation, source=row['source'],
        state=value.state, bits=bits, domain=domain, reservation=reservation, invalid=invalid,
        epoch=row['epoch'], node=node)


def validate_legacy_code_source(value, *, activation, budget):
    fields = _fact_fields(value, LegacyCodeSource)
    source = source_activation_context(activation, budget=budget)
    validate_source_activation(fields['activation'], source=source, budget=budget)
    machine, frame = fields['machine'](), fields['frame']()
    row, node = _current(machine, frame)
    if (fields['activation'] is not activation or fields['epoch'] is not row['epoch'] or
            fields['node'] is not node or _ssa(machine, frame, fields['value_id']) is not fields['value']()):
        _error(detail='original current legacy SSA relation')
    return value


def legacy_code_activation(source, *, budget):
    fields = _fact_fields(source, LegacyCodeSource)
    validate_legacy_code_source(source, activation=fields['activation'], budget=budget)
    return fields['activation']


def legacy_code_details(source, *, activation, budget):
    validate_legacy_code_source(source, activation=activation, budget=budget)
    fields = _fact_fields(source, LegacyCodeSource)
    from types import MappingProxyType
    budget.charge(work=5, edges=5, copied_bytes=192)
    return MappingProxyType({key: fields[key] for key in ('state', 'bits', 'domain', 'reservation', 'invalid')})


def _call():
    module = sys.modules.get('_rax_smir_source_call_v1')
    path = ROOT / 'tools/smir-format/execution/candidate/source_call_projection.py'
    if (module is None or getattr(module, '__file__', None) is None or
            Path(module.__file__).resolve() != path or
            getattr(module, '_SOURCE_CALL_READY', False) is not True):
        raise RuntimeError('SOURCE_CALL_MODULE_IDENTITY')
    return module


def _error(code='SOURCE_REGISTRY_CONTEXT', detail='', kind='semantic'):
    if kind == 'semantic':
        _call()._error(code, detail)
    errors = sys.modules['_rax_smir_call_comparison_errors_v1']
    raise errors.CallComparisonError(kind, code, detail)


def _actual(context, token=None):
    cls = type(context)
    module = sys.modules.get(cls.__module__)
    path = ROOT / 'tools/smir-format/execution/candidate/context.py'
    if (module is None or getattr(module, '__file__', None) is None or
            Path(module.__file__).resolve() != path or getattr(module, 'RootContext', None) is not cls):
        _error(detail='actual RootContext required')
    if token is not None and token is not getattr(module, '_REGISTRY_VERIFICATION_KEY', None):
        _error(detail='private verification issuer required')
    return module


def _constructed(context, token):
    _actual(context, token)
    identity = id(context)

    def discard(reference):
        entry = _CONTEXTS.get(identity)
        if entry is not None and entry['context'] is reference:
            del _CONTEXTS[identity]

    # At most ten digests: no eager wire traversal, capture, or SourceData state.
    _CONTEXTS[identity] = dict(context=weakref.ref(context, discard),
        sections=context.sections, types=context.types, digests=tuple(context._root_hashes.items()),
        generation=object(), abi=None, execution=None)


def _receipt(context):
    _actual(context)
    receipt = _CONTEXTS.get(id(context))
    if (receipt is None or receipt['context']() is not context or
            receipt['sections'] is not context.sections or receipt['types'] is not context.types or
            type(context._root_hashes) is not dict or len(context._root_hashes) != len(receipt['digests']) or
            receipt['digests'] != tuple(context._root_hashes.items()) or
            context.abi is not context.sections.get(10)):
        _error(detail='original construction association')
    return receipt


def _invalidate(context, token, phase):
    _actual(context, token)
    receipt = _receipt(context)
    receipt['generation'] = object()
    receipt['execution'] = None
    if phase == 'abi':
        receipt['abi'] = None


def _verified_abi(context, token):
    _actual(context, token)
    receipt = _receipt(context)
    if context.abi_checked is not True:
        _error(detail='ABI success association')
    receipt['abi'] = weakref.ref(context.abi_graph)


def _verified_execution(context, token):
    _actual(context, token)
    receipt = _receipt(context)
    if (receipt['abi'] is None or receipt['abi']() is not context.abi_graph or
            context.abi_checked is not True):
        # Preserve legacy execution behavior, but never certify forged ABI state.
        return
    receipt['execution'] = weakref.ref(context.execution_checked)


def _proof(context):
    receipt = _receipt(context)
    if (context.abi_checked is not True or receipt['abi'] is None or
            receipt['abi']() is not getattr(context, 'abi_graph', None) or
            receipt['execution'] is None or receipt['execution']() is not context.execution_checked):
        _error('SOURCE_REGISTRY_EVIDENCE_UNAVAILABLE', 'genuine ABI and execution verification required',
               'unavailable')
    return receipt


@dataclass(frozen=True, slots=True, eq=False, init=False)
class _RegistryStamp:
    identity: object
    schema_digest: bytes
    root_digests: tuple

    def __init__(self, identity, schema_digest, root_digests):
        if hasattr(self, 'identity'):
            raise AttributeError('immutable registry stamp')
        for key, value in (('identity', identity), ('schema_digest', schema_digest),
                           ('root_digests', root_digests)):
            object.__setattr__(self, key, value)


@dataclass(frozen=True, slots=True, eq=False, init=False)
class RegistrySourceRecord:
    namespace: str
    original_reference: object
    record: object

    def __init__(self, namespace, original_reference, record):
        if hasattr(self, 'namespace'):
            raise AttributeError('immutable registry record')
        for key, value in (('namespace', namespace), ('original_reference', original_reference), ('record', record)):
            object.__setattr__(self, key, value)


class SourceRegistryContext:
    __slots__ = ('_context', '_projection', '_stamp', '_roots', '_budget', '_call_view',
                 '_receipt', '_generation', '__weakref__')

    def __new__(cls, token=None, *args):
        if token is not _TOKEN or cls is not SourceRegistryContext:
            _error(detail='no public registry view constructor')
        return object.__new__(cls)

    def __init__(self, token, context, projection, stamp, roots, budget, call_view, receipt):
        if hasattr(self, '_context'):
            _error(detail='registry view already initialized')
        for key, value in (('_context', context), ('_projection', projection), ('_stamp', stamp),
                           ('_roots', roots), ('_budget', budget), ('_call_view', call_view),
                           ('_receipt', receipt), ('_generation', receipt['generation'])):
            object.__setattr__(self, key, value)

    def __setattr__(self, name, value):
        raise AttributeError('immutable registry context')

    def __delattr__(self, name):
        raise AttributeError('immutable registry context')

    def call_context(self, *, budget):
        validate_source_registry_context(self, budget=budget)
        value = _call().validate_source_call_context(self._call_view, budget=budget)
        validate_source_registry_context(self, budget=budget)
        return value

    def root(self, section, *, budget):
        validate_source_registry_context(self, budget=budget)
        budget.work(1)
        if type(section) is not int or section not in _PUBLIC_ROOTS:
            _error('SOURCE_REGISTRY_ROOT', 'root namespace')
        value = _call()._wrap(self._roots[section], self._projection.source_api(), budget)
        validate_source_registry_context(self, budget=budget)
        return value

    def record(self, namespace, reference, *, budget):
        validate_source_registry_context(self, budget=budget)
        if type(namespace) is not str:
            _error('SOURCE_REGISTRY_NAMESPACE')
        budget.work(len(namespace) + 1)
        if namespace not in _TABLES and namespace != 'declaration':
            _error('SOURCE_REGISTRY_NAMESPACE')
        # This private API6 parser preserves original qrefs; translate only its
        # expected malformed-reference diagnostic, retaining the shared class.
        try:
            original, kind, identifier, slot = _call()._reference(self, reference, budget)
        except sys.modules['_rax_smir_call_comparison_errors_v1'].CallComparisonError as error:
            if error.code != 'ABI_CC_ENTITY_REFERENCE':
                raise
            _error('SOURCE_REGISTRY_REFERENCE')
        if namespace == 'declaration':
            if kind != 'dependency':
                _error('SOURCE_REGISTRY_NAMESPACE')
            manifest = self._roots[2].field('manifest')
            dependency = _lookup(manifest.field('dependencies'), slot, budget, 'slot')
            rows = dependency.field('declarations')
        else:
            if kind != 'self':
                _error('SOURCE_REGISTRY_NAMESPACE')
            section, table = _TABLES[namespace]
            owner = self._roots[section]
            if namespace == 'export':
                owner = owner.field('manifest')
            rows = owner.field(table)
        selected = _lookup(rows, identifier, budget)
        api = self._projection.source_api()
        budget.charge(work=1, edges=3, copied_bytes=64)
        value = RegistrySourceRecord(namespace, _call()._wrap(original, api, budget),
                                     _call()._wrap(selected, api, budget))
        validate_source_registry_context(self, budget=budget)
        return value


def _lookup(rows, identifier, budget, key='id'):
    budget.charge(work=len(rows), edges=len(rows))
    for row in rows:
        if row.field(key) == identifier:
            return row
    _error('SOURCE_REGISTRY_REFERENCE')


def _capture_check(context, projection, schema, budget, stamp=None, capture=False):
    if type(context.sections) is not dict or len(context.sections) != 10 or set(context.sections) != set(range(1, 11)):
        _error('SOURCE_REGISTRY_ROOT', 'all ten actual roots required')
    roots, digests = projection._roots(context, schema, budget, capture)
    if digests != _receipt(context)['digests'] or (stamp is not None and digests != stamp.root_digests):
        projection._fail('context_snapshot_changed')
    # Verified contains independent copies: verify their current actual content,
    # not merely the public result object's identity or its original flag.
    verified = context.execution_checked
    for section, value in ((1, verified.types_root), (3, verified.functions_root),
                            (8, verified.exceptions_root)):
        walk = projection._WireCapture(schema, budget, False)
        walk.visit(projection.ROOT_NAMES[section], value)
        if projection._digest(walk.hasher, budget) != dict(digests)[section]:
            _error(detail='verified execution snapshot changed')
    return roots, digests


def _issue(context, *, budget):
    _receipt(context)  # Authenticate original construction before inspecting roots.
    functions = context.sections.get(3)
    if type(functions) is not dict or type(functions.get('payload_revision')) is not int:
        _error(detail='actual function root required')
    if functions['payload_revision'] == 3:
        _error('V3_SOURCE_SEMANTIC_ADMISSION_UNAVAILABLE', kind='unavailable')
    receipt = _proof(context)
    generation = receipt['generation']
    projection = _call()._context(context)
    budget = projection._budget(budget)
    budget.work(16)
    cache_key = (id(context), id(budget))
    with _PUBLICATION_LOCK:
        cached = _CACHE.get(cache_key)
        cached_view = None if cached is None else cached()
    if cached_view is not None:
        return validate_source_registry_context(cached_view, budget=budget)
    schema, digest = projection._schema(budget)
    roots, digests = _capture_check(context, projection, schema, budget, capture=True)
    budget.charge(work=16, edges=16, copied_bytes=1024)
    call_view = context.source_call_context(budget=budget)
    _call().validate_source_call_context(call_view, budget=budget)
    if _proof(context) is not receipt or receipt['generation'] is not generation:
        _error(detail='verification changed during capture')
    stamp = _RegistryStamp(object(), digest, digests)
    view = SourceRegistryContext(_TOKEN, context, projection, stamp, roots, budget, call_view, receipt)
    identity = id(view)

    def discard(reference):
        with _PUBLICATION_LOCK:
            issued = _ISSUED.get(identity)
            if issued is not None and issued[0] is reference:
                del _ISSUED[identity]
            if _CACHE.get(cache_key) is reference:
                del _CACHE[cache_key]

    reference = weakref.ref(view, discard)
    with _PUBLICATION_LOCK:
        _ISSUED[identity] = (reference, weakref.ref(context), projection, stamp, roots, budget,
                             weakref.ref(call_view), receipt, receipt['generation'])
    # Validate the fully formed candidate before making it discoverable in cache.
    try:
        validate_source_registry_context(view, budget=budget)
        budget.work(4)
        # Capture and validation spend their original cumulative budget outside
        # this metadata lock. Only one fully validated live identity is published.
        with _PUBLICATION_LOCK:
            cached = _CACHE.get(cache_key)
            winner = None if cached is None else cached()
            if winner is None:
                _CACHE[cache_key] = reference
                winner = view
            elif _ISSUED.get(identity, (None,))[0] is reference:
                del _ISSUED[identity]
    except BaseException:
        with _PUBLICATION_LOCK:
            if (_ISSUED.get(identity, (None,))[0] is reference and
                    _CACHE.get(cache_key) is not reference):
                del _ISSUED[identity]
        raise
    if winner is view:
        return view
    return validate_source_registry_context(winner, budget=budget)


def validate_source_registry_context(value, *, budget):
    if type(value) is not SourceRegistryContext:
        _error(detail='canonical issued registry context required')
    with _PUBLICATION_LOCK:
        entry = _ISSUED.get(id(value))
    if entry is None or entry[0]() is not value:
        _error(detail='unissued registry context')
    if (entry[1]() is not value._context or entry[2] is not value._projection or
            entry[3] is not value._stamp or entry[4] is not value._roots or
            entry[5] is not value._budget or entry[6]() is not value._call_view or
            entry[7] is not value._receipt or entry[8] is not value._generation):
        _error(detail='original registry association')
    projection = value._projection
    budget = projection._budget(budget)
    if budget is not value._budget:
        _error(detail='registry budget association')
    receipt = _proof(value._context)
    if receipt is not value._receipt or receipt['generation'] is not value._generation:
        _error(detail='verification epoch changed')
    if _call()._context(value._context) is not projection:
        _error(detail='capture implementation changed')
    budget.work(16)
    schema, digest = projection._schema(budget)
    if digest != value._stamp.schema_digest:
        projection._fail('SOURCE_DATA_SCHEMA')
    _capture_check(value._context, projection, schema, budget, value._stamp)
    _call().validate_source_call_context(value._call_view, budget=budget)
    if _proof(value._context) is not receipt or receipt['generation'] is not value._generation:
        _error(detail='verification changed during validation')
    return value


_SOURCE_REGISTRY_READY = True
