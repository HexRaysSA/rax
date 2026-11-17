"""Admitted coherent reference execution, with explicit effects and continuations.

This is not connected to the RAX engine, JIT or OS personalities. Registry-backed
imports are explicit test adapters; no host function pointer is ever executed.
"""
from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import weakref
from threading import Lock

from common import Reject, require
from candidate.memory import GuestFault, Memory
from candidate.operations import optional
from candidate import pure
from candidate.type_system import key, ref
from candidate.values import Handle, Pointer, Value, component, freeze, from_raw, materialize, raw_bits, well_defined, validate
from candidate.verify import Verified, verify

_SOURCE_MACHINE_ISSUER = object()
_UNBOUND_FLOW_ISSUER = object()


def _source_api():
    from candidate.context import source_registry_api
    return source_registry_api()


@dataclass(frozen=True)
class Raised:
    exception: object


@dataclass(frozen=True)
class Pending:
    ticket: int


@dataclass(frozen=True)
class Terminated:
    """Trusted owner adapter's process-action request, never a guest value."""
    reason: str


@dataclass
class Frame:
    function: dict
    block: int
    values: dict
    activation: int
    position: int = -1
    predecessor: int | None = None
    continuation: dict | None = None
    progress: dict | None = None


class Machine:
    def __init__(self, admitted, imports=None, symbols=None, environment=None, max_bytes=1024 * 1024,
                 diagnostic_fp_traps=(), action_adapters=None, exception_matcher=None, external_calls=None):
        require(isinstance(admitted, Verified), 'reference_admission')
        # Reverify snapshots: caller mutation of a previous admission grants no
        # unchecked reference execution capability.
        self.admitted = verify(admitted.types_root, admitted.functions_root, admitted.exceptions_root,
                               admitted.dependencies, {k: v for k, v in admitted.types.items.items() if k[0] != 'self'})
        self.types, self.dependencies = self.admitted.types, self.admitted.dependencies
        from candidate.bindings import validate as validate_import
        self.import_contracts = {identity: deepcopy(validate_import(binding, self.types, self.dependencies))
                                 for identity, binding in self.dependencies.imports.items()
                                 if binding['kind'] == 'internal'}
        self.functions = {function['id']: function for function in self.admitted.functions_root['functions']}
        self.regions = {item['function']: {region['id']: region for region in item['regions']}
                        for item in self.admitted.exceptions_root['functions']}
        self.actions = {item['function']: {action['id']: action for action in item['actions']}
                        for item in self.admitted.exceptions_root['functions']}
        self.memory = Memory(self.types, self.dependencies, max_bytes)
        self.imports, self.symbols = imports or {}, symbols or {}
        self.external_calls = external_calls or {}
        self.environment = deepcopy(environment or {'rounding': 'nearest_even', 'flags': [], 'traps': []})
        require(set(self.environment) == {'rounding', 'flags', 'traps'}
                and self.environment['rounding'] in {'nearest_even', 'toward_zero', 'upward', 'downward'}
                and self.environment['traps'] == [], 'fenv_state')
        self.diagnostic_fp_traps = list(diagnostic_fp_traps)
        from candidate.operations import FLAGS, ENV_FLAGS
        require(set(self.diagnostic_fp_traps) <= FLAGS and self.environment['flags'] == sorted(set(self.environment['flags']))
                and set(self.environment['flags']) <= ENV_FLAGS, 'fenv_mask')
        self.stack, self.activation, self.steps = [], 0, 0
        self.pending, self.finished = None, None
        self.tickets, self.code_pointers, self.exposed_code = {}, {}, set()
        self.effect_sequence, self.next_code = 0, 2
        self.labels = {}
        self.label_entries, self.code_entries = {}, {}
        self.handles, self.handle_sequence = {}, 0
        self.action_adapters = action_adapters or {}
        self.exception_matcher = exception_matcher or (lambda payload, nominal: payload['nominal'] == key(nominal))
        self.selected_handlers = {}
        self.catch_contexts = {}
        self.catch_parents = {}
        self.active_journals, self.unwind_state = {}, None
        self.search_log = []
        self._source_runtime = None
        self._unbound_flow = None
        self._flow_reserved = self._flow_event = None
        self._flow_actual_outputs = self._flow_actual_inputs = None
        self._flow_actual_phi = False
        self._flow_computing = False
        self._flow_terminal_error = None
        if type(self) is Machine:
            _source_api()._note_machine(self, admitted, _SOURCE_MACHINE_ISSUER)

    def attach_unbound_value_flow(self, runtime, *, budget):
        from source_value_flow.dynamic import UnboundFlowRuntime
        require(type(runtime) is UnboundFlowRuntime and self._unbound_flow is None,
                'unbound_flow_attachment')
        runtime._attach(self, issuer=_UNBOUND_FLOW_ISSUER, budget=budget)
        self._unbound_flow = runtime

    def _note_unbound_selection(self, original, observed, index, token):
        require(token is pure._UNBOUND_SELECT_ISSUER and self._flow_reserved is not None,
                'unbound_flow_selection_issuer')
        flow = self._unbound_flow
        flow._note_scalar_selection(self._flow_reserved, original, observed, index,
                                   issuer=_UNBOUND_FLOW_ISSUER, budget=flow.budget)

    def _complete_unbound_outcome(self):
        flow = self._unbound_flow
        outputs = (tuple(self._flow_actual_outputs.values()) if self._flow_actual_phi
                   else self._flow_actual_outputs)
        self._flow_event = flow._finish(self._flow_reserved, self._flow_actual_inputs,
            outputs, self.stack[-1].predecessor if self._flow_actual_phi else None,
            issuer=_UNBOUND_FLOW_ISSUER, budget=flow.budget)
        self._flow_actual_outputs = self._flow_actual_inputs = None
        self._flow_actual_phi = False
        return flow._park(self._flow_event)

    def _publish_unbound_completed(self):
        flow, event = self._unbound_flow, self._flow_event
        row = flow._event(event)
        frame = row['frame']
        self.bind(frame, row['definitions'], row['outputs'])
        frame.position = 0 if row['kind'] == 'phi_batch' else frame.position + 1
        self._flow_reserved = self._flow_event = None

    def attach_source_registry(self, registry, source, *, budget):
        require(self._unbound_flow is None, 'unbound_flow_source_registry_unavailable')
        api = _source_api()
        require(self._source_runtime is None and not self.stack and self.finished is None,
                'reference_source_attachment_stage')
        api.validate_source_machine(self, source=source, budget=budget)
        runtime = api._registry_api()
        require(type(registry) is runtime.CodeRegistry, 'reference_source_registry_identity')
        attachment = registry.attach_machine(self, source, budget=budget)
        owner = registry.register_source(source, budget=budget)
        deployment = registry.prepare_deployment((owner,), budget=budget)
        api._associate_machine(self, source, registry, attachment, budget, _SOURCE_MACHINE_ISSUER)
        self._source_runtime = dict(registry=registry, source=source, budget=budget,
                                    attachment=attachment, owner=owner, activations={}, lanes=[], roots=[],
                                    value_lanes={}, deployment=deployment, pending_completion=None,
                                    entries=[], final_return=None, root_cursor=0, reservations=[])
        self._source_runtime['execution_lock'] = Lock()

    def source_activation(self, frame, *, budget):
        return _source_api()._source_activation(self, frame, budget=budget)

    def source_call(self, frame, *, budget):
        return _source_api()._source_call(self, frame, budget=budget)

    def source_entry_outcome(self, entry, *, budget):
        return _source_api()._source_entry_outcome(self, entry, budget=budget)

    def source_legacy(self, frame, value_id, *, budget):
        return _source_api()._source_legacy(self, frame, value_id, budget=budget)

    def _finish_source_roots(self):
        runtime = self._source_runtime
        while runtime['root_cursor'] < len(runtime['roots']):
            root = runtime['roots'][runtime['root_cursor']]
            runtime['registry'].release(root, budget=runtime['budget'])
            runtime['root_cursor'] += 1
        self.finished = runtime['final_return']
        runtime['final_return'] = None

    def _source_actor(self, frame):
        runtime = self._source_runtime
        require(runtime is not None, 'reference_code_address_unavailable')
        source = self.source_activation(frame, budget=runtime['budget'])
        actor = runtime['activations'].get(id(frame))
        if actor is None:
            actor = runtime['registry'].attach_activation(source, budget=runtime['budget'])
            runtime['activations'][id(frame)] = actor
        return actor

    def _source_value(self, frame, output, pending):
        runtime = self._source_runtime
        registry, budget = runtime['registry'], runtime['budget']
        fields = _source_api()._pending_result_fields(self, pending, _SOURCE_MACHINE_ISSUER)
        if fields['value'] is not None:
            return fields['value']
        if fields['borrowed'] is None:
            holder = registry.activation_holder(self._source_actor(frame), budget=budget)
            root, borrowed = registry.adopt_lane(fields['lane'], holder=holder, budget=budget)
            fields['root'], fields['borrowed'] = root, borrowed
            runtime['roots'].append(root)
            runtime['lanes'].append(borrowed)
        borrowed = fields['borrowed']
        if borrowed.state == 'poison':
            value = Value(output, 'poison')
        elif borrowed.state == 'undef':
            value = Value(output, 'undef')
        else:
            target = borrowed.target
            kind = self.types.get(output)['kind']
            permit = borrowed.permit if kind == 'code_ptr' else None
            value = Value(output, 'concrete', Pointer(borrowed.bits, target,
                target.generation if target is not None else 0,
                'code' if kind == 'code_ptr' else 'code_address', None, permit, borrowed))
        fields['value'] = value
        _source_api()._machine(self)['value_lanes'][id(value)] = (weakref.ref(value), weakref.ref(borrowed))
        return value

    def source_code_operation(self, frame, operation, arguments):
        runtime = self._source_runtime
        require(runtime is not None, 'reference_code_address_unavailable')
        output = operation['results'][0]['type']
        require(self.types.get(output)['kind'] != 'vector', 'reference_code_address_group_unavailable')
        registry, budget = runtime['registry'], runtime['budget']
        original = arguments[0]
        pending = _source_api()._begin_result(self, frame, operation, output, _SOURCE_MACHINE_ISSUER)
        fields = _source_api()._pending_result_fields(self, pending, _SOURCE_MACHINE_ISSUER)
        if fields['lane'] is not None:
            return [self._source_value(frame, output, pending)]
        authority = getattr(original.data, 'authority', None)
        if authority is None:
            old = _source_api()._machine(self)['value_lanes'].get(id(original))
            authority = old[1]() if old is not None and old[0]() is original else None
        if operation['op'] == 'code_bind':
            if authority is None:
                if original.state == 'poison':
                    authority = registry.poison(budget=budget)
                elif original.state == 'undef':
                    authority = registry.undef(budget=budget)
                else:
                    authority = registry.originless(original.data.address, budget=budget)
                _source_api()._note_observation(self, frame, authority, original, _SOURCE_MACHINE_ISSUER)
            bound = registry.bind(authority, runtime['source'].call_context(budget=budget), operation['plan'],
                activation=self._source_actor(frame), budget=budget)
            fields['lane'] = bound
            return [self._source_value(frame, output, pending)]
        if authority is None:
            legacy = self.source_legacy(frame, operation['operands'][0], budget=budget)
            authority = registry.attach_legacy(legacy, budget=budget)
        erased = registry.erase(authority, activation=self._source_actor(frame), budget=budget)
        fields['lane'] = erased
        return [self._source_value(frame, output, pending)]

    def fp_commit(self, mode, raised):
        if mode is None or mode['environment'] == 'default' or mode['exceptions'] == 'ignore':
            return
        self.environment['flags'] = sorted(set(self.environment['flags']) | raised)
        enabled = set(self.diagnostic_fp_traps) & raised
        if enabled:
            priority = ['invalid', 'divide_by_zero', 'overflow', 'underflow', 'inexact']
            raise GuestFault('fp_' + next(flag for flag in priority if flag in enabled))

    def activate(self, function, arguments, continuation=None):
        signature = self.types.get(function['signature'])
        require(len(arguments) == len(function['params']), 'runtime_call_arity')
        for argument, parameter, noundef in zip(arguments, function['params'], signature['param_noundef']):
            validate(self.types, argument, self.handles)
            require(self.types.equal(argument.type, parameter['type']), 'runtime_argument_type')
            if noundef and not well_defined(self.types, argument):
                raise GuestFault('ub_noundef_argument', True)
        if self._unbound_flow is None:
            self.activation += 1
            result = Frame(function, function['entry'], {p['id']: v for p, v in zip(function['params'], arguments)},
                           self.activation, continuation=continuation)
        else:
            flow = self._unbound_flow
            reserved = flow._prepare_entry(self, function, arguments,
                                          issuer=_UNBOUND_FLOW_ISSUER, budget=flow.budget)
            result = Frame(function, function['entry'], {p['id']: v for p, v in zip(function['params'], arguments)},
                           self.activation + 1, continuation=continuation)
            event = flow._finish_entry(reserved, self, result,
                                       issuer=_UNBOUND_FLOW_ISSUER, budget=flow.budget)
            flow._publish_entry(self, result, event, issuer=_UNBOUND_FLOW_ISSUER, budget=flow.budget)
        if type(self) is Machine:
            _source_api()._note_frame(self, result, _SOURCE_MACHINE_ISSUER)
        return result

    def start(self, function, arguments):
        require(not self.stack and self.finished is None and function in self.functions, 'runtime_entry')
        self.check_bindings()
        self.stack.append(self.activate(self.functions[function], arguments))
        if self._source_runtime is not None:
            _source_api()._enter_frame(self, self.stack[-1], _SOURCE_MACHINE_ISSUER)

    def check_bindings(self):
        for function in self.functions.values():
            for block in function['blocks']:
                for node in block['ops'] + [block['term']]:
                    if self._source_runtime is not None:
                        require(node['op'] not in {'tailcall', 'throw', 'rethrow', 'resume', 'cleanup_return',
                                                   'landingpad', 'catch_begin', 'catch_end', 'setjmp', 'longjmp'},
                                'reference_source_control_unavailable',
                                'actual source cleanup, nonlocal transfer and unwind issuers are unavailable')
                        if node['op'] in {'code_bind', 'code_erase'}:
                            require(self.types.get(node['results'][0]['type'])['kind'] != 'vector',
                                    'reference_code_address_group_unavailable')
                    require(self._source_runtime is not None or node['op'] not in {'code_bind', 'code_erase'},
                            'reference_code_address_unavailable', 'actual registry producer required')
                    if node['op'] in {'call', 'invoke', 'tailcall'}:
                        require(self._source_runtime is not None or optional(node['source_plan']) is None, 'reference_source_call_unavailable',
                                'actual SourceOrdinaryCall producer required')
                    for name in ['target', 'helper']:
                        target = node.get(name)
                        if not isinstance(target, dict) or 'kind' not in target:
                            continue
                        if target['kind'] == 'import':
                            require(key(target['import']) in self.imports, 'reference_unbound_import')
                        elif target['kind'] == 'direct' and target['function']['module']['kind'] != 'self':
                            require(key(target['function']) in self.external_calls, 'reference_unbound_dependency')
                    if node['op'] == 'address_of':
                        require(self._source_runtime is not None or self.types.get(node['results'][0]['type'])['kind'] != 'code_address',
                                'reference_code_address_unavailable', 'actual selected address issuer required')
                        if self.types.get(node['results'][0]['type'])['kind'] != 'code_address':
                            require(key(node['symbol']) in self.symbols, 'reference_unbound_symbol')
                    if node['op'] == 'tailcall':
                        require(node['target']['kind'] == 'direct' and node['target']['function']['module']['kind'] == 'self',
                                'reference_tail_target', 'this reference supports local direct tail targets only')
        for function_id, regions in self.regions.items():
            for region in regions.values():
                action_ids = list(region['exit_actions'])
                for handler in region['handlers']:
                    action_ids += handler['cleanup_actions']
                    if handler['catch_copy'] is not None:
                        action_ids.append(optional(handler['catch_copy']))
                require(all(key(self.actions[function_id][action]['recipe']) in self.action_adapters
                            for action in action_ids), 'reference_unbound_cleanup')

    def branch(self, frame, target):
        frame.predecessor, frame.block, frame.position = frame.block, target, -1

    def bind(self, frame, declarations, values):
        require(len(declarations) == len(values), 'runtime_result_arity')
        require(all(isinstance(value, Value) and self.types.equal(declaration['type'], value.type)
                    for declaration, value in zip(declarations, values)), 'runtime_result_type')
        for value in values:
            validate(self.types, value, self.handles)
        if self._unbound_flow is None:
            frame.values.update({declaration['id']: value for declaration, value in zip(declarations, values)})
        else:
            flow = self._unbound_flow
            flow._publish(self, frame, self._flow_event, issuer=_UNBOUND_FLOW_ISSUER, budget=flow.budget)
        if type(self) is Machine:
            _source_api()._note_values(self, frame, tuple(d['id'] for d in declarations), values,
                                       _SOURCE_MACHINE_ISSUER)

    def pointer(self, value):
        value = materialize(self.types, value)
        if value.state != 'concrete' or not isinstance(value.data, Pointer):
            raise GuestFault('ub_pointer', True)
        return value.data

    def call(self, frame, target, operands, continuation, extra_arguments=()):
        arguments = [frame.values[value] for value in operands]
        arguments.extend(extra_arguments)
        signature = self.types.get(target['signature'])
        require(len(arguments) == len(signature['params']), 'runtime_call_arity')
        for value, noundef in zip(arguments, signature['param_noundef']):
            if noundef and not well_defined(self.types, value):
                raise GuestFault('ub_noundef_argument', True)
        if self._source_runtime is not None:
            row, node = _source_api()._current(self, frame)
            if node['op'] in {'call', 'invoke', 'tailcall'} and node['source_plan'] is not None:
                require(target['kind'] == 'indirect' and node['op'] != 'tailcall',
                        'reference_source_entry_unavailable', 'this actual slice supports indirect call/invoke normal completion')
                pointer = self.pointer(frame.values[target['value']])
                lane = pointer.authority
                registry_api = _source_api()._registry_api()
                if pointer.address == 0 or pointer.domain != 'code' or type(lane) is not registry_api.BoundLane:
                    raise GuestFault('code_token_invalid')
                selected = lane.target
                if selected is None:
                    raise GuestFault('code_token_invalid')
                runtime = self._source_runtime
                require(selected.source is runtime['source'], 'reference_source_entry_unavailable',
                        'cross-module actual dispatch is unavailable')
                reference = selected.function
                require(reference['module']['kind'] == 'self', 'reference_source_entry_unavailable')
                function = self.functions[reference['id']]
                require(self.types.equal(function['signature'], target['signature']), 'code_token_signature')
                runtime['budget'].charge(work=16, edges=16, copied_bytes=1024)
                call = self.source_call(frame, budget=runtime['budget'])
                actor = self._source_actor(frame)
                child = self.activate(function, arguments, continuation)
                entry = runtime['registry'].entry(lane, call, activation=actor, budget=runtime['budget'])
                require(entry.target is selected, 'reference_source_entry_identity')
                _source_api()._note_entry(self, frame, child, continuation, entry, call, _SOURCE_MACHINE_ISSUER)
                runtime['entries'].append(entry)
                self.stack.append(child)
                _source_api()._enter_frame(self, child, _SOURCE_MACHINE_ISSUER)
                return
        if target['kind'] == 'indirect':
            pointer = self.pointer(frame.values[target['value']])
            if self._source_runtime is not None and pointer.authority is not None:
                raise Reject('reference_source_entry_unavailable', 'bound generic entry has no actual source C')
            if pointer.domain != 'code' or pointer.address == 0 or pointer.address & 1 or pointer.address not in self.code_pointers:
                raise GuestFault('code_token_invalid')
            admitted_pointer, direct = self.code_pointers[pointer.address]
            if pointer != admitted_pointer:
                raise GuestFault('code_token_stale')
            if not self.types.equal(direct['signature'], target['signature']):
                raise GuestFault('code_token_signature')
            target = direct
        if target['kind'] == 'direct':
            if target['function']['module']['kind'] != 'self':
                identity = key(target['function'])
                require(identity in self.external_calls, 'reference_unbound_dependency')
                result = self.external_calls[identity](self, arguments)
                if isinstance(result, Raised):
                    require(not continuation.get('no_guest_throw', False), 'reference_nothrow_helper')
                    self.unwind(result.exception, continuation)
                else:
                    self.complete(frame, continuation, result, signature)
                return
            function = self.functions[target['function']['id']]
            self.stack.append(self.activate(function, arguments, continuation))
            if self._source_runtime is not None:
                _source_api()._enter_frame(self, self.stack[-1], _SOURCE_MACHINE_ISSUER)
            return
        identity = key(target['import'])
        require(identity in self.imports, 'reference_import_adapter_missing', str(identity))
        import_contract = self.import_contracts.get(identity, {})
        completion = import_contract.get('completion', 'returns')
        if completion != 'returns':
            continuation['completion'] = completion
        if completion != 'returns' or 'terminate' in import_contract.get('traps', []):
            continuation['terminal_allowed'] = True
        if self.dependencies.imports[identity]['kind'] == 'host':
            prepared = []
            for argument in arguments:
                if self.types.get(argument.type)['kind'] == 'raw' and argument.state == 'concrete' and argument.data.origins:
                    raise GuestFault('host_pointer_origin')
                prepared.append(freeze(self.types, argument))
            arguments = prepared
            continuation['host'] = True
            continuation['no_guest_throw'] = True
        self.effect_sequence += 1
        require(self.effect_sequence < 2**64, 'effect_ticket_exhausted')
        site = (frame.activation, frame.block, frame.position, self.effect_sequence)
        require(site not in self.tickets, 'effect_replay')
        self.tickets[site] = 'started'
        result = self.imports[identity](self, arguments)
        if isinstance(result, Pending):
            require(result.ticket > 0 and self.pending is None, 'effect_pending')
            self.pending = (result.ticket, frame, continuation, site, signature)
            self.tickets[site] = 'pending'
        elif isinstance(result, Terminated):
            require(continuation.get('terminal_allowed', False), 'reference_terminal_helper')
            self.terminate(result)
            self.tickets[site] = 'terminal'
        elif isinstance(result, Raised):
            require(not continuation.get('no_guest_throw', False), 'reference_nothrow_helper')
            self.tickets[site] = 'raised'
            self.unwind(result.exception, continuation)
        else:
            self.tickets[site] = 'completed'
            self.complete(frame, continuation, result, signature)

    def complete(self, frame, continuation, values, signature):
        require(continuation.get('completion', 'returns') == 'returns', 'reference_helper_completion',
                'nonreturning helper cannot publish ordinary results or a normal continuation')
        require(not continuation.get('no_normal_return', False), 'reference_nonlocal_return',
                'valid nonlocal execution must restore an admitted checkpoint, never advance this operation')
        require(type(values) is list and len(values) == len(signature['results']), 'runtime_import_results')
        for value, typ, noundef in zip(values, signature['results'], signature['result_noundef']):
            require(isinstance(value, Value) and self.types.equal(value.type, typ), 'runtime_result_type')
            if noundef and not well_defined(self.types, value):
                raise GuestFault('ub_noundef_result', True)
            if continuation.get('host', False):
                require(value.state == 'concrete' and (self.types.get(typ)['kind'] != 'raw'
                        or not (value.data.origins or value.data.poison or value.data.undef)), 'host_callback_result')
        self.bind(frame, continuation['results'], values)
        post = continuation.get('post')
        if post == 'catch_begin':
            self.catch_contexts[frame.activation]['entered'] = True
        elif post == 'catch_end':
            parents = self.catch_parents.get(frame.activation, [])
            if parents:
                self.catch_contexts[frame.activation] = parents.pop()
                self.selected_handlers[frame.activation] = self.catch_contexts[frame.activation]['handler']['id']
            else:
                self.catch_contexts.pop(frame.activation, None)
                self.selected_handlers.pop(frame.activation, None)
        if continuation['normal'] is None:
            frame.position += 1
        else:
            self.branch(frame, continuation['normal'])
        if self._source_runtime is not None:
            outcome = _source_api()._seal_completed(self, frame, continuation, values, _SOURCE_MACHINE_ISSUER)
            if outcome is not None:
                entry = _source_api()._fact_fields(outcome, _source_api().SourceEntryOutcome)['entry']()
                self._source_runtime['pending_completion'] = (entry, outcome)

    def terminate(self, outcome):
        from candidate.wire import TOKEN
        require(isinstance(outcome, Terminated) and type(outcome.reason) is str
                and TOKEN.fullmatch(outcome.reason), 'reference_terminal_outcome')
        self.finished = {'kind': 'terminate', 'reason': outcome.reason}

    def resume(self, ticket, values=None, exception=None, terminal=None):
        require(self.pending is not None and self.pending[0] == ticket, 'effect_resume_ticket')
        if self.unwind_state is not None and self.unwind_state['waiting'] == ticket:
            require(sum(item is not None for item in [values, exception, terminal]) == 1, 'cleanup_resume_outcome')
            if terminal is not None:
                self.terminate(terminal)
                self.pending = None
                return
            self.pending = None
            if exception is not None:
                self.finished = {'kind': 'terminate', 'reason': 'cleanup_throws'}
                return
            self.finish_action(values)
            self.drive_unwind()
            return
        _, frame, continuation, site, signature = self.pending
        require(sum(item is not None for item in [values, exception, terminal]) == 1, 'effect_resume_outcome')
        require(exception is None or not continuation.get('no_guest_throw', False), 'reference_nothrow_helper')
        if terminal is not None:
            require(continuation.get('terminal_allowed', False), 'reference_terminal_helper')
            self.terminate(terminal)
            self.pending = None
            self.tickets[site] = 'terminal'
            return
        self.pending = None
        if exception is not None:
            self.tickets[site] = 'raised'
            self.unwind(exception, continuation)
        else:
            self.tickets[site] = 'completed'
            self.complete(frame, continuation, values, signature)

    def unwind(self, exception, immediate=None):
        require(self._source_runtime is None, 'reference_source_unwind_unavailable',
                'actual source entry cleanup and exceptional outcome issuer are unavailable')
        require(isinstance(exception, Value) and self.types.get(exception.type)['kind'] == 'exception',
                'runtime_exception_lease')
        if exception.state != 'concrete':
            raise GuestFault('ub_exception_handle', True)
        validate(self.types, exception, self.handles)
        if immediate is not None and immediate.get('nounwind', False):
            raise GuestFault('ub_nounwind', True)
        if self.unwind_state is not None:
            self.finished = {'kind': 'terminate', 'reason': 'cleanup_throws'}
            return
        payload = self.handles[exception.data.identity]['payload']
        sites = []
        if immediate is not None and immediate['unwind'] is not None:
            sites.append((self.stack[-1], immediate, None))
        for index in range(len(self.stack) - 1, 0, -1):
            escaped = self.stack[index]
            sites.append((self.stack[index - 1], escaped.continuation, escaped))
        actions, search = [], []
        selected = None
        for frame, continuation, escaped in sites:
            if escaped is not None and (escaped.function['escape'] in {'terminate', 'nothrow'}
                                        or (continuation is not None and continuation.get('nounwind', False))):
                undefined = escaped.function['escape'] == 'nothrow' or continuation.get('nounwind', False)
                self.finished = {'kind': 'language_ub' if undefined else 'terminate',
                                 'reason': 'ub_nounwind' if undefined else 'terminate'}
                self.search_log.append(tuple(search))
                return
            if continuation is None or continuation['unwind'] is None:
                continue
            current = continuation['region']
            while current is not None:
                region = self.regions[frame.function['id']][current]
                search.append((frame.activation, current))
                handler = next((handler for handler in region['handlers'] if handler['kind'] == 'catch_all'
                                or self.exception_matcher(payload, optional(handler['nominal']))), None)
                if handler is not None:
                    actions += [(frame, action) for action in handler['cleanup_actions']]
                    if handler['catch_copy'] is not None:
                        actions.append((frame, optional(handler['catch_copy'])))
                    selected = frame, continuation, handler
                    break
                if region['escape'] == 'terminate':
                    self.finished = {'kind': 'terminate', 'reason': 'noexcept_region'}
                    self.search_log.append(tuple(search))
                    return
                actions += [(frame, action) for action in region['exit_actions']]
                current = optional(region['parent'])
            if selected is not None:
                break
        self.search_log.append(tuple(search))
        if selected is None:
            escape = self.stack[0].function['escape']
            self.finished = {'kind': 'language_ub' if escape == 'nothrow' else 'terminate',
                             'reason': 'ub_nounwind' if escape == 'nothrow' else 'uncaught'}
            return
        self.unwind_state = {'exception': exception, 'actions': actions, 'position': 0,
                             'selected': selected, 'waiting': None, 'captures': None, 'results': []}
        self.drive_unwind()

    def finish_action(self, values):
        state = self.unwind_state
        frame, action_id = state['actions'][state['position']]
        action = self.actions[frame.function['id']][action_id]
        recipe = self.dependencies.actions[key(action['recipe'])]
        require(type(values) is list and len(values) == len(recipe['results']), 'cleanup_result_arity')
        for value, nominal in zip(values, recipe['results']):
            expected = optional(self.dependencies.nominals[key(nominal)]['execution'])
            require(expected is not None and self.types.equal(value.type, expected), 'cleanup_result_type')
            validate(self.types, value, self.handles)
        state['results'].append((frame.activation, action_id, values))
        state['position'] += 1
        state['waiting'], state['captures'] = None, None

    def drive_unwind(self):
        state = self.unwind_state
        while state['position'] < len(state['actions']):
            frame, action_id = state['actions'][state['position']]
            action = self.actions[frame.function['id']][action_id]
            arguments = {}
            for capture in action['captures']:
                source = capture['source']
                if source['kind'] == 'value':
                    value = frame.values[source['value']]
                elif source['kind'] == 'exception':
                    value = Value(capture['type'], 'concrete', state['exception'].data)
                else:
                    identity = frame.activation, action_id, capture['parameter']
                    require(identity in self.active_journals, 'cleanup_journal_binding')
                    value = self.active_journals[identity]
                validate(self.types, value, self.handles)
                arguments[capture['parameter']] = value
            state['captures'] = arguments
            result = self.action_adapters[key(action['recipe'])](self, arguments, state['exception'])
            if isinstance(result, Terminated):
                self.terminate(result)
                return
            if isinstance(result, Raised):
                self.finished = {'kind': 'terminate', 'reason': 'cleanup_throws'}
                return
            if isinstance(result, Pending):
                require(result.ticket > 0 and self.pending is None, 'cleanup_pending_ticket')
                state['waiting'] = result.ticket
                self.pending = result.ticket, frame, None, None, None
                return
            self.finish_action(result)
        frame, continuation, handler = state['selected']
        while self.stack[-1] is not frame:
            escaped = self.stack.pop()
            self.memory.restore(escaped.activation, -1)
        self.selected_handlers[frame.activation] = handler['id']
        if frame.activation in self.catch_contexts:
            self.catch_parents.setdefault(frame.activation, []).append(self.catch_contexts[frame.activation])
        self.catch_contexts[frame.activation] = {'exception': state['exception'], 'handler': handler,
                                                'action_results': state['results'], 'entered': False}
        self.bind(frame, [continuation['exception']], [state['exception']])
        self.branch(frame, continuation['unwind'])
        self.unwind_state = None

    def memory_operation(self, operation, arguments):
        name, storage, mode = operation['op'], operation.get('storage'), operation.get('mode')
        if name == 'fence':
            self.memory.effects.append(('fence', operation['order']))
            return []
        if name in {'memcpy', 'memmove', 'memset'}:
            count = arguments[2]
            if not well_defined(self.types, count):
                raise GuestFault('ub_memory_count', True)
            if count.data == 0:
                return []
            if not well_defined(self.types, arguments[0]) or (name != 'memset' and
                    not well_defined(self.types, arguments[1])):
                raise GuestFault('ub_memory_address', True)
            pointer = self.pointer(arguments[0])
            source = raw_bits(self.types, arguments[1]) if name == 'memset' else self.pointer(arguments[1])
            self.memory.bulk(name, pointer, source, count.data, operation['alignment'], operation['volatile'])
            return []
        pointer = self.pointer(arguments[0])
        if mode['elementwise']:
            vector = self.types.get(storage['type'])
            layout = self.dependencies.layouts[key(storage['layout'])]
            child_layout = optional(layout['element'])
            child = self.dependencies.layouts[key(child_layout)]
            frame = self.stack[-1]
            if frame.progress is None:
                frame.progress = {'kind': 'elementwise', 'next_lane': 0, 'observed': [], 'inputs': list(arguments)}
            progress = frame.progress
            require(progress['kind'] == 'elementwise' and progress['inputs'] == list(arguments), 'elementwise_progress')
            while progress['next_lane'] < vector['count']:
                index = progress['next_lane']
                require(layout['stride'] % 8 == 0, 'elementwise_byte_stride')
                address = Pointer(pointer.address + index * layout['stride'] // 8, pointer.origin,
                                  pointer.generation, pointer.domain, pointer.access_range)
                node = deepcopy(operation)
                node['mode']['elementwise'] = False
                node['mode']['alignment'] = min(mode['alignment'], child['alignment'])
                node['storage'] = {'type': vector['element'], 'layout': child_layout, 'nominal': None,
                                   'abi_binding': None, 'bytes': child['access_bytes']}
                node['results'] = [{'id': result['id'], 'type': vector['element']} for result in operation['results']]
                lane_arguments = [Value(arguments[0].type, 'concrete', address)]
                lane_arguments += [component(self.types, argument, [index]) for argument in arguments[1:]]
                values = self.memory_operation(node, lane_arguments)
                progress['observed'].extend(values)
                progress['next_lane'] += 1
            observed = tuple(progress['observed'])
            frame.progress = None
            return [] if name == 'atomic_store' else [Value(storage['type'], 'concrete', observed)]
        if name in {'load', 'atomic_load'}:
            result = [self.memory.load(pointer, storage, mode)]
        elif name in {'store', 'atomic_store'}:
            self.memory.store(pointer, arguments[1], storage, mode)
            result = []
        else:
            self.memory.guard(pointer, storage['bytes'], mode['alignment'], write=True)
            original = self.memory.load(pointer, storage, mode)
            if name == 'cmpxchg':
                # Per-use zero refinement for compared poison bits, while the
                # original observed value/shadow is returned unchanged.
                observed, expected = raw_bits(self.types, original), raw_bits(self.types, arguments[1])
                success = (observed.bits & ~(observed.poison | observed.undef)) == (expected.bits & ~(expected.poison | expected.undef))
                if success:
                    self.memory.store(pointer, arguments[2], storage, mode)
                result = [original, Value(operation['results'][1]['type'], 'concrete', int(success))]
            else:
                action = operation['action']
                if action == 'exchange':
                    desired = arguments[1]
                elif action in {'add', 'sub', 'and', 'or', 'xor'}:
                    node = {'op': 'i_' + action, 'results': [operation['results'][0]], 'operands': [], 'flags': []}
                    desired = pure.execute(self, node, [original, arguments[1]])[0]
                else:
                    desired = self.rmw_extra(operation, original, arguments[1])
                self.memory.store(pointer, desired, storage, mode)
                result = [original]
        self.memory.effects.append((name, mode['order'], mode['failure_order'], mode['volatile']))
        return result

    def rmw_extra(self, operation, left, right):
        from evaluate import signed
        if self.types.get(left.type)['kind'] == 'vector':
            result = []
            for index, child in enumerate(self.types.components(left.type)):
                node = deepcopy(operation)
                node['results'][0]['type'] = child
                result.append(self.rmw_extra(node, component(self.types, left, [index]), component(self.types, right, [index])))
            return Value(left.type, 'concrete', tuple(result))
        action = operation['action']
        if left.state == 'poison' or right.state == 'poison':
            return Value(left.type, 'poison')
        left, right = materialize(self.types, left), materialize(self.types, right)
        a, b, width = left.data, right.data, self.types.width(left.type)
        mask = (1 << width) - 1
        if action == 'nand':
            value = ~(a & b) & mask
        elif action in {'min', 'max', 'umin', 'umax'}:
            av, bv = (signed(a, width), signed(b, width)) if action in {'min', 'max'} else (a, b)
            value = (a if av < bv else b) if action.endswith('min') else (a if av > bv else b)
        elif action == 'uinc_wrap':
            value = 0 if a >= b else (a + 1) & mask
        elif action == 'udec_wrap':
            value = b if a == 0 or a > b else a - 1
        elif action == 'usub_cond':
            value = a - b if a >= b else a
        elif action == 'usub_sat':
            value = max(0, a - b)
        elif action in {'fadd', 'fsub'}:
            node = {'op': 'fp_' + action[1:], 'results': [operation['results'][0]], 'operands': [],
                    'mode': {'environment': 'default', 'rounding': 'nearest_even', 'exceptions': 'ignore'}}
            return pure.execute(self, node, [left, right])[0]
        elif action in {'fmin', 'fmax', 'fminimum', 'fmaximum', 'fminimumnum', 'fmaximumnum'}:
            from candidate.fp import scalar
            operation_name = {'fmin': 'minnum', 'fmax': 'maxnum'}.get(action, action[1:])
            format_name = self.types.get(left.type)['format']
            bits, _ = scalar(operation_name, format_name, [format_name, format_name], [a, b])
            return Value(left.type, 'concrete', bits)
        else:
            raise GuestFault('reference_fp_atomic_selection_unhandled')
        return Value(left.type, 'concrete', value)

    def run(self, fuel=100000, max_frames=1024):
        if self._unbound_flow is not None:
            lock = self._unbound_flow._dispatch_lock
            require(lock.acquire(blocking=False), 'unbound_flow_concurrent_dispatch')
            try:
                if self._flow_terminal_error is not None:
                    raise self._flow_terminal_error
                try:
                    outcome = self._run(fuel, max_frames)
                except BaseException as error:
                    if self._flow_computing:
                        self._flow_terminal_error = error
                        self._flow_computing = False
                    raise
                if self.finished is not None:
                    self._flow_computing = False
                return outcome
            finally:
                lock.release()
        if self._source_runtime is None:
            return self._run(fuel, max_frames)
        lock = self._source_runtime['execution_lock']
        require(lock.acquire(blocking=False), 'reference_source_concurrent_dispatch')
        try:
            return self._run(fuel, max_frames)
        finally:
            lock.release()

    def _run(self, fuel=100000, max_frames=1024):
        if self._source_runtime is not None and self._source_runtime['final_return'] is not None:
            self._finish_source_roots()
        from candidate.wire import SCHEMA
        while self.stack and self.finished is None:
            if self._unbound_flow is not None:
                self._flow_computing = False
            if self._unbound_flow is not None and self._flow_actual_outputs is not None:
                if self._complete_unbound_outcome():
                    return {'kind': 'resource', 'reason': 'unbound_flow_parked', 'event': self._flow_event}
                continue
            if self._unbound_flow is not None and self._flow_event is not None:
                row = self._unbound_flow._event(self._flow_event)
                if row['stage'] == 'parked':
                    return {'kind': 'resource', 'reason': 'unbound_flow_parked', 'event': self._flow_event}
                self._publish_unbound_completed()
                continue
            if self._source_runtime is not None and self._source_runtime['pending_completion'] is not None:
                entry, outcome = self._source_runtime['pending_completion']
                self._source_runtime['registry'].finish_entry(entry, outcome=outcome,
                                                              budget=self._source_runtime['budget'])
                self._source_runtime['pending_completion'] = None
            if self.pending is not None:
                return {'kind': 'suspended', 'ticket': self.pending[0]}
            if fuel == 0 or len(self.stack) > max_frames:
                return {'kind': 'resource', 'reason': 'fuel' if fuel == 0 else 'frames'}
            if self._unbound_flow is None:
                fuel -= 1
                self.steps += 1
            frame = self.stack[-1]
            block = next(block for block in frame.function['blocks'] if block['id'] == frame.block)
            try:
                if frame.position == -1:
                    if self._unbound_flow is not None:
                        flow = self._unbound_flow
                        self._flow_reserved = flow._prepare(self, frame, 'phi_batch', block,
                            tuple(phi['result'] for phi in block['phis']),
                            issuer=_UNBOUND_FLOW_ISSUER, budget=flow.budget)
                        fuel -= 1
                        self.steps += 1
                        self._flow_computing = True
                        selected_ids = []
                        snapshot = {}
                        for phi in block['phis']:
                            selected = next(item['value'] for item in phi['incoming']
                                            if item['predecessor'] == frame.predecessor)
                            selected_ids.append(selected)
                            snapshot[phi['result']['id']] = frame.values[selected]
                        self._flow_actual_inputs = selected_ids
                        self._flow_actual_outputs = snapshot
                        self._flow_actual_phi = True
                        self._flow_computing = False
                        if self._complete_unbound_outcome():
                            return {'kind': 'resource', 'reason': 'unbound_flow_parked', 'event': self._flow_event}
                        self._publish_unbound_completed()
                        continue
                    snapshot = {phi['result']['id']: frame.values[next(item['value'] for item in phi['incoming']
                                if item['predecessor'] == frame.predecessor)] for phi in block['phis']}
                    frame.values.update(snapshot)
                    if type(self) is Machine:
                        _source_api()._note_values(self, frame, tuple(snapshot), tuple(snapshot.values()),
                                                  _SOURCE_MACHINE_ISSUER)
                    frame.position = 0
                    continue
                if frame.position < len(block['ops']):
                    operation = block['ops'][frame.position]
                    if self._unbound_flow is not None:
                        flow = self._unbound_flow
                        kind = {'copy': 'noop', 'freeze': 'freeze', 'select': 'select',
                                'constant': 'literal'}.get(operation['op'], 'ordinary')
                        self._flow_reserved = flow._prepare(self, frame, kind, operation,
                            operation['results'], issuer=_UNBOUND_FLOW_ISSUER, budget=flow.budget)
                        fuel -= 1
                        self.steps += 1
                        self._flow_computing = True
                    if self._source_runtime is not None:
                        _source_api()._dispatch(self, frame, operation, _SOURCE_MACHINE_ISSUER)
                    family = SCHEMA['operation_contracts'][operation['op']]['family']
                    args = [frame.values[value] for value in operation['operands']]
                    if family in {'call', 'helper'}:
                        target = operation['target'] if family == 'call' else operation['helper']
                        extra = []
                        if operation['op'] == 'alloca':
                            alignment_type = self.types.get(target['signature'])['params'][1]
                            extra = [Value(alignment_type, 'concrete', operation['alignment'])]
                        self.call(frame, target, operation['operands'],
                                  {'results': operation['results'], 'normal': None, 'unwind': None,
                                   'nounwind': operation.get('unwind') == 'nounwind',
                                   'no_normal_return': operation['op'] == 'longjmp'}, extra)
                        continue
                    if family == 'exception' and operation['op'] != 'landingpad':
                        self.check_exception_context(operation, args)
                        self.call(frame, operation['helper'], operation['operands'],
                                  {'results': operation['results'], 'normal': None, 'unwind': None,
                                   'no_guest_throw': True, 'post': operation['op']})
                        continue
                    if family in {'memory', 'memory_bulk'}:
                        values = self.memory_operation(operation, args)
                    elif family == 'effect':
                        self.memory.effects.append(('effect_barrier', frame.activation, frame.block, frame.position))
                        values = []
                    elif family == 'environment':
                        values = self.environment_operation(operation, args)
                    elif family == 'pointer' and operation['op'] in {'address_of', 'block_address'}:
                        values = self.address_operation(operation)
                    elif family == 'exception':
                        values = self.exception_operation(operation, args)
                    elif family == 'code_address':
                        values = self.source_code_operation(frame, operation, args)
                    else:
                        values = pure.execute(self, operation, args)
                    if self.finished is not None:
                        return self.finished
                    if self._unbound_flow is not None:
                        self._flow_actual_inputs = operation['operands']
                        self._flow_actual_outputs = values
                        self._flow_actual_phi = False
                        self._flow_computing = False
                        if self._complete_unbound_outcome():
                            return {'kind': 'resource', 'reason': 'unbound_flow_parked', 'event': self._flow_event}
                        self._publish_unbound_completed()
                        continue
                    self.bind(frame, operation['results'], values)
                    if self._source_runtime is not None:
                        _source_api()._finish_result(self, frame, _SOURCE_MACHINE_ISSUER)
                    frame.position += 1
                    continue
                term = block['term']
                if self._unbound_flow is not None:
                    flow = self._unbound_flow
                    flow._control(self, frame, issuer=_UNBOUND_FLOW_ISSUER, budget=flow.budget)
                    fuel -= 1
                    self.steps += 1
                    self._flow_computing = True
                if self._source_runtime is not None:
                    _source_api()._dispatch(self, frame, term, _SOURCE_MACHINE_ISSUER)
                name = term['op']
                if name == 'return':
                    if self.catch_contexts.get(frame.activation, {}).get('entered', False):
                        raise GuestFault('catch_obligation')
                    values = [frame.values[value] for value in term['values']]
                    signature = self.types.get(frame.function['signature'])
                    for value, noundef in zip(values, signature['result_noundef']):
                        if noundef and not well_defined(self.types, value):
                            raise GuestFault('ub_noundef_result', True)
                    if self._source_runtime is not None:
                        _source_api()._returning(self, frame, values, _SOURCE_MACHINE_ISSUER)
                    if self._source_runtime is not None:
                        _source_api()._leave_frame(self, frame, _SOURCE_MACHINE_ISSUER)
                    self.stack.pop()
                    self.memory.restore(frame.activation, -1)
                    if not self.stack:
                        if self._source_runtime is None:
                            self.finished = {'kind': 'return', 'values': values}
                        else:
                            self._source_runtime['final_return'] = {'kind': 'return', 'values': values}
                            self._finish_source_roots()
                    else:
                        self.complete(self.stack[-1], frame.continuation, values, signature)
                elif name == 'jump':
                    self.branch(frame, term['target'])
                elif name in {'cbranch', 'switch'}:
                    value = frame.values[term['condition'] if name == 'cbranch' else term['index']]
                    if value.state != 'concrete':
                        raise GuestFault('ub_control_value', True)
                    target = (term['true'] if value.data else term['false']) if name == 'cbranch' else next(
                        (case['target'] for case in term['cases'] if int.from_bytes(bytes.fromhex(case['value']), 'little') == value.data), term['default'])
                    self.branch(frame, target)
                elif name == 'indirect_branch':
                    pointer = self.pointer(frame.values[term['address']])
                    if pointer.address not in self.labels or pointer.domain != 'label':
                        raise GuestFault('ub_indirect_branch', True)
                    expected, function_id, target = self.labels[pointer.address]
                    if expected != pointer or function_id != frame.function['id'] or target not in term['targets']:
                        raise GuestFault('ub_indirect_branch', True)
                    self.branch(frame, target)
                elif name in {'invoke', 'tailcall'}:
                    if name == 'invoke':
                        continuation = {'results': term['normal']['results'], 'normal': term['normal']['target'],
                                        'unwind': term['unwind']['target'], 'exception': term['unwind']['exception'],
                                        'region': term['region']}
                        self.call(frame, term['target'], term['operands'], continuation)
                    else:
                        target = term['target']
                        require(target['kind'] == 'direct' and target['function']['module']['kind'] == 'self', 'reference_tail_target')
                        values = [frame.values[value] for value in term['operands']]
                        require(not any(entry['live'] and entry['owner'] == frame.activation
                                        and entry['kind'] in {'journal', 'stack_mark', 'va_list'}
                                        for entry in self.handles.values()), 'tail_live_obligation')
                        replacement = self.activate(self.functions[target['function']['id']], values, frame.continuation)
                        self.memory.restore(frame.activation, -1)
                        self.stack[-1] = replacement
                elif name in {'throw', 'rethrow', 'resume', 'cleanup_return'}:
                    exception = term['exception'] if type(term['exception']) is int else optional(term['exception'])
                    if exception is None:
                        raise GuestFault('cleanup_return_without_exception')
                    self.unwind(frame.values[exception])
                elif name == 'terminate':
                    self.finished = {'kind': 'terminate', 'reason': term['reason']}
                else:
                    raise GuestFault('ub_unreachable' if name == 'unreachable' else term['reason'], name == 'unreachable')
            except GuestFault as fault:
                if fault.code.startswith('resource_'):
                    self.finished = {'kind': 'resource', 'reason': fault.code}
                else:
                    self.finished = {'kind': 'language_ub' if fault.language_ub else 'trap', 'reason': fault.code,
                                     'activation': frame.activation, 'function': frame.function['id'],
                                     'block': frame.block, 'operation': frame.position}
            except Reject as error:
                if error.code != 'reference_resource':
                    raise
                self.finished = {'kind': 'resource', 'reason': error.code, 'detail': error.detail}
            except Exception as error:
                if self._source_runtime is None:
                    raise
                api = _source_api()._registry_api()
                if (type(error) is not api.CodeRegistryError or error.kind != 'semantic' or
                        not error.code.startswith(('code_address_', 'code_token_'))):
                    raise
                self.finished = {'kind': 'trap', 'reason': error.code,
                                 'activation': frame.activation, 'function': frame.function['id'],
                                 'block': frame.block, 'operation': frame.position}
        return self.finished

    def environment_operation(self, operation, args):
        name = operation['op']
        if name == 'fenv_pack':
            from candidate.fenv import pack
            from candidate.raw import Raw
            if args[0].state != 'concrete':
                return [Value(operation['results'][0]['type'], args[0].state)]
            return [Value(operation['results'][0]['type'], 'concrete', Raw.integer(256, int.from_bytes(pack(args[0].data), 'little')))]
        if name == 'fenv_unpack':
            from candidate.fenv import unpack
            from common import Reject
            raw = raw_bits(self.types, args[0])
            try:
                if raw.poison:
                    raise Reject('fenv_snapshot')
                snapshot = unpack((raw.bits & ~raw.undef).to_bytes(32, 'little'))
                return [Value(operation['results'][0]['type'], 'concrete', snapshot),
                        Value(operation['results'][1]['type'], 'concrete', 1)]
            except Reject:
                return [Value(operation['results'][0]['type'], 'poison'), Value(operation['results'][1]['type'], 'concrete', 0)]
        if name == 'fenv_get':
            return [Value(operation['results'][0]['type'], 'concrete', deepcopy(self.environment))]
        if name == 'fenv_set':
            if args[0].state != 'concrete':
                raise GuestFault('ub_fenv_handle', True)
            self.environment = deepcopy(args[0].data)
        elif name == 'fenv_clear':
            self.environment['flags'] = sorted(set(self.environment['flags']) - set(operation['flags']))
        elif name == 'fenv_raise':
            self.fp_commit({'environment': 'constrained', 'exceptions': 'strict'}, set(operation['flags']))
        else:
            return [Value(operation['results'][0]['type'], 'concrete', int(bool(set(operation['flags']) & set(self.environment['flags']))))]
        return []

    def address_operation(self, operation):
        output = operation['results'][0]['type']
        if operation['op'] == 'address_of':
            if self.types.get(output)['kind'] == 'code_address':
                runtime = self._source_runtime
                require(runtime is not None, 'reference_code_address_unavailable')
                registry, budget = runtime['registry'], runtime['budget']
                frame = self.stack[-1]
                pending = _source_api()._begin_result(self, frame, operation, output, _SOURCE_MACHINE_ISSUER)
                fields = _source_api()._pending_result_fields(self, pending, _SOURCE_MACHINE_ISSUER)
                if fields['lane'] is None:
                    target = registry.resolve(runtime['deployment'], runtime['owner'], 'symbol',
                                              operation['symbol'], budget=budget)
                    fields['lane'] = registry.address(target, budget=budget)
                return [self._source_value(frame, output, pending)]
            require(key(operation['symbol']) in self.symbols, 'reference_symbol_binding')
            return [Value(output, 'concrete', self.symbols[key(operation['symbol'])])]
        identity_key = operation['function'], operation['block']
        if identity_key in self.label_entries:
            return [Value(output, 'concrete', self.label_entries[identity_key])]
        token = self.next_code
        reservation = None
        if self._source_runtime is not None:
            runtime = self._source_runtime
            reservation = runtime['registry'].reserve_label(runtime['attachment'], ref(operation['function']),
                operation['block'], budget=runtime['budget'])
            token = reservation.bits
        else:
            self.next_code += 2
        require(token < 2**64, 'code_token_exhausted')
        identity = hashlib.sha256(f'label:{operation["function"]}:{operation["block"]}:{token}'.encode()).hexdigest()
        pointer = Pointer(token, identity, reservation.generation if reservation is not None else 1,
                          'label', lineage=object() if reservation is not None else None)
        self.labels[token] = (pointer, operation['function'], operation['block'])
        self.label_entries[identity_key] = pointer
        if reservation is not None:
            self._source_runtime['reservations'].append(reservation)
            _source_api()._note_registration(self, pointer, self.labels[token], reservation, 'label',
                                             ref(operation['function']), _SOURCE_MACHINE_ISSUER)
        return [Value(output, 'concrete', pointer)]

    def register_function(self, symbol, function, signature):
        require(key(function) in self.dependencies.functions
                and self.types.equal(self.dependencies.functions[key(function)], signature), 'code_signature')
        if key(function) in self.code_entries:
            pointer = self.code_entries[key(function)]
            self.symbols[key(symbol)] = pointer
            return pointer
        token = self.next_code
        reservation = None
        if self._source_runtime is not None:
            runtime = self._source_runtime
            reservation = runtime['registry'].reserve_function(runtime['attachment'], function, budget=runtime['budget'])
            token = reservation.bits
        else:
            self.next_code += 2
        require(token < 2**64, 'code_token_exhausted')
        identity = hashlib.sha256(f'function:{key(function)}:{token}'.encode()).hexdigest()
        pointer = Pointer(token, identity, reservation.generation if reservation is not None else 1,
                          'code', lineage=object() if reservation is not None else None)
        self.code_pointers[token] = (pointer, {'kind': 'direct', 'function': function, 'signature': signature})
        self.symbols[key(symbol)] = pointer
        self.code_entries[key(function)] = pointer
        if reservation is not None:
            self._source_runtime['reservations'].append(reservation)
            _source_api()._note_registration(self, pointer, self.code_pointers[token], reservation, 'function',
                                             function, _SOURCE_MACHINE_ISSUER)
        return pointer

    def handle(self, reference, payload, owner=None):
        kind = self.types.get(reference)['kind']
        require(kind in {'exception', 'stack_mark', 'va_list', 'journal'}, 'handle_kind')
        self.handle_sequence += 1
        require(self.handle_sequence < 2**64, 'handle_exhausted')
        identity = self.handle_sequence
        self.handles[identity] = {'kind': kind, 'generation': identity, 'live': True,
                                  'owner': owner, 'payload': payload}
        return Value(reference, 'concrete', Handle(kind, identity, identity))

    def bind_journal(self, activation, action_id, parameter, journal):
        """Trusted live-context binding; a program ID never chooses an instance."""
        frame = next((frame for frame in self.stack if frame.activation == activation), None)
        require(frame is not None and action_id in self.actions.get(frame.function['id'], {}), 'journal_capture_action')
        action = self.actions[frame.function['id']][action_id]
        matches = [capture for capture in action['captures'] if capture['parameter'] == parameter]
        require(len(matches) == 1 and matches[0]['source']['kind'] == 'journal', 'journal_capture_formal')
        validate(self.types, journal, self.handles)
        require(self.types.get(journal.type)['kind'] == 'journal' and journal.state == 'concrete', 'journal_capture_handle')
        entry = self.handles[journal.data.identity]
        require(entry['owner'] == activation and entry['payload']['program'] == key(action['program']), 'journal_capture_owner_program')
        identity = activation, action_id, parameter
        require(identity not in self.active_journals, 'journal_capture_duplicate_binding')
        self.active_journals[identity] = journal

    def exception_operation(self, operation, args):
        name = operation['op']
        if name == 'landingpad':
            exception = args[0]
            if exception.state != 'concrete':
                raise GuestFault('ub_exception_handle', True)
            region = self.regions[self.stack[-1].function['id']][operation['region']]
            if self.stack[-1].activation in self.selected_handlers:
                handler = self.catch_contexts[self.stack[-1].activation]['handler']
                return [Value(operation['results'][0]['type'], 'concrete', handler['selector'])]
            selector = 0
            for handler in region['handlers']:
                nominal = optional(handler['nominal'])
                payload = self.handles[exception.data.identity]['payload']
                if handler['kind'] == 'catch_all' or self.exception_matcher(payload, nominal):
                    selector = handler['selector']
                    break
            return [Value(operation['results'][0]['type'], 'concrete', selector)]
        raise GuestFault('reference_exception_operation')

    def check_exception_context(self, operation, args):
        frame = self.stack[-1]
        if operation['op'] in {'catch_begin', 'catch_end'}:
            context = self.catch_contexts.get(frame.activation)
            require(context is not None and context['exception'] == args[0], 'catch_selected_context')
            if operation['op'] == 'catch_begin':
                require(not context['entered'] and context['handler']['id'] == operation['handler'], 'catch_handler_context')
            else:
                require(context['entered'], 'catch_not_entered')
        else:
            journal = args[0]
            validate(self.types, journal, self.handles)
            require(journal.state == 'concrete' and isinstance(journal.data, Handle), 'journal_live_handle')
            require(self.handles[journal.data.identity]['payload']['program'] == key(operation['program']), 'journal_live_program')
