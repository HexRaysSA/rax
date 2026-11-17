"""Actual-registry Raw8 relay oracle; no source ABI2 or LLVM emission proof."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
FOLDER = ROOT/'docs/specifications/smir/portable/conformance/execution/function-addresses/byte-relay'
PROFILES = ('relay', 'mixed-foreign-equal-bits', 'foreign-equal-bits',
            'reordered-zero-bytes', 'numeric-byte-roundtrip', 'numeric-vector-roundtrip',
            'originless-zero-byte', 'stale-generation', 'readonly-buffer', 'short-buffer')
EXPECTED = {'relay': 'return', 'foreign-equal-bits': 'RT_CODE_REFERENCE',
            'stale-generation': 'code_address_stale', 'readonly-buffer': 'memory_permission',
            'short-buffer': 'memory_bounds'}
MODE = dict(alignment=1, volatile=False, order='none', failure_order='none',
            scope='process', elementwise=False)


def paths():
    execution, runtime = str(ROOT/'tools/smir-format/execution'), str(ROOT/'tools/smir-runtime-contract')
    if execution not in sys.path:
        sys.path.insert(0, execution)
    if runtime not in sys.path:
        sys.path.insert(1, runtime)


def registry_api():
    paths()
    name = '_rax_smir_code_addresses_v1'
    path = ROOT/'tools/smir-runtime-contract/source_roles/code_addresses.py'
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    if Path(sys.modules[name].__file__).resolve() != path.resolve():
        raise RuntimeError('registry implementation identity')
    return sys.modules[name]


def build_document(profile):
    paths()
    from generate_service_type_fixtures import complete_identity, prepare_abi2_nonrecord_source
    from candidate.type_system import ref
    from test_candidate import block, constant, decl, operation
    if profile not in PROFILES+('producer',):
        raise ValueError('unknown byte relay profile')
    roots = complete_identity()
    foreign = profile in {'mixed-foreign-equal-bits', 'foreign-equal-bits'}
    params = [17, 4]+([903] if foreign else [])
    roots[1]['types'] += [dict(id=900, kind='code_address'),
        dict(id=901, kind='code_ptr', signature=ref(12)),
        dict(id=903, kind='vector', element=ref(9), count=8),
        dict(id=904, kind='function', params=[ref(9), ref(4)], results=[ref(9)],
             param_noundef=[False, True], result_noundef=[False], cc='portable', variadic=False),
        dict(id=905, kind='function', params=[ref(t) for t in params], results=[ref(17)],
             param_noundef=[True, True]+([False] if foreign else []), result_noundef=[True], cc='portable', variadic=False),
        dict(id=906, kind='vector', element=ref(2), count=8),
        dict(id=907, kind='function', params=[], results=[ref(903)],
             param_noundef=[], result_noundef=[False], cc='portable', variadic=False),
        dict(id=908, kind='int', bits=1)]
    roots[1]['memory_layouts'] += [dict(id=910, type=ref(9), size=1, access_bytes=1,
        alignment=1, fields=[], element=None, stride=0),
        dict(id=911, type=ref(903), size=8, access_bytes=8, alignment=1,
             fields=[], element={'some': ref(910)}, stride=8)]
    byte_storage = dict(type=ref(9), layout=ref(910), nominal=None, abi_binding=None, bytes=1)
    vector_storage = dict(type=ref(903), layout=ref(911), nominal=None, abi_binding=None, bytes=8)
    def function(identifier, signature, parameters, ops, returned):
        return dict(id=identifier, signature=ref(signature), abi_signature=None,
            params=[decl(i, t) for i, t in enumerate(parameters)], entry=0,
            escape='propagate', no_return=False,
            blocks=[block(0, ops, dict(op='return', values=[returned]))])
    helper = function(2, 904, [9, 4], [
        operation('store', [], [1, 0], storage=deepcopy(byte_storage), mode=dict(MODE)),
        operation('load', [decl(2, 9)], [1], storage=deepcopy(byte_storage), mode=dict(MODE))], 2)
    producer = function(3, 907, [], [
        operation('address_of', [decl(20, 900)], symbol=ref(0)),
        operation('bitcast', [decl(21, 903)], [20])], 21)
    ops = [operation('address_of', [decl(20, 900)], symbol=ref(0)),
           operation('bitcast', [decl(21, 903)], [20]),
           operation('constant', [decl(22, 903)], literal=dict(kind='zero'))]
    assembled = 22
    for i in range(8):
        selected = 7 if profile == 'reordered-zero-bytes' and i == 6 else 6 if profile == 'reordered-zero-bytes' and i == 7 else i
        ops += [constant(100+i, 5, i.to_bytes(8, 'little').hex()),
                operation('ptr_offset', [decl(110+i, 4)], [1, 100+i],
                          inbounds=True, check_base=False, nuw=False, nusw=False, inrange=None)]
        if selected != i:
            ops.append(constant(160+i, 5, selected.to_bytes(8, 'little').hex()))
        vector = 2 if profile == 'foreign-equal-bits' or profile == 'mixed-foreign-equal-bits' and i == 7 else 21
        ops.append(operation('extract_element', [decl(120+i, 9)], [vector, 160+i if selected != i else 100+i]))
        value = 120+i
        if profile == 'numeric-byte-roundtrip' and i == 7:
            ops += [operation('bitcast', [decl(140+i, 2)], [value]),
                    operation('bitcast', [decl(150+i, 9)], [140+i])]
            value = 150+i
        if profile == 'originless-zero-byte' and i == 7:
            ops.append(constant(150+i, 9, '00'))
            value = 150+i
        ops += [operation('call', [decl(200+i, 9)], [value, 110+i],
            target=dict(kind='direct', function=ref(2), signature=ref(904)),
            unwind='propagate', source_plan=None),
            operation('insert_element', [decl(300+i, 903)], [assembled, 200+i, 100+i])]
        assembled = 300+i
    ops.append(operation('load', [decl(400, 903)], [1], storage=vector_storage, mode=dict(MODE)))
    loaded = 400
    if profile == 'numeric-vector-roundtrip':
        ops += [operation('bitcast', [decl(409, 906)], [400]),
                operation('bitcast', [decl(410, 903)], [409])]
        loaded = 410
    ops += [operation('bitcast', [decl(401, 900)], [loaded]),
            operation('bitcast', [decl(402, 900)], [assembled]),
            operation('icmp', [decl(403, 908)], [401, 402], predicate='eq'),
            operation('code_bind', [decl(404, 901)], [401], plan=ref(0)),
            operation('call', [decl(405, 17)], [0],
                target=dict(kind='indirect', value=404, signature=ref(12)),
                unwind='propagate', source_plan={'some': ref(0)})]
    main = function(1, 905, params, ops, 405)
    roots[3]['functions'] += [main, helper, producer]
    roots[1]['types'].sort(key=lambda row: row['id'])
    roots[1]['memory_layouts'].sort(key=lambda row: row['id'])
    prepare_abi2_nonrecord_source(roots)
    return roots


def codec():
    paths()
    name = '_rax_codeaddress_byte_relay_codec'
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, ROOT/'tools/smir-format/codec.py')
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    schemas = {n: json.loads((ROOT/'docs/specifications/smir/portable/schema'/n/'candidate.json').read_bytes())
               for n in ('execution', 'abi', 'runtime')}
    return sys.modules[name].CandidateCodec(schemas)


def encoded_document(profile):
    return codec().encode(build_document(profile))


def make_machine(wire):
    paths()
    from candidate.context import RootContext
    from candidate.machine import Machine
    api = registry_api()
    owner = RootContext(codec().decode(wire).roots)
    owner.verify_abi()
    checked = owner.verify_execution()
    ledger = api._base.SD.SourceQueryBudget(max_work=10**12, max_edges=10**12,
                                           max_copied_bytes=10**12, max_depth=128)
    source = owner.source_registry_context(budget=ledger)
    policy = api.RegistryPolicy(max_targets=32, max_permits=32, max_roots=64,
                               max_activations=64, max_snapshots=32)
    registry = api.CodeRegistry(budget=ledger, policy=policy)
    machine = Machine(checked)
    machine.attach_source_registry(registry, source, budget=ledger)
    owner.assert_snapshot()
    return owner, source, ledger, registry, machine


def foreign_payload(wire):
    owner, source, ledger, registry, machine = make_machine(wire)
    machine.start(3, [])
    result = machine.run(fuel=3)
    if result['kind'] != 'resource' or machine.stack[-1].position != 2:
        raise RuntimeError('actual foreign producer pause')
    frame = machine.stack[-1]
    return (owner, source, ledger, registry, machine), frame.values[21], frame.values[20].data


def witness(profile, wire, producer_wire=None):
    """Drive only actual verified Machine steps; never create opaque origins."""
    paths()
    from candidate.type_system import ref
    from candidate.values import Value
    api = registry_api()
    foreign = None
    if profile in {'mixed-foreign-equal-bits', 'foreign-equal-bits'}:
        foreign, foreign_value, foreign_pointer = foreign_payload(producer_wire)
    owner, source, ledger, registry, machine = make_machine(wire)
    buffer = machine.memory.allocate(7 if profile == 'short-buffer' else 8, 1,
                                     mutable=profile != 'readonly-buffer')
    args = [Value(ref(17), 'concrete', 42), Value(ref(4), 'concrete', buffer)]
    if foreign is not None:
        args.append(foreign_value)
    machine.start(1, args)
    entries, returns = [], []
    issued, reconstruction, rejection, outcome, retired = None, None, None, None, None
    for _ in range(1000):
        frame = machine.stack[-1]
        block = frame.function['blocks'][0]
        if frame.function['id'] == 2 and frame.position == -1:
            entries.append(frame.values[0])
        if frame.function['id'] == 2 and frame.position == len(block['ops']):
            returns.append(frame.values[2])
        if frame.function['id'] == 1:
            if 20 in frame.values and issued is None:
                issued = frame.values[20].data
                if issued.origin is None or issued.authority is None or issued.permit is not None:
                    raise RuntimeError('genuine actual issued CodeAddress required')
                if foreign is not None and issued.address != foreign_pointer.address:
                    raise RuntimeError('actual foreign collision required, no fabricated equal bits')
            node = block['ops'][frame.position] if 0 <= frame.position < len(block['ops']) else block['term']
            if node['op'] == 'code_bind':
                operand = frame.values[401].data
                loaded = frame.values[400]
                reconstruction = dict(bits=operand.address, equal_issued_bits=operand.address == issued.address,
                    same_target=operand.origin is issued.origin,
                    same_authority=operand.authority is issued.authority,
                    generation=operand.generation, domain=operand.domain,
                    lane_origins=[len(value.data.origins) for value in loaded.data],
                    numeric_equality=frame.values[403].data)
                if profile == 'stale-generation' and retired is None:
                    old_owner = machine._source_runtime['owner']
                    old_generation = issued.origin.generation
                    transaction = registry.retire((old_owner,), budget=ledger)
                    new_owner = registry.register_source(source, budget=ledger)
                    new_generation = registry._row(new_owner)['generation']
                    if new_generation <= old_generation:
                        raise RuntimeError('actual new registry generation required')
                    retired = dict(old_generation=old_generation, new_generation=new_generation,
                                   retirement_phase=registry.retire_poll(transaction, budget=ledger).phase)
        try:
            result = machine.run(fuel=1)
        except api.CodeRegistryError as error:
            rejection = dict(kind=error.kind, code=error.code)
            outcome = dict(kind='registry_rejection', reason=error.code)
            break
        if result['kind'] != 'resource' or result.get('reason') != 'fuel':
            outcome = result
            break
    else:
        raise RuntimeError('reference step bound')
    owner.assert_snapshot()
    api._base.SEM.validate_source_registry_context(source, budget=ledger)
    if foreign is not None:
        foreign[0].assert_snapshot()
        api._base.SEM.validate_source_registry_context(foreign[1], budget=foreign[2])
    expected = EXPECTED.get(profile, 'code_address_invalid')
    actual = 'return' if outcome['kind'] == 'return' else outcome['reason']
    if actual != expected:
        raise RuntimeError(profile+': '+str(outcome))
    if profile == 'relay':
        if outcome['values'][0].data != 42 or len(registry._permits) != 1 or len(registry._entries) != 1:
            raise RuntimeError('actual bind/entry/return required')
        if len(entries) != 8 or len(returns) != 8 or any(a.data != b.data for a, b in zip(entries, returns)):
            raise RuntimeError('eight actual Raw8 helper parameter/return relations')
        if not reconstruction['same_target'] or not reconstruction['same_authority']:
            raise RuntimeError('actual original authority not preserved')
    elif registry._permits or registry._entries:
        raise RuntimeError('negative published a permit/entry')
    if machine.exposed_code or machine.memory.exposed or registry._exposed_code or registry._exposed_address:
        raise RuntimeError('raw relay performed numeric exposure')
    def fragments(values):
        return [dict(width=value.data.width, bits=value.data.bits,
                     poison=value.data.poison, undef=value.data.undef,
                     spans=[dict(offset=span.offset, length=span.length, source=span.source,
                                 original_target=span.pointer.origin is issued.origin,
                                 original_authority=span.pointer.authority is issued.authority)
                            for span in value.data.origins]) for value in values]
    return dict(profile=profile, outcome=actual,
        return_value=outcome['values'][0].data if outcome['kind'] == 'return' else None,
        issued_bits=issued.address, reconstruction=reconstruction,
        helper_entries=len(entries), helper_returns=len(returns),
        parameter_fragments=fragments(entries), returned_fragments=fragments(returns),
        stores=sum(row[0] == 'store' for row in machine.memory.effects),
        loads=sum(row[0] == 'load' for row in machine.memory.effects),
        permits=len(registry._permits), entries=len(registry._entries),
        retired_generation=retired, registry_rejection=rejection,
        original_snapshots_unchanged=True, optimize=sys.flags.optimize,
        authority_source='actual verified Machine address_of/private CodeRegistry',
        scope='Execution reference/generic typed Raw8 calls and memory only; no source ABI2/LLVM emission/importer/storage-holder lifetime proof.')
