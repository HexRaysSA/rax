"""Fresh actual generic Machine execution compared with independent native helpers."""
import json
from pathlib import Path
import sys

from reference import ReferenceSession, HelperError, source_api, PROJECT
from candidate.raw import concat
from candidate.values import Value, raw_bits
from candidate.type_system import ref
from code_address_bytes import contract as core

FOLDER = PROJECT / 'docs/specifications/smir/portable/conformance/execution/function-addresses/byte-relay'


def budget():
    return source_api().SourceQueryBudget(max_work=10**13, max_edges=10**10, max_copied_bytes=10**13, max_depth=128)


def require(value, message):
    if not value:
        raise RuntimeError(message)


def encoded_cases():
    data = json.loads((FOLDER / 'cases.json').read_bytes())
    return data, {r['id']: bytes.fromhex(r['encoded_hex']) for r in data['cases']}


def compare_raw(session, expected, actual):
    # Core's span concatenator normalizes adjacent equal-pointer fragments;
    # native independently compresses its per-bit slots.
    record = session.raw_record(concat([actual]))
    require(expected == record, 'native/Core Raw mismatch: ' + repr((expected, record)))


def actual_witness(profile, binary, receipt):
    data, cases = encoded_cases()
    foreign = None
    if profile in ('mixed-foreign-equal-bits', 'foreign-equal-bits'):
        foreign, foreign_value, foreign_pointer = core.foreign_payload(bytes.fromhex(data['producer']['encoded_hex']))
    owner, source, ledger, registry, machine = core.make_machine(cases[profile])
    session = ReferenceSession(binary, receipt, budget=ledger, max_events=512)
    buffer = machine.memory.allocate(7 if profile == 'short-buffer' else 8, 1, mutable=profile != 'readonly-buffer')
    args = [Value(ref(17), 'concrete', 42), Value(ref(4), 'concrete', buffer)]
    if foreign is not None:
        args.append(foreign_value)
    machine.start(1, args)
    entries = returns = comparisons = 0
    split_done = False
    issued, reconstruction, retired, outcome = None, None, None, None
    native_traps = []

    def raw_ref(raw):
        return session.capture_raw(raw, budget=ledger)

    def native(op, args):
        return session.result(session.evaluate(op, args, budget=ledger), budget=ledger)

    def memory_ref():
        return session.capture_memory(machine.memory, buffer, budget=ledger)

    for step in range(1000):
        frame = machine.stack[-1]
        block = frame.function['blocks'][0]
        node = block['ops'][frame.position] if 0 <= frame.position < len(block['ops']) else block['term']
        if frame.function['id'] == 2 and frame.position == -1:
            entries += 1
        if frame.function['id'] == 2 and frame.position == len(block['ops']):
            returns += 1
        if frame.function['id'] == 1 and 20 in frame.values and issued is None:
            issued = frame.values[20].data
            require(issued.origin is not None and issued.authority is not None and issued.permit is None,
                    'actual issued original address required')
            if foreign is not None:
                require(issued.address == foreign_pointer.address, 'actual genuine equal-bit collision required')
        if frame.function['id'] == 1 and 21 in frame.values and not split_done:
            parts = native('split_code64', {'value': raw_ref(raw_bits(machine.types, frame.values[20]))})
            for image, actual in zip(parts, frame.values[21].data):
                compare_raw(session, image, actual.data)
                comparisons += 1
            split_done = True

        expected, trap, captured_before = None, None, None
        if 0 <= frame.position < len(block['ops']) and node['op'] in ('store', 'load'):
            pointer = frame.values[node['operands'][0]].data
            captured_before = session._ref(memory_ref(), 'memory')
            access = session.capture_pointer(pointer, budget=ledger)
            try:
                if node['op'] == 'store':
                    expected = native('store8', {'memory': memory_ref(), 'pointer': access,
                        'value': raw_ref(frame.values[node['operands'][1]].data), 'mask': 255})
                elif node['storage']['bytes'] == 1:
                    expected = native('load8', {'memory': memory_ref(), 'pointer': access})
                else:
                    expected = []
                    for index in range(8):
                        lane = machine.memory.offset(pointer, index, True, False, False)
                        expected.append(native('load8', {'memory': memory_ref(),
                            'pointer': session.capture_pointer(lane, budget=ledger)}))
            except HelperError as error:
                require(error.kind == 'trap', 'unexpected native reference rejection')
                trap = error.code
                native_traps.append(trap)

        numeric_expected = None
        if frame.function['id'] == 1 and 0 <= frame.position < len(block['ops']) and node['op'] == 'bitcast':
            argument = frame.values[node['operands'][0]]
            output_type = machine.types.get(node['results'][0]['type'])
            input_type = machine.types.get(argument.type)
            if input_type['kind'] == 'raw' and output_type['kind'] == 'int':
                numeric_expected = native('observe8', {'value': raw_ref(argument.data)})
            elif input_type['kind'] == 'vector' and output_type['kind'] == 'vector':
                input_child = machine.types.get(input_type['element'])
                output_child = machine.types.get(output_type['element'])
                if input_child['kind'] == 'raw' and output_child['kind'] == 'int':
                    numeric_expected = [native('observe8', {'value': raw_ref(v.data)}) for v in argument.data]

        if frame.function['id'] == 1 and 0 <= frame.position < len(block['ops']) and node['op'] == 'code_bind':
            vector = frame.values[410] if 410 in frame.values else frame.values[400]
            joined = native('join_code64', {'values': tuple(raw_ref(v.data) for v in vector.data)})
            compare_raw(session, joined['raw'], raw_bits(machine.types, vector))
            actual = frame.values[401]
            require(joined['state'] == actual.state, 'join state mismatch')
            pointer = actual.data
            require(int(joined['raw']['bits'], 16) == pointer.address, 'join address mismatch')
            original = session.pointers[joined['origin'] - 1] if joined['origin'] is not None else None
            require((original is None) == (pointer.origin is None), 'join origin availability mismatch')
            if original is not None:
                require(original.origin is pointer.origin and original.generation == pointer.generation
                        and original.authority is pointer.authority, 'join original identity/generation/authority mismatch')
            reconstruction = dict(bits=pointer.address, same_target=pointer.origin is issued.origin,
                same_authority=pointer.authority is issued.authority, original_generation=pointer.generation,
                native_origin=joined['origin'], original_descriptor_generation=(
                    session.origins()[joined['origin'] - 1]['generation'] if joined['origin'] else None))
            comparisons += 1
            if profile == 'stale-generation':
                old_owner = machine._source_runtime['owner']
                old_generation = issued.origin.generation
                retirement = registry.retire((old_owner,), budget=ledger)
                replacement = registry.register_source(source, budget=ledger)
                new_generation = registry._row(replacement)['generation']
                again = native('join_code64', {'values': tuple(raw_ref(v.data) for v in vector.data)})
                require(again == joined and new_generation > old_generation, 'physical helper refreshed stale generation')
                retired = dict(old=old_generation, new=new_generation,
                    phase=registry.retire_poll(retirement, budget=ledger).phase)

        try:
            result = machine.run(fuel=1)
        except core.registry_api().CodeRegistryError as error:
            outcome = {'kind': 'registry_rejection', 'reason': error.code}
            break
        if trap is not None:
            require(result['kind'] == 'trap' and result['reason'] == trap, 'native/Core trap mismatch')
            require(session._ref(memory_ref(), 'memory') == captured_before, 'guard failure partially wrote Core memory')
            comparisons += 1
        elif expected is not None:
            if node['op'] == 'store':
                require(session._ref(memory_ref(), 'memory') == expected, 'native/Core full memory postimage mismatch')
            else:
                actual = frame.values[node['results'][0]['id']]
                if type(expected) is list:
                    for image, value in zip(expected, actual.data):
                        compare_raw(session, image, value.data)
                else:
                    compare_raw(session, expected, actual.data)
            comparisons += 1
        if numeric_expected is not None:
            actual = frame.values[node['results'][0]['id']]
            expected_list = numeric_expected if type(numeric_expected) is list else [numeric_expected]
            actual_list = list(actual.data) if type(numeric_expected) is list else [actual]
            for image, value in zip(expected_list, actual_list):
                require(image['state'] == value.state and image['bits'] == (value.data if value.state == 'concrete' else 0),
                        'native/Core numeric observation mismatch')
                comparisons += 1
        if result['kind'] != 'resource' or result.get('reason') != 'fuel':
            outcome = result
            break
    else:
        raise RuntimeError('actual generic step bound')
    owner.assert_snapshot()
    if foreign is not None:
        foreign[0].assert_snapshot()
    actual_outcome = 'return' if outcome['kind'] == 'return' else outcome['reason']
    expected_outcome = core.EXPECTED.get(profile, 'code_address_invalid')
    require(actual_outcome == expected_outcome, 'actual outcome mismatch ' + repr(outcome))
    if profile == 'relay':
        require(outcome['values'][0].data == 42 and entries == returns == 8
                and len(registry._permits) == len(registry._entries) == 1, 'genuine bind/call42 required')
    else:
        require(not registry._permits and not registry._entries, 'negative issued call authority')
    require(not machine.exposed_code and not machine.memory.exposed and not registry._exposed_code
            and not registry._exposed_address, 'physical helpers/numeric bitcasts exposed pointer')
    return dict(profile=profile, outcome=actual_outcome,
        return_value=outcome['values'][0].data if outcome['kind'] == 'return' else None,
        helper_entries=entries, helper_returns=returns, stores=sum(e[0] == 'store' for e in machine.memory.effects),
        loads=sum(e[0] == 'load' for e in machine.memory.effects), permits=len(registry._permits),
        entries=len(registry._entries), comparisons=comparisons, native_calls=session.native_calls,
        reconstruction=reconstruction, retirement=retired, native_traps=native_traps,
        original_snapshots_unchanged=True, source_fact_authority=False, semantic_admission=False,
        native_guest_execution=False, backend_emission=False, optimize=sys.flags.optimize,
        scope='Fresh actual generic Machine + independent native physical model comparisons, roots retained; no sourceABI2/init/extractor/LLVM semantic execution.')
