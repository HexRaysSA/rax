#!/usr/bin/env python3
"""Run cases on the Python reference machine and print one JSON report each.

    python3 -B oracle.py machine OBJECT < cases.json
    python3 -B oracle.py assemble SOURCE.json EXPECTED.smo

`machine` verifies OBJECT once with the reference verifiers and then runs each
case on a fresh reference Machine in this process. It does not attach the
source registry, so it serves modules whose calls carry no source plan; the
reference CLI's registry setup grows with module size and takes tens of
seconds for a module of twenty functions.

The reference Machine does not implement the internal runtime helpers itself;
its caller supplies them. `helper_adapters` implements `stack_alloc`,
`lifetime_start` and `lifetime_end` on the reference Memory. The helper catalog
leaves poison and undef arguments open; here, as in the Rust interpreter, an
undef size is zero and a poison size is undefined behaviour. `stage_data`
creates the data segments and applies the relocations, which the reference
Machine also leaves to its caller. Input is a JSON array of
`{"function": id, "arguments": [little-endian hex, ...], "fuel": n,
"max_frames": n, "max_memory_bytes": n}`; output is a JSON array of reports shaped like the CLI's.

`assemble` checks that EXPECTED.smo is exactly SOURCE.json assembled.
"""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
SPEC = ROOT / 'docs/specifications/smir/portable'
sys.path[:0] = [str(ROOT / 'tools/smir-format'), str(ROOT / 'tools/smir-format/execution')]

from codec import CandidateCodec  # noqa: E402


def codec():
    return CandidateCodec({owner: json.loads((SPEC / 'schema' / owner / 'candidate.json').read_text())
                           for owner in ('execution', 'runtime', 'abi')})


def helper_adapters(roots, types):
    """Callables for the module's internal helper imports, keyed as the Machine expects."""
    from candidate.memory import GuestFault
    from candidate.values import Value

    def count(value, poison_code):
        if value.state == 'poison':
            raise GuestFault(poison_code, True)
        return 0 if value.state == 'undef' else value.data

    def stack_alloc(result_type):
        def call(engine, arguments):
            size, alignment = arguments
            pointer = engine.memory.allocate(count(size, 'ub_allocation_size'), alignment.data,
                                             owner=engine.stack[-1].activation)
            return [Value(result_type, 'concrete', pointer)]
        return call

    def lifetime(start):
        def call(engine, arguments):
            pointer = engine.pointer(arguments[0])
            engine.memory.lifetime(pointer, count(arguments[1], 'ub_lifetime_size'), start)
            return []
        return call

    adapters = {}
    for record in roots[6]['imports']:
        if record['kind'] != 'internal' or record['namespace'] != 'smir.internal.v1':
            continue
        if record['name'] == 'stack_alloc':
            adapters['self', record['id']] = stack_alloc(types.get(record['signature'])['results'][0])
        elif record['name'] in ('lifetime_start', 'lifetime_end'):
            adapters['self', record['id']] = lifetime(record['name'] == 'lifetime_start')
    return adapters


def register_functions(engine, roots):
    """Give every function of the module a code token and bind its symbol to it.

    The reference Machine issues tokens 2, 4, 6, ... in registration order.
    Registering in function order gives function number i (from zero) the
    token 2 * (i + 1), which is what the Rust interpreter uses.
    """
    signatures = {function['id']: function['signature'] for function in roots[3]['functions']}
    defined = {symbol['definition']['some']['target']['id']: symbol['id']
               for symbol in roots[2]['symbols']
               if symbol['kind'] == 'function' and symbol['definition'] is not None
               and symbol['definition']['some']['kind'] == 'function'}
    for function in sorted(signatures):
        if function in defined:
            target = {'module': {'kind': 'self'}, 'id': function}
            engine.register_function({'module': {'kind': 'self'}, 'id': defined[function]}, target,
                                     signatures[function])


def stage_data(engine, roots):
    """Create the module's data segments in the Machine's memory and bind its data symbols.

    The reference Machine takes the address of each data symbol from its
    caller. This stages the segments the way the Rust interpreter does: one
    object per segment in identifier order, allocated before any stack
    object; then the relocations; then read-only segments are sealed.
    Returns False if the segments do not fit the memory limit.
    """
    from candidate.memory import GuestFault
    from candidate.raw import Raw
    from candidate.values import Pointer

    memory = engine.memory
    objects = {}
    try:
        for segment in roots[4]['segments']:
            image = bytes.fromhex(segment['initial']) + bytes(segment['zero_fill'])
            tail = {'defined': (0, 0), 'poison': (255, 0), 'undef': (0, 255)}[segment['zero_shadow']]
            poison = bytes.fromhex(segment['poison']) + bytes([tail[0]]) * segment['zero_fill']
            undef = bytes.fromhex(segment['undef']) + bytes([tail[1]]) * segment['zero_fill']
            pointer = memory.allocate(len(image), segment['alignment'])
            memory.objects[pointer.origin]['bytes'] = [
                Raw.integer(8, bits & ~(bad | free) & 255, bad, free)
                for bits, bad, free in zip(image, poison, undef)]
            objects[segment['id']] = pointer
    except GuestFault as fault:
        if fault.code.startswith('resource_'):
            return False
        raise
    symbols = {symbol['id']: objects[symbol['definition']['some']['segment']]
               for symbol in roots[2]['symbols']
               if symbol['kind'] == 'data' and symbol['definition'] is not None
               and symbol['definition']['some']['kind'] == 'data'}
    for relocation in roots[5]['relocations']:
        base = objects[relocation['source']]
        store = memory.objects[base.origin]['bytes']
        if relocation['kind'] == 'function_token':
            # The callable pointer register_functions bound to the symbol.
            raw = Raw.pointer(engine.symbols['self', relocation['target']['id']])
            store[relocation['offset']:relocation['offset'] + 8] = [
                raw.slice(bit, 8) for bit in range(0, 64, 8)]
            continue
        target = symbols[relocation['target']['id']]
        address = (target.address + relocation['addend']) % 2 ** 64
        if relocation['kind'] == 'data_address':
            raw = Raw.pointer(Pointer(address, target.origin, target.generation))
        else:
            # An address published as an integer exposes its object.
            memory.expose(target)
            raw = Raw.integer(8 * relocation['width'], address % 2 ** (8 * relocation['width']))
        store[relocation['offset']:relocation['offset'] + relocation['width']] = [
            raw.slice(bit, 8) for bit in range(0, raw.width, 8)]
    for segment in roots[4]['segments']:
        memory.objects[objects[segment['id']].origin]['mutable'] = segment['mutable']
    engine.symbols.update({('self', identifier): pointer for identifier, pointer in symbols.items()})
    return True


def verify_once():
    """Make the reference Machine verify a module once instead of per instance.

    Every Machine re-verifies the admitted module in its constructor, to guard
    against a caller mutating a previous admission. All cases here run on one
    admission that this script never mutates, and for a module of forty
    functions the repeated verification costs several times more than the
    runs themselves. The first result is reused for the same admitted roots.
    """
    import candidate.machine as reference
    verify = reference.verify
    cache = {}

    def cached(types_root, functions_root, exceptions_root, *rest):
        key = (id(types_root), id(functions_root), id(exceptions_root))
        if key not in cache:
            # Keep the roots alive so that their identities stay unique.
            cache[key] = (verify(types_root, functions_root, exceptions_root, *rest),
                          types_root, functions_root, exceptions_root)
        return cache[key][0]

    reference.verify = cached


def machine(path):
    from candidate.context import RootContext
    from candidate.machine import Machine
    from candidate.values import Value

    decoded = codec().decode(Path(path).read_bytes())
    context = RootContext(decoded.roots)
    context.verify_abi()
    context.verify_execution()
    functions = {item['id']: item for item in context.execution_checked.functions_root['functions']}
    adapters = helper_adapters(decoded.roots, context.types)
    verify_once()
    reports = []
    for case in json.load(sys.stdin):
        signature = context.types.get(functions[case['function']]['signature'])
        arguments = [Value(reference, 'concrete', int.from_bytes(bytes.fromhex(bits), 'little'))
                     for reference, bits in zip(signature['params'], case['arguments'], strict=True)]
        engine = Machine(context.execution_checked, imports=adapters, max_bytes=case['max_memory_bytes'])
        register_functions(engine, decoded.roots)
        if not stage_data(engine, decoded.roots):
            reports.append({'status': 'resource', 'steps': 0, 'code': 'resource_memory'})
            continue
        engine.start(case['function'], arguments)
        result = engine.run(fuel=case['fuel'], max_frames=case['max_frames'])
        report = {'status': result['kind'], 'steps': engine.steps}
        if result['kind'] == 'return':
            report['values'] = [
                {'bits_le': value.data.to_bytes((context.types.get(reference)['bits'] + 7) // 8, 'little').hex()}
                if value.state == 'concrete' else {'state': value.state}
                for reference, value in zip(signature['results'], result['values'], strict=True)]
        else:
            report['code'] = result.get('reason', result['kind'])
            for field in ('function', 'block', 'operation'):
                if field in result:
                    report[field] = result[field]
        reports.append(report)
    json.dump(reports, sys.stdout)


def assemble(source, expected):
    import smir
    produced = smir.assemble(json.loads(Path(source).read_text()))
    if produced != Path(expected).read_bytes():
        sys.exit(f'{expected} is not {source} assembled; rerun smir.py assemble')


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == 'machine':
        machine(sys.argv[2])
    elif len(sys.argv) == 4 and sys.argv[1] == 'assemble':
        assemble(sys.argv[2], sys.argv[3])
    else:
        sys.exit(__doc__)
