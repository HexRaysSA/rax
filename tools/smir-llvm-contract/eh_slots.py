"""Compiler-private opaque exception variables -> pruned SSA reference.

No LLVM parser/backend or execution authority. Input is the exact bounded logical
view documented by LLVM-CC041; LLVM SSA/slot declaration grammar is separately
verified before producing this view. No opaque value is represented in memory.
"""
from collections import deque
import re
import json
from pathlib import Path

CONTRACT = json.loads((Path(__file__).resolve().parents[2] /
    'docs/specifications/smir/portable/llvm/eh-slot-contract.json').read_text())
QUOTAS = CONTRACT['quotas']

from canonical import require

def keys(value, expected):
    require(type(value) is dict and set(value) == set(expected.split()), 'E-EH-SLOT-PROFILE')

NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_.]*\Z', re.ASCII)
PREFIX = 'eh_phi_'


def checked(source):
    keys(source, 'revision slots parameters entry blocks')
    require(source['revision'] == 'llvm-eh-slots-v1', 'E-EH-SLOT-PROFILE')
    require(type(source['slots']) is list and len(source['slots']) <= QUOTAS['max_slots'],
            'E-EH-SLOT-RESOURCE')
    for slot in source['slots']:
        require(type(slot) is int and 0 <= slot < 2**32, 'E-EH-SLOT-ID')
    require(source['slots'] == sorted(set(source['slots'])), 'E-EH-SLOT-DECLARATION')
    require(type(source['blocks']) is list and 1 <= len(source['blocks']) <= QUOTAS['max_blocks'],
            'E-EH-SLOT-RESOURCE')
    require(len(source['slots']) * len(source['blocks']) <= QUOTAS['max_slot_block_cells'],
            'E-EH-SLOT-RESOURCE')
    require(all(type(b) is dict and type(b.get('ops')) is list for b in source['blocks']) and
            sum(len(b['ops']) for b in source['blocks']) <= QUOTAS['max_operations'],
            'E-EH-SLOT-RESOURCE')
    require(type(source['parameters']) is list, 'E-EH-SLOT-PROFILE')
    names, definitions, blocks = set(), {}, {}

    def name(value):
        require(type(value) is str and NAME.fullmatch(value) and not value.startswith(PREFIX),
                'E-EH-SLOT-NAME')
        return value

    name(source['entry'])
    for param in source['parameters']:
        name(param)
        require(param not in names, 'E-EH-SLOT-DUPLICATE-VALUE')
        names.add(param)
        definitions[param] = None
    for b in source['blocks']:
        keys(b, 'id ops successors return')
        identity = name(b['id'])
        require(identity not in blocks, 'E-EH-SLOT-DUPLICATE-BLOCK')
        require(type(b['ops']) is list and type(b['successors']) is list and
                len(b['successors']) <= 2 and (b['return'] is None) == bool(b['successors']),
                'E-EH-SLOT-PROFILE')
        for target in b['successors']:
            name(target)
        if b['return'] is not None:
            name(b['return'])
        for position, op in enumerate(b['ops']):
            require(type(op) is dict and op.get('op') in {'get', 'set', 'observe'},
                    'E-EH-SLOT-ESCAPE')
            if op['op'] == 'observe':
                keys(op, 'op value')
            else:
                keys(op, 'op slot ' + ('result' if op['op'] == 'get' else 'value'))
                require(type(op['slot']) is int and op['slot'] in source['slots'],
                        'E-EH-SLOT-ID')
            if 'value' in op:
                name(op['value'])
            if op['op'] == 'get':
                result = name(op['result'])
                require(result not in names, 'E-EH-SLOT-DUPLICATE-VALUE')
                names.add(result)
                definitions[result] = (identity, position)
        blocks[identity] = b
    require(not set(blocks) & names, 'E-EH-SLOT-NAME')
    require(source['entry'] in blocks, 'E-EH-SLOT-ENTRY')
    pred = {b: [] for b in blocks}
    for b in blocks.values():
        for target in b['successors']:
            require(target in blocks, 'E-EH-SLOT-BLOCK')
            pred[target].append(b['id'])  # Preserve duplicate edge multiplicity.
    require(not pred[source['entry']], 'E-EH-SLOT-ENTRY-PREDECESSOR')
    pending, reached = deque([source['entry']]), {source['entry']}
    while pending:
        for target in blocks[pending.popleft()]['successors']:
            if target not in reached:
                reached.add(target)
                pending.append(target)
    require(reached == set(blocks), 'E-EH-SLOT-UNREACHABLE')
    dom = {b: ({b} if b == source['entry'] else set(blocks)) for b in blocks}
    changed = True
    while changed:
        changed = False
        for b in blocks:
            if b == source['entry']:
                continue
            value = {b} | set.intersection(*(dom[p] for p in pred[b]))
            if value != dom[b]:
                dom[b], changed = value, True
    for b in blocks.values():
        uses = [(i, op['value']) for i, op in enumerate(b['ops']) if 'value' in op]
        if b['return'] is not None:
            uses.append((len(b['ops']), b['return']))
        for position, value in uses:
            require(value in definitions, 'E-EH-SLOT-SSA-REFERENCE')
            definition = definitions[value]
            require(definition is None or (definition[0] in dom[b['id']] and
                    (definition[0] != b['id'] or definition[1] < position)), 'E-EH-SLOT-SSA-DOMINANCE')
    return blocks, pred


def eliminate(source):
    """Exact pruned block-parameter SSA; conservative O(N^6) time/O(N^2) space.

    N counts slots, CFG edges and source operations. Reference quotas deliberately
    reject >512 blocks. Provisional phis are live-in slots; trivial phis removed.
    No default poison/undef or opaque allocation is created.
    """
    blocks, pred = checked(source)
    slots = source['slots']
    use, defs = {}, {}
    for identity, block in blocks.items():
        use[identity], defs[identity] = set(), set()
        for op in block['ops']:
            if op['op'] == 'get' and op['slot'] not in defs[identity]:
                use[identity].add(op['slot'])
            elif op['op'] == 'set':
                defs[identity].add(op['slot'])
    live = {b: set() for b in blocks}
    uninitialized = {b: set() for b in blocks}
    changed = True
    while changed:
        changed = False
        for b, block in blocks.items():
            after = set().union(*(live[s] for s in block['successors']))
            value = use[b] | (after - defs[b])
            if value != live[b]:
                live[b], changed = value, True
    changed = True
    while changed:
        changed = False
        for b in blocks:
            before = (set(slots) if b == source['entry'] else
                      set().union(*(uninitialized[p] for p in pred[b])))
            value = before - defs[b]
            if value != uninitialized[b]:
                uninitialized[b], changed = value, True
    for b, block in blocks.items():
        before = (set(slots) if b == source['entry'] else
                  set().union(*(uninitialized[p] for p in pred[b])))
        for op in block['ops']:
            if op['op'] == 'get':
                require(op['slot'] not in before, 'E-EH-SLOT-UNINITIALIZED')
            elif op['op'] == 'set':
                before.discard(op['slot'])
    require(sum(len(live[b]) for b in blocks if b != source['entry']) <= QUOTAS['max_generated_phis'],
            'E-EH-SLOT-RESOURCE')
    aliases, phis, ends, output = {}, {}, {}, []
    for ordinal, (b, block) in enumerate(blocks.items()):
        current, block_phis = {}, []
        if b != source['entry']:
            for slot in sorted(live[b]):
                result = PREFIX + str(ordinal) + '_' + str(slot)
                phi = {'result': result, 'slot': slot, 'incoming': []}
                current[slot] = result
                phis[result] = phi
                block_phis.append(phi)
        operations = []
        for op in block['ops']:
            if op['op'] == 'set':
                current[op['slot']] = op['value']
            elif op['op'] == 'get':
                require(op['slot'] in current, 'E-EH-SLOT-INVARIANT')
                aliases[op['result']] = current[op['slot']]
            else:
                operations.append(dict(op))
        ends[b] = current
        output.append({'id': b, 'phis': block_phis, 'ops': operations,
                       'successors': list(block['successors']), 'return': block['return']})
    for block in output:
        for phi in block['phis']:
            for predecessor in pred[block['id']]:
                require(phi['slot'] in ends[predecessor], 'E-EH-SLOT-INVARIANT')
                phi['incoming'].append({'block': predecessor, 'value': ends[predecessor][phi['slot']]})

    def resolve(value):
        seen, trail = set(), []
        while value in aliases:
            require(value not in seen, 'E-EH-SLOT-ALIAS-CYCLE')
            seen.add(value)
            trail.append(value)
            value = aliases[value]
        for old in trail:
            aliases[old] = value
        return value

    changed = True
    while changed:
        changed = False
        for name, phi in list(phis.items()):
            values = {resolve(pair['value']) for pair in phi['incoming']} - {name}
            require(values, 'E-EH-SLOT-UNINITIALIZED')
            if len(values) == 1:
                aliases[name] = values.pop()
                del phis[name]
                changed = True
    for b in output:
        b['phis'] = [dict(result=p['result'], incoming=[dict(block=x['block'], value=resolve(x['value']))
                      for x in p['incoming']]) for p in b['phis'] if p['result'] in phis]
        for op in b['ops']:
            op['value'] = resolve(op['value'])
        if b['return'] is not None:
            b['return'] = resolve(b['return'])
    return {'revision': 'llvm-eh-ssa-v1', 'parameters': list(source['parameters']),
            'entry': source['entry'], 'blocks': output}


def execute(document, path, arguments):
    """Finite reference path semantics; opaque labels model identity, not bytes.

    Original uses logical slots. SSA output reads simultaneous edge phis. These
    independent state update rules check preservation; no native guest executes.
    """
    require(path and path[0] == document['entry'], 'E-EH-PATH')
    require(set(arguments) == set(document['parameters']), 'E-EH-ARGUMENTS')
    blocks = {b['id']: b for b in document['blocks']}
    env, cells, observed, predecessor = dict(arguments), {}, [], None
    for step, identity in enumerate(path):
        require(identity in blocks, 'E-EH-PATH')
        b = blocks[identity]
        simultaneous = {}
        for phi in b.get('phis', []):
            incoming = [x['value'] for x in phi['incoming'] if x['block'] == predecessor]
            require(incoming and len(set(incoming)) == 1, 'E-EH-PHI-EDGE')
            simultaneous[phi['result']] = env[incoming[0]]
        env.update(simultaneous)
        for op in b['ops']:
            if op['op'] == 'set':
                cells[op['slot']] = env[op['value']]
            elif op['op'] == 'get':
                require(op['slot'] in cells, 'E-EH-SLOT-UNINITIALIZED')
                env[op['result']] = cells[op['slot']]
            else:
                observed.append(env[op['value']])
        if b['return'] is not None:
            require(step == len(path) - 1, 'E-EH-PATH')
            return {'returned': env[b['return']], 'observed': observed}
        require(step + 1 < len(path) and path[step + 1] in b['successors'], 'E-EH-PATH')
        predecessor = identity
    raise ValueError('E-EH-PATH-NO-RETURN')


def llvm_ir(document):
    """Deterministic LLVM-only witness emitter, not SMIR/backend emission."""
    original = document['revision'] == 'llvm-eh-slots-v1'
    if original:
        checked(document)
    e = 'target("smir.exception")'
    branches = [b for b in document['blocks'] if len(b['successors']) == 2]
    parameters = [e + ' %' + p for p in document['parameters']]
    parameters += ['i1 %eh_phi_control_' + str(i) for i, _ in enumerate(branches)]
    controls = {b['id']: i for i, b in enumerate(branches)}
    lines = ['target triple = "x86_64-unknown-linux-gnu"', 'declare void @opaque_observe(' + e + ')']
    if original:
        lines += ['declare ' + e + ' @__smir_eh_slot_get(i32)',
                  'declare void @__smir_eh_slot_set(i32, ' + e + ')']
    lines += ['define ' + e + ' @slot_witness(' + ', '.join(parameters) + ')' +
              (' !smir.eh.slots !0' if original else '') + ' {']
    for b in document['blocks']:
        lines.append(b['id'] + ':')
        for phi in b.get('phis', []):
            incoming = ', '.join('[ %' + x['value'] + ', %' + x['block'] + ' ]' for x in phi['incoming'])
            lines.append('  %' + phi['result'] + ' = phi ' + e + ' ' + incoming)
        for op in b['ops']:
            if op['op'] == 'get':
                lines.append('  %' + op['result'] + ' = call ' + e + ' @__smir_eh_slot_get(i32 ' + str(op['slot']) + ')')
            elif op['op'] == 'set':
                lines.append('  call void @__smir_eh_slot_set(i32 ' + str(op['slot']) + ', ' + e + ' %' + op['value'] + ')')
            else:
                lines.append('  call void @opaque_observe(' + e + ' %' + op['value'] + ')')
        if b['return'] is not None:
            lines.append('  ret ' + e + ' %' + b['return'])
        elif len(b['successors']) == 1:
            lines.append('  br label %' + b['successors'][0])
        else:
            lines.append('  br i1 %eh_phi_control_' + str(controls[b['id']]) + ', label %' + b['successors'][0] + ', label %' + b['successors'][1])
    lines += ['}']
    if original:
        lines.append('!0 = !{i32 1' + ''.join(', i32 ' + str(s) for s in document['slots']) + '}')
    return '\n'.join(lines) + '\n'
