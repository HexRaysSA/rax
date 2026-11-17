"""Canonical syntactic SSA liveness at after-phi execution frontiers."""
from common import require
from candidate.operations import optional
from candidate.verify import Verified, targets, uses


def live_before(admitted, function_id, block_id, operation):
    require(isinstance(admitted, Verified), 'liveness_admission')
    function = next((item for item in admitted.functions_root['functions'] if item['id'] == function_id), None)
    require(function is not None, 'liveness_function')
    blocks = {item['id']: item for item in function['blocks']}
    require(block_id in blocks and type(operation) is int and 0 <= operation <= len(blocks[block_id]['ops']),
            'liveness_frontier')
    eh = next((item for item in admitted.exceptions_root['functions'] if item['function'] == function_id),
              {'regions': [], 'actions': []})
    regions = {item['id']: item for item in eh['regions']}
    actions = {item['id']: item for item in eh['actions']}
    edge_definitions = {identifier: set() for identifier in blocks}
    for block in blocks.values():
        term = block['term']
        if term['op'] == 'invoke':
            edge_definitions[term['normal']['target']] = {item['id'] for item in term['normal']['results']}
            edge_definitions[term['unwind']['target']] = {term['unwind']['exception']['id']}

    def term_uses(term):
        result = set(uses(term))
        if term['op'] == 'invoke':
            current = term['region']
            while current is not None:
                region = regions[current]
                selected = list(region['exit_actions'])
                for handler in region['handlers']:
                    selected += handler['cleanup_actions']
                    if handler['catch_copy'] is not None:
                        selected.append(optional(handler['catch_copy']))
                for action_id in selected:
                    result.update(capture['source']['value'] for capture in actions[action_id]['captures']
                                  if capture['source']['kind'] == 'value')
                current = optional(region['parent'])
        return result

    def before(identifier, position, outgoing):
        block = blocks[identifier]
        live = set(outgoing) | term_uses(block['term'])
        for node in reversed(block['ops'][position:]):
            live.difference_update(result['id'] for result in node['results'])
            live.update(uses(node))
        return live

    incoming = {identifier: set() for identifier in blocks}
    outgoing = {identifier: set() for identifier in blocks}
    changed = True
    while changed:
        changed = False
        for identifier, block in reversed(list(blocks.items())):
            result = set()
            for target in targets(block['term']):
                successor = blocks[target]
                required = incoming[target] - edge_definitions[target]
                required -= {phi['result']['id'] for phi in successor['phis']}
                result |= required
                for phi in successor['phis']:
                    result.add(next(item['value'] for item in phi['incoming'] if item['predecessor'] == identifier))
            new_in = before(identifier, 0, result)
            changed |= new_in != incoming[identifier] or result != outgoing[identifier]
            incoming[identifier], outgoing[identifier] = new_in, result
    return sorted(before(block_id, operation, outgoing[block_id]))
