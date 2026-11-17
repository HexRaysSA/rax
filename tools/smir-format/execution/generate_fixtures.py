"""Regenerate owned, hand-designed semantic cases; expected results are explicit."""
from copy import deepcopy
import json

from common import SPEC


def declaration(identifier, type_id=1):
    return {'id': identifier, 'type': type_id}


def constant(identifier, bits, type_id=1):
    return {'op': 'const', 'out': declaration(identifier, type_id), 'bits': bits}


def binary(op, out, a, b, flags=None):
    result = {'op': op, 'out': declaration(out), 'a': a, 'b': b}
    if op in {'add', 'sub', 'mul', 'shl', 'lshr', 'ashr', 'udiv', 'sdiv'}:
        result['flags'] = [] if flags is None else flags
    return result


def block(identifier, ops, term, phis=None):
    return {'id': identifier, 'phis': [] if phis is None else phis, 'ops': ops, 'term': term}


def module(ops, results=None, term=None):
    return {'revision': 'integer_core_draft_v1',
            'types': [{'kind': 'int', 'id': 0, 'bits': 1}, {'kind': 'int', 'id': 1, 'bits': 8}],
            'functions': [{'id': 0, 'params': [], 'results': [1] if results is None else results,
                           'entry': 0, 'blocks': [block(0, ops, term or {'op': 'return', 'values': [2]})]}]}


def cases():
    fixtures = []

    def accepted(name, document, expected, arguments=None):
        fixtures.append({'name': name, 'module': document, 'entry': 0,
                         'arguments': [] if arguments is None else arguments, 'expected': expected})

    bits = lambda value: {'kind': 'bits', 'bits': value}
    returns = lambda *values: {'kind': 'return', 'values': list(values)}
    wrapped = module([constant(0, 'ff'), constant(1, '01'), binary('add', 2, 0, 1)])
    accepted('wrapping_add_i8', wrapped, returns(bits('00')))
    poisoned = deepcopy(wrapped)
    poisoned['functions'][0]['blocks'][0]['ops'][2]['flags'] = ['nuw']
    accepted('unused_poison_is_deferred', module(poisoned['functions'][0]['blocks'][0]['ops'],
             term={'op': 'return', 'values': [1]}), returns(bits('01')))
    accepted('poison_result_is_not_immediate_ub', poisoned, returns({'kind': 'poison'}))
    frozen = deepcopy(poisoned)
    frozen['functions'][0]['blocks'][0]['ops'].append(
        {'op': 'freeze', 'out': declaration(3), 'value': 2})
    frozen['functions'][0]['blocks'][0]['term']['values'] = [3]
    accepted('freeze_poison_zero_refinement', frozen, returns(bits('00')))
    for op, left, right, result in [('sdiv', 'f9', '03', 'fe'), ('srem', 'f9', '03', 'ff'),
                                   ('ashr', '80', '07', 'ff'), ('lshr', '80', '07', '01')]:
        accepted(f'{op}_signed_boundary', module([constant(0, left), constant(1, right),
                                                binary(op, 2, 0, 1)]), returns(bits(result)))
    for op in ['sdiv', 'srem']:
        accepted(f'{op}_minimum_negative_one_ub', module([constant(0, '80'), constant(1, 'ff'),
                 binary(op, 2, 0, 1)]), {'kind': 'trap', 'code': 'ub_signed_div_overflow'})
    accepted('divide_zero_precise_frontier', module([constant(0, '01'), constant(1, '00'),
             binary('udiv', 2, 0, 1)]), {'kind': 'trap', 'code': 'ub_div_zero', 'operation': 2})
    accepted('exact_division_poison', module([constant(0, '07'), constant(1, '03'),
             binary('udiv', 2, 0, 1, ['exact'])]), returns({'kind': 'poison'}))
    accepted('shift_width_poison', module([constant(0, '01'), constant(1, '08'),
             binary('shl', 2, 0, 1)]), returns({'kind': 'poison'}))
    selected = module([constant(0, '01'), {'op': 'poison', 'out': declaration(1)},
                       constant(2, '00', 0), {'op': 'select', 'out': declaration(3),
                                             'cond': 2, 'true': 1, 'false': 0}],
                      term={'op': 'return', 'values': [3]})
    accepted('unselected_poison_is_not_propagated', selected, returns(bits('01')))
    control = module([{'op': 'poison', 'out': declaration(0, 0)}], [],
                     {'op': 'cbr', 'cond': 0, 'true': 1, 'false': 1})
    control['functions'][0]['blocks'].append(block(1, [], {'op': 'return', 'values': []}))
    accepted('poison_control_even_identical_targets', control,
             {'kind': 'trap', 'code': 'ub_control_value'})
    undef = deepcopy(control)
    undef['functions'][0]['blocks'][0]['ops'][0]['op'] = 'undef'
    accepted('undef_control_is_ub', undef, {'kind': 'trap', 'code': 'ub_control_value'})

    # Three phis exchange values over a self-loop. All read predecessor state.
    loop = module([], [1, 1], {'op': 'br', 'target': 1})
    fn = loop['functions'][0]
    fn['blocks'][0]['ops'] = [constant(0, '01'), constant(1, '02'), constant(2, '00'),
                            constant(3, '01'), constant(4, '03')]
    phis = [{'out': declaration(5), 'incoming': [{'block': 0, 'value': 0}, {'block': 1, 'value': 6}]},
            {'out': declaration(6), 'incoming': [{'block': 0, 'value': 1}, {'block': 1, 'value': 5}]},
            {'out': declaration(7), 'incoming': [{'block': 0, 'value': 2}, {'block': 1, 'value': 8}]}]
    fn['blocks'] += [block(1, [binary('add', 8, 7, 3),
                                  {'op': 'icmp', 'out': declaration(9, 0), 'a': 8, 'b': 4,
                                   'predicate': 'ult'}],
                              {'op': 'cbr', 'cond': 9, 'true': 1, 'false': 2}, phis),
                     block(2, [], {'op': 'return', 'values': [5, 6]})]
    accepted('phi_swap_cycle_simultaneous', loop, returns(bits('01'), bits('02')))

    # Recursive sum(n) = n + sum(n-1), with identical IDs in each activation.
    recursive = module([], [1], {'op': 'cbr', 'cond': 3, 'true': 1, 'false': 2})
    fn = recursive['functions'][0]
    fn['params'] = [declaration(0)]
    fn['blocks'][0]['ops'] = [constant(1, '00'), constant(2, '01'),
                             {'op': 'icmp', 'out': declaration(3, 0), 'a': 0, 'b': 1,
                              'predicate': 'eq'}]
    fn['blocks'] += [block(1, [], {'op': 'return', 'values': [1]}),
                     block(2, [binary('sub', 4, 0, 2),
                               {'op': 'call', 'outs': [declaration(5)], 'callee': 0, 'args': [4]},
                               binary('add', 6, 0, 5)], {'op': 'return', 'values': [6]})]
    accepted('recursive_activation_ids_are_isolated', recursive, returns(bits('37')), ['0a'])
    multi = module([{'op': 'call', 'outs': [declaration(0), declaration(1)], 'callee': 1, 'args': []}],
                   [1, 1], {'op': 'return', 'values': [1, 0]})
    multi['functions'].append({'id': 1, 'params': [], 'results': [1, 1], 'entry': 0,
                              'blocks': [block(0, [constant(0, 'a5'), constant(1, '5a')],
                                               {'op': 'return', 'values': [0, 1]})]})
    accepted('ordered_multi_results_and_continuation', multi, returns(bits('5a'), bits('a5')))
    tail = deepcopy(multi)
    tail['functions'][0]['blocks'][0] = block(0, [], {'op': 'tailcall', 'callee': 1, 'args': []})
    accepted('tailcall_replaces_activation', tail, returns(bits('a5'), bits('5a')))
    wide = module([constant(0, 'ff' * 8191 + '7f', 1), constant(1, '01' + '00' * 8191, 1),
                   binary('add', 2, 0, 1)])
    wide['types'][1]['bits'] = 65535
    accepted('maximum_integer_width_wrap', wide, returns(bits('00' * 8192)))

    def rejected(name, document, code):
        fixtures.append({'name': name, 'module': document, 'reject': code})

    invalid = deepcopy(wrapped)
    invalid['functions'][0]['blocks'][0]['ops'][1]['out']['id'] = 0
    rejected('duplicate_value_definition', invalid, 'duplicate')
    invalid = deepcopy(wrapped)
    invalid['functions'][0]['blocks'][0]['ops'][2]['a'] = 99
    rejected('unknown_value_reference', invalid, 'reference')
    invalid = deepcopy(wrapped)
    invalid['functions'][0]['blocks'][0]['ops'].reverse()
    rejected('use_before_definition', invalid, 'dominance')
    for name, mutator, code in [
            ('phi_duplicate_predecessor', lambda x: x['incoming'].append(deepcopy(x['incoming'][0])), 'phi'),
            ('phi_missing_predecessor', lambda x: x['incoming'].pop(), 'phi'),
            ('phi_non_predecessor', lambda x: x['incoming'][0].update(block=2), 'phi'),
            ('phi_wrong_incoming_type', lambda x: x['incoming'][0].update(value=9), 'dominance')]:
        invalid = deepcopy(loop)
        mutator(invalid['functions'][0]['blocks'][1]['phis'][0])
        rejected(name, invalid, code)
    invalid = deepcopy(wrapped)
    invalid['functions'][0]['blocks'][0]['ops'][2]['flags'] = ['exact']
    rejected('unknown_arithmetic_flag', invalid, 'flags')
    invalid = deepcopy(wrapped)
    invalid['functions'][0]['blocks'][0]['ops'][2]['extra'] = 1
    rejected('unknown_record_field', invalid, 'shape')
    invalid = deepcopy(wrapped)
    invalid['types'][1]['bits'] = 7
    rejected('constant_high_padding_bits', invalid, 'constant')
    invalid = deepcopy(multi)
    invalid['functions'][0]['blocks'][0]['ops'][0]['outs'].pop()
    rejected('call_result_signature_mismatch', invalid, 'call')
    invalid = deepcopy(multi)
    invalid['functions'][0]['blocks'][0]['ops'][0]['callee'] = 99
    rejected('missing_callee', invalid, 'call')
    invalid = deepcopy(wrapped)
    invalid['functions'][0]['blocks'].append(block(1, [], {'op': 'trap'}))
    rejected('unreachable_record_rejected', invalid, 'cfg')
    invalid = deepcopy(wrapped)
    invalid['types'][1]['bits'] = 65536
    rejected('overlarge_integer_type', invalid, 'type')
    return fixtures


def main():
    destination = SPEC / 'conformance/execution/cases.json'
    destination.write_text(json.dumps({'profile': 'integer_core_draft_v1', 'cases': cases()},
                                     indent=2) + '\n')


if __name__ == '__main__':
    main()
