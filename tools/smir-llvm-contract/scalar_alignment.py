"""Finite conditional value-body alignment of already supplied original SMIR."""
from dataclasses import dataclass, field
import weakref
import scalar_conditions as C
A = C.A
require, AlignmentError = (C.require, C.AlignmentError)
_ISSUED = weakref.WeakKeyDictionary()

@dataclass(frozen=True, eq=False)
class ScalarAlignment:
    data: object
    witness: object
    conditions: object
    owner: object
    stamp: object
    ledger: object = field(repr=False)

    def report(self, *, budget):
        C.ledger(budget)
        budget.charge(work=8 * (len(_ISSUED) + 1) ** 2, edges=2, copied_bytes=128)
        row = _ISSUED.get(self)
        require(row is not None and row == (id(self.data), id(self.witness), id(self.conditions), id(self.owner), id(self.stamp), id(budget)) and (self.ledger is budget), 'SCALAR_RESULT_ISSUANCE')
        C.require_issued(self.conditions, self.witness, budget)
        cls = A.R.apis()[0].RootContext
        require(cls.prepare_source_data(self.owner, budget=budget) is self.stamp, 'SCALAR_SOURCE_CHANGED')
        return A.thaw(self.data, budget)

def verify(witness, original_owner, mapping, *, conditions=None, budget):
    C.ledger(budget)
    require(type(witness) is A.ObservationWitness, 'SCALAR_ORIGINAL_AST')
    source = A.ObservationWitness.report(witness, budget=budget)
    require(conditions is not None, 'SCALAR_SOURCE_CONDITIONS_UNAVAILABLE', kind='unavailable')
    C.require_issued(conditions, witness, budget)
    observed = C.ConditionWitness.report(conditions, budget=budget)
    cls = A.R.apis()[0].RootContext
    require(type(original_owner) is cls, 'SCALAR_ORIGINAL_OWNER')
    from candidate import root3_context as V3, factory_meter as M
    owner = original_owner
    V3.owner_budget(owner, budget)
    stamp = cls.prepare_source_data(owner, budget=budget)
    require(owner.sections[3]['payload_revision'] == 3, 'SCALAR_GENUINE_V3_REQUIRED')
    doc, schema_raw = C.schema(budget)
    captured = A.R.capture(mapping, budget)
    A.R.shape(doc['$defs']['mapping'], captured, doc['$defs'], budget)
    require(captured['source_sha256'] == source['source_sha256'] == observed['source_sha256'], 'SCALAR_SOURCE_IDENTITY')
    require(captured['smir_module_digest'] == owner.sections[2]['manifest']['identity'] and captured['smir_root3_sha256'] == dict(stamp.root_digests)[3].hex(), 'SCALAR_MODULE_IDENTITY')
    require(observed['warning_count'] == 0, 'SCALAR_COMPILER_WARNINGS_UNAVAILABLE', kind='unavailable')
    require(observed['cplusplus23'] is True and observed['signed_overflow_behavior'] == 0, 'SCALAR_LANGUAGE_PROFILE_UNAVAILABLE', kind='unavailable')
    budget.charge(work=16 * len(source['raw']['functions']), edges=len(source['raw']['functions']))
    af = next((f for f in source['raw']['functions'] if f['declaration'] == captured['ast_function']), None)
    cf = next((f for f in observed['functions'] if f['declaration'] == captured['ast_function']), None)
    require(af is not None and cf is not None, 'SCALAR_AST_FUNCTION')
    cond = cf['conditions']
    budget.charge(work=128 + 16 * len(cond['parameters']), copied_bytes=1024)
    require(not any((cond[k] for k in ('has_attributes', 'no_return', 'constexpr', 'immediate', 'method', 'variadic', 'builtin_id', 'extern_c', 'storage_class', 'result_overflow_behavior_type'))) and cond['result_plain_builtin_integer'], 'SCALAR_FUNCTION_CONDITIONS_UNAVAILABLE', kind='unavailable')
    require([p['declaration'] for p in cond['parameters']] == af['parameters'], 'SCALAR_PARAMETER_CONDITION_IDENTITY')
    for p in cond['parameters']:
        require(not (p['has_attributes'] or p['has_default_argument'] or p['overflow_behavior_type']) and p['plain_builtin_integer'], 'SCALAR_PARAMETER_CONDITIONS_UNAVAILABLE', kind='unavailable')
    nodes, decls, atypes = ({}, {}, {})
    for rows, table in [(af['nodes'], nodes), (source['raw']['declarations'], decls), (source['raw']['types'], atypes)]:
        budget.charge(work=8 * len(rows), edges=len(rows), copied_bytes=128 * len(rows))
        for row in rows:
            table[row['id']] = row
    proto_id = decls[af['declaration']]['canonical_type']['some']
    proto = atypes[proto_id]['shape']
    require(proto['kind'] == 'function' and proto['calling_convention_inspection'] == 0 and (proto['exception_specification_inspection'] == 0), 'SCALAR_PROTOTYPE_CONDITIONS_UNAVAILABLE', kind='unavailable')
    root = nodes[af['body']]
    require(root['semantic']['kind'] == 'compound' and len(root['children']) == 1, 'SCALAR_STATEMENT_PROFILE_UNAVAILABLE', kind='unavailable')
    ret = nodes[root['children'][0]]
    require(ret['semantic']['kind'] == 'return' and len(ret['semantic']['operands']) == 1 and (ret['semantic']['operands'][0]['node'] is not None), 'SCALAR_RETURN_PROFILE_UNAVAILABLE', kind='unavailable')
    require(captured['return_node'] == ret['id'], 'SCALAR_RETURN_NODE')
    ret_expr = ret['semantic']['operands'][0]['node']['some']
    M.collection(budget, len(af['nodes']), 64)
    expressions = {n['id']: n for n in af['nodes'] if n['semantic']['type'] is not None}
    M.collection(budget, len(nodes) + len(expressions), 64)
    require(set(nodes) == set(expressions) | {root['id'], ret['id']}, 'SCALAR_STATEMENT_PROFILE_UNAVAILABLE', kind='unavailable')
    require([r['node'] for r in cond['expression_types']] == sorted(expressions), 'SCALAR_EXPRESSION_CONDITION_EXHAUSTION')
    for row in cond['expression_types']:
        require(row['plain_builtin_integer'] and (not row['overflow_behavior_type']), 'SCALAR_EXPRESSION_CONDITIONS_UNAVAILABLE', kind='unavailable')

    def source_type(identifier):
        require(identifier in atypes, 'SCALAR_AST_TYPE')
        t = atypes[identifier]
        s = t['shape']
        require(s['kind'] == 'integer' and s['width'] in (8, 16, 32, 64) and (not s['boolean']) and (not (t['const'] or t['volatile'] or t['restrict'])), 'SCALAR_INTEGER_PROFILE_UNAVAILABLE', kind='unavailable')
        return s
    M.collection(budget, len(proto['parameters']) + len(expressions), 64)
    needed_types = set(proto['parameters']) | {proto['result']}
    for n in expressions.values():
        needed_types.add(n['semantic']['type']['some'])
    type_map, node_map = ({}, {})
    budget.charge(work=16 * (len(needed_types) + len(expressions)), edges=len(expressions), copied_bytes=256 * (len(needed_types) + len(expressions)))
    for row in captured['types']:
        require(row['type'] not in type_map, 'SCALAR_TYPE_MAPPING_DUPLICATE')
        source_type(row['type'])
        type_map[row['type']] = row['execution']
    require(set(type_map) == needed_types, 'SCALAR_TYPE_MAPPING_EXHAUSTION')
    for row in captured['nodes']:
        require(row['node'] not in node_map, 'SCALAR_NODE_MAPPING_DUPLICATE')
        node_map[row['node']] = row['value']
    require(set(node_map) == set(expressions), 'SCALAR_NODE_MAPPING_EXHAUSTION')
    raw_contract = V3.codec().raw_contract(owner.sections[3]['source_contract'], budget=budget)
    budget.charge(work=8 * len(raw_contract))
    require(raw_contract['revision'] == 1 and all((type(v) is list and (not v) for k, v in raw_contract.items() if k != 'revision')), 'SCALAR_EMBEDDED_SOURCE_PROFILE_UNAVAILABLE', kind='unavailable')
    cls.verify_abi(owner)
    checked = cls.verify_candidate_body(owner, budget=budget)
    require(type(checked) is V3.V3BodyChecks and checked.owner is owner and (checked.stamp is stamp), 'SCALAR_ORIGINAL_BODY')
    require(A.plain_equal(checked.verified.functions_root, owner.sections[3], budget), 'SCALAR_FULL_ROOT')
    body = checked.verified
    for function in M.iter_rows(budget, body.functions_root['functions']):
        for bb in M.iter_rows(budget, function['blocks']):
            for operation in M.iter_rows(budget, bb['ops']):
                require(operation['op'] != 'source_journal_observe', 'SCALAR_MODULE_OBSERVER_UNAVAILABLE', kind='unavailable')
    budget.charge(work=16 * len(body.functions_root['functions']), edges=len(body.functions_root['functions']))
    sf = next((f for f in body.functions_root['functions'] if f['id'] == captured['smir_function']), None)
    require(sf is not None, 'SCALAR_SMIR_FUNCTION')
    require(len(sf['blocks']) == 1 and sf['entry'] == sf['blocks'][0]['id'] and (not sf['blocks'][0]['phis']) and (not sf['no_return']) and (sf['escape'] == 'propagate'), 'SCALAR_BODY_PROFILE_UNAVAILABLE', kind='unavailable')
    block = sf['blocks'][0]
    require(block['term']['op'] == 'return' and len(block['term']['values']) == 1, 'SCALAR_BODY_RETURN_PROFILE_UNAVAILABLE', kind='unavailable')
    signature = body.types.get(sf['signature'])
    require(signature['kind'] == 'function' and len(signature['params']) == len(proto['parameters']) and (len(signature['results']) == 1) and all(signature['param_noundef']) and (signature['result_noundef'] == [True]), 'SCALAR_SIGNATURE_VALUE_PROFILE_UNAVAILABLE', kind='unavailable')
    for aid, reference in type_map.items():
        t = body.types.get(reference)
        require(t['kind'] == 'int' and t['bits'] == source_type(aid)['width'], 'SCALAR_WIDTH')
    require(signature['params'] == [type_map[i] for i in proto['parameters']] and signature['results'] == [type_map[proto['result']]], 'SCALAR_SIGNATURE_WIDTH_MAPPING')
    require(len(captured['parameters']) == len(af['parameters']) == len(sf['params']), 'SCALAR_PARAMETER_MAPPING')
    param_map = {}
    for i, (row, ap, sp) in enumerate(zip(captured['parameters'], af['parameters'], sf['params'])):
        require(row == dict(declaration=ap, value=sp['id']), 'SCALAR_PARAMETER_MAPPING')
        require(decls[ap]['decl_kind'] == 'ParmVar' and decls[ap]['canonical_type'] == {'some': proto['parameters'][i]}, 'SCALAR_PARAMETER_DECLARATION')
        param_map[ap] = sp['id']
    M.collection(budget, len(sf['params']) + len(block['ops']), 64)
    definitions, value_types = ({}, {p['id']: p['type'] for p in sf['params']})
    budget.charge(work=32 * len(block['ops']), edges=len(block['ops']), copied_bytes=256 * len(block['ops']))
    allowed = {'constant', 'i_add', 'i_sub', 'i_mul', 'i_and', 'i_or', 'i_xor', 'trunc', 'zext', 'sext'}
    for op in block['ops']:
        require(op['op'] in allowed and len(op['results']) == 1 and (not op.get('flags', [])), 'SCALAR_OPERATION_PROFILE_UNAVAILABLE', kind='unavailable')
        result = op['results'][0]
        definitions[result['id']] = op
        value_types[result['id']] = result['type']
    used = set()
    binary_ops = {'+': 'i_add', '-': 'i_sub', '*': 'i_mul', '&': 'i_and', '|': 'i_or', '^': 'i_xor'}
    for nid, n in expressions.items():
        budget.charge(work=128, edges=8, copied_bytes=512)
        q = n['semantic']
        kind, attrs, value = (q['kind'], q['attributes'], node_map[nid])
        aid = q['type']['some']
        st = source_type(aid)
        require(value in value_types and value_types[value] == type_map[aid], 'SCALAR_SSA_TYPE')
        args = [node_map[x['node']['some']] for x in q['operands']]
        op = None
        if kind == 'declaration_reference':
            did = attrs['declaration']
            require(did in param_map and value == param_map[did], 'SCALAR_PARAMETER_SSA')
        elif kind == 'parentheses':
            require(args == [value], 'SCALAR_TRANSPARENT_SSA')
        elif kind == 'cast':
            child = expressions[q['operands'][0]['node']['some']]
            before = source_type(child['semantic']['type']['some'])
            ck = attrs['cast_kind']
            require(ck in ('NoOp', 'LValueToRValue', 'IntegralCast'), 'SCALAR_CAST_PROFILE_UNAVAILABLE', kind='unavailable')
            if ck == 'LValueToRValue':
                require(child['semantic']['kind'] == 'declaration_reference' and args == [value] and (before == st), 'SCALAR_LVALUE_PARAMETER')
            elif ck == 'NoOp' or before['width'] == st['width']:
                require(before['width'] == st['width'] and args == [value], 'SCALAR_TRANSPARENT_SSA')
            else:
                opcode = 'trunc' if st['width'] < before['width'] else 'sext' if before['signed'] else 'zext'
                op = definitions.get(value)
                require(op is not None and op['op'] == opcode and (op['operands'] == args), 'SCALAR_CAST_SIGN_WIDTH')
        elif kind == 'integer_literal':
            op = definitions.get(value)
            require(op is not None and op['op'] == 'constant' and (not op['operands']), 'SCALAR_LITERAL_SSA')
            budget.charge(work=8 * len(attrs['bits_hex']), copied_bytes=128)
            bits = int(attrs['bits_hex'], 16)
            require(not st['signed'] or bits < 1 << st['width'] - 1, 'SCALAR_LITERAL_RANGE_UNAVAILABLE', kind='unavailable')
            literal = op['literal']
            require(literal['kind'] in ('zero', 'bits'), 'SCALAR_LITERAL_UNDEFINED')
            actual = 0 if literal['kind'] == 'zero' else int.from_bytes(bytes.fromhex(literal['value']), 'little')
            require(actual == bits, 'SCALAR_LITERAL_VALUE')
        elif kind == 'binary':
            require(attrs['opcode'] in binary_ops and (not st['signed']), 'SCALAR_BINARY_PROFILE_UNAVAILABLE', kind='unavailable')
            for edge in q['operands']:
                operand_type = source_type(expressions[edge['node']['some']]['semantic']['type']['some'])
                require(not operand_type['signed'] and operand_type['width'] == st['width'], 'SCALAR_BINARY_PROFILE_UNAVAILABLE', kind='unavailable')
            op = definitions.get(value)
            require(op is not None and op['op'] == binary_ops[attrs['opcode']] and (op['operands'] == args), 'SCALAR_BINARY_OPERAND_ORDER')
        else:
            raise AlignmentError('SCALAR_EXPRESSION_PROFILE_UNAVAILABLE', kind='unavailable')
        if op is not None:
            require(value not in used, 'SCALAR_OPERATION_BIJECTION')
            used.add(value)
    require(used == set(definitions), 'SCALAR_OPERATION_EXHAUSTION')
    require(block['term']['values'] == [node_map[ret_expr]], 'SCALAR_RETURN_SSA')
    require(source_type(proto['result']) == source_type(expressions[ret_expr]['semantic']['type']['some']), 'SCALAR_RETURN_VALUE_TYPE')
    require(cls.prepare_source_data(owner, budget=budget) is stamp, 'SCALAR_SOURCE_CHANGED')
    require(C.read(C.SCHEMA, 1 << 20, budget) == schema_raw, 'SCALAR_SCHEMA_CHANGED')
    C.require_issued(conditions, witness, budget)
    from candidate import factory_meter as M
    bound = M.json_bound(captured, budget)
    budget.charge(work=4 * bound, copied_bytes=4 * bound)
    encoded = C.canonical(captured)
    require(len(encoded) <= bound, 'SCALAR_JSON_BOUND')
    out = dict(format='smir-scalar-source-alignment-reference', revision=1, binding='unbound', runtime_authority=False, source_fact_authority=False, executable=False, semantic_admission=False, active_v3_verified=False, source_to_smir_full_provenance=False, finite_alignment_checked=True, source_sha256=source['source_sha256'], condition_oracle_sha256=observed['oracle_sha256'], source_config_sha256=source['config_sha256'], smir_module_digest=captured['smir_module_digest'], smir_root3_sha256=captured['smir_root3_sha256'], ast_function=captured['ast_function'], smir_function=captured['smir_function'], mapping_sha256=C.digest(encoded), profile='scalar-single-block-integer-v1', obligations=['Conditional value-body relation only; source Nominal/FullFn/calling-boundary equivalence not proved.', 'Complete source-function/CFG/lifecycle/EH/registry and runtime semantic admission remain unavailable.', 'No emitter, generated compiler output or execution is supplied.'])
    A.R.shape(doc['$defs']['report'], out, doc['$defs'], budget)
    A.precharge_copy(out, budget)
    result = ScalarAlignment(A.R.freeze(out), witness, conditions, owner, stamp, budget)
    budget.charge(work=8 * (len(_ISSUED) + 1) ** 2, edges=2, copied_bytes=128)
    _ISSUED[result] = (id(result.data), id(witness), id(conditions), id(owner), id(stamp), id(budget))
    return result

def main():
    import argparse
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=C.Path)
    parser.add_argument('--ast-oracle', required=True, type=C.Path)
    parser.add_argument('--condition-oracle', required=True, type=C.Path)
    parser.add_argument('--module', required=True, type=C.Path)
    parser.add_argument('--mapping', required=True, type=C.Path)
    parser.add_argument('--budget', required=True, type=C.Path)
    args = parser.parse_args()
    b = A.load_budget(args.budget)
    source_raw = C.read(args.source, 1 << 20, b)
    module_raw = C.read(args.module, 1 << 20, b)
    mapping_raw = C.read(args.mapping, 1 << 20, b)
    owner = A.R.apis()[0].RootContext.from_module(module_raw, budget=b)
    witness = A.observe(args.source, args.ast_oracle, budget=b)
    require(C.digest(source_raw) == witness.report(budget=b)['source_sha256'], 'SCALAR_SOURCE_CHANGED')
    conditions = C.observe_conditions(args.source, args.condition_oracle, witness=witness, budget=b)
    result = verify(witness, owner, C.load_json(mapping_raw), conditions=conditions, budget=b)
    out = result.report(budget=b)
    for path, expected in [(args.source, source_raw), (args.module, module_raw), (args.mapping, mapping_raw)]:
        require(C.read(path, 1 << 20, b) == expected, 'SCALAR_INPUT_CHANGED')
    C.schema(b)
    from candidate import factory_meter as M
    M.json_bound(out, b)
    print(json.dumps(out, sort_keys=True, separators=(',', ':')))
if __name__ == '__main__':
    main()
