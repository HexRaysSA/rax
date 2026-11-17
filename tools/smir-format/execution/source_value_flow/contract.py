"""Closed UNBOUND SSA assertions. No source facts, events or entry permissions."""
import hashlib
import json
from pathlib import Path

from candidate.context import RootContext
from candidate.source_data_projection import source_api
from candidate.type_system import key
from candidate import factory_meter
from common import Reject

ROOT = Path(__file__).resolve().parents[4]
SCHEMA = ROOT/'docs/specifications/smir/portable/schema/execution/source-value-flow-assertion.json'
MAX_BYTES = 4*1024*1024
MAX_DEFINITIONS = 4096
MAX_ORIGINAL_NODES = 1000000
MAX_ORIGINAL_TEXT = 16*1024*1024


def fail(code, detail='', kind='semantic'):
    raise source_api().SourceDataError(kind, code, detail)


class ShapeMismatch(Exception):
    pass


def validate_shape(schema, value, definitions, budget, depth=0):
    """Executable closed subset used by the checked-in JSON Schema only."""
    if depth > min(64, budget.max_depth):
        fail('FLOW_RESOURCE', 'schema depth', 'resource')
    budget.charge(work=8, edges=1)
    if '$ref' in schema:
        return validate_shape(definitions[schema['$ref'].removeprefix('#/$defs/')],
                              value, definitions, budget, depth+1)
    if 'oneOf' in schema:
        matches = 0
        for branch in schema['oneOf']:
            try:
                validate_shape(branch, value, definitions, budget, depth+1)
                matches += 1
            except ShapeMismatch:
                pass
        if matches != 1:
            raise ShapeMismatch('oneOf')
        return
    typ = schema.get('type')
    actual = {'object': dict, 'array': list, 'integer': int, 'string': str}
    if typ is not None and type(value) is not actual[typ]:
        raise ShapeMismatch('type')
    if 'const' in schema and value != schema['const']:
        raise ShapeMismatch('const')
    if 'enum' in schema and value not in schema['enum']:
        raise ShapeMismatch('enum')
    if typ == 'integer' and not schema.get('minimum', value) <= value <= schema.get('maximum', value):
        raise ShapeMismatch('integer range')
    if typ == 'object':
        fields = schema['properties']
        if set(value) != set(schema['required']) or set(value) - fields.keys():
            raise ShapeMismatch('closed fields')
        budget.charge(work=len(value), edges=len(value))
        for name, child in value.items():
            validate_shape(fields[name], child, definitions, budget, depth+1)
    if typ == 'array':
        if not schema.get('minItems', 0) <= len(value) <= schema['maxItems']:
            raise ShapeMismatch('array extent')
        budget.charge(work=len(value), edges=len(value), copied_bytes=8*len(value))
        for child in value:
            validate_shape(schema['items'], child, definitions, budget, depth+1)


def parse(payload, budget):
    if type(payload) is not bytes:
        fail('FLOW_INPUT', 'exact bytes required')
    if len(payload) > MAX_BYTES:
        fail('FLOW_RESOURCE', 'assertion octets', 'resource')
    budget.charge(work=8*len(payload)+1, copied_bytes=8*len(payload)+64)
    # Bound nesting before the JSON parser allocates recursive containers.
    nesting = 0
    quoted = escaped = False
    for byte in payload:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            nesting += 1
            if nesting > min(64, budget.max_depth):
                fail('FLOW_RESOURCE', 'JSON depth', 'resource')
        elif byte in (93, 125):
            nesting -= 1
    def pairs(items):
        result = {}
        for name, value in items:
            if name in result:
                fail('FLOW_JSON', 'duplicate key')
            result[name] = value
        return result
    def integer(text):
        if len(text) > 11:
            fail('FLOW_JSON', 'integer extent')
        return int(text)
    def invalid(_):
        fail('FLOW_JSON', 'noninteger JSON number')
    try:
        return json.loads(payload, object_pairs_hook=pairs, parse_int=integer,
                          parse_float=invalid, parse_constant=invalid)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        fail('FLOW_JSON', type(error).__name__)


def capture_plain_sections(sections, budget, *, prepaid=False):
    """Reject nonplain roots before any source-controlled lookup or callback."""
    if type(sections) is not dict:
        fail('FLOW_INPUT', 'plain integer-keyed original section map')
    def charge(**amounts):
        if not prepaid:budget.charge(**amounts)
    charge(work=len(sections), edges=len(sections), copied_bytes=32*len(sections))
    if len(sections)>MAX_ORIGINAL_NODES:
        fail('FLOW_RESOURCE','original capture nodes','resource')
    if any(type(key) is not int for key in sections):
        fail('FLOW_INPUT','plain original section keys')
    pending=[(value,0) for value in sections.values()]
    visited=text=0
    while pending:
        value,depth=pending.pop();visited+=1
        charge(work=8,edges=1)
        if depth>budget.max_depth or visited>MAX_ORIGINAL_NODES:
            fail('FLOW_RESOURCE','original capture depth/nodes','resource')
        if type(value) is dict:
            charge(work=len(value),edges=len(value),copied_bytes=32*len(value))
            if visited+len(pending)+len(value)>MAX_ORIGINAL_NODES:
                fail('FLOW_RESOURCE','original capture nodes','resource')
            if any(type(name) is not str for name in value):
                fail('FLOW_INPUT','plain original record keys')
            text+=sum(len(name)for name in value)
            pending.extend((child,depth+1)for child in value.values())
        elif type(value) is list:
            charge(work=len(value),edges=len(value),copied_bytes=32*len(value))
            if visited+len(pending)+len(value)>MAX_ORIGINAL_NODES:
                fail('FLOW_RESOURCE','original capture nodes','resource')
            pending.extend((child,depth+1)for child in value)
        elif type(value) is str:
            text+=len(value)
            charge(work=len(value),copied_bytes=4*len(value))
        elif value is None or type(value) is bool or type(value) is int:
            pass
        else:
            fail('FLOW_INPUT','nonplain original source value')
        if text>MAX_ORIGINAL_TEXT:
            fail('FLOW_RESOURCE','original capture text','resource')


def read_schema_bounded(size):
    with SCHEMA.open('rb',buffering=0) as source:
        raw=source.read(size+1)
    if len(raw)!=size:
        fail('FLOW_CHANGED','assertion schema size changed')
    return raw


def check(owner, payload, *, budget):
    """Check public assertions against original roots; return descriptive flagsfalse.

    Same canonical B accounts this checker and explicit capture reservations.
    Legacy ABI/body delegates are real but their complete canonical cost is NOT
    qualified by this unbound tool. No private source event/fact API is invoked.
    """
    api = source_api()
    if type(budget) is not api.SourceQueryBudget:
        fail('FLOW_BUDGET_REFERENCE')
    budget.charge(work=1, edges=1)
    if type(owner) is not RootContext:
        fail('FLOW_CONTEXT', 'actual original RootContext required')
    # Reserve root capture/guard work before delegation. This is NOT a proof of
    # the complete legacy factories' canonical-B graph/CPU/allocation costs.
    capture_plain_sections(owner.sections, budget)
    for section in owner.sections.values():
        factory_meter.json_bound(section, budget)
    # Fixed local reservation for a bounded primitive afterguard, even after B
    # exhaustion. It is charged to the SAME B, never a fallback/new ledger.
    budget.charge(work=64*(MAX_ORIGINAL_NODES+MAX_ORIGINAL_TEXT+1),
                  edges=4*MAX_ORIGINAL_NODES,
                  copied_bytes=128*MAX_ORIGINAL_NODES+32*MAX_ORIGINAL_TEXT)
    size = SCHEMA.stat().st_size
    budget.charge(work=16*(size+1), copied_bytes=8*(size+1))
    if size > 128*1024:
        fail('FLOW_RESOURCE', 'schema octets', 'resource')
    original_schema = read_schema_bounded(size)
    schema_digest = hashlib.sha256(original_schema).digest()
    error = None
    try:
        owner.assert_snapshot()
        if owner.sections[3]['payload_revision'] != 2:
            fail('FLOW_PROFILE_UNAVAILABLE', 'actual source revision3 admission is separate', 'unavailable')
        owner.verify_abi()
        admitted = owner.verify_execution()
        assertion = parse(payload, budget)
        schema = json.loads(original_schema)
        try:
            validate_shape(schema, assertion, schema['$defs'], budget)
        except ShapeMismatch as mismatch:
            fail('FLOW_SHAPE', str(mismatch))
        return inspect(owner, admitted, assertion, budget)
    except BaseException as caught:
        error = caught
        raise
    finally:
        try:
            capture_plain_sections(owner.sections,budget,prepaid=True)
            owner.assert_snapshot()
            if hashlib.sha256(read_schema_bounded(size)).digest() != schema_digest:
                fail('FLOW_CHANGED', 'assertion schema changed')
        except (Reject, api.SourceDataError) as changed:
            replacement = api.SourceDataError('semantic', 'FLOW_CHANGED', str(changed))
            raise replacement from error if error is not None else changed


def inspect(owner, admitted, assertion, budget):
    function_key = key(assertion['function'])
    if function_key not in owner.functions:
        fail('FLOW_REFERENCE', 'function')
    function = owner.functions[function_key]
    signature = owner.types.get(function['signature'])
    # Portable execution Fn is fixed. Source ellipsis lives in actual ABI plan
    # metadata, including fixed arena/length operands, not Fn.variadic.
    plans = [function['abi_signature']]
    for original_block in function['blocks']:
        for original_node in original_block['ops']+[original_block['term']]:
            if original_node['op'] in {'call','invoke','tailcall'}:
                plans.append(original_node['source_plan'])
    for plan in plans:
        if plan is not None and owner.signatures[key(plan['some'])]['variadic']:
            fail('FLOW_VARARGS_UNAVAILABLE', 'required source-byte varargs protocol gap', 'unavailable')
    definitions = {}
    raw_definitions = {}
    blocks = {block['id']: block for block in function['blocks']}
    def raw(typ):
        item = owner.types.get(typ)
        return item['kind'] == 'raw' and item['bits'] == 8
    def definition(declaration, node, block=None, index=None, parameter=False):
        budget.charge(work=8, edges=1, copied_bytes=96)
        value = declaration['id']
        if not raw(declaration['type']) and owner.types.contains_value_kind(declaration['type'], {'raw'}):
            fail('FLOW_WIDE_UNAVAILABLE', 'required non-scalar-Raw8 source flow gap', 'unavailable')
        definitions[value] = dict(type=declaration['type'], node=node,
                                  block=block, operation=index, parameter=parameter)
        if raw(declaration['type']):
            raw_definitions[value] = definitions[value]
    for parameter, noundef in zip(function['params'], signature['param_noundef']):
        definition(parameter, None, parameter=True)
        if raw(parameter['type']) and noundef:
            fail('FLOW_NOUNDEF', 'source Raw8 parameter')
    for result, noundef in zip(signature['results'], signature['result_noundef']):
        if raw(result) and noundef:
            fail('FLOW_NOUNDEF', 'source Raw8 result')
    for block in function['blocks']:
        for phi in block['phis']:
            definition(phi['result'], phi, block['id'])
        for index, node in enumerate(block['ops']+[block['term']]):
            for result in node.get('results', []):
                definition(result, node, block['id'], index)
    if len(raw_definitions) > MAX_DEFINITIONS:
        fail('FLOW_RESOURCE', 'Raw8 definition count', 'resource')
    def ordered(rows, name):
        identifiers = [row[name] for row in rows]
        if identifiers != sorted(set(identifiers)):
            fail('FLOW_COVERAGE', 'duplicate/unsorted '+name)
        return identifiers
    nominal_rows = assertion['nominals']
    nominal_ids = ordered(nominal_rows, 'value')
    if set(nominal_ids) != raw_definitions.keys():
        fail('FLOW_COVERAGE', 'exact all Raw8 nominal definitions required')
    nominals = {row['value']: row['nominal'] for row in nominal_rows}
    for row in nominal_rows:
        item = owner.nominals.get(key(row['nominal']))
        if (item is None or item['kind'] not in {'scalar','enum'} or
                item['bits'] != 8 or item['representation'] != 'value' or
                item['execution'] is None or not raw(item['execution']['some'])):
            fail('FLOW_NOMINAL', 'original nominal Raw8 execution projection')
    seeds = assertion['seeds']
    ordered(seeds, 'value')
    producers = set()
    for seed in seeds:
        value = seed['value']
        if value not in raw_definitions:
            fail('FLOW_COVERAGE', 'seed result')
        producers.add(value)
        data = raw_definitions[value]
        node = data['node']
        kind = seed['kind']
        if kind == 'parameter':
            valid = data['parameter']
        elif kind == 'literal':
            valid = (node is not None and node.get('op') == 'constant' and
                     node['literal']['kind'] in {'zero', 'bits'})
        elif kind == 'numeric_to_byte':
            valid = node is not None and node.get('op') == 'bitcast' and len(node['operands']) == 1
            if valid:
                typ = owner.types.get(definitions[node['operands'][0]]['type'])
                valid = typ['kind'] == 'int' and typ['bits'] == 8
        else:
            valid = node is not None and node.get('op') == {'load': 'load', 'bitcast': 'bitcast',
                                                         'call_result': 'call'}[kind]
        if not valid:
            fail('FLOW_SEED', kind)
    flows = assertion['flows']
    ordered(flows, 'result')
    for flow in flows:
        result = flow['result']
        if result not in raw_definitions or result in producers:
            fail('FLOW_COVERAGE', 'exactly one producer per result')
        producers.add(result)
        data = raw_definitions[result]
        if data['block'] != flow['block']:
            fail('FLOW_COORDINATE', 'result block')
        node = data['node']
        kind = flow['kind']
        if kind == 'phi':
            if 'incoming' not in node or flow['incoming'] != node['incoming']:
                fail('FLOW_PHI', 'complete original ordered predecessor/value vector')
            if nominals[result] != flow['nominal'] or any(nominals.get(row['value']) != flow['nominal']
                                                         for row in flow['incoming']):
                fail('FLOW_NOMINAL', 'phi incoming/result')
            continue
        if data['operation'] != flow['operation'] or data['operation'] >= len(blocks[flow['block']]['ops']):
            fail('FLOW_COORDINATE', 'operation')
        if kind in {'noop', 'freeze'}:
            expected = {'copy', 'bitcast'} if kind == 'noop' else {'freeze'}
            if node['op'] not in expected or node['operands'] != [flow['input']] or len(node['results']) != 1:
                fail('FLOW_OPCODE', kind)
            if flow['input'] not in raw_definitions:
                fail('FLOW_TYPE', 'scalar Raw8 input required')
            if kind == 'noop':
                if nominals[flow['input']] != flow['input_nominal'] or nominals[result] != flow['result_nominal']:
                    fail('FLOW_NOMINAL', 'noop')
                if node['op'] == 'copy' and flow['input_nominal'] != flow['result_nominal']:
                    fail('FLOW_NOMINAL', 'identity cannot change nominal')
            elif nominals[flow['input']] != flow['nominal'] or nominals[result] != flow['nominal']:
                fail('FLOW_NOMINAL', 'freeze')
        elif kind == 'select':
            if node['op'] != 'select' or node['operands'] != [flow['condition'], flow['true_value'], flow['false_value']]:
                fail('FLOW_OPCODE', 'select operands')
            condition = owner.types.get(definitions[flow['condition']]['type'])
            if condition['kind'] != 'int' or condition['bits'] != 1:
                fail('FLOW_TYPE', 'scalar Int1 selection')
            if any(nominals.get(value) != flow['nominal'] for value in
                   (result, flow['true_value'], flow['false_value'])):
                fail('FLOW_NOMINAL', 'select')
    if producers != raw_definitions.keys():
        fail('FLOW_COVERAGE', 'missing/unclassified Raw8 definition, including unused')
    budget.charge(work=16*len(definitions)+1, edges=len(definitions), copied_bytes=256)
    return dict(format='source-value-flow-unbound-observation', revision=1,
        function=assertion['function'], raw8_definitions=len(raw_definitions),
        flows=len(flows), seeds=len(seeds), static_body_and_abi_verified=True,
        source_facts_issued=False, source_category_proved=False, source_body_equivalence=False,
        source_admission_passed=False, runtime_permission=False,
        private_core_events_issued=False, delegated_factory_cost_qualified=False)
