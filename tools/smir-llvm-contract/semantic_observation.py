"""Actual pinned Clang AST/CFG observations; no lifetime/ABI authority."""
from pathlib import Path
from dataclasses import dataclass, field
import hashlib, json, os, re, selectors, subprocess, sys, tempfile, time, weakref
from collections import Counter
HERE = Path(__file__).resolve().parent
PROJECT = Path(os.environ.get('CSO_REFERENCE_PROJECT', str(HERE.parents[1])))
sys.path.insert(0, str(PROJECT / 'tools/smir-llvm-contract'))
import source_projection as R
HERE = Path(__file__).resolve().parent
SCHEMA = Path(os.environ.get('CSO_REFERENCE_SCHEMA', str(PROJECT / 'docs/specifications/smir/portable/llvm/semantic-observation.schema.json')))
SCHEMA_SHA = '8506ee8690b615271c0304ea1dd90a67847afff9cca14def482884dbafd6cc3e'
PIN = '36763294ef639d8a6a4379d81da653dda1c20686'
COMPILER = '192ac975b062d522570b5f7bd06a235a1918f7c0a0d66f70df2eecdd628d24b7'
MAX_OUTPUT = 64 << 20

class EventError(ValueError):

    def __init__(self, code, detail='', kind='input'):
        self.code = code
        self.detail = detail
        self.kind = kind
        super().__init__(code + ': ' + detail)

def need(test, code, detail='', kind='input'):
    if not test:
        raise EventError(code, detail, kind)

def canonical(x):
    return json.dumps(x, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')

def digest(x):
    return hashlib.sha256(x).hexdigest()

def read(path, limit, budget):
    p = Path(path)
    n = p.stat().st_size
    need(0 <= n <= limit, 'CEW_RESOURCE', 'input size', 'resource')
    budget.charge(work=4 * n + 1, copied_bytes=4 * n + 1)
    with p.open('rb') as f:
        raw = f.read(n + 1)
    need(len(raw) == n, 'CEW_PROVENANCE', 'input changed while reading')
    return raw

def file_hash(path, budget):
    p = Path(path)
    n = p.stat().st_size
    need(0 <= n <= 1 << 31, 'CEW_RESOURCE', 'native input size', 'resource')
    budget.charge(work=2 * n + 1, copied_bytes=n + 1)
    h = hashlib.sha256()
    with p.open('rb') as f:
        total = 0
        for part in iter(lambda: f.read(1 << 20), b''):
            total += len(part)
            need(total <= n, 'CEW_PROVENANCE', 'native input grew')
            h.update(part)
    need(total == n, 'CEW_PROVENANCE', 'native input shrank')
    return h.hexdigest()

def load_json(raw):

    def pairs(rows):
        d = {}
        for k, v in rows:
            need(k not in d, 'CEW_INPUT', 'duplicate JSON key')
            d[k] = v
        return d
    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeError) as e:
        if isinstance(e, EventError):
            raise
        raise EventError('CEW_INPUT', 'invalid JSON/UTF8') from e

def schema(budget):
    raw = read(SCHEMA, 1 << 20, budget)
    need(digest(raw) == SCHEMA_SHA, 'CEW_PROVENANCE', 'schema pin')
    return (load_json(raw), raw)

def native_identity(oracle, budget):
    p = Path(oracle).resolve()
    receipt = p.parent / 'build-receipt.json'
    raw = read(receipt, 4 << 20, budget)
    d = load_json(raw)
    need(type(d.get('exit')) is int and d['exit'] == 0 and (d.get('llvm_pin') == PIN), 'CEW_PROVENANCE', 'actual native build receipt')
    need(type(d) is dict and set(d) == {'format', 'llvm_pin', 'compiler', 'command', 'exit', 'input_hashes', 'drift', 'scope', 'binary'} and (d['format'] == 'draft-semantic-observation-native-build'), 'CEW_PROVENANCE', 'closed native receipt')
    need(type(d['compiler']) is dict and set(d['compiler']) == {'path', 'sha256', 'version'} and (type(d['compiler']['path']) is str) and (type(d['compiler']['version']) is str) and (PIN in d['compiler']['version']), 'CEW_PROVENANCE', 'compiler record')
    need(d['compiler']['sha256'] == COMPILER, 'CEW_PROVENANCE', 'compiler pin')
    need(type(d['binary']) is dict and set(d['binary']) == {'path', 'sha256'} and (type(d['binary']['sha256']) is str) and re.fullmatch('[0-9a-f]{64}', d['binary']['sha256']), 'CEW_PROVENANCE', 'binary record')
    need(type(d['command']) is list and 0 < len(d['command']) <= 4096 and all((type(x) is str and len(x) <= 4096 for x in d['command'])) and (d['drift'] == []) and (type(d['scope']) is str), 'CEW_PROVENANCE', 'build fields')
    inputs = d.get('input_hashes')
    need(type(inputs) is dict and 0 < len(inputs) <= 8192, 'CEW_PROVENANCE', 'native inputs')
    paths = set()
    for name, h in inputs.items():
        need(type(name) is str and type(h) is str and re.fullmatch('[0-9a-f]{64}', h) and Path(name).is_absolute(), 'CEW_PROVENANCE', 'native input record')
        resolved = str(Path(name).resolve())
        need(resolved not in paths, 'CEW_PROVENANCE', 'duplicate native input path')
        paths.add(resolved)
        need(file_hash(name, budget) == h, 'CEW_PROVENANCE', 'native build input changed')
    cpp_inputs = [h for name, h in inputs.items() if Path(name).name == 'semantic_observation.cpp']
    need(len(cpp_inputs) == 1 and cpp_inputs[0] == file_hash(HERE / 'semantic_observation.cpp', budget), 'CEW_PROVENANCE', 'actual source input identity')
    need(str(Path(d['compiler']['path']).resolve()) in paths and file_hash(d['compiler']['path'], budget) == COMPILER, 'CEW_PROVENANCE', 'actual compiler input')
    binary = file_hash(p, budget)
    need(binary == d.get('binary', {}).get('sha256'), 'CEW_PROVENANCE', 'oracle binary')
    return (d, raw, binary, digest(canonical(inputs)))

def run_native(oracle, source, budget):
    budget.charge(work=1, edges=1, copied_bytes=256)
    p = subprocess.Popen([str(oracle), str(source)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sel = selectors.DefaultSelector()
    sel.register(p.stdout, selectors.EVENT_READ, 'stdout')
    sel.register(p.stderr, selectors.EVENT_READ, 'stderr')
    data = {'stdout': bytearray(), 'stderr': bytearray()}
    start = time.monotonic()
    try:
        while sel.get_map():
            need(time.monotonic() - start <= 30, 'CEW_RESOURCE', 'native timeout', 'resource')
            for key, _ in sel.select(0.1):
                budget.charge(work=65536, copied_bytes=65536)
                part = os.read(key.fileobj.fileno(), 65536)
                if not part:
                    sel.unregister(key.fileobj)
                    continue
                need(sum((len(v) for v in data.values())) + len(part) <= MAX_OUTPUT, 'CEW_RESOURCE', 'native output', 'resource')
                data[key.data].extend(part)
        code = p.wait(timeout=1)
    finally:
        sel.close()
        if p.poll() is None:
            p.kill()
            p.wait()
        p.stdout.close()
        p.stderr.close()
    if code:
        detail = data['stderr'].decode('utf8', 'replace')[:4096]
        kind = 'resource' if code == 4 else 'unavailable' if code == 3 else 'input' if code == 2 else 'internal'
        raise EventError('CEW_NATIVE_REJECTED', detail, kind)
    budget.charge(work=8 * len(data['stdout']), copied_bytes=8 * len(data['stdout']))
    return R.capture(load_json(data['stdout']), budget)

def unwrap(x):
    return None if x is None else x['some']

def table(rows, budget):
    budget.charge(work=len(rows), edges=len(rows), copied_bytes=128 * len(rows))
    need([x['id'] for x in rows] == list(range(len(rows))), 'CEW_GRAPH', 'noncanonical local IDs')
    return {x['id']: x for x in rows}

def raw_semantics(raw, source, budget):
    need(raw['source_sha256'] == digest(source) and PIN in raw['library_version'], 'CEW_PROVENANCE', 'source/library identity')
    decls = table(raw['declarations'], budget)
    total = 0

    def ref(q, t):
        if q is not None:
            need(q['some'] in t, 'CEW_GRAPH', 'reference namespace')

    def offsets(span):
        for q in span.values():
            if q is not None:
                need(q['some'] <= len(source), 'CEW_GRAPH', 'source offset')
    for d in decls.values():
        offsets({k: d[k] for k in ['canonical_offset', 'definition_offset']})
        for k in ['semantic_parent', 'canonical_lexical_parent', 'definition_lexical_parent']:
            ref(d[k], decls)
    seen_functions = set()
    for f in raw['functions']:
        budget.charge(work=32, edges=8, copied_bytes=1024)
        need(f['declaration'] in decls and f['declaration'] not in seen_functions, 'CEW_GRAPH', 'function declaration')
        seen_functions.add(f['declaration'])
        need(decls[f['declaration']]['decl_kind'] in ['Function', 'CXXMethod', 'CXXConstructor', 'CXXDestructor', 'CXXConversion'], 'CEW_GRAPH', 'function kind')
        nodes = table(f['nodes'], budget)
        regions = table(f['regions'], budget)
        blocks = {x['id']: x for x in f['blocks']}
        need(len(blocks) == len(f['blocks']) and f['entry'] in blocks and (f['exit'] in blocks), 'CEW_GRAPH', 'CFG role IDs')
        need(f['body'] in nodes, 'CEW_GRAPH', 'body ID')
        total += len(nodes)
        need(total <= 32768, 'CEW_RESOURCE', 'node bound', 'resource')
        for p in f['parameters']:
            need(p in decls and decls[p]['decl_kind'] == 'ParmVar', 'CEW_GRAPH', 'parameter declaration')
        for n in nodes.values():
            budget.charge(work=24 + len(n['children']) + len(n['declarations']), edges=16 + len(n['children']), copied_bytes=64)
            offsets(n['range'])
            ref(n['region'], regions)
            for c in n['children']:
                need(c in nodes, 'CEW_GRAPH', 'AST child')
            for d in n['declarations']:
                need(d in decls, 'CEW_GRAPH', 'AST declaration')
            for k in ['referenced_decl', 'direct_callee', 'constructor', 'temporary_destructor', 'extending_decl', 'return_nrvo_candidate']:
                ref(n[k], decls)
            for k, kind in [('constructor', 'CXXConstructor'), ('temporary_destructor', 'CXXDestructor')]:
                if n[k] is not None:
                    need(decls[n[k]['some']]['decl_kind'] == kind, 'CEW_GRAPH', 'typed declaration edge')
            need((n['type_spelling_inspection'] is None) == (n['value_category'] is None), 'CEW_GRAPH', 'expression inspection pair')
            functions = {'Function', 'CXXMethod', 'CXXConstructor', 'CXXDestructor', 'CXXConversion'}
            if n['direct_callee'] is not None:
                need(decls[n['direct_callee']['some']]['decl_kind'] in functions and (n['stmt_class'].endswith('CallExpr') or n['stmt_class'] == 'UserDefinedLiteral'), 'CEW_GRAPH', 'typed direct callee')
            if n['referenced_decl'] is not None:
                need(n['stmt_class'] in ['DeclRefExpr', 'MemberExpr'] and decls[n['referenced_decl']['some']]['type_spelling_inspection'] is not None, 'CEW_GRAPH', 'typed value reference')
            constructor = n['stmt_class'] in ['CXXConstructExpr', 'CXXTemporaryObjectExpr']
            need(constructor == (n['constructor'] is not None) == (n['is_elidable'] is not None), 'CEW_GRAPH', 'constructor property applicability')
            need((n['temporary_destructor'] is not None) == (n['stmt_class'] == 'CXXBindTemporaryExpr'), 'CEW_GRAPH', 'temporary destructor applicability')
            need((n['bound_to_lvalue_reference'] is not None) == (n['stmt_class'] == 'MaterializeTemporaryExpr'), 'CEW_GRAPH', 'materialization applicability')
            if n['extending_decl'] is not None:
                need(n['stmt_class'] == 'MaterializeTemporaryExpr', 'CEW_GRAPH', 'extending declaration applicability')
            if n['return_nrvo_candidate'] is not None:
                need(n['stmt_class'] == 'ReturnStmt' and decls[n['return_nrvo_candidate']['some']]['decl_kind'] == 'Var', 'CEW_GRAPH', 'NRVO observation applicability')
        for region in regions.values():
            budget.charge(work=8, edges=2, copied_bytes=32)
            need(region['stmt'] in nodes and nodes[region['stmt']]['region'] == {'some': region['id']}, 'CEW_GRAPH', 'AST region association')
            ref(region['parent'], regions)
            need(region['parent'] is None or region['parent']['some'] < region['id'], 'CEW_GRAPH', 'region parent')
            offsets(region['range'])
        seeds = {f['body']}
        for b in blocks.values():
            budget.charge(work=16 + len(b['elements']) + len(b['successors']) + len(b['predecessors']), edges=4 + len(b['successors']) + len(b['predecessors']), copied_bytes=128)
            need([e['index'] for e in b['elements']] == list(range(len(b['elements']))), 'CEW_GRAPH', 'element order')
            for k in ['terminator', 'condition', 'label', 'loop_target']:
                ref(b[k], nodes)
                seeds.update([] if b[k] is None else [b[k]['some']])
            for e in b['successors'] + b['predecessors']:
                ref(e['reachable'], blocks)
                ref(e['possibly_unreachable'], blocks)
            for e in b['elements']:
                budget.charge(work=16 + len(e['expiring_temporaries']), edges=8 + len(e['expiring_temporaries']), copied_bytes=64)
                for k in ['statement', 'trigger']:
                    ref(e[k], nodes)
                    seeds.update([] if e[k] is None else [e[k]['some']])
                for k in ['declaration', 'destructor']:
                    ref(e[k], decls)
                for n in e['expiring_temporaries']:
                    need(n in nodes, 'CEW_GRAPH', 'temporary node')
                    seeds.add(n)
                is_dtor = e['kind'] in ['automatic_object_dtor', 'temporary_dtor', 'base_dtor', 'member_dtor']
                need(is_dtor == (e['destructor'] is not None) == (e['destructor_noreturn_inspection'] is not None), 'CEW_GRAPH', 'destructor property kind')
                if is_dtor:
                    need(decls[e['destructor']['some']]['decl_kind'] == 'CXXDestructor', 'CEW_GRAPH', 'destructor declaration')
                need((e['construction_context'] is not None) == (e['kind'] in ['constructor', 'record_typed_call']), 'CEW_GRAPH', 'construction context kind')
                statement_kinds = {'statement', 'constructor', 'record_typed_call', 'initializer', 'temporary_dtor', 'loop_exit_marker', 'full_expr_cleanup'}
                trigger_kinds = {'scope_begin', 'scope_end', 'lifetime_ends_marker', 'automatic_object_dtor'}
                need((e['statement'] is not None) == (e['kind'] in statement_kinds), 'CEW_GRAPH', 'element statement applicability')
                need((e['trigger'] is not None) == (e['kind'] in trigger_kinds), 'CEW_GRAPH', 'element trigger applicability')
                if e['expiring_temporaries']:
                    need(e['kind'] == 'full_expr_cleanup', 'CEW_GRAPH', 'expiring temporary applicability')
                for n in e['expiring_temporaries']:
                    need(nodes[n]['stmt_class'] == 'MaterializeTemporaryExpr', 'CEW_GRAPH', 'expiring temporary node kind')
                if e['kind'] == 'constructor':
                    need(nodes[e['statement']['some']]['constructor'] is not None, 'CEW_GRAPH', 'CFG constructor statement kind')
                if e['kind'] == 'temporary_dtor':
                    need(nodes[e['statement']['some']]['stmt_class'] == 'CXXBindTemporaryExpr', 'CEW_GRAPH', 'CFG temporary destructor statement kind')
                if e['kind'] in trigger_kinds:
                    need(e['declaration'] is not None and decls[e['declaration']['some']]['decl_kind'] in ['Var', 'ParmVar', 'Decomposition'], 'CEW_GRAPH', 'scope marker variable')
        expected = {bid: Counter() for bid in blocks}
        for bid, b in blocks.items():
            for edge in b['successors']:
                r, u = (unwrap(edge['reachable']), unwrap(edge['possibly_unreachable']))
                need(r is None or u is None or r != u, 'CEW_GRAPH', 'noncanonical alternate edge')
                if r is not None:
                    expected[r][bid, None] += 1
                if u is not None:
                    expected[u][None, bid] += 1
        for bid, b in blocks.items():
            actual = Counter(((unwrap(e['reachable']), unwrap(e['possibly_unreachable'])) for e in b['predecessors']))
            need(actual == expected[bid], 'CEW_GRAPH', 'CFG predecessor successor reciprocity')
        visited = set()
        active = set()

        def visit(n, depth):
            budget.charge(work=1, edges=1)
            need(depth <= 128, 'CEW_RESOURCE', 'AST graph depth', 'resource')
            need(n not in active, 'CEW_GRAPH', 'cyclic AST graph')
            if n in visited:
                return
            active.add(n)
            for c in nodes[n]['children']:
                visit(c, depth + 1)
            active.remove(n)
            visited.add(n)
        for seed in sorted(seeds):
            visit(seed, 0)
        need(len(visited) == len(nodes), 'CEW_GRAPH', 'unaccounted AST node')
    for t in raw['traits_inspection']:
        budget.work(4)
        offsets(t['range'])

def precharge_copy(value, budget):
    stack = [value]
    while stack:
        x = stack.pop()
        budget.charge(work=4, copied_bytes=128)
        if isinstance(x, dict):
            budget.charge(work=len(x), edges=len(x), copied_bytes=128 * len(x))
            stack.extend(x.keys())
            stack.extend(x.values())
        elif isinstance(x, list):
            budget.charge(work=len(x), edges=len(x), copied_bytes=64 * len(x))
            stack.extend(x)
        elif type(x) is str:
            budget.charge(work=4 * len(x), copied_bytes=16 * len(x))

def thaw(value, budget):
    from collections.abc import Mapping
    budget.charge(work=4, copied_bytes=128)
    if isinstance(value, Mapping):
        budget.charge(work=len(value), edges=len(value), copied_bytes=128 * len(value))
        return {thaw(k, budget): thaw(v, budget) for k, v in value.items()}
    if isinstance(value, tuple):
        budget.charge(work=len(value), edges=len(value), copied_bytes=64 * len(value))
        return [thaw(x, budget) for x in value]
    if type(value) is str:
        budget.charge(work=4 * len(value), copied_bytes=16 * len(value))
    return value

def typed_semantics(raw, budget):
    types = table(raw['types'], budget)
    decls = table(raw['declarations'], budget)

    def type_ref(q):
        need(q in types, 'CSO_TYPE', 'type reference')
        return types[q]['shape']

    def decl_ref(q, kind=None):
        need(q in decls and (kind is None or decls[q]['decl_kind'] == kind), 'CSO_DECLARATION', 'typed declaration')
        return decls[q]
    for d in decls.values():
        budget.charge(work=4, edges=1)
        if d['canonical_type'] is not None:
            type_ref(d['canonical_type']['some'])
        need((d['canonical_type'] is None) == (d['type_spelling_inspection'] is None), 'CSO_TYPE', 'declaration type pair')
    for t in types.values():
        budget.charge(work=16, edges=4)
        a = t['shape']
        k = a['kind']
        if k == 'integer':
            need(not a['boolean'] or (a['width'] == 8 and (not a['signed'])), 'CSO_TYPE', 'bool target representation')
        if k in ('pointer', 'lvalue_reference', 'rvalue_reference'):
            type_ref(a['pointee'])
        if k == 'function':
            type_ref(a['result'])
            budget.charge(work=len(a['parameters']), edges=len(a['parameters']))
            for p in a['parameters']:
                type_ref(p)
        if k == 'record':
            owner = decl_ref(a['declaration'], 'CXXRecord')
            seen = set()
            budget.charge(work=4 * len(a['fields']), edges=len(a['fields']), copied_bytes=64 * len(a['fields']))
            for fid in a['fields']:
                d = decl_ref(fid, 'Field')
                need(fid not in seen and d['semantic_parent'] == {'some': a['declaration']}, 'CSO_DECLARATION', 'record field identity')
                seen.add(fid)
    classes = {'integer_literal': ['IntegerLiteral'], 'boolean_literal': ['CXXBoolLiteralExpr'], 'declaration_reference': ['DeclRefExpr'], 'member_reference': ['MemberExpr'], 'cast': ['ImplicitCastExpr', 'CStyleCastExpr', 'CXXStaticCastExpr', 'CXXFunctionalCastExpr'], 'construction': ['CXXConstructExpr', 'CXXTemporaryObjectExpr'], 'initializer_list': ['InitListExpr'], 'binary': ['BinaryOperator', 'CompoundAssignOperator'], 'unary': ['UnaryOperator'], 'call': ['CallExpr', 'CXXMemberCallExpr'], 'compound': ['CompoundStmt'], 'return': ['ReturnStmt'], 'declarations': ['DeclStmt'], 'parentheses': ['ParenExpr'], 'cleanup_wrapper': ['ExprWithCleanups'], 'materialize': ['MaterializeTemporaryExpr'], 'bind_temporary': ['CXXBindTemporaryExpr'], 'implicit_value_initialization': ['ImplicitValueInitExpr'], 'null_statement': ['NullStmt']}
    unary = {'member_reference': 'base', 'cast': 'value', 'unary': 'value', 'parentheses': 'value', 'cleanup_wrapper': 'value', 'materialize': 'value', 'bind_temporary': 'value'}
    zero = {'integer_literal', 'boolean_literal', 'declaration_reference', 'implicit_value_initialization', 'null_statement'}
    for f in raw['functions']:
        nodes = table(f['nodes'], budget)
        for n in nodes.values():
            q = n['semantic']
            k = q['kind']
            a = q['attributes']
            ops = q['operands']
            budget.charge(work=32 + 8 * len(ops) + len(n['children']), edges=8 + len(ops), copied_bytes=256 + 128 * len(ops))
            need(n['stmt_class'] in classes[k], 'CSO_NODE', 'statement/semantic kind')
            statement = k in ('compound', 'return', 'declarations', 'null_statement')
            need((q['type'] is None) == statement and q['value_category'] == n['value_category'], 'CSO_TYPE', 'expression identity/category')
            if q['type'] is not None:
                ty = type_ref(q['type']['some'])
            seen = set()
            children = []
            for op in ops:
                key = (op['role'], op['index'])
                need(key not in seen, 'CSO_OPERAND', 'duplicate operand role')
                seen.add(key)
                if op['node'] is not None:
                    c = op['node']['some']
                    need(c in nodes, 'CSO_OPERAND', 'operand namespace')
                    children.append(c)
            need(Counter(children) == Counter(n['children']), 'CSO_OPERAND', 'operand/AST-child multiplicity')
            roles = [(x['role'], x['index']) for x in ops]
            if k in zero:
                expected = []
            elif k in unary:
                expected = [(unary[k], 0)]
            elif k == 'binary':
                expected = [('left', 0), ('right', 0)]
            elif k == 'return':
                expected = [('value', 0)]
            elif k == 'call':
                expected = [('callee', 0)] + [('argument', i) for i in range(len(ops) - 1)]
            else:
                role = {'construction': 'argument', 'initializer_list': 'initializer', 'compound': 'statement', 'declarations': 'initializer'}[k]
                expected = [(role, i) for i in range(len(ops))]
            need(roles == expected, 'CSO_OPERAND', 'ordered roles/indices')
            if k not in ('return', 'declarations'):
                need(all((x['node'] is not None for x in ops)), 'CSO_OPERAND', 'required operand')
            if k == 'integer_literal':
                w = a['apint_width']
                h = a['bits_hex']
                budget.charge(work=4 * len(h), copied_bytes=4 * len(h))
                need(ty['kind'] == 'integer' and (not ty['boolean']) and (w == ty['width']) and (len(h) == (w + 3) // 4) and (int(h, 16) < 1 << w), 'CSO_LITERAL', 'exact APInt width/bits')
            if k == 'boolean_literal':
                need(ty['kind'] == 'integer' and ty['boolean'], 'CSO_LITERAL', 'boolean type')
            for kind, key, old, declkind in [('declaration_reference', 'declaration', 'referenced_decl', None), ('member_reference', 'declaration', 'referenced_decl', None), ('construction', 'constructor', 'constructor', 'CXXConstructor'), ('call', 'callee', 'direct_callee', None), ('bind_temporary', 'destructor', 'temporary_destructor', 'CXXDestructor')]:
                if k == kind:
                    decl_ref(a[key], declkind)
                    need(n[old] == {'some': a[key]}, 'CSO_DECLARATION', 'actual AST declaration edge')
            if k == 'declarations':
                need(a['declarations'] == n['declarations'] and len(a['declarations']) == len(ops), 'CSO_DECLARATION', 'initializer/declaration order')
            if k == 'construction':
                need(a['elidable'] == n['is_elidable'], 'CSO_NODE', 'constructor property')
            if k == 'materialize':
                need(a['lvalue_reference'] == n['bound_to_lvalue_reference'], 'CSO_NODE', 'materialization property')
            if k == 'cast':
                need(a['syntax'] == n['stmt_class'], 'CSO_NODE', 'cast syntax')

def plain_equal(left, right, budget):
    """Compare captured plain trees with charges before each scalar and copy."""
    pending = [(left, right, 0)]
    pairs = 0
    while pending:
        budget.charge(work=4, edges=1, copied_bytes=64)
        a, b, depth = pending.pop()
        pairs += 1
        need(pairs <= 200000 and depth <= 128, 'CSO_RESOURCE', 'comparison graph bound', 'resource')
        ta, tb = (type(a), type(b))
        need(ta in (dict, list, str, bytes, int, bool, type(None)) and tb in (dict, list, str, bytes, int, bool, type(None)), 'CSO_INPUT', 'plain comparison')
        if ta is not tb:
            return False
        if ta is dict:
            if len(a) != len(b):
                return False
            n = len(a)
            K = 0
            budget.charge(work=4 * (n + 1), edges=2 * n)
            for tree in (a, b):
                for key in tree:
                    need(type(key) is str, 'CSO_INPUT', 'plain dictionary key')
                    budget.charge(work=4 * (len(key) + 1))
                    K = max(K, len(key))
            budget.charge(work=8 * (n + 1) ** 2 * (K + 1), edges=n, copied_bytes=128 * (n + 1))
            for key, value in a.items():
                if key not in b:
                    return False
                pending.append((value, b[key], depth + 1))
        elif ta is list:
            if len(a) != len(b):
                return False
            n = len(a)
            budget.charge(work=4 * (n + 1), edges=n, copied_bytes=128 * (n + 1))
            for i in range(n):
                pending.append((a[i], b[i], depth + 1))
        elif ta in (str, bytes):
            budget.charge(work=4 * (len(a) + len(b) + 1))
            if a != b:
                return False
        elif ta is int:
            budget.charge(work=4 + (a.bit_length() + b.bit_length() + 7) // 8)
            if a != b:
                return False
        elif a is not b:
            return False
    return True

_ISSUED_OBSERVATIONS = weakref.WeakKeyDictionary()

def _require_issued(witness, budget):
    need(type(budget) is R.apis()[4].SourceQueryBudget, 'CEW_INPUT', 'canonical budget class')
    need(type(witness) is ObservationWitness, 'CSO_ORIGINAL', 'actual issued observation required')
    budget.charge(work=4, edges=1)
    issued = _ISSUED_OBSERVATIONS.get(witness)
    need(issued is not None and issued[0] is witness.data and issued[1] is budget and witness.ledger is budget,
         'CSO_ORIGINAL', 'unissued witness or original immutable capture/ledger mismatch')

def resolve(witness, origin, *, budget):
    need(type(budget) is R.apis()[4].SourceQueryBudget, 'CEW_INPUT', 'canonical budget class')
    need(type(witness) is ObservationWitness and budget is witness.ledger, 'CSO_CONTEXT', 'original witness/ledger')
    _require_issued(witness, budget)
    d, unused = schema(budget)
    captured = R.capture(origin, budget)
    R.shape(d['$defs']['origin'], captured, d['$defs'], budget)
    need(captured['source_sha256'] == witness.data['source_sha256'], 'CSO_ORIGIN', 'source identity')
    raw = witness.data['raw']
    budget.charge(work=len(raw['functions']), edges=len(raw['functions']))
    f = next((f for f in raw['functions'] if f['declaration'] == captured['function']), None)
    need(f is not None and captured['node'] < len(f['nodes']), 'CSO_ORIGIN', 'function/node namespace')
    return thaw(f['nodes'][captured['node']], budget)

def match_original(report, source, oracle, *, budget):
    need(type(budget) is R.apis()[4].SourceQueryBudget, 'CEW_INPUT', 'canonical budget class')
    captured = R.capture(report, budget)
    doc, unused = schema(budget)
    R.shape(doc['$defs']['report'], captured, doc['$defs'], budget)
    raw_source = read(source, 1 << 20, budget)
    raw_semantics(captured['raw'], raw_source, budget)
    typed_semantics(captured['raw'], budget)
    actual = observe(source, oracle, budget=budget)
    actual_report = actual.report(budget=budget)
    need(plain_equal(captured, actual_report, budget), 'CSO_ORIGINAL', 'fresh original observation mismatch')
    need(read(source, 1 << 20, budget) == raw_source, 'CEW_PROVENANCE', 'original match source afterguard')
    need(digest(read(SCHEMA, 1 << 20, budget)) == SCHEMA_SHA, 'CEW_PROVENANCE', 'original match schema afterguard')
    build, receipt_raw, binary, inputs = native_identity(oracle, budget)
    need(binary == actual_report['oracle_sha256'] and inputs == actual_report['build_input_identity'], 'CEW_PROVENANCE', 'original match native afterguard')
    return actual

@dataclass(frozen=True, eq=False)
class ObservationWitness:
    data: object
    binding: str = field(default='unbound', init=False)
    runtime_authority: bool = field(default=False, init=False)
    source_fact_authority: bool = field(default=False, init=False)
    executable: bool = field(default=False, init=False)
    ledger: object = field(repr=False, compare=False, default=None)

    def report(self, *, budget):
        need(type(budget) is R.apis()[4].SourceQueryBudget, 'CEW_INPUT', 'canonical budget class')
        need(budget is self.ledger, 'CSO_CONTEXT', 'original ledger')
        _require_issued(self, budget)
        return thaw(self.data, budget)

def observe(source, oracle, *, budget):
    need(type(budget) is R.apis()[4].SourceQueryBudget, 'CEW_INPUT', 'canonical budget class')
    doc, schema_raw = schema(budget)
    raw_source = read(source, 1 << 20, budget)
    need(b'\x00' not in raw_source, 'CEW_INPUT', 'NUL source')
    build, receipt_raw, binary, inputs = native_identity(oracle, budget)
    parent = os.environ.get('CEW_SCRATCH')
    with tempfile.TemporaryDirectory(prefix='source-event-', dir=parent) as tmp:
        copy = Path(tmp) / 'input.cpp'
        budget.charge(work=len(raw_source), copied_bytes=len(raw_source))
        copy.write_bytes(raw_source)
        raw = run_native(oracle, copy, budget)
    R.shape(doc['$defs']['raw'], raw, doc['$defs'], budget)
    raw_semantics(raw, raw_source, budget)
    typed_semantics(raw, budget)
    config = dict(target=raw['target'], source_filesystem=raw['source_filesystem'], options=raw['options'], cfg_options=raw['cfg_options'], char_bits=8, pointer_bits=64, long_bits=64, little_endian=True)
    out = dict(format='clang-semantic-observation-reference', revision=1, binding='unbound', runtime_authority=False, source_fact_authority=False, executable=False, source_sha256=digest(raw_source), config_sha256=digest(canonical(config)), compiler_sha256=COMPILER, oracle_sha256=binary, build_input_identity=inputs, schema_sha256=SCHEMA_SHA, raw=raw, obligations=['Exact APInt patterns and typed operand identities are observations of the pinned Clang AST, not mathematical execution or SMIR lowering.', 'Origin references identify only nodes of this original source observation; no source-to-SMIR operation/function correspondence is issued.', 'The finite body profile excludes unsupported nodes/types; declaration/type/CFG observations are not a complete translation-unit semantic model.', 'AST regions are syntactic containment, not complete C++ lexical/name-lookup or lifetime scopes.', 'CFG scope/lifetime/destructor elements are compiler observations, not full cleanup/lifetime/source-object proofs.', 'Observed throwing paths may lack automatic destructors; no EH/lifetime completeness claimed.', 'Type spellings and traits never substitute for canonical declaration identity or I-C27 subobject-creation evidence.', 'No portable ABI plan, emitter, private S/J/alias/access/union state or runtime/guest execution is established.', 'Translation-unit/global initialization and compiler-emitted ABI variants are not analyzed as function bodies.'])
    R.shape(doc['$defs']['report'], out, doc['$defs'], budget)
    need(read(source, 1 << 20, budget) == raw_source, 'CEW_PROVENANCE', 'source afterguard')
    need(read(SCHEMA, 1 << 20, budget) == schema_raw, 'CEW_PROVENANCE', 'schema afterguard')
    after, after_raw, after_binary, after_inputs = native_identity(oracle, budget)
    need(after_raw == receipt_raw and after_binary == binary and (after_inputs == inputs), 'CEW_PROVENANCE', 'native afterguard')
    precharge_copy(out, budget)
    witness = ObservationWitness(R.freeze(out), ledger=budget)
    budget.charge(work=4, edges=1, copied_bytes=128)
    _ISSUED_OBSERVATIONS[witness] = (witness.data, budget)
    return witness

def load_budget(path):
    path = Path(path)
    size = path.stat().st_size
    need(size <= 4096, 'CEW_INPUT', 'budget bootstrap size')
    with path.open('rb') as stream:
        raw = stream.read(4097)
    need(len(raw) <= 4096 and len(raw) == size, 'CEW_INPUT', 'budget bootstrap growth/size')
    depth = 0
    quoted = False
    escaped = False
    for c in raw.decode('utf8', 'strict'):
        if quoted:
            if escaped:
                escaped = False
            elif c == '\\':
                escaped = True
            elif c == '"':
                quoted = False
        elif c == '"':
            quoted = True
        elif c in '{[':
            depth += 1
            need(depth <= 8, 'CEW_INPUT', 'budget bootstrap depth')
        elif c in '}]':
            depth -= 1
            need(depth >= 0, 'CEW_INPUT', 'budget bootstrap depth')
    d = load_json(raw)
    need(type(d) is dict and set(d) == {'max_work', 'max_edges', 'max_copied_bytes', 'max_depth'}, 'CEW_INPUT', 'budget fields')
    need(all((type(d[k]) is int and 0 <= d[k] <= (1 << 64) - 1 for k in ['max_work', 'max_edges', 'max_copied_bytes'])) and type(d['max_depth']) is int and (1 <= d['max_depth'] <= 128), 'CEW_INPUT', 'budget counts')
    return R.apis()[4].SourceQueryBudget(**d)

def main():
    import argparse
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='command', required=True)
    build = sub.add_parser('build')
    build.add_argument('--llvm', type=Path, required=True)
    build.add_argument('--output', type=Path, required=True)
    obs = sub.add_parser('observe')
    obs.add_argument('--oracle', type=Path, required=True)
    obs.add_argument('--source', type=Path, required=True)
    obs.add_argument('--budget', type=Path, required=True)
    a = p.parse_args()
    if a.command == 'build':
        from build_semantic_observation import build
        build(a.llvm, a.output)
        return
    budget = load_budget(a.budget)
    print(json.dumps(observe(a.source, a.oracle, budget=budget).report(budget=budget), sort_keys=True, indent=2))
if __name__ == '__main__':
    main()
