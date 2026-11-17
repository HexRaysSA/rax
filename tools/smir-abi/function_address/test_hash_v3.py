"""Source-authored V3 vectors, independent preimage oracle and rejection probes.

Run `python3 -m unittest function_address.test_hash_v3 -v` from tools/smir-abi.
`--vectors` prints deterministic vectors without writing any file.
No envelope execution, native witness invocation or private fact constructor.
"""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import unittest

from function_address.hash_v3 import Budget, DOMAIN, HashError, SourceGraph

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / 'docs/specifications/smir/portable/conformance/abi/candidate/complete.json'
VECTORS = ROOT / 'docs/specifications/smir/portable/conformance/abi/function-address/hash-v3-vectors.json'


def budget(**changes):
    limits = dict(max_work=100_000_000, max_edges=1_000_000, max_bytes=128_000_000,
                  max_depth=128, max_nodes=4096)
    limits.update(changes)
    return Budget(**limits)


def ref(identifier, slot=None):
    return {'module': {'kind': 'self'} if slot is None else {'kind': 'dependency', 'slot': slot},
            'id': identifier}


def some(value):
    return {'some': value}


def geometry(identifier, size, align, fields=()):
    return dict(id=identifier, type=ref(identifier), size=size, align=align,
                data_size=size, nonvirtual_size=size, nonvirtual_align=align,
                fields=list(fields), bases=[], vptrs=[])


def source_type(scalar, identifier, kind, **values):
    item = deepcopy(scalar)
    item.update(id=identifier, kind=kind, bits=0, signed=False, elements=[], extent=None,
                representation='none', execution=None, layout=None, flags=[],
                methods=[], enumerators=[], record_input=None)
    item['identity'].update(language='cpp23' if kind == 'record' else 'c23',
        linkage='external' if kind == 'record' else 'builtin',
        entity='example.R' if kind == 'record' else kind, definition='0' * 64)
    item.update(values)
    return item


def source_pair():
    """Same authored R(*)[3] source counter for the active ABI3/V3 contract."""
    current = json.loads(SOURCE.read_text())
    scalar = deepcopy(next(t for t in current['types'] if t['id'] == 1))
    domain = deepcopy(next(d for d in current['domains'] if d['id'] == scalar['domain']))
    record = source_type(scalar, 100, 'record')
    array = source_type(scalar, 101, 'array', elements=[ref(100)], extent=some(3))
    pointer = source_type(scalar, 102, 'pointer', bits=64, elements=[ref(101)],
        representation='value', execution=some(ref(3)), layout=some(102),
        flags=['complete', 'trivial_copy', 'trivial_destroy'])
    fn = source_type(scalar, 103, 'function', elements=[ref(102), ref(102)],
                     extent=some(1), flags=['complete'])
    before = {'types': [scalar, record, array, pointer, fn],
              'layouts': [deepcopy(next(l for l in current['layouts'] if l['id'] == 1)),
                          geometry(102, 8, 8)], 'domains': [domain]}
    after = deepcopy(before)
    record = next(t for t in after['types'] if t['id'] == 100)
    record.update(representation='storage', execution=some(ref(4)), layout=some(100),
        flags=['complete', 'trivial_copy', 'trivial_destroy'], record_input=some({
            'revision': 1, 'kind': 'struct', 'explicit_align': None, 'pod03': True,
            'trivial': True, 'standard_layout': True, 'polymorphic': False,
            'dynamic': False, 'empty': False, 'fields': [{
                'name': some('value'), 'type': ref(1), 'bit_width': None,
                'explicit_align': None, 'no_unique_address': False,
                'anonymous': False, 'access': 'public'}], 'bases': []}))
    next(t for t in after['types'] if t['id'] == 101).update(representation='storage',
        execution=some(ref(5)), layout=some(101), flags=['complete', 'trivial_copy', 'trivial_destroy'])
    after['layouts'] += [geometry(100, 4, 4, [{
        'declaration_index': 0, 'name': 'value', 'type': ref(1),
        'offset_bits': 0, 'width_bits': 32, 'flags': []}]), geometry(101, 12, 4)]
    return before, after


def digest(document, identifier, *, view='DEF', expectations=None, ledger=None):
    ledger = ledger if ledger is not None else budget()
    graph = SourceGraph({'main': document}, expectations=expectations or {}, budget=ledger)
    return graph.hash('main', ref(identifier), budget=ledger, view=view)


def build_vectors():
    before, after = source_pair()
    vectors = []
    for name, document, identifier, view in [
        ('scalar-definition', before, 1, 'DEF'),
        ('pointer-incomplete-array', before, 102, 'DEF'),
        ('pointer-completed-array', after, 102, 'DEF'),
        ('function-incomplete-array', before, 103, 'DEF'),
        ('function-completed-array', after, 103, 'DEF'),
        ('record-declaration', before, 100, 'EXPR'),
        ('record-definition', after, 100, 'DEF')]:
        result = digest(document, identifier, view=view)
        vectors.append({'name': name, 'fragment': document, 'root': ref(identifier),
                        'view': view, 'sha256': result.digest,
                        'preimage_ascii': result.preimage.decode('ascii'),
                        'states': result.states, 'edges': result.edges})
    return {'profile': 'isolated-unconsumed-HASH-V3-EXISTING-01-REV2',
            'admission_proof': False, 'domain_hex': DOMAIN.hex(),
            'source_record_seed': str(SOURCE.relative_to(ROOT)),
            'source_record_seed_sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
            'vectors': vectors}


class HashV3Tests(unittest.TestCase):
    def error(self, code, operation, *args, **kwargs):
        with self.assertRaises(HashError) as raised:
            operation(*args, **kwargs)
        self.assertEqual(raised.exception.code, code)
        return raised.exception

    def test_exact_domain_and_independent_scalar_preimage(self):
        self.assertEqual(DOMAIN.hex(), '534d49522d4e4f4d494e414c2d53484150452d563300')
        self.assertEqual(len(DOMAIN), 22)
        before, _ = source_pair()
        scalar = before['types'][0]
        # Literal grammar projection, independent of normalizer/_label/_quotient.
        label = {'node_kind': 'nominal_definition', 'kind': 'scalar', 'qualifiers': [],
            'abi_identity': before['domains'][0]['abi_identity'],
            'identity': {k: scalar['identity'][k] for k in ('language', 'linkage', 'entity', 'library', 'unit')},
            'bits': 32, 'signed': True, 'extent': None,
            'flags': ['complete', 'trivial_copy', 'trivial_destroy'],
            'enumerators': [], 'methods': [], 'record_input': None,
            'layout': {'size': 4, 'align': 4, 'data_size': 4, 'nonvirtual_size': 4,
                       'nonvirtual_align': 4, 'fields': [], 'bases': [], 'vptrs': []},
            'element_count': 0, 'method_count': 0, 'input_field_count': 0,
            'input_base_count': 0, 'output_field_count': 0, 'output_base_count': 0,
            'has_cpp_class': False}
        expected = DOMAIN + json.dumps([{'label': label, 'children': []}],
            sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode('ascii')
        actual = digest(before, 1)
        self.assertEqual(actual.preimage, expected)
        self.assertEqual(actual.digest, hashlib.sha256(expected).hexdigest())

    def test_actual_array_completion_counter_matches_active_v3(self):
        from nominal import NominalGraph
        before, after = source_pair()
        def active(document, identifier):
            return NominalGraph({**document, 'identity': '1' * 64}, 'main').fingerprint(ref(identifier))
        self.assertEqual(active(before, 102), active(after, 102))
        for document in (before, after):
            for identifier in (100, 101, 102, 103):
                self.assertEqual(active(document, identifier), digest(document, identifier).digest)
        self.assertEqual(digest(before, 102).digest, digest(after, 102).digest)
        self.assertEqual(digest(before, 103).digest, digest(after, 103).digest)

    def test_source_only_incomplete_byvalue_prototype_and_definition_views(self):
        before, after = source_pair()
        for document in (before, after):
            fn = next(t for t in document['types'] if t['id'] == 103)
            fn['elements'] = [ref(100), ref(100)]
        self.assertEqual(digest(before, 103).digest, digest(after, 103).digest)
        self.assertNotEqual(digest(before, 100).digest, digest(after, 100).digest)
        self.assertEqual(digest(before, 100, view='EXPR').digest,
                         digest(after, 100, view='EXPR').digest)

    def test_nested_array_expression_is_transitive(self):
        before, after = source_pair()
        for document, complete in ((before, False), (after, True)):
            array = source_type(document['types'][0], 104, 'array', elements=[ref(101)], extent=some(2))
            if complete:
                array.update(flags=['complete', 'trivial_copy', 'trivial_destroy'],
                             layout=some(104), representation='storage', execution=some(ref(9)))
                document['layouts'].append(geometry(104, 24, 4))
            document['types'].append(array)
            next(t for t in document['types'] if t['id'] == 102)['elements'] = [ref(104)]
        self.assertEqual(digest(before, 102).digest, digest(after, 102).digest)

    def test_count_cv_source_identity_and_nested_noexcept_remain_significant(self):
        before, _ = source_pair()
        original = digest(before, 102).digest
        for identifier, field, value in [(101, 'extent', some(4)), (100, 'qualifiers', ['const'])]:
            changed = deepcopy(before)
            next(t for t in changed['types'] if t['id'] == identifier)[field] = value
            self.assertNotEqual(original, digest(changed, 102).digest)
        changed = deepcopy(before)
        changed['types'][1]['identity']['entity'] = 'other.R'
        self.assertNotEqual(original, digest(changed, 102).digest)
        for document in (before, changed):
            pointer = next(t for t in document['types'] if t['id'] == 102)
            pointer.update(elements=[ref(103)], flags=pointer['flags'] + ['code'], representation='code_address')
            next(t for t in document['types'] if t['id'] == 103)['elements'] = [ref(1), ref(1)]
        changed = deepcopy(before)
        next(t for t in changed['types'] if t['id'] == 103)['flags'].append('noexcept')
        self.assertNotEqual(digest(before, 102).digest, digest(changed, 102).digest)

    def test_alpha_ids_and_namespace_collisions(self):
        _, original = source_pair()
        changed = deepcopy(original)
        ids = {t['id']: t['id'] + 900 for t in changed['types']}
        layouts = {l['id']: l['id'] + 1900 for l in changed['layouts']}
        def typeref(reference):
            reference['id'] = ids[reference['id']]
        for typ in changed['types']:
            typ['id'] = ids[typ['id']]; typ['domain'] = 77
            if typ['layout'] is not None:
                typ['layout']['some'] = layouts[typ['layout']['some']]
            for reference in typ['elements']:
                typeref(reference)
            if typ['record_input'] is not None:
                for field in typ['record_input']['some']['fields']:
                    typeref(field['type'])
        for layout in changed['layouts']:
            layout['id'] = layouts[layout['id']]; typeref(layout['type'])
            for field in layout['fields']:
                typeref(field['type'])
        changed['domains'][0]['id'] = 77
        self.assertEqual(digest(original, 102).digest, digest(changed, ids[102]).digest)
        self.assertEqual(digest(original, 100).digest, digest(changed, ids[100]).digest)

    def test_sharing_quotient_not_graph_allocation_identity(self):
        before, _ = source_pair()
        fn = next(t for t in before['types'] if t['id'] == 103)
        fn.update(elements=[ref(1), ref(1), ref(1)], extent=some(2))
        changed = deepcopy(before)
        scalar = deepcopy(changed['types'][0]); scalar.update(id=400, layout=some(401))
        layout = deepcopy(changed['layouts'][0]); layout.update(id=401, type=ref(400))
        changed['types'].append(scalar); changed['layouts'].append(layout)
        next(t for t in changed['types'] if t['id'] == 103)['elements'][1] = ref(400)
        a, b = digest(before, 103), digest(changed, 103)
        self.assertEqual(a.digest, b.digest)
        self.assertGreater(b.states, a.states)

    def test_none_labels_counts_and_excluded_issued_artifacts(self):
        before, _ = source_pair()
        fn = next(t for t in before['types'] if t['id'] == 103)
        fn['elements'] = [ref(1), ref(1)]
        first = digest(before, 103)
        fn.update(execution=some(ref(12)), representation='signature')
        self.assertEqual(first.digest, digest(before, 103).digest)
        labels = json.loads(first.preimage[len(DOMAIN):])
        root = labels[0]['label']
        self.assertIsNone(root['layout']); self.assertIsNone(root['record_input'])
        self.assertFalse(root['has_cpp_class'])
        self.assertEqual(root['element_count'], len(labels[0]['children']))

    def test_unicode_json_escaping_and_immutable_capture(self):
        before, _ = source_pair()
        before['types'][1]['identity']['entity'] = 'R\n"\\\u00e9\U0001f52e'
        b = budget(); graph = SourceGraph({'main': before}, expectations={}, budget=b)
        result = graph.hash('main', ref(102), budget=b)
        self.assertIn(b'\\u00e9\\ud83d\\udd2e', result.preimage)
        self.assertNotIn('é'.encode(), result.preimage)
        before['types'][1]['identity']['entity'] = 'changed'
        self.assertEqual(result.digest, graph.hash('main', ref(102), budget=b).digest)
        self.assertNotEqual(result.digest, digest(before, 102).digest)
        encoded = result.preimage[len(DOMAIN):]
        self.assertEqual(encoded, json.dumps(json.loads(encoded), sort_keys=True,
            ensure_ascii=True, separators=(',', ':')).encode('ascii'))

    def test_dependency_is_original_consumer_expectation(self):
        before, _ = source_pair()
        original = digest(before, 102).digest
        before['types'][3]['elements'] = [ref(7, 3)]
        self.error('HASH3_UNBOUND_DECLARATION', digest, before, 102)
        self.assertEqual(original, digest(before, 102, expectations={('main', 3, 7): 101}).digest)
        self.error('HASH3_REFERENCE', digest, before, 102, expectations={('main', 3, 7): 777})

    def test_unknown_fields_shapes_and_reserved_ids_reject(self):
        before, _ = source_pair()
        mutations = [
            ('HASH3_SHAPE', lambda d: d['types'][1].update(cpp_class={})),
            ('HASH3_SHAPE', lambda d: d['types'][1].update(extent={})),
            ('HASH3_INTEGER', lambda d: d['types'][1].update(id=True)),
            ('HASH3_ID', lambda d: d['types'][1].update(id=0xffffffff)),
            ('HASH3_REFERENCE', lambda d: d['types'][3]['elements'][0].update(id=888)),
            ('HASH3_ID', lambda d: d['types'][3]['elements'][0].update(id=0xffffffff)),
            ('HASH3_UTF8', lambda d: d['types'][1]['identity'].update(entity='\ud800'))]
        for code, mutate in mutations:
            changed = deepcopy(before); mutate(changed)
            with self.subTest(code=code):self.error(code, digest, changed, 102)

    def test_kind_arity_flags_qualifiers_even_source_only_reject(self):
        before, _ = source_pair()
        mutations = [
            ('HASH3_ARITY', 103, 'elements', [ref(1)]),
            ('HASH3_KIND_FLAGS', 103, 'flags', ['complete', 'polymorphic']),
            ('HASH3_QUALIFIERS', 103, 'qualifiers', ['volatile', 'const']),
            ('HASH3_REFERENCE_CATEGORY', 102, 'flags', ['complete', 'lvalue_ref']),
            ('HASH3_EXTENT', 101, 'extent', some(0)),
            ('HASH3_ARRAY_COMPLETENESS', 101, 'flags', ['complete']),
            ('HASH3_NONOBJECT_LAYOUT', 103, 'layout', some(102)),
            ('HASH3_INCOMPLETE', 100, 'execution', some(ref(1)))]
        for code, identifier, field, value in mutations:
            changed = deepcopy(before)
            next(t for t in changed['types'] if t['id'] == identifier)[field] = value
            with self.subTest(code=code):self.error(code, digest, changed, 103)

    def test_byvalue_cycles_reject_pointer_recursion_remains_finite(self):
        _, after = source_pair()
        r = next(t for t in after['types'] if t['id'] == 100)
        after['layouts'][-2]['fields'][0]['type'] = ref(100)
        r['record_input']['some']['fields'][0]['type'] = ref(100)
        self.error('HASH3_VALUE_CYCLE', digest, after, 100)
        _, after = source_pair()
        pointer = next(t for t in after['types'] if t['id'] == 102)
        pointer['elements'] = [ref(100)]
        after['layouts'][-2]['fields'][0]['type'] = ref(102)
        r = next(t for t in after['types'] if t['id'] == 100)
        r['record_input']['some']['fields'][0]['type'] = ref(102)
        after['layouts'][-2].update(size=8, align=8, data_size=8,
            nonvirtual_size=8, nonvirtual_align=8)
        after['layouts'][-2]['fields'][0]['width_bits'] = 64
        after['layouts'][-1].update(size=24, align=8, data_size=24,
            nonvirtual_size=24, nonvirtual_align=8)
        result = digest(after, 100)
        self.assertLess(result.states, 10)

    def test_budget_zero_atomic_refusal_and_no_policy_reset(self):
        b = budget(max_work=0)
        self.error('HASH3_RESOURCE', b.charge, work=1)
        self.assertEqual(b.used, (0, 0, 0))
        with self.assertRaises(AttributeError):b._limits = (100,) * 5
        self.error('HASH3_BUDGET', b.__init__, max_work=1, max_edges=1,
                   max_bytes=1, max_depth=1, max_nodes=1)
        before, _ = source_pair()
        self.error('HASH3_RESOURCE', digest, before, 102, ledger=b)
        self.assertEqual(b.used, (0, 0, 0))
        self.error('HASH3_BUDGET', SourceGraph, {'main': before}, expectations={}, budget=None)

    def test_node_depth_edge_and_output_budget_boundaries(self):
        before, _ = source_pair()
        self.error('HASH3_NODES', digest, before, 102, ledger=budget(max_nodes=1))
        self.error('HASH3_DEPTH', digest, before, 102, ledger=budget(max_depth=2))
        self.error('HASH3_RESOURCE', digest, before, 102, ledger=budget(max_edges=0))
        b = budget(); SourceGraph({'main': before}, expectations={}, budget=b)
        capture_bytes = b.used[2]
        self.error('HASH3_RESOURCE', digest, before, 102, ledger=budget(max_bytes=capture_bytes + 1024))

    def test_large_names_prefixes_and_unicode_expansion_are_charged(self):
        before, _ = source_pair()
        before['types'][1]['identity']['entity'] = 'R' * 100_000
        self.error('HASH3_RESOURCE', digest, before, 102, ledger=budget(max_work=1000))
        before, _ = source_pair()
        r2 = deepcopy(before['types'][1]); r2['id'] = 200
        prefix = 'common-' * 1000
        before['types'][1]['identity']['entity'] = prefix + 'A'
        r2['identity']['entity'] = prefix + 'B'; before['types'].append(r2)
        next(t for t in before['types'] if t['id'] == 103)['elements'] = [ref(100), ref(200)]
        b = budget(); digest(before, 103, ledger=b)
        self.assertGreater(b.used[0], 4 * len(prefix))
        before, _ = source_pair()
        before['types'][1]['identity']['entity'] = '🔮' * 1000
        probe = budget(); SourceGraph({'main': before}, expectations={}, budget=probe)
        limited = budget(max_bytes=probe.used[2] + 30_000)
        graph = SourceGraph({'main': before}, expectations={}, budget=limited)
        self.error('HASH3_RESOURCE', graph.hash, 'main', ref(100), budget=limited, view='EXPR')

    def test_different_ledger_cannot_query_existing_graph(self):
        before, _ = source_pair(); b = budget()
        graph = SourceGraph({'main': before}, expectations={}, budget=b)
        self.error('HASH3_CONTEXT', graph.hash, 'main', ref(102), budget=budget())

    def test_top_cv_projection_retains_restrict_and_nested_cv(self):
        before, _ = source_pair()
        qualified = deepcopy(before)
        qualified['types'][3]['qualifiers'] = ['const', 'restrict', 'volatile']
        restricted = deepcopy(before)
        restricted['types'][3]['qualifiers'] = ['restrict']
        def projected(document):
            b = budget(); g = SourceGraph({'main': document}, expectations={}, budget=b)
            return g.hash('main', ref(102), budget=b, ignore_top_cv=True).digest
        self.assertEqual(projected(qualified), digest(restricted, 102).digest)
        self.assertNotEqual(projected(qualified), digest(before, 102).digest)
        qualified['types'][1]['qualifiers'] = ['const']
        self.assertNotEqual(projected(qualified), digest(restricted, 102).digest)

    def test_enum_definition_values_and_expression_declaration(self):
        before, _ = source_pair()
        enum = source_type(before['types'][0], 200, 'enum', bits=32, signed=True,
            elements=[ref(1)], flags=['complete', 'scoped', 'fixed_base'],
            enumerators=[{'name': 'red', 'value': '01000000'}],
            layout=some(200), execution=some(ref(1)), representation='value')
        enum['identity'].update(language='cpp23', linkage='external', entity='example.Color')
        before['types'].append(enum); before['layouts'].append(geometry(200, 4, 4))
        changed = deepcopy(before)
        changed['types'][-1]['enumerators'][0]['value'] = '02000000'
        self.assertNotEqual(digest(before, 200).digest, digest(changed, 200).digest)
        self.assertEqual(digest(before, 200, view='EXPR').digest,
                         digest(changed, 200, view='EXPR').digest)

    def test_base_method_vptr_projection_and_excluded_compiled_ids(self):
        _, document = source_pair()
        base = next(t for t in document['types'] if t['id'] == 100)
        base['identity']['entity'] = 'example.Base'
        derived = deepcopy(base)
        derived.update(id=200, layout=some(200),
            flags=['complete', 'polymorphic', 'trivial_destroy'], methods=[{
                'name': 'f', 'signature': ref(103), 'virtual': True,
                'slot': some(0), 'noexcept': False}])
        derived['identity']['entity'] = 'example.Derived'
        inp = derived['record_input']['some']
        inp.update(fields=[], bases=[{'type': ref(100), 'virtual': False, 'access': 'public'}],
                   pod03=False, trivial=False, standard_layout=False, polymorphic=True, dynamic=True)
        layout = geometry(200, 16, 8)
        layout.update(data_size=12, nonvirtual_size=12, bases=[{
            'type': ref(100), 'offset': 8, 'virtual': False, 'declaration_index': some(0),
            'origin_path': [0], 'adjustment': {'kind': 'fixed', 'offset': 8}}],
            vptrs=[{'offset': 0, 'offset_top': 0, 'rtti': some(ref(800)),
                'slots': [ref(900)], 'vcall_offsets': [], 'vbase_offsets': [], 'component_order': []}])
        document['types'].append(derived); document['layouts'].append(layout)
        result = digest(document, 200)
        root = json.loads(result.preimage[len(DOMAIN):])[0]
        self.assertEqual([root['label'][k] for k in ('element_count', 'method_count',
            'input_field_count', 'input_base_count', 'output_field_count', 'output_base_count')], [0, 1, 0, 1, 0, 1])
        self.assertEqual(len(root['children']), 3)
        changed = deepcopy(document)
        changed['layouts'][-1]['vptrs'][0].update(rtti=some(ref(801)), slots=[ref(901)])
        self.assertEqual(result.digest, digest(changed, 200).digest)
        changed['types'][-1]['methods'][0]['name'] = 'g'
        self.assertNotEqual(result.digest, digest(changed, 200).digest)

    def test_current_full_source_inventory_can_be_captured(self):
        full = json.loads(SOURCE.read_text())
        fragment = {k: full[k] for k in ('types', 'layouts', 'domains')}
        b = budget(); graph = SourceGraph({'main': fragment}, expectations={}, budget=b)
        for typ in full['types']:
            self.assertEqual(len(graph.hash('main', ref(typ['id']), budget=b).digest), 64)

    def test_committed_vectors_reproduce_without_writes(self):
        current = json.loads(VECTORS.read_text())
        self.assertEqual(current, build_vectors())
        for vector in current['vectors']:
            preimage = vector['preimage_ascii'].encode('ascii')
            self.assertEqual(hashlib.sha256(preimage).hexdigest(), vector['sha256'])
            payload = preimage[len(DOMAIN):]
            self.assertEqual(payload, json.dumps(json.loads(payload), sort_keys=True,
                ensure_ascii=True, separators=(',', ':')).encode('ascii'))


if __name__ == '__main__':
    if sys.argv[1:] == ['--vectors']:
        print(json.dumps(build_vectors(), ensure_ascii=True, indent=2))
    else:
        unittest.main(verbosity=2)
