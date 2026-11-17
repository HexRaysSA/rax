"""Original-source canonical coverage witnesses and independent finite-set oracle."""
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from itertools import combinations, product
import importlib.util
import json
from pathlib import Path
import sys
import unittest

from candidate.context import RootContext
from candidate import source_join_paths as P
from test_candidate_source_join import fixture as direct_fixture, ledger, ROOT
from record_layout.test_source_programs import document, record, slot, cleanup, program, q
from function_address.fixtures import seal


def budget(**changes):
    policy = dict(max_work=10**17, max_edges=10**12, max_copied_bytes=10**14)
    policy.update(changes)
    return ledger(**policy)


def geometry(constant, width, coefficients=()):
    return dict(offset_constant_bits=constant, offset_coefficients_bits=list(coefficients), width_bits=width)


def member(index):
    return dict(kind='member', declaration_index=index)


def base(index, virtual=False):
    return dict(kind='base', declaration_index=index, virtual=virtual)


def element(first, count=1):
    return dict(kind='element', selection=dict(first=first, count=count))


def cell(name, nominal, routes, layout, kind='observe', slot_id=None, view='complete'):
    return dict(id=name, program='cleanup', selector=dict(declared_leaf=q(nominal), routes=routes),
                leaf_view=view, geometry=layout,
                coverage=dict(kind=kind, **({} if slot_id is None else dict(slot=slot_id))))


def simple(missing=False, bad=False):
    d, a, o, b = direct_fixture(missing=missing, bad=bad, budget=budget())
    d['format'] = 'conditional-source-join-paths'
    d['cells'] = [cell('root', 100, [[]], geometry(0, 32), 'anchor'),
                  cell('value', 1, [[member(0)]], geometry(0, 32), 'whole_slot', 0)]
    return d, a, o, b


def canonical_fixture(root_name='Box', view='complete', outer=2):
    """New inert descriptors from actual original source.smo, never private facts.

    Extended source/body/trait truth remains an explicit real ABI obligation.
    Expected Box/D/Choice geometry below is authored separately from the resolver.
    """
    spec = importlib.util.spec_from_file_location('join_paths_original_codec', ROOT/'tools/smir-format/codec.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    schemas = {n: json.loads((ROOT/'docs/specifications/smir/portable/schema'/n/'candidate.json').read_text())
               for n in ('abi', 'execution', 'runtime')}
    folder = ROOT/'docs/specifications/smir/portable/conformance/abi/source-paths'
    roots = module.CandidateCodec(schemas).decode((folder/'source.smo').read_bytes()).roots
    names = json.loads((folder/'records.json').read_text())
    types = {t['id']: t for t in roots[10]['types']}
    layouts = {l['id']: l for l in roots[10]['layouts']}
    if outer != 2:
        array = types[10010]
        array['extent'] = {'some': outer}
        layout = layouts[array['layout']['some']]
        for name in ('size', 'data_size', 'nonvirtual_size'):
            layout[name] = 120 * outer
        execution = next(t for t in roots[1]['types'] if t['id'] == array['execution']['some']['id'])
        execution['count'] = outer
        box_layout = layouts[types[names['Box']]['layout']['some']]
        box_layout.update(size=88+120*outer, data_size=84+120*outer, nonvirtual_size=84+120*outer)
        box_layout['fields'][2]['width_bits'] = 960*outer
        box_layout['fields'][4]['offset_bits'] = 640+960*outer
        storage = next(t for t in roots[1]['types'] if t['id'] == types[names['Box']]['execution']['some']['id'])
        storage.clear()
        storage.update(id=20009, kind='array', element=q(9), count=box_layout['size'])
    selected = []

    def collect(identifier):
        t = types[identifier]
        if t['kind'] == 'array':
            collect(t['elements'][0]['id'])
        elif t['kind'] == 'record' and identifier not in selected:
            selected.append(identifier)
            for row in t['record_input']['some']['bases'] + t['record_input']['some']['fields']:
                collect(row['type']['id'])

    collect(names[root_name])
    local = {n: i for i, n in enumerate(selected)}
    a = document()
    a['records'] = []
    for n in selected:
        t = types[n]
        layout = layouts[t['layout']['some']]
        rows = []
        for j, placed in enumerate(layout['bases']):
            target = types[placed['type']['id']]
            child = layouts[target['layout']['some']]
            current = t
            route = []
            for index in placed['origin_path']:
                edge = current['record_input']['some']['bases'][index]
                route.append(dict(kind='base', declaration_index=index, virtual=edge['virtual']))
                current = types[edge['type']['id']]
            rows.append(slot(len(rows), 'virtual_base' if placed['virtual'] else 'nonvirtual_base',
                j if placed['virtual'] else placed['declaration_index']['some'], target['id'], local[target['id']],
                8*placed['offset'], 8*child['nonvirtual_size'], paths=[route], alignment=child['nonvirtual_align']))
        for field in layout['fields']:
            declared = types[field['type']['id']]
            leaf = declared
            extents = []
            while leaf['kind'] == 'array':
                extents.append(leaf['extent']['some'])
                leaf = types[leaf['elements'][0]['id']]
            rows.append(slot(len(rows), index=field['declaration_index'], nominal=declared['id'],
                child=local[leaf['id']] if leaf['kind'] == 'record' else None,
                offset=field['offset_bits'], width=field['width_bits'], name=field['name'],
                alignment=layouts[declared['layout']['some']]['align'], array_extents=extents))
        a['records'].append(record(local[n], t['identity']['entity'], layout['size'], layout['nonvirtual_size'], layout['align'],
            nonvirtual_alignment=layout['nonvirtual_align'], source=dict(context=0, nominal=q(n)),
            record_kind=t['record_input']['some']['kind'], slots=rows))
    root = a['records'][0]
    order = sorted([s for s in root['slots'] if view == 'complete' or s['kind'] != 'virtual_base'],
                   key=lambda s: ({'virtual_base': 0, 'nonvirtual_base': 1, 'member': 2}[s['kind']], s['declaration_index']))
    required = [] if root['record_kind'] == 'union' else [s['id'] for s in order]
    a['cleanups'] = [cleanup(0, 0, required, view)]
    # No source-body claim is made; empty implementation is an explicit obligation.
    a['programs'] = []
    signature = roots[10]['signatures'][0]['id']
    a['cleanups'][0]['signature'] = q(signature)
    roots[10]['journals'].append(dict(id=700, signature=signature, params=[], slots=[], normal_order=[], exception_order=[]))
    seal(roots)
    o = RootContext(roots)
    b = budget()
    stamp = o.prepare_source_data(budget=b)
    d = simple()[0]
    family = {n: roots[2]['manifest']['key'][n] for n in ('namespace', 'name', 'abi_major')}
    a['contexts'][0].update(family=family, abi_site=roots[10]['identity'], abi_root=dict(stamp.root_digests)[10].hex(), module_root=dict(stamp.root_digests)[2].hex())
    d['contexts'][0].update(family=family, abi_site=roots[10]['identity'], schema_digest=stamp.schema_digest.hex(), roots=[dict(section=n, digest=h.hex()) for n, h in stamp.root_digests])
    d['programs'][0].update(source_class=q(names[root_name]), view=view, cleanup_signature=q(signature))
    anchor_width = 8 * root['complete_size' if view == 'complete' else 'nonvirtual_size']
    d['cells'] = [cell('root', names[root_name], [[]], geometry(0, anchor_width), 'anchor', view=view)]
    for row in order if root['record_kind'] != 'union' else []:
        routes = [[dict(kind=e['kind'], declaration_index=e['declaration_index'], **({} if e['kind'] == 'member' else dict(virtual=e['virtual']))) for e in path] for path in row['paths']]
        d['cells'].append(cell('slot'+str(row['id']), row['source']['nominal']['id'], routes,
            geometry(row['offset_bits'], row['width_bits']), 'whole_slot', row['id'],
            view='complete' if row['kind'] == 'member' else 'nonvirtual'))
    return d, a, o, b


def run(d, a, o, b, **kw):
    return P.verify(d, a, original_owners=(P.OriginalOwnerInput('original', o),), budget=b, **kw)


def array_partition(d, outer=2, boxes=None):
    d['cells'] = [c for c in d['cells'] if c['id'] != 'slot2']
    boxes = boxes if boxes is not None else [((0, outer), (0, 1)), ((0, outer), (1, 2))]
    for i, box in enumerate(boxes):
        d['cells'].append(cell('part'+str(i), 10005,
            [[member(2)] + [element(first, count) for first, count in box]],
            geometry(640, 320, (960, 320)), 'slot_elements', 2))


class SourceJoinPathsTests(unittest.TestCase):
    def test_actual_original_direct_and_constructor_flags(self):
        d, a, o, b = simple()
        before = deepcopy((d, a))
        r = run(d, a, o, b)
        self.assertEqual(before, (d, a))
        self.assertFalse(r.runtime_authority)
        self.assertFalse(r.source_fact_authority)
        self.assertEqual(r.coverage_certificates[0].covered_cardinality, 1)
        self.assertIsNone(r.coverage_certificates[0].terminal_demand)
        with self.assertRaises(FrozenInstanceError):
            r.binding = 'bound'
        with self.assertRaises(TypeError):
            P.JoinedCanonicalSourceRequirements('', '', (), (), (), (), (), (), runtime_authority=True)

    def test_actual_array_subject_vs_full_element_partition(self):
        d, a, o, b = canonical_fixture()
        whole = run(d, a, o, b)
        cert = next(c for c in whole.coverage_certificates if c.slot == 2)
        self.assertEqual((cert.covered_cardinality, cert.terminal_demand), (1, None))
        array_partition(d)
        result = run(d, a, o, b)
        cert = next(c for c in result.coverage_certificates if c.slot == 2)
        self.assertEqual(cert.covered_cardinality, 6)
        self.assertEqual(cert.principal.leaf_kind, 'array')
        self.assertEqual(cert.terminal_demand.leaf_kind, 'record')
        self.assertEqual(len(cert.terminal_demand.axes), 2)

    def test_array_singleton_hole_overlap_and_mixed_reject(self):
        for boxes in ([((0, 1), (0, 1))], [((0, 2), (0, 2)), ((0, 2), (1, 2))]):
            d, a, o, b = canonical_fixture()
            array_partition(d, boxes=boxes)
            with self.assertRaises(Exception) as caught:
                run(d, a, o, b)
            self.assertEqual(caught.exception.kind, 'semantic')
        d, a, o, b = canonical_fixture()
        saved = deepcopy(d['cells'][3])
        array_partition(d)
        d['cells'].append(saved)
        with self.assertRaisesRegex(P.JoinError, 'SJX_COVERAGE_MIXED'):
            run(d, a, o, b)

    def test_nested_virtual_observation_and_complete_diamond(self):
        d, a, o, b = canonical_fixture()
        d['cells'].append(cell('virtual', 10001, [[member(2), element(0, 2), element(0, 3), base(0), base(0, True)],
            [member(2), element(0, 2), element(0, 3), base(1), base(0, True)]], geometry(896, 32, (960, 320)), view='nonvirtual'))
        self.assertEqual(len(run(d, a, o, b).coverage_certificates), 5)
        d, a, o, b = canonical_fixture('D')
        self.assertEqual(len(run(d, a, o, b).coverage_certificates), 4)

    def test_nonvirtual_view_and_sticky_unknown(self):
        d, a, o, b = canonical_fixture('D', 'nonvirtual')
        self.assertEqual(len(run(d, a, o, b).coverage_certificates), 3)
        d['cells'].append(cell('unknown', 10001, [[base(0), base(0, True)]], geometry(0, 32), view='nonvirtual'))
        with self.assertRaises(P.JoinError) as caught:
            run(d, a, o, b)
        self.assertEqual(caught.exception.kind, 'unavailable')
        self.assertIn('ABI_PATH_NV_MOST_DERIVED_UNAVAILABLE', caught.exception.detail)
        d['cells'].append(cell('bad', 10001, [[base(99)]], geometry(0, 32), view='nonvirtual'))
        with self.assertRaisesRegex(Exception, 'ABI_PATH_DECLARATION_INDEX'):
            run(d, a, o, b)

    def test_union_observation_empty_cleanup(self):
        d, a, o, b = canonical_fixture('Choice')
        d['cells'].append(cell('union_member', 10001, [[member(0)]], geometry(0, 32)))
        self.assertEqual(run(d, a, o, b).coverage_certificates, ())
        d['cells'][-1]['coverage'] = dict(kind='whole_slot', slot=0)
        with self.assertRaisesRegex(P.JoinError, 'SJX_COVERAGE_SLOT'):
            run(d, a, o, b)

    def test_anchor_observation_and_descendant_cannot_cover(self):
        d, a, o, b = simple()
        d['cells'] = d['cells'][:1]
        with self.assertRaisesRegex(P.JoinError, 'SJX_COVERAGE_MISSING'):
            run(d, a, o, b)
        d, a, o, b = canonical_fixture()
        d['cells'][1] = cell('descendant', 10002, [[member(0), member(0)]], geometry(224, 32), 'whole_slot', 0)
        with self.assertRaisesRegex(P.J.source_api().SourceDataError, 'ABI_PATH_DECLARED_LEAF'):
            run(d, a, o, b)

    def test_explicit_geometry_views_and_utf8(self):
        for change, code in [(lambda d: d['cells'][1]['geometry'].update(width_bits=64), 'SJX_GEOMETRY'),
                             (lambda d: d['cells'][1].update(leaf_view='nonvirtual'), 'SJX_LEAF_VIEW'),
                             (lambda d: d['contexts'][0]['family'].update(name='\ud800'), 'SJX_SHAPE')]:
            d, a, o, b = simple()
            change(d)
            with self.assertRaisesRegex(P.JoinError, code):
                run(d, a, o, b)

    def test_fresh_same_bytes_and_prior_owner_reuse(self):
        d, a, o, b = simple()
        first = run(d, a, o, b)
        o2 = RootContext(deepcopy(o.sections))
        second = run(d, a, o2, b)
        self.assertIsNot(first.bindings[0].stamp, second.bindings[0].stamp)
        with self.assertRaisesRegex(P.JoinError, 'SJX_PRIOR_BINDING'):
            run(d, a, o2, b, expected_bindings=first.bindings)

    def test_actual_trillion_extent_bounded_ledger(self):
        n = 10**12
        d, a, o, b = canonical_fixture(outer=n)
        array_partition(d, outer=n)
        start = b._used_work
        result = run(d, a, o, b)
        cert = next(c for c in result.coverage_certificates if c.slot == 2)
        self.assertEqual(cert.covered_cardinality, 3*n)
        self.assertEqual(len(cert.contributors), 2)
        large_work = b._used_work-start
        d, a, o, b = canonical_fixture()
        array_partition(d)
        start = b._used_work
        run(d, a, o, b)
        self.assertLess(large_work, 4*(b._used_work-start))

    def test_small_finite_set_oracle(self):
        b = budget()
        comparisons = 0
        for rank in (1, 2, 3):
            for extents in product(range(1, 4), repeat=rank):
                target = set(product(*(range(e) for e in extents)))
                boxes = list(product(*[[(f, c) for f in range(e) for c in range(1, e-f+1)] for e in extents]))
                for n in range(3):
                    for family in combinations(boxes, n):
                        sets = [set(product(*(range(f, f+c) for f, c in box))) for box in family]
                        expected = all(not (left & right) for left, right in combinations(sets, 2)) and set().union(*sets) == target
                        try:
                            P.partition(extents, family, b)
                            actual = True
                        except P.JoinError:
                            actual = False
                        self.assertEqual(actual, expected, (extents, family))
                        comparisons += 1
        self.assertGreater(comparisons, 1000)

    def test_missing_source_does_not_hide_duplicate_or_missing_demand(self):
        d, a, o, b = simple(missing=True)
        with self.assertRaises(P.JoinError) as caught:
            run(d, a, o, b)
        self.assertEqual(caught.exception.kind, 'unavailable')
        duplicate = deepcopy(d['cells'][0])
        duplicate['id'] = 'same_root'
        duplicate['coverage'] = dict(kind='observe')
        d['cells'].append(duplicate)
        with self.assertRaisesRegex(P.JoinError, 'SJX_CELL_DUPLICATE'):
            run(d, a, o, b)
        d['cells'] = d['cells'][:1]
        with self.assertRaisesRegex(P.JoinError, 'SJX_COVERAGE_MISSING'):
            run(d, a, o, b)
        d, a, o, b = simple(missing=True, bad=True)
        with self.assertRaisesRegex(Exception, 'ABI_SP_ORIGINAL_JOURNAL_SIGNATURE'):
            run(d, a, o, b)

    def test_zero_quotas_depth_cached_indexes_and_prior_bound(self):
        for key in ('max_work', 'max_edges', 'max_copied_bytes'):
            d, a, o, b = simple()
            with self.assertRaises(P.J.source_api().SourceDataError):
                run(d, a, o, budget(**{key: 0}))
        d, a, o, b = simple()
        with self.assertRaises(P.JoinError) as caught:
            run(d, a, o, budget(max_depth=2))
        self.assertEqual(caught.exception.kind, 'resource')
        o.functions = {}
        result = run(d, a, o, b)
        with self.assertRaisesRegex(P.JoinError, 'SJX_PRIOR_BINDING'):
            run(d, a, o, b, expected_bindings=result.bindings*257)
        with self.assertRaisesRegex(P.JoinError, 'SJX_BUDGET_IDENTITY'):
            run(d, a, o, object())

    def test_final_schema_guard_real_delegate_and_no_unbudgeted_read(self):
        from unittest.mock import patch
        import tempfile
        d, a, o, b = simple()
        original = RootContext.prepare_source_data
        count = []
        def measure(owner, *, budget):
            count.append(1)
            return original(owner, budget=budget)
        with patch.object(RootContext, 'prepare_source_data', measure):
            run(d, a, o, b)
        last = len(count)
        with tempfile.TemporaryDirectory(prefix='smir-join-paths-guard-') as folder:
            path = Path(folder)/'schema.json'
            path.write_bytes(P.SCHEMA.read_bytes())
            count.clear()
            def mutate(owner, *, budget):
                result = original(owner, budget=budget)
                count.append(1)
                if len(count) == last:
                    path.write_bytes(path.read_bytes()+b' ')
                return result
            d, a, o, b = simple()
            with patch.object(P, 'SCHEMA', path), patch.object(RootContext, 'prepare_source_data', mutate):
                with self.assertRaisesRegex(P.JoinError, 'SJX_SCHEMA_IDENTITY'):
                    run(d, a, o, b)
        d, a, o, b = simple()
        with patch.object(Path, 'open', side_effect=AssertionError('unbudgeted IO')):
            with self.assertRaises(P.J.source_api().SourceDataError):
                run(d, a, o, budget(max_work=1))

    def test_invalid_box_certificate_units_and_no_nested_element_substitution(self):
        for boxes in ((((0, 1), (0, 6)),), (((True, 1), (0, 3)),), (((0, 2), (0, 0)),)):
            with self.assertRaises(P.JoinError):
                P.partition((2, 3), boxes, budget())
        d, a, o, b = simple()
        cert = run(d, a, o, b).coverage_certificates[0]
        with self.assertRaisesRegex(P.JoinError, 'SJX_CARDINALITY'):
            replace(cert, covered_cardinality=2)
        d, a, o, b = canonical_fixture()
        array_partition(d)
        for row in d['cells']:
            if row['coverage']['kind'] == 'slot_elements':
                row['selector']['routes'][0].append(member(0))
                row['selector']['declared_leaf'] = q(10002)
                row['geometry'] = geometry(864, 32, (960, 320))
        with self.assertRaisesRegex(P.J.source_api().SourceDataError, 'ABI_PATH_DECLARED_LEAF'):
            run(d, a, o, b)

    def test_original_compatible_virtual_leaf_aliases_and_conflicts(self):
        for conflict, qualified in ((False, False), (True, False), (False, True)):
            d, a, old, unused = canonical_fixture('D')
            roots = deepcopy(old.sections)
            types = {t['id']: t for t in roots[10]['types']}
            layouts = {l['id']: l for l in roots[10]['layouts']}
            alias = deepcopy(types[10001])
            alias['id'] = 19001
            alias['layout'] = {'some': 19001}
            if qualified:
                alias['qualifiers'] = ['const']
            placement = deepcopy(layouts[types[10001]['layout']['some']])
            placement.update(id=19001, type=q(19001))
            if conflict:
                alias['record_input']['some']['fields'][0]['name'] = {'some': 'conflict'}
                placement['fields'][0]['name'] = 'conflict'
            roots[10]['types'].append(alias)
            roots[10]['layouts'].append(placement)
            right = types[10004]
            next(b for b in right['record_input']['some']['bases'] if b['virtual'])['type'] = q(19001)
            next(b for b in layouts[right['layout']['some']]['bases'] if b['virtual'])['type'] = q(19001)
            original_record = next(r for r in a['records'] if r['source']['nominal'] == q(10001))
            alias_record = deepcopy(original_record)
            alias_record['id'] = max(r['id'] for r in a['records'])+1
            alias_record['source']['nominal'] = q(19001)
            if conflict:
                alias_record['slots'][0]['name'] = 'conflict'
            right_record = next(r for r in a['records'] if r['source']['nominal'] == q(10004))
            for row in right_record['slots']:
                if row['source']['nominal'] == q(10001):
                    row['source']['nominal'] = q(19001)
                    row['element_record'] = alias_record['id']
            a['records'].append(alias_record)
            seal(roots)
            o = RootContext(roots)
            b = budget()
            stamp = o.prepare_source_data(budget=b)
            a['contexts'][0].update(abi_root=dict(stamp.root_digests)[10].hex(), module_root=dict(stamp.root_digests)[2].hex())
            d['contexts'][0].update(schema_digest=stamp.schema_digest.hex(), roots=[dict(section=n, digest=h.hex()) for n, h in stamp.root_digests])
            target = next(c for c in d['cells'] if c['selector']['declared_leaf'] == q(10001))
            target['selector']['routes'] = [[base(1), base(0, True)]]
            if qualified:
                target['selector']['declared_leaf'] = q(19001)
            if conflict or qualified:
                with self.assertRaises(Exception) as caught:
                    run(d, a, o, b)
                self.assertEqual(caught.exception.kind, 'semantic')
            else:
                result = run(d, a, o, b)
                self.assertEqual(len(result.coverage_certificates), 4)
                cert = next(c for c in result.coverage_certificates if c.slot == target['coverage']['slot'])
                actual = next(p for label, kind, report in result.path_reports if kind == 'cells' for p in report.patterns if p.label == target['id'])
                self.assertEqual(actual.declared_leaf[1], 19001)
                self.assertEqual(cert.principal.declared_leaf[1], 10001)

    def test_authored_cases(self):
        folder = ROOT/'docs/specifications/smir/portable/conformance/execution/source-join-paths'
        for case in json.loads((folder/'cases.json').read_text())['cases']:
            with self.subTest(case=case['id']):
                d, a, o, b = canonical_fixture() if case['base'] == 'Box' else simple(missing=case.get('missing', False), bad=case.get('bad', False))
                if case.get('partition'):
                    array_partition(d)
                if case.get('keep_anchor'):
                    d['cells'] = d['cells'][:1]
                if case.get('duplicate_root'):
                    row = deepcopy(d['cells'][0])
                    row['id'] = 'duplicate'
                    row['coverage'] = dict(kind='observe')
                    d['cells'].append(row)
                for edit in case.get('edits', []):
                    parent = d
                    for key in edit['path'][:-1]:
                        parent = parent[key]
                    parent[edit['path'][-1]] = deepcopy(edit['value'])
                if case['expect'] == 'checked':
                    result = run(d, a, o, b)
                    if 'array_cardinality' in case:
                        self.assertEqual(next(c for c in result.coverage_certificates if c.slot == 2).covered_cardinality, case['array_cardinality'])
                else:
                    with self.assertRaises(Exception) as caught:
                        run(d, a, o, b)
                    self.assertEqual(caught.exception.code, case['expect'])

    def test_schema_original_mutation_and_real_afterguard_budget(self):
        from unittest.mock import patch
        import tempfile
        d, a, o, b = simple()
        with tempfile.TemporaryDirectory(prefix='smir-join-paths-schema-') as folder:
            path = Path(folder)/'schema.json'
            path.write_bytes(P.SCHEMA.read_bytes()+b' ')
            with patch.object(P, 'SCHEMA', path), self.assertRaisesRegex(P.JoinError, 'SJX_SCHEMA_IDENTITY'):
                run(d, a, o, b)
        d, a, o, b = simple()
        original = RootContext.prepare_source_data
        calls = []
        def measured(owner, *, budget):
            calls.append(budget._used_work)
            return original(owner, budget=budget)
        with patch.object(RootContext, 'prepare_source_data', measured):
            run(d, a, o, b)
        limited = budget(max_work=calls[-1])
        # Preserve genuine ledger prehistory by creating/stamping a fresh source.
        d, a, o, b = direct_fixture(budget=limited)
        d['format'] = 'conditional-source-join-paths'
        d['cells'] = [cell('root', 100, [[]], geometry(0, 32), 'anchor'), cell('value', 1, [[member(0)]], geometry(0, 32), 'whole_slot', 0)]
        with self.assertRaises(P.J.source_api().SourceDataError):
            run(d, a, o, b)
        d, a, o, b = simple()
        o.sections[10]['identity'] = '00'*32
        with self.assertRaisesRegex(Exception, 'context_snapshot_changed'):
            run(d, a, o, b)


if __name__ == '__main__':
    unittest.main()
