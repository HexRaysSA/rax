"""Authored conditional protocol cases, not live CPP/source facts."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import unittest
import normal_scope_outcomes as N

FOLDER = N.ROOT / 'docs/specifications/smir/portable/conformance/runtime/normal-scope-outcomes'


def budget(**kw):
    policy = dict(max_work=10000000, max_edges=1000000, max_copied_bytes=64000000, max_depth=64)
    policy.update(kw)
    return N.source_api().SourceQueryBudget(**policy)


def hypothesis():
    program = dict(context='ctx', journal=dict(module=dict(kind='self'), id=0), view='complete')
    shared = dict(scope='a', scope_generation=1, view='v', program=deepcopy(program), object='object',
                  object_generation=1, owner='owner', owner_generation=1, frontier='normal')
    return dict(format='conditional-normal-scope-outcomes', revision=1, binding='unbound', contexts=['ctx'],
        owners=[dict(id='owner', context='ctx', activation='activation', generation=1, state='active')],
        objects=[dict(id='object', context='ctx', generation=1, allocation='storage', allocation_generation=1)],
        journals=[dict(id='j', view='v', owner='owner', owner_generation=1, state='live')],
        views=[dict(id='v', program=program, object='object', object_generation=1, owner='owner',
                    owner_generation=1, mode='construct', state='live', journal='j')],
        scopes=[dict(id='a', view='v', generation=1, subject='existing_object', state='open'),
                dict(id='b', view='v', generation=1, subject='existing_object', state='open')],
        handoffs=[dict(id='h', **shared, current_journal='j', source_contract='original-borrow',
            original_ticket='borrow-return', holder=dict(kind='scope', scope='b', generation=1),
            assumption='conditional_original_normal_handoff')], receipts=[],
        events=[dict(kind='preflight', scope='a', generation=1, journal='j', frontier='normal',
                     location='normal_post', evidence='h', permit='p'), dict(kind='commit', permit='p')])


def terminal(kind):
    d = hypothesis(); d['handoffs'] = []; d['journals'][0]['state'] = 'consumed'
    v = d['views'][0]; v['journal'] = None
    v['state'] = 'published' if kind == 'published' else 'view_completed'
    if kind == 'view_completed': v['program']['view'] = 'nonvirtual'
    if kind == 'destruction_completed': v['mode'] = 'destroy'
    d['scopes'][0]['subject'] = 'physical'
    d['receipts'] = [dict(id='receipt', scope='a', scope_generation=1, view='v', program=deepcopy(v['program']),
        object='object', object_generation=1, owner='owner', owner_generation=1, frontier='normal',
        input_journal='j', kind=kind, assumption='conditional_original_normal_completion')]
    d['events'][0].update(journal=None, location='return_exit', evidence='receipt')
    return d


def cases():
    rows = {}
    def add(name, d, kind='valid', code=None): rows[name] = dict(expected=kind, code=code, document=d)
    add('retained-same-view-scope', hypothesis())
    for subject in ['inline', 'source_object']:
        d = hypothesis(); d['scopes'][0]['subject'] = subject; d['events'][0]['location'] = 'pre_op'
        add(subject + '-association-only', d)
    for kind in ['published', 'view_completed', 'destruction_completed']: add('terminal-' + kind, terminal(kind))
    d = hypothesis(); d['scopes'][0]['subject'] = 'physical'; d['events'][0]['location'] = 'return_exit'
    add('reject-physical-sibling-scope', d, 'semantic', 'NSO_PHYSICAL_RETENTION')
    d = deepcopy(d); d['handoffs'][0]['holder'] = dict(kind='call', ticket='call', owner='owner', owner_generation=1, source_return_contract='unassigned')
    add('unavailable-original-call-contract', d, 'unavailable', 'NSO_RETAINED_CALL_CONTRACT')
    d = hypothesis(); d['events'][0]['evidence'] = None
    add('unavailable-missing-normal-outcome', d, 'unavailable', 'NSO_NORMAL_OUTCOME_UNAVAILABLE')
    for name, edit, code in [
        ('orphan-holder', lambda d: d['scopes'][1].update(state='closed'), 'NSO_RETAINED_HOLDER'),
        ('self-holder', lambda d: d['handoffs'][0]['holder'].update(scope='a'), 'NSO_RETAINED_HOLDER'),
        ('holder-generation', lambda d: d['handoffs'][0]['holder'].update(generation=2), 'NSO_RETAINED_HOLDER'),
        ('owner-generation', lambda d: d['owners'][0].update(generation=2), 'NSO_GENERATION'),
        ('revoked-owner', lambda d: d['owners'][0].update(state='revoked'), 'NSO_OWNER_LIVENESS'),
        ('scope-generation', lambda d: d['events'][0].update(generation=2), 'NSO_GENERATION'),
        ('object-generation', lambda d: d['handoffs'][0].update(object_generation=2), 'NSO_ASSOCIATION'),
        ('program', lambda d: d['handoffs'][0]['program']['journal'].update(id=1), 'NSO_ASSOCIATION'),
        ('normal-frontier', lambda d: d['events'][0].update(frontier='other'), 'NSO_ASSOCIATION'),
        ('live-j-dropped', lambda d: d['events'][0].update(journal=None), 'NSO_TERMINAL_RECEIPT'),
        ('permit-replay', lambda d: d['events'].append(dict(kind='commit', permit='p')), 'NSO_PERMIT_REPLAY'),
        ('duplicate-permit', lambda d: d['events'].insert(1, deepcopy(d['events'][0])), 'NSO_PERMIT_REPLAY'),
        ('source-location', lambda d: d['events'][0].update(location='return_exit'), 'NSO_SITE_MATRIX'),
        ('context', lambda d: d['owners'][0].update(context='other'), 'NSO_CONTEXT'),
        ('duplicate-scope', lambda d: d['scopes'].append(deepcopy(d['scopes'][0])), 'NSO_DUPLICATE'),
        ('bool-generation', lambda d: d['scopes'][0].update(generation=True), 'NSO_SHAPE'),
        ('open-root', lambda d: d.update(extra=None), 'NSO_SHAPE')]:
        d = hypothesis(); edit(d); add('reject-' + name, d, 'semantic', code)
    d = hypothesis(); d['journals'].append(dict(id='old', view='v', owner='owner', owner_generation=1, state='consumed')); d['events'][0]['journal'] = 'old'
    add('reject-consumed-j-input', d, 'semantic', 'NSO_CURRENT_JOURNAL')
    d = terminal('published'); d['events'][0]['journal'] = 'j'
    add('reject-terminal-as-live-j', d, 'semantic', 'NSO_CURRENT_JOURNAL')
    d = terminal('published'); d['receipts'][0]['kind'] = 'destruction_completed'
    add('reject-wrong-terminal-kind', d, 'semantic', 'NSO_TERMINAL_RECEIPT')
    return rows


class NormalScopeTests(unittest.TestCase):
    def test_independent_authored_fixture_matrix(self):
        authored = cases(); self.assertEqual(authored, json.loads((FOLDER / 'cases.json').read_bytes())['cases'])
        for name, case in authored.items():
            with self.subTest(name=name):
                original = deepcopy(case['document'])
                if case['expected'] == 'valid':
                    result = N.verify(case['document'], budget=budget())
                    self.assertEqual(result.closed_scopes, ('a',)); self.assertEqual(result.binding, 'unbound')
                    self.assertFalse(result.runtime_authority); self.assertFalse(result.source_fact_authority)
                else:
                    with self.assertRaises(N.ContractError) as caught: N.verify(case['document'], budget=budget())
                    self.assertEqual((caught.exception.kind, caught.exception.code), (case['expected'], case['code']))
                self.assertEqual(original, case['document'])

    def test_closure_only_changes_projection_once(self):
        d = hypothesis(); m = N.ConditionalModel(d, budget=budget())
        before = deepcopy({name: m.document[name] for name in ['owners', 'objects', 'journals', 'views']})
        p = m.preflight(d['events'][0]); self.assertEqual(m.scopes['a']['state'], 'open'); m.commit(p)
        self.assertEqual(before, {name: m.document[name] for name in before})
        self.assertEqual(m.scopes['a']['state'], 'closed'); self.assertEqual(m.scopes['b']['state'], 'open')
        self.assertEqual(m.journals['j']['state'], 'live')

    def test_zero_quotas_preserve_input(self):
        d = hypothesis(); before = deepcopy(d)
        for field in ['max_work', 'max_edges', 'max_copied_bytes']:
            with self.subTest(field=field), self.assertRaises(N.source_api().SourceDataError) as caught:
                N.verify(d, budget=budget(**{field: 0}))
            self.assertEqual(caught.exception.kind, 'resource'); self.assertEqual(d, before)

    def test_preflight_quota_no_permit_or_closure(self):
        b = budget(); N.ConditionalModel(hypothesis(), budget=b)
        m = N.ConditionalModel(hypothesis(), budget=budget(max_work=b._used_work)); before = m.state_digest
        with self.assertRaises(N.source_api().SourceDataError): m.preflight(hypothesis()['events'][0])
        self.assertEqual(m.state_digest, before); self.assertEqual(m.permits, {}); self.assertEqual(m.scopes['a']['state'], 'open')

    def test_commit_quota_no_permit_consumption(self):
        b = budget(); first = N.ConditionalModel(hypothesis(), budget=b); first.preflight(hypothesis()['events'][0])
        m = N.ConditionalModel(hypothesis(), budget=budget(max_work=b._used_work)); p = m.preflight(hypothesis()['events'][0]); before = m.state_digest
        with self.assertRaises(N.source_api().SourceDataError): m.commit(p)
        self.assertEqual(m.state_digest, before); self.assertFalse(m.permits[p]['consumed']); self.assertEqual(m.scopes['a']['state'], 'open')

    def test_input_snapshot_and_canonical_budget(self):
        d = hypothesis(); m = N.ConditionalModel(d, budget=budget()); d['owners'][0]['generation'] = 99
        self.assertEqual(m.run().closed_scopes, ('a',)); self.assertEqual(m.owners['owner']['generation'], 1)
        with self.assertRaises(N.ContractError) as caught: N.verify(hypothesis(), budget=object())
        self.assertEqual(caught.exception.code, 'NSO_BUDGET_IDENTITY')

    def test_cycle_and_depth(self):
        d = hypothesis(); d['events'].append(d)
        with self.assertRaises(N.ContractError) as caught: N.verify(d, budget=budget())
        self.assertEqual(caught.exception.code, 'NSO_CYCLE')
        with self.assertRaises(N.ContractError) as caught: N.verify(hypothesis(), budget=budget(max_depth=1))
        self.assertEqual((caught.exception.kind, caught.exception.code), ('resource', 'NSO_RESOURCE'))

    def test_closed_holder_cannot_release_last_obligation(self):
        d = hypothesis(); h = deepcopy(d['handoffs'][0]); h.update(id='h2', scope='b', holder=dict(kind='scope', scope='a', generation=1)); d['handoffs'].append(h)
        e = deepcopy(d['events'][0]); e.update(scope='b', evidence='h2', permit='p2'); d['events'] += [e, dict(kind='commit', permit='p2')]
        with self.assertRaises(N.ContractError) as caught: N.verify(d, budget=budget())
        self.assertEqual(caught.exception.code, 'NSO_RETAINED_HOLDER')

    def test_owner_generation_rechecked_at_commit(self):
        m = N.ConditionalModel(hypothesis(), budget=budget()); p = m.preflight(hypothesis()['events'][0]); m.owners['owner']['generation'] = 2
        with self.assertRaises(N.ContractError) as caught: m.commit(p)
        self.assertEqual(caught.exception.code, 'NSO_GENERATION'); self.assertFalse(m.permits[p]['consumed']); self.assertEqual(m.scopes['a']['state'], 'open')


    def test_original_activation_and_allocation_snapshot_rechecked(self):
        for table, field, replacement in [('owners', 'activation', 'other-activation'),
                                           ('objects', 'allocation_generation', 2),
                                           ('objects', 'allocation', 'other-storage')]:
            with self.subTest(table=table, field=field):
                m = N.ConditionalModel(hypothesis(), budget=budget())
                permit = m.preflight(hypothesis()['events'][0])
                row = getattr(m, table)['owner' if table == 'owners' else 'object']
                row[field] = replacement
                with self.assertRaises(N.ContractError) as caught: m.commit(permit)
                self.assertEqual(caught.exception.code, 'NSO_STALE_IDENTITY')
                self.assertFalse(m.permits[permit]['consumed'])
                self.assertEqual(m.scopes['a']['state'], 'open')
                self.assertEqual(m.journals['j']['state'], 'live')

    def test_schema_capture_reserved_before_actual_open(self):
        from unittest.mock import patch
        original_open = Path.open
        reads = []
        ledger = budget(max_work=1397)
        def observed(path, *args, **kwargs):
            if path == N.SCHEMA: reads.append(ledger._used_work)
            return original_open(path, *args, **kwargs)
        with patch.object(Path, 'open', observed):
            with self.assertRaises(N.source_api().SourceDataError):
                N.ConditionalModel(hypothesis(), budget=ledger)
        self.assertEqual(reads, [])

    def test_schema_capture_is_bounded_before_read(self):
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as folder:
            oversized = Path(folder) / 'schema.json'
            with oversized.open('wb') as output: output.truncate(N.MAX_SCHEMA_BYTES + 1)
            original_open = Path.open
            reads = []
            def observed(path, *args, **kwargs):
                if path == oversized: reads.append(True)
                return original_open(path, *args, **kwargs)
            with patch.object(N, 'SCHEMA', oversized), patch.object(Path, 'open', observed):
                with self.assertRaises(N.ContractError) as caught:
                    N.ConditionalModel(hypothesis(), budget=budget())
            self.assertEqual((caught.exception.kind, caught.exception.code), ('resource', 'NSO_SCHEMA_RESOURCE'))
            self.assertEqual(reads, [])


def write_fixtures():
    FOLDER.mkdir(exist_ok=True)
    paths = [Path(__file__), Path(N.__file__), N.SCHEMA, N.ROOT / 'tools/smir-runtime-contract/source_roles/source_data.py']
    document = dict(format='conditional-normal-scope-outcome-fixtures', binding='unbound',
        authority='Conditional hypotheses only; no private facts, issuer, permit or guest execution.',
        provenance={str(p.relative_to(N.ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}, cases=cases())
    (FOLDER / 'cases.json').write_text(json.dumps(document, indent=2) + '\n')
    (FOLDER / 'README.md').write_text('Conditional/unbound normal-scope reference.\n\n'
        'Run python3 -B -m unittest test_normal_scope_outcomes -v from tools/smir-runtime-contract; repeat with -O.\n'
        'Expected outcomes are authored without executing the verifier. RetainedCall is always unavailable.\n'
        'Actual source/ABI/context/normal-outcome/owner-retention proofs and initialization history/current state are external obligations.\n'
        'No result is a private fact, runtime permit, production admission or guest/native/thread qualification.\n')
    print('authored conditional fixtures', len(document['cases']))


if __name__ == '__main__':
    if '--write-fixtures' in sys.argv: write_fixtures()
    else: unittest.main()
