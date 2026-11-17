"""Canonical record authoring and actual reference execution through public CLIs."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import smir

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / 'docs/specifications/smir/portable/conformance/envelope/candidate/reference-execution'


class PortableSourceCLI(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='smir-source-cli-')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.document = json.loads((FIXTURE / 'source.json').read_text())

    def command(self, *arguments):
        return subprocess.run([sys.executable, '-B', str(ROOT / 'tools/smir-format/smir.py'), *map(str, arguments)],
                              text=True, capture_output=True, timeout=240)

    def test_canonical_source_assembles_and_disassembles_exact_bytes(self):
        binary = self.directory / 'object.smo'
        source = self.directory / 'source.json'
        result = self.command('assemble', FIXTURE / 'source.json', '--output', binary)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(binary.read_bytes(), (FIXTURE / 'call42.smo').read_bytes())
        result = self.command('disassemble', binary, '--output', source)
        self.assertEqual(result.returncode, 0, result.stderr)
        rebuilt = self.directory / 'rebuilt.smo'
        result = self.command('assemble', source, '--output', rebuilt)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(rebuilt.read_bytes(), binary.read_bytes())

    def test_image_header_and_opaque_metadata_roundtrip(self):
        self.document['sections']['2']['manifest'].update(kind='image', entry={'some': {'module': {'kind': 'self'}, 'id': 1}})
        self.document['metadata'] = [{'kind': 0x9000, 'required': False, 'hex': '00ffabcd'}]
        encoded = smir.assemble(self.document)
        decoded = smir.disassemble(encoded)
        self.assertEqual(decoded['metadata'], self.document['metadata'])
        self.assertEqual(smir.assemble(decoded), encoded)

    def test_closed_source_and_duplicate_keys(self):
        for damaged in [dict(self.document, unknown=True), {'sections': []},
                        {'sections': {str(k): v for k, v in self.document['sections'].items() if k != '10'}}]:
            with self.subTest(document=damaged.keys()):
                with self.assertRaises(ValueError):
                    smir.assemble(damaged)
        for payload in (b'{"sections":{},"sections":{}}', b'{"x":{"a":1,"a":2}}'):
            with self.assertRaisesRegex(ValueError, 'SOURCE-DUPLICATE-KEY'):
                smir.source_json(payload)
        with self.assertRaisesRegex(ValueError, 'SOURCE-JSON-DEPTH'):
            smir.source_json(b'[' * 2048 + b'0' + b']' * 2048)
        deep = '{"escaped\\\"key":' + '[' * 129 + '0' + ']' * 129 + '}'
        for encoding in ('utf-8', 'utf-16', 'utf-32', 'utf-16le', 'utf-32le'):
            with self.subTest(encoding=encoding):
                with self.assertRaises(ValueError):
                    smir.source_json(deep.encode(encoding))
        damaged = deepcopy(self.document)
        damaged['metadata'] = [{'kind': 0x9000, 'required': False, 'hex': '', 'extra': 1}]
        with self.assertRaisesRegex(ValueError, 'SOURCE-METADATA'):
            smir.assemble(damaged)

    def test_same_input_output_is_rejected_without_mutation(self):
        path = self.directory / 'source.json'
        path.write_text(json.dumps(self.document))
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        result = self.command('assemble', path, '--output', path)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)
        alias = self.directory / 'hardlink.json'
        os.link(path, alias)
        result = self.command('assemble', path, '--output', alias)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)
        self.assertTrue(path.samefile(alias))

    def test_assembly_does_not_bypass_semantic_admission(self):
        self.document['sections']['3']['functions'][0]['blocks'][0]['term']['values'] = [999]
        encoded = smir.assemble(self.document)
        path = self.directory / 'invalid.smo'
        path.write_bytes(encoded)
        result = self.command('run', path, '--entry-function', '1', '--argument-bits', '2a000000',
                              '--reference-policy', FIXTURE / 'policy.json')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(json.loads(result.stdout)['code'], 'ssa_reference')

    def test_authored_arithmetic_function_assembles_and_executes(self):
        function = self.document['sections']['3']['functions'][0]
        typ = deepcopy(function['params'][0]['type'])
        function['blocks'][0]['ops'] = [
            {'op': 'constant', 'results': [{'id': 1, 'type': typ}], 'operands': [],
             'literal': {'kind': 'bits', 'value': '01000000'}},
            {'op': 'i_add', 'results': [{'id': 2, 'type': typ}], 'operands': [0, 1], 'flags': []}]
        function['blocks'][0]['term']['values'] = [2]
        source = self.directory / 'increment.json'
        binary = self.directory / 'increment.smo'
        source.write_text(json.dumps(self.document))
        result = self.command('assemble', source, '--output', binary)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.command('run', binary, '--entry-function', '1', '--argument-bits', '2a000000',
                              '--reference-policy', FIXTURE / 'policy.json')
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        report = json.loads(result.stdout)
        self.assertEqual(report['status'], 'reference-return')
        self.assertEqual(report['values'], [{'bits_le': '2b000000'}])
        self.assertEqual(report['steps'], 9)
        self.assertFalse(report['production_admitted'])


    def integer_type(self, width):
        types = self.document['sections']['1']['types']
        for item in types:
            if item['kind'] == 'int' and item['bits'] == width:
                return {'module': {'kind': 'self'}, 'id': item['id']}
        identifier = max(item['id'] for item in types) + 1
        types.append({'kind': 'int', 'id': identifier, 'bits': width})
        return {'module': {'kind': 'self'}, 'id': identifier}

    def generic_function(self, params, results, *, returns=None, operations=()):
        sections = self.document['sections']
        identifier = max(item['id'] for item in sections['1']['types']) + 1
        signature = {'module': {'kind': 'self'}, 'id': identifier}
        sections['1']['types'].append({'kind': 'function', 'id': identifier,
            'params': deepcopy(params), 'results': deepcopy(results), 'variadic': False,
            'param_noundef': [True] * len(params), 'result_noundef': [True] * len(results),
            'cc': 'portable'})
        function = deepcopy(sections['3']['functions'][0])
        number = max(item['id'] for item in sections['3']['functions']) + 1
        function.update(id=number, signature=signature, abi_signature=None,
                        params=[{'id': i, 'type': deepcopy(t)} for i, t in enumerate(params)])
        function['blocks'][0]['ops'] = deepcopy(list(operations))
        function['blocks'][0]['term']['values'] = list(range(len(results))) if returns is None else returns
        sections['3']['functions'].append(function)
        symbol = deepcopy(sections['2']['symbols'][0])
        symbol.update(id=max(item['id'] for item in sections['2']['symbols']) + 1,
                      name='generic_' + str(number), source_linkage='none',
                      execution=signature, nominal=None, abi_signature=None,
                      definition={'some': {'kind': 'function', 'target': {
                          'module': {'kind': 'self'}, 'id': number}}})
        sections['2']['symbols'].append(symbol)
        return function

    def run_document(self, function, arguments):
        path = self.directory / 'typed.smo'
        path.write_bytes(smir.assemble(self.document))
        options = ['run', path, '--entry-function', str(function['id']),
                   '--reference-policy', FIXTURE / 'policy.json']
        for bits in arguments:
            options.extend(['--argument-bits', bits])
        process = self.command(*options)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        report = json.loads(process.stdout)
        self.assertEqual(report['status'], 'reference-return', report)
        self.assertFalse(report['production_admitted'])
        return report

    def test_generic_int64_wrap_uses_actual_integer_execution(self):
        typ = self.integer_type(64)
        function = self.generic_function([typ], [typ], returns=[2], operations=[
            {'op': 'constant', 'results': [{'id': 1, 'type': typ}], 'operands': [],
             'literal': {'kind': 'bits', 'value': '0100000000000000'}},
            {'op': 'i_add', 'results': [{'id': 2, 'type': typ}], 'operands': [0, 1], 'flags': []}])
        for argument, expected in [('ffffffffffffffff', '0000000000000000'),
                                   ('0000000000000080', '0100000000000080')]:
            with self.subTest(argument=argument):
                self.assertEqual(self.run_document(function, [argument])['values'], [{'bits_le': expected}])

    def test_void_and_mixed_width_multiple_results(self):
        empty = self.generic_function([], [])
        self.assertEqual(self.run_document(empty, [])['values'], [])
        a, b, c = [self.integer_type(width) for width in (8, 9, 64)]
        function = self.generic_function([a, b, c], [c, b, a], returns=[2, 1, 0])
        self.assertEqual(self.run_document(function, ['fe', 'ff01', 'efcdab8967452301'])['values'],
                         [{'bits_le': 'efcdab8967452301'}, {'bits_le': 'ff01'}, {'bits_le': 'fe'}])

    def test_int1_and_int9_preserve_exact_bits(self):
        for width, arguments in [(1, ['00', '01']), (9, ['0000', 'ff01'])]:
            typ = self.integer_type(width)
            function = self.generic_function([typ], [typ])
            for argument in arguments:
                with self.subTest(width=width, argument=argument):
                    self.assertEqual(self.run_document(function, [argument])['values'], [{'bits_le': argument}])

    def test_generic_wide_internal_call(self):
        typ = self.integer_type(64)
        callee = self.generic_function([typ], [typ], returns=[2], operations=[
            {'op': 'constant', 'results': [{'id': 1, 'type': typ}], 'operands': [],
             'literal': {'kind': 'bits', 'value': '0300000000000000'}},
            {'op': 'i_mul', 'results': [{'id': 2, 'type': typ}], 'operands': [0, 1], 'flags': []}])
        caller = self.generic_function([typ], [typ], returns=[1], operations=[
            {'op': 'call', 'results': [{'id': 1, 'type': typ}], 'operands': [0],
             'target': {'kind': 'direct', 'function': {'module': {'kind': 'self'}, 'id': callee['id']},
                        'signature': deepcopy(callee['signature'])},
             'unwind': 'propagate', 'source_plan': None}])
        self.assertEqual(self.run_document(caller, ['ffffffffffffffff'])['values'],
                         [{'bits_le': 'fdffffffffffffff'}])

    def test_generic_internal_bound_pointer_returns_to_real_source_call(self):
        pointer = {'module': {'kind': 'self'}, 'id': 901}
        helper = self.generic_function([pointer], [pointer])
        caller = self.document['sections']['3']['functions'][1]
        ops = caller['blocks'][0]['ops']
        ops.insert(2, {'op': 'call', 'results': [{'id': 23, 'type': pointer}], 'operands': [21],
            'target': {'kind': 'direct', 'function': {'module': {'kind': 'self'}, 'id': helper['id']},
                       'signature': deepcopy(helper['signature'])},
            'unwind': 'propagate', 'source_plan': None})
        ops[3]['target']['value'] = 23
        self.assertEqual(self.run_document(caller, ['2a000000'])['values'], [{'bits_le': '2a000000'}])

    def source_scalar_call(self, entities, *, result_index=0):
        """Author explicit source/ABI/SSA rows; no execution authority is supplied."""
        self.document = json.loads((FIXTURE / 'source.json').read_text())
        sections = self.document['sections']
        abi = sections['10']
        scalar_template, function = deepcopy(abi['types'])
        plan = abi['signatures'][0]
        lowered_template = deepcopy(plan['lowered_params'][0])
        shapes = {'signed char': (8, True), 'unsigned char': (8, False),
                  'short': (16, True), 'unsigned short': (16, False),
                  'int': (32, True), 'unsigned int': (32, False),
                  'long': (64, True), 'unsigned long': (64, False),
                  'long long': (64, True), 'unsigned long long': (64, False)}
        ref = lambda number: {'module': {'kind': 'self'}, 'id': number}
        nodes, layouts, source, physical = [], [], [], []
        for position, entity in enumerate(entities):
            width, signed = shapes[entity]
            execution = self.integer_type(width)
            node = deepcopy(scalar_template)
            identifier = 1000 + position
            node.update(id=identifier, bits=width, signed=signed,
                        execution={'some': execution}, layout={'some': identifier})
            node['identity']['entity'] = entity
            nodes.append(node)
            source.append(ref(identifier))
            physical.append(execution)
            layout = deepcopy(abi['layouts'][0])
            layout.update(id=identifier, type=ref(identifier))
            for name in ('size', 'align', 'data_size', 'nonvirtual_size', 'nonvirtual_align'):
                layout[name] = width // 8
            layouts.append(layout)
            if not any(row['type'] == execution for row in sections['1']['memory_layouts']):
                sections['1']['memory_layouts'].append({'id': identifier, 'type': execution,
                    'size': width // 8, 'alignment': width // 8, 'access_bytes': width // 8,
                    'fields': [], 'element': None, 'stride': 0})
        if result_index is None:
            node = deepcopy(scalar_template)
            node.update(id=2000, kind='void', bits=0, signed=False, representation='none',
                        execution=None, layout=None, flags=['complete'])
            node['identity']['entity'] = 'void'
            nodes.append(node)
            result_source, result_physical = ref(2000), []
            plan['result'] = None
        else:
            result_source, result_physical = source[result_index], [physical[result_index]]
            plan['result'] = {'some': result_source}
        function.update(elements=source + [result_source], extent={'some': len(source)})
        abi['types'] = sorted(nodes + [function], key=lambda row: row['id'])
        abi['layouts'] = layouts
        plan.update(params=deepcopy(source), lowered_results=[] if result_index is None else [result_source])
        plan['lowered_params'] = []
        for position, (item, entity) in enumerate(zip(source, entities, strict=True)):
            lowered = deepcopy(lowered_template)
            lowered.update(source_index={'some': position}, source_type=item, value_type=item,
                           align=shapes[entity][0] // 8, bytes=shapes[entity][0] // 8)
            plan['lowered_params'].append(lowered)
        signature = next(row for row in sections['1']['types'] if row['id'] == 12)
        signature.update(params=physical, results=result_physical,
                         param_noundef=[True] * len(physical), result_noundef=[True] * len(result_physical))
        callee, caller = sections['3']['functions']
        for body in (callee, caller):
            body['params'] = [{'id': i, 'type': typ} for i, typ in enumerate(physical)]
        callee['blocks'][0]['term']['values'] = [] if result_index is None else [result_index]
        call = caller['blocks'][0]['ops'][2]
        call.update(operands=list(range(len(physical))), results=[] if result_index is None else
                    [{'id': 22, 'type': result_physical[0]}])
        caller['blocks'][0]['term']['values'] = [] if result_index is None else [22]
        self.source_fingerprints()
        return caller

    def source_fingerprints(self):
        sys.path.insert(0, str(ROOT / 'tools/smir-abi'))
        try:
            from nominal import NominalGraph
            graph = NominalGraph(self.document['sections']['10'], 'local')
            for node in self.document['sections']['10']['types']:
                if 'complete' in node['flags']:
                    node['identity']['definition'] = graph.fingerprint(
                        {'module': {'kind': 'self'}, 'id': node['id']})
        finally:
            sys.path.remove(str(ROOT / 'tools/smir-abi'))

    def test_source_signed_and_unsigned_scalar_bound_calls(self):
        for entity, octets in [('signed char', 1), ('unsigned char', 1),
                               ('short', 2), ('unsigned short', 2),
                               ('int', 4), ('unsigned int', 4),
                               ('long', 8), ('unsigned long', 8),
                               ('long long', 8), ('unsigned long long', 8)]:
            with self.subTest(entity=entity):
                caller = self.source_scalar_call([entity])
                report = self.run_document(caller, ['ff' * octets])
                self.assertEqual(report['values'], [{'bits_le': 'ff' * octets}])
                self.assertEqual(report['steps'], 7)

    def test_source_mixed_scalar_and_void_bound_calls(self):
        caller = self.source_scalar_call(['unsigned char', 'short', 'unsigned long'], result_index=2)
        self.assertEqual(self.run_document(caller, ['fe', '0080', 'efcdab8967452301'])['values'],
                         [{'bits_le': 'efcdab8967452301'}])
        for entities, arguments in [([], []), (['unsigned short', 'long'], ['ffff', 'ffffffffffffffff'])]:
            caller = self.source_scalar_call(entities, result_index=None)
            report = self.run_document(caller, arguments)
            self.assertEqual(report['values'], [])
            self.assertEqual(report['steps'], 7)

    def test_source_same_long64_before_object_completes(self):
        path = FIXTURE / 'ordinary-scalars/long64-source.smo'
        result = self.command('run', path, '--entry-function', '1', '--argument-bits', 'ffffffffffffffff',
                              '--reference-policy', FIXTURE / 'policy.json')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['content_digest'], 'b97c1d85a234111d4276f793ff8c02176801e21b717d1d9e4c8376cfd0dc556a')
        self.assertEqual(report['values'], [{'bits_le': 'ffffffffffffffff'}])
        self.assertEqual(report['steps'], 7)

    def null_call(self, entity='int', language='cpp23'):
        self.document = json.loads((FIXTURE / 'null-data/null-diamond-source.json').read_text())
        sections = self.document['sections']
        abi = sections['10']
        pointee = next(row for row in abi['types'] if row['id'] == 1)
        if entity == 'void':
            pointee.update(kind='void', bits=0, signed=False, execution=None, layout=None,
                           representation='none', flags=['complete'])
            abi['layouts'] = [row for row in abi['layouts'] if row['id'] != 1]
        else:
            shapes = {'signed char': (8, True), 'unsigned char': (8, False),
                      'short': (16, True), 'unsigned short': (16, False),
                      'int': (32, True), 'unsigned int': (32, False),
                      'long': (64, True), 'unsigned long': (64, False),
                      'long long': (64, True), 'unsigned long long': (64, False)}
            width, signed = shapes[entity]
            pointee.update(bits=width, signed=signed, execution={'some': self.integer_type(width)})
            layout = next(row for row in abi['layouts'] if row['id'] == 1)
            for name in ('size', 'align', 'data_size', 'nonvirtual_size', 'nonvirtual_align'):
                layout[name] = width // 8
        pointee['identity']['entity'] = entity
        for node in abi['types']:
            node['identity']['language'] = language
            if node['kind'] == 'function':
                node['flags'] = ['complete', 'c_linkage'] if language == 'c23' else ['complete']
        sections['2']['symbols'][0]['source_linkage'] = 'c' if language == 'c23' else 'cpp'
        self.source_fingerprints()
        return sections['3']['functions'][1]

    def test_null_pointer_fixture_roundtrip_and_actual_diamond_call(self):
        self.document = json.loads((FIXTURE / 'null-data/null-diamond-source.json').read_text())
        self.assertEqual(smir.assemble(self.document), (FIXTURE / 'null-data/null-diamond.smo').read_bytes())
        original = json.loads((ROOT / 'crates/smir-portable/tests/abi/ordinary-pointer-fixtures/'
                              'original-pointer.source.json').read_text())
        self.assertEqual(self.document['sections']['10'], original['sections']['10'])
        self.assertEqual(self.document['sections']['3']['functions'][0],
                         original['sections']['3']['functions'][0])
        report = self.run_document(self.document['sections']['3']['functions'][1], [])
        self.assertEqual(report['values'], [{'bits_le': '01'}])
        self.assertEqual(report['steps'], 14)

    def test_null_pointer_all_integer_and_void_pointees_both_languages(self):
        for language in ('c23', 'cpp23'):
            for entity in ('signed char', 'unsigned char', 'short', 'unsigned short', 'int',
                           'unsigned int', 'long', 'unsigned long', 'long long',
                           'unsigned long long', 'void'):
                with self.subTest(language=language, entity=entity):
                    self.assertEqual(self.run_document(self.null_call(entity, language), [])['values'],
                                     [{'bits_le': '01'}])

    def test_null_pointer_freeze_copy_select_and_generic_call(self):
        ref = lambda n: {'module': {'kind': 'self'}, 'id': n}
        for state in ('poison', 'undef'):
            caller = self.null_call()
            sections = self.document['sections']
            sections['1']['types'].append(dict(id=3004, kind='function', params=[ref(19)],
                results=[ref(19)], variadic=False, cc='portable', param_noundef=[True], result_noundef=[True]))
            sections['1']['types'].sort(key=lambda row: row['id'])
            sections['3']['functions'].append(dict(id=2, signature=ref(3004), abi_signature=None,
                params=[dict(id=0, type=ref(19))], entry=0, escape='propagate', no_return=False,
                blocks=[dict(id=0, phis=[], ops=[], term=dict(op='return', values=[0]))]))
            ops = caller['blocks'][0]['ops']
            ops[0]['literal'] = {'kind': state}
            ops[1:1] = [dict(op='freeze', results=[dict(id=5, type=ref(19))], operands=[0]),
                dict(op='copy', results=[dict(id=6, type=ref(19))], operands=[5]),
                dict(op='constant', results=[dict(id=7, type=ref(3000))], operands=[], literal=dict(kind='zero')),
                dict(op='select', results=[dict(id=8, type=ref(19))], operands=[7, 0, 6]),
                dict(op='call', results=[dict(id=9, type=ref(19))], operands=[8],
                     target=dict(kind='direct', function=ref(2), signature=ref(3004)),
                     unwind='propagate', source_plan=None)]
            ops[-2]['operands'] = [9]
            ops[-1]['operands'] = [3, 6]
            self.assertEqual(self.run_document(caller, [])['values'], [{'bits_le': '01'}])

    def test_null_pointer_mixed_integer_parameters_and_void_result(self):
        ref = lambda n: {'module': {'kind': 'self'}, 'id': n}
        caller = self.null_call()
        sections = self.document['sections']
        abi = sections['10']
        source_fn = next(row for row in abi['types'] if row['kind'] == 'function')
        source_fn['elements'].insert(1, ref(1))
        source_fn['extent'] = {'some': 2}
        plan = abi['signatures'][0]
        plan['params'].append(ref(1))
        lowered = deepcopy(plan['lowered_params'][0])
        lowered.update(source_index={'some': 1}, source_type=ref(1), value_type=ref(1), align=4, bytes=4)
        plan['lowered_params'].append(lowered)
        physical = next(row for row in sections['1']['types'] if row['id'] == 2000)
        physical['params'].append(ref(1)); physical['param_noundef'].append(True)
        sections['3']['functions'][0]['params'].append(dict(id=1, type=ref(1)))
        ops = caller['blocks'][0]['ops']
        ops.insert(1, dict(op='constant', results=[dict(id=7, type=ref(1))], operands=[],
                           literal=dict(kind='bits', value='2a000000')))
        ops[-2]['operands'].append(7)
        self.source_fingerprints()
        self.assertEqual(self.run_document(caller, [])['values'], [{'bits_le': '01'}])
        # Canonical None-void result, with the same real pointer parameter/call.
        void = deepcopy(next(row for row in abi['types'] if row['id'] == 1))
        void.update(id=501, kind='void', bits=0, signed=False, execution=None, layout=None,
                    representation='none', flags=['complete'])
        void['identity']['entity'] = 'void'; abi['types'].append(void)
        source_fn['elements'][-1] = ref(501)
        plan.update(result=None, lowered_results=[])
        physical.update(results=[], result_noundef=[])
        sections['3']['functions'][0]['blocks'][-1]['term']['values'] = []
        ops[-2]['results'] = []
        ops[-1]['operands'] = [0, 0]
        self.source_fingerprints()
        self.assertEqual(self.run_document(caller, [])['values'], [{'bits_le': '01'}])

    def test_null_pointer_forbidden_producers_and_public_boundaries_before_effects(self):
        ref = lambda n: {'module': {'kind': 'self'}, 'id': n}
        for bits in ('0000000000000000', '0100000000000000'):
            caller = self.null_call()
            caller['blocks'][0]['ops'][0]['literal'] = dict(kind='bits', value=bits)
            self.reject_before_machine(caller, [], 'literal_pointer' if bits.startswith('01')
                                       else 'REFERENCE-NULL-DATAPTR-LITERAL-SCOPE')
        for source, target in [(19, 5), (5, 19), (19, 3), (3, 19), (19, 19)]:
            caller = self.null_call()
            ops = caller['blocks'][0]['ops']
            ops.insert(1, dict(op='constant', results=[dict(id=6, type=ref(source))],
                               operands=[], literal=dict(kind='zero')))
            ops.insert(2, dict(op='bitcast', results=[dict(id=7, type=ref(target))], operands=[6]))
            self.reject_before_machine(caller, [], 'bitcast_pointer' if (source, target) == (19, 5)
                                       else 'REFERENCE-NULL-DATAPTR-OPERATION-SCOPE')
        caller = self.null_call()
        caller['blocks'][0]['ops'][-1]['predicate'] = 'ult'
        self.reject_before_machine(caller, [], 'REFERENCE-NULL-DATAPTR-OPERATION-SCOPE')
        caller = self.null_call()
        self.reject_before_machine(self.document['sections']['3']['functions'][0],
                                   ['0000000000000000'], 'REFERENCE-EXECUTION-TYPE-SCOPE')
        self.reject_before_machine(self.document['sections']['3']['functions'][0],
                                   [], 'REFERENCE-EXECUTION-TYPE-SCOPE')
        caller = self.null_call()
        signature = next(row for row in self.document['sections']['1']['types'] if row['id'] == 3003)
        signature['results'] = [ref(19)]
        caller['blocks'][0]['term']['values'] = [3]
        self.reject_before_machine(caller, [], 'REFERENCE-EXECUTION-TYPE-SCOPE')
        caller = self.null_call()
        # An otherwise unused original body cannot smuggle a producer past scan.
        unused = deepcopy(self.document['sections']['3']['functions'][0])
        unused['id'] = 2
        self.document['sections']['3']['functions'].append(unused)
        unused['blocks'][0]['ops'].append(
            dict(op='constant', results=[dict(id=11, type=ref(19))], operands=[],
                 literal=dict(kind='bits', value='0000000000000000')))
        self.reject_before_machine(caller, [], 'REFERENCE-NULL-DATAPTR-LITERAL-SCOPE')

    def test_null_pointer_wrong_source_pointee_does_not_use_null_exception(self):
        ref = lambda n: {'module': {'kind': 'self'}, 'id': n}
        for before, after in [('int', 'unsigned int'), ('long', 'long long'), ('int', 'void')]:
            caller = self.null_call(before)
            abi = self.document['sections']['10']
            pointee = deepcopy(next(row for row in abi['types'] if row['id'] == 1))
            pointee['id'] = 2; pointee['identity']['entity'] = after
            if after == 'void':
                pointee.update(kind='void', bits=0, signed=False, execution=None, layout=None,
                               representation='none', flags=['complete'])
            else:
                pointee['signed'] = after != 'unsigned int'; pointee['layout'] = {'some': 2}
                layout = deepcopy(next(row for row in abi['layouts'] if row['id'] == 1))
                layout.update(id=2, type=ref(2)); abi['layouts'].append(layout)
            pointer = deepcopy(next(row for row in abi['types'] if row['id'] == 500))
            pointer.update(id=501, elements=[ref(2)], layout={'some': 501})
            layout = deepcopy(next(row for row in abi['layouts'] if row['id'] == 500))
            layout.update(id=501, type=ref(501)); abi['layouts'].append(layout)
            abi['types'] += [pointee, pointer]; abi['types'].sort(key=lambda row: row['id'])
            abi['layouts'].sort(key=lambda row: row['id'])
            abi['signatures'][0]['lowered_params'][0]['value_type'] = ref(501)
            self.source_fingerprints()
            self.reject_before_machine(caller, [], 'ABI_CC_DIRECT_TYPE')

    def test_null_pointer_poison_undef_keep_actual_noundef_traps(self):
        for state in ('poison', 'undef'):
            caller = self.null_call()
            caller['blocks'][0]['ops'][0]['literal'] = {'kind': state}
            path = self.directory / 'noundef.smo'; path.write_bytes(smir.assemble(self.document))
            process = self.command('run', path, '--entry-function', caller['id'],
                                   '--reference-policy', FIXTURE / 'policy.json')
            self.assertEqual(process.returncode, 2, process.stdout + process.stderr)
            report = json.loads(process.stdout)
            self.assertEqual(report['status'], 'reference-language_ub')
            self.assertEqual(report['code'], 'ub_noundef_argument')
            self.assertFalse(report['production_admitted'])

    def test_null_pointer_excluded_source_and_conversion_scopes(self):
        ref = lambda n: {'module': {'kind': 'self'}, 'id': n}
        for kind in ('pointer', 'scalar'):
            caller = self.null_call()
            next(row for row in self.document['sections']['10']['types']
                 if row['kind'] == kind)['qualifiers'] = ['const']
            self.source_fingerprints()
            self.reject_before_machine(caller, [], 'REFERENCE-EXECUTION-SIGNATURE-SCOPE')
        for name in ('inttoptr', 'ptrtoint', 'ptrtoaddr', 'ptr_offset'):
            caller = self.null_call()
            ops = caller['blocks'][0]['ops']
            ops.insert(1, dict(op='constant', results=[dict(id=6, type=ref(5))],
                               operands=[], literal=dict(kind='zero')))
            operation = dict(op=name, results=[dict(id=7, type=ref(19 if name in
                            ('inttoptr', 'ptr_offset') else 5))],
                             operands=[6] if name == 'inttoptr' else [0])
            if name == 'ptr_offset':
                operation.update(operands=[0, 6], inbounds=False, nuw=False, nusw=False,
                                 inrange=None, check_base=False)
            ops.insert(2, operation)
            self.reject_before_machine(caller, [], 'REFERENCE-EXECUTION-OPERATION-SCOPE')
        caller = self.null_call()
        call = caller['blocks'][0]['ops'][-2]
        call['source_plan'] = None
        self.reject_before_machine(caller, [], 'REFERENCE-GENERIC-INDIRECT-CALL-SCOPE')

    def test_excluded_source_plans_reject_before_machine_effects(self):
        caller = self.source_scalar_call(['signed char'])
        scalar = next(row for row in self.document['sections']['10']['types'] if row['kind'] == 'scalar')
        scalar['identity']['entity'] = 'char'
        self.source_fingerprints()
        self.reject_before_machine(caller, ['ff'], 'REFERENCE-EXECUTION-SIGNATURE-SCOPE')
        for association in ('function', 'code_bind', 'call'):
            with self.subTest(association=association):
                caller = self.source_scalar_call([], result_index=None)
                abi = self.document['sections']['10']
                plan = deepcopy(abi['signatures'][0])
                plan['result'] = {'some': {'module': {'kind': 'self'}, 'id': 2000}}
                if association == 'function':
                    abi['signatures'][0] = plan
                else:
                    plan['id'] = 1
                    abi['signatures'].append(plan)
                    operation = caller['blocks'][0]['ops'][1 if association == 'code_bind' else 2]
                    if association == 'code_bind':
                        operation['plan']['id'] = 1
                    else:
                        operation['source_plan']['some']['id'] = 1
                self.reject_before_machine(caller, [], 'REFERENCE-EXECUTION-SIGNATURE-SCOPE')

    def test_source_visibility_rejects_before_machine_effects(self):
        for visibility in ('hidden', 'protected'):
            with self.subTest(visibility=visibility):
                caller = self.source_scalar_call(['long'])
                self.document['sections']['2']['symbols'][0]['visibility'] = visibility
                self.reject_before_machine(caller, ['ffffffffffffffff'],
                                           'REFERENCE-SOURCE-VISIBILITY-SCOPE')

    def reject_before_machine(self, function, arguments, expected):
        path = self.directory / 'refused.smo'
        path.write_bytes(smir.assemble(self.document))
        # Observation wrappers always delegate. Any construction/start/run means
        # preflight occurred too late; they cannot fabricate successful authority.
        probe = r"""
import importlib.util,json,sys
from pathlib import Path
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'tools/smir-format'));import codec
sys.path.insert(0,str(root/'tools/smir-format/execution'))
from candidate.machine import Machine
calls=[]
path=root/'tools/smir-runtime-contract/source_roles/code_addresses.py'
spec=importlib.util.spec_from_file_location('_rax_smir_code_addresses_v1',path)
runtime=importlib.util.module_from_spec(spec);sys.modules[spec.name]=runtime;spec.loader.exec_module(runtime)
registry_calls=[]
registry_init=runtime.CodeRegistry.__init__
def observe_registry(*args,**kwargs):
 registry_calls.append('__init__');return registry_init(*args,**kwargs)
runtime.CodeRegistry.__init__=observe_registry
for name in ('__init__','start','run'):
 original=getattr(Machine,name)
 def observe(*args,_name=name,_original=original,**kwargs):
  calls.append(_name);return _original(*args,**kwargs)
 setattr(Machine,name,observe)
try:
 codec.run_reference(Path(sys.argv[2]).read_bytes(),entry_function=int(sys.argv[3]),
                     argument_bits=json.loads(sys.argv[4]),
                     policy=codec.reference_policy(Path(sys.argv[5]).read_bytes()))
except Exception as error:
 print(json.dumps({'code':getattr(error,'code',str(error)),'machine_calls':calls,'registry_calls':registry_calls}))
else:
 raise RuntimeError('unexpected admission')
"""
        process = subprocess.run([sys.executable, '-B', '-c', probe, str(ROOT), str(path),
            str(function['id']), json.dumps(arguments), str(FIXTURE / 'policy.json')],
            text=True, capture_output=True, timeout=180)
        self.assertEqual(process.returncode, 0, process.stderr + process.stdout)
        report = json.loads(process.stdout)
        self.assertEqual(report['machine_calls'], [], report)
        self.assertEqual(report['registry_calls'], [], report)
        self.assertEqual(report['code'], expected, report)

    def test_invalid_integer_encodings_reject_before_machine_effects(self):
        for width, invalid in [(1, ['02', '0000', '0', 'GG']),
                               (9, ['0002', 'ff', 'ff0100', 'FF01']),
                               (64, ['ffffffff', 'ffffffffffffffffff'])]:
            typ = self.integer_type(width)
            function = self.generic_function([typ], [typ])
            for argument in invalid:
                with self.subTest(width=width, argument=argument):
                    self.reject_before_machine(function, [argument], 'REFERENCE-ARGUMENT-BITS')

    def test_opaque_or_wide_entry_rejects_before_machine_effects(self):
        for type_id in [3, 900, 901]:
            typ = {'module': {'kind': 'self'}, 'id': type_id}
            function = self.generic_function([typ], [typ])
            with self.subTest(type_id=type_id):
                self.reject_before_machine(function, ['0000000000000000'],
                                           'REFERENCE-EXECUTION-SIGNATURE-SCOPE')
        typ = self.integer_type(65)
        function = self.generic_function([typ], [typ])
        self.reject_before_machine(function, ['0000000000000000'],
                                   'REFERENCE-EXECUTION-TYPE-SCOPE')


    def test_source_plan_and_variadic_signatures_reject_before_machine(self):
        typ = self.integer_type(64)
        function = self.generic_function([typ], [typ])
        function['abi_signature'] = {'some': {'module': {'kind': 'self'}, 'id': 0}}
        self.reject_before_machine(function, ['0000000000000000'], 'function_plan_execution')
        function['abi_signature'] = None
        signature = self.document['sections']['1']['types'][-1]
        signature['variadic'] = True
        self.reject_before_machine(function, ['0000000000000000'], 'calling_convention')


if __name__ == '__main__':
    unittest.main()
