"""ABI2 source geometry, rejection boundaries, identity and pinned witnesses."""
from copy import deepcopy
import os
import tempfile
import unittest
from candidate import verify
from candidate_fixtures import build, context, seal
from layout import ABIError
from nominal import NominalGraph, ref, some
from .model import ArrayType, Budget, Model, ModelError, RecordType, ResourceError, ScalarType, MAX_OBJECT
from .witness import run


def record(fields=(), **changes):
    data = dict(kind='struct', language='cpp23', explicit_align=None, pod03=True, trivial=True,
                standard_layout=True, polymorphic=False, dynamic=False, empty=not fields,
                fields=list(fields), bases=[])
    return dict(data, **changes)


def field(name, typ, **changes):
    data = dict(name=name, type=typ, bit_width=None, explicit_align=None, anonymous=False,
                no_unique_address=False, access='public')
    data.update(changes)
    return data


class SourceRecordTests(unittest.TestCase):
    def test_optional_identity_private_record_real_abi_and_layout(self):
        from .checked import CheckedRecords
        from nominal import unit_identity
        from candidate_codec import encode
        doc, evidence = build()
        source = next(t for t in doc['types'] if t['id'] == 3)
        source['identity'].update(linkage='internal', unit=some(unit_identity('example', 'main', 1, 'private-record')))
        seal(doc)
        fingerprint = NominalGraph(doc, 'main').fingerprint(ref(3))
        original_bytes = encode('abi_contract', doc)
        result = verify(doc, context(doc, evidence))
        self.assertFalse(result['admitted_for_execution'])
        graph = NominalGraph(doc, 'main', families={'main': ('example', 'main', 1)})
        checked = CheckedRecords(graph)
        actual = checked.verify(ref(3))
        self.assertEqual((actual.size, actual.align, actual.fields), (8, 4, [0, 32]))
        self.assertEqual(fingerprint, graph.fingerprint(ref(3)))
        self.assertEqual(original_bytes, encode('abi_contract', doc))
        self.assertEqual(checked.bind(ref(3)).key, checked.canonical_class('main', source))

    def test_optional_identity_unit_library_and_private_family_separation(self):
        from .checked import CheckedRecords
        from nominal import unit_identity
        identities = [(None, 'external', None), (some('a' * 64), 'external', None),
                      (some('b' * 64), 'external', None),
                      (None, 'internal', some(unit_identity('example', 'main', 1, 'one'))),
                      (None, 'internal', some(unit_identity('example', 'main', 1, 'two')))]
        keys = []
        for library, linkage, unit in identities:
            doc, evidence = build()
            typ = next(t for t in doc['types'] if t['id'] == 3)
            typ['identity'].update(library=library, linkage=linkage, unit=unit)
            seal(doc)
            verify(doc, context(doc, evidence))
            graph = NominalGraph(doc, 'main', families={'main': ('example', 'main', 1)})
            checked = CheckedRecords(graph)
            key = checked.canonical_class('main', typ)
            hash(key)
            self.assertEqual(checked.verify(ref(3)).size, 8)
            keys.append(key)
        self.assertEqual(len(set(keys)), len(identities))
        doc, _ = build()
        typ = next(t for t in doc['types'] if t['id'] == 3)
        typ['identity'].update(linkage='internal', unit=some(unit_identity('example', 'main', 1, 'same-unit')))
        seal(doc)
        graph = NominalGraph(doc, 'main', modules={'other': deepcopy(doc)},
            families={'main': ('example', 'main', 1), 'other': ('example', 'other', 1)})
        checked = CheckedRecords(graph)
        left = checked.bind(ref(3), 'main').key
        right = checked.bind(ref(3), 'other').key
        self.assertNotEqual(left, right)
        self.assertFalse(graph.compatible(ref(3), ref(3), 'main', 'other'))

    def test_optional_identity_qualified_alias_and_definition_conflict(self):
        from .checked import CheckedRecords
        from nominal import unit_identity
        for conflict in (False, True):
            doc, _ = build()
            original = next(t for t in doc['types'] if t['id'] == 3)
            original['identity'].update(linkage='internal', unit=some(unit_identity('example', 'main', 1, 'alias')))
            alias = deepcopy(original)
            alias['id'] = 999
            alias['qualifiers'] = ['const']
            if conflict:
                alias['record_input']['some']['fields'][0]['name'] = some('different')
            doc['types'].append(alias)
            seal(doc)
            graph = NominalGraph(doc, 'main', families={'main': ('example', 'main', 1)})
            checked = CheckedRecords(graph)
            first = checked.bind(ref(3))
            if conflict:
                with self.assertRaisesRegex(ABIError, 'ABI_CC_SOURCE_CLASS_CONFLICT'):
                    checked.bind(ref(999))
            else:
                self.assertEqual(first.key, checked.bind(ref(999)).key)
                self.assertTrue(graph.compatible(ref(3), ref(999), ignore_top_cv=True))
                self.assertFalse(graph.compatible(ref(3), ref(999)))

    def test_actual_overlap_unaligned_and_narrow_counter_siblings(self):
        doc, evidence = build()
        verify(doc, context(doc, evidence))
        for offset, width in ((0, 32), (16, 32), (32, 1)):
            bad = deepcopy(doc)
            next(l for l in bad['layouts'] if l['id']==3)['fields'][1].update(offset_bits=offset,width_bits=width)
            seal(bad)
            with self.assertRaisesRegex(ABIError, 'ABI_CC_FIELD_DERIVATION'):
                verify(bad, context(bad, evidence))

    def test_source_names_and_declaration_order_are_hash_inputs(self):
        doc, _ = build()
        original = NominalGraph(doc,'main').fingerprint(ref(3))
        for change in ('name', 'order'):
            other = deepcopy(doc)
            fields = other['types'][3]['record_input']['some']['fields']
            if change=='name':fields[0]['name']=some('renamed')
            else:fields.reverse()
            self.assertNotEqual(original,NominalGraph(other,'main').fingerprint(ref(3)))

    def test_missing_input_and_nonrecord_input_reject(self):
        for identifier,value in ((3,None),(1,build()[0]['types'][3]['record_input'])):
            doc,evidence=build();doc['types'][identifier]['record_input']=value;seal(doc)
            with self.assertRaisesRegex(ABIError,'ABI_CC_RECORD_INPUT'):verify(doc,context(doc,evidence))

    def test_names_and_capture_rules(self):
        cases=[('','ABI_CC_FIELD_NAME'),('x\0y','ABI_CC_FIELD_NAME'),
               ('$anonymous0','ABI_CC_FIELD_NAME_RESERVED'),('$unnamed0','ABI_CC_FIELD_NAME_RESERVED'),
               ('$capture01','ABI_CC_CAPTURE_FIELD_NAME'),('$capture1','ABI_CC_CAPTURE_FIELD_NAME')]
        for name,code in cases:
            doc,evidence=build();doc['types'][3]['record_input']['some']['fields'][0]['name']=some(name);seal(doc)
            with self.assertRaisesRegex(ABIError,code):verify(doc,context(doc,evidence))
        doc,evidence=build();doc['types'][3]['record_input']['some']['fields'][0]['name']=some('$capture0')
        next(l for l in doc['layouts'] if l['id']==3)['fields'][0]['name']='$capture0'
        for binding in doc['storage_bindings']:
            for fragment in binding['fragments']:
                if fragment['source_path'] and fragment['source_path'][0]=='a':
                    fragment['source_path'][0]='$capture0'
        seal(doc);verify(doc,context(doc,evidence))

    def test_source_trait_alignment_and_output_rejections(self):
        mutations=[
            ('ABI_CC_SOURCE_ALIGNMENT',lambda d:d['types'][3]['record_input']['some'].update(explicit_align=some(3))),
            ('ABI_CC_SOURCE_ALIGNMENT_WEAK',lambda d:d['types'][3]['record_input']['some']['fields'][1].update(explicit_align=some(1))),
            ('ABI_CC_DYNAMIC_SOURCE',lambda d:d['types'][3]['record_input']['some'].update(dynamic=True)),
            ('ABI_CC_EMPTY_SOURCE',lambda d:d['types'][3]['record_input']['some'].update(empty=True)),
            ('ABI_CC_FIELD_DERIVATION',lambda d:next(l for l in d['layouts'] if l['id']==3)['fields'][1].update(declaration_index=0))]
        for code,change in mutations:
            doc,evidence=build();change(doc);seal(doc)
            with self.assertRaisesRegex(ABIError,code):verify(doc,context(doc,evidence))

    def test_plain_c_flexible_member_geometry(self):
        data=record([field('n',ScalarType(1,1,8,True)),field('data',ArrayType(ScalarType(4,4,32,True),None))])
        data.update(language='c23',pod03=False,trivial=False,standard_layout=False,empty=False)
        actual=Model({'F':data}).layout('F')
        self.assertEqual((actual.size,actual.align,actual.data_size,actual.nvsize,actual.fields),(4,4,4,4,[0,32]))

    def test_cpp_wide_and_c_rejection(self):
        data=record([field('x',ScalarType(1,1,8,True),bit_width=129)])
        actual=Model({'W':data}).layout('W');self.assertEqual((actual.size,actual.align,actual.fields),(32,16,[0]))
        data.update(language='c23',pod03=False,trivial=False,standard_layout=False)
        with self.assertRaisesRegex(ModelError,'C bitfield width'):Model({'W':data}).layout('W')
        data['fields'][0]['type']=ScalarType(4,4,32,False)
        with self.assertRaisesRegex(ModelError,'bitfield nonintegral'):Model({'W':data}).layout('W')

    def test_huge_extent_symbolic_and_overflow(self):
        data=record([field('bytes',ArrayType(ScalarType(1,1),MAX_OBJECT))])
        self.assertEqual(Model({'H':data},Budget(work=100)).layout('H').size,MAX_OBJECT)
        data['fields'][0]['type']=ArrayType(ScalarType(1,1),MAX_OBJECT+1)
        with self.assertRaisesRegex(ModelError,'array extent'):Model({'H':data}).layout('H')

    def test_empty_array_budget_before_expansion(self):
        data=record([field('many',ArrayType(RecordType('E'),10**9),no_unique_address=True)])
        with self.assertRaises(ResourceError):Model({'E':record(),'H':data},Budget(work=1000)).layout('H')
        with self.assertRaises(ResourceError):Model({'E':record()},Budget(memory=1)).layout('E')

    def test_cycles_and_depth(self):
        with self.assertRaisesRegex(ModelError,'byvalue cycle'):Model({'C':record([field('self',RecordType('C'))])}).layout('C')
        records={str(i):record([field('child',RecordType(str(i+1)))]) for i in range(130)};records['130']=record()
        with self.assertRaisesRegex(ResourceError,'depth'):Model(records).layout('0')

    def test_pinned_28_record_source_layout_witness(self):
        with tempfile.TemporaryDirectory(prefix='abi-record-layout-',dir=os.environ.get('SMIR_ABI_TMP')) as path:
            receipt=run(path);self.assertEqual(len(receipt['records']),28)
            self.assertTrue(all(row['match'] for row in receipt['records']),receipt['records'])
            self.assertEqual(receipt['exits'],[0,0,0])

    def test_portable_nonrecord_has_no_invented_source_members(self):
        for identifier in (1,5):
            doc,evidence=build()
            layout=next(l for l in doc['layouts'] if l['id']==identifier)
            layout['fields']=[dict(declaration_index=0,name='invented',type=ref(1),offset_bits=0,width_bits=32,flags=[])]
            seal(doc)
            with self.assertRaisesRegex(ABIError,'ABI_CC_NONRECORD_LAYOUT'):
                verify(doc,context(doc,evidence))

    def test_function_void_and_incomplete_record_never_allocate(self):
        for identifier in (0,12):
            doc,evidence=build()
            doc['types'][identifier]['layout']=some(901)
            doc['layouts'].append(dict(id=901,type=ref(identifier),size=1,align=1,data_size=1,
                                      nonvirtual_size=1,nonvirtual_align=1,fields=[],bases=[],vptrs=[]))
            seal(doc)
            with self.assertRaisesRegex(ABIError,'ABI_CC_NONOBJECT_LAYOUT'):
                verify(doc,context(doc,evidence))
        doc,evidence=build();doc['types'][3].update(flags=[],execution=None,record_input=None,representation='none')
        seal(doc)
        with self.assertRaisesRegex(ABIError,'ABI_CC_INCOMPLETE_LAYOUT'):
            verify(doc,context(doc,evidence))

    def test_opaque_cpp_origin_array_expectation_has_no_storage(self):
        doc,evidence=build()
        forward=deepcopy(doc['types'][3]);forward.update(id=910,flags=[],layout=None,execution=None,
                                                      representation='none',record_input=None)
        forward['identity'].update(entity='example.OpaqueArrayElement')
        array=deepcopy(doc['types'][4]);array.update(id=911,kind='array',bits=0,flags=[],elements=[ref(910)],
            layout=None,execution=None,representation='none',extent=some(3),record_input=None)
        array['identity'].update(entity='array',language='c23')
        doc['types'] += [forward,array];seal(doc);verify(doc,context(doc,evidence))
        bad=deepcopy(doc)
        next(t for t in bad['types'] if t['id']==911)['elements']=[ref(1)]
        seal(bad)
        with self.assertRaisesRegex(ABIError,'ABI_CC_ARRAY_COMPLETENESS'):
            verify(bad,context(bad,evidence))

    def test_synthetic_native_representation_fields_stay_certificate_scoped(self):
        # Bounded trusted-fixture issuer only; this does not qualify a native
        # producer or execute a member pointer. Native representation fields
        # are distinct from portable source FieldDecl reports.
        doc,evidence=build()
        typ=deepcopy(doc['types'][4])
        typ.update(id=930,domain=1,kind='member_pointer',bits=128,elements=[ref(20),ref(22)],
                   representation='none',execution=None,layout=some(930))
        typ['identity'].update(language='cpp23',entity='member_pointer')
        doc['types'].append(typ)
        layout=dict(id=930,type=ref(930),size=16,align=8,data_size=16,nonvirtual_size=16,
                    nonvirtual_align=8,fields=[dict(declaration_index=i,name=name,type=ref(5),
                    offset_bits=i*64,width_bits=64,flags=[]) for i,name in enumerate(('ptr','adjustment'))],
                    bases=[],vptrs=[])
        doc['layouts'].append(layout);seal(doc)
        evidence['native_types']['930']=deepcopy(typ)
        evidence['native_layouts']['930']=deepcopy(layout)
        self.assertFalse(verify(doc,context(doc,evidence))['admitted_for_execution'])
