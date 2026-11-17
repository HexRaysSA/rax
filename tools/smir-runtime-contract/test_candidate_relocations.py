"""R039 actual pointer-derivation arithmetic and atomic publication witnesses."""
import copy
from dataclasses import replace
import unittest

from test_candidate_contract import ref
from test_candidate_closure import HERE
from runtime_candidate import relocations
from runtime_candidate.errors import Reject, some


class RelocationTests(unittest.TestCase):
    def error(self,code,function,*args,**kwargs):
        with self.assertRaises(Reject) as caught:function(*args,**kwargs)
        self.assertEqual(caught.exception.code,code)

    def state(self):
        image={'bytes':bytearray(b'\xaa'*64),'poison':bytearray(b'\x40'*64),
               'undef':bytearray(b'\x04'*64),'origins':[]}
        registry=relocations.Registry({('data',0):image},{'provider':1})
        target={'kind':'data','live':True,'owner':'provider','generation':1,'value':4096,
                'object':9,'object_generation':2,'object_base':4096,'object_size':24,'restriction':None}
        return registry,target

    def record(self,kind='data_address',**kw):
        result={'source_kind':'data','source':0,'offset':0,'width':8,'integer_bits':64 if kind.endswith('_integer') else 0,
            'kind':kind,'target':ref(0),'addend':0,'derivation':[],'check_base':False,'flags':[],'inrange':None}
        result.update(kw);return result

    def test_cpp_vptr_inrange_exact_origin_and_plain_pointer_no_invention(self):
        registry,target=self.state()
        record=self.record(addend=16,flags=['inbounds'],inrange=some({'lower':-16,'upper':8}))
        transaction=registry.prepare([record],lambda ref:target)
        self.assertEqual(registry.images['data',0]['bytes'][:8],b'\xaa'*8)
        registry.commit(transaction)
        origin=registry.images['data',0]['origins'][0]
        self.assertEqual(origin['pointer_bits'],4112)
        self.assertEqual(origin['range'],some({'lower':4096,'upper':4120,'upper_is_limit':False,'empty':False}))
        self.assertEqual(registry.exposed,set())
        other,target=self.state();other.commit(other.prepare([self.record()],lambda ref:target))
        self.assertIsNone(other.images['data',0]['origins'][0]['range'])

    def test_arbitrary_ptrtoint_precision_trunc_zeroextend_padding_and_exposure(self):
        cases=0
        for precision in [1,7,8,13,32,33,63,64,65,127,257]:
            registry,target=self.state();width=(precision+7)//8
            target['value']=0xfedcba9876543210
            record=self.record('data_integer',integer_bits=precision,width=width)
            registry.commit(registry.prepare([record],lambda ref:target))
            image=registry.images['data',0]
            self.assertEqual(int.from_bytes(image['bytes'][:width],'little'),target['value']&((1<<precision)-1))
            self.assertEqual(image['bytes'][width:],b'\xaa'*(64-width))
            self.assertEqual(image['origins'],[])
            self.assertEqual(registry.exposed,{(9,2)})
            cases+=1
        self.assertEqual(cases,11)

    def test_wrapped_result_range_anchor_and_restriction_numeric_ub(self):
        registry,target=self.state();target.update(value=16,object_base=16,object_size=8)
        record=self.record(addend=-32,inrange=some({'lower':-1,'upper':1}))
        registry.commit(registry.prepare([record],lambda ref:target))
        self.assertEqual(registry.images['data',0]['origins'][0]['range'],some({
            'lower':2**64-17,'upper':2**64-15,'upper_is_limit':False,'empty':False}))
        registry,target=self.state()
        bad=self.record('data_integer',inrange=some({'lower':0,'upper':24}))
        self.error('RT_PATCH_INRANGE_EXPOSURE',registry.prepare,[bad],lambda ref:target)
        self.assertEqual(registry.exposed,set())

    def test_prefix_poison_not_erased_by_net_zero_and_malformed_range_reject(self):
        registry,target=self.state()
        record=self.record(derivation=[{'offset':32,'check_base':False,'flags':['inbounds'],'inrange':None}],addend=-32)
        registry.commit(registry.prepare([record],lambda ref:target))
        image=registry.images['data',0]
        self.assertEqual(image['poison'][:8],b'\xff'*8)
        self.assertEqual(image['bytes'][:8],bytes(8));self.assertEqual(image['origins'],[])
        registry,target=self.state()
        self.error('RT_PATCH_INRANGE_BOUNDS',registry.prepare,[self.record(inrange=some({'lower':1,'upper':0}))],lambda ref:target)

    def test_strict_net_zero_original_index_and_historical_allocation(self):
        for strict,weak,poison in [(False,True,False),(True,True,True),(True,False,False)]:
            registry,target=self.state()
            if weak:target={'kind':'data','weak_null':True,'live':True}
            else:target['source_lifetime_live']=False  # Allocation facts still registered.
            record=self.record(check_base=strict,flags=['inbounds'])
            registry.commit(registry.prepare([record],lambda ref:target))
            self.assertEqual(bool(registry.images['data',0]['poison'][0]),poison)
        registry,target=self.state();target['value']=99
        registry.commit(registry.prepare([self.record(check_base=True,flags=['inbounds'])],lambda ref:target))
        self.assertEqual(registry.images['data',0]['poison'][:8],b'\xff'*8)
        registry,target=self.state()
        self.error('RT_PATCH_CHECK_BASE',registry.prepare,[self.record(check_base=True)],lambda ref:target)

    def test_no_partial_bytes_shadow_or_exposure_and_private_ticket_authority(self):
        registry,target=self.state();before=copy.deepcopy(registry.images)
        first=self.record('data_integer')
        second=self.record(offset=4)
        self.error('RT_PATCH_OVERLAP',registry.prepare,[first,second],lambda ref:target)
        self.assertEqual(registry.images,before);self.assertEqual(registry.exposed,set())
        ticket=registry.prepare([first],lambda ref:target)
        forged=replace(ticket)
        self.error('RT_PATCH_TRANSACTION_AUTHORITY',registry.commit,forged)
        registry.generations['provider']=2
        self.error('RT_PATCH_TRANSACTION_STALE',registry.commit,ticket)
        self.assertEqual(registry.images,before);self.assertEqual(registry.exposed,set())

    def test_weak_null_modular_addresses_integer_and_code_no_authority(self):
        for kind in ['data_address','data_integer','function_token','import_token']:
            registry,_=self.state()
            target={'kind':'data' if kind.startswith('data_') else 'function' if kind=='function_token' else 'import',
                    'weak_null':True,'live':True}
            record=self.record(kind,addend=-1 if kind.startswith('data_') else 0)
            registry.commit(registry.prepare([record],lambda ref:target))
            expected=2**64-1 if kind.startswith('data_') else 0
            self.assertEqual(int.from_bytes(registry.images['data',0]['bytes'][:8],'little'),expected)
            self.assertEqual(registry.images['data',0]['origins'],[]);self.assertEqual(registry.exposed,set())
        registry,_=self.state()
        self.error('RT_PATCH_WEAK_TLS',registry.prepare,[self.record('tls_offset')],
                   lambda ref:{'kind':'tls','weak_null':True,'live':True})

    def test_tls_provider_table_alignment_width_overflow_and_helper_distinction(self):
        segments=[{'id':0,'alignment':8,'initial':'000000','zero_fill':0},
                  {'id':1,'alignment':16,'initial':'','zero_fill':9}]
        placement,size=relocations.tls_layout(segments)
        self.assertEqual((placement,size),({0:0,1:16},25))
        registry,target=self.state();target.update(kind='tls',value=16,tls_binding={
            'module':'provider','generation':1,'segment':1,'offset':16})
        registry.commit(registry.prepare([self.record('tls_offset',width=4)],lambda ref:target))
        self.assertEqual(registry.images['data',0]['origins'],[])
        self.assertEqual(registry.bindings[0]['tls_binding']['offset'],16)
        registry,target=self.state();target.update(kind='tls',value=2**32,tls_binding={
            'module':'provider','generation':1,'segment':1,'offset':2**32})
        self.error('RT_PATCH_OVERFLOW',registry.prepare,[self.record('tls_offset',width=4)],lambda ref:target)

    def test_code_token_not_native_pc_and_partial_old_origins_preserved(self):
        registry,target=self.state();target.update(kind='function',value=1,portable=False)
        self.error('RT_PATCH_CODE_TOKEN',registry.prepare,[self.record('function_token')],lambda ref:target)
        origin={'offset':0,'length':64,'source_bit':0,'pointer_bits':1}
        self.assertEqual(relocations.remove_origins([origin],16,48),[
            {**origin,'length':16},{**origin,'offset':48,'length':16,'source_bit':48}])

    def test_static_function_and_import_integer_code_exposure_separate_from_data(self):
        for kind in ['function_integer','import_integer']:
            for precision in [1,13,64,65,257]:
                registry,target=self.state();target.update(kind='function' if kind=='function_integer' else 'import',
                                                           value=7,portable=True)
                record=self.record(kind,integer_bits=precision,width=(precision+7)//8,addend=-9)
                registry.commit(registry.prepare([record],lambda ref:target))
                self.assertEqual(int.from_bytes(registry.images['data',0]['bytes'][:record['width']],'little'),
                                 ((7&((1<<precision)-1))-9)%2**precision)
                self.assertEqual(registry.exposed,set());self.assertEqual(registry.exposed_code,{(9,2)})
                self.assertEqual(registry.images['data',0]['origins'],[])
        registry,target=self.state();target.update(kind='function',value=7,portable=True)
        self.error('RT_PATCH_UNUSED_POINTER_OPTIONS',registry.prepare,[self.record('function_integer',
            derivation=[{'offset':1,'check_base':False,'flags':[],'inrange':None}])],lambda ref:target)


if __name__=='__main__':unittest.main()
