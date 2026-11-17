"""Actual portable AST -> closed UNBOUND execution/ABI fragments, no source facts."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import tempfile

NATIVE_INVOCATIONS=[]
from portable_type_paths import foundation
ROOT = foundation()
sys.path.insert(0, str(ROOT / 'tools/smir-abi'))
from nominal import NominalGraph, ZERO, ref, some
from site_config import identity
from candidate_codec import encode, decode

class ProjectionError(ValueError):
    def __init__(self, code, detail=''):
        self.code = code
        super().__init__(code + (': ' + detail if detail else ''))

def need(ok, code, detail=''):
    if not ok:
        raise ProjectionError(code, detail)

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def project(ast, language):
    need(ast['datalayout'] == json.loads((ROOT/'docs/specifications/smir/portable/llvm/target.json').read_text())['datalayout'], 'PORTABLE_DATALAYOUT_MISMATCH')
    need(ast['factory_calls'] == 1 and ast['triple'] == 'smir64-unknown-rax' and
         ast['little_endian'] is True and ast['pointer_bits'] == 64 and ast['long_bits'] == 64 and
         ast['long_double_bits'] == 128 and ast['long_double_precision'] == 113,
         'PORTABLE_TARGET_MISMATCH')
    rows = ast['ast_types']
    need(len(rows) <= 512 and [r['id'] for r in rows] == list(range(len(rows))), 'PORTABLE_AST_ROWS')
    executions, cache = [], {}
    def isbyte(i):
        return rows[i]['kind'] == 'scalar' and rows[i]['byte_category'] is not None
    def execution(i, lane=False):
        key = i, lane
        if key in cache:
            return cache[key]
        r = rows[i]
        if r['kind'] == 'void':
            cache[key] = None
            return None
        eid = len(executions)
        cache[key] = eid
        executions.append(None)
        kind = r['kind']
        if kind in ('scalar', 'bitint', 'enum'):
            if 'float_format' in r:
                item = dict(kind='float', format={32:'binary32',64:'binary64',128:'binary128'}[r['bits']])
            else:
                item = dict(kind='raw' if isbyte(i) and not lane else 'int', bits=r['bits'])
        elif kind == 'pointer':
            item = (dict(kind='code_address') if rows[r['elements'][0]]['kind'] == 'function'
                    else dict(kind='data_ptr', space='guest_data'))
        elif kind in ('array', 'vector'):
            child = execution(r['elements'][0], kind == 'vector')
            need(child is not None, 'PORTABLE_ELEMENT_UNAVAILABLE')
            item = dict(kind=kind, element=ref(child), count=r['extent'])
        elif kind == 'function':
            params, result = r['elements'][:-1], r['elements'][-1]
            need(all(rows[p]['kind'] not in ('void','array','function') for p in params) and
                 rows[result]['kind'] not in ('array','function'), 'PORTABLE_FUNCTION_UNAVAILABLE')
            ret = execution(result)
            item = dict(kind='function', cc='portable', variadic=False,
                        params=[ref(execution(p)) for p in params],
                        results=[] if ret is None else [ref(ret)],
                        param_noundef=[not isbyte(p) for p in params],
                        result_noundef=[] if ret is None else [not isbyte(result)])
        else:
            raise ProjectionError('PORTABLE_TYPE_UNAVAILABLE', kind)
        executions[eid] = dict(id=eid, **item)
        return eid
    for row in rows:
        execution(row['id'])
    nominals, layouts, plans, relation = [], [], [], []
    for r in rows:
        i, kind = r['id'], r['kind']
        eid = execution(i)
        flags = ['complete'] if kind in ('void', 'function') else ['complete','trivial_copy','trivial_destroy']
        code = kind == 'pointer' and rows[r['elements'][0]]['kind'] == 'function'
        if code: flags.append('code')
        if r['fixed_enum']: flags.append('fixed_base')
        if r['scoped_enum']: flags.append('scoped')
        if r['noexcept']: flags.append('noexcept')
        if kind == 'function' and language == 'c23': flags.append('c_linkage')
        if kind == 'scalar' and r['entity'] == 'char' and r['signed']: flags.append('signed_char')
        enums = []
        for e in r['enumerators']:
            bits, v = r['bits'], int(e['decimal'])
            need((-(1 << (bits-1)) if r['signed'] else 0) <= v < (1 << (bits-int(r['signed']))),
                 'PORTABLE_ENUM_RANGE_UNAVAILABLE')
            enums.append(dict(name=e['name'], value=(v % (1 << bits)).to_bytes((bits+7)//8,'little').hex()))
        nominal = dict(id=i, domain=0, identity=dict(language=language,
            linkage='external' if kind == 'enum' else 'builtin', entity=r['entity'],
            definition=ZERO, library=None, unit=None), kind=kind, qualifiers=r['qualifiers'],
            bits=r['bits'], signed=r['signed'], elements=[ref(e) for e in r['elements']],
            extent=None if r['extent'] is None else some(r['extent']),
            representation='none' if kind == 'void' else 'signature' if kind == 'function' else
                'code_address' if code else 'value', execution=None if eid is None else some(ref(eid)),
            layout=None if r['storage_bits'] is None else some(i), flags=sorted(flags),
            methods=[], enumerators=enums, record_input=None)
        nominals.append(nominal)
        if r['storage_bits'] is not None:
            need(r['storage_bits'] % 8 == r['alignment_bits'] % 8 == 0, 'PORTABLE_LAYOUT_BITS')
            size, align = r['storage_bits']//8, r['alignment_bits']//8
            layouts.append(dict(id=i,type=ref(i),size=size,align=align,data_size=size,
                                nonvirtual_size=size,nonvirtual_align=align,fields=[],bases=[],vptrs=[]))
        plan = None
        if kind == 'function':
            params, ret = r['elements'][:-1], r['elements'][-1]
            plan = len(plans)
            lowered = []
            for index, p in enumerate(params):
                ptype = rows[p]
                lowered.append(dict(source_index=some(index),role='parameter',source_type=ref(p),value_type=ref(p),
                    mode='direct',align=ptype['alignment_bits']//8,bytes=ptype['storage_bits']//8,
                    noundef=not isbyte(p),copy=None,move=None,destroy=None))
            results = [] if rows[ret]['kind'] == 'void' else [ref(ret)]
            plans.append(dict(id=plan,function_type=ref(i),params=[ref(p) for p in params],
                result=None if not results else some(ref(ret)),this_type=None,vtt=False,
                variadic=False,noexcept=r['noexcept'],lowered_params=lowered,lowered_results=results,
                varargs=None,return_noundef=not isbyte(ret),execution=ref(eid)))
        relation.append(dict(ast_type=i,nominal=ref(i),execution=None if eid is None else ref(eid),
                             layout=None if r['storage_bits'] is None else i,call_plan=plan))
    graphdata = dict(types=nominals,layouts=layouts,domains=[dict(id=0,abi_identity=identity(platform_source_abi_revision=2))])
    graph = NominalGraph(graphdata, 'unbound-portable-prototype')
    for n in nominals:
        n['identity']['definition'] = graph.fingerprint(ref(n['id']))
    # Exact existing closed ABI record grammars, not custom approximations.
    for name, values in [('nominal_type',nominals),('object_layout',layouts),('call_signature',plans)]:
        for value in values:
            need(decode(name,encode(name,value)) == value, 'PORTABLE_ABI_RECORD_ROUNDTRIP')
    return dict(format='portable-type-projection-draft-r1',binding='unbound',
        source_fact_authority=False,semantic_admission=False,runtime_authority=False,
        library_membership_authority=False,language=language,
        abi_identity=identity(platform_source_abi_revision=2),
        execution_root=dict(payload_revision=2,types=executions,memory_layouts=[]),
        abi_fragment=dict(types=nominals,layouts=layouts,signatures=plans),
        emitted_type_relation=relation,auxiliary_execution_relation=[dict(vector_ast_type=r['id'],element_ast_type=r['elements'][0],execution=ref(cache[r['elements'][0],True]),reason='numeric_vector_lane') for r in rows if r['kind']=='vector'],declarations=ast['declarations'],enum_hooks=ast['enum_hooks'],
        target={k:ast[k] for k in ['factory_calls','triple','datalayout','little_endian','pointer_bits',
                                  'long_bits','long_double_bits','long_double_precision']},
        limitations=['finite declaration/type facet; no function bodies/records/varargs/references',
            'no genuine pinned std::byte membership or portable va_list implementation',
            'single-source draft recipe, not closed CPP06/07 issuer registration',
            'vector numeric lane execution differs intentionally from scalar byte execution',
            'no SourceEvidencePolicy private facts, complete module roots, storage bindings or admission'])

def run(request, native, *, receipt=None):
    need(type(request) is dict and set(request) == {'language','source'}, 'PORTABLE_RECIPE_FIELDS')
    language, source = request['language'], request['source']
    need(type(language) is str and language in ('c23','cpp23') and type(source) is str,
         'PORTABLE_RECIPE_LANGUAGE')
    try: encoded = source.encode('ascii')
    except UnicodeError as e: raise ProjectionError('PORTABLE_SOURCE_ASCII_PROFILE') from e
    need(0 < len(encoded) <= 1024*1024 and b'\0' not in encoded, 'PORTABLE_SOURCE_LIMIT')
    native = Path(native).resolve()
    before = {str(native):sha(native)}
    if receipt is not None:
        build = json.loads(Path(receipt).read_text())
        need(build['exit'] == 0 and build['drift'] == [] and
             build['binary']['sha256'] == before[str(native)], 'PORTABLE_BUILD_RECEIPT')
        before.update(build['input_hashes'])
        need(all(sha(p) == h for p,h in before.items()), 'PORTABLE_BUILD_INPUT_CHANGED')
    with tempfile.TemporaryDirectory(prefix='portable-type-') as temp:
        path = Path(temp)/('main.cpp' if language == 'cpp23' else 'main.c')
        path.write_bytes(encoded)
        env = {k:v for k,v in os.environ.items() if k not in ('CPATH','C_INCLUDE_PATH','CPLUS_INCLUDE_PATH','OBJC_INCLUDE_PATH','SOURCE_DATE_EPOCH')}
        env['TZ']='UTC'; env['LC_ALL']='C'
        result = subprocess.run([str(native),language,str(path)],capture_output=True,text=True,timeout=20,env=env)
    NATIVE_INVOCATIONS.append(dict(command=[str(native),language,'<temporary-source-main>'],
        source_sha256=hashlib.sha256(encoded).hexdigest(),source_bytes=len(encoded),
        native_sha256=before[str(native)],exit=result.returncode,
        stdout_bytes=len(result.stdout.encode('utf8')),stderr_bytes=len(result.stderr.encode('utf8')),
        stdout_sha256=hashlib.sha256(result.stdout.encode('utf8')).hexdigest(),
        stderr_sha256=hashlib.sha256(result.stderr.encode('utf8')).hexdigest()))
    changed = [p for p,h in before.items() if sha(p) != h]
    need(not changed, 'PORTABLE_INPUT_CHANGED', repr(changed))
    if result.returncode != 0:
        need(not result.stdout.strip(), 'PORTABLE_PARTIAL_PRODUCT_ON_FAILURE')
    need(result.returncode == 0, 'PORTABLE_FRONTEND_UNAVAILABLE', result.stderr[-4096:])
    need(len(result.stdout) <= 2*1024*1024, 'PORTABLE_OUTPUT_LIMIT')
    product = project(json.loads(result.stdout),language)
    product['input'] = dict(source_sha256=hashlib.sha256(encoded).hexdigest(),
                           native_sha256=before[str(native)],virtual_path='/rax-source-v1/main.cpp' if language=='cpp23' else '/rax-source-v1/main.c',
                           source_date_epoch=0,mtime=0)
    return product

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--native',type=Path,required=True)
    parser.add_argument('--build-receipt',type=Path)
    parser.add_argument('--request',type=Path,required=True)
    args = parser.parse_args()
    try:
        with args.request.open('rb') as stream:
            raw = stream.read(8*1024*1024+1)
        need(len(raw)<=8*1024*1024,'PORTABLE_REQUEST_LIMIT')
        def object_pairs(pairs):
            obj={}
            for key,value in pairs:
                need(key not in obj,'PORTABLE_REQUEST_DUPLICATE_FIELD')
                obj[key]=value
            return obj
        request = json.loads(raw.decode('utf8'),object_pairs_hook=object_pairs)
        product = run(request,args.native,receipt=args.build_receipt)
        print(json.dumps(product,sort_keys=True,indent=2))
    except (ProjectionError,OSError,ValueError,RecursionError,subprocess.SubprocessError) as e:
        print(str(e),file=sys.stderr)
        sys.exit(3)
