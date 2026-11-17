#!/usr/bin/env python3
"""Reproduce INT029 whole-object service signatures and fixed integer siblings.

Writes the owned fixed conformance bundle only when invoked without --check.
All source objects are specification witnesses, not service execution evidence.
"""
import argparse
import base64
import zlib
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = ROOT / 'docs/specifications/smir/portable'
OUTPUT = SPEC / 'conformance/runtime/candidate/joint/service-fixed-integer-types.json'
sys.path.insert(0, str(ROOT / 'tools/smir-format'))
from codec import CandidateCodec



# Immutable historical ABI1 counter, retained as a revision rejection input.
# Origin: INT029 actual whole-root wrong rejection; archived before ABI2.
LEGACY_FILE_SEEK_SHA256 = 'b42a4c54196679f147c16f5bfac826104d195d01a9be7ccd2cc53b9a9cbfb4cb'
LEGACY_FILE_SEEK_B85 = (
    'c-oDaOKjXk7=XRWZXTtDrcFv7&~D57q0%%ES_vU0-'
    'bpgTYcIBUoAiL?c%5Ln@h*<Hq!KS7P|F1>P6#0csDk!TBo07%NE{GSDj^V5LL3krH~|MFE+9C-'
    'jCbsv@gu=f;_>fq{`u#h|NqB3S{bQ3wvBHSgdQO$kpF^!AB6EyA-'
    'E28Zo<F#BKKTC2|}@R6Q1nt+<U0}jeO@hPv7@a`T0WU`C+OrPvrxBo#z26FHreTD&J1!ec`xN?ofF@m7k628KCl4V)DVzPAVUv@@'
    '-UpiOQFTI(H)7L+0VQK4}+eyNBxR^~}eK3mzcPb<;PEmhTZCY+GsDYra85gfGOIKAsu0*Dbr{J59HrY8{}%llEXZ8rDQs2T<m!Q0'
    'sErwMggf)a3k{-'
    'B=!qKLk&?;NL*2>G|eT!;ZS{psOFyBW!~%FzqTNyIvhETw2#?XkM}_VOb$iPcF_nGU1(!+lQF;uDDBg$J~w`G>k>h^f1f_&-'
    'AVNUfc3F*ttiI9P8Q3K`=A+^Nk@^!w~yg=<Pa?ab6)zgm9#Mlo{PNcSR2CW#T!{w7DxXhQ!NGp_>JRX>>HRjSSsAu?_>Q`FUzxkq'
    'V3KORig<b#jiGSWZa4h+Mz&h<p0d+vna?-'
    '~Z5h7k%~IOCNoUym#R4vu9qoaJ27Ek}>wWx!S@ZNlHWAc74Y`6{_rOE<I{nzHt7{{Rd9pcy9EOSI<4V>-3c$YbP$f-'
    'TcYB1)cj{c=@T<9xF5)x4oWso371{-l;Ot2qeRd<43|loG3tgtyYVKQ`24PuiMLJyWs~j4N@}J3Uo(3yKc(z0`H?VW$de=u-'
    '3J_X3JbLeLJDJ&$Iou=jMd?Omi9I_OIFANyiF2L!xPI)$tC7v3&64B#EkJ2RGMj`vmFm#3vh1{MITy{psRQKmUE?+3$a?Y+U~4>!'
    'V*hf91W6_3b0y1(se8Y$pA(><Gu_AS&BxL2t#()bzd6Q-'
    '_b<Z7)wx9jzZRr_H;k?!}GCx;cH%RK0FaT89r!ADO;p#ddAau?)vIU8lXeqk-Lqi-hSLEhq33NfE=C9I)4Y+jGsvh-'
    'a=FjpmADnGK`iEVbRo9k;GxY6AaBXhvLE05iydGMJH|0T)DA(UBr+1#8tjVUq+<<Xh6vSw)>gH6+g&r9~N(k!XlO(>vXW70T>vYC'
    'jnsGfGf`I>fhGB%{P|*QRyT=79=JoceT52Rag2b;WGVsLIEXT!JdgkEZeZyb3{yGjl)3%>xa4Plu`uBuX2gg4hmYi4K)GNN2V;L1'
    'Htf4jUObueho~LsZHYBtg|sb=HE31Sm<ha;g`0MW{j8V5uOTKMCzo{ymNc5gJGbGOCtYJ>zK{juutXlvzGphIteR71Sy~gk1<n_H'
    'G`k%6KL50&$9Bw%4Gl;TY>6BuOU67(mmYN<z@kU>V3!?2s=XXT@!L_SIdOYU~iCnBa`E*4ND?hjGWIsg&eq@j7XXnhvwvMmb3lfr'
    'O3&J(@~~ygose6<N_0nPepH^k8}bgs=+al2XR&TSK9z69EvSy3WP(aDqrl(iA9>p(6<<CEbci2$i96T#<1h0XPVN1~*q)#V%1waC'
    '7G!LnWL(cpgB+$*iU4FUfQj7#a$T7@HZ)z*tQQ%A`h?qk+lC1=+pFSWGj-$w_0&YVd!m%rH-vtD0nxXHMlF9?Ggi6FjzQ5xT9*>W'
    'dYK<XI&sLqJ6u&Ms80NU#iLoeAI|7pc9S8WgUA2>H@bOoea_(P;6)K2C{qo}X25MIm-'
    ';DgNToIZ;d7YIrDnONw!cfFDi6Qeu9L<2EVm#RS-'
    'y>^#<pVG)S)e2Kh)R8z8Cl}b<}ffNLlPOMc)z)E0Isp^Am7k?!>u3aaQy*JirMycX$qeK$xp(?~tr1Jb&jOR9qehLObFp)||+XTx'
    'V8i}#dJ`qxMr?@`GsbHa7l!>vN1-oN3-'
    '84An0Lvuy4N?g}Rf>$=zd4QOWJQHHGf)X>K_JwShGvk2^hE>6xReJOqh&7zUuEKEOk|TXuAO_h*BY}OaZ?|SVeD>{xspNs;Ws0W9'
    'f`AHt>V^uEJkrVR^}QKl4cagjHfcBDv%P)4ZJTK4Qnu`dT%yQ3oNJpx@<fsv>cq!o!I*}^#tAeIOdKRQ-'
    'j#AssU;MNgx@2oH_ATj_sP6ZbA5SO|6n`0GEwpNT0`<0k{A<#0Dg}bv{w!QNhhH!0_)1e9x>D0aL+VNW|ALL&=I!6V<9r+{+DDWT'
    '1+sOU4WkAH)tLGMu*+po{Z-hE8Plz?A?2iHG-P!g|TzV~60kGx*k<EjJPNNTb&}Jk`I{b{f9plA`Ij{-3YspF4A{u3sEIc&EQ-Zt'
    '@rThku?Loe)1;zOZoq^A}tANBJ85DQSA)2}(y-;iTDU+qvkNC>Q<~9k80@Ji@oP`<`>s!9PN+X6w{7;X~afXA!5u-'
    '^<}SYQbu?x~7rilJFE_LtFazgZfQ(z4P(=U)JFt`GbX}w-'
    '({A_kT8i@v$>!@B5263rij{<=93p^upj8{?0f3wr6(_K!RySw#SbdHa!iC-'
    '{a>L{MiU+QPkqjQU+V5XRcy1yyPVM>W*hyK0AKG$nH$LXQGM5&=%K$Ev~68uF@9QR;MIcCr<wXIC)uS'
)


def prepare_abi2_nonrecord_source(roots):
    """Offline declared-source regeneration, never a decoder/old-byte upgrade.

    Non-record source kinds have explicit no-record input. Complete record
    declarations must come from the owning ABI source builder; selected output
    fields are never reverse engineered into missing source declarations here.
    """
    contract = roots[10]
    if contract['payload_revision'] != 3:
        raise ValueError('unknown producer ABI source revision')
    if any(item['kind'] == 'record' for item in contract['types']):
        raise ValueError('R-ABI2-EXPLICIT-RECORD-SOURCE-REQUIRED')
    for item in contract['types']:
        if item.get('record_input') is not None:
            raise ValueError('R-ABI2-NONRECORD-SOURCE-INPUT')
        item['record_input'] = None
    for layout in contract['layouts']:
        if layout['fields'] or layout['bases'] or layout['vptrs']:
            raise ValueError('R-ABI2-NONRECORD-OUTPUT-MEMBERS')
    for signature in contract['signatures']:
        if 'execution' not in signature:
            raise ValueError('R-ABI3-EXPLICIT-PLAN-EXECUTION-REQUIRED')
    directory = ROOT / 'tools/smir-abi'
    previous = list(sys.path)
    sys.path.insert(0, str(directory))
    try:
        for name in ('layout', 'nominal', 'graph_identity'):
            loaded = sys.modules.get(name)
            if loaded is not None and Path(loaded.__file__).resolve() != (directory / (name + '.py')).resolve():
                raise ValueError('R-ABI2-IMPORT-CONTEXT: use standalone producer')
        from nominal import NominalGraph
        graph = NominalGraph(contract, 'runtime-abi3-producer')
        for item in contract['types']:
            item['identity']['definition'] = graph.fingerprint(ref(item['id'])) if 'complete' in item['flags'] else '00' * 32
    finally:
        sys.path[:] = previous
    return roots


def legacy_file_seek_case():
    data = zlib.decompress(base64.b85decode(LEGACY_FILE_SEEK_B85.encode('ascii')))
    if hashlib.sha256(data).hexdigest() != LEGACY_FILE_SEEK_SHA256:
        raise ValueError('historical ABI1 counter checksum mismatch')
    return {'name': 'legacy-abi1-original-file-seek', 'accept': False,
            'expected_error': 'WIRE-REVISION', 'capability': 'file',
            'sha256': LEGACY_FILE_SEEK_SHA256, 'encoded_hex': data.hex(),
            'evidence_limit': 'Old ABI1 preflight rejection only, not service semantics.'}


def ref(identifier):
    return {'module': {'kind': 'self'}, 'id': identifier}


def complete_identity():
    source = SPEC / 'conformance/execution/candidate/portable-identity.json'
    roots = {int(key): value for key, value in json.loads(source.read_text())['sections'].items()}
    roots.setdefault(5, {'payload_revision': 2, 'relocations': [], 'constant_initializers': []})
    roots.setdefault(7, {'payload_revision': 1, 'segments': []})
    roots.setdefault(9, {'payload_revision': 1, 'capabilities': [], 'requirements': [], 'limits': []})
    return prepare_abi2_nonrecord_source(roots)


def service_object(specification):
    roots = complete_identity()
    definitions = roots[1]['types']
    integers = {item['bits']: item['id'] for item in definitions if item['kind'] == 'int'}
    pointer = next(item['id'] for item in definitions if item['kind'] == 'data_ptr')
    identifier = max(item['id'] for item in definitions) + 1
    code = None
    if any(formal['type'] == 'code_ptr' for side in ['params', 'results']
           for formal in specification[side]):
        code = identifier
        definitions.append({'id': code, 'kind': 'code_ptr', 'signature': ref(12)})
        identifier += 1

    def execution_type(template):
        if template[0] in 'iu' and template[1:].isdigit():
            return ref(integers[int(template[1:])])
        if template == 'data_ptr':
            return ref(pointer)
        if template == 'code_ptr' and code is not None:
            return ref(code)
        raise ValueError('unknown actual catalog template: ' + template)

    definitions.append({'id': identifier, 'kind': 'function',
        'params': [execution_type(formal['type']) for formal in specification['params']],
        'results': [execution_type(formal['type']) for formal in specification['results']],
        'param_noundef': [formal['noundef'] for formal in specification['params']],
        'result_noundef': [formal['noundef'] for formal in specification['results']],
        'variadic': False, 'cc': 'portable'})
    namespace = specification['descriptor_namespace']
    descriptor = None if namespace == 'none' else {'some': ref(0 if namespace == 'signature' else 1)}
    roots[6]['imports'] = [{'id': 0, 'kind': 'service', 'namespace': specification['namespace'],
        'name': specification['name'], 'version': 1,
        'catalog': '7cbbc87ceb70207fbc59dfe3fa3882d8ea50c8c9d1cf39c585d3b1c8780c15d6',
        'signature': ref(identifier), 'abi': None, 'capability': specification['capability'],
        'descriptor': descriptor}]
    roots[9]['capabilities'] = [specification['capability']]
    return roots


def build_document():
    schema_paths = {name: SPEC / 'schema' / name / 'candidate.json'
                    for name in ['execution', 'runtime', 'abi']}
    codec = CandidateCodec({name: json.loads(path.read_text()) for name, path in schema_paths.items()})
    catalog_path = SPEC / 'schema/runtime/services-v1.json'
    catalog = json.loads(catalog_path.read_text())

    def case(name, roots, accept, capability, error=None):
        data = codec.encode(roots)
        decoded = codec.decode(data)
        if len(decoded.roots) != 10:
            raise ValueError('complete-object witness lacks roots')
        return {'name': name, 'accept': accept, 'expected_error': error, 'capability': capability,
                'sha256': hashlib.sha256(data).hexdigest(), 'content_identity': decoded.content_digest,
                'encoded_hex': data.hex()}

    services = [case(record['name'], service_object(record), True, record['capability'])
                for record in catalog['records']]
    base = service_object(next(record for record in catalog['records'] if record['name'] == 'file.seek'))
    original = case('abi2-equivalent-file-seek-i64', base, True, 'file')
    expected_original = 'b42a4c54196679f147c16f5bfac826104d195d01a9be7ccd2cc53b9a9cbfb4cb'
    cases = [original]
    signature_id = base[6]['imports'][0]['signature']['id']
    for kind, bits in [('int', 32), ('int', 63), ('int', 65), ('raw', 64), ('float', 64), ('data_ptr', 64)]:
        roots = deepcopy(base)
        identifier = max(item['id'] for item in roots[1]['types']) + 1
        record = {'id': identifier, 'kind': kind}
        if kind == 'data_ptr':
            record['space'] = 'guest_data'
        elif kind == 'float':
            record['format'] = 'binary64'
        else:
            record['bits'] = bits
        roots[1]['types'].append(record)
        next(item for item in roots[1]['types'] if item['id'] == signature_id)['params'][1] = ref(identifier)
        cases.append(case('offset-' + kind + '-' + str(bits), roots, False, 'file',
                          'runtime_helper_contract: RT_SERVICE_TYPE'))
    for name, field, value, error in [
        ('bad-catalog', 'catalog', '00' * 32, 'runtime_helper_contract: RT_SERVICE_VERSION'),
        ('bad-version', 'version', 2, 'runtime_helper_contract: RT_SERVICE_VERSION'),
        ('bad-capability', 'capability', 'clock', 'runtime_helper_contract: RT_SERVICE_CAPABILITY'),
        ('unused-descriptor', 'descriptor', {'some': ref(1)}, 'runtime_helper_contract: RT_SERVICE_UNUSED_DESCRIPTOR'),
    ]:
        roots = deepcopy(base)
        roots[6]['imports'][0][field] = value
        cases.append(case(name, roots, False, 'file', error))
    for name, mutation in [('bad-noundef', 0), ('bad-arity', 1), ('wrong-result-width', 2)]:
        roots = deepcopy(base)
        signature = next(item for item in roots[1]['types'] if item['id'] == signature_id)
        if mutation == 0:
            signature['param_noundef'][1] = True
        elif mutation == 1:
            signature['params'].pop()
            signature['param_noundef'].pop()
        else:
            signature['results'][1] = deepcopy(signature['results'][0])
        error = 'runtime_helper_contract: ' + ('RT_SERVICE_TYPE' if mutation == 2 else 'RT_SERVICE_SIGNATURE')
        cases.append(case(name, roots, False, 'file', error))
    roots = deepcopy(base)
    roots[9]['capabilities'] = []
    cases.append(case('missing-capability-request', roots, False, 'file', 'REFERENCE-IMPORT-CAPABILITY-GRANT'))
    roots = deepcopy(base)
    roots[6]['imports'][0]['id'] = 9876
    roots[6]['imports'][0]['signature']['id'] = 80001
    signature = next(item for item in roots[1]['types'] if item['id'] == signature_id)
    signature['id'] = 80001
    integer_id = signature['params'][1]['id']
    next(item for item in roots[1]['types'] if item['id'] == integer_id)['id'] = 70001

    def rename_execution_refs(value):
        if isinstance(value, dict):
            if set(value) == {'module', 'id'} and value['module'] == {'kind': 'self'} and value['id'] == integer_id:
                value['id'] = 70001
            for child in value.values():
                rename_execution_refs(child)
        elif isinstance(value, list):
            for child in value:
                rename_execution_refs(child)

    # This witness's layout-reference IDs are all distinct from integer_id.
    rename_execution_refs(roots[1])
    roots[1]['types'].sort(key=lambda item: item['id'])
    roots[3]['functions'][0]['id'] = 1234
    roots[2]['symbols'][0]['definition']['some']['target']['id'] = 1234
    cases.append(case('alpha-type-signature-function-import-ids', roots, True, 'file'))
    inputs = [ROOT / 'tools/smir-format/codec.py', *schema_paths.values(), catalog_path,
              SPEC / 'conformance/execution/candidate/portable-identity.json',
              ROOT / 'tools/smir-abi/nominal.py', ROOT / 'tools/smir-abi/graph_identity.py',
              ROOT / 'tools/smir-abi/layout.py']
    metadata = {'generator': str(Path(__file__).resolve().relative_to(ROOT)),
                'generator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'input_sha256': {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                 for path in sorted(inputs)},
                'command': 'python3 -B tools/smir-runtime-contract/generate_service_type_fixtures.py',
                'check_command': 'python3 -B tools/smir-runtime-contract/generate_service_type_fixtures.py --check',
                'legacy_original_counter_object_sha256': expected_original,
                'source_regeneration': 'Explicit nonrecord declared-source ABI2 plus V2 fingerprints; no old-byte decoder upgrade',
                'encoded_object_bytes': sum(len(bytes.fromhex(item['encoded_hex'])) for item in services + cases),
                'size_justification': '75 independent complete ten-root byte witnesses (59 service signatures plus16 siblings). '
                    'Hex doubles encoded byte storage; complete framing/root/source identities prevent a scalar-only mock '
                    'from replacing full verification. Deterministic generator and input hashes permit byte-exact replay.'}
    return {'revision': 1, 'proposal': 'INT029REV1', 'provenance': metadata,
            'scope': 'Complete static service/source verification with explicit per-case reference grants; no service/provider/native execution',
            'services': services, 'cases': cases, 'legacy_cases': [legacy_file_seek_case()]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Compare bytes without writing')
    args = parser.parse_args()
    expected = (json.dumps(build_document(), indent=2) + '\n').encode()
    if args.check:
        if OUTPUT.read_bytes() != expected:
            raise SystemExit('generated service corpus is stale')
    else:
        OUTPUT.write_bytes(expected)
    print(('checked' if args.check else 'generated') + ' ' + str(OUTPUT.relative_to(ROOT))
          + ' bytes=' + str(len(expected)) + ' sha256=' + hashlib.sha256(expected).hexdigest())


if __name__ == '__main__':
    main()
