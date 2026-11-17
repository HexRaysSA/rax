#!/usr/bin/env python3
"""Generate INT031 source journal/capture conformance objects, never execution."""
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
OUTPUT = SPEC / 'conformance/runtime/candidate/joint/journal-helper-captures.json'
sys.path.insert(0, str(ROOT / 'tools/smir-format'))
from codec import CandidateCodec
from generate_service_type_fixtures import prepare_abi2_nonrecord_source

LEGACY_COUNTERS_B85 = (
    'c-'
    'rk;ORwCv75*=GZ3BEivd_Ys7D$11Q4|41QjLMc4(uBsY0>}QbEwBi6iI1j+_)_$d+xnMQ6I_krgU`v`p=gS?x*<j&C8GR@6P}B)('
    '!9JTmSLH=hsia_}BLzKfL`%{PgkV&5QFs{`~s#&FFso9N)aeUw@ANHHPowr%xY0!S#Q6_uaQ|zx(#j@BZ}ekAHyvpMP*nDmcMS4A'
    'CoXw4`y2JQ5cNuY;3LF*A%oP^P5{BnD{*B9-vLTSkWvjR}qb7R={0et7-'
    '<eSn|uUw;Es;)cLS6{r;65n&XGUN{dej=~UwFaWBDK?lu^9=K-'
    'Cg;7CAr}W?ipvDjWV}KR>5Pt<g$wd%WG7^ZRjyQq`gAXNS{Tq+z46%xiWOHz`KgRi38|VgWf}`91OcA*QVEg{U5VaeRuQR$$VAJ2'
    'E|F=WNY=UCnKW6<0m-UzX{&3pv;6m14?fZ{e|3PQ{b%t-qZU!o!kJ<O9h75=E+ru8{zw1x)`M7<5p5e<##jgL{mo3+DWmVK-'
    'Z6{ef%jO9ps;JhBAg$m=3229p95vBGv-'
    'K26GANGJTnjlay;gjAildr17Fvwr@Dq9i=BOgk*<4Mw`la3GYn$gZ^H9(XXE@AN!HlBf>&SjjWg;}pOnId!Jw0<fM>l^NP1L9vu2'
    'nJUFAJlFO!sftvf8rO;QgrN(x`ExaaTt@uDaESU7(rV%zpV-'
    'r`^oq+*q#d6)jk1QkPQ7+tNNs(4vcG8RCc|n>Y%;Yji~L+nXBS3oW!Jv)<OIyrFG=MjT|8G^J;zBlB~wrLTl_u|ylom)6@TmSkiv'
    'Tt%x_nZs2I&W}h*&gQEO%nxRk@GR%huEFz;;FB4)Di8i^#)qqcZd&ohRyyPb^x<j%4h6(e1DEqztx=>$7|~)suGSGV`g6Vau#Kan'
    'm0Y28$VGm@{%7=9@sA_hj2lP(9?q=vxXO8(`}2cDih{>4wbzg1{CPzNM5Voc95u=1i_S3ZWo({fuNr-I-'
    't0_bs?^Uo%+7#sSJn?vwL`SRF?yL+2k$`a7sFNuDPL_-P1358c(k6T5J8rCVJh6aF0JOUlEprn%1X==E7{^axzSmulA<}P0@#sc-'
    '{w|}HV!=qSW}_xfwv0m83U-~7cnY#lu^cvX2J<-l(EhU1&u}r9wNAcVK5G^3Sh0kTv;a~hW<=P>op~~ZuD3%8?gKlt)-'
    'GxdCxeTtznJ{<tQCD`AU>6L{=P)Hh|6EK8+3y=}Pb_(A&c*Z~XBEo|W2eJUfnA(r?<}cXO>uCr``JgMw#L_#2}cpyd+DfZx2jzEv'
    'A(!F#0E6?M~g!mF*3E3YLM*8=`+ie;cTdvHCpupUud&nA{VvFuxaQeMw&F9FwUzT*m?+P)}H7R>uNa^2U{s()%re&s5fpRurbpaR'
    'g2f&?Hp<OQFi;2H_^OYvh<e^|rbszMuWtm^2cMDA<ur2WEojE$ud#nDZnO%&Q#MPg~y_uSilHv5+R9Cht%RDavEfo#C_iRT<-'
    'y`%}x%D1^$n`uXKFvJ}89u~Y<%zHB2txyv7I~s|$OoB|?n}ouoM;Zw@V#%a(RvORr=!1`PAe4{9Iv&A+OBP6=kw>ZR2wMRT)aBNg'
    'ja{$>yFd;U#9d3=?qz2$l+#U5TA1$dBnq#-'
    'c<Ysq9=g=8?8j*}iu_OLqxnMmc(gldFPiAci|ebcSAq0M_~5S1*5&cph>DrzelP|%@PWNHw>+&XeS^3Nq9e+|6mtRJ_0+;q!=RN*'
    'xG?D|wBWTEBpKLMk08ky$)J40+CjQ)+I@mHq}%lYIFqdRd?$tCPffPczxYjv&_<525%|rm9#NU@HJG%UACu<rS(7kIL<x>M>5~$2'
    'wsv&6SLlTmOmJzW5fuKiauia;^tTrhzrh&}KZz93cN9@_P)O8jss@nO<=zvVVfr$v5~E}S_yFQ!;f#hhA#Lgtpam!eqf*JG*p0^5'
    '(SX=@j2Gc&8Uxy~MWj~zHjQu3S4S_8Cb@t!us#5-'
    '&;A}f0HSGzb=s3h(BK=KgOC7efHYy%)tk%sLYTC63V`+b(gvPMoKLcsIK>ja&#*`6MTD)+*q)D&q`Hl`=UKdfnW%{t<idRS=#3dm'
    'DS47v4t)dSBx>UrEYp!K4TcMd9w@5-'
    '^SUgsBPy<Lro&CEWXAv7Q>NDSlWmyhhI&bpeo7Il^KqB)CfmXU>L{FPS(oK*cm;K`RIoze1x54{(qyxjyYFSBMD?VTlLj?r)TBG`'
    '5aoeSc5H_-'
    '>l)0&mJwilo~~Z3AkqgYj<he>9kt%~&=|E~gh^r%c{j%$#ypeBM}gBdX*UR7vLYQ1d!<WwYSt$%ZQ{lK(zeI*BKa@uBi(FmbFOSL'
    '!v)NMJq6kn{Jr?dX{6yE3vjU5Ea{j?mL=(L^2)hPpId+oRiXo|+h=hB<C-VEgmmshm#14zoNL~VTtc$Rf{Y*`Q-'
    'p%Fr?VxXvPJ(ZGnJE+h{VxnBro{{F?*khA7Jq&&)m?vvaLxz9T5_D?I9AY`Hb?4r`ZTGt#yhcLt(|Uge-fk%G{Q?gL8=E@AlrYiT'
    'PYCBbwMD`EsA^PCDP1rD`GF9S;pnw1*=hR^$)JjfLxE;xu~oTQr1HV3SXe7&W9epFEgM9;|GEZ+>w{-'
    ')$Upu)^qdT6+?59chX~WFCblIlgAkoA@f}X|gaAy&JlEef=8d&9CliT1b!VlG=C|EWEjlcFE4~?Z_VQv537TKP%#vvu2v(gq&gyq'
    '-!IJWNU1?Y8R1Y6WOA5S}oONpOLnxVY7wx&<@%pQ4?%>Qd7MDvslFHNGShu+HFkhOOZZ>-'
    '*U1=um@@3+Y|iyPNH%L87#qY2j+1%QNvyRR~7fTpUAQHdy3G;OCHt~Bjts%bsC&VNVe0c;xJajIp1%rF#$@0KT>wNfAAo-'
    '1v?fKCnZxAB#}JI%_6Au9edam*P}NYlT1xfIo<3<9?^<MEOSPUs?@eI;}myN)wr5hc1LyTF(+uXz0v(TxyC=uolzZEp5Y$is=9vL'
    'HdbSgb-x}in0p^p$8mSyEV05I1vgeaK7^XZ!HrqRNAUL%Y-'
    '9HRA@nt(Z6Ke|`+VQ`xJ>MKeRbP>qEl$&CwWbA1w|v1tN^`a|LW8^8@IjJykA=Ebazc+EVb+grf5T_m|(vDh3ja{x@IAlZ=1WQr?'
    '#Tb!y8(9UNL=tAf{MxQq+mEaBjau1q*qL(!k{ujn2~BkStP0f)Dc1r??LzoMDo%wO{hLX)h;`_e~!<+&jh;6F^_IIW6Szeq<@q@0'
    'Q(J(kd#J_>1gps~lM~Z}O+DJUy#Kslca%7ISFQlSjVZ-'
    ';G*~+C~DZXbjbON6!UnSY*(bDxo=zFz4XMLBsBf4uTJ(O3&z>@!UkcJ^`MdN@5=JA&YZ6FS*J5DL>K9o{P>|#&aG~%7pPLN62cV#'
    'q=bUW3G(0WIUXipS`AR8he^USEHC-5?Z$TS0EJ8d0-C>BL@O;Z^yvB80-L>uwVxZNI**vb*HUPaSXm!V6`)&o}WqUET`)@F<Q-'
    'Cu2WMSp8fwG)bxj(_moLkr09}cnZFNUBv)*3gMvMPWTVsYxAb123Nj)X-r-'
    '@6!TwZ6$Kx<k=YpojSi=2iDsRSI$*iu^`Iwz!HJ_i3&^g~q7V{ssnKU`w>u<t5o2!0reusEEC-_Q!U~`5IF5KS0Li^%VJ`SyMmXV'
    '7zx-&=WkT55=IlnSJBTLyrGR-@#`7qnOqSh*J*-1NG&>B1Ck9@6_?raRJO3E=a?-IWRxhP?Gu0lM+FMeT_`d)thUMtOf!g-!*-'
    'Rjjd3Xgef7IRfGQwcM=mi*)kwiWC=<`2%f^Jg;L@`Xn$U3g>ZyoEk_uqO}x<RP9so_>4b-'
    'dxkG=g;$7>wa&_DIafd8lU*a`db(0xsCJj@~=0=x&fc!=U;w`Pge{u&gq~71We3H&z+VukWmaON;yE-86jweFg^$}nxG*}!i-'
    'tTBk&1BELpA?Kz-'
    'm8f<LE>iPmt(wJ|E92`8FcZoE+=4L}((Lg+j4U^$q}(HY`pV6;~Z_}Uc%XyL7(UNN9o3@Go5dc}ZVF`!or=oJHc#eiNh;QZ(n1A4'
    '`P|C5RV&u(;j#eiNhpjQkytfyBDAQ!EBuNY8zL%CNB=oJJ0`zi*gnPT{+y8H@N0<PGTUNK<TuU8D{6$5(3fcw#U#eiNhpjQm&6$5'
    '(3fL<}6R}APC1A4`PUNN9o4CoaDdc}ZVF`!or=oJHc#eiNhpjQm&6$5(3fL<}6R}APC1A4`PUNN9o4CoaDdc}ZVG2pJ8;9fDHR}A'
    'PC1A4`PUNN9o47fMf^y>NlxrzaQ`!}ji?nw'
)


def ref(identifier):
    return {'module': {'kind': 'self'}, 'id': identifier}


def complete(name):
    roots = {int(key): value for key, value in json.loads(
        (SPEC / 'conformance/execution/candidate' / (name + '.json')).read_text())['sections'].items()}
    roots.setdefault(5, {'payload_revision': 2, 'relocations': [], 'constant_initializers': []})
    roots.setdefault(7, {'payload_revision': 1, 'segments': []})
    roots.setdefault(9, {'payload_revision': 1, 'capabilities': [], 'requirements': [], 'limits': []})
    return roots


def object_roots(contract, captures):
    roots = complete('storage-tls-wrapper')
    roots[3] = complete('portable-identity')[3]
    definitions = roots[1]['types']
    fresh = max(item['id'] for item in definitions) + 1

    def add(record):
        nonlocal fresh
        identifier = fresh
        fresh += 1
        definitions.append({'id': identifier, **record})
        return identifier

    # Retain the observed counterexample's unused support types exactly. Their
    # presence is part of the original byte identity, not extra runtime evidence.
    add({'kind': 'float', 'format': 'binary32'})
    opaque = {}
    for kind in ['exception', 'journal', 'fenv', 'stack_mark', 'va_list']:
        identifier = next((item['id'] for item in definitions if item['kind'] == kind), None)
        opaque[kind] = identifier if identifier is not None else add({'kind': kind})
    void = add({'kind': 'function', 'params': [], 'results': [], 'param_noundef': [],
                'result_noundef': [], 'variadic': False, 'cc': 'portable'})
    add({'kind': 'code_ptr', 'signature': ref(void)})
    pointer = next(item['id'] for item in definitions if item['kind'] == 'data_ptr')
    signature = add({'kind': 'function', 'params': [ref(pointer)] + [ref(execution) for _, _, execution in captures],
        'results': [ref(opaque['journal'])], 'param_noundef': [False] * (1 + len(captures)),
        'result_noundef': [False], 'variadic': False, 'cc': 'portable'})
    roots[10]['journals'] = [{'id': 0, 'signature': 0,
        'params': [{'id': identifier, 'type': ref(nominal)} for identifier, nominal, _ in captures],
        'slots': [{'id': 0, 'type': ref(1), 'offset': 0, 'extent': 4, 'align': 4,
            'parent': None, 'role': 'root', 'count': 1, 'stride': 4, 'count_source': None,
            'constructor': None, 'destructor': None, 'destructor_kind': 'none', 'covers': [],
            'owner': 0, 'dependencies': [], 'child_program': None}], 'normal_order': [0], 'exception_order': [0]}]
    roots[6]['imports'] = [{'kind': 'internal', 'id': 0, 'namespace': 'smir.internal.v1',
        'name': 'journal_begin', 'version': 1,
        'catalog': hashlib.sha256(b'SMIR-HELPERS-V1\0'+json.dumps(json.loads((SPEC/'schema/runtime/helpers-v1.json').read_text()),sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')).hexdigest(),
        'signature': ref(signature), 'abi': {'some': ref(0)}, 'types': [], 'contract': contract,
        'options': {'alignment': 1, 'scope': 'process', 'order': 'none', 'failure_order': 'none',
            'weak': False, 'comparison': 'none', 'mask': '', 'rounding': 'none', 'exceptions': 'none',
            'predicate': 'none', 'target': None, 'flags': []}}]
    return roots


def build_document():
    paths = {name: SPEC / 'schema' / name / 'candidate.json' for name in ['execution', 'runtime', 'abi']}
    codec = CandidateCodec({name: json.loads(path.read_text()) for name, path in paths.items()})
    cases = []

    def add(name, roots, accept, error=None):
        prepare_abi2_nonrecord_source(roots)
        encoded = codec.encode(roots)
        decoded = codec.decode(encoded)
        if len(decoded.roots) != 10:
            raise ValueError('incomplete object')
        cases.append({'name': name, 'accept': accept, 'expected_error': error,
            'sha256': hashlib.sha256(encoded).hexdigest(), 'content_identity': decoded.content_digest,
            'encoded_hex': encoded.hex()})

    originals = {'construction': '38edec678751efe3e0aebc7da5a628bfd412756d0ed59b0564cdc921bde88da0',
                 'resume': '8aa7d7dec82a5c3a751d0f4b6e55b308ee072e2d40f8d7bf1f33053e09285365'}
    for contract in ['construction', 'resume']:
        for name, captures in [('zero', []), ('one', [(17, 1, 1)]),
                               ('multiple', [(19, 1, 1), (3, 1, 1), (57, 1, 1)]),
                               ('mixed-order', [(20, 1, 1), (4, 4, 4)])]:
            roots = object_roots(contract, captures)
            add(contract + '-' + name, roots, True)

    base = object_roots('construction', [(17, 1, 1)])
    signature_id = base[6]['imports'][0]['signature']['id']
    for name, mutation, error in [
        ('wrong-capture-arity', 0, 'runtime_helper_contract: RT_HELPER_ARITY'),
        ('wrong-capture-type', 1, 'runtime_helper_contract: RT_HELPER_TYPE'),
        ('wrong-capture-noundef', 2, 'runtime_helper_contract: RT_HELPER_NOUNDEF'),
        ('missing-journal-association', 3, 'journal_capture_program'),
        ('wrong-journal-namespace', 4, 'journal_capture_program'),
        ('missing-journal', 5, 'helper_namespace_reference'),
    ]:
        roots = deepcopy(base)
        signature = next(item for item in roots[1]['types'] if item['id'] == signature_id)
        if mutation == 0:
            signature['params'].pop()
            signature['param_noundef'].pop()
        elif mutation == 1:
            signature['params'][1] = ref(5)
        elif mutation == 2:
            signature['param_noundef'][1] = True
        elif mutation == 3:
            roots[6]['imports'][0]['abi'] = None
        elif mutation == 4:
            roots[6]['imports'][0]['abi'] = {'some': {'module': {'kind': 'dependency', 'slot': 99}, 'id': 0}}
        else:
            roots[6]['imports'][0]['abi'] = {'some': ref(99)}
        add(name, roots, False, error)
    roots = deepcopy(base)
    roots[10]['journals'][0]['id'] = 8123
    roots[10]['journals'][0]['slots'][0]['id'] = 91
    roots[10]['journals'][0]['params'][0]['id'] = 10007
    roots[10]['journals'][0]['normal_order'] = [91]
    roots[10]['journals'][0]['exception_order'] = [91]
    roots[6]['imports'][0]['abi'] = {'some': ref(8123)}
    # Rename execution Int32 ID1 while preserving layout/type-reference namespaces.
    next(item for item in roots[1]['types'] if item['id'] == 1)['id'] = 70001

    def rename(value):
        if isinstance(value, dict):
            if set(value) == {'module', 'id'} and value['module'] == {'kind': 'self'} and value['id'] == 1:
                value['id'] = 70001
            for child in value.values():
                rename(child)
        elif isinstance(value, list):
            for child in value:
                rename(child)

    rename(roots[1]['types'])
    for layout in roots[1]['memory_layouts']:
        if layout['type'] == ref(1):
            layout['type'] = ref(70001)
    for nominal in roots[10]['types']:
        if nominal['execution'] == {'some': ref(1)}:
            nominal['execution'] = {'some': ref(70001)}
    roots[1]['types'].sort(key=lambda item: item['id'])
    add('alpha-journal-slot-formal-execution-ids', roots, True)
    roots = object_roots('construction', [])
    signature_id = roots[6]['imports'][0]['signature']['id']
    signature = next(item for item in roots[1]['types'] if item['id'] == signature_id)
    signature.update(params=[ref(5), ref(5)], results=[ref(4)],
                     param_noundef=[False, False], result_noundef=[False])
    roots[6]['imports'][0].update(name='stack_alloc', abi=None, contract='default')
    add('noncapture-control', roots, True)
    inputs = [ROOT / 'tools/smir-format/codec.py',
              ROOT / 'tools/smir-runtime-contract/generate_service_type_fixtures.py',
              *[ROOT / 'tools/smir-abi' / name for name in ('nominal.py','layout.py','graph_identity.py')], *paths.values(),
              SPEC / 'schema/runtime/helpers-v1.json',
              SPEC / 'conformance/execution/candidate/portable-identity.json',
              SPEC / 'conformance/execution/candidate/storage-tls-wrapper.json']
    return {'revision': 1, 'proposal': 'INT031REV1',
        'scope': 'Complete source objects with explicit memory reference grant; no capture values, journal/cleanup/provider/native execution',
        'provenance': {'generator': str(Path(__file__).resolve().relative_to(ROOT)),
            'generator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'input_sha256': {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(inputs)},
            'command': 'python3 -B tools/smir-runtime-contract/generate_journal_capture_fixtures.py',
            'check_command': 'python3 -B tools/smir-runtime-contract/generate_journal_capture_fixtures.py --check',
            'original_counter_sha256': originals,
            'encoded_object_bytes': sum(len(bytes.fromhex(case['encoded_hex'])) for case in cases),
            'size_justification': '16 independent full ten-root objects carry regenerated ABI2 equivalents with separate exact legacy ABI1 revision rejections, zero/one/multiple/mixed source formal order, namespace and signature rejection. Hex retains byte-exact framing/source identity; durable generator/input hashes and --check allow replay.'},
        'legacy_cases': json.loads(zlib.decompress(base64.b85decode(LEGACY_COUNTERS_B85)).decode()),
        'cases': cases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    encoded = (json.dumps(build_document(), indent=2) + '\n').encode()
    if args.check:
        if OUTPUT.read_bytes() != encoded:
            raise SystemExit('stale journal capture fixtures')
    else:
        OUTPUT.write_bytes(encoded)
    print(('checked' if args.check else 'generated') + ' ' + str(OUTPUT.relative_to(ROOT))
          + ' bytes=' + str(len(encoded)) + ' sha256=' + hashlib.sha256(encoded).hexdigest())


if __name__ == '__main__':
    main()
