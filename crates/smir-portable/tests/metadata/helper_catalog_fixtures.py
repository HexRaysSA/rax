"""All 177 helper names / 368 contracts: actual type-signature witnesses.

This generator supplies real declared execution types and actual trivial source
metadata. It does not claim unresolved bridge/recipe/value-layout prerequisites
or emit a whole-metadata admission certificate. Each record states its scope.
"""
from fixture_provenance import provenance, write_bytes, write_text
from pathlib import Path
from copy import deepcopy
import json,hashlib,sys,base64,zlib
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
from profile_fixtures import complete
from fixtures import prepare_declared_abi2_source, CandidateCodec,SCHEMAS,SPEC,ref,some

# Exact historical ABI1 flag objects: revision rejection ONLY.
LEGACY_FLAG_B85 = (
    'c-rk-'
    '*^=e94gHsX_5=52erAfI$T(GwT@}wmQZD~{0BX5fNJ{EEv9sXXJ>8e04oLt6Kndr!kMQl6zx_3S%|C^|e2qV)@b`}|zkLk<{FZ+G'
    '_~MvXKYXO0<1b?xzy6s1@$uzDOEoI51shr5fdz&i0Y99v^>6%4SC~&cv&~1c{U^_#wSjN2COE$BFAUQ=0I~0{95cJ|<T|6*1UCI$'
    '`TzCN=`caH@1G9+hj8ex_x<6r-'
    '@%QC{$}4lANmje(BJO+538hSxZ`}>NuI;$`u5`w{oTGlw}<}WApZltPF(H!&wa&mk2KyStJZdQXcvchN-GSvb}^(C+!+P!@T0S3R'
    '#~xL3dUM(w3Sxry!2Y}^(Bt!;&^CrM#8_)8!)p;%pT_I4y#|<{c&ycoMs&=e!v+{b2TudWaK(>+)J4$3o|p(7|t)Rysq)hU(Pa<t'
    '-!S!0sVDl)bX(QU)Z|Yvfsh`QQ56g(`Lur9re8GULSEoW_mOG<-'
    'fM<W(^;m<=WoZ1<Op@R?21H+9wNI_M%&cIOFIpj=}G+B8_^8uBG=%3vbzM^eriGWP7}#PBzQB)-'
    '%gd#JShfSHrqQk&Ty2>uVIx4q~s|#hZ7z(_IFxXOyHA^IZ<+2Qw>pUP@@UCcxY^phK&P5Wi-'
    '8xEthVja+<XKwUr|X$H{Hh!|#&dcJBcnskN{J@%7k9q}N4Y4;Jf^QrAhY0x_KVn5Oy<+0+QNA~j-'
    '(bR8k#~uAfe}>2SdA3MZiTJhl_UCM$vS9<N(cb=?WfP9(e!%p%vE>na-'
    'O+dFEv_u4DSdUw2d;o$ceX#O>4$hjWBj(PPSJt+?}lxT*e_qyvb3fpp1r55WRP`TxQ6!bTdO;*Wbu!#u@d*jN;WtnWXeIh0DeO2('
    'G6LQHja|%!Kq<LHrV939)tn^H0CUomO5rgwW8H7K{h%|rDSv5jNnI#f16u9`Z$ar;7yhFC*2zGX97HTiHqQxVIqPH;jB<Wac7(lK'
    '^bUtc9dg+P%sQGz+EGFD{xmnsD!D%fN4exYe2sZ<H2me^C$F{MmO#KpxMJ3=A2Mx4FWo@#P~{PCDCaE*c|Q4=+IE^1Xm2bBdqeJp'
    'IFgZt?i|=^O&{$%{#ufyH;aMq!k!JAu<{KjoA#ya>-'
    ';MZr)wrx*K^VdX&}`b<=jCtF4o(uO(I20`YCiWuUkC<a&5zJ*v8%O)h)k*|+hezMk1%0&cW&rxiK1eOH|<n9nqFKi2bReCk_%<E~'
    'SF<6-'
    'e21&|#F3qWn?8!^SeJsRX!^2hG}5gmVPDs8;8s&kZ5$5``F_KV&zH`Yc~M|YJrRcR9qi{;JO^R)eH_C5PK@3pH@<Lk@@wgLASolC'
    'Iw+D>@azTL~)Oed0)BbIRX@DRn)v8TY(3g^7c7EdVNz`if1Ah2opOQK)EbISq-lg~UcI|MDX30}J>Y>s10dSF~;1~ERt=~Ii5jXc'
    'Sut<P{ok|1U2o!j^a-'
    '}MiBJuTklbbZ=`<>?N}*CLWdxl8m?yU2Ww(yx}<Ur+tZzh{5C@3cS9eyE&HOLUjj^|jV(z)m#$;3>|x<@0WaCEW6S7?U0NfwQ;tv'
    'aG6ngFFecB`(1_q=N5uYLU3(pjB$PvFu%F!Fw@ja&XGd;H@#U!Cf%fyDz6v*d1VHV76%eWtU7(Ryh7^F~fZMYq@4@Sz@jPadf+{x'
    'Gv8gTsht2crebC9h9sQpUxy}i*A&jy&qqm9Y*DqP*OYX6o<dO&PuCP{*FrHH@E`%v1VF9-'
    '>i~`G}_=U=Vk!QU7kh36=83q8kMzBpa(D)4_9FSE2VwuGeQeU3P$CSmaE-'
    'pavcqX{b0NV|CTYJ9a~gs#c$L2{(5!%_GnrvxB}|~(Dv+~-~kXXGi=MAeFhD_!8J$`PzERy(OkW|jjxm|Yv%yio-gm<xuW@Edqq>'
    'C;Ku`YhF(nh=8XOI2*s-Vh<lx-8<<6!=s|AGcaPqgvDR7^o0ZUaM4TdR977!T$W{i!4a5kNHGp~F7Q`79S2xSywX5_&|BKUh-TNo'
    'sFwG73B`^C^tFbwsa2s#(EkfZQg)2SpvOFDcpiZ6&RtUP_h+adQeD?A*zK&F+UiRd)gE}+n${low_8=!ewnLfs8qCDk5ny~-'
    '?q0kg$_FHlvak3Zvpxs0n89Gi$x;=0H^&{uJd-'
    'I#LC|&ObO=$hVI7~2O1JRLyq~1@MHkPlZI2gKiC@@9huPa6wX($=Z(xqtQ=w16-%E^~MjD=YfRo1-Wsj-iS<3z`QTb@o*B;=2sxb'
    'hz{j<7(aW9hILb{Hj%iFFl&b{cyZXx;NK{8m#l%b&P`Roa}?#choO!Z_Xs%Z2b%PTQK&CzGl2Y9?GGI#b}-'
    'Pe?ujtE7&{*;NeVn%(%(`=NQ);i^pV`as&g)HZ-'
    '#@v>?LrTcwA4l)h#e6T9QC;k@#PV4DPPyKhrRgC(&WDCB+NU!iQPmIFjfeYm(KJT&S2l!J;7d$Tm^GBPSR$A%5v=ZkUvY6K-'
    ')$ar^1>K(dS?=LA8E=%^f3!Bc6`sDckxZxr^Ule^6u=_`|GzbZ+Z7r(?j~qDXEWl!^6AVXt(_Q-jD3@K9{lg>}N&XYSvA2oRCY-f'
    'pYC+kz&nF*WJZ5+hn%romNjZ`Dc_Z?y%XzMreoKq;V(s^5&-'
    'c{Aclq&5_Xl^>o^p)>krp4!`x}i{K2>!}k~X?UO{~i86SC;Q{9PG||Fc<5v^+e4aRB?avfrAFo7MSIv|c$+l&1VIhZ;MiWPf7S8o'
    '~W6cTB8sb^9%kzUzVteposc2FQ(?C)sqP#qUDc`Y&FL^yiqg-ri%F6lXEb^IM(aB}5q|vn6K4zNoPHsAP%f{)bZ9VP+t#vkfz9-'
    'lGr+YGL<LWEiQ(o2H-@cF4Ib%KFhYRLDMzwLm1DqvSn6u!{iu0#X4|#BB*6B0&`wX@-`}isJHKXkyU(fsc-'
    '1m8#*q{2^zWHKLp^u;Jwd55XolNlp{FeV~OXq6b{#o<6wfO1jn#NpeISowNhAlb4{QL{o(V2D2LoVMoPf;&@MO%k2wDP`U`u>TWV'
    '#O(0C)&cb|56Ps)Gb<r)KfM(TW`m*SRDy|P>-?XeVE}4lZCDQO1v#+Ifc6K#?ayE7*kFFebMLikn?k7t;+A7-'
    '&x8m8lL#OoNSvKSu1glZ(C(~SBX}EZwWoV^)7E7<@$U#S(U9%47Q?k+~O0xFmfl7fWF))D|v!Bk1-'
    'DxPFH+Ta>%B<s}C+pm+blmczP>Y-tQlaPPX&Xn@XVi8|}k;(Yfk)t}7~)F|pJPd5f}`-'
    'h@i5ow1(f)0O$%YpJgBmo;@QiP@#VWm}I0Mv+1U_3$xE5Ri;Mk20#k4{!(@{onx!WC^AothXhPL7suP!DTzYleUK%uk*xsvzECnO'
    '?7(r|3^qOo@(GrWnopKOReRRAK<h!VhDqQGk_L3SomAVXmAS(rUX9W5kbKDRHq=*ka-BB<<5B~V|ERu%$-'
    'W>ww%w^I^N3p?FgUiuXME@a$8w*lzW>Q^KR|>)A|nec8&0zdcp1tJ6d=#ve3W8QlZ0JnicG(j2_lZoeJpmwgy<2cVwl0NSAr1wH_'
    'vKDm{9ueARpHaADW@sea_oTItTm+~97ky1%6_#co>I!&Rtv^d)bs(mvJKAGOj$Ot`LFZF{|TE#0|p&13B<Rw`jd*HW*1!?%K;$9l'
    'rKmj23yd$I8Br7H}k>lXgzN4)uwZ+_I9pSRfzPis%_Ucat)ZO6T-'
    '#ynT5KI^gZx^lB!+c<wde)#zHM@Ur6$Cr;_qSt{N6l`#2)J|JF3O6{f!jN<tvln3)V${RnlNkkM^`kL5!c~#%$L~MvxclGIuiyT|'
    'sr!=ksr#Ber0%<i)P47my6+xR_YeJt8u5y#`$XNZA4rJ0Pt<*)?h|$Yf0w#{vV~Qr`!i<G8i>x{{t%s?==}f9bpEBlgMs0?z($N*'
    'Lsm?3h+`4XommR0WVSI!FGWJX8U!1>65fw_P~5_iMG=*ssQg6bKdpzT{CBCgMCGqhg^9{fRDRZ?@-'
    'Kwu|7#*YQTK_uPt<*)?h|#NsQX0SC+dC=hp78R-'
    '6!fkQTK_uPt<*)?h|#NsQX0SC+a>?_ldes)P17v6Lp`c`$XL*>ON8TiMmhJ{iU9qsQX0S|Kp@d)P17v-'
    '>a1(>VB)Hov8cWO7FWLqV5xQpQ!sp-CythQ>puTR7wbzRLpS*YUCWO4r}3s%PI_GvSDNzQgJP#jVz9kLZ;vq3rW}^yBc-'
    '>YxsHm`fJ)z_&F2rQux7Z6NP^Z_mILLS%sFfrSQ9l6n^)N!Y|oF3cn)?KT-IJ!q14pUk|cG;U@||QTS`vMByh2|2{9=?<1n{KcMi'
    'Zk&SuaDp)R}f}`f(nI49bTR0vKqlW}E;b}^xsG&!25h7?%aIDMP+Te-8PZWNl@SoO06n=KovlE5CMj0jwKT-JI6@|a71L?=PkmQN'
    'dU(YCs(!c3PlzyW06Q%z-'
    '8d3U*(od9rqVyA`pD6uA=_g7*QTmC}Pn3S5^b@6@DE&m~CrUq2`ias{lzyW06Q!Rh{Y2>}N<UHhiPBG$exmdfrJpGMkLrVo(od9r'
    'qVyA`pD6uA>3>>#diVN&F{Pi62@7IX&<>6W)<bqvazp8O&JG-rcX1Rkn+Wy;`$2gSI;4wI^MG08$M3)Y3v(NDKL'
)

DEFAULT={'alignment':1,'scope':'process','order':'none','failure_order':'none','weak':False,
 'comparison':'none','mask':'','rounding':'none','exceptions':'none','predicate':'none','target':None,'flags':[]}

def main():
    catalog_path=SPEC/'schema/runtime/helpers-v1.json';catalog=json.loads(catalog_path.read_text())
    codec=CandidateCodec(SCHEMAS);folder=HERE/'helper-catalog-fixtures';folder.mkdir(exist_ok=True);manifest={}
    for spec in catalog['records']:
      for contract in spec['contracts']:
        roots=complete('storage-tls-wrapper');roots[6]['imports']=[]
        roots[3]=complete('portable-identity')[3]  # independent identity body; every helper is deliberately unused
        types=roots[1]['types'];fresh=max(t['id'] for t in types)+1
        def add(record):
            nonlocal fresh
            identifier=fresh;fresh+=1;record.update(id=identifier);types.append(record);return identifier
        integer={t['bits']:t['id'] for t in types if t['kind']=='int'}
        data_ptr=next(t['id'] for t in types if t['kind']=='data_ptr')
        f32=add({'kind':'float','format':'binary32'})
        opaque={kind:next((t['id'] for t in types if t['kind']==kind),None) for kind in ('exception','journal','fenv','stack_mark','va_list')}
        for kind,identifier in opaque.items():
            if identifier is None:opaque[kind]=add({'kind':kind})
        void=add({'kind':'function','params':[],'results':[],'param_noundef':[],'result_noundef':[],'variadic':False,'cc':'portable'})
        code_ptr=add({'kind':'code_ptr','signature':ref(void)})
        binding=[]
        for constraint in spec['type_parameters']:
            if constraint in ('integer','integer_value','storage_value'):binding.append(integer[32])
            elif constraint in ('float','floating_value'):binding.append(f32)
            elif constraint=='pointer':binding.append(data_ptr)
            else:raise RuntimeError(('unknown constraint',constraint))
        def formal(template):
            if template=='journal_captures':return []
            if template.startswith('type'):return [ref(binding[int(template[4:])])]
            if template[0] in 'iu' and template[1:].isdigit():return [ref(integer[int(template[1:])])]
            if template=='data_ptr':return [ref(data_ptr)]
            if template=='code_ptr':return [ref(code_ptr)]
            if template in opaque:return [ref(opaque[template])]
            raise RuntimeError(('unknown formal',template))
        signature=add({'kind':'function','params':[x for f in spec['params'] for x in formal(f['type'])],
          'results':[x for f in spec['results'] for x in formal(f['type'])],
          'param_noundef':[f['noundef'] for f in spec['params'] for _ in formal(f['type'])],
          'result_noundef':[f['noundef'] for f in spec['results'] for _ in formal(f['type'])],
          'variadic':False,'cc':'portable'})
        roots[10]['journals']=[{'id':0,'signature':0,'params':[],'slots':[{'id':0,'type':ref(1),
          'offset':0,'extent':4,'align':4,'parent':None,'role':'root','count':1,'stride':4,
          'count_source':None,'constructor':None,'destructor':None,'destructor_kind':'none',
          'covers':[],'owner':0,'dependencies':[],'child_program':None}], 'normal_order':[0],'exception_order':[0]}]
        options=deepcopy(DEFAULT);policy=spec['policy'];name=spec['name'];namespace=spec['abi_namespace'][contract]
        abi=None;binding_prerequisite='real source ABI association available'
        if namespace=='storage_binding':abi=some(ref(1))
        elif namespace in ('nominal','signature','journal'):abi=some(ref(1 if namespace=='nominal' else 0))
        elif namespace=='bridge':abi=some(ref(0));binding_prerequisite='bridge metadata absent: TYPE PHASE ONLY, full binding is not a positive'
        elif namespace not in ('none','optional_storage_binding'):raise RuntimeError(namespace)
        if name.startswith('atomic_flag_'):
            binding_prerequisite='KNOWN INVALID nominal Int32 for atomic_flag: TYPE/OPTION PHASE ONLY; actual atomic_flag1B metadata required'
        elif namespace=='nominal':
            binding_prerequisite='Nominal source role requires separate semantic audit: TYPE/OPTION PHASE ONLY; existence is not source-kind proof'
        target=spec['target_namespace'][contract]
        if target=='storage_layout':
            first=binding[0]
            if first==integer[32]:layout=0
            elif first==data_ptr:layout=7
            elif first==f32:
                layout=max(l['id'] for l in roots[1]['memory_layouts'])+1
                roots[1]['memory_layouts'].append({'id':layout,'type':ref(f32),'size':4,'alignment':4,'access_bytes':4,'fields':[],'element':None,'stride':0})
                if namespace=='storage_binding':binding_prerequisite='float source value binding not supplied: TYPE/OPTION PHASE ONLY'
            else:raise RuntimeError(first)
            options['target']=some(ref(layout));options['alignment']=8 if first==data_ptr else 4
        elif target=='tls':options['target']=some(ref(0))
        elif target=='recipe':
            options['target']=some({'module':{'kind':'dependency','slot':7},'id':99})
            roots[2]['manifest']['dependencies']=[{'slot':7,'key':{'namespace':'catalog','name':'recipe','abi_major':1,'abi_minor':0},
                'minimum_minor':0,'maximum_minor':None,'site':roots[10]['identity'],'declarations':[{'id':99,'kind':'recipe','symbol_kind':'none',
                'source_linkage':'none','namespace':'catalog','name':'cleanup','execution':None,'nominal':None,'abi_signature':None,'weak':False}]}]
            binding_prerequisite='DEP recipe provider absent: static local expectation only, no bound provider'
        elif target!='none':raise RuntimeError(target)
        if policy in ('atomic','atomic_flag') and name!='atomic_is_lock_free':options['order']='seq_cst'
        if name=='atomic_cmpxchg':options['failure_order']='acquire'
        if policy=='atomic' and target=='storage_layout':options['comparison']=contract if contract in ('full_storage','value_mask','llvm_precision') else 'none'
        if policy in ('fp','libm') or (policy=='atomic' and spec['type_parameters']==['float']):
            options.update(rounding='dynamic',exceptions='strict')
            if name=='fp_compare':options['predicate']='oeq'
            if name in ('fp_lround','fp_llround'):options['rounding']='nearest_away'
        roots[6]['imports']=[{'kind':'internal','id':0,'namespace':spec['namespace'],'name':name,'version':1,
          'catalog':'56cf1e07ba5256a958c27fcdce5b013f09a3e27552d0d1e3e579f33035643988',
          'signature':ref(signature),'abi':abi,'types':[ref(i) for i in binding],'contract':contract,'options':options}]
        prepare_declared_abi2_source(roots)
        label=name+'--'+contract;data=codec.encode(roots);codec.decode(data);write_bytes(folder/(label+'.smo'), data)
        manifest[label]={'name':name,'contract':contract,'policy':policy,'sha256':hashlib.sha256(data).hexdigest(),
          'bytes':len(data),'type_signature_expected':True,'full_binding_prerequisite':binding_prerequisite}
    write_text(folder/'manifest.json', json.dumps({'scope':__doc__,'catalog_sha256':hashlib.sha256(catalog_path.read_bytes()).hexdigest(),'provenance':provenance(__file__, ['crates/smir-portable/tests/metadata/fixtures.py', 'crates/smir-portable/tests/metadata/profile_fixtures.py', 'docs/specifications/smir/portable/conformance/execution/candidate/storage-tls-wrapper.json', 'docs/specifications/smir/portable/conformance/execution/candidate/portable-identity.json', 'docs/specifications/smir/portable/schema/runtime/helpers-v1.json'], manifest),'cases':manifest},indent=2)+'\n')
    legacy=json.loads(zlib.decompress(base64.b85decode(LEGACY_FLAG_B85)).decode())
    oldfolder=HERE/'legacy-abi1';oldfolder.mkdir(exist_ok=True)
    for name,case in legacy.items():
        data=bytes.fromhex(case.pop('encoded_hex'))
        if hashlib.sha256(data).hexdigest()!=case['sha256']:raise RuntimeError('legacy flag checksum')
        write_bytes(oldfolder/(name+'.smo'), data)
    write_text(oldfolder/'manifest.json',json.dumps({'scope':'ABI1 rawrevision rejection only; not source-kind semantic evidence', 'cases':legacy},indent=2)+'\n')
    print('helper names',len(catalog['records']),'contract signatures',len(manifest))
if __name__=='__main__':main()
