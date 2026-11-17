#!/usr/bin/env python3
"""Deterministic owned candidate fixture generation; no cross-role outputs."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
from check_candidate import CORPUS
from runtime_candidate.wire import encode


def roots():
    return {2:{'payload_revision':2,'manifest':{'identity':'0'*64,'key':{
        'namespace':'test','name':'fixture','abi_major':1,'abi_minor':1},'kind':'object','entry':None,
        'site':'a'*64,'personality':'linux','foreign_isa':'none','dependencies':[],'exports':[]},
        'symbols':[],'comdats':[],'initializers':[],'finalizers':[]},
        4:{'payload_revision':1,'segments':[]},5:{'payload_revision':2,'relocations':[],'constant_initializers':[]},
        6:{'payload_revision':1,'imports':[]},7:{'payload_revision':1,'segments':[]},
        9:{'payload_revision':1,'capabilities':[],'requirements':[],'limits':[]}}


def build():
    cases={}
    def case(name,surface,document,code=None):
        cases[name]={'surface':surface,'accept':code is None,'code':code,'document':document}
    names={2:'runtime_symbols',4:'runtime_data',5:'runtime_relocations',6:'runtime_imports',
           7:'runtime_tls',9:'runtime_capabilities'}
    for number,value in roots().items():
        name=names[number];raw=encode(name,value)
        case(name+'-roundtrip','wire',{'record':name,'value':value})
        case(name+'-truncated','wire',{'record':name,'encoded':raw[:-1].hex()},'RT_WIRE')
        case(name+'-trailing','wire',{'record':name,'encoded':(raw+b'\0').hex()},'RT_WIRE')
        bad=copy.deepcopy(value);bad['extra']=0
        case(name+'-extra','wire',{'record':name,'value':bad},'RT_WIRE')
    case('roots-minimal-object','runtime_roots',{'site':'a'*64,'grants':[],'roots':roots()})
    for name,edit,code in [
        ('image-no-entry',lambda r:r[2]['manifest'].update(kind='image'),'RT_IMAGE_ENTRY'),
        ('object-entry',lambda r:r[2]['manifest'].update(entry={'some':{'module':{'kind':'self'},'id':0}}),'RT_IMAGE_ENTRY'),
        ('ungranted',lambda r:r[9].update(capabilities=['file']),'RT_CAPABILITY_GRANT'),
        ('unknown-cap',lambda r:r[9].update(capabilities=['arbitrary']),'RT_CAPABILITIES'),
        ('personality',lambda r:r[2]['manifest'].update(personality='host'),'RT_PERSONALITY'),
        ('wrong-site',lambda r:r[2]['manifest'].update(site='b'*64),'RT_SITE_IDENTITY')]:
        value=roots();edit(value);case(name,'runtime_roots',{'site':'a'*64,'grants':[],'roots':value},code)
    for word in [0,63,0x400,0x83f,0xc3f]:case(f'fenv-{word:x}','fenv',{'word':word})
    for word in [-1,64,0x1000,2**64]:case(f'fenv-invalid-{word}','fenv',{'word':word},'RT_FENV_WORD')
    registered=[['feature','threads',1]]
    for name,entries,code in [
        ('exact',[{'kind':'feature','name':'threads','version':1}],None),
        ('unsupported',[{'kind':'feature','name':'threads','version':2}],'RT_REQUIREMENT_UNSUPPORTED'),
        ('unknown-kind',[{'kind':'anything','name':'threads','version':1}],'RT_REQUIREMENT_KIND'),
        ('zero-version',[{'kind':'feature','name':'threads','version':0}],'RT_REQUIREMENT_VALUE')]:
        case('requirement-'+name,'requirements',{'registered':registered,'requirements':entries},code)
    case('startup-empty','startup',{'name':'p','arguments':[],'environment':[],'base':65536})
    case('startup-unicode','startup',{'name':'p','arguments':['\u03bb',''],'environment':[{'name':'X','value':'a'}],'base':65536})
    case('startup-nul','startup',{'name':'p','arguments':['\0'],'environment':[],'base':65536},'RT_STARTUP_TEXT')
    case('startup-onepast','startup',{'name':'p','arguments':[],'environment':[],'base':2**64-2},'RT_STARTUP_RESOURCE')
    for domain in ['linux','darwin','win32','ntstatus']:
        case('errno-'+domain,'errno',{'domain':domain,'native':0})
    case('errno-unknown-native','errno',{'domain':'win32','native':2**31-1})
    case('errno-unknown-portable','errno',{'domain':'linux','status':999999},'RT_ERROR_STATUS')
    case('time-boundary','structure',{'name':'time16','bytes':struct.pack('<qII',-1,999999999,0).hex()})
    case('time-nanosecond-reject','structure',{'name':'time16','bytes':struct.pack('<qII',0,1000000000,0).hex()},'RT_SERVICE_NANOSECONDS')
    case('time-reserved-reject','structure',{'name':'time16','bytes':struct.pack('<qII',0,0,1).hex()},'RT_SERVICE_RESERVED')
    case('dir-empty-reject','structure',{'name':'dir_entry','bytes':struct.pack('<IIII',1,1,0,0).hex()},'RT_SERVICE_TEXT')
    def member(label,body='01'):
        return {'symbol':label,'abi':'a'*64,'kind':'function','extent':len(bytes.fromhex(body)),
                'body':body,'extent_policy':'fixed'}
    def group(policy,ordinal,members):
        return {'key':'g','selection':policy,'key_symbol':'a','members':members,'input_ordinal':ordinal}
    for policy in ['any','exactmatch','largest','samesize','noduplicates','nodeduplicate']:
        case('comdat-'+policy,'comdat',[group(policy,0,[member('a')])])
    for policy in ['any','largest','samesize']:
        case('comdat-unequal-'+policy,'comdat',[group(policy,0,[member('a')]),group(policy,1,[member('a'),member('b')])])
    case('comdat-exact-members-reject','comdat',[group('exactmatch',0,[member('a')]),
        group('exactmatch',1,[member('a'),member('b')])],'RT_COMDAT_EXACTMATCH')
    case('comdat-union-abi-reject','comdat',[group('any',0,[member('a')]),group('any',1,[member('a'),member('b')]),
        group('any',2,[member('a'),{**member('b'),'abi':'b'*64}])],'RT_COMDAT_ABI')
    ref={'module':{'kind':'self'},'id':7}
    initializer={'id':0,'source_kind':'data','source':9,'offset':1,'layout':ref,'function':ref,'association':None}
    case('constant-initializer-record','wire',{'record':'runtime_constant_initializer','value':initializer})
    for key in initializer:
        bad={k:v for k,v in initializer.items() if k!=key}
        case('constant-missing-'+key,'wire',{'record':'runtime_constant_initializer','value':bad},'RT_WIRE')
    for name,step,code in [
        ('allzero',{'offset':0,'check_base':False,'flags':[],'inrange':None},None),
        ('strict-netzero',{'offset':0,'check_base':True,'flags':['inbounds'],'inrange':None},None),
        ('strict-no-inbounds',{'offset':0,'check_base':True,'flags':[],'inrange':None},'RT_PATCH_CHECK_BASE'),
        ('unknown-flag',{'offset':0,'check_base':False,'flags':['unknown'],'inrange':None},'RT_PATCH_FLAGS'),
        ('range-inverted',{'offset':0,'check_base':False,'flags':[],
                           'inrange':{'some':{'lower':1,'upper':0}}},'RT_PATCH_INRANGE_BOUNDS')]:
        case('gep-step-'+name,'relocation_step',step,code)
    for kind,key in [('object','certificate'),('partial','builder')]:
        seed={'kind':kind,key:1,'revision':1}
        case('journal-seed-'+kind,'wire',{'record':'runtime_journal_seed','value':seed})
        case('journal-seed-'+kind+'-old-missing-kind','wire',
             {'record':'runtime_journal_seed','value':{key:1,'revision':1}},'RT_WIRE')
    return cases



# Archived, explicit ABI1 non-record producer declarations; not an input decoder.
# Exact original bundle/object hashes are retained for historical traceability.
_ABI2_JOINT_SOURCE_B85 = (
    'c-rmVYf~FXx(D#DqT;m`_x+N*BA9HbgTV)IcC%Y4RbR0ZA#o%@;!XLxpY9pm00|H{8!!30QZY!Ho}RwVGn(h;`F$shE-psH?&RZz'
    '9}T+GkC&+%M;ER?-'
    '1++Voj3|t7il=HKL<BSlbx^s_4|$sAzhZ&rsJ#hYA5}6nZh*1UK)=_<DIXESA)T;ok2Qx;bYJFKJ86DI40H3*E=ES#C;ahOGyIfn'
    'mVl<_fcf#B5|A&>nvd^NTYM6j$}u(N`^ZvGPOIec82aE)sos;Ukz)8W7mJ2rb+j5H0e+K*QtDLGP)Xv)EkdR(@Cv7t^d177o+jV-'
    'oSkvT}_vVGMV(6?RUNwuXfy^e?Dvvx%`#}sr|V<sN7G3SU3FX)lNU|d`-'
    '%Z`u|SNM<>&9Kc?ojTBo|d`VsnS=VBDE2F(k<^oQl8ok<$xoll=Wy}G@Bv*rHjeE(+S{`ofhw>S209^5~h@1Ls84M6^o7WjR~_ou'
    'y4&XY84_E~@ZwI8P+nnKz>p4UNauEMLGYd5$`z4BuEtrS$Nv|2J}H;S&m-'
    'YlCux@`Js)@=OYZewJtW}`QnjXv0MV$pG%YjDs0ODUJ`<6z`sZ=A0Clm2Mf6jirhbk3x0t=Tx8mC!GBnl*9T+p}G*eOrk|d(GY-y'
    'I-64XU8ymHM*(mT~5b!-e0;<*N5|~G@1758*9pwclK9bRa=x-Kd%>`Prudmur|VSUuD5-'
    'cV_NX{>HJ}4R0&?YB7E8Z5&GPln_Gs<#IHhIzOn3Ve_$NBj>AOXlh$~aqKR7!_ie4p}BNiUD1D<z1((Wv#s7d7Rsl`X>v7~-'
    'Yunl{n5o-yK&#eeyMwQgGt(WApEfh@@oCjuzQx|R}X(=-2vY?*ewo4Y;`EN{`c9B?A62Fv_&cAPZ~3~Rvxus`Yb-'
    '6ADUlg?P@{o6P6z`Tkpu)1&z@yid;DnKCoK9dN2@~pUug#Uge~4722Z>rH^h!1HaFguFYq@w!q~Px$)S2-'
    '1+oVd5bmC<mjRt%WS^n{;-_B{+-72Q`E4;aW`JMaKnBs4bTLo=`xj3GYtJSd$&|-'
    '{BeG+EAeQVX7iFq<5bRzz5c|NN(@KCcJ7r8`qPhf-dXK4)yX>Vy;F)&D?O1Zn`}koMp#Zu@M(n4PQ+*^NjzIis3n1hNK0wIq>r^$'
    'CDQF(xSwkTT+hb!xBjsHMixQqV!!Px^PWw=xr@uvik}vZHS#}~kh-n~r2$5@ZJNps`opW=>X7J9>vqmK$|z$-GvNd^%2?-'
    'wDlZxxc}!9%?@c+V9J6Lj3+qJ6gjiONH)vXSxb`&OUJJ|u<Z>XB(t>V!HBR#;z8P!yQtAHid=ZtG8n(SV|9F|<O^=S6Yl_L}q8Tw'
    'aBhA^7FG`pNNOdTs-%_}mZ@m~-'
    'n}=Rm3I^VVU*@}?MQJNjYk3{f`=^=rN`FJQlvhU=b%4&xYpXW<xxLOPJ@bn@Ps<@zThsSv{Z@|Ol~t`B{k&FrzTB^E<7E>)5MP$k'
    '{9qJ*SuO+R!=uaD(7*i9pZzpV<BPiW=(4UjsqCe;a1)!>PmrIQC15s*N)c%iTnz+wF2|!wckZV16ILC{qu#89cFDbS61pA!>-'
    '*!#8^=8lRJIH}OFM}A;q`+#o!3FuG)4KKY!{#5Wa@^~-'
    'ra>}Z5iWKn%T`etQMo1>Rzm@H0$f7A6qYTdsu8N(zX}lm#!IKi#2f2zvxfzKZyUk>W|avPAREn`4a!1&x<LC89vN^X}<_q4APqsO'
    'dYi=E9tXWqcWJU`h(ir{F#5+1?aLrNM-rmq0juY9Q*A_WTgoPeLr?}((H(5{<*W(uk2-'
    '9&cFR;wPMfwv(ujHKWCr)To%Am>G>dB{c5GI@6BbJpM7&wM^p`L7T=ky`97nppV$5I^vVr-%K}zjTz=m&|KX9}wv+|01XS(F-'
    '!w&*U9gx|;}rUr^IsN=ReOZ<>Ds$d1@=%_R7TQZ^lKWY*jrgUSDI__WmFhleq5eJOH4Le{91NVM?@?$x``AnM%Rmz(juyEzn~kB2'
    'F+q#_m#@IVEOgf?2C!{35R@Iyz}@*ZNA}n>^ELNEf4)pq<?RGIvlkZ*_+NfkGWvGeP+G)tGU^EvUjU3r{$zNJKDCb%N2+lpHEhPU'
    'A-VFFHGlkZqIhpG>d*O%lTvxAq>hnwnX=C+PmyG@zZa=wd?J98m4hS^!nv=)xWxE*PQZhuX(#1!C-'
    'KGQI|}m6=$~0PQ`63Q`QNt%MUa<C3%dF21b-ow_==Lug>Ao<uVqT#YKk)-|qe6AG_Zk^!AT-'
    'zdhXV?f+wM|J~Wa@zH4=K2z63py9&(lIEdA`Th8)xnkH<#&^dje>?c$;OK9?H$NWjzCGCM?d_hP-B;ds-`!i_(f;3iZ}t!O&-Tk'
    '--yIwsJhOtQ-|wF6zj;Q5PS1AF4)&f=foA*O`=h@f9KG2;d3r%--=FO7zIjShe7}2II{R$@<Y@PBR!ndA-'
    'N6$}diS^zHZ^N4qBI3(z2}wl{&c^$cl`F<!QuW%@8s+W2UANpJpAG9Q~Rb@3uy-F{(Zf&VZ$<W_V#-'
    'RXS+uS@83RU&usx^%AFja9)Gv>oNLM`Q+EIK-R|E0JzLiWW&PIgkILXKL-R?y{$c;*v`p=Lwq3j1)6@Nvx+L^Y_uuXw-'
    '9IzS*>^NfYf72b;hs&~CAqH1cej4-^0`<$%g{aj@$_u}?Gp<)Jl@+qJoxAC+5PQ!UlDJQkB-'
    'ldkLtQzO8cKDmU6Ot^yc_&nF~K0+&h%+E#vI$;E9_)ZH<4{0{^^4d9n4u+x^}@kB`c^Znw;&-P5Nw-uu#n$8Vmx_1_QPl(n=p;_h'
    'BKNo;>G|2R9@?VTRXPubh9hGoZZ_K#`|@%H{>XugP9xBY2vkJ4wHPd?KbvMJ{6`_sc-'
    '{ryRmc=ybMc<!0CclP7E{ez?Lj+=Aq?#aPvS!xg7zB}B1yMJ`{&`NWA#cofm^I^8Pzuigd*4E`TcRD*&m$9-'
    '<*W4`VyOVO#t8H`o^fLaoclwM&dBS>itAMSStee|EVbz)y@QkQyrG&N%zAtqsrR?qQeZNHr(af!P@0u85_pq6=XSGF6>H>1O`{VK'
    'Z)mk-Idi`OF8<wEe(!M=@U!uS_bus<l_xoiko;<OjO`+Z066pO!tPAe$7D6@^vM##2yZNp7Znc1u-'
    'G3~@oLddD#lhSS^&Y$NooKI~VRqji-rpeiY<}>!qvMnPb^CgAaN5j`9}Z3rzCAcRIQy};dsKp>-P<AFV@JZx)7n-'
    'QzqRR6i4fNB;dFfv`N-z2+i!>=w<uwA2)RumYtEXF9O-rQO#$c@HMqMbZoP3msnkg1X~(cq#yk{xc4cPa#Iq~ZgcVOL<-'
    'Qnqi=(<5;%>3=5Bp_&ob+~o*gZJhy?1tRab%mr=111-'
    'pj<znysv>(IqUrW;OzUdV(lJnUzz$>`%T7!Gl*{7{%HU2<?ko%{9Wmrr_J7@<K7Q@C-0ByFxkH5?@rGSd*ANv{ZHxN`dV4U-'
    '|e35egA~z`bJUZym4@2`aP|bvp2m*Ou%*JY!!yDZLE5e_`^84*mIZt=HB--'
    ')!RDdQ&+=Z>urK@ldSSvZ!kLV2RG;q`o4XqW)V!Lqp>?ry;&x}{I>I&Y`}SHF<E4jEK)eGF4EYQg61!*-'
    't~X{*Y>sMD|wFt*VLx@!hMjM8`;xw|GHm}pt-rS{B?eRWqB)Vd86$28z~GsS=&T}5ynt0g%mDQ!x9TxP$e{{$%+(1_Bv5Rz2H78<'
    '*YQ$1a6WhJI&4Z_M88jQ&jJp4bQLI1cJc$>Yc?|HuWOEpxz^$HungwN`2b*mx&{j(lu_pvznvYHeJ1Oe37OfM)TWk|99mE{oG&N_'
    'a3LqahjBBx!FOsqocj&RfbD*|6`fUL^gHh!?%ncbHiqf(ZC)x99G-m?x6T-'
    'nIpNe(}R&*G4H%mf=QO0E<ei<ln^pAB3L3)F~_78GC7`nrp`r8jj@D>Y*sscCEIVc=Pxgx)Au(DZF_%qt8lA+UnXQM`+jl%YBuHT'
    'J=8@O@{=ThON2|twc;}KK!}i$mL^R+bIw@Eidye971nrbjmudFE>kX(%Xt#wN(RsTu)CL|GMCc0JEH-'
    '>0Kfpi0Kfpi0Kfpi0Kfpi0ACyim>()(EBW6s&5w1v%-'
    '}B!7I?226|zLMlqF}%1)<@}Q!BHhi8)@c5F}yF8p~rSpP)2JLqfSiBvCavtbZw3uuanYCVo&a;L8t>;|F)w+Nm3#r^keHYf-'
    '}ed7t;2gq2D>$t7%cNqjF~DA%AH^}?%%HHi7|&>(b!23aKZ&aNeUi}|u$2k=L9z<d+)Y0GW^A^{=+A^{=+BKdO>$*V=}%%<9zwcn'
    'E6t({p@JG1h=(2d%07#A297#A297#A297#A297#A297#A297#A297#A297#A297#A297#A297#A297#A297#A297?+2Q%Z-'
    'fBdwZXKrp|4$AD=SWW16KXY&YlmJ^jyPEWJ%hRI2nS6+U?(h{~3D9aJ=&DM`yn5YlDOvbEGRC6b9YTN)Hy?f+Q{)n}aet0mr?`Rv'
    '&<|3Tq2yVZG{IPILA^-'
    'h0$`|a^z@3dS>?Vi0qsb}rA<|%U@k~K!?Oc@tknwS`;igHd$lQYVcPfF7uOfWiTNm=<kaoI9u5)F5rezKrX&COakCpafKCpafKCp'
    'afKCpafKr>8onFU=A;Dx(%91Qe8}97|NLJ*!E!f(4&>N`yJ%Qe;$@>oA{!4%7v~X`neJWnhW6w?zLTyz(41^qeP|{Aa`vs0yeGs0'
    'yeGs0yBU0t*5Q0t*5Q0t*5Q0t*5Q0t*5Q0t*5Q0t*5Q0t*5Q0t*5Q0t*5Q0t*5Q0t*5Q0t*5Q0t*5Q@<l%H<US2>{JvhDeE0rnuZ'
    'gaYj^7@%(aKsBpuMr$DC12QL}sb2%_24bLbOOyg+xeTlCvBW&qf==Lp03k7`R9}sXHj3-c4P~fO*0XZ~$-sZ~$-sZ~$-sZ~$-'
    'saKM-H5R@+s8$_3wG|7eN1yh+tX@v6HM#V_Tftld4_a=D4sI`jGl&LM3fx-'
    'o6EfK&5Uo19w!jm$f4WJF64WJF64WJF64WJF64WJF64WJF64WJF64WJF64WJF64WJF64WJF64WJF64WJF64WJF64WJF64WJF64WJ'
    'F64gNrF@W^KmFh$FBAy#{;8Ij(U2IMAsL!~30@oc$IF-5|nB1Bkcj1DaEdiOeMvy%C<Sbn>|CihFX-'
    'g54)G!B>nm;smpm;smpm;smpm;so<%XkJsWHQI>cp%#3%w_ONSWc-'
    '<&LrY<DF3I?d&;Txnp)`v%RCCEgLl*suz>AZKn<|(MFI1E#6ty;=8rUgr1>MwA8Gzb^GBLL()^L;k2HUz`6JCAY5qv_N18v<{E_C'
    '5G=HS|Bh4Ra{z&sjnm^L~k>-'
    'yyf28>%%^zw0Nb^UUKhpe>=8rW07m((!qSHaEBw}ev?x>(dX<;d|(d(#$<xWNxMIbbLs<>3b5p7b=BxKo4s`Y99)4>E;{>bu2mOr'
    'xmk>!spe`NV1%O6?(FE7hKv1}!`&hY57Fe*!BIEm5*A);bg24|=sT63+Gk%U?2iS^Rt60iqrkmdj1k>y{)c_jHG$sbAnNb*OLKa%'
    '{B<c}nOB>5xBA4&d5@<)<ClKhe6k0gI2`6J06N&ZOkN0L91{E_63B!49NBgr30{z&pil0TCCk>rmge<b-'
    'M$sbAnk4y4zGp{acde6?}qCf7=Zd7-'
    'F9+gqu4WnW6_AsRGbq#ZB4#l8%K6aNMdcjT7N}aoxb(1tM8(my9zfMZKU#G=Zv)huPtYPP)aX&2+@gFh<$M5UK(Rc5U_L|`S==kk'
    'H8!XKh(fLx>{+s{pepXSyIEB$T&Xd2Mn5MIF_%d?;a@OPwFS8BXq^)J;FUKRFZr#(X%WmxYdf&2+q9-Rgtxs%fYtXy-'
    '@2WP*Ub9j1So`tlep!r>S>G)3<~H`sn$)r_4*ZX7^5?hs%E;W*>g}EC+l@X;4Olnm@65tyH}Ri2toa{4tRK<9WzBU>+tz9?8@M#s'
    '#pQo)>^6xCf68JpOTxX`tg{zCN3+hV`KPt)yqR8P<F+|Ze_GqNyZ^$Qwgf*V4ms~P$C`#=)LtS@N29^ybrTJ>vC-'
    '@LPWY<1)R=v22^$HE#8XG3q9W2jjnYH~&y(fExNImPktLpujai2vtmP%N3|VUv6lJ#7v|Ps2itmP+9@ojGBRYGB2c40hr15o|v)X'
    'aP*eN|XZu;IT(jAX}?bL&Ny$o?*&o16x&tj~Pou=J8<1#Ah1!HHDYR=U(4L*L;8IC%o>q~&vS@ii=i?p)3fQ~|Gg)-'
    'Jks5wiVZ5rkEJgxEdN_6;oQAXK!sY4lqY4O4CJRtw-'
    '=gBJ4Ts{LT>LguE$#cR}{jpq{X&bc_irCUnRC}LPrrBr4OM|O&4JNI&+!1b7laYUUH7*fnt@xfB4C-'
    'z>*Cj%}nsnMTVQ0}MB~~BDZ<=QAF5a7@N#|;kI<D=5a>dcDhO{(YPUF()srJZMox>W*cG~)v#!ay{&1}=~A%$N`BhQMMjpj}hEVu'
    'pV#;LqK?OY8@ygnLSmk<B?VN@EZ9o`)mFZz>7(-EKMW3vR#<tjZ6R+>wBr-BisF*M1{req>hN^`Gd8D&N?N2S-'
    'ohVl^~%H<7{nk$i0)GTnJYT?U>teGa=I+D6&?-w<9xVdl|g{zC%byt`re?D$0TI+v#@KWm-C5_bDGG(H1%n-'
    'v$?<Nu>iN0J``#J`)w~CgIjWQ=?Jjp&u4cZIZ3)&0X3)&0X3)&0X3)=f)Xs?jTkQ_6kh6!$b$~;;kk~e};T7tn6H42rh;w@KKJSi'
    '@uGc-'
    't9!bIvkXz%v4x85f!Kir3Vm%F*Uo=x5OJUu2{y7R^PbA9kiC4hv1gn@*Cgn@*Cgn@*Cgn@*Cgn@*Cgn@*Cgn@*Cgn@*Cgn@*Cgn@'
    '*Cgn@*Cgn@*Cgn@*Cgn@*Cgn@*Cgn@*Cgn@(~M#3BU;v<>p@{Ucfgk!r0M;o6J=Cv<V&1<bheJq#=k#g--Fr;*e$(-'
    'aE0~e7+&WPfI<ixVK**PMOP%r{80x$wF0x$wF0x$wF0x$wE#t6iuc@U8&k$CV_XrqavmMN=9l8y($SxtOmvHY6L<r&E`XC*nKPWd'
    '2U1pY!sVD?Xczz4twzz4twzz4twzz4twzz4twzz4twzz4twzz4twzz4twzz4twzz4twzz4twzz4twzz4twzz4twzz4twzz4twzz1'
    'ya0~WbzpVJ0J5k!z&m)WH<FY``oVG=hsG8t8hGTETG5{d^Nt>vC1lWmz~TzM%2hYf%YfDM2RfDM2RfDM2RfDL##&ku;nm+LSWl&T'
    'S;S3Jv1e3ry$LUPp1(U4W*)DfqwGE`|LoyuMqN~MGi_zT&9X=xMC0MG!?0MG!?0MG!?0MG!?0MG!?0MG!?0MG!?0MG!?0MG!?0MG'
    '!?0MG!?0MG!?0MG!?0MG!?0MG!?0MG!?0MG!?fTz%antk)RWdPGLE9#BP(Ri(NGLDtGr;~Q1OhINu=0RI6N@E9?NH9(?LJ75&D8V'
    'CS0Av7U0Av7U0Av7U0Av7Uz>ARqtXxZ(L?WR|mY`6V7+Yx@gby*)Ae`l#ISY<krFABmBvYb76OBkp=cFM6{z5XK&C~`C01f~S01f'
    '~S01f~S01f~S01f~S01f~S01f~S01f~S01f~S01f~S01f~S01f~S01f~S01f~S01f~S01f~S01f~ScoGhnCE$E&6T2>I?$FNUqCf'
    '7=?q7F*9+kn~4WnW6_AsRGb#wP=+&}L({hEeh)UGts(P%Jv-'
    'E7^K^}4<jzG`Od>|;wpKv*Q6IvN!fkp^m%CMtNIEGNcgLkWp2@oa3&Is{=YFFh2p)+Q**Y`uMYwP=9j;oxIulG;R!f3cswnq^%5i'
    '~RIeJ=9M4Q2H!QzUjEZpp!>e<4zi0r@^SKcAdIZwh3_4Qc7FX*l~5M(XbB1?l^sLlMg9=RogdwNEdE#AoC;(>vd$Fu;fG%Cb4X@b'
    'D2q=UGl;3I-bh!F-T`cpothy1<gDWZWRf&=T_#+j?;=|8f?zQm*z>73*`kfL@}bQu*S>8y-'
    'M0q#kkT!l>aO(6*p9HB5tH0WGRT&HRH~fUB*OJeSAZVicl_Ta+XMGybvKIqp37W2+DYw1?5;Mk$PuwkGY<UMxpfbWeR0P&hl%TPJ'
    'cbmet5kyT3#=X>2)X#+K=UYw)kLoK5xJJdD2XQ*?sIKGl@D$7gO@3`BMF{tl-+lau|x(G7zZtKB-Kz&y1G=rOHw*t+w3NR&5dhFR'
    '#Xzqe-'
    'p!Zm7u!om}Qur}S#K(v!|O<uoo`o;vfX*j=t5op!k_A387dt!5m2vlt%Z6h`AX>9}#~3`;>}{`Id@CtcTrD#eY;2%8^!$6b}#Jg!'
    'GttJF@Oa{4M~<2YD3UZJQ<jE6)@H&f|S8A;`pa?(=X<gz5WP=0n<#B2qZA}3$gEmIoFs>}pyj(6U;ZQZ*!*2Yn|x|l7kzPU%<+|n'
    'NnuFK2}vxJYO6l(9D&rccifxf(}{Z~yU`pu}G5`Sze(L6KtbLJ7<MPIYjlQuG)W%ia4)BSfEkGlOyw+!s=N>bBG=H*Htar;!(<YC'
    'mwF;C)MNf&H)c=zP@#GKA`d7PitU^k56mpg_lTs%E~U%yR#ceuME7iYtIwhqqMxjMWr`jd;AGP!<8ufTyXXG}L)p6eIr^^<z7+vL'
    'GZtz(olQfo^97L6-0g<<7fnn;W!`f{z~>lrtDTh2y=N12l{o@Ae-UbgD((+mOW1nC6n1nC6n1nC6n1nC6nd^rz$lF5*A!NaIwf*Y'
    'SQkCuq!jbN0PII#qjLS-'
    '4ODOXH9DK4ZlG)P$@Na{RD=U<3)u3i8Ebpmw)bpmw)bpmw)bpmw)bpmw)bpmw)bpmw)bpmw)bpmw)bpmw)bpmw)bpmw)bpmw)bpm'
    'w)bpmw)bpmw)bpmw)bv}qXANh2rRV4B5WdC&ks0q5(LID|KD6K^;cit$%Sp9{DC@huKYZ5ZGSqW(v(OE<m$|U35a-'
    'qF2M7d@5&qaSSDJxO;va~O-'
    '0I&eC0I&eC0I&eC0I&eCz{|q|u>^xLnV3j2JWEO(Rnan;O(NN<EIDDK`qE4!mnC55fx9SE{WlJ>C+x3=1==PC0{{a60{{a60{{a6'
    '0{{a60{{a60{{a60{{a60{{a60{{a60{{a60{{a60{{a60{{a60{{a60{{a60{{a60{{a60{{bf@{<9a<e3H*Tp-'
    'L+sj@bKMIwbJE+!=jw?<_iv-'
    '5;x?#l#=!qYnCe6qxDelh?>vOkjjk?fCTe<b@O*&oUNNcKmv|BFfXr<O}9C?&!tUarDekjbWyh@vbIRj$QsjLNta%f(snhNeKMus'
    ')U$T{6e<WB@!F03-k;03-'
    'k;;4_c_3K9Sk01^Na01^Na01^Na01^Na01^Na01^Na01^Na01^Na01^Na01^Na01^Na01^Na01~i)1W=HGmqG$4NC2J;@OhpLz)N'
    'c-r&F0(l3ST%bY3K;7-7m7rfg~VkfL-vCdDZ)jZY0xmMQ0iROJ3A0{{yE3jhlM3jhlM3jhlM3jhnepeF+)k*$d?<q~rHl)Us_Wx>'
    'kdDLayl^OX6lnJ>}0%Yqmi6tls*63$!Z@MHim05AYB05AYB05AYB05AYB05AYB05AYB05AYB05AYB05AYB05AYB05AYB05AYB05A'
    'YB05AYB05AYB05AYB05AYB06ZCBt0x1{>_cfLVS=H=1`*5J<2?!9QNdH@j2My$qe)Q8j5H~!(v+E6>Xp%n-'
    '1B4ri)?>n`y<;Q+5X7(N47t*{gLgDZ2uRN?e9zqL`W(uB{AkebB;z+CaJetWnCh4%{}*o<*b=;PSHq{BqqBcN_dV(1K`mBFaa<DF'
    'aa<DpTh)Lpa7r%pa7r%pa7r%pa7r%pa7r%pa7r%pa7r%pa7r%pa7r%pa7r%pa7r%pa7r%pa7r%pny#%z(NJQ7!_c_0`PQz&+~ME6'
    't(B2acS1lbK|7YlABDZQ#A`rY8qT}UK^f;HZ)4<V%Ay`XO+>$J@9k@fB}F3fB}F3fB}F3fB}F3fPt3-2DBGiDdM%rIdBq^<e^-'
    'ig%T^O<Xq;ICQgZF$tulbpd!mCO0cd7=R{CE9sm>o6aW+e6aW+e6aW+e6aW+e6aW+e6aW+e6aW+e6aW+e6aW+e6aW+e6aW+e6aW+'
    'e6aW+e6aW+e6aW+e6aW+e6aW+ePYBrd2?0qfORQx!Ng+6AnP;1o6iEq39r2Mk;Vj9HdTYH8iIJ>`Ryk82qvo5R5TK;w8ae;S`A5z'
    '_a{iI?kDPzx{3GWdIsY#v=bup{Ne(t-'
    'YH|!IQXV9UF8B~lDwj`ADjhtRO#7&)$dQF?qvMoOZaBe10`QOk$N<Oy$N<QI&maSuuN!~^fCGR7fCGR7fCGR7fCGR7fCGR7fCGR7'
    'fCGR7fCGR7fCGR7fCGR7fCGR7fCGR7fCGR7HsFBS9X0rXm*E5Mb|;7co)+-rrv(JXICs{0n|U-'
    '+Fv64J%4O%N$(m#lqYN}BYZXme)ZObqvJIO1G9B-'
    'KS^)3>@Br`t@Br`t@Br`t@Br|@%fbVkT1y=_PDLlBP9;z$oC!&!WG?vVBNf6(s%dsKCQFoKnG&w035H3B2L^xzfCYdBfCYdBfCYd'
    'BfCYdBfCYdBfCYdBfCYdBfCYdBfCYdBfCYdBfCYdBfCYdBfCYdBfCYdBfCYdBfCYdBfCYdBfCW7L$pKPZYimY7Wx{$_=8x7ou;gQ'
    'DTT3m?HWMwF3rbqaEVGeHmkAL%JEb;1IY2NgtkUKG5C9MW5C9MW5C9MW5C9MW5CAVm0MHUfa!ZI5UL+bNp~P~{ND|(rEO_)%5@KV'
    'C6|?Y(J53{ZRAwod=ECCf0eE}>oB*5voB*7_XK(_`?;L;yfCYdBfCYdBfCYdBfCYdBfCYdBfCYdBfCYdBfCYdBfCYdBfCYdBfCYd'
    'BfCYdBfCYdBHei9(+iDO4FGCD$=u@x(JWb%qPZNmDMPh8yG{zh>F_C90L?G4+>H?>w6NKkRurlumPcmvt>Xf94Bxm#ePZIzr04M+'
    '`04M+`04M+`04M+`c!8k6NfLyyIjG=W3B`lvD#j$W${~;(tudMFBxzuo#^fVoB5<W@pe{^|c%%TR0H^?{0H^?{0H^?{0H^?{0H^?'
    '{0H^?{0H^?{0H^?{0H^?{0H^?{0H^?{0H^?{0H^?{0H^?{0H^?{0H^?{0H^?{0I0y0RG^0VdnGb||L*W$uU?FmP;B?0IjgR<0@69'
    '}W1>M&>10yUXB(9;LHH=62{xxpj8P$$uHcH3;DbonS+0n2mMt@b>OqaKQ@rB@B%A=80Gt4v0Gt4v0Gt4v0Gz;!aRS+~7)5>1fKHN'
    '&7@gEIC*z&<*{GO|t`WME(vk8`jK&krdA7Q2LYi;q@ZbSFcmSFJngE&rn&7i(0trn3O#n>*O#n>*O#n>*O#n>*O#n>*O#n>*O#n>'
    '*O#n>*O#n>*O#n>*O#n>*O#n>*O#n^skS37O1TRh#NN9q;ye4RGm)*t$v-'
    '+=N13`EuVx*c{uLE<@l%Jxt#+#(P6NctsdFGNuX>64QB!s9L6-'
    '*G#!!iZPjmyxi?bU5>W_H_y?=FsG?g{#(2>=NI2>=NI2>=NI2>=NI2>=OR3M5ce5$CPV#IUGc3A&XLikc*B^qDi6IhTs~%qVxM#P'
    'U)kX=S;jOPQ5xxxY3f&>E89>5@QxNtED$u7o9kC4eRPPgsH)2*42h!G=JQXDb3pz5qucABF^VVgIj^1P?Xr9ZPWU2KQ-'
    '#dpCT9CwOT4^`hYZ>cSMj6u=a~6u=a~6u=a~6u=a~6u=a~6u=a~6u=a~6u=a~6u=a~6u=a~6u=a0Zwl(|wJ+NeH1`Kyk|t2(5A+1'
    'L`tvcjkREsQ=FhPN5}05sOi*vGjz^cHNlmZWIXF5aOrPxkP@{mGSrBE;HA@cb%$vMZx}{qa`a5-'
    'n>W9ua<up#ikUF8>NB*Y6I+Ijy`AyT{W5+l5<6`;LWHh)=<8GNfX`J2s<F7iyQK!_pf1O^JDqWXO9Cuv2=uakXChyK@+&`~*K)te'
    'n#X(xC1{w@EN_oj6p^PV&lcZj8!<=-UYc7Jw%qh!lOo6H7b!47~XmX@6+cM7n9|TzWQU'
)

def generate_abi2_joint(check=False):
    import base64, zlib, hashlib
    from generate_service_type_fixtures import prepare_abi2_nonrecord_source
    sys.path.insert(0, str(HERE.parents[1] / 'tools/smir-format'))
    from codec import CandidateCodec
    root=HERE.parents[1]; spec=root/'docs/specifications/smir/portable'
    schemas={role:json.loads((spec/'schema'/role/'candidate.json').read_text())
             for role in ('execution','runtime','abi')}
    codec=CandidateCodec(schemas)
    sources=json.loads(zlib.decompress(base64.b85decode(_ABI2_JOINT_SOURCE_B85)).decode())
    inputs=[root/'tools/smir-runtime-contract/generate_service_type_fixtures.py',
            *[spec/'schema'/role/'candidate.json' for role in ('execution','runtime','abi')],
            *[root/'tools/smir-abi'/name for name in ('nominal.py','layout.py','graph_identity.py')],
            root/'tools/smir-format/codec.py']
    for name, source in sources.items():
        document=source['document']
        for case in document['cases']:
            roots={int(k):v for k,v in case.pop('source_roots').items()}
            # These archived declarations are producer source recipes, never
            # decoded old objects. All 22 recipes author one ordinary identity
            # plan with execution Fn12 (including the alpha-renamed plan77).
            for number in (1, 2, 3, 5):
                roots[number]['payload_revision'] = 2
            roots[10]['payload_revision'] = 3
            for plan in roots[10]['signatures']:
                if plan['id'] not in (0, 77):
                    raise ValueError('unknown joint source plan recipe')
                plan['execution'] = {'module': {'kind': 'self'}, 'id': 12}
            if case.get('name') == 'function-pointer-common-positive':
                pointer = next(t for t in roots[1]['types'] if t['id'] == 202)
                if pointer != {'id': 202, 'kind': 'code_ptr',
                               'signature': {'module': {'kind': 'self'}, 'id': 12}}:
                    raise ValueError('unknown common function-pointer recipe')
                pointer.clear(); pointer.update(id=202, kind='code_address')
                nominal_pointer = next(t for t in roots[10]['types'] if t['id'] == 13)
                nominal_pointer['representation'] = 'code_address'
            def author_generic_calls(value):
                if isinstance(value, dict):
                    if value.get('op') in ('call', 'invoke', 'tailcall'):
                        # These historical operations have no source call plan.
                        value['source_plan'] = None
                    for child in value.values(): author_generic_calls(child)
                elif isinstance(value, list):
                    for child in value: author_generic_calls(child)
            author_generic_calls(roots[3])
            prepare_abi2_nonrecord_source(roots)
            data=codec.encode(roots); decoded=codec.decode(data)
            case.update(encoded_hex=data.hex(),sha256=hashlib.sha256(data).hexdigest(),
                        content_identity=decoded.content_digest)
        document['abi2_provenance']={'generator':str(Path(__file__).relative_to(root)),
            'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'original_abi1_bundle_sha256':source['original_bundle_sha256'],
            'input_sha256':{str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs},
            'source_method':'Explicit archived source recipes authored as ABI3 with plan.execution=SELF Fn12, generic source_plan=None and source function-pointer CodeAddress202; V3 definition hashes. Original semantic assertions retained; no old wire decode or runtime upgrade.',
            'size_justification':'Complete independent ten-root framing and cross-section rejection witnesses; deterministic compressed source declarations retain original identities.',
            'check_command':'python3 -B tools/smir-runtime-contract/candidate/fixture_build.py --abi2-joint --check'}
        output=spec/'conformance/runtime/candidate/joint'/(name+'.json')
        data=(json.dumps(document,indent=2)+'\n').encode()
        if check:
            if output.read_bytes()!=data:raise RuntimeError('stale ABI2 joint fixture: '+name)
        else:output.write_bytes(data)
        print(('checked' if check else 'generated')+' ABI3 '+name+' '+hashlib.sha256(data).hexdigest())

if __name__=='__main__':
    if '--abi2-joint' in sys.argv:
        generate_abi2_joint('--check' in sys.argv)
        raise SystemExit(0)
    CORPUS.mkdir(parents=True,exist_ok=True)
    cases=build()
    for name,case in cases.items():(CORPUS/(name+'.json')).write_text(json.dumps(case,indent=2,ensure_ascii=True)+'\n')
    print(f'{len(cases)} candidate fixtures written; no other corpus regenerated')
