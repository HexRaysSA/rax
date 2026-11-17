#!/usr/bin/env python3
"""Preserve exact pre-INT032 ABI2 Int32 state-source semantic regressions.

The five objects previously issued real finite-profile facts. Accepted INT032
makes these source-role violations; this generator never reencodes/upgrades them.
"""
import base64, zlib, json, hashlib
from pathlib import Path
from fixture_provenance import provenance, write_bytes, write_text

SOURCE_B85 = (
    'c-rlqTaVqg5rF^8KIeh=OI`~DeF%`kZJ!NZn-'
    '+;3)JBmY$bavUx}2j6De3GQo7f{`ch8}yAvqilhY~;Qx2GRJy#LpKe){?8+uxr2ub<M#r*D<u>YJzZ%g-'
    'r%O7UIz(S3x}r;q6;_x{tr!_)n_4>7^1xBqze*Eiq&?akYFfB*iUZ~yY<-'
    'P`ZKdjt7?NWZ{Y$wd@aG7^cSjyO^d20xUL`Exnk_*GC#?ha0tM;?zkf!@g)#L@fwp07l(W&UW0SezHj>+98bDTxqye>(Y91;t7}A'
    '!>2ntn$lEeU|ydD!*FQXO-Wt6{eT@-'
    'H_6*k6Gn62l?$XzhB9xtL(L(>7sdy{7TT}CF3_bmCKb?Nzc8+$SR$!>d7@zRO`tK=FT=sKsx-'
    '$tcezy&8M8wS}Liz7BWw{X8H0^j_S&>kYW^v-;f(*W|d|QOm#J@)=%kn-L|n#<Jb{&CC6{-s-Q+m@ww!%>L#I~W-2H(_d@&3?Hs-'
    'PWHeD(v(i?@AivxxHLk|~O}1>NEJyINRC21+bT{J8mbz_qFAqDRGkI70>0euSV-'
    'K&L<(%Fa1yfDhR!Vu_+6N1wVm3I|kR!WtRQV1qlBFMlY4!U~3T@eJuuUnVDP?Ot3!k>pyDRmEZ(Mn3O@!7k<yjczZR(UKe{`izJu'
    '6{5E_Ba6)}v!virAT-_R`zOrk?YRY8tZ5Y1vzSxyHO<?&h0w2Vcvc?eA>8*+B`WseQ539Xk?yyRv<V=BS~K9;4*?F<xV}bwPU>Eh'
    'mcSz$s5Tc?buXXBixfi6VRIlk%B35tN9YQy3x9(9GBzHPqRTstA@_z4Dl9!9&R6sgwo(U^g{YFshhxs``x*g*eJ6h}BFuL5(ujIi'
    'VoY=*VM|N_lS_Toqw_zyPsMB#03$)5!)+NzqsFj8GdQVC2G>RkCU6_p#Hq4da|Cvvl07TcYgF%){Yx5jJ|mS~?`uD`D6}?f|X4_3'
    'Ld`?x)@Ay)ARkqMl(78<Ra-'
    'v&L0)ea3=9Kr^6Ys&t(_<cS(9xJH6bCHzgzaWI#f#fkQarr&#Bou_mSvZ@7ueMjAP3UnR|w%T6x{5v|n`M0fa^u;QQj_O=y=6R!S'
    '6ZE7#+~(&Raj4n@AU|xH%VGYsFe=kJCres!O7c=45LvJxj!^Z}BnX<ADa6X&NhX!E(gdb+h#^T&D9^+?o*>eYERskQPg2{=VfiOv'
    'O>2$W(G%_Tttw}r4nrSpJj2lQHIC<+-}#h#@3QqYd-'
    '>Y_=uH36b2IF7Jt!MJH|NEf!4Kz*TV6d_{RVyzydmW<w7G!qdPw24#Db7R!iA!K21|r%i&HdQLGSD0KdV(($d-'
    '#A1?vE70o#SHgx;wmYm6*u`K`+gavSe__Q;tRUkLvC-'
    'p;73(X5e!rRh>mNw43nVs(s^)TD$Q^+l((QxH}#!KIN#Q21nJ7E+}8IS5(4!5I#}i4>4GizGQ1Yq5H&JoM@mi^CbFPfJxIOD3Qnz'
    '<e#7(U2yjt$8A(fTo~SD!CMk()e5&DEmTr34YfyAiboBnp(aM<=f-d(bJ_#F5nEb4}`XBe?=Y$qP2!?-IGV8!8bSuj-cqE=!7*}Z'
    '%)e>!qm1?5ZJCS?Z`8==d112o?=ygSjmPs4cv=u*4Q4GP_4QzaoK0-gv_eV;z3T-'
    'cPYJ7V<{!CHp?MzEOM&0OBrl6M(%asPe=@)SqN}1*aF*1Ev*~%a2r)})&FF9x2tje;2Vazm2pYy_>>|x>*G$#8+;2BWsJg^o_Cq<'
    '4m6|=o(ftBeL;)#JxPPlp6*8MOR8G0V{#Zlof>uZ4t-ecfe(IcA!QtEP!qc^0m|p~>d6Zh{eZ@c?sxo-'
    'n%6nH%<eUgNxPC4bzI08YckAHFzFgS#Ba7?9S_e+r{t+|JaK7jUtG7grMw{O{8jQuH+tK3uiVRwCuGKwQxu<4{!Vk`P?Epm0X80+'
    ')iEZjXQ|`2&dO_>KK1}Bsj^IfZT~Dz$T&BXo|1Gthfa6<x^m9VZse3CTRjM@w8api6y4L&6HwXH|CyS~!AeB!(dSrRofE`3`waa7'
    '9&ebLJL7KO*VH+^NT|JQH<4It&e(79P#YnJwhnP*+-'
    'dP>A=6r<QMW1X;2h%k%d>at%6widBf7F<oy$Y@JN100mZ~S|ay;a_(jJb4*lz!T-'
    'B`Fz)}Ai2`YjqNR$%L#o=VhE(?XrWWSznGJ@9Q_T<G^c4%&F(GVAo#B;>rLAr6u2D7@P7Ie*@juj)9h9%j&YXRMxYzlM7Av#Xk(q'
    '(@dseR(H5yg4oHl%HSvk)^!HBKDsB%o6W=)(mwVB-fau=(Q6?vN<-LM;DRgF0w7&Y4%iue=fQ$BW(1r0n%YK$ubgby)!%9>n-'
    ';fAat00b~-4j*uNZB8$<hQq)*|m9DEV1L3;A-f&BJLLa!v=Jb}L;bGw>o$(`q~rrhm%Vl8XArigucb%r&&k@BS3whj&~WVO<0%3-'
    'V}=Xkv_#{|V1!dA1>{euT(TkvD4_M~L0AxYF3<>nDo{a$j|8rPTEC|8>rqH=n-'
    '7I|b;bYht!Z8WX6FEb5sCsm!Rd1H0dwjOgJt+h6~J|^e*r@Jz0%auoRH*r;aeA~XP&Km3bIGkiI=cu+EcR|h+D~wTar^WdpsjE1+'
    'Q|t7I{AC2&seO1z`W(@ABp=uNc-{B7O)OV^ZQpz_rizar?6t-fv^bgS1?VaN*VfKax&5`~b!)N1-'
    '8ETascAJZL>s!s1mpd$(vD88TOM-yc6S%`&{wqk@FuN3uNb~R5L3)@YSdY5;n;tPhOE-'
    'J#TvLAqS4WMJC;TECBaYW$57+G65;s4!sdK+zO8FHQTo0+hx)5!3^4)ZEk36wIbWA7Mg80JJJaLJh9`cJm2I;}nmcKDeO6hlqC6$'
    'EWuHcU^2q1=y9vUi7#tXpmewgvJWYao=Q7bkdX`|?)6z>#Lr_db8$H#Q7#6r!$_o|Q{Jgn7l`MPBHd_Mj>m{`+`O0p)-'
    '6z;|{alok{ib=^zfyN8gt`yK>Y|I`NhmM-'
    '7@%T#b7p+@T6a3^?Y>&?P?p1PmtDP0`+ruuRg?m4QDR97BuB@hE`bzd+6HYrbdL;@X639;(FNwbQ^J6sby2f4dFt&Rm^1s$XlH-k'
    'cE1N7@95KU&xzdKqjSGIVy*e(9Tku7;XC?%w5OxDx2LV8_8yAuJ~UhQ%9N+^u=19}Gx}3~p;Xyl#m4<$t@a;la<5l+_6{GX&}Sa('
    'nFoL7A)a|Wdq>{I<LR5Hk3Tpj)zi06Rw`|^r_rPmPxvST^-'
    'N@AWpNL|mZDABu?yjOj3n4d4Rb6d6@4(`>30y8KCQtQWnL3}5ibnBIC}uTkZa&eG|SD#be(?%zT}JGOTGxckQJEXSs#1}7r~cs5q'
    'yak!Iy;K3xY2Qz99H=9ekk=ZCT#?^m5?Kg*wq*oe*+C$mR1xF88&Dk()J##Uv*XLIx3FS}~C%k(1=C!~u+ZF!so}V2Zn7a$>MXg}'
    '5^^<`8s2(B%&ey3oV%`&i9b50s$C*duuXyk)q(lEyjfE;?5HupdO(N(ma}lOCp9kNdh-{Fxxe%Y!rNUi0-'
    '99<8y7L~I7Z83bn#oI!8~!5IW+5S&492EiEwXAqo0a0bB{1ZNPOL2w4a83bn#oI!8~!5IW+5S&492EiEwXAqo0a0bB{1ZNPOL2w4'
    'a83bp(JaEP_aGQo359`=$v!oEA<iLCm8KN*_z_C-3jY}>>LY(8^M5qa6;-'
    'V3JNdag6=iY@6KmWQQXY{MSGDd_y*DGVF?UOU)h*Xh%66T1Up{x8Z9FQ~S8aWfmMRLYmBxekgGf2)LIfLZPWpd`s>sdt8dit@?=X'
    '_<%8I}fL8G|&<>(DggH4v?OLtQq(c^Qq5igRm|Ns;Sld9+k%0ZY^v1vAEg7ZZ%hq@s&V8J3WwL6U}iX|IfV8OBDJJ6Cu2np#fbC0'
    '-fxnoP|fg{)cY`*m2F^=N-'
    'Bng&T4Bx#VOL6QbZ8YF3uq(PDfNg5<+kfcG921yzuX^^Brk_Jf{Bx#VOL6QbZ8YF3uq(PDfNg5<+kfcG921yzuX^^Brk_Jf{Bx$}'
    'dk|x<?saAoPeb&k`4+V1PEj8I#u1th#mH!+Zyub8i;gPk3u#EczM<jeCY0~?+0BP8(zJi9nFi2x_AEXHvUqKUAub=@B-'
    'vw#n#aGb8i?5(btNhOQK^l7zq;VHP8g~(-'
    '@d(l&NP{2^f;87bn&XYmd)q?sbu$Rad`*DNnAfD}lY<Zt4BJC7mc{aH(MWGIm>jV&LqN)Trse&FEGCE@!HXCV>v{+l6@oDc#*nZ3'
    '6*B{lQEvz~_3`I}US1z`S!(v{##|6|LC^(37X)1pbV1MsK^FvF5OhJ%1wj`CT@Z9Z&;>yk1YHnxLC^(37X)1pbV1MsK^FvF5OhJ%'
    '1wj`CT@Z9Z&;>yk1YHnxLD1!k16`;O$z_(I%#^@Ycq?guSXoJtL%D+`EfwWI_RdjgUADhl#&yV1!$6F}jiAfNPwu~;?ok)$=GR1B'
    ')C;37LHALYbn%@rdG*d1aJya9g<X7S47>Qw7`}dIOzfjB=_2ZqFQP8_BI*M245BWGx*+O;sLMsvg*P`f_fljNo%mcx%=7BmvnAdL'
    '{1BZ%bmlXoGl_Urwyzs$iw12{9u~YQhoGY)Lf9Y)Qwi3;!Ab#>JS}$wOw_?hB{aTM2GN;6Haf%4j@g|v>~Pk347V`@6f(?16{cy;'
    'Ve4M`^S*cH^--Ly*1u*P2T>eEaS+8p6bDfpL~#(sK@<m397J&t#X%GYQ5-'
    '~Z5XC_h2T>eEaS+8p6bDfpL~#(sK@<m397J&t#X%GYQ5-~Z5XC_h2T>eEalSAVhe(+`h{&31$IHA-'
    'bK*Xh8Bu2FDs6&Jj(h482hS!+f-4j=fh(7ke)|3Q{{z*@Pl^'
)


def main():
    here=Path(__file__).resolve().parent;folder=here/'source-role-fixtures';folder.mkdir(exist_ok=True)
    # Archived SOURCE_B85 remains an exact historical oracle. Current witnesses
    # are independently authored from the actual new-contract state producers.
    from fixtures import CandidateCodec, SCHEMAS, ref
    codec=CandidateCodec(SCHEMAS);cases={};inputs=[]
    for name in ('longjmp','setjmp','va_copy','va_end','va_start'):
        source=here/'state-helper-fixtures'/(name+'.smo')
        roots=codec.decode(source.read_bytes()).roots
        # Explicitly select ordinary Int32 as the wrong source role. No type
        # purpose is inferred from size or legacy bytes.
        roots[6]['imports'][0]['abi']={'some':ref(1)}
        data=codec.encode(roots);codec.decode(data)
        write_bytes(folder/(name+'.smo'),data)
        cases[name]={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),
                     'expected_class':'semantic','expected_code':'RT_HELPER_SOURCE_ROLE'}
        inputs.append(str(source.relative_to(__import__('fixture_provenance').ROOT)))
    write_text(folder/'manifest.json',json.dumps({'scope':'Current ABI3 wrong-Int32 source-role regressions; historical ABI2 bytes preserved separately.',
        'provenance':provenance(__file__,['crates/smir-portable/tests/metadata/fixtures.py',*inputs],cases),'cases':cases},indent=2)+'\n')
    print('current ABI3 Int32 source semantic regressions',len(cases))

if __name__=='__main__':main()
