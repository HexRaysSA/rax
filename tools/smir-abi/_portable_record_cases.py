"""Actual portable frontend fixtures; no skips, no host-target fallback."""
from pathlib import Path
import hashlib,json,os,sys,unittest
from portable_record_project import run,ProjectionError,NATIVE_INVOCATIONS
from portable_record_check import check
from portable_record_paths import foundation
FOUNDATION=foundation()
BASE=Path(os.environ['PORTABLE_RECORD_QUALIFICATION'])
NATIVE=Path(os.environ['PORTABLE_RECORD_NATIVE'])
COUNTS=[]
CACHE_BEFORE=Path(sys.pycache_prefix).exists() if sys.pycache_prefix else None

def request(language,source):return dict(language=language,source=source)

class FrontendTests(unittest.TestCase):
    def positive(self,name,language,source):
        req=request(language,source)
        product=run(req,NATIVE)
        counts=check(product)
        (BASE/(name+'.request.json')).write_text(json.dumps(req,indent=2)+'\n')
        (BASE/(name+'.product.json')).write_text(json.dumps(product,sort_keys=True,indent=2)+'\n')
        COUNTS.append(dict(name=name,**counts))
        return product
    def negative(self,name,language,source,code='PORTABLE_FRONTEND_UNAVAILABLE',diagnostic=None):
        req=request(language,source)
        try:run(req,NATIVE)
        except ProjectionError as e:
            self.assertEqual(e.code,code)
            if code=='PORTABLE_FRONTEND_UNAVAILABLE':
                expected=diagnostic or {'varargs-direct':'PORTABLE_RECORD_UNAVAILABLE','varargs-unused':'PORTABLE_RECORD_UNAVAILABLE',
                    'varargs-nested':'PORTABLE_RECORD_UNAVAILABLE','va-alias':'PORTABLE_VA_LIST_UNAVAILABLE',
                    'va-size':'PORTABLE_VA_LIST_UNAVAILABLE','va-trait':'PORTABLE_VA_LIST_UNAVAILABLE',
                    'va-macro':'PORTABLE_SOURCE_MACRO_ACTION_UNAVAILABLE','record':'PORTABLE_DECL_UNAVAILABLE',
                    'reference':'PORTABLE_RECORD_UNAVAILABLE','body':'PORTABLE_FUNCTION_UNAVAILABLE',
                    'cpp-bitint':'PORTABLE_RECORD_UNAVAILABLE','vector-three':'PORTABLE_RECORD_UNAVAILABLE',
                    'vector-wide':'PORTABLE_RECORD_UNAVAILABLE','vector-bool':'PORTABLE_RECORD_UNAVAILABLE',
                    'enum-expr':'PORTABLE_ENUM_INITIALIZER_UNAVAILABLE','enum-wide':'PORTABLE_ENUM_INITIALIZER_UNAVAILABLE',
                    'line-action':'PORTABLE_SOURCE_LINE_ACTION_UNAVAILABLE','macro-action':'PORTABLE_SOURCE_MACRO_ACTION_UNAVAILABLE',
                    'include':'PORTABLE_SOURCE_INCLUDE_UNAVAILABLE','pragma':'PORTABLE_SOURCE_PRAGMA_UNAVAILABLE',
                    'cpp-c-linkage':'PORTABLE_CPP_LINKAGE_UNAVAILABLE','va-decltype':'PORTABLE_VA_LIST_UNAVAILABLE',
                    'va-arg':'PORTABLE_VA_LIST_UNAVAILABLE','enum-size-init':'PORTABLE_ENUM_INITIALIZER_UNAVAILABLE',
                    'unknown-attribute':"unknown attribute 'rax_unknown' ignored",'ms-abi':"'ms_abi' calling convention is not supported",
                    'vectorcall':"'vectorcall' calling convention is not supported",'type-attribute':'PORTABLE_RECORD_ATTRIBUTES_UNAVAILABLE'}[name]
                self.assertIn(expected,str(e))
                if name=='va-macro':self.assertIn('PORTABLE_VA_LIST_UNAVAILABLE',str(e))
            (BASE/(name+'.rejection.json')).write_text(json.dumps(dict(request=req,error=str(e)),indent=2)+'\n')
        else:self.fail('unsupported source produced output: '+name)
    def test_c23_target_byte_bool_array_function(self):
        p=self.positive('c23-model','c23',r'''
#if __SMIR__ != 1 || __SIZEOF_POINTER__ != 8 || __SIZEOF_LONG__ != 8 || __LDBL_MANT_DIG__ != 113
#error wrong portable target
#endif
#if defined(__linux__) || defined(__APPLE__) || defined(_WIN32) || defined(__aarch64__) || defined(__x86_64__)
#error native target leaked
#endif
_Static_assert(sizeof(long double)==16 && _Alignof(long double)==16,"quad");
_Static_assert(sizeof(__int128)==16 && _Alignof(__int128)==16,"int128");
_Static_assert(__BOOL_WIDTH__==1 && (char)-1<0,"bool/char");
_Static_assert(__GCC_ATOMIC_INT_LOCK_FREE==0 && __CLANG_ATOMIC_POINTER_LOCK_FREE==0,"atomic");
_Static_assert(!__atomic_always_lock_free(4,0),"ordinary atomics never lockfree");
char c; signed char sc; unsigned char uc; bool b; unsigned char bytes[5];
typedef unsigned char char8_t; char8_t c23char8;
_Static_assert(__builtin_types_compatible_p(char8_t,unsigned char),"C23 char8 alias");
unsigned char echo(unsigned char, bool, int);
typedef unsigned char (*Callback)(signed char);
Callback callback;
''')
        ns=p['abi_fragment']['types'];xs=p['execution_root']['types']
        self.assertTrue(any(t['kind']=='raw' and t['bits']==8 for t in xs))
        self.assertTrue(any(t['kind']=='int' and t['bits']==1 for t in xs))
        self.assertTrue(any(t['kind']=='code_address' for t in xs))
        self.assertTrue(any(s['return_noundef'] is False for s in p['abi_fragment']['signatures']))
    def test_all_contract_predefines(self):
        predefines=json.loads((FOUNDATION/'docs/specifications/smir/portable/llvm/frontend-contract.json').read_text())['predefines']
        for language in ('c23','cpp23'):
            lines=[]
            for name,value in sorted(predefines.items()):
                condition=('__is_same('+name+','+value+')' if language=='cpp23' else
                           '__builtin_types_compatible_p('+name+','+value+')') if name.endswith('_TYPE__') else '('+name+')==('+value+')'
                lines.append(('static_assert' if language=='cpp23' else '_Static_assert')+'('+condition+',"'+name+'");')
            lines.append('int product;')
            self.positive('predefines-'+language,language,'\n'.join(lines))
    def test_cpp23_distinct_char8(self):
        p=self.positive('cpp23-byte','cpp23',r'''
static_assert(!__is_same(char8_t,unsigned char));
static_assert(sizeof(wchar_t)==4 && (wchar_t)-1<0);
char8_t utf8; unsigned char uc; signed char sc; char c; bool b;
char8_t echo(char8_t, unsigned char, bool) noexcept;
using Callback=char8_t(*)(char8_t) noexcept;
Callback callback;
''')
        names={t['identity']['entity'] for t in p['abi_fragment']['types']}
        self.assertIn('char8_t',names);self.assertIn('unsigned char',names)
    def test_c23_bitint_boundaries(self):
        self.positive('c23-bitint','c23',r'''
_Static_assert(sizeof(unsigned _BitInt(1))==1,"u1");
_Static_assert(sizeof(_BitInt(65))==16 && _Alignof(_BitInt(65))==8,"65");
_Static_assert(sizeof(_BitInt(128))==16 && _Alignof(_BitInt(128))==8,"128");
_Static_assert(sizeof(unsigned _BitInt(65535))==8192 && _Alignof(unsigned _BitInt(65535))==8,"max");
unsigned _BitInt(1) b1; _BitInt(2) b2; _BitInt(7) b7; _BitInt(8) b8;
_BitInt(9) b9; _BitInt(17) b17; _BitInt(33) b33; _BitInt(65) b65;
_BitInt(128) b128; unsigned _BitInt(65535) max;
_BitInt(65) identity(_BitInt(65));
''')
    def test_cpp23_enum_preuse_boundaries(self):
        p=self.positive('cpp23-enum','cpp23',r'''
enum Empty {};
enum A {a0=0,a1=2147483647};
enum B {b0=2147483648U};
enum C {c0=4294967296UL};
enum D {d0=9223372036854775808UL};
enum N {n0=-1,n1=2147483647};
enum class F:unsigned char {f=255};
enum class G {g=0};
enum class H:bool {h0=false,h1=true};
static_assert(__is_same(__underlying_type(Empty),int));
static_assert(__is_same(__underlying_type(A),int) && __is_same(decltype(+a0),int));
static_assert(__is_same(__underlying_type(B),unsigned int) && __is_same(decltype(+b0),unsigned int));
static_assert(__is_same(__underlying_type(C),long) && __is_same(decltype(+c0),long));
static_assert(__is_same(__underlying_type(D),unsigned long) && __is_same(decltype(+d0),unsigned long));
static_assert(__is_same(__underlying_type(N),int) && n0<0);
static_assert(sizeof(A)==4 && sizeof(B)==4 && sizeof(C)==8 && sizeof(D)==8);
static_assert(__is_same(__underlying_type(F),unsigned char));
static_assert(__is_same(__underlying_type(G),int));
static_assert(__is_same(__underlying_type(H),bool) && sizeof(H)==1);
static_assert(static_cast<int>(H::h0)==0 && static_cast<int>(H::h1)==1);
using SelectedArray=unsigned char[sizeof(C)]; SelectedArray selected;
static_assert((a0-1)<0 && (c0-4294967297L)<0 && (d0-9223372036854775809UL)>0);
A a; B b; C c; D d; N n; F f; G g; A choose(A,B,C,D,F);
''')
        self.assertGreaterEqual(len(p['enum_hooks']),6)
    def test_c23_enum_member_type(self):
        self.positive('c23-enum','c23',r'''
enum A {a0=0,a1=2147483647};
enum B {b0=2147483648U,b1=0};
enum C {c0=4294967296UL,c1=0};
_Static_assert(__builtin_types_compatible_p(enum A,int),"A");
_Static_assert(__builtin_types_compatible_p(enum B,unsigned int),"B");
_Static_assert(__builtin_types_compatible_p(enum C,long),"C");
_Static_assert(__builtin_types_compatible_p(__typeof__(a0),int),"member int");
_Static_assert(__builtin_types_compatible_p(__typeof__(b1),enum B),"all members enum");
_Static_assert(__builtin_types_compatible_p(__typeof__(c1),enum C),"all members enum");
_Static_assert((c0-4294967297L)<0,"signed selection");
enum A a; enum B b; enum C c;
''')
    def test_numeric_vectors_byte_arrays(self):
        p=self.positive('numeric-vector','cpp23',r'''
using V=unsigned char __attribute__((ext_vector_type(4)));
using W=signed char __attribute__((vector_size(16)));
using F=float __attribute__((ext_vector_type(4)));
V v; W w; F f; unsigned char array[4]; V call(V,unsigned char);
static_assert(sizeof(V)==4 && alignof(V)==4);
static_assert(sizeof(W)==16 && alignof(W)==16);
''')
        xs={x['id']:x for x in p['execution_root']['types']}
        self.assertTrue(any(x['kind']=='vector' and xs[x['element']['id']]['kind']=='int' and xs[x['element']['id']]['bits']==8 for x in xs.values()))
        self.assertTrue(any(x['kind']=='array' and xs[x['element']['id']]['kind']=='raw' for x in xs.values()))
    def test_clock_vfs(self):
        self.positive('clock','cpp23',r'''
static_assert(__builtin_strcmp(__DATE__,"Jan  1 1970")==0);
static_assert(__builtin_strcmp(__TIME__,"00:00:00")==0);
static_assert(__builtin_strcmp(__FILE__,"/rax-source-v1/main.cpp")==0);
static_assert(__builtin_strcmp(__TIMESTAMP__,"Thu Jan  1 00:00:00 1970")==0);
int value;
''')
    def test_byte_named_enum_is_numeric(self):
        p=self.positive('pretend-byte','cpp23','namespace std { enum class byte:unsigned char {zero}; } std::byte value;')
        n=next(t for t in p['abi_fragment']['types'] if t['kind']=='enum')
        x=p['execution_root']['types'][n['execution']['some']['id']]
        self.assertEqual(x['kind'],'int')
    def test_executable_schemas(self):
        from portable_record_schema import generate
        from contract_json import verify
        for name,expected in zip(('portable_record_request.schema.json','portable_record_projection.schema.json'),generate()):
            self.assertEqual(json.loads(Path(__file__).with_name(name).read_text()),expected)
        reqschema=generate()[0]
        verify(request('c23','int x;'),reqschema)
        with self.assertRaises(ValueError):verify(dict(language='c23',source='int x;',target='native'),reqschema)
        with self.assertRaises(ValueError):verify(request('c23','int café;'),reqschema)
        product=run(request('c23','int x;'),NATIVE)
        product['unexpected']=True
        with self.assertRaises(ValueError):check(product)
    def test_independent_checker_rejects_mutations(self):
        from copy import deepcopy
        from portable_record_check import CheckError
        p=run(request('c23','unsigned char f(unsigned char);'),NATIVE)
        check(p)
        byte=next(x for x in p['execution_root']['types'] if x['kind']=='raw')
        a=deepcopy(p);a['execution_root']['types'][byte['id']]['kind']='int'
        with self.assertRaises(CheckError):check(a)
        a=deepcopy(p);a['abi_fragment']['signatures'][0]['lowered_params'][0]['noundef']=True
        with self.assertRaises(CheckError):check(a)
        a=deepcopy(p);a['abi_fragment']['signatures'][0]['variadic']=True
        with self.assertRaises(CheckError):check(a)
        a=deepcopy(p);a['emitted_type_relation'].pop()
        with self.assertRaises(CheckError):check(a)
        a=deepcopy(p);a['execution_root']['types'].append(dict(id=len(a['execution_root']['types']),kind='int',bits=17))
        with self.assertRaises(CheckError):check(a)
    def test_reject_va_list_decltype(self):self.negative('va-decltype','cpp23','using Hidden=decltype((__builtin_va_list)0);')
    def test_reject_va_arg_expr(self):self.negative('va-arg','c23','typedef __typeof__(__builtin_va_arg((__builtin_va_list)0,int)) T;')
    def test_reject_enum_typequery_initializer(self):self.negative('enum-size-init','cpp23','enum E {a=sizeof(int)};')
    def test_reject_unknown_attribute(self):self.negative('unknown-attribute','c23','int __attribute__((rax_unknown)) f(int);')
    def test_reject_foreign_ms_abi(self):self.negative('ms-abi','c23','int __attribute__((ms_abi)) f(int);')
    def test_reject_foreign_vectorcall(self):self.negative('vectorcall','cpp23','int __attribute__((vectorcall)) f(int);')
    def test_reject_type_attribute(self):self.negative('type-attribute','cpp23','using P=int * _Nonnull; P pointer;')
    def test_reject_varargs_direct(self):self.negative('varargs-direct','c23','void f(int,...);')
    def test_reject_varargs_unused_typedef(self):self.negative('varargs-unused','c23','typedef void F(int,...);')
    def test_reject_varargs_nested_pointer(self):self.negative('varargs-nested','cpp23','using F=void(*)(int,...); F pointer;')
    def test_reject_va_list_unused_alias(self):self.negative('va-alias','c23','typedef __builtin_va_list Hidden;')
    def test_reject_va_list_size(self):self.negative('va-size','cpp23','static_assert(sizeof(__builtin_va_list)==8);')
    def test_reject_va_list_trait(self):self.negative('va-trait','cpp23','static_assert(__is_same(__builtin_va_list,void*));')
    def test_reject_source_macro_va_alias(self):self.negative('va-macro','c23','#define VA __builtin_va_list\nVA value;')
    def test_reject_records(self):self.negative('record','cpp23','struct R {int x;}; R r;')
    def test_reject_reference(self):self.negative('reference','cpp23','int &r();')
    def test_reject_function_body(self):self.negative('body','c23','int f(int x){return x;}')
    def test_reject_cpp_bitint(self):self.negative('cpp-bitint','cpp23','_BitInt(65) value;')
    def test_reject_vector_three(self):self.negative('vector-three','cpp23','using V=int __attribute__((ext_vector_type(3))); V v;')
    def test_reject_vector_wide(self):self.negative('vector-wide','cpp23','using V=int __attribute__((ext_vector_type(32))); V v;')
    def test_reject_vector_bool(self):self.negative('vector-bool','cpp23','using V=bool __attribute__((ext_vector_type(8))); V v;')
    def test_reject_enum_expression(self):self.negative('enum-expr','cpp23','enum E {a=1,b=a+1};')
    def test_reject_enum_outside64(self):self.negative('enum-wide','cpp23','enum E {a=(unsigned __int128)1<<100};')
    def test_reject_line_action(self):self.negative('line-action','c23','#line 42 "native.c"\nint x;')
    def test_reject_macro_target_override(self):self.negative('macro-action','c23','#define __SMIR__ 0\nint x;')
    def test_reject_include(self):self.negative('include','c23','#include "/etc/passwd"\nint x;')
    def test_reject_pragma(self):self.negative('pragma','c23','#pragma pack(1)\nint x;')
    def test_reject_cpp_c_linkage(self):self.negative('cpp-c-linkage','cpp23','extern "C" { typedef void F(); } F *p;')
    def test_reject_unknown_recipe(self):
        with self.assertRaises(ProjectionError) as c:run(dict(language='c23',source='int x;',target='aarch64'),NATIVE)
        self.assertEqual(c.exception.code,'PORTABLE_RECIPE_FIELDS')
    def test_reject_nonascii(self):self.negative('nonascii','c23','int café;','PORTABLE_SOURCE_ASCII_PROFILE')
    def test_reject_oversize(self):self.negative('oversize','c23',' '*(1024*1024+1),'PORTABLE_SOURCE_LIMIT')


    def record_layout(self, product, name):
        nominal = next(n for n in product['abi_fragment']['types']
                       if n['kind'] == 'record' and n['identity']['entity'] == name)
        layout = next(l for l in product['abi_fragment']['layouts']
                      if l['id'] == nominal['layout']['some'])
        return nominal, layout

    def test_record_padding_union_nested_self_pointer(self):
        p = self.positive('record-ordinary', 'c23', r"""
struct Inner { char a; int b; char c; };
union U { unsigned char bytes[3]; long value; };
struct Outer { struct Inner list[2]; union U u; unsigned _BitInt(65) wide; };
struct Node { struct Node *next; int value; };
struct Inner copy(struct Inner, unsigned char, union U);
_Static_assert(sizeof(struct Inner)==12 && _Alignof(struct Inner)==4,"Inner");
_Static_assert(__builtin_offsetof(struct Inner,b)==4 && __builtin_offsetof(struct Inner,c)==8,"padding");
_Static_assert(sizeof(union U)==8 && _Alignof(union U)==8,"union");
_Static_assert(sizeof(struct Outer)==48 && _Alignof(struct Outer)==8,"Outer");
_Static_assert(__builtin_offsetof(struct Outer,u)==24 && __builtin_offsetof(struct Outer,wide)==32,"nested");
_Static_assert(sizeof(struct Node)==16 && __builtin_offsetof(struct Node,value)==8,"self");
struct Outer object;
""")
        self.assertEqual([l['offset_bits'] for l in self.record_layout(p,'Inner')[1]['fields']], [0,32,64])
        self.assertEqual([l['offset_bits'] for l in self.record_layout(p,'U')[1]['fields']], [0,0])
        self.assertEqual([a['mode'] for a in p['abi_fragment']['signatures'][0]['lowered_params']],
                         ['sret','indirect_copy','direct','indirect_copy'])
        self.assertTrue(any(r['origins']==['source','abi_lowering'] for r in p['emitted_type_relation']))

    def test_record_one_byte_always_indirect(self):
        p = self.positive('record-one-byte','c23',
            'struct One { unsigned char x; }; union Tiny { unsigned char x; }; '
            'struct One twice(struct One,struct One,unsigned char,union Tiny);')
        plan = p['abi_fragment']['signatures'][0]
        self.assertEqual([a['mode'] for a in plan['lowered_params']],
                         ['sret','indirect_copy','indirect_copy','direct','indirect_copy'])
        self.assertEqual([a['source_index'] for a in plan['lowered_params']],
                         [None,{'some':0},{'some':1},{'some':2},{'some':3}])
        self.assertEqual([a['bytes'] for a in plan['lowered_params']], [1]*5)
        self.assertEqual([a['noundef'] for a in plan['lowered_params']], [True,True,True,False,True])
        self.assertEqual(plan['lowered_results'], [])

    def test_record_nested_array_tail_stride(self):
        p = self.positive('record-array-stride','c23',r"""
struct Inner { int x; char y; };
struct Matrix { short m[2][3]; struct Inner rows[2]; char end; };
_Static_assert(sizeof(struct Inner)==8,"tail");
_Static_assert(__builtin_offsetof(struct Matrix,rows)==12,"rows");
_Static_assert(__builtin_offsetof(struct Matrix,end)==28 && sizeof(struct Matrix)==32,"stride");
""")
        self.assertEqual([f['offset_bits'] for f in self.record_layout(p,'Matrix')[1]['fields']], [0,96,224])

    def test_record_explicit_alignment(self):
        p = self.positive('record-alignment','c23',r"""
struct __attribute__((aligned(32))) Aligned { char first; _Alignas(16) int value; char last; };
_Static_assert(sizeof(struct Aligned)==32 && _Alignof(struct Aligned)==32,"alignment");
_Static_assert(__builtin_offsetof(struct Aligned,value)==16 && __builtin_offsetof(struct Aligned,last)==20,"fields");
""")
        self.assertEqual((self.record_layout(p,'Aligned')[1]['size'],self.record_layout(p,'Aligned')[1]['align']), (32,32))

    def test_record_alignment_exact_limit(self):
        self.positive('record-align-limit','c23',
            'struct __attribute__((aligned(65536))) HugeAlign { char x; }; '
            '_Static_assert(sizeof(struct HugeAlign)==65536 && _Alignof(struct HugeAlign)==65536,"limit");')

    def test_record_scalar_bitint_enum_layout(self):
        p = self.positive('record-numeric','c23',r"""
enum E { zero=0, high=2147483648U };
struct Numeric { bool b; enum E e; _BitInt(65) wide; __int128 i; long double f; };
_Static_assert(__builtin_offsetof(struct Numeric,e)==4,"enum");
_Static_assert(__builtin_offsetof(struct Numeric,wide)==8,"wide");
_Static_assert(__builtin_offsetof(struct Numeric,i)==32 && __builtin_offsetof(struct Numeric,f)==48,"quad");
_Static_assert(sizeof(struct Numeric)==64 && _Alignof(struct Numeric)==16,"size");
""")
        self.assertEqual([f['offset_bits'] for f in self.record_layout(p,'Numeric')[1]['fields']], [0,32,64,256,384])
        self.assertEqual(self.record_layout(p,'Numeric')[1]['fields'][2]['width_bits'],128)

    def test_record_union_nested_padding(self):
        self.positive('record-union-padding','c23',
            'struct Inner { int a; char b; }; union Outer { struct Inner record; unsigned char bytes[17]; }; '
            '_Static_assert(sizeof(union Outer)==20 && _Alignof(union Outer)==4,"union-rounded");')

    def test_record_raw_width_boundaries(self):
        for size in (8191,8192,65536):
            p = self.positive('record-width-'+str(size),'c23',
                'struct Wide { unsigned char bytes['+str(size)+']; }; '
                '_Static_assert(sizeof(struct Wide)=='+str(size)+',"width"); struct Wide copy(struct Wide);')
            n,l = self.record_layout(p,'Wide')
            x = next(x for x in p['execution_root']['types'] if x['id']==n['execution']['some']['id'])
            self.assertEqual((l['size'],x['bits']), (size,size*8))

    def test_record_field_count_exact_limit(self):
        p = self.positive('record-64-fields','c23',
            'struct Many {'+''.join('char f'+str(i)+';' for i in range(64))+'}; '
            '_Static_assert(sizeof(struct Many)==64,"fields");')
        self.assertEqual(len(self.record_layout(p,'Many')[1]['fields']),64)

    def test_record_large_bitint_field(self):
        self.positive('record-large-bitint','c23',
            'struct Holder { unsigned _BitInt(16384) value; char end; }; '
            '_Static_assert(sizeof(unsigned _BitInt(16384))==2048 && sizeof(struct Holder)==2056,"large");')

    def test_record_reject_bitint_enum_upstream(self):
        self.negative('record-bitint-enum','c23',
            'enum Wide : unsigned _BitInt(16384) { huge = 0 }; struct Holder { enum Wide value; };',
            diagnostic="is an invalid underlying type")

    def test_record_qualified_fields(self):
        self.positive('record-qualified','c23',
            'struct Leaf { int x; }; struct Q { const struct Leaf value; volatile int y; struct Leaf * const p; }; '
            '_Static_assert(sizeof(struct Q)==16 && __builtin_offsetof(struct Q,p)==8,"qualified");')

    def test_record_reject_bitfield(self):
        self.negative('record-bitfield','c23','struct R { unsigned x:3; };', diagnostic='PORTABLE_RECORD_FIELD_UNAVAILABLE')

    def test_record_reject_zero_bitfield(self):
        self.negative('record-zero-bitfield','c23','struct R { int x; unsigned :0; int y; };',diagnostic='PORTABLE_RECORD_FIELD_UNAVAILABLE')

    def test_record_reject_packed(self):
        self.negative('record-packed','c23','struct __attribute__((packed)) R { char a; int b; };',diagnostic='PORTABLE_RECORD_UNAVAILABLE')

    def test_record_reject_anonymous(self):
        self.negative('record-anonymous','c23','struct R { union { int x; long y; }; };',diagnostic='PORTABLE_RECORD_FIELD_UNAVAILABLE')

    def test_record_reject_flexible_array(self):
        self.negative('record-flexible','c23','struct R { int count; char tail[]; };',diagnostic='PORTABLE_RECORD_FIELD_UNAVAILABLE')

    def test_record_reject_incomplete(self):
        self.negative('record-incomplete','c23','struct R; struct R *p;',diagnostic='PORTABLE_RECORD_UNAVAILABLE')

    def test_record_reject_empty(self):
        self.negative('record-empty','c23','struct R {};',diagnostic='PORTABLE_RECORD_EMPTY_UNAVAILABLE')

    def test_record_reject_over_extent(self):
        self.negative('record-over-extent','c23','struct R { unsigned char bytes[65537]; };',diagnostic='PORTABLE_RECORD_EXTENT_UNAVAILABLE')

    def test_record_reject_alignment_rounding_over_extent(self):
        self.negative('record-rounded-over','c23','struct R { unsigned char bytes[65535]; int tail; };',diagnostic='PORTABLE_RECORD_EXTENT_UNAVAILABLE')

    def test_record_reject_over_alignment(self):
        self.negative('record-over-align','c23','struct __attribute__((aligned(131072))) R { char x; };',diagnostic='PORTABLE_RECORD_UNAVAILABLE')

    def test_record_reject_over_field_count(self):
        self.negative('record-65-fields','c23','struct R {'+''.join('char f'+str(i)+';' for i in range(65))+'};',diagnostic='PORTABLE_RECORD_FIELD_UNAVAILABLE')

    def test_record_reject_weaker_alignment(self):
        self.negative('record-weak-align','c23','struct R { int x __attribute__((aligned(1))); };',code='PORTABLE_RECORD_LAYOUT_MISMATCH')

    def test_record_checker_rejects_mutations(self):
        from copy import deepcopy
        p = self.positive('record-mutations','c23',
            'struct R { char first; int value; }; struct R copy(struct R,unsigned char);')
        n,l = self.record_layout(p,'R')
        def reject(edit):
            forged = deepcopy(p)
            edit(forged)
            with self.assertRaises(ValueError):
                check(forged)
        li = p['abi_fragment']['layouts'].index(l)
        ni = p['abi_fragment']['types'].index(n)
        reject(lambda q:q['abi_fragment']['layouts'][li]['fields'][1].update(offset_bits=8))
        reject(lambda q:q['abi_fragment']['layouts'][li]['fields'][0].update(width_bits=32))
        reject(lambda q:q['abi_fragment']['layouts'][li].update(size=4))
        reject(lambda q:q['abi_fragment']['types'][ni]['record_input']['some'].update(trivial=True))
        reject(lambda q:q['abi_fragment']['signatures'][0]['lowered_params'].reverse())
        reject(lambda q:q['abi_fragment']['signatures'][0]['lowered_params'][1].update(mode='direct'))
        reject(lambda q:q['abi_derivations'].pop())
        reject(lambda q:q['abi_derivations'][0].update(pointer_type=q['abi_derivations'][0]['source_type']))
        reject(lambda q:q['emitted_type_relation'][ni].update(origins=[]))
        reject(lambda q:q['record_observations'][0].update(ast_data_size=1))
        reject(lambda q:q['emitted_type_relation'][ni].update(execution=q['abi_derivations'][0]['pointer_type']))
        reject(lambda q:q['emitted_type_relation'][ni].update(layout=None))
        reject(lambda q:q['emitted_type_relation'][ni].update(nominal=q['abi_derivations'][0]['pointer_type']))
        reject(lambda q:q['emitted_type_relation'][ni].update(call_plan=0))
        pointer = p['abi_derivations'][0]['pointer_type']['id']
        pointer_relation = next(i for i,r in enumerate(p['emitted_type_relation']) if r['nominal']['id']==pointer)
        reject(lambda q:q['emitted_type_relation'][pointer_relation].update(origins=['source']))

if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(FrontendTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    (BASE/'results.json').write_text(json.dumps(dict(pid=os.getpid(),source=str(Path(__file__).resolve()),tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),optimize=sys.flags.optimize,dont_write_bytecode=sys.dont_write_bytecode,cache_prefix=sys.pycache_prefix,positive_products=COUNTS,native_invocations=NATIVE_INVOCATIONS,cache_before=CACHE_BEFORE,cache_after=Path(sys.pycache_prefix).exists() if sys.pycache_prefix else None,loaded_modules={str(Path(m.__file__).resolve()):hashlib.sha256(Path(m.__file__).read_bytes()).hexdigest() for m in tuple(sys.modules.values()) if getattr(m,'__file__',None) and str(m.__file__).endswith('.py') and Path(m.__file__).is_file()}),indent=2)+'\n')
    sys.exit(not result.wasSuccessful())
