"""Actual portable frontend fixtures; no skips, no host-target fallback."""
from pathlib import Path
import hashlib,json,os,sys,unittest
from portable_type_project import run,ProjectionError,NATIVE_INVOCATIONS
from portable_type_check import check
from portable_type_paths import foundation
FOUNDATION=foundation()
BASE=Path(os.environ['PORTABLE_TYPE_QUALIFICATION'])
NATIVE=Path(os.environ['PORTABLE_TYPE_NATIVE'])
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
    def negative(self,name,language,source,code='PORTABLE_FRONTEND_UNAVAILABLE'):
        req=request(language,source)
        try:run(req,NATIVE)
        except ProjectionError as e:
            self.assertEqual(e.code,code)
            if code=='PORTABLE_FRONTEND_UNAVAILABLE':
                expected={'varargs-direct':'PORTABLE_TYPE_UNAVAILABLE','varargs-unused':'PORTABLE_TYPE_UNAVAILABLE',
                    'varargs-nested':'PORTABLE_TYPE_UNAVAILABLE','va-alias':'PORTABLE_VA_LIST_UNAVAILABLE',
                    'va-size':'PORTABLE_VA_LIST_UNAVAILABLE','va-trait':'PORTABLE_VA_LIST_UNAVAILABLE',
                    'va-macro':'PORTABLE_SOURCE_MACRO_ACTION_UNAVAILABLE','record':'PORTABLE_DECL_UNAVAILABLE',
                    'reference':'PORTABLE_TYPE_UNAVAILABLE','body':'PORTABLE_FUNCTION_UNAVAILABLE',
                    'cpp-bitint':'PORTABLE_TYPE_UNAVAILABLE','vector-three':'PORTABLE_TYPE_UNAVAILABLE',
                    'vector-wide':'PORTABLE_TYPE_UNAVAILABLE','vector-bool':'PORTABLE_TYPE_UNAVAILABLE',
                    'enum-expr':'PORTABLE_ENUM_INITIALIZER_UNAVAILABLE','enum-wide':'PORTABLE_ENUM_INITIALIZER_UNAVAILABLE',
                    'line-action':'PORTABLE_SOURCE_LINE_ACTION_UNAVAILABLE','macro-action':'PORTABLE_SOURCE_MACRO_ACTION_UNAVAILABLE',
                    'include':'PORTABLE_SOURCE_INCLUDE_UNAVAILABLE','pragma':'PORTABLE_SOURCE_PRAGMA_UNAVAILABLE',
                    'cpp-c-linkage':'PORTABLE_CPP_LINKAGE_UNAVAILABLE','va-decltype':'PORTABLE_VA_LIST_UNAVAILABLE',
                    'va-arg':'PORTABLE_VA_LIST_UNAVAILABLE','enum-size-init':'PORTABLE_ENUM_INITIALIZER_UNAVAILABLE',
                    'unknown-attribute':"unknown attribute 'rax_unknown' ignored",'ms-abi':"'ms_abi' calling convention is not supported",
                    'vectorcall':"'vectorcall' calling convention is not supported",'type-attribute':'PORTABLE_TYPE_ATTRIBUTES_UNAVAILABLE'}[name]
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
        from portable_type_schema import generate
        from contract_json import verify
        for name,expected in zip(('portable_type_request.schema.json','portable_type_projection.schema.json'),generate()):
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
        from portable_type_check import CheckError
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

if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(FrontendTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    (BASE/'results.json').write_text(json.dumps(dict(pid=os.getpid(),source=str(Path(__file__).resolve()),tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),optimize=sys.flags.optimize,dont_write_bytecode=sys.dont_write_bytecode,cache_prefix=sys.pycache_prefix,positive_products=COUNTS,native_invocations=NATIVE_INVOCATIONS,cache_before=CACHE_BEFORE,cache_after=Path(sys.pycache_prefix).exists() if sys.pycache_prefix else None,loaded_modules={str(Path(m.__file__).resolve()):hashlib.sha256(Path(m.__file__).read_bytes()).hexdigest() for m in tuple(sys.modules.values()) if getattr(m,'__file__',None) and str(m.__file__).endswith('.py') and Path(m.__file__).is_file()}),indent=2)+'\n')
    sys.exit(not result.wasSuccessful())
