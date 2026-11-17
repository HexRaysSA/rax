/* Independent Clang witness. No target sysroot or host headers. */
struct Plain { char a; int b; };
struct Bits { unsigned a:3; unsigned b:5; unsigned :0; unsigned c:1; char d; };
struct BoundaryBits { unsigned a:31; unsigned b:2; char c; };
struct Unnamed { char a; unsigned long :1; char b; };
struct BitIntField { char a; _BitInt(65) b; };
struct Int128Field { char a; __int128 b; };
union MixedUnion { char a; double b; };
struct Aligned { _Alignas(32) char a; };
struct MemberAligned { char a; _Alignas(32) int b; };
typedef int int3 __attribute__((ext_vector_type(3)));
struct VectorField { char a; int3 b; };
struct Three { char a; char b; char c; };
struct AtomicField { _Atomic(struct Three) a; char b; };
struct Flexible { char a; double data[]; };
const unsigned long long abi_properties[] = {
    sizeof(long), sizeof(void*), sizeof(long double), __LDBL_MANT_DIG__,
    sizeof(__WCHAR_TYPE__), ((__WCHAR_TYPE__)-1 < 0),
    sizeof(__builtin_va_list), _Alignof(__builtin_va_list),
    sizeof(_BitInt(65)), _Alignof(_BitInt(65)),
    sizeof(__int128), _Alignof(__int128)
};
