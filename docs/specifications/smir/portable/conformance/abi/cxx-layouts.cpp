// Existing-target generic Itanium and Microsoft comparison, no runtime invocation.
struct Empty {};
struct Ebo : Empty { int x; };
struct Poly { virtual ~Poly(); int x; };
struct Other { virtual void g(); char y; };
struct Multi : Poly, Other { char z; };
struct Virtual : virtual Poly { int y; };
struct Nua { [[no_unique_address]] Empty e; int x; };
#if !defined(_MSC_VER)
struct Wide { unsigned char a:20; char b; };
#endif
struct Repeated : Empty { Empty e; };
struct alignas(32) Aligned { char x; };
using u32 = __UINT32_TYPE__;
using u64 = __UINT64_TYPE__;
using PortableWint = u32;
constexpr PortableWint portable_weof = 0xffffffffu;
static_assert(sizeof(PortableWint) == 4 && alignof(PortableWint) == 4);
static_assert(portable_weof > 0x10ffffu);
struct PortableVaState {
    u64 area;
    u64 cursor;
    u64 limit;
    u64 cookie;
};
using PortableVaList = PortableVaState[1];
static_assert(sizeof(PortableVaList) == 32 && alignof(PortableVaList) == 8);
static_assert(__builtin_offsetof(PortableVaState, cookie) == 24);
extern "C" void portable_va_parameter(PortableVaList state) {
    state->cursor = 0;
}
struct alignas(16) BridgeFrame {
    u32 revision;
    u32 flags;
    u64 signature_ref;
    u64 arguments_address;
    u64 arguments_bytes;
    u64 result_address;
    u64 result_bytes;
    u64 transition_id;
    u64 exception_lease;
    u32 status;
    u32 reserved_zero;
    u64 continuation_generation;
};
static_assert(sizeof(BridgeFrame) == 80 && alignof(BridgeFrame) == 16);
static_assert(__builtin_offsetof(BridgeFrame, signature_ref) == 8);
static_assert(__builtin_offsetof(BridgeFrame, transition_id) == 48);
static_assert(__builtin_offsetof(BridgeFrame, status) == 64);
static_assert(__builtin_offsetof(BridgeFrame, continuation_generation) == 72);
extern "C" const unsigned long long member_properties[] = {
    sizeof(int Empty::*), alignof(int Empty::*),
    sizeof(void (Poly::*)()), alignof(void (Poly::*)()),
    sizeof(PortableVaList), alignof(PortableVaList)
};
int Empty::* null_data = nullptr;
void (Poly::*null_method)() = nullptr;
void (Other::*virtual_method)() = &Other::g;
