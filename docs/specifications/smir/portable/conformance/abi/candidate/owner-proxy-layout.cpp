// Header-free selected portable contract, not an upstream libc++ build.
using u32 = __UINT32_TYPE__;
using u64 = __UINT64_TYPE__;
struct alignas(8) OwnerProxy {
    u32 revision;
    u32 reserved;
    u64 proxy_id;
    u64 payload_id;
    u64 generation;
};
struct PortableExceptionPtr { const OwnerProxy* __ptr_; };
static_assert(sizeof(OwnerProxy) == 32 && alignof(OwnerProxy) == 8);
static_assert(__builtin_offsetof(OwnerProxy, proxy_id) == 8);
static_assert(__builtin_offsetof(OwnerProxy, payload_id) == 16);
static_assert(__builtin_offsetof(OwnerProxy, generation) == 24);
static_assert(sizeof(PortableExceptionPtr) == 8 && alignof(PortableExceptionPtr) == 8);
static_assert(__builtin_offsetof(PortableExceptionPtr, __ptr_) == 0);
