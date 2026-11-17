// Dedicated source ABI data witnesses; no native FE constants or host headers.
using u32 = __UINT32_TYPE__;
using u64 = __UINT64_TYPE__;
struct alignas(8) RaxFenv {
    u32 revision;
    u32 rounding;
    u32 flags;
    u32 traps;
    u64 control;
    u64 reserved;
};
struct alignas(8) RaxFemode { u32 rounding; u32 traps; u64 control; };
using RaxFexcept = u32;
static_assert(sizeof(RaxFenv) == 32 && alignof(RaxFenv) == 8);
static_assert(sizeof(RaxFemode) == 16 && alignof(RaxFemode) == 8);
static_assert(sizeof(RaxFexcept) == 4 && alignof(RaxFexcept) == 4);
static_assert(__builtin_offsetof(RaxFenv, traps) == 12);
static_assert(__builtin_offsetof(RaxFenv, control) == 16);
static_assert(__builtin_offsetof(RaxFenv, reserved) == 24);
extern "C" const RaxFenv __rax_default_fenv = {1, 0, 0, 0, 0, 0};
extern "C" const RaxFemode __rax_default_femode = {0, 0, 0};
const RaxFenv* default_environment() { return &__rax_default_fenv; }
const RaxFemode* default_mode() { return &__rax_default_femode; }
