/* Actual overload/failure/delete witness; definitions deliberately external. */
#include "coroutine.cpp"
using Size = decltype(sizeof(0));
namespace std { enum class align_val_t : Size; }
struct AllocationTask {
    void *frame;
    struct alignas(64) promise_type {
#ifdef NONALIGNED_FALLBACK
        static void *operator new(Size) noexcept;
        static void operator delete(void *, Size) noexcept;
#else
        static void *operator new(Size, std::align_val_t) noexcept;
        static void operator delete(void *, Size, std::align_val_t) noexcept;
#endif
        static AllocationTask get_return_object_on_allocation_failure() noexcept { return {nullptr}; }
        AllocationTask get_return_object() noexcept {
            return {__builtin_coro_promise(this, alignof(promise_type), true)};
        }
        Pause initial_suspend() noexcept { return {}; }
        Pause final_suspend() noexcept { return {}; }
        void return_void() noexcept {}
        void unhandled_exception() noexcept {}
    };
};
AllocationTask allocation_task() { co_await Pause{}; co_return; }
