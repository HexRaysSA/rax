/* Source va_list storage, not the VM's opaque va_list execution handle. */
#include "coroutine-state.cpp"
extern void observe_va_value(int) noexcept;
StateTask copy_va_list(__builtin_va_list source) {
    __builtin_va_list copy;
    __builtin_va_copy(copy, source);
    co_await Pause{};
    observe_va_value(__builtin_va_arg(copy, int));
    __builtin_va_end(copy);
    co_return;
}
