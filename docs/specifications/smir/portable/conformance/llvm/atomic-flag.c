/* Actual pinned Clang resource header, explicit existing x86-64 target. */
#include <stdatomic.h>
static_assert(sizeof(atomic_flag) == 1);
static_assert(alignof(atomic_flag) == 1);
atomic_flag native_flag = ATOMIC_FLAG_INIT;
bool native_flag_exchange(void) {
    return atomic_flag_test_and_set_explicit(&native_flag, memory_order_acq_rel);
}
void native_flag_reset(void) {
    atomic_flag_clear_explicit(&native_flag, memory_order_release);
}
