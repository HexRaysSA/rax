/* Native source-order mapping oracle; no runtime memory ordering qualification. */
void relaxed_fence(void) { __c11_atomic_thread_fence(__ATOMIC_RELAXED); }
void dynamic_fence(int order) { __c11_atomic_thread_fence(order); }
