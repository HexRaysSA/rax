/* Header-free native-host source oracle; never portable SMIR execution. */
#include "coroutine.cpp"
static int order;
static int destroyed;
struct Immediate {
    bool await_ready() noexcept { return false; }
    void await_suspend(std::coroutine_handle<> handle) noexcept {
        order = order * 10 + 1;
        __builtin_coro_resume(handle.address());
        // No awaiter/frame access after publishing/resuming the handle.
        order = order * 10 + 3;
    }
    void await_resume() noexcept {}
};
struct ReentrantTask {
    void *frame;
    struct promise_type {
        ReentrantTask get_return_object() noexcept {
            return {__builtin_coro_promise(this, alignof(promise_type), true)};
        }
        Pause initial_suspend() noexcept { return {}; }
        Pause final_suspend() noexcept { return {}; }
        void return_void() noexcept {}
        void unhandled_exception() noexcept { __builtin_abort(); }
    };
};
struct CountDestroy { ~CountDestroy() { ++destroyed; } };
ReentrantTask run_immediate() {
    CountDestroy guard;
    co_await Immediate{};
    order = order * 10 + 2;
    co_return;
}
int main() {
    ReentrantTask task = run_immediate();
    __builtin_coro_resume(task.frame);
    order = order * 10 + 4;
    if (order != 1234 || destroyed != 1 || !__builtin_coro_done(task.frame)) return 1;
    __builtin_coro_destroy(task.frame);
    return order == 1234 && destroyed == 1 ? 0 : 2;
}
