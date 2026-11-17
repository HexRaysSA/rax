/* Source-only protocol witness, not an installed <coroutine>/<exception>. */
#include "coroutine.cpp"
extern "C" void *current_owner() noexcept;
extern "C" void retain_owner(void *) noexcept;
extern "C" void release_owner(void *) noexcept;
extern "C" void inspect_owner(void *) noexcept;
extern void may_throw(int);
struct OwnedProxy {
    void *owner = nullptr;
    OwnedProxy() noexcept = default;
    OwnedProxy(const OwnedProxy &other) noexcept : owner(other.owner) { retain_owner(owner); }
    ~OwnedProxy() { release_owner(owner); }
    void capture_current() noexcept {
        void *next = current_owner(); // already retained by current_owner
        release_owner(owner);
        owner = next;
    }
};
static_assert(sizeof(OwnedProxy) == 8 && alignof(OwnedProxy) == 8);
struct StateTask {
    void *frame;
    struct alignas(64) promise_type {
        int state = 0;
        StateTask get_return_object() noexcept {
            return {__builtin_coro_promise(this, alignof(promise_type), true)};
        }
        Pause initial_suspend() noexcept { return {}; }
        Pause final_suspend() noexcept { return {}; }
        void return_void() noexcept {}
        void unhandled_exception() noexcept {}
    };
};
StateTask coroutine_state(int value) {
    OwnedProxy saved;
    try { may_throw(value); }
    catch (...) { saved.capture_current(); }
    co_await Pause{};
    inspect_owner(saved.owner);
    co_return;
}
struct Guard {
    explicit Guard(int);
    ~Guard();
};
struct Pair { Guard first, second; };
struct IntPause {
    int value;
    bool await_ready() noexcept { return false; }
    void await_suspend(std::coroutine_handle<>) noexcept {}
    int await_resume() noexcept { return value; }
};
extern void inspect_pair(Pair *);
StateTask aggregate_across_suspend() {
    Pair pair{Guard(co_await IntPause{1}), Guard(co_await IntPause{2})};
    inspect_pair(&pair);
    co_return;
}
#ifdef REJECT_CATCH_SUSPEND
StateTask invalid_catch_suspend() {
    try { may_throw(1); }
    catch (...) { co_await Pause{}; }
    co_return;
}
#endif
