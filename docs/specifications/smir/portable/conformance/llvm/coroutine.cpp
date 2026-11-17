/* Minimal standard coroutine protocol scaffolding; not a hosted library claim. */
namespace std {
template<class R, class... Args> struct coroutine_traits { using promise_type=typename R::promise_type; };
template<class Promise=void> struct coroutine_handle;
template<> struct coroutine_handle<void> {
    void *address_;
    static coroutine_handle from_address(void *p) noexcept { return {p}; }
    void *address() const noexcept { return address_; }
};
template<class Promise> struct coroutine_handle {
    void *address_;
    static coroutine_handle from_address(void *p) noexcept { return {p}; }
    operator coroutine_handle<>() const noexcept { return coroutine_handle<>::from_address(address_); }
};
}
struct Pause {
    bool await_ready() noexcept { return false; }
    void await_suspend(std::coroutine_handle<>) noexcept {}
    void await_resume() noexcept {}
};
struct Task {
    struct promise_type {
        Task get_return_object() noexcept { return {}; }
        Pause initial_suspend() noexcept { return {}; }
        Pause final_suspend() noexcept { return {}; }
        void return_void() noexcept {}
        void unhandled_exception() noexcept {}
    };
};
Task make_task() { co_await Pause{}; co_return; }
