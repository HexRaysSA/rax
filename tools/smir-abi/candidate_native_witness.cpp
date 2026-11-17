// Native C++ language/reference witness; no RAX/SMIR execution or foreign bridge.
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <future>
#include <memory>
#include <new>
#include <string>
#include <thread>

static std::string trace;
struct Part {
    char name;
    explicit Part(char name, bool fail = false) : name(name) {
        trace += name;
        if (fail) {
            throw 7;
        }
    }
    ~Part() { trace += static_cast<char>(name + ('a' - 'A')); }
};
struct Whole {
    Part first{'A'};
    Part second{'B', true};
    ~Whole() { trace += 'w'; }
};
struct Base { int value = 3; virtual ~Base() = default; };
struct Derived : Base { int other = 4; };
struct Private : private Base {};
struct Left : Base {};
struct Right : Base {};
struct Ambiguous : Left, Right {};
struct Boom {
    Boom() = default;
    Boom(const Boom &) { throw 9; }
};

int main(int argc, char **argv) {
    if (argc > 1 && std::string(argv[1]) == "object_lifetimes") {
        std::atomic<unsigned> destroyed{0};
        std::atomic<bool> different{false};
        struct Threaded {
            std::thread::id constructor;
            std::atomic<unsigned> *destroyed;
            std::atomic<bool> *different;
            Threaded(std::atomic<unsigned> &count, std::atomic<bool> &other)
                : constructor(std::this_thread::get_id()), destroyed(&count), different(&other) {}
            ~Threaded() {
                different->store(constructor != std::this_thread::get_id());
                destroyed->fetch_add(1);
            }
        };
        auto value = std::make_unique<Threaded>(destroyed, different);
        auto worker = std::async(std::launch::async, [owned = std::move(value)]() mutable { owned.reset(); });
        worker.get();
        struct Plain { int value; };
        alignas(Plain) unsigned char bytes[sizeof(Plain)];
        Plain *old = ::new (bytes) Plain{1};
        ::new (bytes) Plain{42};
        int replaced = old->value;
        old->~Plain();
        std::atomic<unsigned> ended{0};
        struct Member { std::atomic<unsigned> *count; ~Member() { ++*count; } };
        struct Manual { Member member; explicit Manual(std::atomic<unsigned> &count) : member{&count} { member.~Member(); } };
        Manual *manual = new Manual(ended);
        ::operator delete(static_cast<void *>(manual));
        if (destroyed != 1 || !different || replaced != 42 || ended != 1) { return 7; }
        std::puts("object_threads=1 placement=42 ended_member=1");
        return 0;
    }
    if (argc > 1 && std::string(argv[1]) == "catch_copy") {
        std::set_terminate([] {
            std::puts("catch-copy-terminate");
            std::fflush(stdout);
            std::_Exit(73);
        });
        try { throw Boom{}; } catch (Boom value) { (void)value; }
        return 1;
    }
    try { Whole value; (void)value; } catch (int) {}
    if (trace != "ABa") {
        return 2;
    }
    unsigned matches = 0;
    try { throw Derived{}; } catch (const Base &) { ++matches; }
    try { throw Private{}; } catch (Base &) { return 3; } catch (...) { ++matches; }
    try { throw Ambiguous{}; } catch (Base &) { return 4; } catch (...) { ++matches; }
    try { throw nullptr; } catch (int Base::* pointer) { if (pointer == nullptr) { ++matches; } }
    try { throw static_cast<Derived *>(nullptr); } catch (Base *pointer) { if (pointer == nullptr) { ++matches; } }
    std::exception_ptr retained;
    try { throw Derived{}; } catch (...) { retained = std::current_exception(); }
    auto copied = std::async(std::launch::async, [retained] {
        try { std::rethrow_exception(retained); } catch (const Base &value) { return value.value; }
        return -1;
    });
    if (copied.get() != 3 || matches != 5) {
        return 5;
    }
    // A deliberately paused ordinary worker cannot block atomic_flag progress.
    std::promise<void> release;
    auto wait = release.get_future();
    auto blocked = std::async(std::launch::async, [&wait] { wait.wait(); });
    std::atomic_flag flag = ATOMIC_FLAG_INIT;
    auto progress = std::async(std::launch::async, [&flag] {
        for (unsigned index = 0; index < 100000; ++index) {
            if (flag.test_and_set(std::memory_order_seq_cst)) { return false; }
            if (!flag.test(std::memory_order_acquire)) { return false; }
            flag.clear(std::memory_order_release);
        }
        return true;
    });
    bool ready = progress.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
    release.set_value();
    blocked.get();
    if (!ready || !progress.get()) {
        return 6;
    }
    std::printf("trace=ABa catches=5 exception_ptr=3 flag_iterations=100000 flag_size=%zu\n", sizeof(flag));
}
