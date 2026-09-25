// SPDX-License-Identifier: MIT
//
// Coroutine frame lifetime and RAII checksum test.

#include <array>
#include <coroutine>
#include <cstdint>
#include <exception>
#include <iostream>
#include <type_traits>
#include <utility>
#include <variant>

namespace {

std::uint64_t mix64(std::uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

struct LifetimeLog {
    std::uint64_t *trace;
    int *live;
    std::uint64_t tag;

    LifetimeLog(std::uint64_t &trace_ref, int &live_ref, std::uint64_t tag_ref)
        : trace(&trace_ref), live(&live_ref), tag(tag_ref) {
        ++*live;
        *trace = mix64(*trace + tag + static_cast<std::uint64_t>(*live) * 17ULL);
    }

    LifetimeLog(const LifetimeLog &) = delete;
    LifetimeLog &operator=(const LifetimeLog &) = delete;

    ~LifetimeLog() {
        *trace = mix64(*trace ^ (tag + 0x9e3779b97f4a7c15ULL + static_cast<std::uint64_t>(*live)));
        --*live;
    }
};

struct ValueEvent {
    int depth = 0;
    std::uint64_t value = 0;
};

struct ForkEvent {
    std::uint64_t left = 0;
    std::uint64_t right = 0;
};

struct MarkerEvent {
    int live = 0;
    std::uint64_t trace_low = 0;
};

using Event = std::variant<ValueEvent, ForkEvent, MarkerEvent>;

template <typename T>
class Generator {
public:
    struct promise_type {
        T current{};

        Generator get_return_object() {
            return Generator(std::coroutine_handle<promise_type>::from_promise(*this));
        }

        std::suspend_always initial_suspend() noexcept { return {}; }
        std::suspend_always final_suspend() noexcept { return {}; }
        void return_void() noexcept {}

        std::suspend_always yield_value(T value) noexcept {
            current = std::move(value);
            return {};
        }

        void unhandled_exception() { std::terminate(); }
    };

    explicit Generator(std::coroutine_handle<promise_type> handle) : handle_(handle) {}
    Generator(const Generator &) = delete;
    Generator &operator=(const Generator &) = delete;

    Generator(Generator &&other) noexcept : handle_(other.handle_) {
        other.handle_ = {};
    }

    Generator &operator=(Generator &&other) noexcept {
        if (this != &other) {
            if (handle_) {
                handle_.destroy();
            }
            handle_ = other.handle_;
            other.handle_ = {};
        }
        return *this;
    }

    ~Generator() {
        if (handle_) {
            handle_.destroy();
        }
    }

    bool next() {
        if (!handle_ || handle_.done()) {
            return false;
        }
        handle_.resume();
        return !handle_.done();
    }

    const T &value() const {
        return handle_.promise().current;
    }

private:
    std::coroutine_handle<promise_type> handle_;
};

__attribute__((noinline))
Generator<Event> make_events(int seed, int rounds, std::uint64_t &trace, int &live) {
    LifetimeLog frame(trace, live, 0x1000ULL + static_cast<std::uint64_t>(seed));

    auto transform = [bias = static_cast<std::uint64_t>(seed * 131 + 7)](int step, int depth) {
        std::uint64_t x = bias + static_cast<std::uint64_t>(step * 97 + depth * 53);
        return mix64(x ^ (x << ((step % 5) + 1)));
    };

    for (int step = 0; step < rounds; ++step) {
        LifetimeLog iteration(trace, live, 0x2000ULL + static_cast<std::uint64_t>(seed * 31 + step));
        std::uint64_t value = transform(step, live) ^ trace;

        if ((value + static_cast<std::uint64_t>(step)) % 3ULL == 0ULL) {
            co_yield ForkEvent{mix64(value + 11ULL), mix64(value + 29ULL)};
        } else {
            co_yield ValueEvent{live + step, value};
        }

        if ((step & 1) == 0) {
            LifetimeLog nested(trace, live, 0x3000ULL + static_cast<std::uint64_t>(step + seed));
            co_yield MarkerEvent{live, trace & 0xffffULL};
        }
    }
}

struct StepAwaiter {
    std::uint64_t input;
    std::uint64_t *trace;

    bool await_ready() const noexcept {
        return (input & 7ULL) == 0ULL;
    }

    bool await_suspend(std::coroutine_handle<>) const noexcept {
        *trace = mix64(*trace + input + 0x51ed270bULL);
        return (input & 1ULL) != 0ULL;
    }

    std::uint64_t await_resume() const noexcept {
        return mix64(input ^ 0xa5a5a5a5a5a5a5a5ULL);
    }
};

class Task {
public:
    struct promise_type {
        std::uint64_t result = 0;

        Task get_return_object() {
            return Task(std::coroutine_handle<promise_type>::from_promise(*this));
        }

        std::suspend_always initial_suspend() noexcept { return {}; }
        std::suspend_always final_suspend() noexcept { return {}; }
        void return_value(std::uint64_t value) noexcept { result = value; }
        void unhandled_exception() { std::terminate(); }
    };

    explicit Task(std::coroutine_handle<promise_type> handle) : handle_(handle) {}
    Task(const Task &) = delete;
    Task &operator=(const Task &) = delete;

    Task(Task &&other) noexcept : handle_(other.handle_) {
        other.handle_ = {};
    }

    ~Task() {
        if (handle_) {
            handle_.destroy();
        }
    }

    std::uint64_t run() {
        while (handle_ && !handle_.done()) {
            handle_.resume();
        }
        return handle_.promise().result;
    }

private:
    std::coroutine_handle<promise_type> handle_;
};

__attribute__((noinline))
Task fold_with_awaits(const std::array<int, 8> seeds, std::uint64_t &trace, int &live) {
    LifetimeLog frame(trace, live, 0x4000ULL);
    std::uint64_t total = 0;

    for (std::size_t i = 0; i < seeds.size(); ++i) {
        LifetimeLog step(trace, live, 0x5000ULL + static_cast<std::uint64_t>(i));
        std::uint64_t input = trace ^ static_cast<std::uint64_t>(seeds[i] * 257 + static_cast<int>(i));
        std::uint64_t awaited = co_await StepAwaiter{input, &trace};
        total ^= mix64(awaited + static_cast<std::uint64_t>(live * 13 + seeds[i]));
    }

    co_return total ^ trace;
}

template <typename Visitor>
std::uint64_t consume_events(Generator<Event> events, int max_events, Visitor visitor) {
    std::uint64_t checksum = 0x6d2b79f5ULL;
    int consumed = 0;

    while (consumed < max_events && events.next()) {
        checksum = mix64(checksum + std::visit(visitor, events.value()) + static_cast<std::uint64_t>(consumed));
        ++consumed;
    }

    return checksum ^ static_cast<std::uint64_t>(consumed * 4099);
}

} // namespace

int main() {
    std::uint64_t trace = 0x123456789abcdef0ULL;
    int live = 0;
    std::uint64_t checksum = 0;

    auto visitor = [&checksum](const auto &event) -> std::uint64_t {
        using EventType = std::decay_t<decltype(event)>;
        if constexpr (std::is_same_v<EventType, ValueEvent>) {
            return mix64(event.value + static_cast<std::uint64_t>(event.depth * 19));
        } else if constexpr (std::is_same_v<EventType, ForkEvent>) {
            return mix64(event.left ^ (event.right + 0x9e3779b97f4a7c15ULL));
        } else {
            checksum ^= mix64(event.trace_low + static_cast<std::uint64_t>(event.live * 101));
            return checksum;
        }
    };

    for (int seed = 1; seed <= 12; ++seed) {
        auto events = make_events(seed, 5 + (seed % 4), trace, live);
        checksum ^= consume_events(std::move(events), 32, visitor);

        if ((seed % 3) == 0) {
            auto cancelled = make_events(seed + 40, 9, trace, live);
            for (int i = 0; i < 3 && cancelled.next(); ++i) {
                checksum += std::visit(visitor, cancelled.value());
            }
        }
    }

    auto task = fold_with_awaits({3, 1, 4, 1, 5, 9, 2, 6}, trace, live);
    checksum ^= task.run();
    checksum = mix64(checksum ^ trace ^ static_cast<std::uint64_t>(live));

    std::cout << "cpp_coroutine_lifetime " << checksum << ' ' << live << '\n';
    return live == 0 ? 0 : 1;
}
