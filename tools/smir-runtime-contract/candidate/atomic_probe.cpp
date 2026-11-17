// Independent arbitrary-byte arithmetic and atomic_flag/large-SC witnesses.
#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using Bytes = std::vector<std::uint8_t>;
static void check(bool value, const char* message) {
    if (!value) { throw std::runtime_error(message); }
}
static Bytes hex(std::string_view input) {
    check(!input.empty() && input.size() % 2 == 0 && input.size() <= 2097152, "hex extent");
    Bytes result;
    for (std::size_t i = 0; i < input.size(); i += 2) {
        unsigned byte = 0;
        auto parsed = std::from_chars(input.data() + i, input.data() + i + 2, byte, 16);
        check(parsed.ec == std::errc{} && parsed.ptr == input.data() + i + 2, "hex syntax");
        result.push_back(static_cast<std::uint8_t>(byte));
    }
    return result;
}
static void trim(Bytes& value, std::size_t bits) {
    for (std::size_t i = (bits + 7) / 8; i < value.size(); ++i) { value[i] = 0; }
    if (bits % 8) { value[bits / 8] &= (1u << (bits % 8)) - 1; }
}
static int compare(const Bytes& a, const Bytes& b) {
    for (std::size_t i = a.size(); i > 0; --i) {
        if (a[i - 1] != b[i - 1]) { return a[i - 1] < b[i - 1] ? -1 : 1; }
    }
    return 0;
}
static Bytes add(const Bytes& a, const Bytes& b, bool subtract) {
    Bytes result(a.size());
    unsigned carry = subtract ? 1 : 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        unsigned sum = a[i] + (subtract ? unsigned(b[i] ^ 255) : unsigned(b[i])) + carry;
        result[i] = static_cast<std::uint8_t>(sum);
        carry = sum >> 8;
    }
    return result;
}
static Bytes rmw(std::string_view operation, Bytes a, Bytes b, std::size_t bits) {
    check(a.size() == b.size() && bits > 0 && bits <= a.size() * 8, "precision");
    trim(a, bits);
    trim(b, bits);
    Bytes result(a.size()), one(a.size());
    one[0] = 1;
    auto unsigned_order = compare(a, b);
    bool negative_a = (a[(bits - 1) / 8] >> ((bits - 1) % 8)) & 1;
    bool negative_b = (b[(bits - 1) / 8] >> ((bits - 1) % 8)) & 1;
    auto signed_order = negative_a == negative_b ? unsigned_order : (negative_a ? -1 : 1);
    bool zero = std::all_of(a.begin(), a.end(), [](auto byte) { return byte == 0; });
    if (operation == "add") { result = add(a, b, false); }
    else if (operation == "sub") { result = add(a, b, true); }
    else if (operation == "umin") { result = unsigned_order < 0 ? a : b; }
    else if (operation == "umax") { result = unsigned_order > 0 ? a : b; }
    else if (operation == "smin") { result = signed_order < 0 ? a : b; }
    else if (operation == "smax") { result = signed_order > 0 ? a : b; }
    else if (operation == "uinc_wrap") { result = unsigned_order >= 0 ? result : add(a, one, false); }
    else if (operation == "udec_wrap") { result = zero || unsigned_order > 0 ? b : add(a, one, true); }
    else if (operation == "usub_cond") { result = unsigned_order >= 0 ? add(a, b, true) : a; }
    else if (operation == "usub_sat") { result = unsigned_order >= 0 ? add(a, b, true) : result; }
    else {
        check(operation == "and" || operation == "or" || operation == "xor" || operation == "nand", "operation");
        for (std::size_t i = 0; i < a.size(); ++i) {
            if (operation == "and") { result[i] = a[i] & b[i]; }
            else if (operation == "or") { result[i] = a[i] | b[i]; }
            else if (operation == "xor") { result[i] = a[i] ^ b[i]; }
            else { result[i] = static_cast<std::uint8_t>(~(a[i] & b[i])); }
        }
    }
    trim(result, bits);
    return result;
}
struct Flag {
    // Canonical guest flag byte; header remains allocated until all lookup
    // epochs retire. No shadow/alias copy of value exists in another buffer.
    std::atomic<std::uint8_t> value{0};
    std::atomic<std::uint64_t> pins{0};
    std::atomic<bool> live{true};
    bool enter() {
        if (!live.load(std::memory_order_seq_cst)) { return false; }
        pins.fetch_add(1, std::memory_order_seq_cst);
        if (!live.load(std::memory_order_seq_cst)) {
            pins.fetch_sub(1, std::memory_order_seq_cst);
            return false;
        }
        return true;
    }
    bool test_set() {
        check(enter(), "flag lifetime");
        auto old = value.exchange(1, std::memory_order_seq_cst);
        pins.fetch_sub(1, std::memory_order_seq_cst);
        return old != 0;
    }
    void clear() {
        check(enter(), "flag lifetime");
        value.store(0, std::memory_order_seq_cst);
        pins.fetch_sub(1, std::memory_order_seq_cst);
    }
    bool test() {
        check(enter(), "flag lifetime");
        auto result = value.load(std::memory_order_seq_cst);
        pins.fetch_sub(1, std::memory_order_seq_cst);
        return result != 0;
    }
};
struct Large {
    std::mutex generic_sc;
    Bytes bytes = Bytes(33);
    void store(unsigned value) {
        std::lock_guard lock(generic_sc);
        std::atomic_thread_fence(std::memory_order_seq_cst);
        bytes[0] = static_cast<std::uint8_t>(value);
        std::atomic_thread_fence(std::memory_order_seq_cst);
    }
    unsigned load() {
        std::lock_guard lock(generic_sc);
        std::atomic_thread_fence(std::memory_order_seq_cst);
        auto result = bytes[0];
        std::atomic_thread_fence(std::memory_order_seq_cst);
        return result;
    }
};
static void flag_progress() {
    Flag flag;
    check(flag.value.is_lock_free() && flag.pins.is_lock_free() && flag.live.is_lock_free(), "native primitive not lock-free");
    Large large;
    std::atomic<bool> owner_ready{false}, release_owner{false}, flag_done{false};
    std::thread paused([&] {
        std::lock_guard held(large.generic_sc);
        owner_ready.store(true);
        while (!release_owner.load()) { std::this_thread::yield(); }
    });
    while (!owner_ready.load()) { std::this_thread::yield(); }
    std::thread worker([&] {
        for (unsigned i = 0; i < 100000; ++i) {
            check(!flag.test_set() && flag.test(), "flag coherence");
            flag.clear();
        }
        flag_done.store(true);
    });
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (!flag_done.load() && std::chrono::steady_clock::now() < deadline) { std::this_thread::yield(); }
    bool progressed = flag_done.load();
    release_owner.store(true);
    paused.join();
    worker.join();
    check(progressed, "flag depended on paused generic lock owner");
    check(flag.enter(), "guard");
    flag.live.store(false);
    check(flag.pins.load() == 1 && !flag.enter(), "revocation admitted reader or reclaimed pin");
    flag.pins.fetch_sub(1);
    check(flag.pins.load() == 0, "pin release");
}
static void mixed_sc() {
    unsigned forbidden = 0;
    for (unsigned iteration = 0; iteration < 1000; ++iteration) {
        Flag flag;
        Large large;
        std::atomic<unsigned> arrived{0};
        std::atomic<bool> start{false};
        unsigned a = 0, b = 0;
        auto barrier = [&] {
            arrived.fetch_add(1);
            while (!start.load()) { std::this_thread::yield(); }
        };
        std::thread first([&] { barrier(); large.store(1); a = flag.test(); });
        std::thread second([&] { barrier(); flag.test_set(); b = large.load(); });
        while (arrived.load() != 2) { std::this_thread::yield(); }
        start.store(true);
        first.join();
        second.join();
        forbidden += a == 0 && b == 0;
    }
    check(forbidden == 0, "mixed SC store-buffering cycle");
}
int main(int argc, char** argv) {
    try {
        if (argc == 6 && std::string_view(argv[1]) == "rmw") {
            std::size_t bits = 0;
            std::string_view text(argv[3]);
            auto parsed = std::from_chars(text.data(), text.data() + text.size(), bits);
            check(parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size(), "bits");
            auto result = rmw(argv[2], hex(argv[4]), hex(argv[5]), bits);
            for (auto byte : result) { std::cout << std::hex << std::setw(2) << std::setfill('0') << unsigned(byte); }
            std::cout << '\n';
        } else {
            check(argc == 2 && std::string_view(argv[1]) == "flag", "arguments");
            flag_progress();
            mixed_sc();
            std::cout << "flag_hot_operations=300000 paused_generic_owner_progress=passed mixed_sc_trials=1000 forbidden=0\n";
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 2;
    }
}
