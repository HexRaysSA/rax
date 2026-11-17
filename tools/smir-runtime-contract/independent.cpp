// Independent arithmetic/layout and real-host-thread protocol witnesses.
// These do not call RAX or execute portable SMIR or generated native code.
#include <algorithm>
#include <atomic>
#include <charconv>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

static void check(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

static std::uint64_t parse_unsigned(std::string_view value) {
    std::uint64_t result = 0;
    auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
    check(parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size(), "integer");
    return result;
}

static std::int64_t parse_signed(std::string_view value) {
    std::int64_t result = 0;
    auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
    check(parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size(), "integer");
    return result;
}

static int relocation(std::uint64_t base, std::int64_t addend, unsigned width) {
    check(width == 4 || width == 8, "width");
    std::uint64_t value;
    if (addend >= 0) {
        auto positive = static_cast<std::uint64_t>(addend);
        if (base > std::numeric_limits<std::uint64_t>::max() - positive) {
            std::cout << "OVERFLOW\n";
            return 2;
        }
        value = base + positive;
    } else {
        auto magnitude = static_cast<std::uint64_t>(-(addend + 1)) + 1;
        if (base < magnitude) {
            std::cout << "OVERFLOW\n";
            return 2;
        }
        value = base - magnitude;
    }
    if (width == 4 && value > std::numeric_limits<std::uint32_t>::max()) {
        std::cout << "OVERFLOW\n";
        return 2;
    }
    for (unsigned index = 0; index < width; ++index) {
        std::cout << std::hex << std::setfill('0') << std::setw(2)
                  << ((value >> (index * 8)) & 0xff);
    }
    std::cout << '\n';
    return 0;
}

static std::vector<unsigned char> unhex(std::string_view input) {
    check(input.size() % 2 == 0, "hex length");
    std::vector<unsigned char> bytes;
    for (std::size_t index = 0; index < input.size(); index += 2) {
        unsigned value = 0;
        auto parsed = std::from_chars(input.data() + index, input.data() + index + 2, value, 16);
        check(parsed.ec == std::errc{} && parsed.ptr == input.data() + index + 2, "hex");
        bytes.push_back(static_cast<unsigned char>(value));
    }
    return bytes;
}

static std::uint64_t little(const std::vector<unsigned char>& bytes,
                            std::size_t offset, unsigned width) {
    std::uint64_t result = 0;
    for (unsigned index = 0; index < width; ++index) {
        result |= static_cast<std::uint64_t>(bytes.at(offset + index)) << (index * 8);
    }
    return result;
}

static int locator(std::string_view input) {
    auto bytes = unhex(input);
    check(bytes.size() == 64, "locator size");
    const std::vector<unsigned char> magic = {'R', 'A', 'X', 'S', 'M', 'I', 'R', 0};
    check(std::equal(magic.begin(), magic.end(), bytes.begin()), "locator magic");
    check(little(bytes, 8, 2) == 1 && little(bytes, 10, 2) == 0 &&
          little(bytes, 12, 4) == 0, "locator flags");
    auto offset = little(bytes, 16, 8);
    auto length = little(bytes, 24, 8);
    check(length != 0 && offset <= std::numeric_limits<std::uint64_t>::max() - (length - 1),
          "locator overflow");
    std::cout << offset << ' ' << length << ' ';
    for (std::size_t index = 32; index < 64; ++index) {
        std::cout << std::hex << std::setfill('0') << std::setw(2)
                  << static_cast<unsigned>(bytes[index]);
    }
    std::cout << '\n';
    return 0;
}

struct ParallelMemory {
    std::mutex lifecycle;
    std::condition_variable changed;
    std::mutex backing;
    unsigned active = 0;
    unsigned arrived = 0;
    bool closed = false;
    bool release_workers = false;
    bool reclaimed = false;
    std::uint64_t value = 0;

    void worker() {
        {
            std::unique_lock lock(lifecycle);
            check(!closed && !reclaimed, "guard admission");
            ++active;
            ++arrived;
            changed.notify_all();
            changed.wait(lock, [&] { return release_workers; });
        }
        // The two guards alias one backing. They do not retain lifecycle locks
        // across execution. All accesses share backing identity serialization.
        for (unsigned index = 0; index < 10000; ++index) {
            std::lock_guard lock(backing);
            ++value;
        }
        {
            std::lock_guard lock(lifecycle);
            check(!reclaimed, "premature reuse");
            --active;
            changed.notify_all();
        }
    }
};

static void parallel_lifetime() {
    ParallelMemory memory;
    std::thread first([&] { memory.worker(); });
    std::thread second([&] { memory.worker(); });
    {
        std::unique_lock lock(memory.lifecycle);
        memory.changed.wait(lock, [&] { return memory.arrived == 2; });
        check(memory.active == 2, "parallel guest regions absent");
        memory.closed = true;
        check(!memory.reclaimed, "revocation reclaimed active aliases");
        memory.release_workers = true;
        memory.changed.notify_all();
        memory.changed.wait(lock, [&] { return memory.active == 0; });
        memory.reclaimed = true;
    }
    first.join();
    second.join();
    check(memory.value == 20000 && memory.reclaimed, "alias RMW/lifetime");
}

static void completion_races() {
    for (unsigned iteration = 0; iteration < 200; ++iteration) {
        // 0=pending, 1=completed, 2=cancelled. The successful CAS owns commit.
        std::atomic<unsigned> ticket{0};
        std::atomic<unsigned> arrived{0};
        std::atomic<bool> start{false};
        unsigned effects = 0;
        unsigned next_operation = 0;
        auto race = [&](unsigned desired) {
            arrived.fetch_add(1, std::memory_order_release);
            while (!start.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            unsigned expected = 0;
            if (ticket.compare_exchange_strong(expected, desired, std::memory_order_acq_rel)) {
                if (desired == 1) {
                    ++effects;
                }
                ++next_operation;
            }
        };
        std::thread completion(race, 1);
        std::thread cancellation(race, 2);
        while (arrived.load(std::memory_order_acquire) != 2) {
            std::this_thread::yield();
        }
        start.store(true, std::memory_order_release);
        completion.join();
        cancellation.join();
        check(next_operation == 1, "effect replay or lost completion");
        check(effects == (ticket.load() == 1 ? 1u : 0u), "commit ownership");
    }
}

int main(int argc, char** argv) {
    try {
        if (argc == 5 && std::string_view(argv[1]) == "relocate") {
            auto width = parse_unsigned(argv[4]);
            check(width == 4 || width == 8, "width");
            return relocation(parse_unsigned(argv[2]), parse_signed(argv[3]),
                              static_cast<unsigned>(width));
        }
        if (argc == 3 && std::string_view(argv[1]) == "locator") {
            return locator(argv[2]);
        }
        check(argc == 2 && std::string_view(argv[1]) == "parallel", "arguments");
        parallel_lifetime();
        completion_races();
        std::cout << "parallel_workers=2 alias_updates=20000 completion_races=200 passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 2;
    }
}
