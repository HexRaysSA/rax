// SPDX-License-Identifier: MIT
//
// Nested exception unwinding, RAII cleanup, and variant visitation.

#include <array>
#include <cstdint>
#include <exception>
#include <iostream>
#include <type_traits>
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

std::uint64_t rotl64(std::uint64_t x, unsigned shift) {
    shift &= 63U;
    return shift == 0U ? x : ((x << shift) | (x >> (64U - shift)));
}

struct ScopeMark {
    std::uint64_t *trace;
    int *live;
    std::uint64_t tag;

    ScopeMark(std::uint64_t &trace_ref, int &live_ref, std::uint64_t tag_ref)
        : trace(&trace_ref), live(&live_ref), tag(tag_ref) {
        ++*live;
        *trace = mix64(*trace + tag + static_cast<std::uint64_t>(*live) * 17ULL);
    }

    ScopeMark(const ScopeMark &) = delete;
    ScopeMark &operator=(const ScopeMark &) = delete;

    ~ScopeMark() noexcept {
        const std::uint64_t unwinding = static_cast<std::uint64_t>(std::uncaught_exceptions());
        *trace = mix64((*trace ^ tag) + static_cast<std::uint64_t>(*live) * 31ULL + unwinding * 97ULL);
        --*live;
    }
};

struct Fault {
    std::uint32_t code;

    explicit Fault(std::uint32_t code_ref) : code(code_ref) {}
    virtual ~Fault() = default;

    virtual std::uint64_t value() const {
        return static_cast<std::uint64_t>(code) * 131ULL;
    }
};

struct PhaseFault final : Fault {
    std::uint32_t phase;

    PhaseFault(std::uint32_t code_ref, std::uint32_t phase_ref)
        : Fault(code_ref), phase(phase_ref) {}

    std::uint64_t value() const override {
        return static_cast<std::uint64_t>(code) * 257ULL + phase;
    }
};

struct RetryFault final : Fault {
    std::uint64_t token;

    RetryFault(std::uint32_t code_ref, std::uint64_t token_ref)
        : Fault(code_ref), token(token_ref) {}

    std::uint64_t value() const override {
        return token ^ (static_cast<std::uint64_t>(code) * 65537ULL);
    }
};

struct Atom {
    std::uint64_t value;
};

struct Pair {
    std::uint8_t left;
    std::uint8_t right;
    std::uint16_t salt;
};

struct Gate {
    std::uint8_t source;
    std::uint16_t mask;
};

struct Detour {
    std::uint8_t source;
    std::uint8_t span;
    std::uint32_t trip;
};

using Payload = std::variant<Atom, Pair, Gate, Detour>;

template <typename... F>
struct Overloaded : F... {
    using F::operator()...;
};

template <typename... F>
Overloaded(F...) -> Overloaded<F...>;

constexpr std::array<Payload, 8> make_payloads() {
    return {{
        Atom{0x1234ULL},
        Pair{0, 2, 19},
        Gate{1, 0x2d},
        Detour{2, 3, 0x40},
        Pair{3, 1, 71},
        Gate{4, 0x55},
        Detour{5, 2, 0x33},
        Atom{0x9e37ULL},
    }};
}

__attribute__((noinline))
std::uint64_t visit_payload(const Payload &payload,
                            const std::array<std::uint64_t, 8> &values,
                            std::uint64_t seed,
                            std::uint64_t &trace,
                            int &live,
                            std::size_t index,
                            int round) {
    ScopeMark scope(trace, live, 0x10000ULL + static_cast<std::uint64_t>(index * 31 + round));

    auto visitor = Overloaded{
        [&](const Atom &atom) -> std::uint64_t {
            const std::uint64_t out = mix64(atom.value + seed + static_cast<std::uint64_t>(round * 23));
            if (((out >> (index & 7U)) & 15ULL) == 5ULL && (round & 1) != 0) {
                throw PhaseFault(static_cast<std::uint32_t>(index + 11U), static_cast<std::uint32_t>(round));
            }
            return out;
        },
        [&](const Pair &pair) -> std::uint64_t {
            const std::uint64_t left = values[pair.left];
            const std::uint64_t right = values[pair.right];
            const std::uint64_t out = mix64((left + pair.salt) ^ rotl64(right + seed, pair.left + pair.right));
            if (((round + static_cast<int>(index) + pair.salt) % 7) == 0) {
                throw Fault(static_cast<std::uint32_t>(pair.salt + index));
            }
            return out;
        },
        [&](const Gate &gate) -> std::uint64_t {
            const std::uint64_t source = values[gate.source] ^ seed;
            if (((source + gate.mask + static_cast<std::uint64_t>(round)) & gate.mask) == 0ULL) {
                throw PhaseFault(static_cast<std::uint32_t>(gate.mask), static_cast<std::uint32_t>(index + round));
            }
            return rotl64(mix64(source + trace), gate.source + round);
        },
        [&](const Detour &detour) -> std::uint64_t {
            const std::uint64_t source = values[detour.source];
            if (((detour.trip + static_cast<std::uint32_t>(round + index)) & 3U) == 0U) {
                throw RetryFault(detour.trip + static_cast<std::uint32_t>(index), mix64(source + seed));
            }
            return mix64(source + trace + static_cast<std::uint64_t>(detour.span * 149U));
        },
    };

    return std::visit(visitor, payload);
}

__attribute__((noinline))
std::uint64_t recover_payload(const Fault &fault,
                              const Payload &payload,
                              std::uint64_t seed,
                              std::uint64_t &trace,
                              int &live,
                              int round) {
    ScopeMark scope(trace, live, 0x20000ULL + static_cast<std::uint64_t>(round));

    const std::uint64_t base = mix64(fault.value() + seed + trace);
    return std::visit([&](const auto &item) -> std::uint64_t {
        using Item = std::decay_t<decltype(item)>;
        if constexpr (std::is_same_v<Item, Atom>) {
            return mix64(base + item.value);
        } else if constexpr (std::is_same_v<Item, Pair>) {
            return rotl64(base ^ item.salt, item.left + item.right + round);
        } else if constexpr (std::is_same_v<Item, Gate>) {
            return mix64(base + item.mask + item.source);
        } else {
            return rotl64(base + item.trip, item.span + round);
        }
    }, payload);
}

__attribute__((noinline))
std::uint64_t descend(int depth, std::uint64_t seed, std::uint64_t &trace, int &live) {
    ScopeMark scope(trace, live, 0x30000ULL + static_cast<std::uint64_t>(depth));

    if (depth == 0) {
        throw PhaseFault(0x77U, static_cast<std::uint32_t>(seed & 31ULL));
    }

    try {
        const std::uint64_t child = descend(depth - 1, mix64(seed + static_cast<std::uint64_t>(depth)), trace, live);
        return mix64(child + seed + static_cast<std::uint64_t>(depth * 101));
    } catch (const PhaseFault &fault) {
        ScopeMark caught(trace, live, 0x40000ULL + static_cast<std::uint64_t>(depth));
        if ((depth & 1) != 0) {
            throw;
        }
        return mix64(fault.value() + seed + trace + static_cast<std::uint64_t>(depth));
    }
}

__attribute__((noinline))
std::uint64_t evaluate() {
    const auto payloads = make_payloads();
    std::array<std::uint64_t, payloads.size()> values{};
    std::uint64_t trace = 0x6a09e667f3bcc909ULL;
    std::uint64_t checksum = 0xbb67ae8584caa73bULL;
    int live = 0;

    for (int round = 0; round < 2; ++round) { /* rax: was 11 */
        ScopeMark round_scope(trace, live, 0x50000ULL + static_cast<std::uint64_t>(round));

        for (std::size_t i = 0; i < payloads.size(); ++i) {
            try {
                try {
                    values[i] = visit_payload(payloads[i], values, checksum ^ trace, trace, live, i, round);
                } catch (const RetryFault &fault) {
                    ScopeMark retry_scope(trace, live, 0x60000ULL + i);
                    if (((fault.code + static_cast<std::uint32_t>(round)) & 1U) == 0U) {
                        throw;
                    }
                    values[i] = recover_payload(fault, payloads[(i + 3U) % payloads.size()], checksum, trace, live, round);
                } catch (const Fault &fault) {
                    values[i] = recover_payload(fault, payloads[i], checksum, trace, live, round);
                }
            } catch (const Fault &fault) {
                ScopeMark outer_catch(trace, live, 0x70000ULL + i + static_cast<std::uint64_t>(round * 13));
                values[i] = mix64(fault.value() + checksum + values[(i + 7U) % values.size()]);
            }

            checksum = mix64(checksum ^ values[i] ^ trace ^ static_cast<std::uint64_t>(i * 4099 + round));
        }

        try {
            checksum ^= descend(3 + (round % 3), checksum, trace, live);
        } catch (const Fault &fault) {
            ScopeMark final_catch(trace, live, 0x80000ULL + static_cast<std::uint64_t>(round));
            checksum = mix64(checksum + fault.value() + trace);
        }
    }

    for (std::uint64_t value : values) {
        checksum = mix64(checksum + value + trace);
    }

    return checksum ^ trace ^ static_cast<std::uint64_t>(live);
}

} // namespace

int main() {
    const std::uint64_t checksum = evaluate();
    std::cout << "cpp_exception_variant_unwind " << checksum << '\n';
    return 0;
}
