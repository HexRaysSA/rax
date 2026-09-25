// SPDX-License-Identifier: MIT
//
// Consteval tuple-generated automaton with runtime checksum folding.

#include <array>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <tuple>
#include <type_traits>
#include <utility>

namespace {

constexpr std::size_t StateCount = 8;
constexpr std::size_t Alphabet = 6;
constexpr std::size_t InputCount = 97;

constexpr std::uint64_t rotl64(std::uint64_t value, unsigned shift) {
    shift &= 63U;
    return shift == 0U ? value : ((value << shift) | (value >> (64U - shift)));
}

constexpr std::uint64_t mix64(std::uint64_t value) {
    value ^= value >> 31;
    value *= 0x7fb5d329728ea185ULL;
    value ^= value >> 27;
    value *= 0x81dadef4bc2dd44dULL;
    value ^= value >> 33;
    return value;
}

template <std::size_t Id, std::uint32_t Bias, std::uint32_t Mask, bool Accepting>
struct State {
    static constexpr std::size_t id = Id;
    static constexpr bool accepting = Accepting;

    static consteval std::uint8_t next(std::size_t symbol) {
        std::uint32_t x = static_cast<std::uint32_t>((symbol + 1U) * Bias + Id * 17U);
        x ^= (x << ((Id % 5U) + 1U)) ^ (Mask + static_cast<std::uint32_t>(symbol * symbol * 11U));
        x += (Accepting ? 29U : 7U) + static_cast<std::uint32_t>(Id * symbol);
        return static_cast<std::uint8_t>((x ^ (x >> 4U) ^ (x >> 9U)) % StateCount);
    }

    static consteval std::uint32_t emit(std::size_t symbol) {
        std::uint32_t x = Bias ^ (Mask * 33U) ^ static_cast<std::uint32_t>((Id + 3U) * (symbol + 5U));
        x = (x << ((symbol % 4U) + 1U)) ^ (x >> ((Id % 3U) + 1U)) ^ (Bias * 131U);
        return x + static_cast<std::uint32_t>(Accepting ? 0x5aU : 0xc3U);
    }
};

using MachineSpec = std::tuple<
    State<0, 13, 0x21, true>,
    State<1, 29, 0x56, false>,
    State<2, 37, 0xa3, false>,
    State<3, 43, 0x7c, true>,
    State<4, 61, 0x35, false>,
    State<5, 73, 0xe1, true>,
    State<6, 89, 0x49, false>,
    State<7, 97, 0xb6, true>>;

struct MachineTables {
    std::array<std::uint8_t, StateCount * Alphabet> next{};
    std::array<std::uint32_t, StateCount * Alphabet> emit{};
    std::array<std::uint8_t, StateCount> accepting{};
    std::array<std::uint64_t, StateCount> row_salt{};
};

template <typename StateType, std::size_t... Symbols>
consteval void fill_row(MachineTables &tables, std::index_sequence<Symbols...>) {
    using S = std::remove_cvref_t<StateType>;
    tables.accepting[S::id] = S::accepting ? 1U : 0U;
    tables.row_salt[S::id] = mix64(static_cast<std::uint64_t>(S::id + 1U) * 0x9e3779b185ebca87ULL);
    ((tables.next[S::id * Alphabet + Symbols] = S::next(Symbols),
      tables.emit[S::id * Alphabet + Symbols] = S::emit(Symbols)),
     ...);
}

template <typename... States>
consteval MachineTables build_tables(std::tuple<States...> states) {
    MachineTables tables{};
    std::apply(
        [&]<typename... Ts>(Ts... unpacked) {
            (fill_row<Ts>(tables, std::make_index_sequence<Alphabet>{}), ...);
            (void)sizeof...(unpacked);
        },
        states);
    return tables;
}

template <std::size_t... I>
consteval std::array<std::uint8_t, sizeof...(I)> build_input(std::index_sequence<I...>) {
    return {{
        static_cast<std::uint8_t>(((I * I + 3U * I + 7U) ^ (I >> 1U) ^ (I << (I % 3U))) % Alphabet)...,
    }};
}

constexpr MachineTables Tables = build_tables(MachineSpec{});
constexpr auto Input = build_input(std::make_index_sequence<InputCount>{});

consteval std::uint64_t table_fingerprint() {
    std::uint64_t value = 0x1f123bb5a77d90abULL;
    for (std::size_t i = 0; i < Tables.next.size(); ++i) {
        value = mix64(value + Tables.next[i] * 257ULL + Tables.emit[i] * (i + 11ULL));
    }
    for (std::size_t i = 0; i < Tables.accepting.size(); ++i) {
        value ^= rotl64(Tables.row_salt[i] + Tables.accepting[i] * 0x10101ULL, static_cast<unsigned>(i + 3U));
    }
    return value;
}

constexpr std::uint64_t Fingerprint = table_fingerprint();
static_assert(Fingerprint != 0);
static_assert(Tables.next.size() == StateCount * Alphabet);

__attribute__((noinline))
std::uint64_t run_automaton(std::uint8_t &final_state) {
    std::array<std::uint16_t, StateCount> visits{};
    std::uint64_t checksum = Fingerprint;
    std::uint8_t state = 0;
    std::uint8_t shadow = 3;

    for (std::size_t round = 0; round < 11; ++round) {
        for (std::size_t i = 0; i < Input.size(); ++i) {
            const std::uint8_t raw = Input[(i * 17U + round * 5U) % Input.size()];
            const std::uint8_t symbol = static_cast<std::uint8_t>((raw + state + shadow + round) % Alphabet);
            const std::size_t offset = static_cast<std::size_t>(state) * Alphabet + symbol;
            const std::uint8_t next = Tables.next[offset];
            const std::uint64_t emitted = Tables.emit[offset] + Tables.row_salt[next];

            if (Tables.accepting[next] != 0U) {
                checksum = mix64(rotl64(checksum ^ emitted, static_cast<unsigned>((symbol + round) & 31U)));
            } else if (((emitted + checksum + i) & 3ULL) == 0ULL) {
                checksum ^= mix64(emitted + static_cast<std::uint64_t>(state * 4099U + next));
            } else {
                checksum = mix64(checksum + emitted + static_cast<std::uint64_t>(symbol * 97U));
            }

            ++visits[next];
            shadow = static_cast<std::uint8_t>((shadow + next + symbol + (checksum & 7ULL)) % StateCount);
            state = static_cast<std::uint8_t>((next ^ (shadow & 1U)) % StateCount);
        }
    }

    for (std::size_t i = 0; i < visits.size(); ++i) {
        const std::uint64_t folded = static_cast<std::uint64_t>(visits[i]) * (i + 19ULL);
        checksum = mix64(checksum ^ folded ^ Tables.row_salt[i]);
    }

    final_state = state;
    return checksum ^ static_cast<std::uint64_t>(shadow);
}

} // namespace

int main() {
    std::uint8_t state = 0;
    const std::uint64_t checksum = run_automaton(state);
    std::printf("cpp_consteval_tuple_automaton %" PRIu64 " %u\n", checksum, static_cast<unsigned>(state));
    return 0;
}
