// SPDX-License-Identifier: MIT
//
// Constexpr graph metadata with runtime variant visitation and virtual rules.

#include <array>
#include <cstdint>
#include <iostream>
#include <memory>
#include <variant>
#include <vector>

namespace {

constexpr std::size_t NodeCount = 9;
constexpr std::size_t EdgeCount = 15;
constexpr std::uint16_t Inf = 0x3fff;

struct Edge {
    std::uint8_t from;
    std::uint8_t to;
    std::uint16_t weight;
};

constexpr std::array<Edge, EdgeCount> Edges{{
    {0, 1, 3}, {0, 2, 8}, {1, 3, 2}, {1, 4, 7}, {2, 4, 1},
    {2, 5, 6}, {3, 6, 4}, {4, 3, 5}, {4, 6, 2}, {4, 7, 9},
    {5, 7, 3}, {6, 8, 6}, {7, 6, 1}, {7, 8, 4}, {2, 8, 15},
}};

constexpr std::uint64_t mix64(std::uint64_t x) {
    x ^= x >> 32;
    x *= 0xd6e8feb86659fd93ULL;
    x ^= x >> 32;
    x *= 0xd6e8feb86659fd93ULL;
    x ^= x >> 32;
    return x;
}

constexpr std::uint64_t rotl64(std::uint64_t x, unsigned shift) {
    shift &= 63U;
    return shift == 0U ? x : ((x << shift) | (x >> (64U - shift)));
}

constexpr std::array<std::uint16_t, NodeCount * NodeCount> compute_distances() {
    std::array<std::uint16_t, NodeCount * NodeCount> dist{};

    for (std::size_t i = 0; i < dist.size(); ++i) {
        dist[i] = Inf;
    }
    for (std::size_t i = 0; i < NodeCount; ++i) {
        dist[i * NodeCount + i] = 0;
    }
    for (const Edge edge : Edges) {
        dist[edge.from * NodeCount + edge.to] = edge.weight;
    }

    for (std::size_t k = 0; k < NodeCount; ++k) {
        for (std::size_t i = 0; i < NodeCount; ++i) {
            for (std::size_t j = 0; j < NodeCount; ++j) {
                const std::uint16_t via = static_cast<std::uint16_t>(
                    dist[i * NodeCount + k] + dist[k * NodeCount + j]);
                if (via < dist[i * NodeCount + j]) {
                    dist[i * NodeCount + j] = via;
                }
            }
        }
    }

    return dist;
}

constexpr auto Distances = compute_distances();

consteval std::uint64_t compile_seed() {
    std::uint64_t seed = 0x7f4a7c159e3779b9ULL;
    for (std::size_t i = 0; i < Distances.size(); ++i) {
        seed = mix64(seed + static_cast<std::uint64_t>(Distances[i]) * (i + 11ULL));
    }
    return seed;
}

constexpr std::uint64_t CompileSeed = compile_seed();

static_assert(Distances[0 * NodeCount + 8] == 15);
static_assert(Distances[5 * NodeCount + 8] == 7);

struct Literal {
    std::uint64_t value;
};

struct Combine {
    std::uint8_t left;
    std::uint8_t right;
    std::uint32_t bias;
};

struct Gate {
    std::uint8_t source;
    std::uint16_t mask;
};

struct Delay {
    std::uint8_t source;
    std::uint8_t span;
};

using Payload = std::variant<Literal, Combine, Gate, Delay>;

template <typename... F>
struct Overloaded : F... {
    using F::operator()...;
};

template <typename... F>
Overloaded(F...) -> Overloaded<F...>;

struct ScopeTrace {
    std::uint64_t *checksum;
    int *depth;
    std::uint64_t tag;

    ScopeTrace(std::uint64_t &checksum_ref, int &depth_ref, std::uint64_t tag_ref)
        : checksum(&checksum_ref), depth(&depth_ref), tag(tag_ref) {
        ++*depth;
        *checksum = mix64(*checksum + tag + static_cast<std::uint64_t>(*depth));
    }

    ScopeTrace(const ScopeTrace &) = delete;
    ScopeTrace &operator=(const ScopeTrace &) = delete;

    ~ScopeTrace() {
        *checksum = mix64(*checksum ^ (tag + static_cast<std::uint64_t>(*depth) * 23ULL));
        --*depth;
    }
};

class Rule {
public:
    virtual ~Rule() = default;
    virtual std::uint64_t apply(std::size_t node, std::uint64_t value, std::uint64_t salt) const = 0;
};

class AffineRule final : public Rule {
public:
    std::uint64_t apply(std::size_t node, std::uint64_t value, std::uint64_t salt) const override {
        return mix64(value + salt + node * 0x45d9f3bULL);
    }
};

class GateRule final : public Rule {
public:
    std::uint64_t apply(std::size_t node, std::uint64_t value, std::uint64_t salt) const override {
        const std::uint16_t d = Distances[node * NodeCount + (NodeCount - 1)];
        const std::uint64_t folded = d == Inf ? value ^ salt : value + static_cast<std::uint64_t>(d * 131);
        return rotl64(folded, static_cast<unsigned>((node + d) & 15U));
    }
};

class RuleSet {
public:
    RuleSet() {
        rules_.push_back(std::make_unique<AffineRule>());
        rules_.push_back(std::make_unique<GateRule>());
    }

    std::uint64_t apply(std::size_t node, std::uint64_t value, std::uint64_t salt) const {
        std::uint64_t result = value;
        for (const auto &rule : rules_) {
            result = rule->apply(node, result, salt);
        }
        return result;
    }

private:
    std::vector<std::unique_ptr<Rule>> rules_;
};

std::array<Payload, NodeCount> make_payloads() {
    return {{
        Literal{17},
        Combine{0, 2, 41},
        Gate{0, 0x31},
        Delay{1, 3},
        Combine{2, 3, 97},
        Literal{29},
        Gate{4, 0x57},
        Delay{5, 5},
        Combine{6, 7, 193},
    }};
}

template <typename Select>
std::uint64_t summarize(const std::array<std::uint64_t, NodeCount> &values, Select select) {
    std::uint64_t out = 0x243f6a8885a308d3ULL;
    for (std::size_t i = 0; i < values.size(); ++i) {
        out = mix64(out + select(i, values[i]) + static_cast<std::uint64_t>(i * 313));
    }
    return out;
}

__attribute__((noinline))
std::uint64_t evaluate_graph() {
    const RuleSet rules;
    auto payloads = make_payloads();
    std::array<std::uint64_t, NodeCount> values{};
    std::uint64_t checksum = CompileSeed;
    int depth = 0;

    ScopeTrace root(checksum, depth, 0x10000ULL);

    for (std::size_t round = 0; round < 7; ++round) {
        ScopeTrace round_scope(checksum, depth, 0x20000ULL + round);

        for (std::size_t node = 0; node < NodeCount; ++node) {
            ScopeTrace node_scope(checksum, depth, 0x30000ULL + node + round * 17ULL);
            std::uint64_t incoming = 0;

            for (const Edge edge : Edges) {
                if (edge.to == node) {
                    incoming ^= rotl64(values[edge.from] + edge.weight + round, edge.weight);
                }
            }

            auto visitor = Overloaded{
                [&](const Literal &literal) {
                    return mix64(literal.value + incoming + round * 13ULL);
                },
                [&](const Combine &combine) {
                    const std::uint64_t left = values[combine.left];
                    const std::uint64_t right = values[combine.right];
                    return mix64((left * 3ULL) ^ rotl64(right + combine.bias, combine.left + combine.right));
                },
                [&](const Gate &gate) {
                    const std::uint64_t source = values[gate.source];
                    const bool open = ((source + incoming + gate.mask + round) & gate.mask) != 0ULL;
                    return open ? mix64(source + incoming) : mix64(incoming ^ gate.mask);
                },
                [&](const Delay &delay) {
                    const std::uint16_t distance = Distances[delay.source * NodeCount + node];
                    const std::uint64_t base = values[delay.source] + static_cast<std::uint64_t>(delay.span * 17);
                    return distance == Inf ? mix64(base ^ incoming) : mix64(base + distance + incoming);
                },
            };

            const std::uint64_t raw = std::visit(visitor, payloads[node]);
            values[node] = rules.apply(node, raw, checksum ^ (round << 8));
            checksum ^= mix64(values[node] + incoming + static_cast<std::uint64_t>(node * 101 + round));
        }
    }

    checksum ^= summarize(values, [&](std::size_t node, std::uint64_t value) {
        const std::uint16_t distance = Distances[node * NodeCount + (NodeCount - 1)];
        return distance == Inf ? value : value + static_cast<std::uint64_t>(distance * 1009);
    });

    return checksum ^ static_cast<std::uint64_t>(depth);
}

} // namespace

int main() {
    const std::uint64_t checksum = evaluate_graph();
    std::cout << "cpp_constexpr_variant_graph " << checksum << '\n';
    return 0;
}
