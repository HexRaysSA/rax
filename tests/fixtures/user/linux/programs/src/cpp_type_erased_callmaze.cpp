// SPDX-License-Identifier: MIT
//
// Inline type-erased callable maze with lambdas, member pointers, and function pointers.

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <new>
#include <type_traits>
#include <utility>

namespace {

std::uint64_t mix64(std::uint64_t x) {
    x ^= x >> 32;
    x *= 0xd6e8feb86659fd93ULL;
    x ^= x >> 32;
    x *= 0xd6e8feb86659fd93ULL;
    x ^= x >> 32;
    return x;
}

std::uint64_t rotl64(std::uint64_t x, unsigned shift) {
    shift &= 63U;
    return shift == 0U ? x : ((x << shift) | (x >> (64U - shift)));
}

__attribute__((noinline))
std::uint64_t plain_scramble(std::uint64_t value, int step) {
    return mix64(value + static_cast<std::uint64_t>(step * 0x45d9f3b));
}

__attribute__((noinline))
std::uint64_t plain_gate(std::uint64_t value, int step) {
    const std::uint64_t mask = 0x9e3779b97f4a7c15ULL + static_cast<std::uint64_t>(step * 17);
    return ((value + mask) & 1ULL) == 0ULL ? rotl64(value ^ mask, step) : mix64(value + mask);
}

class SmallOp {
public:
    using Call = std::uint64_t (*)(const void *, std::uint64_t, int);
    using Copy = void (*)(void *, const void *);
    using Destroy = void (*)(void *);

    template <typename F>
    explicit SmallOp(F callable) {
        using Fn = std::decay_t<F>;
        static_assert(sizeof(Fn) <= StorageSize);
        static_assert(alignof(Fn) <= alignof(Storage));
        std::construct_at(ptr<Fn>(), std::move(callable));
        table_ = &table_for<Fn>();
    }

    SmallOp(const SmallOp &other) : table_(other.table_) {
        table_->copy(&storage_, &other.storage_);
    }

    SmallOp &operator=(const SmallOp &other) {
        if (this != &other) {
            SmallOp tmp(other);
            swap(tmp);
        }
        return *this;
    }

    ~SmallOp() {
        table_->destroy(&storage_);
    }

    std::uint64_t operator()(std::uint64_t value, int step) const {
        return table_->call(&storage_, value, step);
    }

    void swap(SmallOp &other) noexcept {
        alignas(Storage) std::byte tmp[StorageSize]{};
        table_->copy(tmp, &storage_);
        table_->destroy(&storage_);
        other.table_->copy(&storage_, &other.storage_);
        other.table_->destroy(&other.storage_);
        table_->copy(&other.storage_, tmp);
        table_->destroy(tmp);
        std::swap(table_, other.table_);
    }

private:
    static constexpr std::size_t StorageSize = 48;
    using Storage = std::max_align_t;

    struct Table {
        Call call;
        Copy copy;
        Destroy destroy;
    };

    template <typename F>
    F *ptr() {
        return std::launder(reinterpret_cast<F *>(&storage_));
    }

    template <typename F>
    static const F *cptr(const void *storage) {
        return std::launder(reinterpret_cast<const F *>(storage));
    }

    template <typename F>
    static F *mptr(void *storage) {
        return std::launder(reinterpret_cast<F *>(storage));
    }

    template <typename F>
    static const Table &table_for() {
        static const Table table{
            [](const void *storage, std::uint64_t value, int step) -> std::uint64_t {
                return (*cptr<F>(storage))(value, step);
            },
            [](void *dst, const void *src) {
                std::construct_at(mptr<F>(dst), *cptr<F>(src));
            },
            [](void *storage) {
                std::destroy_at(mptr<F>(storage));
            },
        };
        return table;
    }

    alignas(Storage) std::byte storage_[StorageSize]{};
    const Table *table_ = nullptr;
};

struct FunctionThunk {
    std::uint64_t (*fn)(std::uint64_t, int);
    std::uint64_t salt;

    std::uint64_t operator()(std::uint64_t value, int step) const {
        return fn(value ^ salt, step + static_cast<int>(salt & 7ULL));
    }
};

class Mixer {
public:
    explicit Mixer(std::uint64_t bias_ref) : bias_(bias_ref) {}

    __attribute__((noinline))
    std::uint64_t affine(std::uint64_t value, int step) const {
        return mix64(value + bias_ + static_cast<std::uint64_t>(step * 131));
    }

    __attribute__((noinline))
    std::uint64_t folded(std::uint64_t value, int step) const {
        return rotl64(value ^ mix64(bias_ + static_cast<std::uint64_t>(step)), step + 11);
    }

private:
    std::uint64_t bias_;
};

struct MemberThunk {
    const Mixer *object;
    std::uint64_t (Mixer::*method)(std::uint64_t, int) const;
    std::uint64_t tweak;

    std::uint64_t operator()(std::uint64_t value, int step) const {
        const std::uint64_t adjusted = value + tweak + static_cast<std::uint64_t>(step * 29);
        return (object->*method)(adjusted, step);
    }
};

struct ManualNode {
    enum class Kind : std::uint8_t {
        Rotate,
        XorFold,
        Call
    };

    Kind kind;
    std::uint8_t op_index;
    std::uint64_t salt;

    std::uint64_t dispatch(const std::array<SmallOp, 8> &ops, std::uint64_t value, int step) const {
        switch (kind) {
            case Kind::Rotate:
                return rotl64(value + salt, op_index + step);
            case Kind::XorFold:
                return mix64((value ^ salt) + static_cast<std::uint64_t>(op_index * 1009U + step));
            case Kind::Call:
                return ops[op_index](value + salt, step + static_cast<int>(op_index));
        }
        return value;
    }
};

__attribute__((noinline))
std::uint64_t run_maze(const std::array<SmallOp, 8> &ops, const std::array<ManualNode, 9> &nodes) {
    std::array<std::uint64_t, 6> lanes{{
        0x243f6a8885a308d3ULL,
        0x13198a2e03707344ULL,
        0xa4093822299f31d0ULL,
        0x082efa98ec4e6c89ULL,
        0x452821e638d01377ULL,
        0xbe5466cf34e90c6cULL,
    }};

    std::uint64_t checksum = 0xc0ac29b7c97c50ddULL;

    for (int round = 0; round < 18; ++round) {
        for (std::size_t i = 0; i < nodes.size(); ++i) {
            const std::size_t lane = (i + static_cast<std::size_t>(round)) % lanes.size();
            const std::uint64_t prior = lanes[(lane + lanes.size() - 1U) % lanes.size()];
            const std::uint64_t indirect = nodes[i].dispatch(ops, lanes[lane] ^ prior ^ checksum, round);
            const std::size_t op_index = static_cast<std::size_t>((indirect + i + static_cast<std::size_t>(round)) & 7ULL);

            lanes[lane] = ops[op_index](indirect + lanes[(lane + 2U) % lanes.size()], round + static_cast<int>(i));
            checksum = mix64(checksum + lanes[lane] + indirect + static_cast<std::uint64_t>(op_index * 4099U));
        }
    }

    for (std::uint64_t lane : lanes) {
        checksum = mix64(checksum ^ lane);
    }

    return checksum;
}

} // namespace

int main() {
    const Mixer a(0x6a09e667f3bcc909ULL);
    const Mixer b(0xbb67ae8584caa73bULL);

    const auto lambda_a = [bias = 0x3c6ef372fe94f82bULL](std::uint64_t value, int step) {
        return mix64(value + bias + static_cast<std::uint64_t>(step * 43));
    };
    const auto lambda_b = [left = 7U, right = 19U](std::uint64_t value, int step) {
        return rotl64(value + right, left + static_cast<unsigned>(step)) ^ mix64(value + left);
    };
    const auto lambda_c = [mask = 0xa54ff53a5f1d36f1ULL](std::uint64_t value, int step) {
        return ((value >> (step & 15)) & 1ULL) != 0ULL ? mix64(value ^ mask) : rotl64(value + mask, step + 3);
    };

    const std::array<SmallOp, 8> ops{{
        SmallOp(FunctionThunk{plain_scramble, 0x510e527fade682d1ULL}),
        SmallOp(FunctionThunk{plain_gate, 0x9b05688c2b3e6c1fULL}),
        SmallOp(MemberThunk{&a, &Mixer::affine, 0x1f83d9abfb41bd6bULL}),
        SmallOp(MemberThunk{&a, &Mixer::folded, 0x5be0cd19137e2179ULL}),
        SmallOp(MemberThunk{&b, &Mixer::affine, 0x1111111111111111ULL}),
        SmallOp(MemberThunk{&b, &Mixer::folded, 0x2222222222222222ULL}),
        SmallOp(lambda_a),
        SmallOp([lambda_b, lambda_c](std::uint64_t value, int step) {
            return lambda_c(lambda_b(value, step), step + 5);
        }),
    }};

    const std::array<ManualNode, 9> nodes{{
        {ManualNode::Kind::Call, 0, 0x10ULL},
        {ManualNode::Kind::Rotate, 2, 0x20ULL},
        {ManualNode::Kind::XorFold, 4, 0x30ULL},
        {ManualNode::Kind::Call, 6, 0x40ULL},
        {ManualNode::Kind::Rotate, 1, 0x50ULL},
        {ManualNode::Kind::Call, 7, 0x60ULL},
        {ManualNode::Kind::XorFold, 3, 0x70ULL},
        {ManualNode::Kind::Rotate, 5, 0x80ULL},
        {ManualNode::Kind::Call, 2, 0x90ULL},
    }};

    const std::uint64_t checksum = run_maze(ops, nodes);
    std::cout << "cpp_type_erased_callmaze " << checksum << '\n';
    return 0;
}
