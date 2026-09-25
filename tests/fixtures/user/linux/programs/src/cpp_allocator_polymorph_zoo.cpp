// SPDX-License-Identifier: MIT
//
// Custom resource ownership, polymorphic calls, RAII, and container churn.

#include <algorithm>
#include <array>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <memory>
#include <new>
#include <type_traits>
#include <utility>
#include <vector>

namespace {

constexpr std::uint64_t rotl64(std::uint64_t value, unsigned shift) {
    shift &= 63U;
    return shift == 0U ? value : ((value << shift) | (value >> (64U - shift)));
}

std::uint64_t mix64(std::uint64_t value) {
    value ^= value >> 30;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27;
    value *= 0x94d049bb133111ebULL;
    value ^= value >> 31;
    return value;
}

class ZooResource {
public:
    void *allocate(std::size_t bytes, std::size_t alignment) {
        if (bytes == 0) {
            bytes = 1;
        }

        void *ptr = nullptr;
        if (alignment > __STDCPP_DEFAULT_NEW_ALIGNMENT__) {
            ptr = ::operator new(bytes, std::align_val_t(alignment));
        } else {
            ptr = ::operator new(bytes);
        }

        ++live_blocks_;
        allocated_bytes_ += bytes;
        trace_ = mix64(trace_ + bytes * 17ULL + alignment * 131ULL + static_cast<std::uint64_t>(live_blocks_));
        return ptr;
    }

    void deallocate(void *ptr, std::size_t bytes, std::size_t alignment) noexcept {
        if (ptr == nullptr) {
            return;
        }

        if (bytes == 0) {
            bytes = 1;
        }

        trace_ = mix64(trace_ ^ (bytes * 29ULL + alignment * 193ULL + static_cast<std::uint64_t>(live_blocks_)));
        allocated_bytes_ -= bytes;
        --live_blocks_;

        if (alignment > __STDCPP_DEFAULT_NEW_ALIGNMENT__) {
            ::operator delete(ptr, std::align_val_t(alignment));
        } else {
            ::operator delete(ptr);
        }
    }

    void note_construct(std::uint64_t tag) {
        ++live_tickets_;
        trace_ = mix64(trace_ + tag + static_cast<std::uint64_t>(live_tickets_ * 41));
    }

    void note_destroy(std::uint64_t tag) noexcept {
        trace_ = mix64(trace_ ^ (tag + static_cast<std::uint64_t>(live_tickets_ * 67)));
        --live_tickets_;
    }

    std::uint64_t trace() const { return trace_; }
    std::size_t allocated_bytes() const { return allocated_bytes_; }
    int live_blocks() const { return live_blocks_; }
    int live_tickets() const { return live_tickets_; }

private:
    std::uint64_t trace_ = 0x3141592653589793ULL;
    std::size_t allocated_bytes_ = 0;
    int live_blocks_ = 0;
    int live_tickets_ = 0;
};

template <typename T>
struct ZooAllocator {
    using value_type = T;
    using propagate_on_container_move_assignment = std::true_type;

    ZooResource *resource = nullptr;

    ZooAllocator() noexcept = default;
    explicit ZooAllocator(ZooResource &resource_ref) noexcept : resource(&resource_ref) {}

    template <typename U>
    ZooAllocator(const ZooAllocator<U> &other) noexcept : resource(other.resource) {}

    T *allocate(std::size_t count) {
        if (resource == nullptr || count > std::numeric_limits<std::size_t>::max() / sizeof(T)) {
            throw std::bad_array_new_length();
        }
        return static_cast<T *>(resource->allocate(count * sizeof(T), alignof(T)));
    }

    void deallocate(T *ptr, std::size_t count) noexcept {
        resource->deallocate(ptr, count * sizeof(T), alignof(T));
    }

    template <typename U>
    bool operator==(const ZooAllocator<U> &other) const noexcept {
        return resource == other.resource;
    }

    template <typename U>
    bool operator!=(const ZooAllocator<U> &other) const noexcept {
        return !(*this == other);
    }
};

class Ticket {
public:
    Ticket(ZooResource &resource_ref, std::uint64_t tag_ref) : resource_(&resource_ref), tag_(tag_ref) {
        resource_->note_construct(tag_);
    }

    Ticket(const Ticket &) = delete;
    Ticket &operator=(const Ticket &) = delete;

    ~Ticket() {
        resource_->note_destroy(tag_);
    }

private:
    ZooResource *resource_;
    std::uint64_t tag_;
};

class Actor {
public:
    virtual std::uint64_t step(std::uint64_t input, int tick) = 0;
    virtual void perturb(std::uint64_t value) = 0;
    virtual int weight() const = 0;
    virtual void destroy(ZooResource &resource) noexcept = 0;

protected:
    ~Actor() = default;
};

struct ActorDeleter {
    ZooResource *resource = nullptr;

    void operator()(Actor *actor) const noexcept {
        if (actor != nullptr) {
            actor->destroy(*resource);
        }
    }
};

using OwnedActor = std::unique_ptr<Actor, ActorDeleter>;

template <typename T, typename... Args>
OwnedActor make_actor(ZooResource &resource, Args &&...args) {
    void *storage = resource.allocate(sizeof(T), alignof(T));
    try {
        return OwnedActor(new (storage) T(resource, std::forward<Args>(args)...), ActorDeleter{&resource});
    } catch (...) {
        resource.deallocate(storage, sizeof(T), alignof(T));
        throw;
    }
}

class CounterActor final : public Actor {
public:
    CounterActor(ZooResource &resource, int seed)
        : ticket_(resource, 0x1000ULL + static_cast<std::uint64_t>(seed)), bias_(seed * 97U + 11U) {
        for (std::size_t i = 0; i < cells_.size(); ++i) {
            cells_[i] = static_cast<std::uint32_t>(seed * 31 + static_cast<int>(i * i + 3));
        }
    }

    std::uint64_t step(std::uint64_t input, int tick) override {
        std::uint64_t out = input + bias_ + static_cast<std::uint64_t>(tick * 19);
        for (std::size_t i = 0; i < cells_.size(); ++i) {
            cells_[i] = static_cast<std::uint32_t>(mix64(cells_[i] + out + i) & 0xffffffffULL);
            out ^= rotl64(cells_[i] + static_cast<std::uint64_t>(i * 101), static_cast<unsigned>((tick + i) & 31));
        }
        return mix64(out);
    }

    void perturb(std::uint64_t value) override {
        bias_ ^= static_cast<std::uint32_t>((value >> 5) ^ (value & 0xffffU));
        cells_[value % cells_.size()] += static_cast<std::uint32_t>(value | 1ULL);
    }

    int weight() const override {
        return static_cast<int>((bias_ ^ cells_[2] ^ cells_[5]) & 127U);
    }

    void destroy(ZooResource &resource) noexcept override {
        void *raw = this;
        std::destroy_at(this);
        resource.deallocate(raw, sizeof(CounterActor), alignof(CounterActor));
    }

private:
    Ticket ticket_;
    std::array<std::uint32_t, 6> cells_{};
    std::uint32_t bias_;
};

class BufferActor final : public Actor {
public:
    BufferActor(ZooResource &resource, int seed)
        : ticket_(resource, 0x2000ULL + static_cast<std::uint64_t>(seed)),
          data_(ZooAllocator<std::uint32_t>(resource)),
          factor_(static_cast<std::uint32_t>(seed * 53 + 5)) {
        data_.reserve(10);
        for (int i = 0; i < 6 + (seed % 5); ++i) {
            data_.push_back(static_cast<std::uint32_t>(seed * 17 + i * 23));
        }
    }

    std::uint64_t step(std::uint64_t input, int tick) override {
        if (((input + static_cast<std::uint64_t>(tick)) & 1ULL) != 0ULL) {
            data_.push_back(static_cast<std::uint32_t>(mix64(input + factor_ + data_.size()) & 0xffffffffULL));
        } else if (data_.size() > 4) {
            data_.erase(data_.begin() + static_cast<std::ptrdiff_t>((input + tick) % data_.size()));
        }

        if ((tick % 3) == 0 && data_.size() > 1) {
            std::rotate(data_.begin(), data_.begin() + static_cast<std::ptrdiff_t>(data_.size() / 2), data_.end());
        }

        std::uint64_t out = input ^ factor_;
        for (std::uint32_t value : data_) {
            out = mix64(out + value + static_cast<std::uint64_t>(data_.size() * 13));
        }
        return out;
    }

    void perturb(std::uint64_t value) override {
        factor_ = static_cast<std::uint32_t>(mix64(value + factor_) & 0xffffffffULL);
        if (data_.size() > 14) {
            data_.resize(9);
        }
    }

    int weight() const override {
        return static_cast<int>((factor_ + data_.size() * 11U) & 255U);
    }

    void destroy(ZooResource &resource) noexcept override {
        void *raw = this;
        std::destroy_at(this);
        resource.deallocate(raw, sizeof(BufferActor), alignof(BufferActor));
    }

private:
    Ticket ticket_;
    std::vector<std::uint32_t, ZooAllocator<std::uint32_t>> data_;
    std::uint32_t factor_;
};

class BranchActor final : public Actor {
public:
    BranchActor(ZooResource &resource, int seed)
        : outer_(resource, 0x3000ULL + static_cast<std::uint64_t>(seed)),
          inner_(resource, 0x4000ULL + static_cast<std::uint64_t>(seed * 3)),
          state_(mix64(static_cast<std::uint64_t>(seed * 65537 + 19))) {}

    std::uint64_t step(std::uint64_t input, int tick) override {
        std::uint64_t out = state_ ^ input ^ static_cast<std::uint64_t>(tick * 313);
        for (int lane = 0; lane < 5; ++lane) {
            if (((out >> lane) & 1ULL) != 0ULL) {
                out = mix64(out + static_cast<std::uint64_t>(lane * 0x45d9f3b));
            } else {
                out = rotl64(out ^ state_, static_cast<unsigned>(lane + tick));
            }
        }
        state_ = mix64(out + input + static_cast<std::uint64_t>(tick));
        return state_ ^ out;
    }

    void perturb(std::uint64_t value) override {
        state_ ^= rotl64(value + 0x9e3779b97f4a7c15ULL, static_cast<unsigned>(value & 31ULL));
    }

    int weight() const override {
        return static_cast<int>((state_ ^ (state_ >> 17)) & 191ULL);
    }

    void destroy(ZooResource &resource) noexcept override {
        void *raw = this;
        std::destroy_at(this);
        resource.deallocate(raw, sizeof(BranchActor), alignof(BranchActor));
    }

private:
    Ticket outer_;
    Ticket inner_;
    std::uint64_t state_;
};

template <typename Vector>
void append_actor(Vector &zoo, ZooResource &resource, int seed) {
    switch (seed % 3) {
    case 0:
        zoo.push_back(make_actor<CounterActor>(resource, seed));
        break;
    case 1:
        zoo.push_back(make_actor<BufferActor>(resource, seed));
        break;
    default:
        zoo.push_back(make_actor<BranchActor>(resource, seed));
        break;
    }
}

struct RunResult {
    std::uint64_t checksum;
    int live_blocks;
    int live_tickets;
};

__attribute__((noinline))
RunResult run_zoo() {
    ZooResource resource;
    std::uint64_t checksum = 0x6a09e667f3bcc909ULL;

    {
        std::vector<OwnedActor, ZooAllocator<OwnedActor>> zoo{ZooAllocator<OwnedActor>(resource)};
        std::vector<std::uint64_t, ZooAllocator<std::uint64_t>> churn{ZooAllocator<std::uint64_t>(resource)};
        zoo.reserve(24);
        churn.reserve(32);

        for (int seed = 0; seed < 15; ++seed) {
            append_actor(zoo, resource, seed + 3);
        }

        for (int round = 0; round < 38; ++round) {
            for (std::size_t i = 0; i < zoo.size(); ++i) {
                const std::uint64_t input = checksum ^ static_cast<std::uint64_t>((round + 1) * (i + 17));
                const std::uint64_t value = zoo[i]->step(input, round);
                checksum = mix64(checksum + value + static_cast<std::uint64_t>(zoo[i]->weight() * 31));

                if (((value + i + static_cast<std::size_t>(round)) % 5U) == 0U) {
                    zoo[i]->perturb(checksum ^ value);
                }

                churn.push_back(value ^ checksum);
                if (churn.size() > 26) {
                    churn.erase(churn.begin() + static_cast<std::ptrdiff_t>((value + i) % churn.size()));
                }
            }

            if ((round % 6) == 2 && zoo.size() < 22) {
                append_actor(zoo, resource, round + 40);
            }

            if ((round % 7) == 4 && zoo.size() > 9) {
                const std::size_t victim = static_cast<std::size_t>(checksum % zoo.size());
                zoo.erase(zoo.begin() + static_cast<std::ptrdiff_t>(victim));
                append_actor(zoo, resource, round + 70);
            }

            if ((round & 3) == 1 && zoo.size() > 2) {
                std::rotate(zoo.begin(), zoo.begin() + static_cast<std::ptrdiff_t>((round % static_cast<int>(zoo.size()))), zoo.end());
            }

            for (std::uint64_t value : churn) {
                checksum ^= rotl64(value + resource.trace(), static_cast<unsigned>(value & 15ULL));
            }
        }
    }

    checksum = mix64(checksum ^ resource.trace() ^ static_cast<std::uint64_t>(resource.allocated_bytes()));
    return {checksum, resource.live_blocks(), resource.live_tickets()};
}

} // namespace

int main() {
    const RunResult result = run_zoo();
    std::printf("cpp_allocator_polymorph_zoo %" PRIu64 " %d %d\n",
                result.checksum,
                result.live_blocks,
                result.live_tickets);
    return (result.live_blocks == 0 && result.live_tickets == 0) ? 0 : 1;
}
