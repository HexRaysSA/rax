// Experimental SMIR 0.1 framing. No executable admission or LLVM dependency.
#ifndef RAX_SMIR_FORMAT_CODEC_HPP
#define RAX_SMIR_FORMAT_CODEC_HPP

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <vector>

namespace rax::smir::framing {

struct Section {
    std::uint16_t kind;
    bool required;
    std::span<const std::uint8_t> payload;
};

// Views borrow input storage, which must remain alive and unchanged.
struct Result {
    unsigned error = 0;
    std::uint16_t kind = 0;
    std::uint32_t entry = 0xffffffff;
    std::vector<Section> sections;
};

inline std::uint64_t read(std::span<const std::uint8_t> bytes,
                          std::size_t offset, std::size_t width) {
    // Internal helper: callers establish the complete containing record first.
    std::uint64_t result = 0;
    for (std::size_t index = 0; index < width; ++index) {
        result |= std::uint64_t(bytes[offset + index]) << (8 * index);
    }
    return result;
}

inline Result decode(std::span<const std::uint8_t> bytes,
                     std::size_t max_bytes = std::size_t{1} << 30,
                     std::uint32_t max_sections = 1024) {
    auto failure = [](unsigned code) {
        Result result;
        result.error = code;
        return result;
    };
    if (bytes.size() > max_bytes) {
        return failure(5);
    }
    if (bytes.size() < 48) {
        return failure(1);
    }
    constexpr std::uint8_t magic[] = {'S', 'M', 'I', 'R', 13, 10, 26, 10};
    for (std::size_t index = 0; index < 8; ++index) {
        if (bytes[index] != magic[index]) {
            return failure(2);
        }
    }
    if (read(bytes, 8, 2) != 0 || read(bytes, 10, 2) != 1) {
        return failure(3);
    }
    const auto kind = read(bytes, 12, 2);
    const auto entry = read(bytes, 40, 4);
    if ((kind != 1 && kind != 2) || read(bytes, 14, 2) != 0 ||
        read(bytes, 16, 4) != 1 || read(bytes, 24, 8) != bytes.size() ||
        read(bytes, 32, 8) != 48 || read(bytes, 44, 4) != 0 ||
        (kind == 1 && entry != 0xffffffff)) {
        return failure(4);
    }
    const auto count = read(bytes, 20, 4);
    if (count > max_sections) {
        return failure(5);
    }
    // Division establishes bounds without overflowing host size arithmetic.
    if (count > (bytes.size() - 48) / 24) {
        return failure(6);
    }
    std::size_t cursor = 48 + static_cast<std::size_t>(count) * 24;
    std::uint64_t previous = 0;
    Result result;
    result.kind = static_cast<std::uint16_t>(kind);
    result.entry = static_cast<std::uint32_t>(entry);
    for (std::size_t index = 0; index < count; ++index) {
        const auto record = 48 + index * 24;
        const auto tag = read(bytes, record, 2);
        const auto flags = read(bytes, record + 2, 2);
        if (tag <= previous || flags > 1 || read(bytes, record + 4, 4) != 0) {
            return failure(6);
        }
        if ((tag < 0x8000 && (tag > 9 || flags != 1)) ||
            (tag >= 0x8000 && flags != 0)) {
            return failure(8);
        }
        const auto offset = read(bytes, record + 8, 8);
        const auto length = read(bytes, record + 16, 8);
        if (cursor > std::numeric_limits<std::size_t>::max() - 7) {
            return failure(7);
        }
        const auto start = (cursor + 7) & ~std::size_t{7};
        if (offset != start || offset > bytes.size() ||
            length > bytes.size() - static_cast<std::size_t>(offset)) {
            return failure(7);
        }
        for (auto padding = cursor; padding < start; ++padding) {
            if (bytes[padding] != 0) {
                return failure(9);
            }
        }
        result.sections.push_back({static_cast<std::uint16_t>(tag), flags == 1,
            bytes.subspan(start, static_cast<std::size_t>(length))});
        previous = tag;
        cursor = start + static_cast<std::size_t>(length);
    }
    if (cursor != bytes.size()) {
        return failure(9);
    }
    return result;
}

} // namespace rax::smir::framing

#endif
