// Experimental SMIR 0.1 and candidate 0.2 framing. No executable admission.
#ifndef RAX_SMIR_FORMAT_CODEC_HPP
#define RAX_SMIR_FORMAT_CODEC_HPP

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <limits>
#include <map>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
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

namespace detail {
inline Result decode_profile(std::span<const std::uint8_t> bytes,
                             std::size_t max_bytes,
                             std::uint32_t max_sections, bool candidate) {
    const unsigned revision = candidate ? 2 : 1;
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
    if (read(bytes, 8, 2) != 0 || read(bytes, 10, 2) != revision) {
        return failure(3);
    }
    const auto kind = read(bytes, 12, 2);
    const auto entry = read(bytes, 40, 4);
    if ((kind != 1 && kind != 2) || read(bytes, 14, 2) != 0 ||
        read(bytes, 16, 4) != revision || read(bytes, 24, 8) != bytes.size() ||
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
        if ((tag < 0x8000 && (tag > (candidate ? 10 : 9) || flags != 1)) ||
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
    if (candidate && std::count_if(result.sections.begin(), result.sections.end(),
            [](const Section &section) { return section.kind < 0x8000; }) != 10) {
        return failure(8);
    }
    return result;
}
} // namespace detail

inline Result decode(std::span<const std::uint8_t> bytes,
                     std::size_t max_bytes = std::size_t{1} << 30,
                     std::uint32_t max_sections = 1024) {
    return detail::decode_profile(bytes, max_bytes, max_sections, false);
}

// A separate unverified candidate result; successful framing is not admission.
struct CandidateResult {
    Result envelope;
};

inline CandidateResult decode_candidate(std::span<const std::uint8_t> bytes,
                                       std::size_t max_bytes = std::size_t{1} << 30,
                                       std::uint32_t max_sections = 1024) {
    return {detail::decode_profile(bytes, max_bytes, max_sections, true)};
}

struct Encoding {
    unsigned error = 0;
    std::vector<std::uint8_t> bytes;
};

// Independent canonical serializer. The borrowed source payloads must remain
// valid through this call. No partially encoded output escapes on rejection.
// Time O(output bytes + sections * log(sections)); metadata space O(sections).
namespace detail {
inline Encoding encode_profile(const Result &module, std::size_t max_bytes,
                               std::uint32_t max_sections, bool candidate) {
    auto failure = [](unsigned code) {
        Encoding result;
        result.error = code;
        return result;
    };
    if (module.error != 0) {
        return failure(module.error);
    }
    if (module.sections.size() > max_sections || max_bytes < 48 ||
        module.sections.size() > (max_bytes - 48) / 24) {
        return failure(5);
    }
    if ((module.kind != 1 && module.kind != 2) ||
        (module.kind == 1 && module.entry != 0xffffffff)) {
        return failure(4);
    }
    auto sections = module.sections;
    std::sort(sections.begin(), sections.end(), [](const Section &a, const Section &b) {
        return a.kind < b.kind;
    });
    std::size_t cursor = 48 + sections.size() * 24;
    for (const auto &section : sections) {
        if (cursor > std::numeric_limits<std::size_t>::max() - 7) {
            return failure(5);
        }
        const auto start = (cursor + 7) & ~std::size_t{7};
        if (start > max_bytes || section.payload.size() > max_bytes - start) {
            return failure(5);
        }
        cursor = start + section.payload.size();
    }
    Encoding result;
    result.bytes.resize(cursor, 0);
    auto write = [&](std::size_t offset, std::uint64_t value, std::size_t width) {
        for (std::size_t index = 0; index < width; ++index) {
            result.bytes[offset + index] = static_cast<std::uint8_t>(value >> (8 * index));
        }
    };
    constexpr std::uint8_t magic[] = {'S', 'M', 'I', 'R', 13, 10, 26, 10};
    std::copy(std::begin(magic), std::end(magic), result.bytes.begin());
    write(10, candidate ? 2 : 1, 2);
    write(12, module.kind, 2);
    write(16, candidate ? 2 : 1, 4);
    write(20, sections.size(), 4);
    write(24, cursor, 8);
    write(32, 48, 8);
    write(40, module.entry, 4);
    cursor = 48 + sections.size() * 24;
    for (std::size_t index = 0; index < sections.size(); ++index) {
        const auto &section = sections[index];
        const auto start = (cursor + 7) & ~std::size_t{7};
        const auto record = 48 + index * 24;
        write(record, section.kind, 2);
        write(record + 2, section.required ? 1 : 0, 2);
        write(record + 8, start, 8);
        write(record + 16, section.payload.size(), 8);
        std::copy(section.payload.begin(), section.payload.end(), result.bytes.begin() + start);
        cursor = start + section.payload.size();
    }
    // The independent parser rejects duplicate/unknown semantic tags and flags.
    const auto checked = decode_profile(result.bytes, max_bytes, max_sections, candidate);
    if (checked.error != 0) {
        return failure(checked.error);
    }
    return result;
}
} // namespace detail

inline Encoding encode(const Result &module,
                       std::size_t max_bytes = std::size_t{1} << 30,
                       std::uint32_t max_sections = 1024) {
    return detail::encode_profile(module, max_bytes, max_sections, false);
}

inline Encoding encode_candidate(const CandidateResult &module,
                                 std::size_t max_bytes = std::size_t{1} << 30,
                                 std::uint32_t max_sections = 1024) {
    return detail::encode_profile(module.envelope, max_bytes, max_sections, true);
}

} // namespace rax::smir::framing

// Independent INT-008 ordered-record reference. This is representation checking,
// not executable admission. The schema is an explicit immutable input snapshot.
namespace rax::smir::records {

using Fields = std::vector<std::pair<std::string, std::string>>;
struct Definition {
    std::string discriminator;
    Fields fields;
    std::map<std::string, Fields> variants;
};
using Schema = std::map<std::string, Definition>;

struct Limits {
    std::size_t bytes = 16 * 1024 * 1024;
    std::size_t nodes = 1000000;
    std::size_t depth = 64;
    std::size_t list = 65536;
    std::size_t string = 1024 * 1024;
};

enum class Tag { Unsigned, Signed, Boolean, Bytes, Text, Vector, Option, Record };
struct Value {
    Tag tag = Tag::Record;
    // Signed numbers use sign-extended two's-complement bits, never a host cast
    // from an out-of-range unsigned integer. Text contains validated UTF-8.
    std::uint64_t number = 0;
    std::string data;
    std::vector<Value> elements;
    std::vector<std::pair<std::string, Value>> fields;
};

class Error : public std::runtime_error {
public:
    explicit Error(const char *code) : std::runtime_error(code) {}
};

class Codec {
    const Schema schema;
    const Limits limits;

    static void require(bool condition, const char *code) {
        if (!condition) {
            throw Error(code);
        }
    }

    static bool token(const std::string &text) {
        return !text.empty() && text.size() <= 63 && text[0] >= 'a' && text[0] <= 'z' &&
            std::all_of(text.begin(), text.end(), [](unsigned char byte) {
                return (byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9') || byte == '_';
            });
    }

    static unsigned integer(const std::string &kind) {
        if (kind == "u8" || kind == "i8") return 1;
        if (kind == "u16" || kind == "i16") return 2;
        if (kind == "u32" || kind == "i32") return 4;
        if (kind == "u64" || kind == "i64") return 8;
        return 0;
    }

    static bool primitive(const std::string &kind) {
        return integer(kind) || kind == "bool" || kind == "bytes" || kind == "hex" ||
            kind == "utf8" || kind == "token" || kind == "digest32";
    }

    void kind(std::string name) const {
        for (unsigned depth = 0; depth <= 128; ++depth) {
            if (name.starts_with("vec:") || name.starts_with("opt:")) {
                name.erase(0, 4);
            } else {
                require(primitive(name) || schema.contains(name), "WIRE-SCHEMA");
                return;
            }
        }
        throw Error("WIRE-SCHEMA");
    }

    void audit(const Fields &fields, const std::string &discriminator) const {
        std::set<std::string> names;
        if (!discriminator.empty()) names.insert(discriminator);
        for (const auto &[name, type] : fields) {
            require(token(name) && names.insert(name).second, "WIRE-SCHEMA");
            kind(type);
        }
    }

    static void utf8(const std::string &text) {
        for (std::size_t cursor = 0; cursor < text.size();) {
            const auto lead = static_cast<unsigned char>(text[cursor++]);
            if (lead < 0x80) continue;
            const unsigned count = lead >= 0xc2 && lead <= 0xdf ? 1 :
                lead >= 0xe0 && lead <= 0xef ? 2 : lead >= 0xf0 && lead <= 0xf4 ? 3 : 0;
            require(count != 0 && count <= text.size() - cursor, "WIRE-TEXT");
            std::uint32_t scalar = lead & ((1u << (6 - count)) - 1);
            for (unsigned index = 0; index < count; ++index) {
                const auto byte = static_cast<unsigned char>(text[cursor++]);
                require((byte & 0xc0) == 0x80, "WIRE-TEXT");
                scalar = (scalar << 6) | (byte & 0x3f);
            }
            require(scalar >= (count == 1 ? 0x80u : count == 2 ? 0x800u : 0x10000u) &&
                    scalar <= 0x10ffff && !(scalar >= 0xd800 && scalar <= 0xdfff), "WIRE-TEXT");
        }
    }

    void visit(std::size_t depth, std::size_t &nodes) const {
        require(depth <= limits.depth && nodes < limits.nodes, "WIRE-LIMIT");
        ++nodes;
    }

    Value read(const std::string &type, std::span<const std::uint8_t> bytes,
               std::size_t &cursor, std::size_t depth, std::size_t &nodes) const {
        visit(depth, nodes);
        auto number = [&](unsigned width) {
            require(width <= bytes.size() - cursor, "WIRE-TRUNCATED");
            std::uint64_t result = 0;
            for (unsigned index = 0; index < width; ++index) {
                result |= std::uint64_t(bytes[cursor++]) << (8 * index);
            }
            return result;
        };
        auto text = [&](std::size_t count) {
            require(count <= bytes.size() - cursor, "WIRE-TRUNCATED");
            std::string result;
            if (count != 0) result.assign(reinterpret_cast<const char *>(bytes.data() + cursor), count);
            cursor += count;
            return result;
        };
        Value result;
        if (type.starts_with("vec:") || type.starts_with("opt:")) {
            const bool vector = type.starts_with("vec:");
            const auto count = number(vector ? 4 : 1);
            require(vector ? count <= limits.list && count <= limits.nodes : count <= 1,
                    vector ? "WIRE-LIMIT" : "WIRE-TAG");
            result.tag = vector ? Tag::Vector : Tag::Option;
            for (std::uint64_t index = 0; index < count; ++index) {
                result.elements.push_back(read(type.substr(4), bytes, cursor, depth + 1, nodes));
            }
        } else if (const auto width = integer(type)) {
            result.tag = type[0] == 'i' ? Tag::Signed : Tag::Unsigned;
            result.number = number(width);
            if (type[0] == 'i' && width < 8 && (result.number & (std::uint64_t{1} << (width * 8 - 1)))) {
                result.number |= ~((std::uint64_t{1} << (width * 8)) - 1);
            }
        } else if (type == "bool") {
            result.tag = Tag::Boolean;
            result.number = number(1);
            require(result.number <= 1, "WIRE-RANGE");
        } else if (type == "bytes" || type == "hex" || type == "digest32") {
            result.tag = Tag::Bytes;
            result.data = text(type == "digest32" ? 32 : number(4));
        } else if (type == "utf8" || type == "token") {
            const auto count = number(type == "token" ? 1 : 4);
            require(count <= limits.string, "WIRE-LIMIT");
            result.tag = Tag::Text;
            result.data = text(count);
            utf8(result.data);
            require(type != "token" || token(result.data), "WIRE-TEXT");
        } else {
            const auto &definition = schema.at(type);
            const Fields *fields = &definition.fields;
            if (!definition.discriminator.empty()) {
                auto tag = read("token", bytes, cursor, depth + 1, nodes);
                require(definition.variants.contains(tag.data), "WIRE-TAG");
                fields = &definition.variants.at(tag.data);
                result.fields.emplace_back(definition.discriminator, std::move(tag));
            }
            for (const auto &[name, child] : *fields) {
                result.fields.emplace_back(name, read(child, bytes, cursor, depth + 1, nodes));
            }
        }
        return result;
    }

    void write(const std::string &type, const Value &value, std::vector<std::uint8_t> &bytes,
               std::size_t depth, std::size_t &nodes) const {
        visit(depth, nodes);
        auto number = [&](std::uint64_t number, unsigned width) {
            require(width <= limits.bytes - bytes.size(), "WIRE-LIMIT");
            for (unsigned index = 0; index < width; ++index) {
                bytes.push_back(static_cast<std::uint8_t>(number >> (8 * index)));
            }
        };
        auto text = [&](const std::string &data) {
            require(data.size() <= limits.bytes - bytes.size(), "WIRE-LIMIT");
            bytes.insert(bytes.end(), data.begin(), data.end());
        };
        if (type.starts_with("vec:") || type.starts_with("opt:")) {
            const bool vector = type.starts_with("vec:");
            require(value.tag == (vector ? Tag::Vector : Tag::Option), "WIRE-TYPE");
            require(vector ? value.elements.size() <= limits.list && value.elements.size() <= 0xffffffffu :
                    value.elements.size() <= 1, vector ? "WIRE-LIMIT" : "WIRE-TYPE");
            number(value.elements.size(), vector ? 4 : 1);
            for (const auto &element : value.elements) write(type.substr(4), element, bytes, depth + 1, nodes);
        } else if (const auto width = integer(type)) {
            const bool signed_integer = type[0] == 'i';
            require(value.tag == (signed_integer ? Tag::Signed : Tag::Unsigned), "WIRE-TYPE");
            if (width < 8) {
                if (signed_integer) {
                    const auto limit = std::int64_t{1} << (width * 8 - 1);
                    const auto integer = std::bit_cast<std::int64_t>(value.number);
                    require(integer >= -limit && integer < limit, "WIRE-RANGE");
                } else {
                    require(value.number < (std::uint64_t{1} << (width * 8)), "WIRE-RANGE");
                }
            }
            number(value.number, width);
        } else if (type == "bool") {
            require(value.tag == Tag::Boolean && value.number <= 1, "WIRE-TYPE");
            number(value.number, 1);
        } else if (type == "bytes" || type == "hex" || type == "digest32") {
            require(value.tag == Tag::Bytes, "WIRE-TYPE");
            if (type == "digest32") require(value.data.size() == 32, "WIRE-RANGE");
            else {
                require(value.data.size() <= 0xffffffffu, "WIRE-LIMIT");
                number(value.data.size(), 4);
            }
            text(value.data);
        } else if (type == "utf8" || type == "token") {
            require(value.tag == Tag::Text, "WIRE-TYPE");
            require(value.data.size() <= limits.string && value.data.size() <= 0xffffffffu, "WIRE-LIMIT");
            utf8(value.data);
            require(type != "token" || token(value.data), "WIRE-TEXT");
            number(value.data.size(), type == "token" ? 1 : 4);
            text(value.data);
        } else {
            require(value.tag == Tag::Record, "WIRE-TYPE");
            std::map<std::string, const Value *> members;
            for (const auto &[name, member] : value.fields) {
                require(members.emplace(name, &member).second, "WIRE-TYPE");
            }
            const auto &definition = schema.at(type);
            const Fields *fields = &definition.fields;
            if (!definition.discriminator.empty()) {
                require(members.contains(definition.discriminator), "WIRE-TYPE");
                const auto &tag = *members.at(definition.discriminator);
                require(tag.tag == Tag::Text && definition.variants.contains(tag.data), "WIRE-TAG");
                fields = &definition.variants.at(tag.data);
                write("token", tag, bytes, depth + 1, nodes);
            }
            require(members.size() == fields->size() + !definition.discriminator.empty(), "WIRE-TYPE");
            for (const auto &[name, child] : *fields) {
                require(members.contains(name), "WIRE-TYPE");
                write(child, *members.at(name), bytes, depth + 1, nodes);
            }
        }
    }

public:
    explicit Codec(Schema definitions, Limits resources = {}) : schema(std::move(definitions)), limits(resources) {
        require(!schema.empty(), "WIRE-SCHEMA");
        require(limits.depth <= 128, "WIRE-CONFIG");
        for (const auto &[name, definition] : schema) {
            require(token(name) && !primitive(name), "WIRE-SCHEMA");
            if (definition.discriminator.empty()) {
                require(definition.variants.empty(), "WIRE-SCHEMA");
                audit(definition.fields, "");
            } else {
                require(token(definition.discriminator) && definition.fields.empty() &&
                        !definition.variants.empty(), "WIRE-SCHEMA");
                for (const auto &[tag, fields] : definition.variants) {
                    require(token(tag), "WIRE-SCHEMA");
                    audit(fields, definition.discriminator);
                }
            }
        }
    }

    // O((schema + visited nodes) * log(schema + visited nodes) + payload bytes)
    // worst-case work; space O(schema + visited nodes + payload bytes), bounded
    // by resource limits. Ordered schema/member maps account for logarithms.
    // The returned tree owns its payloads. No borrowed mutable schema survives.
    Value decode(const std::string &type, std::span<const std::uint8_t> bytes) const {
        kind(type);
        require(bytes.size() <= limits.bytes, "WIRE-LIMIT");
        std::size_t cursor = 0, nodes = 0;
        auto result = read(type, bytes, cursor, 0, nodes);
        require(cursor == bytes.size(), "WIRE-TRAILING");
        return result;
    }

    std::vector<std::uint8_t> encode(const std::string &type, const Value &value) const {
        kind(type);
        std::size_t nodes = 0;
        std::vector<std::uint8_t> bytes;
        write(type, value, bytes, 0, nodes);
        return bytes;
    }
};

} // namespace rax::smir::records

#endif
