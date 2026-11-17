// Independent ordered ABI decoder. No JSON library or Python codec reuse.
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using Fields = std::vector<std::pair<std::string, std::string>>;
struct Record {
    Fields fields;
    std::map<std::string, Fields> variants;
};
#include "candidate_records.inc"

static void require(bool condition) {
    if (!condition) {
        throw std::runtime_error("reject");
    }
}

static std::string quote(const std::string &text) {
    std::ostringstream output;
    output << '"';
    for (unsigned char byte : text) {
        if (byte == '"' || byte == '\\') {
            output << '\\' << static_cast<char>(byte);
        } else if (byte < 32) {
            output << "\\u00" << std::hex << std::setw(2) << std::setfill('0') << unsigned(byte);
        } else {
            output << static_cast<char>(byte);
        }
    }
    output << '"';
    return output.str();
}

static void validate_utf8(const std::string &text) {
    std::size_t cursor = 0;
    while (cursor < text.size()) {
        auto lead = static_cast<unsigned char>(text[cursor++]);
        if (lead < 0x80) {
            continue;
        }
        unsigned continuation = lead >= 0xc2 && lead <= 0xdf ? 1 :
                                lead >= 0xe0 && lead <= 0xef ? 2 :
                                lead >= 0xf0 && lead <= 0xf4 ? 3 : 0;
        require(continuation != 0 && continuation <= text.size() - cursor);
        std::uint32_t scalar = lead & ((1u << (6 - continuation)) - 1);
        for (unsigned index = 0; index < continuation; ++index) {
            auto byte = static_cast<unsigned char>(text[cursor++]);
            require((byte & 0xc0) == 0x80);
            scalar = (scalar << 6) | (byte & 0x3f);
        }
        require(scalar >= (continuation == 1 ? 0x80u : continuation == 2 ? 0x800u : 0x10000u));
        require(scalar <= 0x10ffff && !(scalar >= 0xd800 && scalar <= 0xdfff));
    }
}

class Decoder {
    std::vector<unsigned char> bytes;
    std::size_t cursor = 0;
    std::size_t nodes = 0;

    std::uint64_t number(unsigned width) {
        require(width <= bytes.size() - cursor);
        std::uint64_t value = 0;
        for (unsigned index = 0; index < width; ++index) {
            value |= std::uint64_t(bytes[cursor++]) << (index * 8);
        }
        return value;
    }

    std::string take(std::size_t count) {
        require(count <= bytes.size() - cursor);
        std::string result(bytes.begin() + cursor, bytes.begin() + cursor + count);
        cursor += count;
        return result;
    }

public:
    explicit Decoder(const std::string &hex) {
        require(hex.size() % 2 == 0 && hex.size() <= 16 * 1024 * 1024);
        auto digit = [](char byte) -> unsigned {
            require((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f'));
            return byte <= '9' ? unsigned(byte - '0') : unsigned(byte - 'a' + 10);
        };
        for (std::size_t index = 0; index < hex.size(); index += 2) {
            bytes.push_back(static_cast<unsigned char>((digit(hex[index]) << 4) | digit(hex[index + 1])));
        }
    }

    std::string read(const std::string &kind, unsigned depth = 0) {
        require(depth <= 128 && ++nodes <= 200000);
        if (kind == "u8" || kind == "u16" || kind == "u32" || kind == "u64" ||
            kind == "i8" || kind == "i16" || kind == "i32" || kind == "i64") {
            unsigned bits = static_cast<unsigned>(std::stoul(kind.substr(1)));
            auto value = number(bits / 8);
            if (kind[0] == 'i' && (value & (std::uint64_t(1) << (bits - 1)))) {
                auto mask = bits == 64 ? ~std::uint64_t(0) : (std::uint64_t(1) << bits) - 1;
                return "-" + std::to_string((~value & mask) + 1);
            }
            return std::to_string(value);
        }
        if (kind == "bool") {
            auto value = number(1);
            require(value <= 1);
            return value ? "true" : "false";
        }
        if (kind.rfind("opt:", 0) == 0) {
            auto tag = number(1);
            require(tag <= 1);
            return tag ? "{\"some\":" + read(kind.substr(4), depth + 1) + "}" : "null";
        }
        if (kind.rfind("vec:", 0) == 0) {
            auto count = number(4);
            require(count <= 10000);
            std::string result = "[";
            for (std::uint64_t index = 0; index < count; ++index) {
                result += (index ? "," : "") + read(kind.substr(4), depth + 1);
            }
            return result + "]";
        }
        if (kind == "digest32" || kind == "hex" || kind == "bytes") {
            auto payload = take(kind == "digest32" ? 32 : number(4));
            const char *digits = "0123456789abcdef";
            std::string hex;
            for (unsigned char byte : payload) {
                hex += digits[byte >> 4];
                hex += digits[byte & 15];
            }
            return quote(hex);
        }
        if (kind == "utf8" || kind == "token") {
            auto text = take(number(kind == "token" ? 1 : 4));
            validate_utf8(text);
            if (kind == "token") {
                require(!text.empty() && text.size() <= 63 && text[0] >= 'a' && text[0] <= 'z');
                for (char byte : text) {
                    require((byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9') || byte == '_');
                }
            }
            return quote(text);
        }
        auto record = RECORDS.find(kind);
        require(record != RECORDS.end());
        const Fields *fields = &record->second.fields;
        std::string result = "{";
        bool comma = false;
        if (!record->second.variants.empty()) {
            auto tag = read("token", depth + 1);
            auto raw = tag.substr(1, tag.size() - 2);
            auto variant = record->second.variants.find(raw);
            require(variant != record->second.variants.end());
            fields = &variant->second;
            result += "\"kind\":" + tag;
            comma = true;
        }
        for (const auto &[name, field_kind] : *fields) {
            result += (comma ? "," : "") + quote(name) + ":" + read(field_kind, depth + 1);
            comma = true;
        }
        return result + "}";
    }

    void finish() const {
        require(cursor == bytes.size());
    }
};

int main() {
    std::string line;
    while (std::getline(std::cin, line)) {
        try {
            auto separator = line.find(' ');
            require(separator != std::string::npos);
            Decoder decoder(line.substr(separator + 1));
            auto result = decoder.read(line.substr(0, separator));
            decoder.finish();
            std::cout << "{\"ok\":true,\"value\":" << result << "}\n";
        } catch (const std::exception &) {
            std::cout << "{\"ok\":false}\n";
        }
    }
}
