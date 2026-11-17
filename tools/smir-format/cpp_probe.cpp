#include "codec.hpp"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <string>

#ifdef SMIR_RECORD_TEST_SCHEMA
#include SMIR_RECORD_TEST_SCHEMA

static void json_string(const std::string &text) {
    std::cout << '"';
    for (unsigned char byte : text) {
        if (byte == '"' || byte == '\\') {
            std::cout << '\\' << static_cast<char>(byte);
        } else if (byte < 32) {
            std::cout << "\\u00" << std::hex << std::setfill('0') << std::setw(2) << unsigned(byte);
        } else {
            std::cout << static_cast<char>(byte);
        }
    }
    std::cout << std::dec << '"';
}

static void json_value(const rax::smir::records::Value &value) {
    using rax::smir::records::Tag;
    switch (value.tag) {
    case Tag::Unsigned: std::cout << value.number; break;
    case Tag::Signed: std::cout << std::bit_cast<std::int64_t>(value.number); break;
    case Tag::Boolean: std::cout << (value.number ? "true" : "false"); break;
    case Tag::Text: json_string(value.data); break;
    case Tag::Bytes: {
        const char *digits = "0123456789abcdef";
        std::string hex;
        for (unsigned char byte : value.data) {
            hex += digits[byte >> 4];
            hex += digits[byte & 15];
        }
        json_string(hex);
        break;
    }
    case Tag::Option:
        if (value.elements.empty()) std::cout << "null";
        else {
            std::cout << "{\"some\":";
            json_value(value.elements[0]);
            std::cout << '}';
        }
        break;
    case Tag::Vector:
        std::cout << '[';
        for (std::size_t index = 0; index < value.elements.size(); ++index) {
            if (index) std::cout << ',';
            json_value(value.elements[index]);
        }
        std::cout << ']';
        break;
    case Tag::Record:
        std::cout << '{';
        for (std::size_t index = 0; index < value.fields.size(); ++index) {
            if (index) std::cout << ',';
            json_string(value.fields[index].first);
            std::cout << ':';
            json_value(value.fields[index].second);
        }
        std::cout << '}';
        break;
    }
}

static int record_probe(const std::string &type, const char *path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return 3;
    // The extra byte detects oversized input before constructing a value tree.
    std::vector<std::uint8_t> bytes;
    char chunk[4096];
    constexpr std::size_t limit = 16 * 1024 * 1024;
    while (input && bytes.size() <= limit) {
        const auto count = std::min(sizeof(chunk), limit + 1 - bytes.size());
        input.read(chunk, static_cast<std::streamsize>(count));
        bytes.insert(bytes.end(), chunk, chunk + input.gcount());
    }
    if (input.bad()) return 3;
    try {
        const rax::smir::records::Codec codec(smir_test_schema);
        const auto value = codec.decode(type, bytes);
        if (codec.encode(type, value) != bytes) return 4;
        json_value(value);
        std::cout << '\n';
        return 0;
    } catch (const rax::smir::records::Error &error) {
        std::cout << error.what() << '\n';
        return 2;
    }
}

// This composes framing and ordered records. It does not check the content
// digest or semantic admission, and cannot issue an executable object.
static int candidate_records_probe(const char *path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return 3;
    constexpr std::size_t limit = 64 * 1024 * 1024;
    std::vector<std::uint8_t> bytes;
    char chunk[4096];
    while (input && bytes.size() <= limit) {
        const auto count = std::min(sizeof(chunk), limit + 1 - bytes.size());
        input.read(chunk, static_cast<std::streamsize>(count));
        bytes.insert(bytes.end(), chunk, chunk + input.gcount());
    }
    if (input.bad()) return 3;
    const auto container = rax::smir::framing::decode_candidate(bytes, limit, 1024);
    if (container.envelope.error != 0) {
        std::cout << "SMIR-E" << std::setfill('0') << std::setw(3)
                  << container.envelope.error << '\n';
        return 2;
    }
    try {
        using namespace rax::smir::records;
        static constexpr const char *names[] = {
            "execution_types", "runtime_symbols", "execution_functions",
            "runtime_data", "runtime_relocations", "runtime_imports",
            "runtime_tls", "execution_exceptions", "runtime_capabilities", "abi_contract"
        };
        std::map<unsigned, Value> roots;
        Limits limits;
        // Every root uses only the remaining shared value-node allowance.
        auto charge = [&](auto &&self, const Value &value) -> void {
            if (limits.nodes == 0) throw Error("WIRE-LIMIT");
            --limits.nodes;
            for (const auto &child : value.elements) self(self, child);
            for (const auto &field : value.fields) self(self, field.second);
        };
        for (const auto &section : container.envelope.sections) {
            if (section.kind >= 0x8000) continue;
            const auto payload = section.payload;
            // Independently authored table for the coherent CodeAddress cut.
            static constexpr unsigned revisions[] = {2, 2, 2, 1, 2, 1, 1, 1, 1, 3};
            const unsigned expected = revisions[section.kind - 1];
            if (payload.size() < 4) throw Error("WIRE-REVISION");
            const auto revision = std::uint32_t(payload[0]) |
                (std::uint32_t(payload[1]) << 8) | (std::uint32_t(payload[2]) << 16) |
                (std::uint32_t(payload[3]) << 24);
            if (revision != expected) throw Error("WIRE-REVISION");
            const Codec codec(smir_test_schema, limits);
            auto value = codec.decode(names[section.kind - 1], payload);
            if (codec.encode(names[section.kind - 1], value) !=
                std::vector<std::uint8_t>(payload.begin(), payload.end())) {
                throw Error("WIRE-REENCODE");
            }
            charge(charge, value);
            roots.emplace(section.kind, std::move(value));
        }
        std::cout << "{\"status\":\"decoded-records\",\"executable_admitted\":false,\"roots\":{";
        bool first = true;
        for (const auto &[identifier, value] : roots) {
            if (!first) std::cout << ',';
            first = false;
            json_string(std::to_string(identifier));
            std::cout << ':';
            json_value(value);
        }
        std::cout << "}}\n";
        return 0;
    } catch (const rax::smir::records::Error &error) {
        std::cout << error.what() << '\n';
        return 2;
    }
}

static int record_encoder_tests() {
    using namespace rax::smir::records;
    const Codec codec(smir_test_schema);
    unsigned cases = 0;
    auto rejected = [&](auto action, const std::string &expected) {
        ++cases;
        try { action(); }
        catch (const Error &error) { return error.what() == expected; }
        return false;
    };
    Value value;
    value.tag = Tag::Unsigned;
    value.number = 256;
    if (!rejected([&] { codec.encode("u8", value); }, "WIRE-RANGE")) return 1;
    value.tag = Tag::Signed;
    value.number = std::bit_cast<std::uint64_t>(std::int64_t{-129});
    if (!rejected([&] { codec.encode("i8", value); }, "WIRE-RANGE")) return 1;
    value.number = 128;
    if (!rejected([&] { codec.encode("i8", value); }, "WIRE-RANGE")) return 1;
    value.tag = Tag::Boolean;
    value.number = 2;
    if (!rejected([&] { codec.encode("bool", value); }, "WIRE-TYPE")) return 1;
    value.tag = Tag::Text;
    value.data = "";
    if (!rejected([&] { codec.encode("token", value); }, "WIRE-TEXT")) return 1;
    value.data = std::string("\xed\xa0\x80", 3);
    if (!rejected([&] { codec.encode("utf8", value); }, "WIRE-TEXT")) return 1;
    value.tag = Tag::Bytes;
    value.data = "short";
    if (!rejected([&] { codec.encode("digest32", value); }, "WIRE-RANGE")) return 1;
    value = {};
    value.tag = Tag::Option;
    value.elements = {Value{}, Value{}};
    if (!rejected([&] { codec.encode("opt:u8", value); }, "WIRE-TYPE")) return 1;
    value = {};
    if (!rejected([&] { codec.encode("choice", value); }, "WIRE-TYPE")) return 1;
    Value tag;
    tag.tag = Tag::Text;
    tag.data = "none";
    value.fields = {{"kind", tag}, {"kind", tag}};
    if (!rejected([&] { codec.encode("choice", value); }, "WIRE-TYPE")) return 1;
    value.fields = {{"kind", tag}, {"extra", tag}};
    if (!rejected([&] { codec.encode("choice", value); }, "WIRE-TYPE")) return 1;
    value.fields = {{"kind", tag}};
    ++cases;
    if (codec.encode("choice", value) != std::vector<std::uint8_t>{4, 'n', 'o', 'n', 'e'}) return 1;
    Limits tiny;
    tiny.bytes = 1;
    value = {};
    value.tag = Tag::Unsigned;
    if (!rejected([&] { Codec(smir_test_schema, tiny).encode("u16", value); }, "WIRE-LIMIT")) return 1;
    auto invalid = smir_test_schema;
    invalid["bad"] = {"", {{"x", "u8"}, {"x", "u16"}}, {}};
    if (!rejected([&] { Codec checked(invalid); }, "WIRE-SCHEMA")) return 1;
    ++cases;
    value.tag = Tag::Signed;
    value.number = std::bit_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::min());
    if (codec.encode("i64", value) != std::vector<std::uint8_t>{0, 0, 0, 0, 0, 0, 0, 128}) return 1;
    std::cout << "C++ record encoder partitions: " << cases << '\n';
    return 0;
}
#endif

int encoder_tests() {
    namespace framing = rax::smir::framing;
    const std::uint8_t payload[] = {0xab};
    framing::Result module;
    module.kind = 1;
    module.sections = {{0xffff, false, {}}, {1, true, payload}};
    const auto encoded = framing::encode(module);
    const auto decoded = framing::decode(encoded.bytes);
    if (encoded.error != 0 || decoded.error != 0 || decoded.sections.size() != 2 ||
        decoded.sections[0].kind != 1 || decoded.sections[1].kind != 0xffff ||
        decoded.sections[0].payload.size() != 1 || decoded.sections[0].payload[0] != 0xab) {
        return 1;
    }
    unsigned cases = 1;
    auto check = [&](framing::Result value, unsigned error) {
        const auto result = framing::encode(value);
        ++cases;
        return result.error == error && result.bytes.empty();
    };
    auto changed = module;
    changed.kind = 0;
    if (!check(changed, 4)) {
        return 1;
    }
    changed = module;
    changed.entry = 0;
    if (!check(changed, 4)) {
        return 1;
    }
    changed = module;
    changed.error = 8;
    if (!check(changed, 8)) {
        return 1;
    }
    for (const auto &sections : std::vector<std::vector<framing::Section>>{
            {{1, true, {}}, {1, true, {}}}, {{1, false, {}}},
            {{10, true, {}}}, {{0xffff, true, {}}}}) {
        changed = module;
        changed.sections = sections;
        if (!check(changed, sections.size() == 2 ? 6 : 8)) {
            return 1;
        }
    }
    for (const auto max_bytes : {std::size_t{47}, std::size_t{95}, std::size_t{96}}) {
        const auto result = framing::encode(module, max_bytes);
        ++cases;
        if (result.error != 5 || !result.bytes.empty()) {
            return 1;
        }
    }
    ++cases;
    if (framing::encode(module, 1024, 1).error != 5) {
        return 1;
    }
    changed = module;
    changed.sections.clear();
    const auto empty = framing::encode(changed, 48, 0);
    ++cases;
    if (empty.error != 0 || empty.bytes.size() != 48 || framing::decode(empty.bytes).error != 0) {
        return 1;
    }
    std::cout << "C++ encoder partitions: " << cases << '\n';
    return 0;
}

int main(int argc, char **argv) {
#ifdef SMIR_RECORD_TEST_SCHEMA
    if (argc == 2 && std::string(argv[1]) == "--record-self-test") {
        return record_encoder_tests();
    }
    if (argc == 4 && std::string(argv[1]) == "--record") {
        return record_probe(argv[2], argv[3]);
    }
    if (argc == 3 && std::string(argv[1]) == "--candidate-records") {
        return candidate_records_probe(argv[2]);
    }
#endif
    const bool candidate = argc == 3 && std::string(argv[1]) == "--candidate";
    if (argc != 2 && !candidate) {
        return 3;
    }
    if (std::string(argv[1]) == "--self-test") {
        return encoder_tests();
    }
    std::ifstream input(argv[candidate ? 2 : 1], std::ios::binary);
    if (!input) {
        return 3;
    }
    constexpr std::size_t max_bytes = std::size_t{1} << 30;
    std::vector<std::uint8_t> bytes;
    char chunk[4096];
    while (input && bytes.size() <= max_bytes) {
        const auto count = std::min(sizeof(chunk), max_bytes + 1 - bytes.size());
        input.read(chunk, static_cast<std::streamsize>(count));
        bytes.insert(bytes.end(), chunk, chunk + input.gcount());
    }
    if (input.bad()) {
        return 3;
    }
    namespace framing = rax::smir::framing;
    const auto candidate_result = candidate ? framing::decode_candidate(bytes)
                                           : framing::CandidateResult{};
    const auto result = candidate ? candidate_result.envelope : framing::decode(bytes);
    if (result.error != 0) {
        std::cout << "SMIR-E" << std::setfill('0') << std::setw(3)
                  << result.error << '\n';
        return 2;
    }
    const auto encoded = candidate ? framing::encode_candidate(candidate_result)
                                   : framing::encode(result);
    if (encoded.error != 0 || encoded.bytes != bytes) {
        std::cerr << "independent C++ canonical encoding differs\n";
        return 4;
    }
    std::cout << "OK " << result.kind << ' ' << result.entry << '\n';
    for (const auto &section : result.sections) {
        std::cout << std::dec << section.kind << ' ' << section.required << ' ';
        for (auto byte : section.payload) {
            std::cout << std::hex << std::setfill('0') << std::setw(2)
                      << static_cast<unsigned>(byte);
        }
        std::cout << '\n';
    }
}
