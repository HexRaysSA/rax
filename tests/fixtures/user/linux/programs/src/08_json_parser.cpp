/**
 * Complete JSON Parser and Serializer in Modern C++17
 * 
 * Features:
 * - JsonValue class using std::variant for type-safe JSON values
 * - Recursive descent parser with proper tokenization
 * - Full JSON spec support: null, bool, numbers, strings, arrays, objects
 * - Unicode escape sequences (\uXXXX) and all standard escapes
 * - Pretty-print and compact serialization
 * - Detailed error messages with line/column numbers
 * - Parse from string or file
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <variant>
#include <optional>
#include <stdexcept>
#include <memory>
#include <charconv>
#include <cmath>
#include <iomanip>
#include <cctype>

// Forward declarations
class JsonValue;

// Type aliases for JSON types
using JsonNull = std::nullptr_t;
using JsonBool = bool;
using JsonNumber = double;
using JsonString = std::string;
using JsonArray = std::vector<JsonValue>;
using JsonObject = std::map<std::string, JsonValue>;

// =============================================================================
// JSON Parse Error with Location Information
// =============================================================================

class JsonParseError : public std::runtime_error {
public:
    size_t line;
    size_t column;
    std::string context;
    
    JsonParseError(const std::string& message, size_t line, size_t column, 
                   const std::string& context = "")
        : std::runtime_error(format_message(message, line, column, context))
        , line(line)
        , column(column)
        , context(context)
    {}
    
private:
    static std::string format_message(const std::string& msg, size_t line, 
                                       size_t col, const std::string& ctx) {
        std::ostringstream oss;
        oss << "JSON parse error at line " << line << ", column " << col << ": " << msg;
        if (!ctx.empty()) {
            oss << "\n  near: \"" << ctx << "\"";
        }
        return oss.str();
    }
};

// =============================================================================
// JsonValue Class - Core JSON Type
// =============================================================================

class JsonValue {
public:
    // The variant holding all possible JSON types
    using ValueType = std::variant<JsonNull, JsonBool, JsonNumber, JsonString, 
                                    JsonArray, JsonObject>;
    
private:
    ValueType m_value;
    
public:
    // Constructors
    JsonValue() : m_value(nullptr) {}
    JsonValue(std::nullptr_t) : m_value(nullptr) {}
    JsonValue(bool b) : m_value(b) {}
    JsonValue(int n) : m_value(static_cast<double>(n)) {}
    JsonValue(long n) : m_value(static_cast<double>(n)) {}
    JsonValue(long long n) : m_value(static_cast<double>(n)) {}
    JsonValue(double n) : m_value(n) {}
    JsonValue(const char* s) : m_value(std::string(s)) {}
    JsonValue(const std::string& s) : m_value(s) {}
    JsonValue(std::string&& s) : m_value(std::move(s)) {}
    JsonValue(const JsonArray& arr) : m_value(arr) {}
    JsonValue(JsonArray&& arr) : m_value(std::move(arr)) {}
    JsonValue(const JsonObject& obj) : m_value(obj) {}
    JsonValue(JsonObject&& obj) : m_value(std::move(obj)) {}
    
    // Initializer list constructors for convenience
    JsonValue(std::initializer_list<JsonValue> init) : m_value(JsonArray(init)) {}
    JsonValue(std::initializer_list<std::pair<const std::string, JsonValue>> init)
        : m_value(JsonObject(init.begin(), init.end())) {}
    
    // Type checking methods
    bool is_null() const { return std::holds_alternative<JsonNull>(m_value); }
    bool is_bool() const { return std::holds_alternative<JsonBool>(m_value); }
    bool is_number() const { return std::holds_alternative<JsonNumber>(m_value); }
    bool is_string() const { return std::holds_alternative<JsonString>(m_value); }
    bool is_array() const { return std::holds_alternative<JsonArray>(m_value); }
    bool is_object() const { return std::holds_alternative<JsonObject>(m_value); }
    
    // Type name for error messages
    std::string type_name() const {
        if (is_null()) return "null";
        if (is_bool()) return "boolean";
        if (is_number()) return "number";
        if (is_string()) return "string";
        if (is_array()) return "array";
        if (is_object()) return "object";
        return "unknown";
    }
    
    // Accessor methods with error handling
    std::optional<bool> as_bool() const {
        if (auto* p = std::get_if<JsonBool>(&m_value)) {
            return *p;
        }
        return std::nullopt;
    }
    
    std::optional<double> as_number() const {
        if (auto* p = std::get_if<JsonNumber>(&m_value)) {
            return *p;
        }
        return std::nullopt;
    }
    
    std::optional<int> as_int() const {
        if (auto* p = std::get_if<JsonNumber>(&m_value)) {
            return static_cast<int>(*p);
        }
        return std::nullopt;
    }
    
    std::optional<std::string> as_string() const {
        if (auto* p = std::get_if<JsonString>(&m_value)) {
            return *p;
        }
        return std::nullopt;
    }
    
    std::optional<std::reference_wrapper<const JsonArray>> as_array() const {
        if (auto* p = std::get_if<JsonArray>(&m_value)) {
            return std::cref(*p);
        }
        return std::nullopt;
    }
    
    std::optional<std::reference_wrapper<JsonArray>> as_array() {
        if (auto* p = std::get_if<JsonArray>(&m_value)) {
            return std::ref(*p);
        }
        return std::nullopt;
    }
    
    std::optional<std::reference_wrapper<const JsonObject>> as_object() const {
        if (auto* p = std::get_if<JsonObject>(&m_value)) {
            return std::cref(*p);
        }
        return std::nullopt;
    }
    
    std::optional<std::reference_wrapper<JsonObject>> as_object() {
        if (auto* p = std::get_if<JsonObject>(&m_value)) {
            return std::ref(*p);
        }
        return std::nullopt;
    }
    
    // Direct access (throws if wrong type) - useful when you've already checked
    bool& get_bool() { return std::get<JsonBool>(m_value); }
    const bool& get_bool() const { return std::get<JsonBool>(m_value); }
    double& get_number() { return std::get<JsonNumber>(m_value); }
    const double& get_number() const { return std::get<JsonNumber>(m_value); }
    std::string& get_string() { return std::get<JsonString>(m_value); }
    const std::string& get_string() const { return std::get<JsonString>(m_value); }
    JsonArray& get_array() { return std::get<JsonArray>(m_value); }
    const JsonArray& get_array() const { return std::get<JsonArray>(m_value); }
    JsonObject& get_object() { return std::get<JsonObject>(m_value); }
    const JsonObject& get_object() const { return std::get<JsonObject>(m_value); }
    
    // Array operator[] - access by index
    JsonValue& operator[](size_t index) {
        if (!is_array()) {
            throw std::runtime_error("JSON value is not an array (is " + type_name() + ")");
        }
        auto& arr = get_array();
        if (index >= arr.size()) {
            throw std::out_of_range("Array index " + std::to_string(index) + 
                                    " out of bounds (size: " + std::to_string(arr.size()) + ")");
        }
        return arr[index];
    }
    
    const JsonValue& operator[](size_t index) const {
        if (!is_array()) {
            throw std::runtime_error("JSON value is not an array (is " + type_name() + ")");
        }
        const auto& arr = get_array();
        if (index >= arr.size()) {
            throw std::out_of_range("Array index " + std::to_string(index) + 
                                    " out of bounds (size: " + std::to_string(arr.size()) + ")");
        }
        return arr[index];
    }
    
    // Object operator[] - access by key (creates entry if doesn't exist for non-const)
    JsonValue& operator[](const std::string& key) {
        if (!is_object()) {
            throw std::runtime_error("JSON value is not an object (is " + type_name() + ")");
        }
        return get_object()[key];
    }
    
    const JsonValue& operator[](const std::string& key) const {
        if (!is_object()) {
            throw std::runtime_error("JSON value is not an object (is " + type_name() + ")");
        }
        const auto& obj = get_object();
        auto it = obj.find(key);
        if (it == obj.end()) {
            throw std::out_of_range("Key not found: " + key);
        }
        return it->second;
    }
    
    // Convenience: check if object contains key
    bool contains(const std::string& key) const {
        if (auto obj = as_object()) {
            return obj->get().find(key) != obj->get().end();
        }
        return false;
    }
    
    // Get value with default
    template<typename T>
    T value_or(const std::string& key, T default_val) const {
        if (!is_object()) return default_val;
        const auto& obj = get_object();
        auto it = obj.find(key);
        if (it == obj.end()) return default_val;
        
        if constexpr (std::is_same_v<T, bool>) {
            return it->second.as_bool().value_or(default_val);
        } else if constexpr (std::is_arithmetic_v<T>) {
            return static_cast<T>(it->second.as_number().value_or(default_val));
        } else if constexpr (std::is_same_v<T, std::string>) {
            return it->second.as_string().value_or(default_val);
        }
        return default_val;
    }
    
    // Array size / Object size
    size_t size() const {
        if (is_array()) return get_array().size();
        if (is_object()) return get_object().size();
        throw std::runtime_error("size() called on non-container JSON value");
    }
    
    bool empty() const {
        if (is_array()) return get_array().empty();
        if (is_object()) return get_object().empty();
        if (is_string()) return get_string().empty();
        return is_null();
    }
    
    // Array push_back
    void push_back(const JsonValue& val) {
        if (!is_array()) {
            throw std::runtime_error("push_back() called on non-array JSON value");
        }
        get_array().push_back(val);
    }
    
    void push_back(JsonValue&& val) {
        if (!is_array()) {
            throw std::runtime_error("push_back() called on non-array JSON value");
        }
        get_array().push_back(std::move(val));
    }
    
    // Erase from object
    bool erase(const std::string& key) {
        if (!is_object()) return false;
        return get_object().erase(key) > 0;
    }
    
    // Get underlying variant (for advanced usage)
    ValueType& variant() { return m_value; }
    const ValueType& variant() const { return m_value; }
};

// =============================================================================
// Tokenizer / Lexer
// =============================================================================

enum class TokenType {
    LeftBrace,      // {
    RightBrace,     // }
    LeftBracket,    // [
    RightBracket,   // ]
    Colon,          // :
    Comma,          // ,
    String,
    Number,
    True,
    False,
    Null,
    EndOfInput,
    Error
};

struct Token {
    TokenType type;
    std::string value;
    size_t line;
    size_t column;
    
    Token(TokenType t, std::string v, size_t l, size_t c)
        : type(t), value(std::move(v)), line(l), column(c) {}
};

class Tokenizer {
private:
    std::string_view m_input;
    size_t m_pos = 0;
    size_t m_line = 1;
    size_t m_column = 1;
    
public:
    explicit Tokenizer(std::string_view input) : m_input(input) {}
    
    Token next_token() {
        skip_whitespace();
        
        if (m_pos >= m_input.size()) {
            return Token(TokenType::EndOfInput, "", m_line, m_column);
        }
        
        size_t start_line = m_line;
        size_t start_col = m_column;
        char c = current();
        
        switch (c) {
            case '{': advance(); return Token(TokenType::LeftBrace, "{", start_line, start_col);
            case '}': advance(); return Token(TokenType::RightBrace, "}", start_line, start_col);
            case '[': advance(); return Token(TokenType::LeftBracket, "[", start_line, start_col);
            case ']': advance(); return Token(TokenType::RightBracket, "]", start_line, start_col);
            case ':': advance(); return Token(TokenType::Colon, ":", start_line, start_col);
            case ',': advance(); return Token(TokenType::Comma, ",", start_line, start_col);
            case '"': return parse_string(start_line, start_col);
            case 't': return parse_keyword("true", TokenType::True, start_line, start_col);
            case 'f': return parse_keyword("false", TokenType::False, start_line, start_col);
            case 'n': return parse_keyword("null", TokenType::Null, start_line, start_col);
            default:
                if (c == '-' || std::isdigit(c)) {
                    return parse_number(start_line, start_col);
                }
                return Token(TokenType::Error, 
                            std::string("Unexpected character: '") + c + "'",
                            start_line, start_col);
        }
    }
    
    // Get context around current position for error messages
    std::string get_context(size_t radius = 20) const {
        size_t start = (m_pos > radius) ? m_pos - radius : 0;
        size_t end = std::min(m_pos + radius, m_input.size());
        std::string ctx(m_input.substr(start, end - start));
        // Replace newlines with spaces for display
        for (char& c : ctx) {
            if (c == '\n' || c == '\r' || c == '\t') c = ' ';
        }
        return ctx;
    }
    
private:
    char current() const {
        return (m_pos < m_input.size()) ? m_input[m_pos] : '\0';
    }
    
    char peek(size_t offset = 1) const {
        return (m_pos + offset < m_input.size()) ? m_input[m_pos + offset] : '\0';
    }
    
    void advance() {
        if (m_pos < m_input.size()) {
            if (m_input[m_pos] == '\n') {
                m_line++;
                m_column = 1;
            } else {
                m_column++;
            }
            m_pos++;
        }
    }
    
    void skip_whitespace() {
        while (m_pos < m_input.size() && std::isspace(current())) {
            advance();
        }
    }
    
    Token parse_string(size_t start_line, size_t start_col) {
        advance();  // Skip opening quote
        std::string result;
        
        while (m_pos < m_input.size() && current() != '"') {
            if (current() == '\\') {
                advance();
                if (m_pos >= m_input.size()) {
                    return Token(TokenType::Error, "Unterminated string escape", 
                                m_line, m_column);
                }
                
                switch (current()) {
                    case '"':  result += '"'; break;
                    case '\\': result += '\\'; break;
                    case '/':  result += '/'; break;
                    case 'b':  result += '\b'; break;
                    case 'f':  result += '\f'; break;
                    case 'n':  result += '\n'; break;
                    case 'r':  result += '\r'; break;
                    case 't':  result += '\t'; break;
                    case 'u': {
                        // Parse \uXXXX unicode escape
                        std::string hex;
                        for (int i = 0; i < 4; i++) {
                            advance();
                            if (m_pos >= m_input.size() || !std::isxdigit(current())) {
                                return Token(TokenType::Error, 
                                            "Invalid unicode escape sequence",
                                            m_line, m_column);
                            }
                            hex += current();
                        }
                        
                        // Convert hex to codepoint
                        unsigned int codepoint = 0;
                        std::from_chars(hex.data(), hex.data() + hex.size(), 
                                        codepoint, 16);
                        
                        // Handle surrogate pairs for characters outside BMP
                        if (codepoint >= 0xD800 && codepoint <= 0xDBFF) {
                            // High surrogate - expect low surrogate
                            if (peek() == '\\' && peek(2) == 'u') {
                                advance(); advance(); // Skip \u
                                std::string hex2;
                                for (int i = 0; i < 4; i++) {
                                    advance();
                                    if (!std::isxdigit(current())) {
                                        return Token(TokenType::Error,
                                                    "Invalid surrogate pair",
                                                    m_line, m_column);
                                    }
                                    hex2 += current();
                                }
                                unsigned int low = 0;
                                std::from_chars(hex2.data(), hex2.data() + hex2.size(),
                                                low, 16);
                                if (low >= 0xDC00 && low <= 0xDFFF) {
                                    codepoint = 0x10000 + ((codepoint - 0xD800) << 10) +
                                                (low - 0xDC00);
                                }
                            }
                        }
                        
                        // Encode codepoint as UTF-8
                        if (codepoint < 0x80) {
                            result += static_cast<char>(codepoint);
                        } else if (codepoint < 0x800) {
                            result += static_cast<char>(0xC0 | (codepoint >> 6));
                            result += static_cast<char>(0x80 | (codepoint & 0x3F));
                        } else if (codepoint < 0x10000) {
                            result += static_cast<char>(0xE0 | (codepoint >> 12));
                            result += static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F));
                            result += static_cast<char>(0x80 | (codepoint & 0x3F));
                        } else {
                            result += static_cast<char>(0xF0 | (codepoint >> 18));
                            result += static_cast<char>(0x80 | ((codepoint >> 12) & 0x3F));
                            result += static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F));
                            result += static_cast<char>(0x80 | (codepoint & 0x3F));
                        }
                        break;
                    }
                    default:
                        return Token(TokenType::Error, 
                                    std::string("Invalid escape sequence: \\") + current(),
                                    m_line, m_column);
                }
            } else if (static_cast<unsigned char>(current()) < 0x20) {
                // Control characters not allowed in strings
                return Token(TokenType::Error, "Control character in string", 
                            m_line, m_column);
            } else {
                result += current();
            }
            advance();
        }
        
        if (current() != '"') {
            return Token(TokenType::Error, "Unterminated string", start_line, start_col);
        }
        advance();  // Skip closing quote
        
        return Token(TokenType::String, std::move(result), start_line, start_col);
    }
    
    Token parse_number(size_t start_line, size_t start_col) {
        size_t start_pos = m_pos;
        
        // Optional minus
        if (current() == '-') advance();
        
        // Integer part
        if (current() == '0') {
            advance();
        } else if (std::isdigit(current())) {
            while (std::isdigit(current())) advance();
        } else {
            return Token(TokenType::Error, "Invalid number", m_line, m_column);
        }
        
        // Fractional part
        if (current() == '.') {
            advance();
            if (!std::isdigit(current())) {
                return Token(TokenType::Error, 
                            "Expected digit after decimal point", m_line, m_column);
            }
            while (std::isdigit(current())) advance();
        }
        
        // Exponent part
        if (current() == 'e' || current() == 'E') {
            advance();
            if (current() == '+' || current() == '-') advance();
            if (!std::isdigit(current())) {
                return Token(TokenType::Error, 
                            "Expected digit in exponent", m_line, m_column);
            }
            while (std::isdigit(current())) advance();
        }
        
        std::string num_str(m_input.substr(start_pos, m_pos - start_pos));
        return Token(TokenType::Number, std::move(num_str), start_line, start_col);
    }
    
    Token parse_keyword(const char* keyword, TokenType type, 
                        size_t start_line, size_t start_col) {
        std::string_view kw(keyword);
        if (m_input.substr(m_pos, kw.size()) == kw) {
            // Make sure it's not a prefix of something else
            size_t end = m_pos + kw.size();
            if (end >= m_input.size() || !std::isalnum(m_input[end])) {
                for (size_t i = 0; i < kw.size(); i++) advance();
                return Token(type, std::string(keyword), start_line, start_col);
            }
        }
        return Token(TokenType::Error, 
                    std::string("Expected '") + keyword + "'", start_line, start_col);
    }
};

// =============================================================================
// JSON Parser - Recursive Descent
// =============================================================================

class JsonParser {
private:
    Tokenizer m_tokenizer;
    Token m_current_token;
    std::string m_source;  // Keep source for context in errors
    
public:
    explicit JsonParser(const std::string& input) 
        : m_tokenizer(input)
        , m_current_token(TokenType::EndOfInput, "", 1, 1)
        , m_source(input)
    {
        advance();
    }
    
    JsonValue parse() {
        JsonValue result = parse_value();
        
        if (m_current_token.type != TokenType::EndOfInput) {
            throw JsonParseError("Unexpected content after JSON value",
                                m_current_token.line, m_current_token.column,
                                m_tokenizer.get_context());
        }
        
        return result;
    }
    
    // Static convenience methods
    static JsonValue from_string(const std::string& input) {
        JsonParser parser(input);
        return parser.parse();
    }
    
    static std::optional<JsonValue> try_parse(const std::string& input, 
                                               std::string* error_out = nullptr) {
        try {
            return from_string(input);
        } catch (const JsonParseError& e) {
            if (error_out) *error_out = e.what();
            return std::nullopt;
        }
    }
    
    static JsonValue from_file(const std::string& filename) {
        std::ifstream file(filename);
        if (!file) {
            throw std::runtime_error("Failed to open file: " + filename);
        }
        
        std::ostringstream ss;
        ss << file.rdbuf();
        return from_string(ss.str());
    }
    
    static std::optional<JsonValue> try_parse_file(const std::string& filename,
                                                    std::string* error_out = nullptr) {
        try {
            return from_file(filename);
        } catch (const std::exception& e) {
            if (error_out) *error_out = e.what();
            return std::nullopt;
        }
    }
    
private:
    void advance() {
        m_current_token = m_tokenizer.next_token();
        
        if (m_current_token.type == TokenType::Error) {
            throw JsonParseError(m_current_token.value,
                                m_current_token.line, m_current_token.column,
                                m_tokenizer.get_context());
        }
    }
    
    void expect(TokenType type, const std::string& expected) {
        if (m_current_token.type != type) {
            throw JsonParseError("Expected " + expected + ", got '" + 
                                m_current_token.value + "'",
                                m_current_token.line, m_current_token.column,
                                m_tokenizer.get_context());
        }
    }
    
    JsonValue parse_value() {
        switch (m_current_token.type) {
            case TokenType::LeftBrace:
                return parse_object();
            case TokenType::LeftBracket:
                return parse_array();
            case TokenType::String: {
                std::string val = std::move(m_current_token.value);
                advance();
                return JsonValue(std::move(val));
            }
            case TokenType::Number: {
                double val = std::stod(m_current_token.value);
                advance();
                return JsonValue(val);
            }
            case TokenType::True:
                advance();
                return JsonValue(true);
            case TokenType::False:
                advance();
                return JsonValue(false);
            case TokenType::Null:
                advance();
                return JsonValue(nullptr);
            case TokenType::EndOfInput:
                throw JsonParseError("Unexpected end of input",
                                    m_current_token.line, m_current_token.column, "");
            default:
                throw JsonParseError("Unexpected token: " + m_current_token.value,
                                    m_current_token.line, m_current_token.column,
                                    m_tokenizer.get_context());
        }
    }
    
    JsonValue parse_object() {
        expect(TokenType::LeftBrace, "'{'");
        advance();
        
        JsonObject obj;
        
        if (m_current_token.type == TokenType::RightBrace) {
            advance();
            return JsonValue(std::move(obj));
        }
        
        while (true) {
            expect(TokenType::String, "string key");
            std::string key = std::move(m_current_token.value);
            advance();
            
            expect(TokenType::Colon, "':'");
            advance();
            
            obj[std::move(key)] = parse_value();
            
            if (m_current_token.type == TokenType::RightBrace) {
                advance();
                break;
            }
            
            expect(TokenType::Comma, "',' or '}'");
            advance();
            
            // Trailing comma check (not standard JSON but helpful error)
            if (m_current_token.type == TokenType::RightBrace) {
                throw JsonParseError("Trailing comma not allowed in JSON",
                                    m_current_token.line, m_current_token.column,
                                    m_tokenizer.get_context());
            }
        }
        
        return JsonValue(std::move(obj));
    }
    
    JsonValue parse_array() {
        expect(TokenType::LeftBracket, "'['");
        advance();
        
        JsonArray arr;
        
        if (m_current_token.type == TokenType::RightBracket) {
            advance();
            return JsonValue(std::move(arr));
        }
        
        while (true) {
            arr.push_back(parse_value());
            
            if (m_current_token.type == TokenType::RightBracket) {
                advance();
                break;
            }
            
            expect(TokenType::Comma, "',' or ']'");
            advance();
            
            // Trailing comma check
            if (m_current_token.type == TokenType::RightBracket) {
                throw JsonParseError("Trailing comma not allowed in JSON",
                                    m_current_token.line, m_current_token.column,
                                    m_tokenizer.get_context());
            }
        }
        
        return JsonValue(std::move(arr));
    }
};

// =============================================================================
// JSON Serializer
// =============================================================================

struct JsonSerializerOptions {
    bool pretty = true;
    int indent_size = 2;
    char indent_char = ' ';
    bool escape_unicode = false;  // If true, escape non-ASCII as \uXXXX
    bool sort_keys = false;       // If true, sort object keys alphabetically
};

class JsonSerializer {
public:
    using Options = JsonSerializerOptions;
    
private:
    std::ostringstream m_output;
    Options m_options;
    int m_depth = 0;
    
public:
    explicit JsonSerializer(const Options& options = {}) : m_options(options) {}
    
    std::string serialize(const JsonValue& value) {
        m_output.str("");
        m_output.clear();
        m_depth = 0;
        write_value(value);
        return m_output.str();
    }
    
    // Static convenience methods
    static std::string to_string(const JsonValue& value, bool pretty = true, 
                                  int indent = 2) {
        Options opts;
        opts.pretty = pretty;
        opts.indent_size = indent;
        JsonSerializer serializer(opts);
        return serializer.serialize(value);
    }
    
    static std::string to_compact_string(const JsonValue& value) {
        return to_string(value, false);
    }
    
    static bool to_file(const JsonValue& value, const std::string& filename,
                        bool pretty = true, int indent = 2) {
        std::ofstream file(filename);
        if (!file) return false;
        file << to_string(value, pretty, indent);
        return file.good();
    }
    
private:
    void write_indent() {
        if (m_options.pretty) {
            m_output << '\n';
            for (int i = 0; i < m_depth * m_options.indent_size; i++) {
                m_output << m_options.indent_char;
            }
        }
    }
    
    void write_value(const JsonValue& value) {
        if (value.is_null()) {
            m_output << "null";
        } else if (value.is_bool()) {
            m_output << (value.get_bool() ? "true" : "false");
        } else if (value.is_number()) {
            write_number(value.get_number());
        } else if (value.is_string()) {
            write_string(value.get_string());
        } else if (value.is_array()) {
            write_array(value.get_array());
        } else if (value.is_object()) {
            write_object(value.get_object());
        }
    }
    
    void write_number(double num) {
        if (std::isnan(num) || std::isinf(num)) {
            // JSON doesn't support NaN/Infinity, use null
            m_output << "null";
            return;
        }
        
        // Check if it's an integer
        if (std::floor(num) == num && 
            num >= -9007199254740992.0 && num <= 9007199254740992.0) {
            m_output << static_cast<long long>(num);
        } else {
            // Use full precision for floats
            m_output << std::setprecision(17) << num;
        }
    }
    
    void write_string(const std::string& str) {
        m_output << '"';
        for (unsigned char c : str) {
            switch (c) {
                case '"':  m_output << "\\\""; break;
                case '\\': m_output << "\\\\"; break;
                case '\b': m_output << "\\b"; break;
                case '\f': m_output << "\\f"; break;
                case '\n': m_output << "\\n"; break;
                case '\r': m_output << "\\r"; break;
                case '\t': m_output << "\\t"; break;
                default:
                    if (c < 0x20) {
                        // Control characters
                        m_output << "\\u" << std::hex << std::setfill('0') 
                                 << std::setw(4) << static_cast<int>(c)
                                 << std::dec;
                    } else if (m_options.escape_unicode && c >= 0x80) {
                        // Non-ASCII - escape as \uXXXX
                        m_output << "\\u" << std::hex << std::setfill('0')
                                 << std::setw(4) << static_cast<int>(c)
                                 << std::dec;
                    } else {
                        m_output << c;
                    }
            }
        }
        m_output << '"';
    }
    
    void write_array(const JsonArray& arr) {
        if (arr.empty()) {
            m_output << "[]";
            return;
        }
        
        m_output << '[';
        m_depth++;
        
        bool first = true;
        for (const auto& elem : arr) {
            if (!first) m_output << ',';
            first = false;
            write_indent();
            write_value(elem);
        }
        
        m_depth--;
        write_indent();
        m_output << ']';
    }
    
    void write_object(const JsonObject& obj) {
        if (obj.empty()) {
            m_output << "{}";
            return;
        }
        
        m_output << '{';
        m_depth++;
        
        // std::map already keeps keys sorted, so we just iterate
        bool first = true;
        for (const auto& [key, val] : obj) {
            if (!first) m_output << ',';
            first = false;
            write_indent();
            write_string(key);
            m_output << ':';
            if (m_options.pretty) m_output << ' ';
            write_value(val);
        }
        
        m_depth--;
        write_indent();
        m_output << '}';
    }
};

// =============================================================================
// Convenience free functions
// =============================================================================

namespace json {
    // Parse JSON from string
    inline JsonValue parse(const std::string& input) {
        return JsonParser::from_string(input);
    }
    
    // Try to parse, returning nullopt on failure
    inline std::optional<JsonValue> try_parse(const std::string& input,
                                               std::string* error = nullptr) {
        return JsonParser::try_parse(input, error);
    }
    
    // Parse from file
    inline JsonValue parse_file(const std::string& filename) {
        return JsonParser::from_file(filename);
    }
    
    // Serialize to string
    inline std::string stringify(const JsonValue& value, bool pretty = true, 
                                  int indent = 2) {
        return JsonSerializer::to_string(value, pretty, indent);
    }
    
    // Serialize to compact string
    inline std::string compact(const JsonValue& value) {
        return JsonSerializer::to_compact_string(value);
    }
    
    // Create JSON array
    inline JsonValue array(std::initializer_list<JsonValue> init = {}) {
        return JsonValue(JsonArray(init));
    }
    
    // Create JSON object
    inline JsonValue object(std::initializer_list<std::pair<const std::string, JsonValue>> init = {}) {
        return JsonValue(JsonObject(init.begin(), init.end()));
    }
}

// =============================================================================
// Main Function - Demonstration
// =============================================================================

int main() {
    std::cout << "=== JSON Parser and Serializer Demo ===\n\n";
    
    // -------------------------------------------------------------------------
    // 1. Parse a complex nested JSON string
    // -------------------------------------------------------------------------
    std::cout << "1. Parsing complex nested JSON:\n";
    std::cout << std::string(50, '-') << '\n';
    
    std::string complex_json = R"JSON({
        "name": "JSON Parser Test",
        "version": 2.5,
        "enabled": true,
        "features": {
            "unicode": "Hello )JSON" R"JSON(\u4e16\u754c (World in Chinese)",
            "escapes": "Line1\nLine2\tTabbed\\Backslash\"Quote",
            "nested": {
                "level1": {
                    "level2": {
                        "level3": [1, 2, 3, null, true, false]
                    }
                }
            }
        },
        "numbers": {
            "integer": 42,
            "negative": -17,
            "float": 3.14159,
            "scientific": 6.022e23,
            "small": 1.23e-10,
            "zero": 0
        },
        "arrays": {
            "empty": [],
            "mixed": [1, "two", true, null, {"nested": "object"}, [1, 2, 3]],
            "strings": ["apple", "banana", "cherry"]
        },
        "emptyObject": {},
        "metadata": null
    })JSON";
    
    try {
        JsonValue doc = json::parse(complex_json);
        std::cout << "Successfully parsed JSON!\n\n";
        
        // -------------------------------------------------------------------------
        // 2. Access and display various values
        // -------------------------------------------------------------------------
        std::cout << "2. Accessing values:\n";
        std::cout << std::string(50, '-') << '\n';
        
        std::cout << "  name: " << doc["name"].get_string() << '\n';
        std::cout << "  version: " << doc["version"].get_number() << '\n';
        std::cout << "  enabled: " << (doc["enabled"].get_bool() ? "true" : "false") << '\n';
        
        // Using safe accessors with std::optional
        if (auto val = doc["numbers"]["integer"].as_int()) {
            std::cout << "  numbers.integer: " << *val << '\n';
        }
        if (auto val = doc["numbers"]["scientific"].as_number()) {
            std::cout << "  numbers.scientific: " << std::scientific << *val << std::fixed << '\n';
        }
        
        // Access nested values
        std::cout << "  features.unicode: " << doc["features"]["unicode"].get_string() << '\n';
        std::cout << "  features.nested.level1.level2.level3[2]: " 
                  << doc["features"]["nested"]["level1"]["level2"]["level3"][2].as_int().value() << '\n';
        
        // Array access
        std::cout << "  arrays.strings[1]: " << doc["arrays"]["strings"][1].get_string() << '\n';
        std::cout << "  arrays.mixed size: " << doc["arrays"]["mixed"].size() << '\n';
        
        std::cout << '\n';
        
        // -------------------------------------------------------------------------
        // 3. Modify the JSON document
        // -------------------------------------------------------------------------
        std::cout << "3. Modifying the document:\n";
        std::cout << std::string(50, '-') << '\n';
        
        // Add new fields
        doc["newField"] = "Added programmatically";
        doc["timestamp"] = 1234567890;
        doc["numbers"]["added"] = 999;
        
        // Modify existing fields
        doc["version"] = 3.0;
        doc["enabled"] = false;
        
        // Add to arrays
        doc["arrays"]["strings"].push_back("date");
        doc["arrays"]["strings"].push_back("elderberry");
        
        // Create new array
        doc["newArray"] = JsonArray{10, 20, 30, 40, 50};
        
        // Create nested object
        doc["newObject"] = JsonObject{
            {"key1", "value1"},
            {"key2", 42},
            {"key3", JsonArray{true, false, nullptr}}
        };
        
        // Delete a field
        doc.erase("metadata");
        
        std::cout << "  Added fields: newField, timestamp, numbers.added, newArray, newObject\n";
        std::cout << "  Modified: version (now " << doc["version"].as_number().value() << ")\n";
        std::cout << "  Modified: enabled (now " << (doc["enabled"].get_bool() ? "true" : "false") << ")\n";
        std::cout << "  Deleted: metadata\n";
        std::cout << "  arrays.strings now has " << doc["arrays"]["strings"].size() << " elements\n";
        std::cout << '\n';
        
        // -------------------------------------------------------------------------
        // 4. Pretty-print serialization
        // -------------------------------------------------------------------------
        std::cout << "4. Pretty-printed output (first 60 lines):\n";
        std::cout << std::string(50, '-') << '\n';
        
        std::string pretty = json::stringify(doc, true, 2);
        
        // Print first ~60 lines
        std::istringstream iss(pretty);
        std::string line;
        int line_count = 0;
        while (std::getline(iss, line) && line_count < 60) {
            std::cout << line << '\n';
            line_count++;
        }
        if (line_count >= 60) {
            std::cout << "  ... (truncated)\n";
        }
        std::cout << '\n';
        
        // -------------------------------------------------------------------------
        // 5. Compact serialization
        // -------------------------------------------------------------------------
        std::cout << "5. Compact serialization (first 200 chars):\n";
        std::cout << std::string(50, '-') << '\n';
        
        std::string compact = json::compact(doc);
        if (compact.length() > 200) {
            std::cout << compact.substr(0, 200) << "...\n";
        } else {
            std::cout << compact << '\n';
        }
        std::cout << "  Total length: " << compact.length() << " characters\n";
        std::cout << "  Pretty length: " << pretty.length() << " characters\n";
        std::cout << '\n';
        
        // -------------------------------------------------------------------------
        // 6. Build JSON programmatically
        // -------------------------------------------------------------------------
        std::cout << "6. Building JSON programmatically:\n";
        std::cout << std::string(50, '-') << '\n';
        
        JsonValue config = json::object({
            {"application", "MyApp"},
            {"settings", json::object({
                {"theme", "dark"},
                {"fontSize", 14},
                {"autoSave", true},
                {"recentFiles", json::array({
                    "/path/to/file1.txt",
                    "/path/to/file2.txt"
                })}
            })},
            {"users", json::array({
                json::object({{"name", "Alice"}, {"role", "admin"}}),
                json::object({{"name", "Bob"}, {"role", "user"}})
            })}
        });
        
        std::cout << json::stringify(config) << '\n';
        std::cout << '\n';
        
        // -------------------------------------------------------------------------
        // 7. Error handling demonstration
        // -------------------------------------------------------------------------
        std::cout << "7. Error handling demonstrations:\n";
        std::cout << std::string(50, '-') << '\n';
        
        // Test various malformed JSON
        std::vector<std::pair<std::string, std::string>> error_tests = {
            {R"({"key": })", "Missing value"},
            {R"({"key" "value"})", "Missing colon"},
            {R"([1, 2, 3,])", "Trailing comma"},
            {R"("unterminated string)", "Unterminated string"},
            {R"({"key": "\z"})", "Invalid escape"},
            {R"({"key": 12.34.56})", "Invalid number"},
            {R"(undefined)", "Invalid literal"},
        };
        
        for (const auto& [json_str, desc] : error_tests) {
            std::string error;
            auto result = json::try_parse(json_str, &error);
            if (!result) {
                // Truncate long error messages
                if (error.length() > 70) {
                    error = error.substr(0, 67) + "...";
                }
                std::cout << "  " << desc << ":\n    " << error << "\n\n";
            }
        }
        
        // -------------------------------------------------------------------------
        // 8. Value type checking and safe access
        // -------------------------------------------------------------------------
        std::cout << "8. Type checking and safe access:\n";
        std::cout << std::string(50, '-') << '\n';
        
        JsonValue mixed = json::array({42, "hello", true, nullptr, json::object({{"x", 1}})});
        
        for (size_t i = 0; i < mixed.size(); i++) {
            const auto& val = mixed[i];
            std::cout << "  [" << i << "]: type=" << val.type_name();
            
            if (auto n = val.as_int()) {
                std::cout << ", value=" << *n;
            } else if (auto s = val.as_string()) {
                std::cout << ", value=\"" << *s << "\"";
            } else if (auto b = val.as_bool()) {
                std::cout << ", value=" << (*b ? "true" : "false");
            } else if (val.is_null()) {
                std::cout << ", value=null";
            } else if (val.is_object()) {
                std::cout << ", keys=" << val.size();
            }
            std::cout << '\n';
        }
        std::cout << '\n';
        
        // -------------------------------------------------------------------------
        // 9. Using value_or for safe defaults
        // -------------------------------------------------------------------------
        std::cout << "9. Safe defaults with value_or():\n";
        std::cout << std::string(50, '-') << '\n';
        
        JsonValue settings = json::object({
            {"timeout", 30},
            {"verbose", true}
        });
        
        std::cout << "  timeout: " << settings.value_or("timeout", 60) << " (exists)\n";
        std::cout << "  retries: " << settings.value_or("retries", 3) << " (default)\n";
        std::cout << "  verbose: " << (settings.value_or("verbose", false) ? "true" : "false") << " (exists)\n";
        std::cout << "  debug: " << (settings.value_or("debug", false) ? "true" : "false") << " (default)\n";
        std::cout << '\n';
        
        // -------------------------------------------------------------------------
        // 10. Unicode and escape sequence handling
        // -------------------------------------------------------------------------
        std::cout << "10. Unicode and escape sequences:\n";
        std::cout << std::string(50, '-') << '\n';
        
        // Parse JSON with various escape sequences
        JsonValue unicode_test = json::parse(R"({
            "chinese": "\u4e2d\u6587",
            "japanese": "\u65e5\u672c\u8a9e",
            "emoji": "\ud83d\ude00",
            "escapes": "Tab:\t Newline:\n Quote:\" Backslash:\\"
        })");
        
        std::cout << "  Chinese: " << unicode_test["chinese"].get_string() << '\n';
        std::cout << "  Japanese: " << unicode_test["japanese"].get_string() << '\n';
        std::cout << "  Emoji: " << unicode_test["emoji"].get_string() << '\n';
        std::cout << "  Escapes (raw): ";
        for (char c : unicode_test["escapes"].get_string()) {
            if (c == '\t') std::cout << "[TAB]";
            else if (c == '\n') std::cout << "[NL]";
            else std::cout << c;
        }
        std::cout << '\n';
        std::cout << '\n';
        
        std::cout << "=== All tests completed successfully! ===\n";
        
    } catch (const JsonParseError& e) {
        std::cerr << "Parse error: " << e.what() << '\n';
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }
    
    return 0;
}
