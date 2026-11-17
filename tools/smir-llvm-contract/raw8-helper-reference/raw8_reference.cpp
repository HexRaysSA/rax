// Independent finite per-bit physical Raw model. No target machine or guest ABI.
#include "llvm/Support/JSON.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/raw_ostream.h"
#include <array>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>
using llvm::json::Array;
using llvm::json::Object;
using llvm::json::Value;
static std::string Operation;
static void emit(const char *Status, const std::string &Code, Value Result) {
    Object R{{"format", "smir-raw8-helper-response"}, {"revision", 1},
        {"operation", Operation}, {"status", Status}, {"code", Code},
        {"result", std::move(Result)}, {"source_fact_authority", false},
        {"semantic_admission", false}, {"runtime_authority", false}};
    llvm::outs() << llvm::formatv("{0}\n", Value(std::move(R)));
    llvm::outs().flush();
}
[[noreturn]] static void fail(const std::string &Code, bool Trap = false) {
    emit(Trap ? "trap" : "rejected", Code, nullptr);
    std::exit(Trap ? 3 : 2);
}
static const Object &object(const Value &V) {
    const auto *O = V.getAsObject();
    if (!O) fail("RAW_INPUT");
    return *O;
}
static const Value &field(const Object &O, const char *K) {
    const auto *V = O.get(K);
    if (!V) fail("RAW_INPUT");
    return *V;
}
static void exact(const Object &O, std::initializer_list<const char *> Keys) {
    if (O.size() != Keys.size()) fail("RAW_INPUT");
    for (auto K : Keys) if (!O.get(K)) fail("RAW_INPUT");
}
static std::string text(const Value &V) {
    auto S = V.getAsString();
    if (!S) fail("RAW_INPUT");
    return S->str();
}
static uint64_t number(const Value &V, uint64_t Max = 0xfffffffeULL) {
    auto N = V.getAsInteger();
    if (!N || *N < 0 || static_cast<uint64_t>(*N) > Max) fail("RAW_INPUT");
    return static_cast<uint64_t>(*N);
}
static bool boolean(const Value &V) {
    auto B = V.getAsBoolean();
    if (!B) fail("RAW_INPUT");
    return *B;
}
static uint64_t hex(const Value &V) {
    std::string S = text(V);
    if (S.size() != 16) fail("RAW_INPUT");
    uint64_t R = 0;
    for (char C : S) {
        unsigned D = C >= '0' && C <= '9' ? C - '0' : C >= 'a' && C <= 'f' ? C - 'a' + 10 : 16;
        if (D == 16) fail("RAW_INPUT");
        R = (R << 4) | D;
    }
    return R;
}
static std::string hex(uint64_t V) {
    std::ostringstream S;
    S << std::hex << std::setfill('0') << std::setw(16) << V;
    return S.str();
}
static uint32_t label(const Value &V) {
    if (V.kind() == Value::Null) return 0;
    auto N = number(V);
    if (!N) fail("RAW_INPUT");
    return static_cast<uint32_t>(N);
}
static const Array &array(const Value &V, unsigned Max) {
    const auto *A = V.getAsArray();
    if (!A || A->size() > Max) fail("RAW_INPUT");
    return *A;
}
struct Range {
    bool Present = false, Empty = false, Top = false;
    uint64_t Lower = 0, Upper = 0;
};
static Range range(const Value &V) {
    if (V.kind() == Value::Null) return {};
    const auto &O = object(V);
    exact(O, {"lower", "upper", "upper_is_limit", "empty"});
    Range R{true, boolean(field(O, "empty")), boolean(field(O, "upper_is_limit")),
        hex(field(O, "lower")), hex(field(O, "upper"))};
    if ((R.Top && R.Upper) || (R.Empty && (R.Lower || R.Upper || R.Top)) ||
        (!R.Empty && !R.Top && R.Lower > R.Upper)) fail("RAW_INPUT");
    return R;
}
static bool equal(Range A, Range B) {
    return A.Present == B.Present && A.Empty == B.Empty && A.Top == B.Top &&
        A.Lower == B.Lower && A.Upper == B.Upper;
}
static Range intersect(Range A, Range B) {
    if (!A.Present) return B;
    if (!B.Present) return A;
    if (A.Empty || B.Empty) return {true, true, false, 0, 0};
    Range R{true, false, A.Top && B.Top, std::max(A.Lower, B.Lower),
        A.Top ? B.Upper : B.Top ? A.Upper : std::min(A.Upper, B.Upper)};
    if (!R.Top && R.Lower > R.Upper) return {true, true, false, 0, 0};
    return R;
}
static Value encode(Range R) {
    if (!R.Present) return nullptr;
    return Object{{"lower", hex(R.Lower)}, {"upper", hex(R.Upper)},
        {"upper_is_limit", R.Top}, {"empty", R.Empty}};
}
struct Origin {
    uint32_t Id = 0, Identity = 0, Permit = 0, Lineage = 0, Authority = 0;
    uint64_t Address = 0, Generation = 0;
    std::string Domain;
    Range Bounds;
};
static std::map<uint32_t, Origin> Origins;
static bool equal(const Origin &A, const Origin &B) {
    // Core Pointer authority is retained metadata, excluded from its equality.
    return A.Address == B.Address && A.Identity == B.Identity && A.Generation == B.Generation &&
        A.Domain == B.Domain && equal(A.Bounds, B.Bounds) && A.Permit == B.Permit && A.Lineage == B.Lineage;
}
struct Bit { bool Value = false, Poison = false, Undef = false; uint32_t Origin = 0; unsigned Source = 0; };
struct Raw { unsigned Width = 0; std::array<Bit, 64> Bits{}; };
static Raw raw(const Value &V, unsigned Width = 0) {
    const auto &O = object(V);
    exact(O, {"width", "bits", "poison", "undef", "origins"});
    Raw R; R.Width = number(field(O, "width"), 64);
    if ((R.Width != 8 && R.Width != 64) || (Width && Width != R.Width)) fail("RAW_WIDTH");
    uint64_t B = hex(field(O, "bits")), P = hex(field(O, "poison")), U = hex(field(O, "undef"));
    uint64_t M = R.Width == 64 ? UINT64_MAX : 255;
    if (((B | P | U) & ~M) || (P & U)) fail("RAW_INPUT");
    for (unsigned I = 0; I < R.Width; ++I) R.Bits[I] = {bool((B >> I) & 1), bool((P >> I) & 1), bool((U >> I) & 1), 0, 0};
    unsigned End = 0;
    for (const auto &S : array(field(O, "origins"), 64)) {
        const auto &F = object(S); exact(F, {"offset", "length", "origin", "source"});
        unsigned At = number(field(F, "offset"), 63), N = number(field(F, "length"), 64),
            Source = number(field(F, "source"), 63), Id = label(field(F, "origin"));
        if (!N || At < End || At + N > R.Width || Source + N > 64 || !Origins.count(Id)) fail("RAW_INPUT");
        for (unsigned J = 0; J < N; ++J) {
            Bit &D = R.Bits[At + J];
            if (D.Poison || D.Undef || D.Value != bool((Origins.at(Id).Address >> (Source + J)) & 1)) fail("RAW_ORIGIN_BITS");
            D.Origin = Id; D.Source = Source + J;
        }
        End = At + N;
    }
    return R;
}
static Value encode(const Raw &R) {
    uint64_t B = 0, P = 0, U = 0;
    Array Spans;
    for (unsigned I = 0; I < R.Width; ++I) {
        if (R.Bits[I].Value) B |= uint64_t(1) << I;
        if (R.Bits[I].Poison) P |= uint64_t(1) << I;
        if (R.Bits[I].Undef) U |= uint64_t(1) << I;
        if (!R.Bits[I].Origin) continue;
        unsigned Start = I, Source = R.Bits[I].Source, Id = R.Bits[I].Origin;
        while (I + 1 < R.Width && R.Bits[I + 1].Origin &&
               equal(Origins.at(Id), Origins.at(R.Bits[I + 1].Origin)) && R.Bits[I + 1].Source == Source + I + 1 - Start) ++I;
        Spans.push_back(Object{{"offset", Start}, {"length", I + 1 - Start}, {"origin", Id}, {"source", Source}});
    }
    // Span scanning above skips per-bit accumulation: calculate masks separately.
    B = P = U = 0;
    for (unsigned I = 0; I < R.Width; ++I) {
        if (R.Bits[I].Value) B |= uint64_t(1) << I;
        if (R.Bits[I].Poison) P |= uint64_t(1) << I;
        if (R.Bits[I].Undef) U |= uint64_t(1) << I;
    }
    return Object{{"width", R.Width}, {"bits", hex(B)}, {"poison", hex(P)}, {"undef", hex(U)}, {"origins", std::move(Spans)}};
}
static Raw slice(const Raw &R, unsigned Offset) {
    Raw B; B.Width = 8;
    for (unsigned I = 0; I < 8; ++I) B.Bits[I] = R.Bits[Offset + I];
    return B;
}
struct Memory { uint32_t Object = 0; uint64_t Base = 0, Generation = 0; bool Live = false, Mutable = false; std::vector<bool> Active; std::vector<Raw> Bytes; };
static Memory memory(const Value &V) {
    const auto &O = object(V); exact(O, {"object", "base", "generation", "live", "mutable", "active", "bytes"});
    Memory M; M.Object = label(field(O, "object")); M.Base = hex(field(O, "base")); M.Generation = hex(field(O, "generation"));
    M.Live = boolean(field(O, "live")); M.Mutable = boolean(field(O, "mutable"));
    if (!M.Object) fail("RAW_INPUT");
    for (const auto &B : array(field(O, "bytes"), 64)) M.Bytes.push_back(raw(B, 8));
    for (const auto &A : array(field(O, "active"), 64)) M.Active.push_back(boolean(A));
    if (M.Active.size() != M.Bytes.size() || static_cast<unsigned __int128>(M.Base) + M.Bytes.size() > (static_cast<unsigned __int128>(1) << 64)) fail("RAW_INPUT");
    return M;
}
static Value encode(const Memory &M) {
    Array Bytes, Active;
    for (const auto &B : M.Bytes) Bytes.push_back(encode(B));
    for (bool B : M.Active) Active.push_back(B);
    return Object{{"object", M.Object}, {"base", hex(M.Base)}, {"generation", hex(M.Generation)},
        {"live", M.Live}, {"mutable", M.Mutable}, {"active", std::move(Active)}, {"bytes", std::move(Bytes)}};
}
static unsigned access(const Memory &M, const Value &V, bool Write) {
    const auto &O = object(V); exact(O, {"object", "address", "generation", "domain", "range"});
    uint32_t Id = label(field(O, "object")); uint64_t Address = hex(field(O, "address"));
    if (text(field(O, "domain")) != "data" || Id != M.Object) fail("pointer_provenance", true);
    if (!M.Live || hex(field(O, "generation")) != M.Generation) fail("memory_lifetime", true);
    if (Address < M.Base || static_cast<unsigned __int128>(Address) >= static_cast<unsigned __int128>(M.Base) + M.Bytes.size()) fail("memory_bounds", true);
    if (Write && !M.Mutable) fail("memory_permission", true);
    Range B = range(field(O, "range"));
    if (B.Present && (B.Empty || Address < B.Lower || (!B.Top && static_cast<unsigned __int128>(Address) + 1 > B.Upper))) fail("ub_inrange_access", true);
    unsigned Offset = Address - M.Base;
    if (!M.Active[Offset]) fail("memory_lifetime", true);
    return Offset;
}
int main() {
    std::array<char, 32769> Buffer{}; std::cin.read(Buffer.data(), Buffer.size());
    auto N = std::cin.gcount();
    if (N > 32768) fail("RAW_RESOURCE");
    unsigned Depth = 0;
    bool Quoted = false, Escaped = false;
    for (std::streamsize I = 0; I < N; ++I) {
        char C = Buffer[I];
        if (Quoted) {
            if (Escaped) Escaped = false;
            else if (C == '\\') Escaped = true;
            else if (C == '"') Quoted = false;
        } else if (C == '"') Quoted = true;
        else if (C == '{' || C == '[') {
            if (++Depth > 32) fail("RAW_RESOURCE");
        } else if (C == '}' || C == ']') {
            if (!Depth) fail("RAW_INPUT");
            --Depth;
        } else if ((C >= '0' && C <= '9') || C == '-') {
            std::streamsize End = I;
            for (; End < N; ++End) {
                char D = Buffer[End];
                if (!((D >= '0' && D <= '9') || D == '.' || D == 'e' || D == 'E' || D == '+' || D == '-')) break;
                if (D < '0' || D > '9') fail("RAW_INPUT");
            }
            I = End - 1;
        }
    }
    auto Parsed = llvm::json::parse(llvm::StringRef(Buffer.data(), N));
    if (!Parsed) { llvm::consumeError(Parsed.takeError()); fail("RAW_INPUT"); }
    std::string Canonical;
    llvm::raw_string_ostream CanonicalStream(Canonical);
    CanonicalStream << llvm::formatv("{0}", *Parsed);
    CanonicalStream.flush();
    if (Canonical != std::string(Buffer.data(), N)) fail("RAW_CANONICAL");
    const auto &Q = object(*Parsed); exact(Q, {"format", "revision", "operation", "origins", "arguments"});
    if (text(field(Q, "format")) != "smir-raw8-helper-request" || number(field(Q, "revision"), 1) != 1) fail("RAW_INPUT");
    Operation = text(field(Q, "operation"));
    if (Operation.size() > 64) fail("RAW_INPUT");
    for (const auto &V : array(field(Q, "origins"), 128)) {
        const auto &O = object(V); exact(O, {"id", "bits", "identity", "generation", "domain", "range", "permit", "lineage", "authority"});
        Origin P; P.Id = label(field(O, "id")); P.Address = hex(field(O, "bits")); P.Identity = label(field(O, "identity"));
        P.Generation = hex(field(O, "generation")); P.Domain = text(field(O, "domain")); P.Bounds = range(field(O, "range"));
        P.Permit = label(field(O, "permit")); P.Lineage = label(field(O, "lineage")); P.Authority = label(field(O, "authority"));
        if (!P.Id || !Origins.emplace(P.Id, P).second) fail("RAW_INPUT");
        if (P.Domain != "data" && P.Domain != "code" && P.Domain != "code_address" && P.Domain != "label" && P.Domain != "unprovenanced") fail("RAW_INPUT");
    }
    const auto &A = object(field(Q, "arguments"));
    if (Operation == "from_int8") {
        exact(A, {"state", "bits"}); std::string S = text(field(A, "state")); unsigned B = number(field(A, "bits"), 255);
        if ((S != "concrete" && S != "poison" && S != "undef") || (S != "concrete" && B)) fail("RAW_INPUT");
        Raw R; R.Width = 8;
        for (unsigned I = 0; I < 8; ++I) R.Bits[I] = {bool((B >> I) & 1), S == "poison", S == "undef", 0, 0};
        emit("ok", "", encode(R));
    } else if (Operation == "freeze8" || Operation == "observe8" || Operation == "split_code64") {
        exact(A, {"value"}); Raw R = raw(field(A, "value"), Operation == "split_code64" ? 64 : 8);
        if (Operation == "split_code64") {
            Array Parts; for (unsigned I = 0; I < 8; ++I) Parts.push_back(encode(slice(R, 8 * I)));
            emit("ok", "", std::move(Parts));
        } else if (Operation == "freeze8") {
            for (unsigned I = 0; I < 8; ++I) if (R.Bits[I].Poison || R.Bits[I].Undef) R.Bits[I] = {};
            emit("ok", "", encode(R));
        } else {
            for (unsigned I = 0; I < 8; ++I) if (R.Bits[I].Poison) { emit("ok", "", Object{{"state", "poison"}, {"bits", 0}}); return 0; }
            unsigned B = 0;
            for (unsigned I = 0; I < 8; ++I) {
                if (R.Bits[I].Origin && Origins.at(R.Bits[I].Origin).Bounds.Present) fail("ub_inrange_address_conversion", true);
                if (R.Bits[I].Value && !R.Bits[I].Undef) B |= 1U << I;
            }
            emit("ok", "", Object{{"state", "concrete"}, {"bits", B}});
        }
    } else if (Operation == "join_code64") {
        exact(A, {"values"}); const auto &Parts = array(field(A, "values"), 8);
        if (Parts.size() != 8) fail("RAW_INPUT");
        Raw R; R.Width = 64;
        for (unsigned I = 0; I < 8; ++I) { Raw B = raw(Parts[I], 8); for (unsigned J = 0; J < 8; ++J) R.Bits[8 * I + J] = B.Bits[J]; }
        bool Poison = false, Complete = R.Bits[0].Origin != 0; uint32_t Id = R.Bits[0].Origin; Range Bounds;
        for (unsigned I = 0; I < 64; ++I) {
            Poison |= R.Bits[I].Poison;
            if (!R.Bits[I].Origin || !Id || !equal(Origins.at(Id), Origins.at(R.Bits[I].Origin)) || R.Bits[I].Source != I) Complete = false;
            if (R.Bits[I].Origin) Bounds = intersect(Bounds, Origins.at(R.Bits[I].Origin).Bounds);
        }
        if (Complete) Bounds = Origins.at(Id).Bounds;
        if (Poison) { Id = 0; Bounds = {}; }
        else if (!Complete || Origins.at(Id).Domain != "code_address" || Origins.at(Id).Permit) Id = 0;
        emit("ok", "", Object{{"raw", encode(R)}, {"state", Poison ? "poison" : "concrete"}, {"origin", Id ? Value(Id) : Value(nullptr)}, {"range", encode(Bounds)}});
    } else if (Operation == "load8" || Operation == "store8") {
        if (Operation == "load8") exact(A, {"memory", "pointer"}); else exact(A, {"memory", "pointer", "value", "mask"});
        Memory M = memory(field(A, "memory")); unsigned Offset = access(M, field(A, "pointer"), Operation == "store8");
        if (Operation == "load8") emit("ok", "", encode(M.Bytes[Offset]));
        else {
            Raw R = raw(field(A, "value"), 8); unsigned Mask = number(field(A, "mask"), 255);
            for (unsigned I = 0; I < 8; ++I) if ((Mask >> I) & 1) M.Bytes[Offset].Bits[I] = R.Bits[I];
            emit("ok", "", encode(M));
        }
    } else fail("RAW_OPERATION_UNAVAILABLE");
}
