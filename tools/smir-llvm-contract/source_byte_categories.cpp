// DRAFT independent native category/physical-declaration witness; no source facts.
#include "clang/AST/ASTContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Basic/Version.h"
#include "clang/Tooling/Tooling.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Lex/Preprocessor.h"
#include "clang/Lex/PreprocessorOptions.h"
#include "clang/Lex/PPCallbacks.h"
#include "clang/Basic/DiagnosticLex.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Support/VirtualFileSystem.h"
#include <cstdlib>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <vector>
using namespace clang;
using llvm::json::Array;
using llvm::json::Object;
using llvm::json::Value;
static constexpr const char *Root = "/rax-source-v1/";
[[noreturn]] static void fail(const char *Code, const char *Detail, int Exit = 3) {
    std::string Kind = "unavailable", Public = "BYTE_OBSERVATION_ORACLE_PROTOCOL";
    std::string C = Code;
    if (C == "BYTE_INPUT") { Kind = "semantic"; Public = "BYTE_OBSERVATION_INPUT"; }
    else if (C == "BYTE_LOCATION") { Kind = "semantic"; Public = "BYTE_OBSERVATION_LOCATION"; }
    else if (C == "BYTE_PARSE") { Kind = "semantic"; Public = "BYTE_OBSERVATION_SOURCE_REJECTED"; }
    else if (C == "BYTE_RESOURCE") { Kind = "resource"; Public = "BYTE_OBSERVATION_RESOURCE"; }
    else if (C == "BYTE_RECIPE_UNAVAILABLE") Public = "BYTE_OBSERVATION_RECIPE_UNAVAILABLE";
    else if (C == "BYTE_LIBRARY_UNAVAILABLE") Public = "BYTE_OBSERVATION_LIBRARY_UNAVAILABLE";
    Object Result{{"format", "smir-native-byte-category-core"}, {"revision", 1},
                  {"status", "error"}, {"kind", Kind}, {"code", Public}, {"detail", Detail}};
    llvm::outs() << llvm::formatv("{0}\n", Value(std::move(Result)));
    llvm::outs().flush();
    std::exit(Exit);
}
static std::string hash(llvm::StringRef S) {
    auto H = llvm::SHA256::hash(llvm::ArrayRef<uint8_t>(
        reinterpret_cast<const uint8_t *>(S.data()), S.size()));
    return llvm::toHex(H, true);
}
static bool pathOK(llvm::StringRef S) {
    if (S.empty() || S.starts_with("/") || S.contains('\\') || S.contains('\0')) return false;
    llvm::SmallVector<llvm::StringRef, 8> Parts;
    S.split(Parts, '/');
    for (auto P : Parts) if (P.empty() || P == "." || P == "..") return false;
    return true;
}
static std::string text(const Object &O, llvm::StringRef K) {
    auto S = O.getString(K);
    if (!S) fail("BYTE_INPUT", "required string", 2);
    return S->str();
}
static const Object &object(const Value &V) {
    auto *O = V.getAsObject();
    if (!O) fail("BYTE_INPUT", "expected object", 2);
    return *O;
}
static void fields(const Object &O, std::initializer_list<const char *> Names) {
    if (O.size() != Names.size()) fail("BYTE_INPUT", "closed object arity", 2);
    for (auto N : Names) if (!O.get(N)) fail("BYTE_INPUT", "closed object key", 2);
}
struct File { std::string Data, Hash; };
using Key = std::tuple<std::string, unsigned, std::string>;
class Observer : public RecursiveASTVisitor<Observer> {
    ASTContext &C;
    const std::map<std::string, File> &Files;
    const std::vector<Key> &Queries;
    std::map<Key, Value> Found;
    std::set<Key> Wanted;
    unsigned Work = 0;
    std::string physical(SourceLocation L) {
        if (L.isInvalid() || L.isMacroID()) fail("BYTE_LOCATION", "nonphysical declaration");
        auto Name = C.getSourceManager().getFilename(L);
        if (!Name.consume_front(Root) || !Files.count(Name.str()))
            fail("BYTE_LOCATION", "declaration not in exact virtual bundle");
        return Name.str();
    }
    Value location(const Decl *D) {
        std::string Name = physical(D->getLocation());
        return Object{{"file", Name}, {"offset", C.getSourceManager().getFileOffset(D->getLocation())},
                      {"file_sha256", Files.at(Name).Hash}};
    }
    bool pinned(const EnumDecl *D, const char *Name, const char *Hash) {
        if (!D || D->getLocation().isInvalid() || D->getLocation().isMacroID()) return false;
        auto L = D->getLocation();
        auto F = C.getSourceManager().getFilename(L);
        if (!F.consume_front(Root) || F != Name) return false;
        auto I = Files.find(Name);
        if (I == Files.end() || I->second.Hash != Hash) return false;
        auto At = I->second.Data.find("enum class byte");
        return At != std::string::npos &&
               C.getSourceManager().getFileOffset(L) == At + std::string("enum class ").size();
    }
    Value observe(QualType Q, const Key &K) {
        Q = C.getCanonicalType(Q);
        const Type *T = Q.getTypePtr();
        std::string Kind = T->getTypeClassName();
        const char *Category = "unsupported";
        Value Declaration = nullptr, Definition = nullptr;
        if (const auto *B = dyn_cast<BuiltinType>(T)) {
            switch (B->getKind()) {
#define BUILTIN_TYPE(Id, SingletonId) case BuiltinType::Id: Kind = "Builtin:" #Id; break;
#include "clang/AST/BuiltinTypes.def"
            default: Kind = "Builtin:" + B->getName(C.getPrintingPolicy()).str(); break;
            }
            if (B->getKind() == BuiltinType::Char_U)
                fail("BYTE_RECIPE_UNAVAILABLE", "unsigned plain char");
            switch (B->getKind()) {
            case BuiltinType::Char_S: Category = "char"; break;
            case BuiltinType::SChar: Category = "signed_char"; break;
            case BuiltinType::UChar: Category = "unsigned_char"; break;
            case BuiltinType::Char8: Category = "char8_t"; break;
            default: if (T->isIntegerType() || T->isRealFloatingType()) Category = "numeric"; break;
            }
        } else if (const auto *E = dyn_cast<EnumType>(T)) {
            const auto *First = E->getDecl()->getCanonicalDecl();
            Declaration = location(First);
            Category = "numeric";
            if (T->isStdByteType()) {
                const auto *Def = First->getDefinition();
                if (!pinned(First, "libcxx/__fwd/byte.h", "4465d56f10be4ac0340d502ad34f4a6f772a194d08e981eadcffcea91f138670") ||
                    !pinned(Def, "libcxx/__cstddef/byte.h", "b4e4f7dbb20ba21e4e3a622c206b6e1d365da83d8abb086181704b67e4587aa7") ||
                    !First->isScoped() || !Def->enumerators().empty() ||
                    !C.hasSameType(Def->getIntegerType(), C.UnsignedCharTy))
                    fail("BYTE_LIBRARY_UNAVAILABLE", "std byte first/definition not actual pinned declarations");
                Category = "std_byte";
                Definition = location(Def);
            }
        } else if (isa<BitIntType>(T)) Category = "numeric";
        Value Precision = nullptr, Signed = nullptr, Storage = nullptr, Alignment = nullptr;
        QualType Integer = Q;
        if (const auto *E = dyn_cast<EnumType>(T)) Integer = E->getDecl()->getIntegerType();
        if (!Integer.isNull() && !Integer->isDependentType() && Integer->isIntegerType()) {
            Precision = C.getIntWidth(Integer);
            Signed = Integer->isSignedIntegerType();
        }
        if (T->isObjectType() && !T->isIncompleteType() && !T->isDependentType() &&
            !T->isVariablyModifiedType() && !T->isSizelessType()) {
            Storage = C.getTypeSize(Q);
            Alignment = C.getTypeAlign(Q);
        }
        if (std::string(Category) == "char" || std::string(Category) == "signed_char" ||
            std::string(Category) == "unsigned_char" || std::string(Category) == "char8_t" ||
            std::string(Category) == "std_byte") {
            if (C.getIntWidth(Integer) != 8 || C.getTypeSize(Q) != 8 || C.getTypeAlign(Q) != 8)
                fail("BYTE_RECIPE_UNAVAILABLE", "byte dimension mismatch");
        }
        const char *CV = Q.isConstQualified() ? (Q.isVolatileQualified() ? "const_volatile" : "const") :
                                              (Q.isVolatileQualified() ? "volatile" : "none");
        return Object{{"selector", Object{{"file", std::get<0>(K)}, {"offset", std::get<1>(K)}, {"kind", std::get<2>(K)}}},
            {"canonical_kind", Kind}, {"category", Category}, {"value_bits", std::move(Precision)},
            {"storage_bits", std::move(Storage)}, {"alignment_bits", std::move(Alignment)},
            {"signed", std::move(Signed)}, {"cv", CV}, {"declaration", std::move(Declaration)},
            {"library_definition", std::move(Definition)}};
    }
    void visit(Decl *D, QualType Q, const char *Kind) {
        SourceLocation L = D->getLocation();
        if (L.isInvalid() || L.isMacroID()) return;
        auto F = C.getSourceManager().getFilename(L);
        if (!F.consume_front(Root)) return;
        Key K{F.str(), C.getSourceManager().getFileOffset(L), Kind};
        if (Wanted.find(K) == Wanted.end()) return;
        if (Found.count(K)) fail("BYTE_LOCATION", "ambiguous declaration");
        Found.emplace(K, observe(Q, K));
    }
public:
    Observer(ASTContext &Context, const std::map<std::string, File> &F, const std::vector<Key> &Q)
        : C(Context), Files(F), Queries(Q), Wanted(Q.begin(), Q.end()) {}
    bool VisitDecl(Decl *) { if (++Work > 100000) fail("BYTE_RESOURCE", "AST work", 4); return true; }
    bool VisitStmt(Stmt *) { if (++Work > 100000) fail("BYTE_RESOURCE", "AST work", 4); return true; }
    bool VisitTypeLoc(TypeLoc) { if (++Work > 100000) fail("BYTE_RESOURCE", "AST work", 4); return true; }
    bool VisitVarDecl(VarDecl *D) { visit(D, D->getType(), isa<ParmVarDecl>(D) ? "parameter" : "var"); return true; }
    bool VisitFieldDecl(FieldDecl *D) { visit(D, D->getType(), "field"); return true; }
    bool VisitTypedefNameDecl(TypedefNameDecl *D) { visit(D, D->getUnderlyingType(), "typedef"); return true; }
    bool VisitEnumDecl(EnumDecl *D) { visit(D, C.getCanonicalTypeDeclType(D), "enum"); return true; }
    Array finish() {
        Array A;
        for (const auto &K : Queries) {
            auto I = Found.find(K);
            if (I == Found.end()) fail("BYTE_LOCATION", "selector absent or macro");
            A.push_back(std::move(I->second));
        }
        return A;
    }
};
class Policy : public PPCallbacks {
    SourceManager &SM;
    std::set<std::string> CompilerPredefines;
    void check(const Token &T) {
        const auto *I = T.getIdentifierInfo();
        if (!I) return;
        auto N = I->getName();
        auto P = SM.getFilename(SM.getSpellingLoc(T.getLocation()));
        if (P.empty()) {
            if (N.starts_with("__") || N == "_LP64" || N == "_ILP32") CompilerPredefines.insert(N.str());
            return;
        }
        if (N == "__DATE__" || N == "__TIME__" || N == "__TIMESTAMP__" || CompilerPredefines.count(N.str()))
            fail("BYTE_RECIPE_UNAVAILABLE", "protected profile predefine source override");
    }
public:
    explicit Policy(SourceManager &S) : SM(S) {}
    void MacroDefined(const Token &T, const MacroDirective *) override { check(T); }
    void MacroUndefined(const Token &T, const MacroDefinition &, const MacroDirective *) override { check(T); }
    bool FileNotFound(llvm::StringRef) override {
        fail("BYTE_RECIPE_UNAVAILABLE", "required virtual include missing");
    }
    void InclusionDirective(SourceLocation L, const Token &, llvm::StringRef Name,
        bool, CharSourceRange, OptionalFileEntryRef, llvm::StringRef, llvm::StringRef,
        const Module *, bool, SrcMgr::CharacteristicKind) override {
        if (SM.getFilename(SM.getSpellingLoc(L)).empty() && Name.starts_with(Root)) return;
        if (!pathOK(Name)) fail("BYTE_RECIPE_UNAVAILABLE", "absolute or escaping include path");
    }
    void moduleImport(SourceLocation, ModuleIdPath, const Module *) override {
        fail("BYTE_RECIPE_UNAVAILABLE", "module import unsupported by observational backend");
    }
};
class Diagnostics : public DiagnosticConsumer {
public:
    bool MissingFile = false;
    void HandleDiagnostic(DiagnosticsEngine::Level L, const Diagnostic &D) override {
        DiagnosticConsumer::HandleDiagnostic(L, D);
        if (D.getID() == diag::err_pp_file_not_found) MissingFile = true;
    }
};
class Consumer : public ASTConsumer {
    const std::map<std::string, File> &Files;
    const std::vector<Key> &Queries;
    Array &Rows;
public:
    Consumer(const std::map<std::string, File> &F, const std::vector<Key> &Q, Array &R)
        : Files(F), Queries(Q), Rows(R) {}
    void HandleTranslationUnit(ASTContext &C) override {
        if (C.getDiagnostics().hasErrorOccurred()) return;
        if (!C.getLangOpts().CurrentModule.empty()) fail("BYTE_RECIPE_UNAVAILABLE", "module unit");
        if (C.getCharWidth() != 8 || C.getTypeSize(C.LongTy) != 64 || C.getTargetInfo().isBigEndian() ||
            C.getTargetInfo().getPointerWidth(LangAS::Default) != 64)
            fail("BYTE_RECIPE_UNAVAILABLE", "target");
        Observer O(C, Files, Queries);
        O.TraverseDecl(C.getTranslationUnitDecl());
        Rows = O.finish();
    }
};
class Action : public ASTFrontendAction {
    const std::map<std::string, File> &Files;
    const std::vector<Key> &Queries;
    Array &Rows;
public:
    Action(const std::map<std::string, File> &F, const std::vector<Key> &Q, Array &R)
        : Files(F), Queries(Q), Rows(R) {}
    bool BeginInvocation(CompilerInstance &CI) override {
        CI.getPreprocessorOpts().SourceDateEpoch = 0;
        CI.getPreprocessorOpts().InitDateTimeMacros = DateTimeInitKind::Default;
        return true;
    }
    bool BeginSourceFileAction(CompilerInstance &CI) override {
        CI.getPreprocessor().addPPCallbacks(std::make_unique<Policy>(CI.getSourceManager()));
        return true;
    }
    std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &, llvm::StringRef) override {
        return std::make_unique<Consumer>(Files, Queries, Rows);
    }
};
static void validateArguments(const std::vector<std::string> &A) {
    static const std::set<std::string> Single{
        "-O0", "-O1", "-O2", "-O3", "-Os", "-Oz", "-pedantic-errors",
        "-std=c23", "-std=gnu23", "-std=c++23", "-std=gnu++23"};
    static const std::set<std::string> Pair{"-I", "-iquote", "-isystem", "-idirafter", "-include"};
    for (size_t I = 0; I < A.size(); ++I) {
        llvm::StringRef S = A[I];
        if (S.contains('\n') || S.contains('\r') || S.contains('\0')) fail("BYTE_INPUT", "argument encoding", 2);
        if (Single.count(A[I])) continue;
        if (Pair.count(A[I])) {
            if (++I == A.size()) fail("BYTE_INPUT", "argument pair", 2);
            llvm::StringRef P = A[I];
            if (!P.consume_front(Root) || (!P.empty() && !pathOK(P))) fail("BYTE_INPUT", "argument path", 2);
            continue;
        }
        if (S.consume_front("-D") || S.consume_front("-U")) {
            auto N = S.take_until([](char C) { return C == '=' || C == '('; });
            if (N == "__DATE__" || N == "__TIME__" || N == "__TIMESTAMP__")
                fail("BYTE_RECIPE_UNAVAILABLE", "protected clock macro recipe override");
            if (N.empty()) fail("BYTE_INPUT", "macro name", 2);
            continue;
        }
        fail("BYTE_INPUT", "unknown private native argument", 2);
    }
}
int main() {
    std::string Input(4 * 1024 * 1024 + 1, '\0');
    std::cin.read(Input.data(), Input.size()); Input.resize(std::cin.gcount());
    if (Input.size() > 4 * 1024 * 1024) fail("BYTE_RESOURCE", "request size", 4);
    auto Parsed = llvm::json::parse(Input);
    if (!Parsed) { llvm::consumeError(Parsed.takeError()); fail("BYTE_INPUT", "JSON", 2); }
    const auto &R = object(*Parsed); fields(R, {"language", "entry", "files", "selectors", "arguments"});
    std::string Language = text(R, "language"), Entry = text(R, "entry");
    if ((Language != "c23" && Language != "cpp23") || !pathOK(Entry)) fail("BYTE_INPUT", "language/entry", 2);
    auto *F = R.getArray("files"), *Q = R.getArray("selectors"), *A = R.getArray("arguments");
    if (!F || !Q || !A || F->size() > 4096 || Q->size() > 4096 || A->size() > 4096)
        fail("BYTE_INPUT", "vectors", 2);
    std::vector<std::string> Extra;
    for (const auto &V : *A) {
        auto S = V.getAsString(); if (!S) fail("BYTE_INPUT", "argument string", 2);
        Extra.push_back(S->str());
    }
    validateArguments(Extra);
    auto FS = llvm::makeIntrusiveRefCnt<llvm::vfs::InMemoryFileSystem>();
    if (FS->setCurrentWorkingDirectory("/rax-source-v1")) fail("BYTE_INTERNAL", "cwd", 70);
    std::map<std::string, File> Files;
    size_t Bytes = 0;
    for (const auto &V : *F) {
        const auto &O = object(V); fields(O, {"name", "data"});
        std::string Name = text(O, "name"), Hex = text(O, "data");
        if (!pathOK(Name) || Hex.size() % 2 || Hex.find_first_not_of("0123456789abcdef") != std::string::npos)
            fail("BYTE_INPUT", "file path/hex", 2);
        std::string Data = llvm::fromHex(Hex); Bytes += Data.size();
        if (Bytes > 1024 * 1024) fail("BYTE_RESOURCE", "source bytes", 4);
        if (!Files.emplace(Name, File{Data, hash(Data)}).second) fail("BYTE_INPUT", "duplicate file", 2);
        FS->addFile(std::string(Root) + Name, 0, llvm::MemoryBuffer::getMemBufferCopy(Data));
    }
    if (!Files.count(Entry)) fail("BYTE_INPUT", "entry missing", 2);
    std::vector<Key> Queries; std::set<Key> Unique;
    for (const auto &V : *Q) {
        const auto &O = object(V); fields(O, {"file", "offset", "kind"});
        std::string File = text(O, "file"), Kind = text(O, "kind"); auto At = O.getInteger("offset");
        if (!At || *At < 0 || *At > 0xfffffffeLL || !Files.count(File) || static_cast<uint64_t>(*At) >= Files.at(File).Data.size() ||
            (Kind != "var" && Kind != "parameter" && Kind != "field" && Kind != "typedef" && Kind != "enum"))
            fail("BYTE_INPUT", "selector", 2);
        Key K{File, static_cast<unsigned>(*At), Kind};
        if (!Unique.insert(K).second) fail("BYTE_INPUT", "duplicate selector", 2);
        Queries.push_back(K);
    }
    std::vector<std::string> Options{"clang-tool", "-fsyntax-only", "-target", "x86_64-unknown-linux-gnu",
        "-nostdinc", "-fsigned-char", "-fno-short-enums", "-ffp-contract=off", "-fno-fast-math",
        "-Xclang", "-source-date-epoch", "-Xclang", "0", "-fno-implicit-modules", "-fno-implicit-module-maps"};
    if (Language == "cpp23") Options.insert(Options.end(), {"-xc++", "-nostdinc++", "-fexceptions", "-fcxx-exceptions", "-frtti", "-fthreadsafe-statics"});
    else Options.insert(Options.end(), {"-xc"});
    Options.insert(Options.end(), Extra.begin(), Extra.end());
    Options.push_back(std::string(Root) + Entry);
    Array Rows;
    FileSystemOptions FO; FO.WorkingDir = "/rax-source-v1";
    llvm::IntrusiveRefCntPtr<FileManager> FM(new FileManager(FO, FS));
    Diagnostics D;
    tooling::ToolInvocation Invocation(Options, std::make_unique<Action>(Files, Queries, Rows), FM.get());
    Invocation.setDiagnosticConsumer(&D);
    if (!Invocation.run()) {
        if (D.MissingFile) fail("BYTE_RECIPE_UNAVAILABLE", "missing virtual include");
        fail("BYTE_PARSE", "actual pinned frontend rejected source");
    }
    Object Result{{"format", "smir-native-byte-category-core"}, {"revision", 1}, {"status", "ok"},
        {"binding", "unbound"}, {"source_fact_authority", false}, {"semantic_admission", false}, {"runtime_authority", false},
        {"recipe_profile", "lp64-ast-surrogate-v1"}, {"library_version", getClangFullVersion()},
        {"language", Language}, {"input_sha256", hash(Input)}, {"rows", std::move(Rows)}};
    llvm::outs() << llvm::formatv("{0}\n", Value(std::move(Result)));
}
