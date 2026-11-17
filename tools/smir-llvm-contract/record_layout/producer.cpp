#include "producer.hpp"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/ExprCXX.h"
#include "clang/Basic/Version.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"
#include <set>

namespace smir_witness {
class Records : public clang::RecursiveASTVisitor<Records> {
    clang::ASTContext &Context;
public:
    std::vector<const clang::RecordDecl *> Found;
    std::vector<const clang::CallExpr *> Calls;
    std::vector<const clang::CXXThrowExpr *> Throws;
    std::vector<const clang::CXXMethodDecl *> DeclaredMethods;
    std::set<const clang::CXXMethodDecl *> SeenMethods;
    std::vector<const clang::FunctionDecl *> Functions;
    std::set<const clang::FunctionDecl *> SeenFunctions;
    std::vector<const clang::VarDecl *> FunctionVariables;
    explicit Records(clang::ASTContext &C) : Context(C) {}
    bool VisitRecordDecl(clang::RecordDecl *R) {
        if (R->isCompleteDefinition() && !R->isImplicit() &&
            Context.getSourceManager().isWrittenInMainFile(R->getLocation())) Found.push_back(R);
        return true;
    }
    bool VisitCallExpr(clang::CallExpr *Call) {
        if (Context.getSourceManager().isWrittenInMainFile(Call->getExprLoc())) Calls.push_back(Call);
        return true;
    }
    bool VisitCXXThrowExpr(clang::CXXThrowExpr *Throw) {
        if (Context.getSourceManager().isWrittenInMainFile(Throw->getExprLoc())) Throws.push_back(Throw);
        return true;
    }
    bool VisitCXXMethodDecl(clang::CXXMethodDecl *Method) {
        Method = Method->getCanonicalDecl();
        if (!Method->isImplicit() && !Method->getParent()->isDependentContext() &&
            Context.getSourceManager().isWrittenInMainFile(Method->getLocation()) &&
            SeenMethods.insert(Method).second) DeclaredMethods.push_back(Method);
        return true;
    }
    bool VisitFunctionDecl(clang::FunctionDecl *Function) {
        if (!llvm::isa<clang::CXXMethodDecl>(Function) && !Function->isImplicit() &&
            !Function->isDependentContext() &&
            Context.getSourceManager().isWrittenInMainFile(Function->getLocation()) &&
            SeenFunctions.insert(Function->getCanonicalDecl()).second)
            Functions.push_back(Function->getCanonicalDecl());
        return true;
    }
    bool VisitVarDecl(clang::VarDecl *Variable) {
        auto Type = Variable->getType();
        if (Variable->hasGlobalStorage() && !Type->isDependentType() &&
            (Type->isPointerType() || Type->isReferenceType()) &&
            Type->getPointeeType()->isFunctionType() &&
            Context.getSourceManager().isWrittenInMainFile(Variable->getLocation()))
            FunctionVariables.push_back(Variable);
        return true;
    }
};
Object Producer::run() {
    Records Visitor(Context);
    Visitor.TraverseDecl(Context.getTranslationUnitDecl());
    if (Visitor.Found.size() > 256) error({}, "E-WITNESS-RESOURCE: record limit");
    for (const auto *R : Visitor.Found) declaration(R);
    if (SourcePrograms) return lifetimePrograms(Visitor.Found);
    Array Roots;
    for (const auto *R : Visitor.Found) {
        if (failed()) break;
        if (R->isDependentContext()) {
            error(R->getLocation(), "E-WITNESS-DEPENDENT-RECORD");
            break;
        }
        Roots.push_back(reference(Context.getTypeDeclType(clang::ElaboratedTypeKeyword::None, std::nullopt, R)));
    }
    Array Calls, Throws, Declarations;
    unsigned UnissuedCalls = 0;
    if (Visitor.Calls.size() + Visitor.Throws.size() > 256)
        error({}, "E-WITNESS-RESOURCE: expression observation limit");
    for (const auto *Call : Visitor.Calls) {
        if (failed()) break;
        if (Call->isTypeDependent() || Call->isValueDependent()) { ++UnissuedCalls; continue; }
        if (!step(Call->getNumArgs())) break;
        Array Arguments;
        for (const auto *Argument : Call->arguments()) {
            if (Argument->isTypeDependent()) { error(Call->getExprLoc(), "E-WITNESS-DEPENDENT-CALL"); break; }
            Arguments.push_back(reference(Argument->getType()));
        }
        const auto *Callee = Call->getDirectCallee();
        Calls.push_back(Object{{"callee", Callee ? Callee->getQualifiedNameAsString() : "<indirect>"},
                               {"arguments_after_sema", std::move(Arguments)}});
    }
    for (const auto *Throw : Visitor.Throws) {
        if (failed()) break;
        if (!step()) break;
        const auto *Operand = Throw->getSubExpr();
        Value Type = nullptr;
        if (Operand) {
            if (Operand->isTypeDependent()) { error(Throw->getExprLoc(), "E-WITNESS-DEPENDENT-THROW"); break; }
            Type = some(reference(Context.getExceptionObjectType(Operand->getType())));
        }
        Throws.push_back(Object{{"rethrow", Operand == nullptr}, {"normalized_payload_type", std::move(Type)}});
    }
    if (Visitor.DeclaredMethods.size() > 512) error({}, "E-WITNESS-RESOURCE: method observation limit");
    for (const auto *Method : Visitor.DeclaredMethods) {
        if (failed() || !step(8)) break;
        Array Parameters;
        for (const auto *Parameter : Method->parameters()) Parameters.push_back(Parameter->getType().getAsString());
        Declarations.push_back(Object{{"name", Method->getQualifiedNameAsString()},
            {"parent_source_type", reference(Context.getTypeDeclType(
                clang::ElaboratedTypeKeyword::None, std::nullopt, Method->getParent()))},
            {"static", Method->isStatic()}, {"explicit_object", Method->isExplicitObjectMemberFunction()},
            {"implicit_this", Method->isImplicitObjectMemberFunction()},
            {"ref_qualifier", Method->getRefQualifier() == clang::RQ_LValue ? "lvalue" :
                Method->getRefQualifier() == clang::RQ_RValue ? "rvalue" : "none"},
            {"undeduced_return", Method->getReturnType()->isUndeducedType()},
            {"function_spelling", Method->getType().getAsString()}, {"parameter_spellings", std::move(Parameters)},
            {"runtime_binding", false}});
    }
    Array FunctionDeclarations, VariableRoots;
    if (Visitor.Functions.size() + Visitor.FunctionVariables.size() > 512)
        error({}, "E-WITNESS-RESOURCE: ordinary function declaration limit");
    for (const auto *Original : Visitor.Functions) {
        const auto *Function = Original->getMostRecentDecl();
        if (failed() || !step(4)) break;
        if (Function->getType()->isDependentType() || Function->getReturnType()->isUndeducedType())
            continue;
        FunctionDeclarations.push_back(Object{
            {"name", Function->getQualifiedNameAsString()},
            {"type", reference(Function->getType())},
            {"source_linkage", Function->getLanguageLinkage() == clang::CLanguageLinkage ? "c" : "cpp"}});
    }
    for (const auto *Variable : Visitor.FunctionVariables) {
        if (failed() || !step(4)) break;
        VariableRoots.push_back(Object{{"name", Variable->getQualifiedNameAsString()},
                                       {"type", reference(Variable->getType())}});
    }
    Array TypeNodes, MethodNodes;
    for (auto &T : Types) {
        if (!T) { error({}, "E-WITNESS-TYPE-INCOMPLETE"); break; }
        TypeNodes.push_back(std::move(*T));
    }
    for (auto &M : Methods) {
        if (!M) { error({}, "E-WITNESS-METHOD-INCOMPLETE"); break; }
        MethodNodes.push_back(std::move(*M));
    }
    return Object{{"format", "clang-record-input-draft-v2"}, {"source_owner", Unit},
                  {"language", Context.getLangOpts().CPlusPlus ? "cpp23" : "c23"},
                  {"library_version", clang::getClangFullVersion()},
                  {"status", failed() ? "rejected" : "source-witness"},
                  {"record_roots", std::move(Roots)}, {"types", std::move(TypeNodes)},
                  {"function_declarations", std::move(FunctionDeclarations)},
                  {"variable_type_roots", std::move(VariableRoots)},
                  {"calls", std::move(Calls)}, {"throws", std::move(Throws)},
                  {"declared_method_observations", std::move(Declarations)}, {"unissued_call_observations", UnissuedCalls},
                  {"method_declarations", std::move(MethodNodes)},
                  {"target", "x86_64-unknown-linux-gnu"}, {"native_layout_oracle", true},
                  {"portable_layout_certified", false}, {"runtime_symbols_bound", false},
                  {"smir_emitted", false}, {"backend_emission", false}, {"native_execution", false}};
}
class Consumer : public clang::ASTConsumer {
    std::optional<Object> &Result;
    std::string Unit;
    bool Programs;
public:
    Consumer(std::optional<Object> &R, std::string U, bool P) : Result(R), Unit(std::move(U)), Programs(P) {}
    void HandleTranslationUnit(clang::ASTContext &Context) override {
        if (Context.getDiagnostics().hasErrorOccurred()) return;
        Producer P(Context, Unit, Programs);
        Result = P.run();
    }
};
class Action : public clang::ASTFrontendAction {
    std::optional<Object> &Result;
    std::string Unit;
    bool Programs;
public:
    Action(std::optional<Object> &R, std::string U, bool P) : Result(R), Unit(std::move(U)), Programs(P) {}
    std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(clang::CompilerInstance &, llvm::StringRef) override {
        return std::make_unique<Consumer>(Result, Unit, Programs);
    }
};
}
int main(int Argc, char **Argv) {
    if (Argc < 3 || Argc > 5) {
        llvm::errs() << "usage: record-input-witness SOURCE LOGICAL_UNIT [c23|cpp23] [--source-programs]\n";
        return 2;
    }
    std::string Unit = Argv[2];
    if (Unit.empty() || Unit.size() > 128 || Unit.find_first_not_of(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != std::string::npos) {
        llvm::errs() << "invalid logical unit\n";
        return 2;
    }
    bool Programs = Argc > 3 && std::string(Argv[Argc - 1]) == "--source-programs";
    int Positional = Argc - (Programs ? 1 : 0);
    if (Positional > 4) return 2;
    bool C = Positional == 4 && std::string(Argv[3]) == "c23";
    if (Positional == 4 && !C && std::string(Argv[3]) != "cpp23") return 2;
    if (C && Programs) {
        llvm::errs() << "E-SOURCE-PROGRAM-CXX-REQUIRED\n";
        return 2;
    }
    auto Source = llvm::MemoryBuffer::getFile(Argv[1]);
    if (!Source || (*Source)->getBufferSize() > 1024 * 1024) { llvm::errs() << "source IO/size\n"; return 2; }
    std::optional<smir_witness::Object> Result;
    std::vector<std::string> Arguments = {C ? "-xc" : "-xc++", C ? "-std=c23" : "-std=c++23",
        "-target", "x86_64-unknown-linux-gnu", "-nostdinc", "-pedantic-errors"};
    if (!C) Arguments.push_back("-nostdinc++");
    bool Success = clang::tooling::runToolOnCodeWithArgs(std::make_unique<smir_witness::Action>(Result, Unit, Programs),
        (*Source)->getBuffer(), Arguments, Argv[1]);
    if (!Result || !Success) return 1;
    llvm::outs() << llvm::formatv("{0:2}\n", llvm::json::Value(std::move(*Result)));
    return 0;
}
