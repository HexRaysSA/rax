// Draft AST-only source witness. No SMIR, machine code or native authority.
#pragma once
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/DeclCXX.h"
#include "llvm/Support/JSON.h"
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace smir_witness {
using Object = llvm::json::Object;
using Array = llvm::json::Array;
using Value = llvm::json::Value;

class Producer {
    clang::ASTContext &Context;
    std::string Unit;
    std::map<void *, unsigned> TypeIds;
    std::vector<std::optional<Object>> Types;
    std::map<const clang::RecordDecl *, unsigned> DeclIds;
    std::map<const clang::CXXMethodDecl *, unsigned> MethodIds;
    std::vector<std::optional<Object>> Methods;
    unsigned Work = 0;
    bool Invalid = false;
    bool SourcePrograms = false;

public:
    Producer(clang::ASTContext &Context, std::string Unit, bool SourcePrograms = false);
    Object run();
    Object lifetimePrograms(const std::vector<const clang::RecordDecl *> &Records);
    unsigned type(clang::QualType Type);
    Object reference(clang::QualType Type);
    Object method(const clang::CXXMethodDecl *Method);
    unsigned declaration(const clang::RecordDecl *Record);
    Object input(const clang::RecordDecl *Record);
    Object layout(const clang::RecordDecl *Record);
    Array vptrs(const clang::CXXRecordDecl *Record);
    Object construction(const clang::CXXRecordDecl *Record);
    bool step(unsigned Amount = 1);
    void error(clang::SourceLocation Location, llvm::StringRef Message);
    bool failed() const { return Invalid; }
};
Value some(Value Value);
std::string access(clang::AccessSpecifier Access);
}
