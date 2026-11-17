#include "producer.hpp"
#include "clang/AST/Attr.h"
#include "clang/AST/RecordLayout.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/TargetInfo.h"
#include "llvm/ADT/SmallString.h"
#include <limits>

namespace smir_witness {
Value some(Value V) { return Object{{"some", std::move(V)}}; }
std::string access(clang::AccessSpecifier A) {
    switch (A) {
        case clang::AS_public: return "public";
        case clang::AS_protected: return "protected";
        case clang::AS_private: return "private";
        case clang::AS_none: return "public"; // C record fields have no C++ access.
    }
    llvm_unreachable("access kind");
}
Producer::Producer(clang::ASTContext &C, std::string U, bool Programs)
    : Context(C), Unit(std::move(U)), SourcePrograms(Programs) {}
bool Producer::step(unsigned N) {
    if (N > 100000 - Work) {
        error({}, "E-WITNESS-RESOURCE: source graph work limit");
        return false;
    }
    Work += N;
    return true;
}
void Producer::error(clang::SourceLocation L, llvm::StringRef Message) {
    Invalid = true;
    unsigned Id = Context.getDiagnostics().getCustomDiagID(clang::DiagnosticsEngine::Error, "%0");
    Context.getDiagnostics().Report(L, Id) << Message;
}
unsigned Producer::declaration(const clang::RecordDecl *R) {
    R = llvm::cast<clang::RecordDecl>(R->getCanonicalDecl());
    auto Result = DeclIds.emplace(R, DeclIds.size());
    return Result.first->second;
}
Object Producer::reference(clang::QualType T) {
    return Object{{"module", Object{{"kind", "self"}}}, {"id", type(T)}};
}
unsigned Producer::type(clang::QualType T) {
    T = Context.getCanonicalType(T);
    void *Key = T.getAsOpaquePtr();
    auto Found = TypeIds.find(Key);
    if (Found != TypeIds.end()) return Found->second;
    if (!step(8) || Types.size() >= 4096) {
        error({}, "E-WITNESS-RESOURCE: type graph limit");
        return 0;
    }
    unsigned Id = Types.size();
    TypeIds.emplace(Key, Id);
    Types.emplace_back(); // Reserve before traversing pointer/self edges.
    Object Node{{"id", Id}, {"owner", Unit}, {"spelling", T.getAsString()},
                {"const", T.isConstQualified()}, {"volatile", T.isVolatileQualified()}};
    if (const auto *R = T->getAs<clang::RecordType>()) {
        const clang::RecordDecl *D = R->getDecl()->getDefinition();
        Node["kind"] = "record";
        Node["record_name"] = R->getDecl()->getQualifiedNameAsString();
        Node["source_decl"] = declaration(R->getDecl());
        const auto *Cxx = llvm::dyn_cast<clang::CXXRecordDecl>(R->getDecl());
        Node["is_lambda"] = Cxx && Cxx->isLambda();
        Node["complete"] = D != nullptr;
        Node["record_input"] = D ? some(input(D)) : Value(nullptr);
        if (D && !failed()) {
            Object Selected = layout(D);
            Selected["type"] = reference(T);
            Node["native_layout"] = std::move(Selected);
            if (Cxx && Cxx->getNumVBases()) Node["construction"] = construction(Cxx);
        } else Node["native_layout"] = nullptr;
    } else if (const auto *A = Context.getAsConstantArrayType(T)) {
        Node["kind"] = "array";
        Node["element"] = reference(A->getElementType());
        if (A->getSize().getActiveBits() > 63) error({}, "E-WITNESS-ARRAY-EXTENT");
        else Node["count"] = static_cast<int64_t>(A->getSize().getZExtValue());
    } else if (const auto *A = Context.getAsIncompleteArrayType(T)) {
        Node["kind"] = "array";
        Node["element"] = reference(A->getElementType());
        Node["count"] = nullptr;
    } else if (T->isPointerType() || T->isReferenceType()) {
        Node["kind"] = T->isPointerType() ? "pointer" : "reference";
        Node["pointee"] = reference(T->getPointeeType());
        // Classify source storage without instantiating a callable ABI for F.
        Node["portable_pointer_kind"] =
            T->getPointeeType()->isFunctionType() ? "code_address" : "data_ptr";
        if (T->isReferenceType())
            Node["reference_category"] = T->isLValueReferenceType() ? "lvalue" : "rvalue";
    } else if (const auto *F = T->getAs<clang::FunctionProtoType>()) {
        Node["kind"] = "function";
        Node["result"] = reference(F->getReturnType());
        Array Parameters;
        for (clang::QualType P : F->param_types()) Parameters.push_back(reference(P));
        Node["params"] = std::move(Parameters);
        Node["variadic"] = F->isVariadic();
        auto ExceptionSpec = F->getExceptionSpecType();
        bool Unresolved = clang::isUnresolvedExceptionSpec(ExceptionSpec) ||
                          ExceptionSpec == clang::EST_Unparsed ||
                          ExceptionSpec == clang::EST_DependentNoexcept;
        Node["noexcept"] = Unresolved ? Value(nullptr) : Value(F->isNothrow());
        Node["exception_spec_state"] = Unresolved ? "unresolved" : "resolved";
        Node["ref_qualifier"] = F->getRefQualifier() == clang::RQ_LValue ? "lvalue" :
                                F->getRefQualifier() == clang::RQ_RValue ? "rvalue" : "none";
    } else if (const auto *E = T->getAs<clang::EnumType>()) {
        Node["kind"] = "enum";
        auto Underlying = E->getDecl()->getIntegerType();
        if (Underlying.isNull()) {
            error(E->getDecl()->getLocation(), "E-WITNESS-INCOMPLETE-ENUM");
            Node["underlying"] = nullptr;
        } else Node["underlying"] = reference(Underlying);
    } else if (T->isIntegerType()) {
        Node["kind"] = "scalar";
        Node["value_bits"] = Context.getIntWidth(T);
        Node["signed"] = T->isSignedIntegerType();
        Node["integer_family"] = T->isBitIntType() ? "bitint" : "builtin";
    } else if (T->isRealFloatingType()) {
        Node["kind"] = "float";
        Node["native_comparable"] = T->isSpecificBuiltinType(clang::BuiltinType::Float) ||
                                      T->isSpecificBuiltinType(clang::BuiltinType::Double);
    } else if (T->isVoidType()) Node["kind"] = "void";
    else {
        error({}, "E-WITNESS-SOURCE-TYPE: unsupported witness source type");
        Node["kind"] = "unavailable";
    }
    if (!T->isIncompleteType() && !T->isFunctionType() && !T->isVoidType()) {
        Node["native_size_bits"] = static_cast<int64_t>(Context.getTypeSize(T));
        Node["native_align_bits"] = static_cast<int64_t>(Context.getTypeAlign(T));
    }
    Types[Id] = std::move(Node);
    return Id;
}
Object Producer::input(const clang::RecordDecl *R) {
    bool Cxx = Context.getLangOpts().CPlusPlus;
    const auto *C = llvm::dyn_cast<clang::CXXRecordDecl>(R);
    auto Alignment = [&](const clang::Decl *D) -> Value {
        unsigned Bits = D->getMaxAlignment();
        if (!Bits) return nullptr;
        if (Bits % 8 || Bits / 8 > 65536) error(D->getLocation(), "E-WITNESS-ALIGNMENT");
        return some(Bits / 8);
    };
    Object Result{{"revision", 1}, {"kind", R->isUnion() ? "union" : R->isClass() ? "class" : "struct"},
                  {"explicit_align", Alignment(R)}, {"pod03", C ? C->isPOD() : false},
                  {"trivial", C ? C->isTrivial() : false},
                  {"standard_layout", C ? C->isCXX11StandardLayout() : false},
                  {"polymorphic", C ? C->isPolymorphic() : false},
                  {"dynamic", C ? C->isDynamicClass() : false},
                  {"empty", C ? C->isEmpty() : false}};
    if (R->hasAttr<clang::PackedAttr>() || R->hasAttr<clang::MSStructAttr>() ||
        R->hasAttr<clang::MaxFieldAlignmentAttr>()) error(R->getLocation(), "E-WITNESS-EXCLUDED-LAYOUT-ATTRIBUTE");
    Array Fields;
    unsigned FieldIndex = 0;
    for (const clang::FieldDecl *F : R->fields()) {
        if (!step(8)) break;
        Value Width = nullptr;
        if (F->isBitField()) {
            const auto *Expression = llvm::dyn_cast<clang::ConstantExpr>(F->getBitWidth());
            if (!Expression || !Expression->getAPValueResult().isInt()) {
                error(F->getLocation(), "E-WITNESS-BITWIDTH-EVIDENCE");
            } else {
                const auto &Bits = Expression->getAPValueResult().getInt();
                if (Bits.isNegative() || Bits.getActiveBits() > 32) {
                    error(F->getLocation(), "E-SMIR-UPSTREAM-BITFIELD-WIDTH");
                } else Width = some(static_cast<int64_t>(Bits.getZExtValue()));
            }
        }
        Value Name = F->getIdentifier() ? some(F->getNameAsString()) : Value(nullptr);
        if (F->getIdentifier() && llvm::StringRef(F->getNameAsString()).starts_with("$capture"))
            error(F->getLocation(), "E-SMIR-RESERVED-METADATA-NAME");
        if (!F->getIdentifier() && !F->isBitField() && !F->isAnonymousStructOrUnion()) {
            if (C && C->isLambda() && F->isImplicit())
                Name = some("$capture" + std::to_string(FieldIndex));
            else error(F->getLocation(), "E-WITNESS-IMPLICIT-UNNAMED-FIELD");
        }
        if (F->hasAttr<clang::PackedAttr>() || (F->isBitField() && F->getMaxAlignment()))
            error(F->getLocation(), "E-WITNESS-EXCLUDED-FIELD-ATTRIBUTE");
        Fields.push_back(Object{{"name", std::move(Name)}, {"type", reference(F->getType())},
                                {"bit_width", std::move(Width)}, {"explicit_align", Alignment(F)},
                                {"no_unique_address", F->hasAttr<clang::NoUniqueAddressAttr>()},
                                {"anonymous", F->isAnonymousStructOrUnion()},
                                {"access", Cxx ? access(F->getAccess()) : "public"}});
        ++FieldIndex;
    }
    Array Bases;
    if (C) for (const clang::CXXBaseSpecifier &B : C->bases()) {
        step(4);
        Bases.push_back(Object{{"type", reference(B.getType())}, {"virtual", B.isVirtual()},
                               {"access", access(B.getAccessSpecifier())}});
    }
    Result["fields"] = std::move(Fields);
    Result["bases"] = std::move(Bases);
    return Result;
}
}
