#include "producer.hpp"
#include "clang/AST/ExprCXX.h"
#include "clang/Basic/Version.h"
#include "clang/Basic/SourceManager.h"
#include "llvm/ADT/SmallString.h"
#include <algorithm>
#include <functional>
#include <set>

namespace smir_witness {
// Source order data only. No storage addresses, cleanup capabilities or emitted IR.
Object Producer::lifetimePrograms(const std::vector<const clang::RecordDecl *> &Input) {
    Array Records, TypesOut, MethodsOut, Programs;
    std::map<const clang::CXXRecordDecl *, unsigned> RecordIds;
    std::map<void *, unsigned> NeutralTypes;
    std::map<const clang::CXXMethodDecl *, unsigned> NeutralMethods;
    auto record = [&](const clang::CXXRecordDecl *R) {
        R = R->getCanonicalDecl();
        auto Found = RecordIds.find(R);
        if (Found != RecordIds.end()) return Found->second;
        unsigned Id = declaration(R);
        if (Records.size() >= 256 || R->getQualifiedNameAsString().size() > 4096)
            error(R->getLocation(), "E-SOURCE-PROGRAM-RESOURCE");
        RecordIds.emplace(R, Id);
        Records.push_back(Object{{"id", Id}, {"name", R->getQualifiedNameAsString()}});
        return Id;
    };
    auto type = [&](clang::QualType T) {
        T = Context.getCanonicalType(T);
        auto Found = NeutralTypes.find(T.getAsOpaquePtr());
        if (Found != NeutralTypes.end()) return Found->second;
        unsigned Id = NeutralTypes.size();
        if (!step(8) || Id >= 4096 || T->isDependentType()) {
            error({}, "E-SOURCE-PROGRAM-TYPE"); return 0u;
        }
        NeutralTypes.emplace(T.getAsOpaquePtr(), Id);
        if (T.getAsString().size() > 4096) error({}, "E-SOURCE-PROGRAM-RESOURCE");
        clang::QualType Element = T;
        Array Extents;
        while (const auto *A = Context.getAsConstantArrayType(Element)) {
            if (!step() || A->getSize().getActiveBits() > 63 || Extents.size() >= 16) {
                error({}, "E-SOURCE-PROGRAM-ARRAY-EXTENT"); break;
            }
            llvm::SmallString<32> Count;
            A->getSize().toStringUnsigned(Count);
            Extents.push_back(std::string(Count));
            Element = A->getElementType();
        }
        if (Element->isArrayType()) error({}, "E-SOURCE-PROGRAM-UNRESOLVED-ARRAY");
        Value Decl = nullptr;
        if (auto *R = Element->getAsCXXRecordDecl()) {
            if (R->isUnion()) error(R->getLocation(), "E-SOURCE-PROGRAM-UNION");
            Decl = record(R);
        }
        std::string Kind = T->isArrayType() ? "array" : T->isRecordType() ? "record" :
            T->isReferenceType() ? "reference" : T->isPointerType() ? "pointer" :
            T->isArithmeticType() || T->isEnumeralType() ? "scalar" : "unsupported";
        if (Kind == "unsupported") error({}, "E-SOURCE-PROGRAM-TYPE");
        TypesOut.push_back(Object{{"id", Id}, {"spelling", T.getAsString()},
            {"kind", Kind}, {"element_record", std::move(Decl)}, {"array_extents", std::move(Extents)}});
        return Id;
    };
    auto method = [&](const clang::CXXMethodDecl *M) {
        M = M->getCanonicalDecl();
        auto Found = NeutralMethods.find(M);
        if (Found != NeutralMethods.end()) return Found->second;
        unsigned Id = NeutralMethods.size();
        if (!step(8) || Id >= 1024) { error({}, "E-SOURCE-PROGRAM-RESOURCE"); return 0u; }
        NeutralMethods.emplace(M, Id);
        if (M->getNumParams() > 512 || M->getType().getAsString().size() > 4096 ||
            M->getQualifiedNameAsString().size() > 4096)
            error(M->getLocation(), "E-SOURCE-PROGRAM-RESOURCE");
        Array Parameters;
        for (const auto *P : M->parameters()) Parameters.push_back(type(P->getType()));
        MethodsOut.push_back(Object{{"id", Id}, {"record", record(M->getParent())},
            {"name", M->getQualifiedNameAsString()}, {"signature_spelling", M->getType().getAsString()},
            {"parameters", std::move(Parameters)}, {"implicit", M->isImplicit()},
            {"has_definition", M->hasBody()}});
        return Id;
    };
    struct Slot {
        const char *Kind;
        unsigned Index;
        clang::QualType Type;
        const clang::FieldDecl *Field = nullptr;
    };
    std::set<const clang::CXXRecordDecl *> Seen;
    for (const auto *InputRecord : Input) {
        const auto *R = llvm::dyn_cast<clang::CXXRecordDecl>(InputRecord);
        if (!R || !Seen.insert(R->getCanonicalDecl()).second) continue;
        if (failed() || !step(8)) break;
        if (R->isDependentContext()) { error(R->getLocation(), "E-SOURCE-PROGRAM-DEPENDENT"); break; }
        if (R->isUnion()) { error(R->getLocation(), "E-SOURCE-PROGRAM-UNION"); break; }
        unsigned Owner = record(R);
        std::vector<Slot> Coverage;
        unsigned Index = 0;
        for (const auto &B : R->vbases()) Coverage.push_back({"virtual_base", Index++, B.getType()});
        Index = 0;
        for (const auto &B : R->bases()) {
            if (!B.isVirtual()) Coverage.push_back({"nonvirtual_base", Index, B.getType()});
            ++Index;
        }
        Index = 0;
        for (const auto *F : R->fields()) {
            if (F->getNameAsString().size() > 4096) error(F->getLocation(), "E-SOURCE-PROGRAM-RESOURCE");
            if (!F->isUnnamedBitField()) Coverage.push_back({"member", Index, F->getType(), F});
            ++Index;
        }
        if (Coverage.size() > 4096) { error(R->getLocation(), "E-SOURCE-PROGRAM-RESOURCE"); break; }
        std::vector<const clang::CXXMethodDecl *> Definitions;
        for (const auto *C : R->ctors()) if (!C->isImplicit()) Definitions.push_back(C);
        if (const auto *D = R->getDestructor(); D && !D->isImplicit()) Definitions.push_back(D);
        for (const auto *Original : Definitions) {
            const auto *Definition = llvm::dyn_cast_or_null<clang::CXXMethodDecl>(Original->getDefinition());
            if (!Definition || Original->isDeleted() || Original->isDefaulted() || Definition->isDefaulted()) {
                error(Original->getLocation(), "E-SOURCE-PROGRAM-NO-DEFINITION"); break;
            }
            if (Definition->getType()->isDependentType()) {
                error(Definition->getLocation(), "E-SOURCE-PROGRAM-DEPENDENT"); break;
            }
            if (llvm::isa<clang::CXXTryStmt>(Definition->getBody())) {
                error(Definition->getLocation(), "E-SOURCE-PROGRAM-FUNCTION-TRY"); break;
            }
            const auto *Ctor = llvm::dyn_cast<clang::CXXConstructorDecl>(Definition);
            if (Ctor && R->isAbstract()) {
                error(Definition->getLocation(), "E-SOURCE-PROGRAM-ABSTRACT"); break;
            }
            using Init = std::pair<const clang::CXXCtorInitializer *, unsigned>;
            std::map<const clang::FieldDecl *, Init> Fields;
            std::map<std::pair<void *, bool>, Init> Bases;
            if (Ctor) {
                unsigned I = 0;
                for (const auto *CI : Ctor->inits()) {
                    if (CI->isPackExpansion() || CI->isIndirectMemberInitializer()) {
                        error(Ctor->getLocation(), "E-SOURCE-PROGRAM-INITIALIZER"); break;
                    }
                    if (CI->isMemberInitializer()) Fields.emplace(CI->getMember(), Init{CI, I});
                    else if (CI->isBaseInitializer())
                        Bases.emplace(std::make_pair(Context.getCanonicalType(
                            clang::QualType(CI->getBaseClass(), 0)).getAsOpaquePtr(), CI->isBaseVirtual()), Init{CI, I});
                    ++I;
                }
            }
            unsigned Method = method(Definition);
            for (bool Complete : {true, false}) {
                if (failed() || !step(8)) break;
                unsigned Program = Programs.size();
                if (Program >= 1024) { error({}, "E-SOURCE-PROGRAM-RESOURCE"); break; }
                std::string Variant = std::string(Complete ? "complete_" : "base_") + (Ctor ? "constructor" : "destructor");
                Array Steps;
                Value Delegate = nullptr;
                bool Delegating = Ctor && Ctor->isDelegatingConstructor();
                if (Delegating) {
                    auto *Target = Ctor->getTargetConstructor();
                    if (!Target) { error(Ctor->getLocation(), "E-SOURCE-PROGRAM-DELEGATION"); break; }
                    Delegate = Object{{"target_method", method(Target)}, {"target_variant", Variant},
                        {"owner_relation", "distinct_program"}};
                }
                std::vector<Slot> Selected;
                if (!Delegating) for (const auto &S : Coverage)
                    if (Complete || std::string(S.Kind) != "virtual_base") Selected.push_back(S);
                if (!Ctor) std::reverse(Selected.begin(), Selected.end());
                int PreviousInit = -1;
                for (const auto &S : Selected) {
                    if (failed() || !step(8)) break;
                    Init Found{nullptr, 0};
                    if (Ctor) {
                        if (S.Field) {
                            auto I = Fields.find(S.Field); if (I != Fields.end()) Found = I->second;
                        } else {
                            auto I = Bases.find({Context.getCanonicalType(S.Type).getAsOpaquePtr(), std::string(S.Kind) == "virtual_base"});
                            if (I != Bases.end()) Found = I->second;
                        }
                    }
                    Value Initializer = nullptr;
                    if (Found.first) {
                        if (static_cast<int>(Found.second) <= PreviousInit) {
                            error(Definition->getLocation(), "E-SOURCE-PROGRAM-SEMA-ORDER"); break;
                        }
                        PreviousInit = Found.second;
                        const auto *CI = Found.first;
                        auto Location = Context.getSourceManager().getPresumedLoc(CI->getSourceLocation());
                        Initializer = Object{{"sema_index", Found.second},
                            {"textual_index", CI->isWritten() ? Value(CI->getSourceOrder()) : Value(nullptr)},
                            {"written", CI->isWritten()}, {"in_class", CI->isInClassMemberInitializer()},
                            {"expression_class", CI->getInit()->getStmtClassName()},
                            {"line", Location.isValid() ? Location.getLine() : 0},
                            {"column", Location.isValid() ? Location.getColumn() : 0}};
                    }
                    clang::QualType Element = Context.getBaseElementType(S.Type);
                    const auto *Class = Element->getAsCXXRecordDecl();
                    Value Destructor = nullptr;
                    std::string Destruction = "none";
                    if (Class && !Class->hasTrivialDestructor()) {
                        if (!Class->getDestructor()) { error({}, "E-SOURCE-PROGRAM-NO-DEFINITION"); break; }
                        Destructor = method(Class->getDestructor());
                        Destruction = S.Field ? "complete" : "base";
                    }
                    Steps.push_back(Object{{"order", static_cast<int64_t>(Steps.size())},
                        {"kind", S.Kind}, {"declaring_record", Owner}, {"declaration_index", S.Index},
                        {"member", S.Field ? Value(S.Field->getNameAsString()) : Value(nullptr)},
                        {"type", type(S.Type)}, {"initializer", std::move(Initializer)},
                        {"destruction", Destruction}, {"destructor_method", std::move(Destructor)},
                        {"array_progress", S.Type->isArrayType() ? "symbolic_prefix_reverse_cleanup" : "none"}});
                }
                Programs.push_back(Object{{"id", Program}, {"owner_label", "program_" + std::to_string(Program)},
                    {"source_method", Method}, {"source_record", Owner}, {"variant", Variant},
                    {"coverage", Complete ? "complete" : "nonvirtual"}, {"delegate", std::move(Delegate)},
                    {"steps", std::move(Steps)}, {"body", "opaque_ast_body"},
                    {"cleanup", Delegating ? "matching_variant_after_target_completion" :
                        Ctor ? "reverse_completed_prefix" : "body_then_reverse_covered"}});
            }
        }
    }
    return Object{{"format", "draft-independent-source-program-witness"}, {"revision", 1},
        {"binding", "unbound"}, {"source_owner", Unit}, {"library_version", clang::getClangFullVersion()},
        {"target", "x86_64-unknown-linux-gnu"}, {"records", std::move(Records)},
        {"types", std::move(TypesOut)}, {"methods", std::move(MethodsOut)}, {"programs", std::move(Programs)},
        {"smir_emitted", false}, {"backend_emission", false}, {"runtime_authority", false}, {"native_execution", false}};
}
}
