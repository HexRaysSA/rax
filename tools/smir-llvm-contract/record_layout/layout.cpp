#include "producer.hpp"
#include "clang/AST/Attr.h"
#include "clang/AST/RecordLayout.h"
#include "clang/AST/VTableBuilder.h"
#include "llvm/ADT/SmallVector.h"
#include <set>

namespace smir_witness {
static bool findVirtualPath(const clang::CXXRecordDecl *Current,
                            const clang::CXXRecordDecl *Target,
                            std::vector<unsigned> &Path,
                            std::set<const clang::CXXRecordDecl *> &Visited) {
    if (!Visited.insert(Current->getCanonicalDecl()).second) return false;
    unsigned Index = 0;
    for (const auto &Base : Current->bases()) {
        const auto *Child = Base.getType()->getAsCXXRecordDecl();
        Path.push_back(Index++);
        if (Base.isVirtual() && Child->getCanonicalDecl() == Target->getCanonicalDecl()) return true;
        if (findVirtualPath(Child, Target, Path, Visited)) return true;
        Path.pop_back();
    }
    return false;
}
Object Producer::layout(const clang::RecordDecl *R) {
    const auto &L = Context.getASTRecordLayout(R);
    const auto *C = llvm::dyn_cast<clang::CXXRecordDecl>(R);
    Object Result{{"type", reference(Context.getTypeDeclType(clang::ElaboratedTypeKeyword::None, std::nullopt, R))},
                  {"size", L.getSize().getQuantity()}, {"align", L.getAlignment().getQuantity()},
                  {"data_size", L.getDataSize().getQuantity()},
                  {"nonvirtual_size", C ? L.getNonVirtualSize().getQuantity() : L.getSize().getQuantity()},
                  {"nonvirtual_align", C ? L.getNonVirtualAlignment().getQuantity() : L.getAlignment().getQuantity()}};
    Array Fields;
    unsigned Index = 0;
    for (const clang::FieldDecl *F : R->fields()) {
        if (!step(4)) break;
        std::string Name = F->getNameAsString();
        if (!F->getIdentifier()) {
            const char *Prefix = C && C->isLambda() && F->isImplicit() && !F->isBitField() &&
                                 !F->isAnonymousStructOrUnion() ? "$capture" :
                                 F->isAnonymousStructOrUnion() ? "$anonymous" : "$unnamed";
            Name = std::string(Prefix) + std::to_string(Index);
        }
        Array Flags;
        if (F->isAnonymousStructOrUnion()) Flags.push_back("anonymous");
        if (F->isBitField()) Flags.push_back("bitfield");
        if (F->getType()->isIncompleteArrayType()) Flags.push_back("flexible");
        if (F->hasAttr<clang::NoUniqueAddressAttr>()) Flags.push_back("no_unique_address");
        if (F->getAccess() == clang::AS_private) Flags.push_back("private");
        if (F->getAccess() == clang::AS_protected) Flags.push_back("protected");
        if (F->isUnnamedBitField()) Flags.push_back("unnamed");
        uint64_t Width = F->isBitField() ? F->getBitWidth()->EvaluateKnownConstInt(Context).getZExtValue()
                         : F->getType()->isIncompleteArrayType() ? 0 : Context.getTypeSize(F->getType());
        Fields.push_back(Object{{"declaration_index", Index}, {"name", Name},
                                {"type", reference(F->getType())},
                                {"offset_bits", static_cast<int64_t>(L.getFieldOffset(Index))},
                                {"width_bits", static_cast<int64_t>(Width)}, {"flags", std::move(Flags)}});
        ++Index;
    }
    Array Bases;
    if (C) {
        unsigned I = 0;
        for (const auto &Base : C->bases()) {
            if (!Base.isVirtual()) {
                auto Offset = L.getBaseClassOffset(Base.getType()->getAsCXXRecordDecl()).getQuantity();
                Bases.push_back(Object{{"type", reference(Base.getType())}, {"offset", Offset},
                                       {"virtual", false}, {"declaration_index", some(I)},
                                       {"origin_path", Array{I}},
                                       {"adjustment", Object{{"kind", "fixed"}, {"offset", Offset}}}});
            }
            ++I;
        }
        auto *V = llvm::dyn_cast<clang::ItaniumVTableContext>(Context.getVTableContext());
        for (const auto &Base : C->vbases()) {
            const auto *B = Base.getType()->getAsCXXRecordDecl();
            std::vector<unsigned> Path;
            std::set<const clang::CXXRecordDecl *> Visited;
            if (!findVirtualPath(C, B, Path, Visited) || !V) {
                error(R->getLocation(), "E-WITNESS-VIRTUAL-BASE-OWNER");
                continue;
            }
            Array Origin;
            for (unsigned P : Path) Origin.push_back(P);
            auto Offset = L.getVBaseClassOffset(B).getQuantity();
            auto Slot = V->getVirtualBaseOffsetOffset(C, B).getQuantity();
            Bases.push_back(Object{{"type", reference(Base.getType())}, {"offset", Offset},
                                   {"virtual", true}, {"declaration_index", nullptr},
                                   {"origin_path", std::move(Origin)},
                                   {"adjustment", Object{{"kind", "virtual"}, {"vptr_offset", 0},
                                                         {"slot_bytes", Slot}, {"addend", 0}}}});
        }
    }
    Result["fields"] = std::move(Fields);
    Result["bases"] = std::move(Bases);
    Result["vptrs"] = C && C->isDynamicClass() ? vptrs(C) : Array{};
    return Result;
}
Object Producer::method(const clang::CXXMethodDecl *M) {
    M = M->getCanonicalDecl();
    auto Found = MethodIds.find(M);
    if (Found == MethodIds.end()) {
        step(8);
        unsigned Id = Methods.size();
        MethodIds.emplace(M, Id);
        Methods.emplace_back();
        Object Row{{"id", Id}, {"owner", Unit}, {"name", M->getQualifiedNameAsString()},
                                 {"type", reference(M->getType())}, {"is_pure", M->isPureVirtual()},
                                 {"body_materialized", false}, {"runtime_symbol_bound", false}};
        Row["parent_source_type"] = reference(Context.getTypeDeclType(
            clang::ElaboratedTypeKeyword::None, std::nullopt, M->getParent()));
        Row["const"] = M->isConst();
        Row["volatile"] = M->isVolatile();
        Row["ref_qualifier"] = M->getRefQualifier() == clang::RQ_LValue ? "lvalue" :
                               M->getRefQualifier() == clang::RQ_RValue ? "rvalue" : "none";
        Row["is_deleted"] = M->isDeleted();
        Row["is_destructor"] = llvm::isa<clang::CXXDestructorDecl>(M);
        Array Overrides;
        for (const auto *Overridden : M->overridden_methods()) {
            if (!step()) break;
            Overrides.push_back(method(Overridden));
        }
        Row["overrides"] = std::move(Overrides);
        Methods[Id] = std::move(Row);
        Found = MethodIds.find(M);
    }
    return Object{{"namespace", "source-method-declaration"}, {"owner", Unit}, {"id", Found->second}};
}
Array Producer::vptrs(const clang::CXXRecordDecl *R) {
    Array Result;
    auto *V = llvm::dyn_cast<clang::ItaniumVTableContext>(Context.getVTableContext());
    if (!V) { error(R->getLocation(), "E-WITNESS-NON-ITANIUM"); return Result; }
    const auto &Table = V->getVTableLayout(R);
    auto Components = Table.vtable_components();
    const auto &L = Context.getASTRecordLayout(R);
    std::set<int64_t> EmittedOffsets;
    for (const auto &Entry : Table.getAddressPoints()) {
        int64_t Offset = Entry.first.getBaseOffset().getQuantity();
        if (!EmittedOffsets.insert(Offset).second) continue;
        size_t Start = Table.getVTableOffset(Entry.second.VTableIndex);
        size_t End = Start + Table.getVTableSize(Entry.second.VTableIndex);
        size_t Address = Start + Entry.second.AddressPointIndex;
        if (Address < Start + 2 || Address > End || End > Components.size()) {
            error(R->getLocation(), "E-WITNESS-VTABLE-RANGE"); continue;
        }
        Array VCall, VBase, Slots, Raw, Order, Thunks, BaseTargets;
        Value RTTI = nullptr;
        int64_t ToTop = 0;
        for (size_t I = Start; I < End; ++I) {
            if (!step()) break;
            const auto &C = Components[I];
            Object Item{{"component_index", static_cast<int64_t>(I - Start)},
                        {"address_relative_bytes", (static_cast<int64_t>(I) - static_cast<int64_t>(Address)) * 8}};
            switch (C.getKind()) {
                case clang::VTableComponent::CK_VCallOffset:
                    Order.push_back("vcall");
                    Item["kind"] = "vcall_offset";
                    Item["value"] = C.getVCallOffset().getQuantity();
                    VCall.push_back(C.getVCallOffset().getQuantity()); break;
                case clang::VTableComponent::CK_VBaseOffset:
                    Order.push_back("vbase");
                    Item["kind"] = "vbase_offset";
                    Item["value"] = C.getVBaseOffset().getQuantity();
                    VBase.push_back(C.getVBaseOffset().getQuantity()); break;
                case clang::VTableComponent::CK_OffsetToTop:
                    Item["kind"] = "offset_to_top";
                    ToTop = C.getOffsetToTop().getQuantity(); Item["value"] = ToTop; break;
                case clang::VTableComponent::CK_RTTI:
                    Item["kind"] = "rtti";
                    RTTI = some(Object{{"namespace", "source-rtti-declaration"}, {"owner", Unit},
                                       {"source_type", reference(Context.getTypeDeclType(clang::ElaboratedTypeKeyword::None, std::nullopt, C.getRTTIDecl()))}});
                    break;
                default: {
                    const auto *M = C.getKind() == clang::VTableComponent::CK_UnusedFunctionPointer
                                      ? C.getUnusedFunctionDecl() : C.getFunctionDecl();
                    Object Ref = method(M);
                    std::string Variant = C.getKind() == clang::VTableComponent::CK_CompleteDtorPointer ? "complete-destructor"
                                        : C.getKind() == clang::VTableComponent::CK_DeletingDtorPointer ? "deleting-destructor"
                                        : C.getKind() == clang::VTableComponent::CK_UnusedFunctionPointer ? "unused" : "function";
                    Item["kind"] = Variant;
                    Item["declaration"] = method(M);
                    Ref["variant"] = Variant;
                    Slots.push_back(std::move(Ref));
                }
            }
            Raw.push_back(std::move(Item));
        }
        for (const auto &EntryThunk : Table.vtable_thunks()) {
            size_t Index = EntryThunk.first;
            if (Index < Start || Index >= End) continue;
            if (!step(8)) break;
            const auto &Thunk = EntryThunk.second;
            const auto *Target = Components[Index].getFunctionDecl();
            Value Origin = Thunk.Method ? some(method(Thunk.Method)) : Value(nullptr);
            Thunks.push_back(Object{{"component_index", static_cast<int64_t>(Index - Start)},
                {"address_relative_bytes", (static_cast<int64_t>(Index) - static_cast<int64_t>(Address)) * 8},
                {"source_target", method(Target)}, {"source_origin", std::move(Origin)},
                {"this_nonvirtual_bytes", Thunk.This.NonVirtual},
                {"this_vcall_slot_bytes", Thunk.This.Virtual.Itanium.VCallOffsetOffset},
                {"return_nonvirtual_bytes", Thunk.Return.NonVirtual},
                {"return_vbase_slot_bytes", Thunk.Return.Virtual.Itanium.VBaseOffsetOffset},
                {"return_policy", Thunk.Return.isEmpty() ? "identity" :
                    Target->getReturnType()->isReferenceType() ? "reference" : "nullable_pointer"},
                {"runtime_thunk_bound", false}, {"body_materialized", false}});
        }
        for (const auto &Alias : Table.getAddressPoints()) {
            if (Alias.first.getBaseOffset().getQuantity() != Offset) continue;
            const auto *Receiver = Alias.first.getBase();
            for (const auto &Base : Receiver->vbases()) {
                if (!step(8)) break;
                const auto *Target = Base.getType()->getAsCXXRecordDecl();
                int64_t Slot = V->getVirtualBaseOffsetOffset(Receiver, Target).getQuantity();
                int64_t Index = static_cast<int64_t>(Address) + Slot / 8;
                if (Slot >= 0 || Slot % 8 || Index < static_cast<int64_t>(Start) ||
                    Index >= static_cast<int64_t>(Address) ||
                    Components[Index].getKind() != clang::VTableComponent::CK_VBaseOffset) {
                    error(R->getLocation(), "E-WITNESS-VBASE-COMPONENT-QUERY");
                    continue;
                }
                BaseTargets.push_back(Object{
                    {"receiver_source_type", reference(Context.getTypeDeclType(
                        clang::ElaboratedTypeKeyword::None, std::nullopt, Receiver))},
                    {"target_source_type", reference(Base.getType())}, {"slot_bytes", Slot},
                    {"receiver_offset", Offset},
                    {"target_offset", L.getVBaseClassOffset(Target).getQuantity()},
                    {"component_value", Components[Index].getVBaseOffset().getQuantity()},
                    {"runtime_binding", false}});
            }
        }
        Result.push_back(Object{{"offset", Offset}, {"offset_top", ToTop}, {"rtti", std::move(RTTI)},
                                {"slots", std::move(Slots)}, {"vcall_offsets", std::move(VCall)},
                                {"vbase_offsets", std::move(VBase)}, {"raw_components", std::move(Raw)},
                                {"component_order", std::move(Order)},
                                {"raw_thunks", std::move(Thunks)},
                                {"vbase_slot_targets", std::move(BaseTargets)},
                                {"runtime_symbols_bound", false}, {"native_certificate", false},
                                {"complete_object_size", L.getSize().getQuantity()}});
    }
    llvm::sort(Result, [](const Value &A, const Value &B) {
        return A.getAsObject()->getInteger("offset") < B.getAsObject()->getInteger("offset");
    });
    return Result;
}
}
