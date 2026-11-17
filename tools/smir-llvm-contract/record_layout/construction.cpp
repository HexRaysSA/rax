#include "producer.hpp"
#include "clang/AST/VTableBuilder.h"
#include "clang/AST/VTTBuilder.h"

namespace smir_witness {
Object Producer::construction(const clang::CXXRecordDecl *R) {
    auto *V = llvm::dyn_cast<clang::ItaniumVTableContext>(Context.getVTableContext());
    if (!V) { error(R->getLocation(), "E-WITNESS-NON-ITANIUM"); return {}; }
    // true populates actual definition components; this AST builder emits no IR.
    clang::VTTBuilder Builder(Context, R, true);
    Array Groups, Entries;
    const auto &Definitions = Builder.getVTTVTables();
    for (size_t Index = 0; Index < Definitions.size(); ++Index) {
        if (!step(8)) break;
        const auto &Definition = Definitions[Index];
        std::unique_ptr<clang::VTableLayout> Owned;
        const clang::VTableLayout *Table;
        if (Definition.getBase() == R) Table = &V->getVTableLayout(R);
        else {
            Owned = V->createConstructionVTableLayout(Definition.getBase(), Definition.getBaseOffset(),
                                                       Definition.isVirtual(), R);
            Table = Owned.get();
        }
        Array Points, Components;
        for (const auto &Point : Table->getAddressPoints()) {
            if (!step(4)) break;
            Points.push_back(Object{{"source_receiver", reference(Context.getTypeDeclType(
                clang::ElaboratedTypeKeyword::None, std::nullopt, Point.first.getBase()))},
                {"storage_offset", Point.first.getBaseOffset().getQuantity()},
                {"table_index", Point.second.VTableIndex},
                {"address_point_index", Point.second.AddressPointIndex}});
        }
        for (const auto &Component : Table->vtable_components()) {
            if (!step()) break;
            Object Row;
            switch (Component.getKind()) {
                case clang::VTableComponent::CK_VCallOffset:
                    Row = Object{{"kind", "vcall"}, {"value", Component.getVCallOffset().getQuantity()}}; break;
                case clang::VTableComponent::CK_VBaseOffset:
                    Row = Object{{"kind", "vbase"}, {"value", Component.getVBaseOffset().getQuantity()}}; break;
                case clang::VTableComponent::CK_OffsetToTop:
                    Row = Object{{"kind", "offset_top"}, {"value", Component.getOffsetToTop().getQuantity()}}; break;
                case clang::VTableComponent::CK_RTTI:
                    Row = Object{{"kind", "rtti"}, {"source_type", reference(Context.getTypeDeclType(
                        clang::ElaboratedTypeKeyword::None, std::nullopt, Component.getRTTIDecl()))}}; break;
                default:
                    Row = Object{{"kind", Component.getKind() == clang::VTableComponent::CK_CompleteDtorPointer ? "complete-destructor" :
                        Component.getKind() == clang::VTableComponent::CK_DeletingDtorPointer ? "deleting-destructor" :
                        Component.getKind() == clang::VTableComponent::CK_UnusedFunctionPointer ? "unused" : "function"}, {"source_method", method(
                        Component.getKind() == clang::VTableComponent::CK_UnusedFunctionPointer ?
                        Component.getUnusedFunctionDecl() : Component.getFunctionDecl())}};
            }
            Components.push_back(std::move(Row));
        }
        for (const auto &Entry : Builder.getVTTComponents()) {
            if (!step()) break;
            if (Entry.VTableIndex != Index) continue;
            auto Point = Table->getAddressPoint(Entry.VTableBase);
            Entries.push_back(Object{{"vtt_index", static_cast<int64_t>(&Entry - Builder.getVTTComponents().data())},
                {"group_index", static_cast<int64_t>(Index)},
                {"source_receiver", reference(Context.getTypeDeclType(
                    clang::ElaboratedTypeKeyword::None, std::nullopt, Entry.VTableBase.getBase()))},
                {"storage_offset", Entry.VTableBase.getBaseOffset().getQuantity()},
                {"table_index", Point.VTableIndex}, {"address_point_index", Point.AddressPointIndex},
                {"global_component_index", static_cast<int64_t>(Table->getVTableOffset(Point.VTableIndex) + Point.AddressPointIndex)}});
        }
        Groups.push_back(Object{{"index", static_cast<int64_t>(Index)},
            {"kind", Definition.getBase() == R ? "complete" : "construction"},
            {"current_type", reference(Context.getTypeDeclType(
                clang::ElaboratedTypeKeyword::None, std::nullopt, Definition.getBase()))},
            {"storage_type", reference(Context.getTypeDeclType(clang::ElaboratedTypeKeyword::None, std::nullopt, R))},
            {"subobject_offset", Definition.getBaseOffset().getQuantity()}, {"virtual", Definition.isVirtual()},
            {"address_points", std::move(Points)}, {"raw_components", std::move(Components)}});
    }
    llvm::sort(Entries, [](const Value &A, const Value &B) {
        return A.getAsObject()->getInteger("vtt_index") < B.getAsObject()->getInteger("vtt_index");
    });
    return Object{{"groups", std::move(Groups)}, {"entries", std::move(Entries)},
                  {"runtime_binding", false}, {"source_path_bound", false}, {"smir_emitted", false}};
}
}
