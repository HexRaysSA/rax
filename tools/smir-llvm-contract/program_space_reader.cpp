// Pinned LLVM library witness only. No TargetMachine or portable admission.
#include "llvm/ADT/DenseSet.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <vector>

int main(int argc, char **argv) {
    if (argc != 3)
        return 64;
    llvm::LLVMContext context;
    llvm::SMDiagnostic diagnostic;
    auto module = llvm::parseIRFile(argv[1], diagnostic, context);
    if (!module) {
        diagnostic.print(argv[0], llvm::errs());
        return 2;
    }
    if (llvm::verifyModule(*module, &llvm::errs()))
        return 3;
    if (module->getDataLayoutStr() != argv[2])
        return 4;
    const auto &layout = module->getDataLayout();
    auto *binding = llvm::TargetExtType::get(context, "smir.code_binding");
    auto *scope = llvm::TargetExtType::get(context, "smir.source_scope");
    bool exact = layout.getPointerSizeInBits(1) == 64 &&
                 layout.getIndexSizeInBits(1) == 64 &&
                 layout.getPointerABIAlignment(1).value() == 8 &&
                 layout.getPointerPrefAlignment(1).value() == 8 &&
                 layout.getProgramAddressSpace() == 1 &&
                 layout.hasExternalState(1) &&
                 !layout.hasUnstableRepresentation(1) &&
                 layout.getNullPtrValue(1) == 0 &&
                 !binding->isSized() && !scope->isSized();

    // Observe LLVM's label address space without assigning a SMIR domain.
    std::vector<const llvm::Constant *> pending;
    for (const auto &global : module->global_values())
        pending.push_back(&global);
    llvm::DenseSet<const llvm::Constant *> seen;
    std::vector<unsigned> labelSpaces;
    while (!pending.empty()) {
        const auto *value = pending.back();
        pending.pop_back();
        if (!seen.insert(value).second)
            continue;
        if (const auto *label = llvm::dyn_cast<llvm::BlockAddress>(value))
            labelSpaces.push_back(label->getType()->getPointerAddressSpace());
        for (const auto &operand : value->operands())
            if (const auto *child = llvm::dyn_cast<llvm::Constant>(operand.get()))
                pending.push_back(child);
    }
    std::sort(labelSpaces.begin(), labelSpaces.end());
    llvm::outs() << "{\"pointer_bits\":" << layout.getPointerSizeInBits(1)
                 << ",\"index_bits\":" << layout.getIndexSizeInBits(1)
                 << ",\"abi_alignment_bytes\":" << layout.getPointerABIAlignment(1).value()
                 << ",\"preferred_alignment_bytes\":" << layout.getPointerPrefAlignment(1).value()
                 << ",\"program_address_space\":" << layout.getProgramAddressSpace()
                 << ",\"external_state\":" << (layout.hasExternalState(1) ? "true" : "false")
                 << ",\"unstable_representation\":" << (layout.hasUnstableRepresentation(1) ? "true" : "false")
                 << ",\"null_zero\":" << (layout.getNullPtrValue(1) == 0 ? "true" : "false")
                 << ",\"code_binding_sized\":" << (binding->isSized() ? "true" : "false")
                 << ",\"source_scope_sized\":" << (scope->isSized() ? "true" : "false")
                 << ",\"blockaddress_address_spaces\":[";
    for (unsigned index = 0; index < labelSpaces.size(); ++index) {
        if (index)
            llvm::outs() << ',';
        llvm::outs() << labelSpaces[index];
    }
    llvm::outs() << "],\"scope\":\"llvm_structural_only\"}\n";
    return exact ? 0 : 5;
}
