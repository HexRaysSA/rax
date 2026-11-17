// Source declaration/layout oracle only; no SMIR or guest execution.
#include "clang/AST/ASTContext.h"
#include "clang/AST/Attr.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/RecordLayout.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Basic/Version.h"
#include "clang/Frontend/ASTUnit.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <fstream>
#include <string>
#include <vector>

using namespace clang;
using llvm::json::Array;
using llvm::json::Object;
using llvm::json::Value;

class Oracle : public RecursiveASTVisitor<Oracle> {
  ASTContext &C;
  bool Failed = false;
  unsigned Nodes = 0;
public:
  std::vector<const CXXRecordDecl *> Records;
  explicit Oracle(ASTContext &Context) : C(Context) {}
  bool fail(llvm::StringRef Message) {
    llvm::errs() << "SOURCE-CELL-ORACLE-SCOPE: " << Message << '\n';
    Failed = true;
    return false;
  }
  bool VisitCXXRecordDecl(CXXRecordDecl *R) {
    if (R->isImplicit() || !R->isCompleteDefinition() ||
        !C.getSourceManager().isWrittenInMainFile(R->getLocation())) return true;
    if (R->getLocation().isMacroID() || Records.size() >= 256 || R->isDependentContext() || R->getName().empty() ||
        isa<ClassTemplateSpecializationDecl>(R)) return fail("record/name/template limit");
    Records.push_back(R);
    return true;
  }
  std::string key(const CXXRecordDecl *R) {
    R = R->getDefinition();
    if (!R || !C.getSourceManager().isWrittenInMainFile(R->getLocation())) {
      fail("external or incomplete source record"); return "unresolved";
    }
    return std::to_string(C.getSourceManager().getFileOffset(R->getLocation())) +
           ":" + R->getQualifiedNameAsString();
  }
  Value type(QualType T, unsigned Depth = 0) {
    if (++Nodes > 32768 || Depth > 64) { fail("type graph limit"); return nullptr; }
    T = T.getCanonicalType();
    Array Qualifiers;
    if (T.isConstQualified()) Qualifiers.push_back("const");
    if (T.isVolatileQualified()) Qualifiers.push_back("volatile");
    if (T.isRestrictQualified()) Qualifiers.push_back("restrict");
    Object Result{{"qualifiers", std::move(Qualifiers)}};
    if (const auto *A = C.getAsConstantArrayType(T)) {
      if (A->getSize().getActiveBits() > 64) { fail("array extent exceeds u64"); return nullptr; }
      Result["kind"] = "array";
      Result["extent"] = A->getSize().getZExtValue();
      Result["element"] = type(A->getElementType(), Depth + 1);
    } else if (const auto *R = T->getAsCXXRecordDecl()) {
      Result["kind"] = "record";
      Result["record"] = key(R);
    } else {
      if (T->isIncompleteType() || !T->isObjectType()) { fail("nonobject/incomplete type"); return nullptr; }
      Result["kind"] = "scalar";
      Result["spelling"] = T.getAsString();
    }
    if (!Failed) {
      Result["size_bits"] = C.getTypeSize(T);
      Result["align_bits"] = static_cast<uint64_t>(C.getTypeAlign(T));
    }
    return Result;
  }
  Value record(const CXXRecordDecl *R) {
    const auto &L = C.getASTRecordLayout(R);
    Array Fields, Bases, Virtuals;
    unsigned I = 0;
    for (const FieldDecl *F : R->fields()) {
      if (I >= 4096 || F->getLocation().isMacroID()) { fail("field limit/macro declaration"); break; }
      Value Width = nullptr;
      if (F->isBitField()) Width = static_cast<uint64_t>(F->getBitWidthValue());
      Fields.push_back(Object{{"index", I}, {"name", F->getNameAsString()},
        {"source_offset", C.getSourceManager().getFileOffset(F->getLocation())},
        {"type", type(F->getType())}, {"offset_bits", L.getFieldOffset(I)},
        {"declaration_align_bits", static_cast<uint64_t>(C.getDeclAlign(F).getQuantity() * 8)},
        {"bit_width", std::move(Width)}, {"no_unique_address", F->hasAttr<NoUniqueAddressAttr>()}});
      ++I;
    }
    I = 0;
    for (const auto &B : R->bases()) {
      const auto *Base = B.getType()->getAsCXXRecordDecl()->getDefinition();
      const auto Offset = B.isVirtual() ? L.getVBaseClassOffset(Base) : L.getBaseClassOffset(Base);
      Bases.push_back(Object{{"index", I++}, {"record", key(Base)}, {"virtual", B.isVirtual()},
                            {"offset_bits", static_cast<uint64_t>(Offset.getQuantity() * 8)}});
    }
    for (const auto &B : R->vbases()) {
      const auto *Base = B.getType()->getAsCXXRecordDecl()->getDefinition();
      Virtuals.push_back(Object{{"record", key(Base)},
          {"offset_bits", static_cast<uint64_t>(L.getVBaseClassOffset(Base).getQuantity() * 8)}});
    }
    return Object{{"id", key(R)}, {"name", R->getQualifiedNameAsString()},
      {"source_offset", C.getSourceManager().getFileOffset(R->getLocation())},
      {"union", R->isUnion()}, {"dynamic", R->isDynamicClass()},
      {"size_bits", static_cast<uint64_t>(L.getSize().getQuantity() * 8)},
      {"data_size_bits", static_cast<uint64_t>(L.getDataSize().getQuantity() * 8)},
      {"align_bits", static_cast<uint64_t>(L.getAlignment().getQuantity() * 8)},
      {"nonvirtual_size_bits", static_cast<uint64_t>(L.getNonVirtualSize().getQuantity() * 8)},
      {"nonvirtual_align_bits", static_cast<uint64_t>(L.getNonVirtualAlignment().getQuantity() * 8)},
      {"fields", std::move(Fields)}, {"bases", std::move(Bases)}, {"virtual_bases", std::move(Virtuals)}};
  }
  bool failed() const { return Failed; }
};

int main(int argc, char **argv) {
  if (argc != 3) { llvm::errs() << "usage: source-cell-oracle SOURCE TARGET\n"; return 2; }
  std::ifstream Stream(argv[1], std::ios::binary);
  if (!Stream) return 2;
  std::string Input(1024 * 1024 + 1, '\0');
  Stream.read(&Input[0], Input.size());
  Input.resize(static_cast<size_t>(Stream.gcount()));
  if (Input.size() > 1024 * 1024) return 2;
  std::vector<std::string> Args{"-std=c++23", "-pedantic-errors", "-target", argv[2]};
  auto Unit = tooling::buildASTFromCodeWithArgs(Input, Args, argv[1]);
  if (!Unit || Unit->getDiagnostics().hasErrorOccurred()) return 2;
  auto &C = Unit->getASTContext();
  if (C.getCharWidth() != 8 || C.getTargetInfo().getPointerWidth(LangAS::Default) != 64 ||
      C.getTargetInfo().isBigEndian()) return 2;
  Oracle O(C);
  O.TraverseDecl(C.getTranslationUnitDecl());
  std::sort(O.Records.begin(), O.Records.end(), [&](auto *A, auto *B) {
    return C.getSourceManager().getFileOffset(A->getLocation()) <
           C.getSourceManager().getFileOffset(B->getLocation());
  });
  Array Records;
  for (auto *R : O.Records) Records.push_back(O.record(R));
  if (O.failed()) return 2;
  Object Result{{"format", "clang-source-cell-raw"}, {"revision", 1},
    {"clang_version", getClangFullVersion()}, {"target", argv[2]},
    {"char_bits", 8}, {"pointer_bits", 64}, {"little_endian", true},
    {"records", std::move(Records)}};
  llvm::outs() << llvm::formatv("{0:2}", Value(std::move(Result))) << '\n';
}
