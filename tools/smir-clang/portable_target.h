// The portable SMIR Clang target: smir64-unknown-rax, LP64, little-endian.
//
// The pinned LLVM checkout has no SMIR target and is not modified. This header
// supplies the one function Clang uses to create a TargetInfo for a triple.
// The build links a copy of libclangBasic with its own Targets.cpp.o removed,
// so this definition is the only one. Including this header in more than one
// translation unit of a program is an error.
//
// The data layout and type properties are those of the ABI chapter. The class
// began as the declaration-only target in tools/smir-abi/portable_type_frontend.cpp.
#ifndef RAX_SMIR_CLANG_PORTABLE_TARGET_H
#define RAX_SMIR_CLANG_PORTABLE_TARGET_H

#include "clang/Basic/Builtins.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/MacroBuilder.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Basic/TargetOptions.h"
#include "llvm/ADT/APFloat.h"
#include "llvm/TargetParser/Triple.h"

namespace smir {

// The class body below uses Clang's names unqualified.
using namespace clang;

inline constexpr const char *Triple = "smir64-unknown-rax";
inline constexpr const char *Layout = "e-p:64:64:64:64-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64-i128:128:128-f16:16:16-f32:32:32-f64:64:64-f128:128:128-v8:8:8-v16:16:16-v32:32:32-v64:64:64-v128:128:128-v256:256:256-v512:512:512-a:0:64-n8:16:32:64-S128-pe1:64:64:64:64-P1";
class PortableTarget final : public clang::TargetInfo {
public:
  explicit PortableTarget(const llvm::Triple &T) : TargetInfo(T) {
    BigEndian = false;
    PointerWidth = PointerAlign = 64;
    BoolWidth = BoolAlign = 8;
    ShortWidth = ShortAlign = 16;
    IntWidth = IntAlign = 32;
    LongWidth = LongAlign = LongLongWidth = LongLongAlign = 64;
    Int128Align = 128;
    BitIntMaxAlign = 64;
    MaxBitIntWidth = 65535;
    HalfWidth = HalfAlign = 16;
    BFloat16Width = BFloat16Align = 16;
    FloatWidth = FloatAlign = 32;
    DoubleWidth = DoubleAlign = 64;
    LongDoubleWidth = LongDoubleAlign = Float128Align = 128;
    HalfFormat = &llvm::APFloat::IEEEhalf();
    FloatFormat = &llvm::APFloat::IEEEsingle();
    DoubleFormat = &llvm::APFloat::IEEEdouble();
    LongDoubleFormat = Float128Format = &llvm::APFloat::IEEEquad();
    SizeType = UnsignedLong;
    PtrDiffType = IntPtrType = IntMaxType = Int64Type = SignedLong;
    WCharType = SignedInt;
    WIntType = UnsignedInt;
    Char16Type = UnsignedShort;
    Char32Type = UnsignedInt;
    SuitableAlign = NewAlign = DefaultAlignForAttributeAligned = 128;
    MinGlobalAlign = 0;
    LargeArrayMinWidth = LargeArrayAlign = 0;
    MaxVectorAlign = 512;
    MaxAtomicPromoteWidth = 128;
    MaxAtomicInlineWidth = 0;
    UseBitFieldTypeAlignment = true;
    UseZeroLengthBitfieldAlignment = false;
    UseLeadingZeroLengthBitfield = UseExplicitBitFieldAlignment = true;
    ZeroLengthBitfieldBoundary = 0;
    LargestOverSizedBitfieldContainer = 128;
    TheCXXABI.set(TargetCXXABI::GenericItanium);
    HasMicrosoftRecordLayout = false;
    HasFloat128 = HasLongDouble = HasFPReturn = HasStrictFP = true;
    HasFloat16 = HasBFloat16 = HasIbm128 = false;
    NoAsmVariants = true;
    HasMustTail = false;
    UserLabelPrefix = "";
    resetDataLayout(Layout);
  }
  bool hasBitIntType() const override { return true; }
  void getTargetDefines(const LangOptions &, MacroBuilder &B) const override {
    B.defineMacro("__SMIR__", "1");
    B.defineMacro("__CHAR8_TYPE__", "unsigned char");
    B.defineMacro("__SMIR_POINTER_WIDTH__", "64");
  }
  llvm::SmallVector<Builtin::InfosShard> getTargetBuiltins() const override { return {}; }
  BuiltinVaListKind getBuiltinVaListKind() const override {
    // Bootstrap internal construction only. Source use is unsupported; never
    // represented as the portable 32-byte va_list in a published product.
    return VoidPtrBuiltinVaList;
  }
  bool validateAsmConstraint(const char *&, ConstraintInfo &) const override { return false; }
  std::string_view getClobbers() const override { return {}; }
  CallingConvCheckResult checkCallingConvention(CallingConv C) const override {
    return C == CC_C ? CCCR_OK : CCCR_Error;
  }
protected:
  llvm::ArrayRef<const char *> getGCCRegNames() const override { return {}; }
  llvm::ArrayRef<GCCRegAlias> getGCCRegAliases() const override { return {}; }
};

} // namespace smir

clang::TargetInfo *clang::TargetInfo::CreateTargetInfo(clang::DiagnosticsEngine &Diags,
                                                       clang::TargetOptions &Options) {
  if (Options.Triple != smir::Triple || !Options.CPU.empty() || !Options.TuneCPU.empty() ||
      !Options.ABI.empty() || !Options.FeaturesAsWritten.empty() || !Options.Features.empty()) {
    Diags.Report(Diags.getCustomDiagID(clang::DiagnosticsEngine::Error,
                                       "only the smir64-unknown-rax target is available"));
    return nullptr;
  }
  auto *Target = new smir::PortableTarget(llvm::Triple(Options.Triple));
  Target->TargetOpts = &Options;
  return Target;
}

bool clang::TargetInfo::validateOpenCLTarget(const clang::LangOptions &,
                                             clang::DiagnosticsEngine &Diags) const {
  Diags.Report(Diags.getCustomDiagID(clang::DiagnosticsEngine::Error,
                                     "OpenCL is not supported by the portable SMIR target"));
  return false;
}

#endif
