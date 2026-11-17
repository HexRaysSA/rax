// Out-of-tree pinned frontend bootstrap; no TargetMachine or source authority.
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/RecordLayout.h"
#include "clang/AST/Attr.h"
#include <set>
#include "clang/Lex/PPCallbacks.h"
#include "llvm/ADT/SmallString.h"
#include <map>
#include "clang/Basic/MacroBuilder.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Basic/TargetOptions.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/CompilerInvocation.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Lex/Preprocessor.h"
#include "clang/Lex/PreprocessorOptions.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/VirtualFileSystem.h"
#include <fstream>
#include <iostream>
using namespace clang;
using llvm::json::Array;
using llvm::json::Object;
using llvm::json::Value;
namespace {
constexpr const char *Layout = "e-p:64:64:64:64-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64-i128:128:128-f16:16:16-f32:32:32-f64:64:64-f128:128:128-v8:8:8-v16:16:16-v32:32:32-v64:64:64-v128:128:128-v256:256:256-v512:512:512-a:0:64-n8:16:32:64-S128-pe1:64:64:64:64-P1";
unsigned FactoryCalls = 0;
class PortableTarget final : public TargetInfo {
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

Array Rows, Types, EnumHooks;
std::set<unsigned> SourceTypes, AbiTypes;
bool Rejected = false;
void reject(ASTContext &C, SourceLocation L, const char *Code) {
  Rejected = true;
  C.getDiagnostics().Report(L, C.getDiagnostics().getCustomDiagID(
      DiagnosticsEngine::Error, "%0")) << Code;
}
class Consumer final : public ASTConsumer, public RecursiveASTVisitor<Consumer> {
  ASTContext *Context = nullptr;
  std::map<void *, unsigned> IDs;
  unsigned Depth = 0;
  bool main(SourceLocation L) const {
    return L.isValid() && Context->getSourceManager().isWrittenInMainFile(
      Context->getSourceManager().getExpansionLoc(L));
  }
  unsigned type(QualType Q, SourceLocation L, bool Derived=false) {
    auto &C = *Context;
    Q = C.getCanonicalType(Q);
    auto Found = IDs.find(Q.getAsOpaquePtr());
    if (Found != IDs.end()) {
      (Derived?AbiTypes:SourceTypes).insert(Found->second);
      return Found->second;
    }
    if (Types.size() >= 512 || Depth >= 32) {
      reject(C,L,"PORTABLE_RECORD_RESOURCE"); return 0;
    }
    unsigned ID = Types.size();
    IDs[Q.getAsOpaquePtr()] = ID;
    (Derived?AbiTypes:SourceTypes).insert(ID);
    Types.push_back(nullptr);
    ++Depth;
    Object T{{"id",ID},{"spelling",Q.getAsString()},{"kind","unsupported"},
      {"bits",0},{"signed",false},{"byte_category",nullptr},
      {"storage_bits",nullptr},{"alignment_bits",nullptr},
      {"elements",Array{}},{"extent",nullptr},{"enumerators",Array{}},
      {"entity",""},{"fixed_enum",false},{"scoped_enum",false},
      {"noexcept",false},{"qualifiers",Array{}},{"record",nullptr},{"abi_pointer",nullptr}};
    Array Qualifiers;
    if (Q.isConstQualified()) Qualifiers.push_back("const");
    if (Q.isRestrictQualified()) Qualifiers.push_back("restrict");
    if (Q.isVolatileQualified()) Qualifiers.push_back("volatile");
    T["qualifiers"] = std::move(Qualifiers);
    bool Supported = !Q.hasAddressSpace() && !Q.isObjCGCWeak() && !Q.isObjCGCStrong();
    auto Scalar = [&](const char *Name, unsigned Bits, bool Signed, const char *Byte = nullptr) {
      T["kind"]="scalar"; T["entity"]=Name; T["bits"]=Bits; T["signed"]=Signed;
      if (Byte) T["byte_category"]=Byte;
    };
    if (const auto *B = Q->getAs<BuiltinType>()) {
      switch (B->getKind()) {
      case BuiltinType::Void: T["kind"]="void"; T["entity"]="void"; break;
      case BuiltinType::Bool: Scalar("bool",1,false); break;
      case BuiltinType::Char_S: Scalar("char",8,true,"char"); break;
      case BuiltinType::SChar: Scalar("signed char",8,true,"signed_char"); break;
      case BuiltinType::UChar: Scalar("unsigned char",8,false,"unsigned_char"); break;
      case BuiltinType::Char8: Scalar("char8_t",8,false,"char8_t"); break;
      case BuiltinType::WChar_S: Scalar("wchar_t",32,true); break;
      case BuiltinType::Char16: Scalar("char16_t",16,false); break;
      case BuiltinType::Char32: Scalar("char32_t",32,false); break;
      case BuiltinType::Short: Scalar("short",16,true); break;
      case BuiltinType::UShort: Scalar("unsigned short",16,false); break;
      case BuiltinType::Int: Scalar("int",32,true); break;
      case BuiltinType::UInt: Scalar("unsigned int",32,false); break;
      case BuiltinType::Long: Scalar("long",64,true); break;
      case BuiltinType::ULong: Scalar("unsigned long",64,false); break;
      case BuiltinType::LongLong: Scalar("long long",64,true); break;
      case BuiltinType::ULongLong: Scalar("unsigned long long",64,false); break;
      case BuiltinType::Int128: Scalar("__int128",128,true); break;
      case BuiltinType::UInt128: Scalar("unsigned __int128",128,false); break;
      case BuiltinType::Float: Scalar("float",32,false); T["float_format"]="ieee32"; break;
      case BuiltinType::Double: Scalar("double",64,false); T["float_format"]="ieee64"; break;
      case BuiltinType::LongDouble: Scalar("long double",128,false); T["float_format"]="ieee128"; break;
      default: Supported=false;
      }
    } else if (const auto *B = Q->getAs<BitIntType>()) {
      Supported &= !C.getLangOpts().CPlusPlus;
      T["kind"]="bitint"; T["entity"]="bitint";
      T["bits"]=B->getNumBits(); T["signed"]=B->isSigned();
    } else if (const auto *E = Q->getAs<EnumType>()) {
      const EnumDecl *D=E->getDecl()->getDefinition();
      if (!D || D->getName().empty() || !main(D->getLocation()) || D->hasAttrs()) Supported=false;
      else {
        T["kind"]="enum"; T["entity"]=D->getQualifiedNameAsString();
        T["bits"]=C.getIntWidth(D->getIntegerType());
        T["signed"]=D->getIntegerType()->isSignedIntegerType();
        T["fixed_enum"]=D->isFixed(); T["scoped_enum"]=D->isScoped();
        T["elements"]=Array{type(D->getIntegerType(),L)};
        Array Values;
        for (const auto *V : D->enumerators()) {
          llvm::SmallString<64> Digits;
          V->getInitVal().toString(Digits,10);
          Values.push_back(Object{{"name",V->getNameAsString()},{"decimal",Digits.str().str()}});
        }
        T["enumerators"]=std::move(Values);
      }
    } else if (const auto *R=Q->getAs<RecordType>()) {
      const RecordDecl *D=R->getDecl()->getDefinition();
      if (!D || C.getLangOpts().CPlusPlus || D->getName().empty() ||
          !D->getDeclContext()->isTranslationUnit() || !main(D->getLocation())) {
        reject(C,L,"PORTABLE_DECL_UNAVAILABLE"); Supported=false;
      } else {
        unsigned Explicit=D->getMaxAlignment();
        for (const Attr *A:D->attrs()) if (!isa<AlignedAttr>(A)) Supported=false;
        if (Explicit>65536*8 || Explicit%8) Supported=false;
        Array Fields;
        unsigned Index=0;
        for (const FieldDecl *F:D->fields()) {
          if (++Index>64 || F->isBitField() || F->isAnonymousStructOrUnion() ||
              F->getName().empty() || F->getType()->isIncompleteType() || F->getType()->isFunctionType()) {
            reject(C,F->getLocation(),"PORTABLE_RECORD_FIELD_UNAVAILABLE"); Supported=false; continue;
          }
          unsigned Alignment=F->getMaxAlignment();
          for (const Attr *A:F->attrs()) if (!isa<AlignedAttr>(A)) Supported=false;
          if (Alignment>65536*8 || Alignment%8) Supported=false;
          unsigned Child=type(F->getType(),F->getLocation());
          Fields.push_back(Object{{"index",Index-1},{"name",F->getNameAsString()},
            {"type_id",Child},{"offset_bits",0},
            {"explicit_align",Alignment?Value(Alignment/8):Value(nullptr)}});
        }
        if (!Index) { reject(C,L,"PORTABLE_RECORD_EMPTY_UNAVAILABLE"); Supported=false; }
        if (Supported) {
          const ASTRecordLayout &RL=C.getASTRecordLayout(D);
          if (RL.getSize().getQuantity()<=0 || RL.getSize().getQuantity()>65536) {
            reject(C,L,"PORTABLE_RECORD_EXTENT_UNAVAILABLE"); Supported=false;
          } else {
            for (unsigned I=0;I<Fields.size();++I)
              (*Fields[I].getAsObject())["offset_bits"]=RL.getFieldOffset(I);
            T["kind"]="record"; T["entity"]=D->getNameAsString();
            T["record"]=Object{{"kind",D->isUnion()?"union":"struct"},
              {"explicit_align",Explicit?Value(Explicit/8):Value(nullptr)},
              {"ast_data_size",RL.getDataSize().getQuantity()},{"fields",std::move(Fields)}};
            T["abi_pointer"]=type(C.getPointerType(Q),L,true);
          }
        }
      }
    } else if (const auto *P=Q->getAs<PointerType>()) {
      T["kind"]="pointer"; T["entity"]="pointer"; T["bits"]=64;
      T["elements"]=Array{type(P->getPointeeType(),L)};
    } else if (const auto *A=C.getAsConstantArrayType(Q)) {
      if (A->getSize().getActiveBits()>31 || A->getSize().isZero()) Supported=false;
      T["kind"]="array"; T["entity"]="array";
      T["elements"]=Array{type(A->getElementType(),L)};
      T["extent"]=A->getSize().getLimitedValue();
    } else if (const auto *V=Q->getAs<VectorType>()) {
      QualType E=V->getElementType();
      unsigned Bits=C.getTypeSize(E), Count=V->getNumElements();
      Supported &= E->isBuiltinType() && !E->isBooleanType() &&
        (E->isIntegerType() || E->isRealFloatingType()) &&
        (Bits==8 || Bits==16 || Bits==32 || Bits==64) && Count>=2 &&
        llvm::isPowerOf2_64(uint64_t(Bits)*Count) && uint64_t(Bits)*Count<=512;
      T["kind"]="vector"; T["entity"]="vector";
      T["elements"]=Array{type(E,L)}; T["extent"]=Count;
    } else if (const auto *F=Q->getAs<FunctionProtoType>()) {
      Supported &= !F->isVariadic() && F->getCallConv()==CC_C &&
        (F->getExceptionSpecType()==EST_None || F->getExceptionSpecType()==EST_BasicNoexcept ||
         F->getExceptionSpecType()==EST_NoexceptTrue || F->getExceptionSpecType()==EST_NoexceptFalse);
      T["kind"]="function"; T["entity"]="function";
      Array Children;
      for (QualType P:F->param_types()) Children.push_back(type(P,L));
      Children.push_back(type(F->getReturnType(),L));
      T["elements"]=std::move(Children); T["extent"]=F->getNumParams();
      T["noexcept"]=F->isNothrow();
    } else Supported=false;
    if (Supported && !Q->isVoidType() && !Q->isFunctionType()) {
      auto Info=C.getTypeInfo(Q);
      if (Info.Width>uint64_t(0x7fffffff)*8) Supported=false;
      else { T["storage_bits"]=Info.Width; T["alignment_bits"]=Info.Align; }
    }
    if (!Supported) reject(C,L,"PORTABLE_RECORD_UNAVAILABLE");
    Types[ID]=std::move(T);
    --Depth;
    return ID;
  }
public:
  void Initialize(ASTContext &C) override { Context=&C; }
  void HandleTagDeclDefinition(TagDecl *Tag) override {
    auto *D=dyn_cast<EnumDecl>(Tag);
    if (!D || D->isFixed()) return;
    auto &C=*Context;
    if (D->hasAttrs() || D->getPreviousDecl()) { reject(C,D->getLocation(),"PORTABLE_ENUM_ATTRIBUTES_OR_REDECL_UNAVAILABLE"); return; }
    // Finite grammar excludes type queries/casts/previous-enumerator use inside
    // definitions: no native-selected enum-dependent result may predate the hook.
    for (auto *E:D->enumerators()) if (Expr *Init=E->getInitExpr()) {
      Expr *X=Init;
      for (unsigned I=0;I<32;++I) {
        Expr *Y=X->IgnoreParenImpCasts();
        if (auto *K=dyn_cast<ConstantExpr>(Y)) Y=K->getSubExpr();
        if (Y==X) break;
        X=Y;
      }
      if (auto *U=dyn_cast<UnaryOperator>(X)) {
        if (U->getOpcode()!=UO_Minus && U->getOpcode()!=UO_Plus) {
          reject(C,E->getLocation(),"PORTABLE_ENUM_INITIALIZER_UNAVAILABLE"); return;
        }
        X=U->getSubExpr()->IgnoreParenImpCasts();
      }
      if (!isa<IntegerLiteral>(X)) {
        reject(C,E->getLocation(),"PORTABLE_ENUM_INITIALIZER_UNAVAILABLE"); return;
      }
    }
    QualType Selected;
    for (QualType Candidate:{C.IntTy,C.UnsignedIntTy,C.LongTy,C.UnsignedLongTy}) {
      bool Fits=true;
      for (auto *E:D->enumerators()) {
        llvm::APSInt V=E->getInitVal();
        Fits &= C.isRepresentableIntegerValue(V,Candidate);
      }
      if (Fits) { Selected=Candidate; break; }
    }
    if (Selected.isNull()) { reject(C,D->getLocation(),"PORTABLE_ENUM_RANGE_UNAVAILABLE"); return; }
    auto Old=D->getIntegerType().getAsString();
    D->setIntegerType(Selected);
    D->setPromotionType(Selected);
    bool AllInt=true;
    for (auto *E:D->enumerators()) {
      llvm::APSInt V=E->getInitVal();
      AllInt &= C.isRepresentableIntegerValue(V,C.IntTy);
    }
    for (auto *E:D->enumerators()) {
      llvm::APSInt V=E->getInitVal().extOrTrunc(C.getIntWidth(Selected));
      V.setIsUnsigned(Selected->isUnsignedIntegerType());
      E->setInitVal(C,V);
      QualType NewType=!C.getLangOpts().CPlusPlus && AllInt?C.IntTy:Selected;
      if (Expr *Init=E->getInitExpr()) {
        if (!C.hasSameType(NewType,Init->getType()))
          E->setInitExpr(ImplicitCastExpr::Create(C,NewType,CK_IntegralCast,
            Init,nullptr,VK_PRValue,FPOptionsOverride()));
      }
      E->setType(C.getLangOpts().CPlusPlus || !AllInt?
        QualType(C.getCanonicalTagType(D)):C.IntTy);
    }
    EnumHooks.push_back(Object{{"name",D->getNameAsString()},{"before",Old},
      {"after",Selected.getAsString()},{"phase","before_subsequent_declarations"}});
  }
  bool VisitLinkageSpecDecl(LinkageSpecDecl *D) {
    if (main(D->getBeginLoc())) reject(*Context,D->getBeginLoc(),"PORTABLE_CPP_LINKAGE_UNAVAILABLE");
    return true;
  }
  bool VisitNamespaceDecl(NamespaceDecl *D) {
    if (main(D->getLocation()) && D->isAnonymousNamespace())
      reject(*Context,D->getLocation(),"PORTABLE_ANONYMOUS_NAMESPACE_UNAVAILABLE");
    return true;
  }
  bool VisitTypeLoc(TypeLoc T) {
    if (main(T.getBeginLoc())) {
      if (isa<AttributedType>(T.getType().getTypePtr()))
        reject(*Context,T.getBeginLoc(),"PORTABLE_RECORD_ATTRIBUTES_UNAVAILABLE");
      type(T.getType(),T.getBeginLoc());
    }
    return true;
  }
  bool VisitNamedDecl(NamedDecl *D) {
    if (!main(D->getLocation()) || D->isImplicit()) return true;
    if (Rows.size()>=512) { reject(*Context,D->getLocation(),"PORTABLE_DECL_RESOURCE"); return false; }
    QualType Q;
    if (auto *V=dyn_cast<ValueDecl>(D)) {
      if (isa<EnumConstantDecl>(D)) return true;
      Q=V->getType();
    } else if (auto *T=dyn_cast<TypedefNameDecl>(D)) {
      if (T->hasAttrs()) reject(*Context,D->getLocation(),"PORTABLE_RECORDDEF_ATTRIBUTES_UNAVAILABLE");
      Q=T->getUnderlyingType();
    }
    else if (auto *E=dyn_cast<EnumDecl>(D)) Q=Context->getCanonicalTagType(E);
    else if (auto *R=dyn_cast<RecordDecl>(D)) Q=Context->getCanonicalTagType(R);
    else if (isa<NamespaceDecl>(D)) return true;
    else { reject(*Context,D->getLocation(),"PORTABLE_DECL_UNAVAILABLE"); return true; }
    if (auto *F=dyn_cast<FunctionDecl>(D)) {
      if (F->doesThisDeclarationHaveABody() || (Context->getLangOpts().CPlusPlus && F->isExternC()) ||
          F->hasAttrs() || F->isTemplated())
        reject(*Context,D->getLocation(),"PORTABLE_FUNCTION_UNAVAILABLE");
    } else if (isa<VarDecl>(D) && D->hasAttrs())
      reject(*Context,D->getLocation(),"PORTABLE_VARIABLE_ATTRIBUTES_UNAVAILABLE");
    unsigned ID=type(Q,D->getLocation());
    Rows.push_back(Object{{"name",D->getQualifiedNameAsString()},
      {"decl_kind",D->getDeclKindName()},{"type_id",ID},
      {"source_offset",Context->getSourceManager().getFileOffset(
        Context->getSourceManager().getExpansionLoc(D->getLocation()))}});
    return true;
  }
  void HandleTranslationUnit(ASTContext &C) override { TraverseDecl(C.getTranslationUnitDecl()); }
};
class Guards final:public PPCallbacks {
  Preprocessor &PP;
  void deny(SourceLocation L,const char *Code) {
    if (!PP.getSourceManager().isWrittenInMainFile(L)) return;
    Rejected=true;
    PP.getDiagnostics().Report(L,PP.getDiagnostics().getCustomDiagID(DiagnosticsEngine::Error,"%0"))<<Code;
  }
public:
  explicit Guards(Preprocessor &P):PP(P){}
  bool FileNotFound(llvm::StringRef) override {
    Rejected=true;
    PP.getDiagnostics().Report(PP.getDiagnostics().getCustomDiagID(
      DiagnosticsEngine::Error,"PORTABLE_SOURCE_INCLUDE_UNAVAILABLE"));
    return false;
  }
  void FileChanged(SourceLocation L,FileChangeReason R,SrcMgr::CharacteristicKind,FileID) override {
    if (R==RenameFile || R==SystemHeaderPragma) deny(L,"PORTABLE_SOURCE_LINE_ACTION_UNAVAILABLE");
  }
  void InclusionDirective(SourceLocation L,const Token &,llvm::StringRef,bool,CharSourceRange,
      OptionalFileEntryRef,llvm::StringRef,llvm::StringRef,const Module *,bool,
      SrcMgr::CharacteristicKind) override { deny(L,"PORTABLE_SOURCE_INCLUDE_UNAVAILABLE"); }
  void MacroDefined(const Token &T,const MacroDirective *) override { deny(T.getLocation(),"PORTABLE_SOURCE_MACRO_ACTION_UNAVAILABLE"); }
  void MacroUndefined(const Token &T,const MacroDefinition &,const MacroDirective *) override { deny(T.getLocation(),"PORTABLE_SOURCE_MACRO_ACTION_UNAVAILABLE"); }
  void PragmaDirective(SourceLocation L,PragmaIntroducerKind) override { deny(L,"PORTABLE_SOURCE_PRAGMA_UNAVAILABLE"); }
};
class Action final : public ASTFrontendAction {
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &, llvm::StringRef) override {
    return std::make_unique<Consumer>();
  }
  bool BeginSourceFileAction(CompilerInstance &CI) override {
    // Pinned generic InitPreprocessor returns "sometimes" when inline width=0.
    // Selected portable policy is explicitly never lock-free for ordinary types.
    std::string P = CI.getPreprocessor().getPredefines();
    for (auto Prefix : {"__GCC_ATOMIC_", "__CLANG_ATOMIC_"})
      for (auto Type : {"BOOL", "CHAR", "CHAR8_T", "CHAR16_T", "CHAR32_T", "WCHAR_T", "SHORT", "INT", "LONG", "LLONG", "POINTER"}) {
        std::string Name = std::string(Prefix) + Type + "_LOCK_FREE";
        P += "\n#undef " + Name + "\n#define " + Name + " 0\n";
      }
    CI.getPreprocessor().setPredefines(P);
    CI.getPreprocessor().addPPCallbacks(std::make_unique<Guards>(CI.getPreprocessor()));
    CI.getPreprocessor().setTokenWatcher([&CI](const Token &T) {
      if (const IdentifierInfo *I=T.getIdentifierInfo()) {
        auto N=I->getName();
        if (N=="__builtin_va_list" || N=="__builtin_va_start" || N=="__builtin_va_arg" ||
            N=="__builtin_va_end" || N=="__builtin_va_copy" || N=="__gnuc_va_list") {
          Rejected=true;
          CI.getDiagnostics().Report(T.getLocation(),CI.getDiagnostics().getCustomDiagID(
              DiagnosticsEngine::Error,"PORTABLE_VA_LIST_UNAVAILABLE"));
        }
      }
    });
    return true;
  }
};
}

// These two member definitions replace ONLY Targets.cpp.o in an OWNCOORD copy of
// libclangBasic. The original checkout/archive is untouched; no native allocator.
TargetInfo *TargetInfo::CreateTargetInfo(DiagnosticsEngine &D, TargetOptions &O) {
  if (O.Triple != "smir64-unknown-rax" || !O.CPU.empty() || !O.TuneCPU.empty() ||
      !O.ABI.empty() || !O.FeaturesAsWritten.empty() || !O.Features.empty()) {
    D.Report(D.getCustomDiagID(DiagnosticsEngine::Error, "unsupported portable type target request"));
    return nullptr;
  }
  auto *T = new PortableTarget(llvm::Triple(O.Triple));
  T->TargetOpts = &O;
  ++FactoryCalls;
  return T;
}
bool TargetInfo::validateOpenCLTarget(const LangOptions &, DiagnosticsEngine &D) const {
  D.Report(D.getCustomDiagID(DiagnosticsEngine::Error, "OpenCL is outside portable type profile"));
  return false;
}

int main(int Count, char **Args) {
  if (Count != 3 || (std::string(Args[1]) != "c23" && std::string(Args[1]) != "cpp23")) return 2;
  bool CXX = std::string(Args[1]) == "cpp23";
  std::ifstream In(Args[2], std::ios::binary);
  if (!In) return 2;
  std::string Source(1024 * 1024 + 1, '\0');
  In.read(Source.data(), Source.size()); Source.resize(In.gcount());
  if (Source.size() > 1024 * 1024) return 4;
  auto Invocation = std::make_shared<CompilerInvocation>();
  CompilerInstance CI(Invocation);
  auto FS = llvm::makeIntrusiveRefCnt<llvm::vfs::InMemoryFileSystem>();
  FS->setCurrentWorkingDirectory("/rax-source-v1");
  std::string Main = CXX ? "/rax-source-v1/main.cpp" : "/rax-source-v1/main.c";
  FS->addFile(Main, 0, llvm::MemoryBuffer::getMemBufferCopy(Source));
  CI.setVirtualFileSystem(FS);
  CI.createDiagnostics();
  std::vector<const char *> Options{"-triple", "smir64-unknown-rax", "-x", CXX ? "c++" : "c", CXX ? "-std=c++23" : "-std=c23", "-fsyntax-only", "-Werror", "-nostdsysteminc", "-nobuiltininc", Main.c_str()};
  if (CXX) { Options.push_back("-fexceptions"); Options.push_back("-fcxx-exceptions"); }
  if (!CompilerInvocation::CreateFromArgs(*Invocation, Options, CI.getDiagnostics())) return 2;
  ProcessWarningOptions(CI.getDiagnostics(),CI.getDiagnosticOpts(),*FS);
  CI.getLangOpts().CharIsSigned = true;
  CI.getLangOpts().RTTI = CI.getLangOpts().RTTIData = CXX;
  CI.getLangOpts().Exceptions = CI.getLangOpts().CXXExceptions = CXX;
  CI.getPreprocessorOpts().SourceDateEpoch = 0;
  Action A;
  bool OK = CI.ExecuteAction(A) && !CI.getDiagnostics().hasErrorOccurred();
  if (!OK || Rejected) return 3;
  for (unsigned I=0;I<Types.size();++I) {
    auto &Row=*Types[I].getAsObject();
    Row["source_seen"]=bool(SourceTypes.count(I));
    Row["abi_seen"]=bool(AbiTypes.count(I));
  }
  auto &T = CI.getTarget();
  Object Result{{"format", "portable-target-bootstrap-draft"}, {"binding", "unbound"},
    {"source_fact_authority", false}, {"semantic_admission", false}, {"runtime_authority", false},
    {"factory_calls", FactoryCalls}, {"triple", T.getTriple().str()}, {"datalayout", T.getDataLayoutString()},
    {"little_endian", !T.isBigEndian()}, {"pointer_bits", T.getPointerWidth(LangAS::Default)},
    {"long_bits", T.getLongWidth()}, {"long_double_bits", T.getLongDoubleWidth()},
    {"long_double_precision", llvm::APFloat::semanticsPrecision(T.getLongDoubleFormat())},
    {"declarations", std::move(Rows)}, {"ast_types",std::move(Types)}, {"enum_hooks",std::move(EnumHooks)}, {"scope", "UNBOUND finite C23 record/type projection; no bitfields/C++records/source issuer/body/backend"}};
  llvm::outs() << llvm::formatv("{0:2}\n", Value(std::move(Result)));
}
