// Pinned AST source sidecar; no backend, guest execution or private facts.
#include "clang/AST/ASTContext.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/DeclTemplate.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Basic/Version.h"
#include "clang/Frontend/ASTUnit.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Support/raw_ostream.h"
#include <fstream>
#include <map>
#include <optional>
#include <string>
#include <vector>
using namespace clang;
using llvm::json::Array;
using llvm::json::Object;
using llvm::json::Value;
static constexpr const char *Pin="36763294ef639d8a6a4379d81da653dda1c20686";
static Value some(Value V){return Object{{"some",std::move(V)}};}
static const char *linkage(Linkage L){
 switch(L){case Linkage::Invalid:return "Invalid";case Linkage::None:return "None";
 case Linkage::Internal:return "Internal";case Linkage::UniqueExternal:return "UniqueExternal";
 case Linkage::VisibleNone:return "VisibleNone";case Linkage::Module:return "Module";
 case Linkage::External:return "External";}return "Invalid";
}
class Sidecar:public RecursiveASTVisitor<Sidecar>{
 ASTContext &C;bool Failed=false;unsigned Work=0;
 std::map<void *,unsigned> Ids;std::vector<std::optional<Object>> Types;
public:
 Array Roots;
 explicit Sidecar(ASTContext &Context):C(Context){}
 void fail(llvm::StringRef Message){
  if(!Failed)llvm::errs()<<"E-SOURCE-PROJECTION-SOURCE-SCOPE: "<<Message<<'\n';
  Failed=true;
 }
 bool failed()const{return Failed;}
 Value key(const CXXRecordDecl *R){
  const auto &SM=C.getSourceManager();const auto *Canonical=R->getCanonicalDecl();
  if(Canonical->getName().empty()||Canonical->getLocation().isMacroID()||
     !SM.isWrittenInMainFile(Canonical->getLocation())){fail("nonmain/macro/unnamed declaration");return nullptr;}
  Value Definition=nullptr;
  if(const auto *D=R->getDefinition()){
   if(D->getLocation().isMacroID()||!SM.isWrittenInMainFile(D->getLocation())){fail("nonmain/macro definition");return nullptr;}
   Definition=some(SM.getFileOffset(D->getLocation()));
  }
  return Object{{"canonical_offset",SM.getFileOffset(Canonical->getLocation())},
   {"definition_offset",std::move(Definition)},{"qualified_name",Canonical->getQualifiedNameAsString()}};
 }
 unsigned type(QualType T,unsigned Depth=0){
  T=C.getCanonicalType(T);auto It=Ids.find(T.getAsOpaquePtr());if(It!=Ids.end())return It->second;
  if(++Work>100000||Depth>128||Types.size()>=4096){fail("graph resource bound");return 0;}
  if(T.isRestrictQualified()||T.getAddressSpace()!=LangAS::Default){fail("unsupported qualifiers/address space");return 0;}
  unsigned Id=Types.size();Ids.emplace(T.getAsOpaquePtr(),Id);Types.emplace_back();
  Object Data;
  if(const auto *BT=T->getAs<BuiltinType>()){
   const char *Name=nullptr;
   switch(BT->getKind()){
   case BuiltinType::Bool:Name="Bool";break;case BuiltinType::SChar:Name="SChar";break;
   case BuiltinType::UChar:Name="UChar";break;case BuiltinType::Short:Name="Short";break;
   case BuiltinType::UShort:Name="UShort";break;case BuiltinType::Int:Name="Int";break;
   case BuiltinType::UInt:Name="UInt";break;case BuiltinType::Long:Name="Long";break;
   case BuiltinType::ULong:Name="ULong";break;case BuiltinType::LongLong:Name="LongLong";break;
   case BuiltinType::ULongLong:Name="ULongLong";break;case BuiltinType::Float:Name="Float";break;
   case BuiltinType::Double:Name="Double";break;case BuiltinType::Void:Name="Void";break;
   default:fail("unsupported builtin enum");break;
   }
   if(!Name)return Id;
   unsigned Bits=T->isVoidType()?0:T->isIntegerType()?C.getIntWidth(T):C.getTypeSize(T);
   Data=Object{{"kind","builtin"},{"builtin",Name},{"value_bits",Bits},{"signed",T->isSignedIntegerType()}};
  }else if(const auto *R=T->getAsCXXRecordDecl()){
   if(R->isDependentContext()||R->isLambda()||isa<ClassTemplateSpecializationDecl>(R)){fail("template/lambda record");return Id;}
   const auto *D=R->getDefinition();Array Fields,Bases;unsigned Methods=0;Value Traits=nullptr;
   if(D){
    for(const auto *Decl:D->decls()){
     if(const auto *Method=dyn_cast<CXXMethodDecl>(Decl)){if(!Method->isImplicit())++Methods;}
     if(isa<FunctionTemplateDecl>(Decl))++Methods;
    }
    unsigned Index=0;
    for(const auto *F:D->fields()){
     if(Index>=4096||F->getLocation().isMacroID()||F->getBeginLoc().isMacroID()){fail("field bound/macro");break;}
     Fields.push_back(Object{{"index",Index++},{"type",type(F->getType(),Depth+1)}});
    }
    Index=0;for(const auto &B:D->bases()){
     if(Index>=4096){fail("base bound");break;}
     Bases.push_back(Object{{"index",Index++},{"type",type(B.getType(),Depth+1)},{"virtual",B.isVirtual()}});
    }
    Traits=some(Object{{"pod03",D->isPOD()},{"trivial",D->isTrivial()},
     {"standard_layout",D->isCXX11StandardLayout()},{"polymorphic",D->isPolymorphic()},
     {"dynamic",D->isDynamicClass()},{"empty",D->isEmpty()},
     {"needs_copy_resolution",D->needsOverloadResolutionForCopyConstructor()},
     {"needs_destructor_resolution",D->needsOverloadResolutionForDestructor()},
     {"simple_copy",D->hasSimpleCopyConstructor()},{"trivial_copy_ctor",D->hasTrivialCopyConstructor()},
     {"trivially_copyable",D->isTriviallyCopyable()},{"simple_destructor",D->hasSimpleDestructor()},
     {"trivial_destructor",D->hasTrivialDestructor()}});
   }
   Data=Object{{"kind","record"},{"declaration",key(R)},{"complete",D!=nullptr},
    {"ast_linkage",linkage(R->getLinkageInternal())},{"anonymous_namespace",R->isInAnonymousNamespace()},
    {"local_class",R->isLocalClass()!=nullptr},{"lambda",R->isLambda()},
    {"user_declared_methods",Methods},{"traits",std::move(Traits)},
    {"fields",std::move(Fields)},{"bases",std::move(Bases)}};
  }else if(const auto *A=C.getAsConstantArrayType(T)){
   if(A->getSize().getActiveBits()>64){fail("array extent");return Id;}
   Data=Object{{"kind","array"},{"element",type(A->getElementType(),Depth+1)},
    {"count",some(A->getSize().getZExtValue())}};
  }else if(const auto *A=C.getAsIncompleteArrayType(T)){
   Data=Object{{"kind","array"},{"element",type(A->getElementType(),Depth+1)},{"count",nullptr}};
  }else if(T->isPointerType()){
   Data=Object{{"kind","pointer"},{"pointee",type(T->getPointeeType(),Depth+1)}};
  }else if(T->isReferenceType()){
   Data=Object{{"kind","reference"},{"pointee",type(T->getPointeeType(),Depth+1)},
    {"category",T->isLValueReferenceType()?"lvalue":"rvalue"}};
  }else{fail("unsupported source type");return Id;}
  Types[Id]=Object{{"id",Id},{"const",T.isConstQualified()},{"volatile",T.isVolatileQualified()},{"data",std::move(Data)}};
  return Id;
 }
 bool VisitCXXRecordDecl(CXXRecordDecl *R){
  if(R->isCompleteDefinition()&&!R->isImplicit()&&C.getSourceManager().isWrittenInMainFile(R->getLocation())){
   if(Roots.size()>=256){fail("record root bound");return false;}
   Roots.push_back(type(C.getTypeDeclType(ElaboratedTypeKeyword::None,std::nullopt,R)));
  }
  return !Failed;
 }
 Array nodes(){Array Out;for(auto &T:Types){if(!T){fail("incomplete type graph");return {}; }Out.push_back(std::move(*T));}return Out;}
};
int main(int Argc,char **Argv){
 if(Argc!=2){llvm::errs()<<"usage: source-projection-sidecar SOURCE\n";return 2;}
 std::ifstream Stream(Argv[1],std::ios::binary);if(!Stream)return 2;
 std::string Source(1024*1024+1,'\0');Stream.read(&Source[0],Source.size());Source.resize(Stream.gcount());
 if(Source.size()>1024*1024)return 2;
 std::vector<std::string> Options{"-xc++","-std=c++23","-target","x86_64-unknown-linux-gnu","-nostdinc","-pedantic-errors","-nostdinc++"};
 auto A=tooling::buildASTFromCodeWithArgs(Source,Options,Argv[1]);
 if(!A||A->getDiagnostics().hasErrorOccurred())return 2;
 auto &C=A->getASTContext();if(C.getCharWidth()!=8||C.getTypeSize(C.LongTy)!=64||
  C.getTargetInfo().getPointerWidth(LangAS::Default)!=64||C.getTargetInfo().isBigEndian())return 2;
 Sidecar S(C);S.TraverseDecl(C.getTranslationUnitDecl());if(S.failed())return 2;Array Nodes=S.nodes();if(S.failed())return 2;
 auto Hash=llvm::SHA256::hash(llvm::ArrayRef<uint8_t>(reinterpret_cast<const uint8_t*>(Source.data()),Source.size()));
 Array Args;for(const auto &Option:Options)Args.push_back(Option);
 Object Result{{"format","clang-original-source-sidecar"},{"revision",1},{"language","cpp23"},
  {"llvm_pin",Pin},{"library_version",getClangFullVersion()},{"target","x86_64-unknown-linux-gnu"},
  {"source_sha256",llvm::toHex(Hash,true)},{"options",std::move(Args)},
  {"char_bits",8},{"pointer_bits",64},{"long_bits",64},{"little_endian",true},
  {"roots",std::move(S.Roots)},{"types",std::move(Nodes)}};
 llvm::outs()<<llvm::formatv("{0:2}\n",Value(std::move(Result)));
}
