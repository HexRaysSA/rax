// Owncoord DRAFT: actual pinned AST/CFG observations, never lifetime authority.
#include "clang/AST/ASTContext.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Analysis/CFG.h"
#include "clang/Analysis/ConstructionContext.h"
#include "clang/Basic/BuiltinTraits.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Basic/Version.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Support/VirtualFileSystem.h"
#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <map>
#include <set>
#include <vector>
using namespace clang;
using llvm::json::Array;
using llvm::json::Object;
using llvm::json::Value;
static constexpr const char *Pin="36763294ef639d8a6a4379d81da653dda1c20686";
[[noreturn]] static void fail(const char *Code,const char *Detail,int Exit=3){
 llvm::errs()<<Code<<": "<<Detail<<'\n'; std::exit(Exit);
}
static Value opt(unsigned N){return Object{{"some",N}};}
static const char *contextName(const ConstructionContext *CC){
 if(!CC)return "absent";
 switch(CC->getKind()){
 case ConstructionContext::SimpleVariableKind:return "simple_variable";
 case ConstructionContext::CXX17ElidedCopyVariableKind:return "cxx17_elided_copy_variable";
 case ConstructionContext::SimpleConstructorInitializerKind:return "simple_initializer";
 case ConstructionContext::CXX17ElidedCopyConstructorInitializerKind:return "cxx17_elided_copy_initializer";
 case ConstructionContext::NewAllocatedObjectKind:return "new_allocated";
 case ConstructionContext::SimpleTemporaryObjectKind:return "simple_temporary";
 case ConstructionContext::ElidedTemporaryObjectKind:return "elided_temporary";
 case ConstructionContext::SimpleReturnedValueKind:return "simple_returned_value";
 case ConstructionContext::CXX17ElidedCopyReturnedValueKind:return "cxx17_elided_copy_returned_value";
 case ConstructionContext::ArgumentKind:return "argument";
 case ConstructionContext::LambdaCaptureKind:return "lambda_capture";
 }
 fail("CEW_CFG_KIND","unknown construction context");
}
struct Unit {
 ASTContext &C; std::map<const Decl*,unsigned> DeclIDs; std::vector<Object> Decls;
 Array Functions,Traits; unsigned TotalNodes=0;
 explicit Unit(ASTContext &Context):C(Context){}
 Value location(SourceLocation L){
  if(L.isInvalid())return nullptr;
  if(L.isMacroID())fail("CEW_PROFILE","macro source coordinate");
  if(!C.getSourceManager().isWrittenInMainFile(L))return nullptr;
  return opt(C.getSourceManager().getFileOffset(L));
 }
 Object range(SourceRange R){return Object{{"begin_offset",location(R.getBegin())},{"end_token_offset",location(R.getEnd())}};}
 unsigned decl(const NamedDecl *D){
  if(!D)fail("CEW_INTERNAL","null declaration",70);
  const auto *Canonical=cast<NamedDecl>(D->getCanonicalDecl());
  auto Found=DeclIDs.find(Canonical);if(Found!=DeclIDs.end())return Found->second;
  if(Decls.size()>=4096)fail("CEW_RESOURCE","declaration bound",4);
  unsigned ID=Decls.size();DeclIDs[Canonical]=ID;Decls.emplace_back();
  const NamedDecl *Definition=nullptr;
  if(const auto *F=dyn_cast<FunctionDecl>(D))Definition=F->getDefinition();
  else if(const auto *T=dyn_cast<TagDecl>(D))Definition=T->getDefinition();
  else if(const auto *V=dyn_cast<VarDecl>(D))Definition=V->getDefinition();else if(isa<FieldDecl>(D))Definition=D;
  Value Ty=nullptr;if(const auto *V=dyn_cast<ValueDecl>(D))Ty=V->getType().getCanonicalType().getAsString();
  auto Parent=[&](const DeclContext *DC)->Value {
   if(!DC)return nullptr;
   if(const auto *ND=dyn_cast<NamedDecl>(Decl::castFromDeclContext(DC)))return opt(decl(ND));
   return nullptr;
  };
  Value SemanticParent=Parent(Canonical->getDeclContext());
  Value LexicalParent=Parent(Canonical->getLexicalDeclContext());
  Value DefinitionParent=Definition?Parent(Definition->getLexicalDeclContext()):Value(nullptr);
  Decls[ID]=Object{{"id",ID},{"decl_kind",Canonical->getDeclKindName()},
   {"qualified_name",Canonical->getQualifiedNameAsString()},{"implicit",Canonical->isImplicit()},
   {"canonical_offset",location(Canonical->getLocation())},
   {"definition_offset",Definition?location(Definition->getLocation()):Value(nullptr)},
   {"type_spelling_inspection",std::move(Ty)},{"semantic_parent",std::move(SemanticParent)},{"canonical_lexical_parent",std::move(LexicalParent)},{"definition_lexical_parent",std::move(DefinitionParent)}};
  return ID;
 }
};
struct Function {
 Unit &U; std::map<const Stmt*,unsigned> IDs;std::vector<Object> Nodes,Regions;
 explicit Function(Unit &V):U(V){}
 Value ref(const Stmt *S){if(!S)return nullptr;return opt(node(S,-1));}
 static bool region(const Stmt *S){return isa<CompoundStmt,IfStmt,ForStmt,WhileStmt,DoStmt,SwitchStmt,CXXTryStmt,CXXCatchStmt,CXXForRangeStmt>(S);}
 unsigned node(const Stmt *S,int Parent,unsigned Depth=0){
  if(!S)fail("CEW_INTERNAL","null AST node",70);
  auto Found=IDs.find(S);if(Found!=IDs.end())return Found->second;
  if(Depth>128||Nodes.size()>=8192||++U.TotalNodes>32768)fail("CEW_RESOURCE","AST node/depth bound",4);
  if(isa<LambdaExpr,CoroutineBodyStmt,CoawaitExpr,CoyieldExpr,CoreturnStmt,GotoStmt,IndirectGotoStmt,AsmStmt,CXXNewExpr,CXXDeleteExpr>(S))
   fail("CEW_PROFILE","unsupported lambda/coroutine/goto/asm/allocation");
  unsigned ID=Nodes.size();IDs[S]=ID;Nodes.emplace_back();int Scope=Parent;
  if(region(S)){
   Scope=Regions.size();Regions.push_back(Object{{"id",Scope},{"stmt",ID},{"stmt_class",S->getStmtClassName()},
    {"parent",Parent<0?Value(nullptr):opt(Parent)},{"range",U.range(S->getSourceRange())}});
  }
  Array Children,Declarations;
  for(const Stmt *Child:S->children())if(Child)Children.push_back(node(Child,Scope,Depth+1));
  Value Reference=nullptr,Call=nullptr,Constructor=nullptr,Destructor=nullptr,Extending=nullptr,Elidable=nullptr,LRef=nullptr,NRVO=nullptr;
  if(const auto *DS=dyn_cast<DeclStmt>(S))for(const Decl *D:DS->decls()){
   if(const auto *ND=dyn_cast<NamedDecl>(D))Declarations.push_back(U.decl(ND));
   if(const auto *V=dyn_cast<VarDecl>(D))if(V->isStaticLocal()||V->getTLSKind()!=VarDecl::TLS_None)
    fail("CEW_PROFILE","static or TLS local initialization");
  }
  if(const auto *Catch=dyn_cast<CXXCatchStmt>(S))if(const auto *D=Catch->getExceptionDecl())Declarations.push_back(U.decl(D));
  if(const auto *D=dyn_cast<DeclRefExpr>(S))Reference=opt(U.decl(D->getDecl()));
  if(const auto *M=dyn_cast<MemberExpr>(S))Reference=opt(U.decl(M->getMemberDecl()));
  if(const auto *CE=dyn_cast<CallExpr>(S))if(const auto *D=CE->getDirectCallee())Call=opt(U.decl(D));
  if(const auto *CE=dyn_cast<CXXConstructExpr>(S)){Constructor=opt(U.decl(CE->getConstructor()));Elidable=CE->isElidable();}
  if(const auto *B=dyn_cast<CXXBindTemporaryExpr>(S))Destructor=opt(U.decl(B->getTemporary()->getDestructor()));
  if(const auto *M=dyn_cast<MaterializeTemporaryExpr>(S)){
   if(const auto *D=M->getExtendingDecl())Extending=opt(U.decl(D));LRef=M->isBoundToLvalueReference();
  }
  if(const auto *R=dyn_cast<ReturnStmt>(S))if(const auto *D=R->getNRVOCandidate())NRVO=opt(U.decl(D));
  Value Type=nullptr,Category=nullptr;
  if(const auto *E=dyn_cast<Expr>(S)){Type=E->getType().getCanonicalType().getAsString();Category=E->isLValue()?"lvalue":E->isXValue()?"xvalue":"prvalue";}
  Nodes[ID]=Object{{"id",ID},{"stmt_class",S->getStmtClassName()},{"range",U.range(S->getSourceRange())},
   {"region",Scope<0?Value(nullptr):opt(Scope)},{"children",std::move(Children)},
   {"declarations",std::move(Declarations)},{"referenced_decl",std::move(Reference)},{"direct_callee",std::move(Call)},
   {"constructor",std::move(Constructor)},{"temporary_destructor",std::move(Destructor)},
   {"extending_decl",std::move(Extending)},{"is_elidable",std::move(Elidable)},
   {"bound_to_lvalue_reference",std::move(LRef)},{"return_nrvo_candidate",std::move(NRVO)},
   {"type_spelling_inspection",std::move(Type)},{"value_category",std::move(Category)}};
  return ID;
 }
 Object element(CFGElement E,unsigned Index){
  const char *Kind=nullptr;Value Statement=nullptr,Trigger=nullptr,Declaration=nullptr,Destructor=nullptr,Context=nullptr,NoReturn=nullptr;Array Expiring;
  switch(E.getKind()){
  case CFGElement::Statement:Kind="statement";Statement=ref(E.castAs<CFGStmt>().getStmt());break;
  case CFGElement::Constructor:{Kind="constructor";auto V=E.castAs<CFGConstructor>();Statement=ref(V.getStmt());Context=contextName(V.getConstructionContext());break;}
  case CFGElement::CXXRecordTypedCall:{Kind="record_typed_call";auto V=E.castAs<CFGCXXRecordTypedCall>();Statement=ref(V.getStmt());Context=contextName(V.getConstructionContext());break;}
  case CFGElement::Initializer:{Kind="initializer";auto *I=E.castAs<CFGInitializer>().getInitializer();Statement=ref(I->getInit());if(I->isMemberInitializer())Declaration=opt(U.decl(I->getMember()));else if(I->isBaseInitializer())if(auto *D=I->getBaseClass()->getAsCXXRecordDecl())Declaration=opt(U.decl(D));break;}
  case CFGElement::ScopeBegin:{Kind="scope_begin";auto V=E.castAs<CFGScopeBegin>();Trigger=ref(V.getTriggerStmt());Declaration=opt(U.decl(V.getVarDecl()));break;}
  case CFGElement::ScopeEnd:{Kind="scope_end";auto V=E.castAs<CFGScopeEnd>();Trigger=ref(V.getTriggerStmt());Declaration=opt(U.decl(V.getVarDecl()));break;}
  case CFGElement::LifetimeEnds:{Kind="lifetime_ends_marker";auto V=E.castAs<CFGLifetimeEnds>();Trigger=ref(V.getTriggerStmt());Declaration=opt(U.decl(V.getVarDecl()));break;}
  case CFGElement::AutomaticObjectDtor:{Kind="automatic_object_dtor";auto V=E.castAs<CFGAutomaticObjDtor>();Declaration=opt(U.decl(V.getVarDecl()));Trigger=ref(V.getTriggerStmt());break;}
  case CFGElement::TemporaryDtor:{Kind="temporary_dtor";Statement=ref(E.castAs<CFGTemporaryDtor>().getBindTemporaryExpr());break;}
  case CFGElement::BaseDtor:{Kind="base_dtor";auto *D=E.castAs<CFGBaseDtor>().getBaseSpecifier()->getType()->getAsCXXRecordDecl();if(D)Declaration=opt(U.decl(D));break;}
  case CFGElement::MemberDtor:Kind="member_dtor";Declaration=opt(U.decl(E.castAs<CFGMemberDtor>().getFieldDecl()));break;
  case CFGElement::LoopExit:Kind="loop_exit_marker";Statement=ref(E.castAs<CFGLoopExit>().getLoopStmt());break;
  case CFGElement::FullExprCleanup:{Kind="full_expr_cleanup";auto V=E.castAs<CFGFullExprCleanup>();Statement=ref(V.getCleanupExpr());for(auto *M:V.getExpiringMTEs())Expiring.push_back(node(M,-1));break;}
  case CFGElement::NewAllocator:case CFGElement::DeleteDtor:case CFGElement::CleanupFunction:fail("CEW_PROFILE","unsupported CFG allocation/cleanup attribute");
  }
  if(!Kind)fail("CEW_CFG_KIND","unhandled actual CFG element");
  if(auto D=E.getAs<CFGImplicitDtor>()){
   const CXXDestructorDecl *DD=nullptr;
   if(E.getKind()==CFGElement::BaseDtor){const auto *RD=E.castAs<CFGBaseDtor>().getBaseSpecifier()->getType()->getAsCXXRecordDecl();if(RD)DD=RD->getDestructor();}
   else DD=D->getDestructorDecl(U.C);
   if(!DD)fail("CEW_CFG_KIND","missing actual destructor declaration");
   Destructor=opt(U.decl(DD));NoReturn=DD->isNoReturn();
  }
  return Object{{"index",Index},{"kind",Kind},{"statement",std::move(Statement)},
   {"trigger",std::move(Trigger)},{"declaration",std::move(Declaration)},
   {"destructor",std::move(Destructor)},{"construction_context",std::move(Context)},
   {"destructor_noreturn_inspection",std::move(NoReturn)},{"expiring_temporaries",std::move(Expiring)}};
 }
 Object edge(const CFGBlock::AdjacentBlock &E){
  return Object{{"reachable",E.getReachableBlock()?opt(E.getReachableBlock()->getBlockID()):Value(nullptr)},
   {"possibly_unreachable",E.getPossiblyUnreachableBlock()?opt(E.getPossiblyUnreachableBlock()->getBlockID()):Value(nullptr)}};
 }
 Object run(const FunctionDecl *D){
  unsigned Body=node(D->getBody(),-1);Array Parameters;for(const auto *P:D->parameters())Parameters.push_back(U.decl(P));
  CFG::BuildOptions O;O.PruneTriviallyFalseEdges=false;O.AddEHEdges=true;O.AddInitializers=true;O.AddImplicitDtors=true;O.AddLifetime=true;O.AddParameterLifetimes=false;O.AddLoopExit=true;O.AddTemporaryDtors=true;O.AddScopes=true;O.AddStaticInitBranches=false;O.AddCXXNewAllocator=false;O.AddCXXDefaultInitExprInCtors=true;O.AddCXXDefaultInitExprInAggregates=true;O.AddRichCXXConstructors=true;O.MarkElidedCXXConstructors=true;O.AddVirtualBaseBranches=false;O.OmitImplicitValueInitializers=false;O.AssumeReachableDefaultInSwitchStatements=false;O.setAllAlwaysAdd();
  auto G=CFG::buildCFG(D,const_cast<Stmt*>(D->getBody()),&U.C,O);if(!G)fail("CEW_CFG_UNAVAILABLE","actual Clang CFG build failed");
  if(G->size()>4096)fail("CEW_RESOURCE","CFG block bound",4);std::vector<const CFGBlock*> Ordered;for(const auto *B:*G)Ordered.push_back(B);
  std::sort(Ordered.begin(),Ordered.end(),[](const CFGBlock *A,const CFGBlock *B){return A->getBlockID()<B->getBlockID();});Array Blocks;
  unsigned Total=0;for(const auto *B:Ordered){Array Elements,Successors,Predecessors;unsigned Index=0;
   for(auto E:*B){if(++Total>16384)fail("CEW_RESOURCE","CFG element bound",4);Elements.push_back(element(E,Index++));}
   for(const auto &E:B->succs())Successors.push_back(edge(E));for(const auto &E:B->preds())Predecessors.push_back(edge(E));
   Value Terminator=ref(B->getTerminatorStmt()),Condition=ref(B->getTerminatorCondition(false));
   Blocks.push_back(Object{{"id",B->getBlockID()},{"elements",std::move(Elements)},{"successors",std::move(Successors)},{"predecessors",std::move(Predecessors)},
    {"terminator",std::move(Terminator)},{"condition",std::move(Condition)},{"label",ref(B->getLabel())},{"loop_target",ref(B->getLoopTarget())},
    {"terminator_kind",B->getTerminatorStmt()?Value(static_cast<unsigned>(B->getTerminator().getKind())):Value(nullptr)},
    {"has_noreturn_element_inspection",B->hasNoReturnElement()}});
  }
  Array NodeRows,RegionRows;for(auto &N:Nodes)NodeRows.push_back(std::move(N));for(auto &R:Regions)RegionRows.push_back(std::move(R));
  return Object{{"declaration",U.decl(D)},{"body",Body},{"parameters",std::move(Parameters)},{"entry",G->getEntry().getBlockID()},{"exit",G->getExit().getBlockID()},
   {"nodes",std::move(NodeRows)},{"regions",std::move(RegionRows)},{"blocks",std::move(Blocks)}};
 }
};
class Collector:public RecursiveASTVisitor<Collector>{
 Unit &U;std::set<const FunctionDecl*> Seen;
public:
 explicit Collector(Unit &V):U(V){}
 bool VisitNamedDecl(NamedDecl *D){if(!D->isImplicit()&&U.C.getSourceManager().isWrittenInMainFile(D->getLocation()))U.decl(D);return true;}
 bool VisitTemplateDecl(TemplateDecl *){fail("CEW_PROFILE","template declaration");}
 bool VisitCXXRecordDecl(CXXRecordDecl *D){if(D->isCompleteDefinition()&&D->isDynamicClass())fail("CEW_PROFILE","dynamic/virtual class");return true;}
 bool VisitFunctionDecl(FunctionDecl *D){
  if(!D->isThisDeclarationADefinition()||D->isImplicit()||!D->doesThisDeclarationHaveABody())return true;
  if(!U.C.getSourceManager().isWrittenInMainFile(D->getLocation()))fail("CEW_PROFILE","nonmain body");
  if(D->isTemplated()||D->isDependentContext())fail("CEW_PROFILE","template body");
  if(!Seen.insert(D->getCanonicalDecl()).second)return true;if(U.Functions.size()>=64)fail("CEW_RESOURCE","function bound",4);
  Function F(U);U.Functions.push_back(F.run(D));return true;
 }
 bool VisitTypeTraitExpr(TypeTraitExpr *T){
  if(T->isValueDependent()||!T->isStoredAsBoolean())return true;Array Args;for(unsigned I=0;I<T->getNumArgs();++I)Args.push_back(T->getArg(I)->getType().getCanonicalType().getAsString());
  U.Traits.push_back(Object{{"trait",getTraitSpelling(T->getTrait())},{"arguments_spelling_inspection",std::move(Args)},{"value",T->getBoolValue()},{"range",U.range(T->getSourceRange())}});return true;
 }
};
int main(int Argc,char **Argv){
 if(Argc!=2)fail("CEW_INPUT","expected one source path",2);std::ifstream Stream(Argv[1],std::ios::binary);if(!Stream)fail("CEW_INPUT","cannot read source",2);
 std::string Source(1024*1024+1,'\0');Stream.read(&Source[0],Source.size());Source.resize(Stream.gcount());if(Source.size()>1024*1024)fail("CEW_RESOURCE","source byte bound",4);
 if(Source.find('\0')!=std::string::npos)fail("CEW_INPUT","NUL source",2);
 if(Source.find('#')!=std::string::npos||Source.find("%:")!=std::string::npos||Source.find("??=")!=std::string::npos)fail("CEW_PROFILE","preprocessor introducer spelling");
 for(size_t I=0;I<Source.size();++I)if(Source[I]=='\\'){
  size_t J=I+1;while(J<Source.size()&&(Source[J]==' '||Source[J]=='\t'||Source[J]=='\v'||Source[J]=='\f'))++J;
  if(J<Source.size()&&(Source[J]=='\n'||Source[J]=='\r'))fail("CEW_PROFILE","escaped newline source spelling");
 }
 std::vector<std::string> Options{"-xc++","-std=c++23","-target","x86_64-unknown-linux-gnu","-nostdinc","-pedantic-errors","-nostdinc++","-fexceptions","-fcxx-exceptions","-fno-trigraphs"};
 auto FS=llvm::makeIntrusiveRefCnt<llvm::vfs::InMemoryFileSystem>();
 if(FS->setCurrentWorkingDirectory("/"))fail("CEW_INTERNAL","in-memory filesystem cwd",70);
 auto AST=tooling::buildASTFromCodeWithArgs(Source,Options,Argv[1],"clang-tool",std::make_shared<PCHContainerOperations>(),tooling::getClangStripDependencyFileAdjuster(),tooling::FileContentMappings(),nullptr,FS);if(!AST||AST->getDiagnostics().hasErrorOccurred())fail("CEW_COMPILER_REJECTED","actual compiler diagnostics",2);
 auto &C=AST->getASTContext();if(C.getCharWidth()!=8||C.getTypeSize(C.LongTy)!=64||C.getTargetInfo().getPointerWidth(LangAS::Default)!=64||C.getTargetInfo().isBigEndian())fail("CEW_TARGET","unexpected target");
 Unit U(C);Collector V(U);V.TraverseDecl(C.getTranslationUnitDecl());Array DeclRows;for(auto &D:U.Decls)DeclRows.push_back(std::move(D));Array Args;for(const auto &O:Options)Args.push_back(O);
 Object Config{{"prune_trivially_false_edges",false},{"add_eh_edges",true},{"add_initializers",true},{"add_implicit_dtors",true},{"add_lifetime_markers",true},{"add_parameter_lifetimes",false},{"add_loop_exit_markers",true},{"add_temporary_dtors",true},{"add_scope_markers",true},{"add_static_init_branches",false},{"add_cxx_new_allocator",false},{"add_cxx_default_init_ctors",true},{"add_cxx_default_init_aggregates",true},{"add_rich_cxx_constructors",true},{"mark_elided_cxx_constructors",true},{"add_virtual_base_branches",false},{"omit_implicit_value_initializers",false},{"assume_reachable_switch_default",false},{"all_ast_statements",true}};
 auto Hash=llvm::SHA256::hash(llvm::ArrayRef<uint8_t>(reinterpret_cast<const uint8_t*>(Source.data()),Source.size()));
 Object Result{{"format","clang-source-events-raw"},{"revision",1},{"binding","unbound"},{"runtime_authority",false},{"source_fact_authority",false},{"llvm_pin",Pin},{"library_version",getClangFullVersion()},
  {"target","x86_64-unknown-linux-gnu"},{"source_filesystem","main-buffer-only-in-memory"},{"source_sha256",llvm::toHex(Hash,true)},{"options",std::move(Args)},{"cfg_options",std::move(Config)},
  {"char_bits",8},{"pointer_bits",64},{"long_bits",64},{"little_endian",true},
  {"declarations",std::move(DeclRows)},{"functions",std::move(U.Functions)},{"traits_inspection",std::move(U.Traits)}};
 llvm::outs()<<llvm::formatv("{0:2}\n",Value(std::move(Result)));return 0;
}
