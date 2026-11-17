#ifndef RAX_LLVM_C_LINKAGE_WITNESS_H
#define RAX_LLVM_C_LINKAGE_WITNESS_H
struct CRecord { int tag; long count; };
#ifdef __cplusplus
extern "C" {
#endif
long c_api(struct CRecord *record, int delta);
extern struct CRecord c_shared;
extern struct CRecord *c_current;
#ifdef __cplusplus
extern wchar_t c_wide;
#else
extern int c_wide;
#endif
#ifdef __cplusplus
}
#endif
#endif
