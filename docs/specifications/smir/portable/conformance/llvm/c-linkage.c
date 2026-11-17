#include "c-linkage.h"
_Static_assert(sizeof(struct CRecord) == 16, "LP64 record size");
_Static_assert(__builtin_offsetof(struct CRecord, count) == 8, "LP64 field offset");
struct CRecord c_shared = {3, 40};
struct CRecord *c_current = &c_shared;
int c_wide = 65;
long c_api(struct CRecord *record, int delta) {
    record->count += delta;
    return record->tag + record->count;
}
