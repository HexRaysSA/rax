#include "c-linkage.h"
static_assert(sizeof(CRecord) == 16);
static_assert(__builtin_offsetof(CRecord, count) == 8);
int cpp_api(int value) { return value + 1; }
long cpp_api(long value) { return value + 2; }
int main() {
    CRecord record{3, 40};
    return c_api(&record, 2) == 45 && record.count == 42 &&
           c_api(c_current, 2) == 45 && c_shared.count == 42 && c_wide == 65 &&
           cpp_api(1) == 2 && cpp_api(1L) == 3 ? 0 : 1;
}
