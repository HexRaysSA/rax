// Draft selected state declarations, not native libc types or builtin identity.
struct VaState { unsigned long area, cursor, limit, cookie; };
using VaList = VaState[1];
struct JumpState {
    unsigned int revision, reserved;
    unsigned long process, checkpoint, generation;
};
using JumpBuffer = JumpState[1];
struct SourceWrappers { VaList list; JumpBuffer buffer; };
struct AdjustedParameters {
    void (*start)(VaList);
    int (*set_jump)(JumpBuffer);
};
struct StoredReference { int &variable; };
static_assert(sizeof(VaState) == 32 && alignof(VaState) == 8);
static_assert(sizeof(JumpState) == 32 && alignof(JumpState) == 8);
static_assert(sizeof(VaList) == 32 && sizeof(JumpBuffer) == 32);
static_assert(sizeof(StoredReference) == 8 && sizeof(int) == 4);
