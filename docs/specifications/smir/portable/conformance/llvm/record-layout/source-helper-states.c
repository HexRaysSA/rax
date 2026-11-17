/* Draft selected state declarations, not native libc types or builtin identity. */
struct VaState { unsigned long area, cursor, limit, cookie; };
typedef struct VaState VaList[1];
struct JumpState {
    unsigned int revision, reserved;
    unsigned long process, checkpoint, generation;
};
typedef struct JumpState JumpBuffer[1];
struct SourceWrappers { VaList list; JumpBuffer buffer; };
struct AdjustedParameters {
    void (*start)(VaList);
    int (*set_jump)(JumpBuffer);
};
static_assert(sizeof(struct VaState) == 32);
static_assert(_Alignof(struct VaState) == 8);
static_assert(sizeof(struct JumpState) == 32);
static_assert(_Alignof(struct JumpState) == 8);
static_assert(sizeof(VaList) == 32);
static_assert(sizeof(JumpBuffer) == 32);
