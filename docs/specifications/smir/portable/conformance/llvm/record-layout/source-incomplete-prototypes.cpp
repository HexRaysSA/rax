// Existing-target compile witness only. No call to the incomplete prototype.
struct R;
struct Logical {
    virtual R method(R);
    virtual ~Logical() = default;
};
static_assert(sizeof(Logical) == 8);
Logical object;
using Function = R(R);
using Pointer = Function*;
static_assert(sizeof(Pointer) == 8);
R function(R);
Pointer null_pointer = nullptr;
Pointer address_pointer = &function;
Pointer copy_pointer() { return address_pointer; }
