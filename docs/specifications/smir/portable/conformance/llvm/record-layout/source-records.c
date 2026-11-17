struct PlainC { char first; int second; };
struct AnonymousC { int tag; union { int count; float ratio; }; char tail; };
struct FlexibleC { unsigned count; alignas(16) int values[]; };
struct BitfieldsC { unsigned first:3; unsigned:0; unsigned second:5; };
static_assert(sizeof(struct PlainC)==8 && alignof(struct PlainC)==4);
static_assert(sizeof(struct AnonymousC)==12);
static_assert(sizeof(struct FlexibleC)==16 && alignof(struct FlexibleC)==16);
static_assert(sizeof(struct BitfieldsC)==8);
