struct Empty {};
struct Inner { int value; };
struct Outer {
  bool ready;
  unsigned long count;
  Inner parts[2][3];
  Inner *pointer;
  [[no_unique_address]] Empty marker;
};
namespace { struct Hidden { long value; }; }
void first() { struct Same { int value; }; }
void second() { struct Same { int value; }; }
struct Qualified { const Inner *first; Inner *second; const int value; };
struct Forward;
struct Holder { Forward *pointer; };
struct Base { int value; };
struct Derived : Base { short tail; };
union Choice { int integer; double real; };
struct ReferenceHolder { int &value; };
struct VoidHolder { void *pointer; };
