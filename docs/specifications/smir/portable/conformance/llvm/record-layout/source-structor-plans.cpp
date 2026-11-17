// One source prototype has distinct complete/base execution signatures.
struct V { int value; };
struct A : virtual V {
    A(int);
    ~A();
};
A::A(int) {}
A::~A() {}
