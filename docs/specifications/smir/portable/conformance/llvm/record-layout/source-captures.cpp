void value_capture() {
    int x = 1;
    long y = 2;
    auto lambda = [x, y] { return x + y; };
    struct ValueHolder { decltype(lambda) value; };
}
void reference_capture() {
    int x = 1;
    auto lambda = [&x] { return x; };
    struct ReferenceHolder { decltype(lambda) value; };
}
void array_capture() {
    int array[3] = {};
    auto lambda = [array] { return array[0]; };
    struct ArrayHolder { decltype(lambda) value; };
}
void init_capture() {
    auto lambda = [renamed = 3] { return renamed; };
    struct InitHolder { decltype(lambda) value; };
}
void empty_capture() {
    auto lambda = [] { return 0; };
    struct EmptyHolder { decltype(lambda) value; };
}
struct ThisOwner {
    int member;
    void capture_this() {
        auto lambda = [*this] { return member; };
        struct ThisHolder { decltype(lambda) value; };
    }
};
