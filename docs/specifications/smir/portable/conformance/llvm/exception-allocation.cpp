/* Source ABI exception payload exists before construction and catch dispatch. */
struct Payload {
    int value;
    explicit Payload(int);
    Payload(const Payload&);
    ~Payload() noexcept;
};
[[noreturn]] void allocate_construct_throw(int value) {
    throw Payload(value);
}
int catch_payload() {
    try {
        allocate_construct_throw(7);
    } catch (const Payload& payload) {
        return payload.value;
    }
}
int catch_copy() {
    try {
        allocate_construct_throw(9);
    } catch (Payload payload) {
        return payload.value;
    }
}
