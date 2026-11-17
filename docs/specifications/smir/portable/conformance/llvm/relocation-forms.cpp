/* Header-free ordinary absolute Itanium vtable and source ptrtoint witnesses. */
int target[2];
int *plain = &target[1];
unsigned long address_bits = (unsigned long)&target[1];
struct V {
    int value = 1;
    virtual int get() const { return value; }
};
constinit V object;
