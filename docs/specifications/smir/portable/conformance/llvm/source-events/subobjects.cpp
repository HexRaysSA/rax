struct Base { ~Base() {} };
struct Member { ~Member() {} };
struct Derived : Base { Member member; ~Derived() {} };
void subobjects() { Derived value; }
