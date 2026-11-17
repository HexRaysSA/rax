struct Result {
    virtual Result *clone();
    virtual Result &reference();
    virtual ~Result();
};
struct Prefix { virtual void pad(); };
struct Derived: Prefix, Result {
    Derived *clone() override;
    Derived &reference() override;
    ~Derived() override;
};
