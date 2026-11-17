extern "C" void event(int);
struct Delegating {
    int value;
    Delegating(int argument) : value(argument) { event(100 + value); }
    Delegating() : Delegating(7) { event(200); }
    ~Delegating() { event(300); }
};
extern "C" void exercise_delegate() { Delegating object; }
