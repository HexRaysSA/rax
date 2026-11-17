extern "C" void event(int);
struct Part {
    int tag;
    Part(int value) : tag(value) { event(tag); }
    ~Part() { event(-tag); }
};
struct Virtual {
    Part value;
    Virtual() : value(10) {}
    ~Virtual() {}
};
struct Left : virtual Virtual {
    Part left;
    Left() : left(20) {}
    ~Left() {}
};
struct Right : virtual Virtual {
    Part right;
    Right() : right(30) {}
    ~Right() {}
};
struct Diamond : Left, Right {
    Part first;
    Part second;
    Part array[2];
    // Textual order intentionally differs from actual Sema construction order.
    Diamond() : second(50), Right(), first(40), Left(), array{60, 61} {}
    ~Diamond() {}
};
extern "C" void exercise() { Diamond object; }
// A genuine derived source use forces the base variants into the IR witness.
struct Further : Diamond {
    Further() {}
    ~Further() {}
};
extern "C" void exercise_base() { Further object; }
