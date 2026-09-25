/*
 * C++ Virtual Function Dispatch
 *
 * Tests virtual method tables and dynamic dispatch.
 * Exercises vtable lookups and indirect calls.
 *
 * Features exercised:
 *   - Single inheritance virtual calls
 *   - Multiple inheritance
 *   - Virtual destructors
 *   - Covariant return types
 */

#include <cstdint>
#include <cinttypes> /* rax: print the result so that runs can be compared */
#include <cstdio>

volatile int64_t sink;

/* Simple single inheritance hierarchy */
class Shape {
public:
    virtual ~Shape() = default;
    virtual int64_t area() const = 0;
    virtual int64_t perimeter() const = 0;
    virtual const char* name() const { return "Shape"; }
};

class Circle : public Shape {
    int radius;
public:
    explicit Circle(int r) : radius(r) {}
    int64_t area() const override { return (int64_t)(314 * radius * radius / 100); }
    int64_t perimeter() const override { return (int64_t)(628 * radius / 100); }
    const char* name() const override { return "Circle"; }
    int get_radius() const { return radius; }
};

class Rectangle : public Shape {
    int width, height;
public:
    Rectangle(int w, int h) : width(w), height(h) {}
    int64_t area() const override { return (int64_t)width * height; }
    int64_t perimeter() const override { return 2 * (int64_t)(width + height); }
    const char* name() const override { return "Rectangle"; }
};

class Square : public Rectangle {
public:
    explicit Square(int side) : Rectangle(side, side) {}
    const char* name() const override { return "Square"; }
};

class Triangle : public Shape {
    int base, height;
public:
    Triangle(int b, int h) : base(b), height(h) {}
    int64_t area() const override { return (int64_t)base * height / 2; }
    int64_t perimeter() const override { return (int64_t)(base + height + base); } /* Approximate */
    const char* name() const override { return "Triangle"; }
};

/* Multiple inheritance */
class Drawable {
public:
    virtual ~Drawable() = default;
    virtual void draw() const = 0;
    virtual int get_color() const { return 0; }
};

class Movable {
public:
    virtual ~Movable() = default;
    virtual void move(int dx, int dy) = 0;
    virtual int get_x() const = 0;
    virtual int get_y() const = 0;
};

class Sprite : public Drawable, public Movable {
    int x, y;
    int color;
    int width, height;
public:
    Sprite(int px, int py, int c, int w, int h)
        : x(px), y(py), color(c), width(w), height(h) {}

    void draw() const override { /* Would draw sprite */ }
    int get_color() const override { return color; }

    void move(int dx, int dy) override { x += dx; y += dy; }
    int get_x() const override { return x; }
    int get_y() const override { return y; }

    int get_width() const { return width; }
    int get_height() const { return height; }
};

/* Diamond inheritance with virtual base */
class Animal {
protected:
    int age;
public:
    explicit Animal(int a) : age(a) {}
    virtual ~Animal() = default;
    virtual int64_t sound() const = 0;
    int get_age() const { return age; }
};

class Mammal : virtual public Animal {
protected:
    int fur_length;
public:
    Mammal(int a, int f) : Animal(a), fur_length(f) {}
    int get_fur() const { return fur_length; }
};

class WingedAnimal : virtual public Animal {
protected:
    int wingspan;
public:
    WingedAnimal(int a, int w) : Animal(a), wingspan(w) {}
    int get_wingspan() const { return wingspan; }
};

class Bat : public Mammal, public WingedAnimal {
public:
    Bat(int a, int f, int w) : Animal(a), Mammal(a, f), WingedAnimal(a, w) {}
    int64_t sound() const override { return 42; /* Ultrasonic! */ }
};

/* Covariant return types */
class Base {
public:
    virtual ~Base() = default;
    virtual Base* clone() const { return new Base(*this); }
    virtual int value() const { return 1; }
};

class Derived : public Base {
    int extra;
public:
    explicit Derived(int e) : extra(e) {}
    Derived* clone() const override { return new Derived(*this); }
    int value() const override { return extra; }
};

/* Non-virtual interface pattern (Template Method) */
class Algorithm {
public:
    virtual ~Algorithm() = default;

    /* Non-virtual public interface */
    int64_t execute(int input) const {
        int64_t result = preprocess(input);
        result = do_work(result);
        result = postprocess(result);
        return result;
    }

protected:
    virtual int64_t preprocess(int input) const { return input; }
    virtual int64_t do_work(int64_t val) const = 0;
    virtual int64_t postprocess(int64_t result) const { return result; }
};

class AlgorithmA : public Algorithm {
protected:
    int64_t preprocess(int input) const override { return input * 2; }
    int64_t do_work(int64_t val) const override { return val + 100; }
};

class AlgorithmB : public Algorithm {
protected:
    int64_t do_work(int64_t val) const override { return val * val; }
    int64_t postprocess(int64_t result) const override { return result / 10; }
};

/* Deep hierarchy */
class Level0 {
public:
    virtual ~Level0() = default;
    virtual int level() const { return 0; }
    virtual int64_t compute(int x) const { return x; }
};

class Level1 : public Level0 {
public:
    int level() const override { return 1; }
    int64_t compute(int x) const override { return Level0::compute(x) + 10; }
};

class Level2 : public Level1 {
public:
    int level() const override { return 2; }
    int64_t compute(int x) const override { return Level1::compute(x) + 20; }
};

class Level3 : public Level2 {
public:
    int level() const override { return 3; }
    int64_t compute(int x) const override { return Level2::compute(x) + 30; }
};

class Level4 : public Level3 {
public:
    int level() const override { return 4; }
    int64_t compute(int x) const override { return Level3::compute(x) + 40; }
};

/* Helper to process shapes polymorphically */
__attribute__((noinline))
int64_t process_shape(const Shape* s) {
    return s->area() + s->perimeter();
}

__attribute__((noinline))
int64_t process_drawable_movable(Drawable* d, Movable* m) {
    d->draw();
    m->move(1, 1);
    return d->get_color() + m->get_x() + m->get_y();
}

int main() {
    int64_t result = 0;

    /* Shape hierarchy */
    Circle circles[3] = {Circle(10), Circle(20), Circle(30)};
    Rectangle rectangles[3] = {Rectangle(5, 10), Rectangle(15, 20), Rectangle(25, 30)};
    Square squares[3] = {Square(5), Square(10), Square(15)};
    Triangle triangles[3] = {Triangle(6, 8), Triangle(12, 16), Triangle(18, 24)};

    Shape* shapes[12];
    for (int i = 0; i < 3; i++) {
        shapes[i] = &circles[i];
        shapes[i + 3] = &rectangles[i];
        shapes[i + 6] = &squares[i];
        shapes[i + 9] = &triangles[i];
    }

    /* Sprite with multiple inheritance */
    Sprite sprites[4] = {
        Sprite(0, 0, 0xFF0000, 32, 32),
        Sprite(100, 100, 0x00FF00, 64, 64),
        Sprite(200, 50, 0x0000FF, 16, 16),
        Sprite(50, 200, 0xFFFF00, 48, 48)
    };

    /* Diamond inheritance */
    Bat bat(5, 2, 30);

    /* Covariant return */
    Base base;
    Derived derived(42);
    Base* bases[2] = {&base, &derived};

    /* Algorithms */
    AlgorithmA alg_a;
    AlgorithmB alg_b;
    const Algorithm* algorithms[2] = {&alg_a, &alg_b};

    /* Deep hierarchy */
    Level0 l0;
    Level1 l1;
    Level2 l2;
    Level3 l3;
    Level4 l4;
    Level0* levels[5] = {&l0, &l1, &l2, &l3, &l4};

    for (int iter = 0; iter < 300; iter++) { /* rax: was 50000 */
        /* Process shapes */
        for (int i = 0; i < 12; i++) {
            result += process_shape(shapes[i]);
            result += shapes[(iter + i) % 12]->area();
        }

        /* Multiple inheritance */
        Sprite* sprite = &sprites[iter % 4];
        result += process_drawable_movable(sprite, sprite);
        result += sprite->get_width() + sprite->get_height();

        /* Diamond inheritance */
        result += bat.sound();
        result += bat.get_age() + bat.get_fur() + bat.get_wingspan();

        /* Covariant return - clone and delete */
        if (iter % 1000 == 0) {
            Base* cloned = bases[iter % 2]->clone();
            result += cloned->value();
            delete cloned;
        } else {
            result += bases[iter % 2]->value();
        }

        /* Template method pattern */
        result += algorithms[iter % 2]->execute(iter % 100);

        /* Deep hierarchy */
        result += levels[iter % 5]->compute(iter % 50);
        result += levels[iter % 5]->level();
    }

    sink = result;
    std::printf("sink=%" PRId64 "\n", static_cast<int64_t>(sink)); /* rax: print the result so that runs can be compared */
    return 0;
}
