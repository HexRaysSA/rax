/*
 * Struct Return Values
 *
 * Functions returning structs of various sizes.
 * Small structs may be returned in registers, large ones via hidden pointer.
 *
 * Features exercised:
 *   - Register return (small structs)
 *   - Hidden pointer return (large structs)
 *   - Struct packing and alignment
 */

#include <stdint.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

volatile int64_t sink;

/* Small struct - may fit in registers */
typedef struct {
    int x, y;
} Point2D;

typedef struct {
    int x, y, z;
} Point3D;

typedef struct {
    int x, y, z, w;
} Point4D;

/* Larger structs - require hidden pointer */
typedef struct {
    int data[8];
} Array8;

typedef struct {
    int data[16];
} Array16;

/* Mixed types */
typedef struct {
    int i;
    double d;
} IntDouble;

typedef struct {
    float f;
    int i;
    double d;
} FloatIntDouble;

/* Nested */
typedef struct {
    Point2D p1;
    Point2D p2;
} TwoPoints;

__attribute__((noinline))
Point2D make_point2d(int x, int y) {
    Point2D p = {x, y};
    return p;
}

__attribute__((noinline))
Point3D make_point3d(int x, int y, int z) {
    Point3D p = {x, y, z};
    return p;
}

__attribute__((noinline))
Point4D make_point4d(int x, int y, int z, int w) {
    Point4D p = {x, y, z, w};
    return p;
}

__attribute__((noinline))
Array8 make_array8(int base) {
    Array8 a;
    for (int i = 0; i < 8; i++) {
        a.data[i] = base + i;
    }
    return a;
}

__attribute__((noinline))
Array16 make_array16(int base) {
    Array16 a;
    for (int i = 0; i < 16; i++) {
        a.data[i] = base + i;
    }
    return a;
}

__attribute__((noinline))
IntDouble make_int_double(int i, double d) {
    IntDouble s = {i, d};
    return s;
}

__attribute__((noinline))
FloatIntDouble make_fid(float f, int i, double d) {
    FloatIntDouble s = {f, i, d};
    return s;
}

__attribute__((noinline))
TwoPoints make_two_points(int x1, int y1, int x2, int y2) {
    TwoPoints tp = {{x1, y1}, {x2, y2}};
    return tp;
}

__attribute__((noinline))
Point2D add_points(Point2D a, Point2D b) {
    Point2D r = {a.x + b.x, a.y + b.y};
    return r;
}

int main(void) {
    int64_t result = 0;

    for (int i = 0; i < 800; i++) { /* rax: was 100000 */
        Point2D p2 = make_point2d(i, i + 1);
        result += p2.x + p2.y;

        Point3D p3 = make_point3d(i, i + 1, i + 2);
        result += p3.x + p3.y + p3.z;

        Point4D p4 = make_point4d(i, i + 1, i + 2, i + 3);
        result += p4.x + p4.y + p4.z + p4.w;

        Array8 a8 = make_array8(i);
        for (int j = 0; j < 8; j++) result += a8.data[j];

        Array16 a16 = make_array16(i);
        for (int j = 0; j < 16; j++) result += a16.data[j];

        IntDouble id = make_int_double(i, (double)i * 0.5);
        result += id.i + (int64_t)id.d;

        FloatIntDouble fid = make_fid((float)i, i, (double)i);
        result += (int64_t)fid.f + fid.i + (int64_t)fid.d;

        TwoPoints tp = make_two_points(i, i+1, i+2, i+3);
        result += tp.p1.x + tp.p1.y + tp.p2.x + tp.p2.y;

        Point2D sum = add_points(p2, make_point2d(1, 1));
        result += sum.x + sum.y;
    }

    sink = result;
    printf("sink=%" PRId64 "\n", sink); /* rax: print the result so that runs can be compared */
    return 0;
}
