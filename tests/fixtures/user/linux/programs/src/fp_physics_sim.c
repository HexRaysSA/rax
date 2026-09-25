/*
 * N-Body Gravitational Simulation
 *
 * Simulates gravitational interactions between particles.
 * Heavy use of sqrt, division, multiply-accumulate.
 *
 * Features exercised:
 *   - FP sqrt (or approximation)
 *   - FP division
 *   - FP multiply-accumulate
 *   - Vectorizable force calculation
 */

#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define NUM_BODIES 12 /* rax: was 128 */
#define TIME_STEPS 12 /* rax: was 100 */
#define DT 0.01

volatile double sink;

typedef struct {
    double x, y, z;       /* Position */
    double vx, vy, vz;    /* Velocity */
    double ax, ay, az;    /* Acceleration */
    double mass;
} Body;

static Body bodies[NUM_BODIES];

/* Approximate sqrt using Newton-Raphson */
static double approx_sqrt(double x) {
    if (x <= 0.0) return 0.0;

    /* Initial guess using bit manipulation */
    double guess = x * 0.5;

    /* Newton-Raphson iterations */
    for (int i = 0; i < 10; i++) {
        guess = 0.5 * (guess + x / guess);
    }

    return guess;
}

/* Approximate 1/sqrt(x) - important for gravitational force */
static double approx_rsqrt(double x) {
    if (x <= 0.0) return 0.0;

    double half = 0.5 * x;
    double guess = 1.0 / approx_sqrt(x);

    /* One Newton-Raphson refinement for rsqrt */
    guess = guess * (1.5 - half * guess * guess);
    guess = guess * (1.5 - half * guess * guess);

    return guess;
}

/* Initialize bodies in a pseudo-random configuration */
static void init_bodies(void) {
    unsigned int seed = 42;

    for (int i = 0; i < NUM_BODIES; i++) {
        /* Position in unit cube */
        seed = seed * 1103515245 + 12345;
        bodies[i].x = (double)((seed >> 16) & 0xFFFF) / 65536.0 - 0.5;
        seed = seed * 1103515245 + 12345;
        bodies[i].y = (double)((seed >> 16) & 0xFFFF) / 65536.0 - 0.5;
        seed = seed * 1103515245 + 12345;
        bodies[i].z = (double)((seed >> 16) & 0xFFFF) / 65536.0 - 0.5;

        /* Small random velocity */
        seed = seed * 1103515245 + 12345;
        bodies[i].vx = 0.01 * ((double)((seed >> 16) & 0xFFFF) / 65536.0 - 0.5);
        seed = seed * 1103515245 + 12345;
        bodies[i].vy = 0.01 * ((double)((seed >> 16) & 0xFFFF) / 65536.0 - 0.5);
        seed = seed * 1103515245 + 12345;
        bodies[i].vz = 0.01 * ((double)((seed >> 16) & 0xFFFF) / 65536.0 - 0.5);

        bodies[i].ax = 0.0;
        bodies[i].ay = 0.0;
        bodies[i].az = 0.0;

        bodies[i].mass = 1.0 + 0.5 * ((double)((seed >> 16) & 0xFFFF) / 65536.0);
    }
}

/* Compute gravitational forces between all pairs */
static void compute_forces(void) {
    /* Reset accelerations */
    for (int i = 0; i < NUM_BODIES; i++) {
        bodies[i].ax = 0.0;
        bodies[i].ay = 0.0;
        bodies[i].az = 0.0;
    }

    /* Compute pairwise forces */
    const double G = 0.001;  /* Gravitational constant */
    const double softening = 0.01;  /* Avoid singularity */

    for (int i = 0; i < NUM_BODIES; i++) {
        for (int j = i + 1; j < NUM_BODIES; j++) {
            /* Distance vector */
            double dx = bodies[j].x - bodies[i].x;
            double dy = bodies[j].y - bodies[i].y;
            double dz = bodies[j].z - bodies[i].z;

            /* Distance squared */
            double dist_sq = dx * dx + dy * dy + dz * dz + softening;

            /* Force magnitude: G * m1 * m2 / r^2 */
            /* For acceleration: F/m = G * m_other / r^2 */
            /* We need 1/r^3 for the vector form */
            double inv_dist = approx_rsqrt(dist_sq);
            double inv_dist3 = inv_dist * inv_dist * inv_dist;

            double force_factor = G * inv_dist3;

            /* Force on i from j */
            double fi = force_factor * bodies[j].mass;
            bodies[i].ax += fi * dx;
            bodies[i].ay += fi * dy;
            bodies[i].az += fi * dz;

            /* Force on j from i (Newton's 3rd law) */
            double fj = force_factor * bodies[i].mass;
            bodies[j].ax -= fj * dx;
            bodies[j].ay -= fj * dy;
            bodies[j].az -= fj * dz;
        }
    }
}

/* Update positions and velocities (leapfrog integration) */
static void integrate(double dt) {
    for (int i = 0; i < NUM_BODIES; i++) {
        /* Update velocity */
        bodies[i].vx += bodies[i].ax * dt;
        bodies[i].vy += bodies[i].ay * dt;
        bodies[i].vz += bodies[i].az * dt;

        /* Update position */
        bodies[i].x += bodies[i].vx * dt;
        bodies[i].y += bodies[i].vy * dt;
        bodies[i].z += bodies[i].vz * dt;
    }
}

/* Compute total kinetic energy */
static double kinetic_energy(void) {
    double ke = 0.0;
    for (int i = 0; i < NUM_BODIES; i++) {
        double v_sq = bodies[i].vx * bodies[i].vx
                    + bodies[i].vy * bodies[i].vy
                    + bodies[i].vz * bodies[i].vz;
        ke += 0.5 * bodies[i].mass * v_sq;
    }
    return ke;
}

int main(void) {
    double total_energy = 0.0;

    for (int run = 0; run < 2; run++) { /* rax: was 10 */
        init_bodies();

        for (int step = 0; step < TIME_STEPS; step++) {
            compute_forces();
            integrate(DT);

            /* Sample energy periodically */
            if (step % 10 == 0) {
                total_energy += kinetic_energy();
            }
        }
    }

    sink = total_energy;
    uint64_t total_energy_bits; /* rax: print the result so that runs can be compared */
    memcpy(&total_energy_bits, &total_energy, sizeof total_energy_bits);
    printf("total_energy=%016" PRIx64 "\n", total_energy_bits);
    return 0;
}
