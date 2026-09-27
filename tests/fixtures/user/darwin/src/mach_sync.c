/* Mach semaphores, clocks, and sleeping. */
#include <mach/clock.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    mach_port_t task = mach_task_self();
    semaphore_t s;
    kern_return_t kr = semaphore_create(task, &s, SYNC_POLICY_FIFO, 0);
    mach_port_type_t t;
    mach_port_type(task, s, &t);
    printf("create: kr=%#x type=%#x\n", kr, t);
    kr = semaphore_create(task, &s, SYNC_POLICY_FIFO, -1);
    printf("create negative: kr=%#x\n", kr);
    kr = semaphore_create(task, &s, 0x100, 0);
    printf("create bad policy: kr=%#x\n", kr);
    semaphore_create(task, &s, SYNC_POLICY_FIFO, 0);

    mach_timespec_t zero = { 0, 0 }, ms = { 0, 1000000 }, bad = { 0, 1000000000 };
    printf("timedwait poll: kr=%#x\n", semaphore_timedwait(s, zero));
    printf("timedwait 1ms: kr=%#x\n", semaphore_timedwait(s, ms));
    printf("timedwait bad nsec: kr=%#x\n", semaphore_timedwait(s, bad));
    printf("signal: kr=%#x\n", semaphore_signal(s));
    printf("wait after signal: kr=%#x\n", semaphore_wait(s));
    printf("signal x2: kr=%#x %#x\n", semaphore_signal(s), semaphore_signal(s));
    printf("wait x2: kr=%#x %#x\n", semaphore_wait(s), semaphore_timedwait(s, zero));
    printf("third poll: kr=%#x\n", semaphore_timedwait(s, zero));
    printf("signal_all without waiters: kr=%#x\n", semaphore_signal_all(s));
    printf("poll after signal_all: kr=%#x\n", semaphore_timedwait(s, zero));
    printf("signal_thread without waiter: kr=%#x\n", semaphore_signal_thread(s, mach_thread_self()));

    semaphore_t s2;
    semaphore_create(task, &s2, SYNC_POLICY_FIFO, 1);
    printf("wait_signal: kr=%#x\n", semaphore_wait_signal(s2, s));
    printf("signalled by wait_signal: kr=%#x\n", semaphore_timedwait(s, zero));
    printf("timedwait_signal: kr=%#x\n", semaphore_timedwait_signal(s2, s, ms));
    printf("signalled by timedwait_signal: kr=%#x\n", semaphore_timedwait(s, zero));

    printf("destroy: kr=%#x\n", semaphore_destroy(task, s2));
    printf("signal destroyed: kr=%#x\n", semaphore_signal(s2));
    printf("signal null: kr=%#x\n", semaphore_signal(MACH_PORT_NULL));
    printf("signal a non-semaphore: kr=%#x\n", semaphore_signal(mach_task_self()));

    /* Sleeping. */
    struct timespec req = { 0, 2000000 }, rem = { 9, 9 };
    uint64_t t0 = mach_absolute_time();
    int r = nanosleep(&req, &rem);
    uint64_t t1 = mach_absolute_time();
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    uint64_t slept = (t1 - t0) * tb.numer / tb.denom;
    printf("nanosleep 2ms: r=%d slept_at_least=%d\n", r, slept >= 2000000);
    t0 = mach_absolute_time();
    kr = mach_wait_until(t0 + (3000000ull * tb.denom / tb.numer));
    slept = (mach_absolute_time() - t0) * tb.numer / tb.denom;
    printf("mach_wait_until 3ms: kr=%#x slept_at_least=%d\n", kr, slept >= 3000000);
    printf("usleep: r=%d\n", usleep(1000));
    printf("thread_switch: kr=%#x\n", thread_switch(MACH_PORT_NULL, SWITCH_OPTION_NONE, 0));

    /* Clocks. */
    clock_serv_t sys, cal;
    host_get_clock_service(mach_host_self(), SYSTEM_CLOCK, &sys);
    kr = host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cal);
    printf("clock services: kr=%#x\n", kr);
    mach_timespec_t a, b;
    kr = clock_get_time(sys, &a);
    clock_get_time(sys, &b);
    printf("system clock: kr=%#x monotonic=%d\n", kr, b.tv_sec > a.tv_sec || (b.tv_sec == a.tv_sec && b.tv_nsec >= a.tv_nsec));
    kr = clock_get_time(cal, &a);
    time_t now = time(NULL);
    printf("calendar clock: kr=%#x near_time=%d\n", kr, a.tv_sec >= now - 2 && a.tv_sec <= now + 2);
    int res; mach_msg_type_number_t cnt = 1;
    kr = clock_get_attributes(sys, CLOCK_GET_TIME_RES, (clock_attr_t)&res, &cnt);
    printf("resolution: kr=%#x res=%d\n", kr, res);
    kr = host_get_clock_service(mach_host_self(), 7, &sys);
    printf("bad clock: kr=%#x\n", kr);
    return 0;
}
