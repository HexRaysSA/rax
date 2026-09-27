/* Unguarding a port that is not guarded is a fatal EXC_GUARD: the task is
 * killed with SIGKILL before the call returns to it. */
#include <mach/mach.h>
#include <stdio.h>

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    mach_port_t p;
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p);
    printf("allocate: kr=%#x\n", kr);
    kr = mach_port_unguard(mach_task_self(), p, 1);
    printf("unguard returned: kr=%#x\n", kr);
    return 0;
}
