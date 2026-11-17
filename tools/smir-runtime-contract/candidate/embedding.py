"""Embedding process/thread/owner-cleanup lifecycle oracle (R026 REV7).

No exported C API implementation; state transitions are tested independently.
"""
from contextlib import contextmanager
from threading import Condition, local

from .errors import require

CALLBACK = local()


@contextmanager
def host_callback(context):
    previous = getattr(CALLBACK, 'contexts', ())
    CALLBACK.contexts = previous + (context,)
    try:yield
    finally:CALLBACK.contexts = previous


def guest_entry_allowed(context):
    require(context not in getattr(CALLBACK, 'contexts', ()), 'RT_CAPI_REENTRY_EDEADLK')


class Process:
    def __init__(self, context, *, image=False, diagnostic_policy=0):
        self.context, self.image, self.diagnostic_policy = context, image, diagnostic_policy
        self.condition = Condition()
        self.state, self.initialization = 'active', 'uninitialized'
        self.next_thread = 1
        self.threads = {}
        self.main_started = False
        self.owner_leases = {}
        self.cleanup_queue = []
        self.cleanup_running = 0
        self.exit_code = None
        self.exit_publications = 0

    def start(self, initialize, *, main=False):
        guest_entry_allowed(self.context)
        with self.condition:
            require(self.state == 'active', 'RT_CAPI_PROCESS_CLOSING')
            require(not main or self.image and not self.main_started, 'RT_CAPI_MAIN_ONCE')
            require(not self.image or main or self.main_started, 'RT_CAPI_CRT_EBUSY')
            if main:self.main_started = True
            identity = self.next_thread
            require(identity < 2**64-1, 'RT_CAPI_THREAD_RESOURCE')
            self.next_thread += 1
            self.threads[identity] = {'state': 'initializing', 'errno': 0, 'rounding': 'nearest_even',
                                      'flags': 0, 'diagnostic_policy': self.diagnostic_policy, 'main': main}
            while self.initialization == 'initializing':self.condition.wait()
            if self.initialization == 'failed':
                self.threads[identity]['state'] = 'failed'
                require(False, 'RT_CAPI_INITIALIZATION_FAILED')
            claim = self.initialization == 'uninitialized'
            if claim:self.initialization = 'initializing'
        if claim:
            try:initialize(identity)  # Same guest thread, no process lock held.
            except BaseException:
                with self.condition:
                    self.initialization = 'failed'
                    self.threads[identity]['state'] = 'failed'
                    self.condition.notify_all()
                raise
            with self.condition:
                self.initialization = 'initialized'
                self.condition.notify_all()
        with self.condition:
            require(self.state == 'active', 'RT_CAPI_PROCESS_CLOSING')
            self.threads[identity]['state'] = 'running'
        return identity

    def finish_thread(self, thread, tls_cleanup, *, exit_code=None):
        with self.condition:
            require(thread in self.threads and self.threads[thread]['state'] == 'running', 'RT_CAPI_THREAD_STATE')
            self.threads[thread]['state'] = 'cleaning'
        tls_cleanup(thread)
        with self.condition:
            self.threads[thread]['state'] = 'exited'
            if self.threads[thread]['main']:
                self.state, self.exit_code = 'closing', exit_code
            self._publish_exit()
            self.condition.notify_all()

    def retain_owner(self, identity, destructor):
        with self.condition:
            require(self.state != 'exited', 'RT_CAPI_POSTEXIT_OWNER')
            if identity not in self.owner_leases:self.owner_leases[identity] = {'refs': 0, 'destructor': destructor}
            require(self.owner_leases[identity]['destructor'] is destructor, 'RT_CAPI_OWNER_IDENTITY')
            self.owner_leases[identity]['refs'] += 1

    def release_owner(self, identity):
        # Nonblocking release is valid even from host callback dynamic extent.
        with self.condition:
            require(identity in self.owner_leases and self.owner_leases[identity]['refs'] > 0, 'RT_CAPI_OWNER_REPLAY')
            fact = self.owner_leases[identity]
            fact['refs'] -= 1
            if fact['refs'] == 0:
                self.cleanup_queue.append(fact['destructor'])
                del self.owner_leases[identity]
            self.condition.notify_all()

    def _publish_exit(self):
        if self.state == 'closing' and not self.owner_leases and not self.cleanup_queue and not self.cleanup_running and all(
                t['state'] in {'exited', 'failed'} for t in self.threads.values()):
            self.state = 'exited'
            self.exit_publications += 1

    def join(self):
        guest_entry_allowed(self.context)
        with self.condition:
            if not self.image and self.state == 'active':self.state = 'closing'
            self._publish_exit()
            return self.state

    def drive_cleanup(self):
        """Derivative guest cleanup runs before terminal exit, never on host stack."""
        guest_entry_allowed(self.context)
        with self.condition:
            require(self.state != 'exited', 'RT_CAPI_POSTEXIT_CLEANUP')
            if not self.cleanup_queue:return False
            cleanup = self.cleanup_queue.pop(0)
            self.cleanup_running += 1
        try:cleanup()
        finally:
            with self.condition:
                self.cleanup_running -= 1
                self._publish_exit()
                self.condition.notify_all()
        return True

    def finalize(self):
        with self.condition:require(self.state == 'exited', 'RT_CAPI_FINALIZE_EBUSY')
