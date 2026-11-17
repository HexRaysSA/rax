"""Authoritative process-domain reservation model for concurrent module admission."""
from threading import Lock

from .errors import require


class ProcessAdmission:
    """Atomic pin-before-constructor, later external publication; O(new modules).

    Full verifier produces plan before this state machine. The lock is an admission
    lock, never held over constructors or cleanup. Failed initialization retains
    pinned ISA, since a native entry/checkpoint may already have occurred.
    """
    def __init__(self, personality):
        require(personality in {'linux','darwin','windows'},'RT_PROCESS_PERSONALITY')
        self.personality = personality
        self.foreign_isa = 'none'
        self.epoch = 0
        self.modules = {}
        self._lock = Lock()

    def snapshot(self):
        with self._lock:
            return {'epoch': self.epoch, 'personality': self.personality,
                    'foreign_isa': self.foreign_isa}

    def commit(self, plan, expected_epoch, initialize):
        with self._lock:
            require(plan['personality'] == self.personality, 'RT_PROCESS_PERSONALITY')
            selected = plan['foreign_isa']
            require(selected in {'none','x86_64','aarch64'} and
                    (self.foreign_isa == 'none' or selected in {'none',self.foreign_isa}),
                    'RT_PROCESS_ISA')
            require(self.epoch == expected_epoch, 'RT_ADMISSION_RETRY')
            fresh = [a for a in plan['order'] if a not in self.modules]
            require(all(self.modules.get(a) == 'live' for a in plan['order'] if a not in fresh),
                    'RT_MODULE_NOT_LIVE')
            if selected != 'none':
                self.foreign_isa = selected
            self.epoch += 1
            for artifact in fresh:
                self.modules[artifact] = 'initializing'
        # A reservation can be observed for BUSY/retry, never called as live code.
        completed = []
        try:
            for group in plan['components']:
                for artifact in group:
                    if artifact in fresh:
                        initialize(artifact)
                        completed.append(artifact)
        except BaseException:
            with self._lock:
                for artifact in fresh:
                    self.modules[artifact] = 'failed_pinned'
                self.epoch += 1
            # Typed per-program cleanup is executed by initialize transaction;
            # this state machine never guesses which source objects committed.
            raise
        with self._lock:
            for artifact in fresh:
                self.modules[artifact] = 'live'
            self.epoch += 1
        return tuple(completed)
