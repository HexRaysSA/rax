"""Private-E / process-owner-proxy protocol oracle, R035 REV3.

No native unwind, guest execution, or typed construction is inferred from bytes.
Trusted factories supply admitted object/type/destructor/completion/code facts.
"""
from dataclasses import dataclass
from threading import Lock
import struct

from .errors import require


@dataclass(frozen=True)
class Pointer:
    process: int
    object: int
    generation: int
    address: int
    role: str


@dataclass(frozen=True)
class Facade:
    process: int
    identity: int
    thread: int


@dataclass
class Cleanup:
    identity: int
    payload: int
    state: str = 'prepared'


class Raised(Exception):
    def __init__(self, facade):
        self.facade = facade


class Registry:
    def __init__(self, process, objects, code_check, completion_check, default_handler):
        self.process, self.objects = process, objects
        self.code_check, self.completion_check = code_check, completion_check
        self.lock = Lock()
        self.payloads, self.facades, self.proxies, self.threads = {}, {}, {}, {}
        self.cleanups, self.next_id = {}, 1
        require(code_check(default_handler), 'RT_EH_TERMINATE_SIGNATURE')
        self.handler = default_handler
        self.aborted = False

    def _id(self):
        require(self.next_id < 2**64-1, 'RT_EH_RESOURCE')
        result = self.next_id
        self.next_id += 1
        return result

    def _thread(self, thread):
        require(type(thread) is int and thread > 0, 'RT_EH_THREAD')
        return self.threads.setdefault(thread, {'uncaught': 0, 'catches': [], 'terminating': False})

    def _facade(self, facade, thread):
        require(isinstance(facade, Facade) and facade.process == self.process and facade.thread == thread,
                'RT_EH_FACADE_OWNER')
        fact = self.facades.get(facade.identity)
        require(fact is not None and fact['thread'] == thread and fact['refs'] > 0 and
                self.payloads[fact['payload']]['state'] != 'dead',
                'RT_EH_STALE_FACADE')
        return fact

    def _pointer(self, pointer):
        require(isinstance(pointer, Pointer) and pointer.process == self.process and pointer.role == 'owner',
                'RT_EH_OWNER_POINTER')
        owner = self.proxies.get(pointer.object)
        obj = self.objects.get(pointer.object)
        require(owner is not None and obj is not None and obj['live'] and
                (pointer.generation, pointer.address) == (obj['generation'], obj['address']) and
                owner['pointer'] == pointer and self.payloads[owner['payload']]['state'] not in {'retiring', 'dead'},
                'RT_EH_OWNER_POINTER')
        return self.payloads[owner['payload']]

    def allocate(self, thread, *, object_id, nominal, destructor, proxy_object):
        with self.lock:
            obj, proxy = self.objects[object_id], self.objects[proxy_object]
            require(obj['live'] and obj['address'] > 0 and obj['address']+obj['size'] <= 2**64-1 and
                    obj['address'] % obj['alignment'] == 0 and proxy['live'] and proxy['size'] == 32 and
                    proxy['alignment'] >= 8 and proxy['address'] % 8 == 0 and proxy_object not in self.proxies,
                    'RT_EH_ALLOCATION')
            identity, facade_id = self._id(), self._id()
            pointer = Pointer(self.process, proxy_object, proxy['generation'], proxy['address'], 'owner')
            payload = {'id': identity, 'object': object_id, 'nominal': nominal, 'destructor': destructor,
                       'state': 'allocated', 'owner_refs': 0, 'facade_refs': 1, 'destructor_entries': 0,
                       'proxy': pointer, 'ever_raised': False}
            self.payloads[identity] = payload
            self.proxies[proxy_object] = {'payload': identity, 'pointer': pointer,
                'header': struct.pack('<IIQQQ', 1, 0, self._id(), identity, proxy['generation'])}
            self.facades[facade_id] = {'payload': identity, 'thread': thread, 'phase': 'allocated',
                                      'refs': 1, 'counted': False, 'handler': None, 'adjusted': None}
            self._thread(thread)
            return Facade(self.process, facade_id, thread)

    def object_address(self, facade, thread):
        with self.lock:
            fact = self._facade(facade, thread)
            obj = self.objects[self.payloads[fact['payload']]['object']]
            require(obj['live'], 'RT_EH_PAYLOAD_DEAD')
            return Pointer(self.process, self.payloads[fact['payload']]['object'], obj['generation'], obj['address'], 'payload')

    def complete_construction(self, facade, thread, certificate):
        with self.lock:
            fact = self._facade(facade, thread)
            payload = self.payloads[fact['payload']]
            require(payload['state'] == 'allocated' and self.completion_check(payload, certificate),
                    'RT_EH_CONSTRUCTION_CERTIFICATE')
            payload['state'] = 'constructed'

    def _propagate(self, fact, thread):
        local = self._thread(thread)
        require(local['uncaught'] < 2**31-1, 'RT_EH_RESOURCE')
        require(not fact['counted'], 'RT_EH_REPLAY')
        fact.update(phase='propagating', counted=True, handler=self.handler, adjusted=None)
        local['uncaught'] += 1

    def raise_initial(self, facade, thread):
        with self.lock:
            fact = self._facade(facade, thread)
            payload = self.payloads[fact['payload']]
            require(payload['state'] == 'constructed' and not payload['ever_raised'] and fact['phase'] == 'allocated',
                    'RT_EH_THROW_STATE')
            self._propagate(fact, thread)
            payload['ever_raised'] = True
            return facade  # Represents ONLY the invoke unwind edge, never a normal result.

    def select_catch(self, facade, thread, adjusted):
        with self.lock:
            fact = self._facade(facade, thread)
            require(fact['phase'] == 'propagating' and isinstance(adjusted, Pointer) and
                    adjusted.process == self.process, 'RT_EH_CATCH_SELECTION')
            # Actual RTTI/recipe validator supplies the adjusted pointer proof.
            obj = self.objects.get(adjusted.object)
            require(obj is not None and obj['live'] and obj['generation'] == adjusted.generation and
                    obj['address'] <= adjusted.address <= obj['address']+obj['size'], 'RT_EH_CATCH_SELECTION')
            fact['adjusted'] = adjusted

    def catch_object(self, facade, thread):
        with self.lock:
            fact = self._facade(facade, thread)
            require(fact['phase'] in {'propagating', 'caught'} and fact['adjusted'] is not None,
                    'RT_EH_CATCH_SELECTION')
            return fact['adjusted']  # No copy, begin-catch, refcount, or fenv transition.

    def begin_catch(self, facade, thread):
        with self.lock:
            fact = self._facade(facade, thread)
            require(fact['phase'] == 'propagating' and fact['adjusted'] is not None, 'RT_EH_CATCH_STATE')
            local = self._thread(thread)
            require(fact['counted'] and local['uncaught'] > 0, 'RT_EH_COUNT')
            local['uncaught'] -= 1
            fact.update(phase='caught', counted=False)
            local['catches'].append(facade.identity)
            return fact['adjusted']

    def current_owner(self, thread):
        with self.lock:
            catches = self._thread(thread)['catches']
            if not catches:return None
            payload = self.payloads[self.facades[catches[-1]]['payload']]
            require(payload['owner_refs'] < 2**64-1, 'RT_EH_RESOURCE')
            payload['owner_refs'] += 1
            return payload['proxy']

    def owner_retain(self, pointer):
        if pointer is None:return
        with self.lock:
            payload = self._pointer(pointer)
            require(payload['owner_refs'] > 0 and payload['owner_refs'] < 2**64-1, 'RT_EH_OWNER_REFS')
            payload['owner_refs'] += 1

    def _retire(self, payload):
        if payload['owner_refs'] or payload['facade_refs']:return None
        require(payload['state'] in {'allocated', 'constructed'}, 'RT_EH_REPLAY')
        if payload['state'] == 'allocated':
            payload['state'] = 'dead'
            return None  # Failed initial construction never invokes complete T destructor.
        payload['state'] = 'retiring'
        cleanup = Cleanup(self._id(), payload['id'])
        self.cleanups[cleanup.identity] = cleanup
        return cleanup

    def owner_release(self, pointer):
        if pointer is None:return None
        with self.lock:
            payload = self._pointer(pointer)
            require(payload['owner_refs'] > 0, 'RT_EH_OWNER_REFS')
            payload['owner_refs'] -= 1
            return self._retire(payload)

    def release(self, facade, thread):
        with self.lock:
            fact = self._facade(facade, thread)
            require(fact['phase'] in {'allocated', 'retained'}, 'RT_EH_RELEASE_STATE')
            fact['refs'] -= 1
            payload = self.payloads[fact['payload']]
            payload['facade_refs'] -= 1
            return self._retire(payload)

    def end_catch(self, facade, thread):
        with self.lock:
            fact = self._facade(facade, thread)
            local = self._thread(thread)
            require(fact['phase'] == 'caught' and local['catches'] and local['catches'][-1] == facade.identity,
                    'RT_EH_CATCH_STATE')
            local['catches'].pop()
            fact.update(phase='retained')
        return self.release(facade, thread)

    def owner_rethrow(self, pointer, thread):
        with self.lock:
            payload = self._pointer(pointer)
            require(payload['state'] == 'constructed' and payload['owner_refs'] > 0, 'RT_EH_RETHROW_STATE')
            identity = self._id()
            fact = {'payload': payload['id'], 'thread': thread, 'phase': 'retained', 'refs': 1,
                    'counted': False, 'handler': None, 'adjusted': None}
            self._propagate(fact, thread)
            self.facades[identity] = fact
            payload['facade_refs'] += 1
            return Facade(self.process, identity, thread)  # unwind edge only

    def uncaught(self, thread):
        with self.lock:return self._thread(thread)['uncaught']

    def rethrow_current(self, thread, handler_call):
        with self.lock:
            catches = self._thread(thread)['catches']
            if catches:
                old = self.facades[catches[-1]]
                require(old['phase'] == 'caught', 'RT_EH_CATCH_STATE')
                identity = self._id()
                fact = {'payload': old['payload'], 'thread': thread, 'phase': 'retained', 'refs': 1,
                        'counted': False, 'handler': None, 'adjusted': None}
                self._propagate(fact, thread)
                fact['handler'] = old['handler']
                self.facades[identity] = fact
                self.payloads[old['payload']]['facade_refs'] += 1
                return Facade(self.process, identity, thread)
        self.terminate(thread, handler_call)
        return None  # Terminal, never a normal helper result.

    def set_terminate(self, token):
        require(self.code_check(token), 'RT_EH_TERMINATE_SIGNATURE')
        with self.lock:
            previous, self.handler = self.handler, token
            return previous

    def get_terminate(self):
        with self.lock:return self.handler

    def terminate(self, thread, handler_call, *, cause=None):
        """Dispatch outside lock. Always terminal; return/throw -> immediate abort."""
        with self.lock:
            local = self._thread(thread)
            require(not local['terminating'], 'RT_EH_RECURSIVE_TERMINATE')
            token = (self.facades[local['catches'][-1]]['handler'] if local['catches'] else self.handler)
            if cause is not None:
                fact = self._facade(cause, thread)
                token = fact['handler']
                require(fact['phase'] == 'propagating' and fact['counted'], 'RT_EH_TERMINATE_CAUSE')
                fact.update(phase='caught', counted=False)
                local['uncaught'] -= 1
                local['catches'].append(cause.identity)
            local['terminating'] = True
        try:handler_call(token)
        except Exception:pass
        finally:
            with self.lock:self.aborted = True

    def begin_cleanup(self, cleanup):
        with self.lock:
            require(self.cleanups.get(cleanup.identity) is cleanup and cleanup.state == 'prepared', 'RT_EH_CLEANUP_REPLAY')
            payload = self.payloads[cleanup.payload]
            require(payload['state'] == 'retiring' and payload['destructor_entries'] == 0, 'RT_EH_CLEANUP_REPLAY')
            cleanup.state = 'running'
            payload['destructor_entries'] += 1
            return payload['destructor']

    def finish_cleanup(self, cleanup, *, aborted=False):
        with self.lock:
            require(self.cleanups.get(cleanup.identity) is cleanup and cleanup.state == 'running',
                    'RT_EH_CLEANUP_REPLAY')
            if aborted:self.aborted = True
            cleanup.state = 'completed'
            self.payloads[cleanup.payload]['state'] = 'dead'

    def run_cleanup(self, cleanup, destructor_call, *, thread=None, handler_call=None):
        destructor = self.begin_cleanup(cleanup)
        raised = False
        try:destructor_call(destructor)
        except Raised as failure:
            require(thread is not None and handler_call is not None, 'RT_EH_TERMINATE_CONTEXT')
            self.terminate(thread, handler_call, cause=failure.facade)
            raised = True
        except Exception:
            # Host-language callback boundary failure; this is not a guest C++
            # exception and cannot be mistaken for typed source termination.
            raised = True
        self.finish_cleanup(cleanup, aborted=raised)
        return raised


class OwnerValue:
    """Source exception_ptr's one pointer field; move/copy/swap need no E memory."""
    def __init__(self, registry, pointer=None):
        self.registry, self.pointer = registry, pointer

    def copy_from(self, source):
        require(source.registry is self.registry, 'RT_EH_OWNER_PROCESS')
        new = source.pointer
        self.registry.owner_retain(new)
        old, self.pointer = self.pointer, new
        return self.registry.owner_release(old)

    def move_from(self, source):
        require(source.registry is self.registry, 'RT_EH_OWNER_PROCESS')
        new, source.pointer = source.pointer, None
        old, self.pointer = self.pointer, new
        return self.registry.owner_release(old)

    def swap(self, source):
        require(source.registry is self.registry, 'RT_EH_OWNER_PROCESS')
        self.pointer, source.pointer = source.pointer, self.pointer

    def release(self):
        old, self.pointer = self.pointer, None
        return self.registry.owner_release(old)
