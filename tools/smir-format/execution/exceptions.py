"""Logical two-phase exception protocol witness, with no native unwinding.

An exception lease and compiler-supplied dynamic frame descriptors are explicit
inputs. Exact identity match is the only typed-catch relation implemented here.
No Python/Rust/host exception is used as a guest exception or native personality.
"""
import json

from common import Limits, check_shape, require


def verify_protocol(document, limits=Limits()):
    check_shape('exception_protocol', document, limits)
    require(document['revision'] == 'exception_flow_draft_v1', 'eh_revision')
    require(document['thread'] > 0 and document['lease'] > 0, 'eh_identity', 'thread and lease')
    require(len(document['type_identity']) == 64, 'eh_identity', '256-bit type identity')
    activations = set()
    foreign_domains = set()
    for frame in document['frames']:
        require(frame['activation'] > 0 and frame['activation'] not in activations,
                'eh_identity', 'unique activation')
        activations.add(frame['activation'])
        require(frame['thread'] == document['thread'], 'eh_thread')
        require(len(frame['module']) == 64 and frame['generation'] > 0, 'eh_identity', 'module lease')
        require(frame['domain'] in {'portable', 'x86_64', 'aarch64'}, 'eh_domain')
        if frame['domain'] != 'portable':
            foreign_domains.add(frame['domain'])
            require(len(foreign_domains) <= 1, 'eh_domain', 'one foreign ISA per process')
        require(frame['escape'] in {'may_unwind', 'terminate'}, 'eh_escape')
        cleanup_ids = [cleanup['id'] for cleanup in frame['cleanup']]
        require(len(cleanup_ids) == len(set(cleanup_ids)), 'eh_cleanup', 'duplicate cleanup')
        catch_all = False
        for handler in frame['handlers']:
            require(not catch_all, 'eh_handler', 'handler after catch-all')
            if handler['kind'] == 'typed':
                require(len(handler['type_identity']) == 64, 'eh_identity', 'catch type')
            else:
                catch_all = True
            identifiers = [cleanup['id'] for cleanup in handler['cleanup']]
            require(len(identifiers) == len(set(identifiers)), 'eh_cleanup', 'handler cleanup path')
    return document


def plan(document, limits=Limits()):
    """Search without effects, then plan cleanup and one handler installation.

    The outermost frame is first. A terminate boundary is a search barrier: if
    no inner handler matches, terminate is selected without first cleaning
    frames. Uncaught exceptions likewise terminate without claiming destructor
    execution. A personality implementation must later implement this protocol.
    """
    verify_protocol(document, limits)
    events = []
    selected = None
    for frame in reversed(document['frames']):
        activation = frame['activation']
        events.append({'phase': 'search', 'activation': activation})
        for handler in frame['handlers']:
            if handler['kind'] == 'catch_all' or handler['type_identity'] == document['type_identity']:
                selected = (frame, handler)
                break
        if selected:
            break
        if frame['escape'] == 'terminate':
            events.append({'phase': 'terminate', 'reason': 'noexcept', 'activation': activation})
            return events
    if selected is None:
        events.append({'phase': 'terminate', 'reason': 'uncaught'})
        return events
    selected_frame, handler = selected
    for frame in reversed(document['frames']):
        path = handler['cleanup'] if frame is selected_frame else frame['cleanup']
        for cleanup in path:
            events.append({'phase': 'cleanup', 'activation': frame['activation'],
                           'cleanup': cleanup['id'], 'entry': cleanup['entry']})
        if frame is selected_frame:
            events.append({'phase': 'install', 'activation': frame['activation'],
                           'entry': handler['entry'], 'lease': document['lease']})
            return events
    raise ValueError('internal selected frame not found')


class Protocol:
    """Execute a planned logical event sequence once; reject replay and mismatch."""

    def __init__(self, document):
        self.events = plan(document)
        self._expected = [json.dumps(event, sort_keys=True) for event in self.events]
        self.lease = document['lease']
        self.type_identity = document['type_identity']
        self.position = 0
        self.caught = False
        self.released = False

    def commit(self, event):
        require(not self.released and self.position < len(self._expected), 'eh_replay')
        require(json.dumps(event, sort_keys=True) == self._expected[self.position],
                'eh_progress', 'phase/continuation mismatch')
        if event['phase'] == 'install':
            self.caught = True
        self.position += 1

    def cleanup_throws(self):
        require(self.position < len(self._expected)
                and json.loads(self._expected[self.position])['phase'] == 'cleanup',
                'eh_progress', 'not at cleanup')
        # Throw during active unwinding terminates; it cannot continue installing
        # the earlier selected handler or accidentally repeat prior cleanups.
        self.events = ([json.loads(event) for event in self._expected[:self.position]]
                       + [{'phase': 'terminate', 'reason': 'double_exception'}])
        self._expected = [json.dumps(event, sort_keys=True) for event in self.events]

    def release(self):
        require(self.position == len(self._expected) and self.caught and not self.released,
                'eh_release', 'catch not completed or already released')
        self.released = True

    def rethrow(self, document):
        require(self.position == len(self._expected) and self.caught and not self.released,
                'eh_rethrow', 'no active catch')
        require(document.get('lease') == self.lease and document.get('type_identity') == self.type_identity,
                'eh_identity', 'rethrow must preserve exception identity')
        continuation = Protocol(document)
        self.released = True
        return continuation
