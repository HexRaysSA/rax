"""Process-owned completed-object facts and atomic fresh-destructor claims.

Only trusted transitions populate this registry. Snapshot bytes can describe
these facts but cannot create an object, lease, live child, or destruction claim.
"""
from copy import deepcopy
from threading import RLock

from .errors import option, require, some, unique
from .wire import validate_shape


class Registry:
    def __init__(self, objects, program, leases, *, capture_check=None):
        self.objects, self.program, self.leases = objects, program, leases
        self.items = {}
        self.next_id = 1
        self.lock = RLock()
        self.forward = {}
        self.ended_owners={}
        self.capture_check=capture_check

    def _storage(self, certificate):
        obj = self.objects.get(certificate['object'])
        require(obj is not None and obj['live'] and obj['generation'] == certificate['object_generation'] and
                0 < obj['address'] <= certificate['address'] < obj['address'] + obj['size'] <= 2**64-1,
                'RT_LIFETIME_STORAGE')
        for lease in certificate['leases']:
            require(lease in self.leases and self.leases[lease]['live'], 'RT_LIFETIME_LEASE')
        return obj

    def _children(self, certificate, definition):
        slots = unique(definition['slots'], 'id')
        for entry in certificate['subobjects']:
            child = option(entry['child'])
            descriptor = slots[entry['slot']]
            expected = option(descriptor['child_program'])
            require((child is None) == (expected is None), 'RT_LIFETIME_CHILD')
            if child is None:continue
            other = self.items.get(child)
            require(other is not None and other['phase'] == 'alive' and other['claim'] is None and
                    other['object'] == certificate['object'] and
                    other['object_generation'] == certificate['object_generation'] and
                    other['address'] == certificate['address'] + descriptor['offset'] + entry['element']*descriptor['stride'] and
                    self.program(other['module'], other['program'])[0] ==
                    self.program(certificate['module'], expected)[0], 'RT_LIFETIME_CHILD')

    def publish(self, state, current_subobjects):
        """Consume replay-validated constructor state + CURRENT trusted child facts.

        current_subobjects maps (slot,element) -> {lifetime,child}. An explicitly
        ended member is absent; completed construction history cannot revive it.
        O(slots + live children), excluding already-verified constructor replay.
        """
        with self.lock:
            document, definition = state['document'], state['definition']
            require(document['state']['stage'] == 'alive' and document['seed'] is None,
                    'RT_LIFETIME_PUBLICATION')
            require(not document['captures'] or self.capture_check is not None,'RT_LIFETIME_CAPTURES')
            if self.capture_check is not None:self.capture_check(document)
            certificate = {'id': self.next_id, 'revision': 1, 'module': document['module'],
                'module_generation': document['module_generation'], 'object': document['object'],
                'object_generation': document['object_generation'], 'address': document['object_address'],
                'program': deepcopy(document['program']), 'counts': deepcopy(document['counts']),
                'captures': deepcopy(document['captures']), 'subobjects': [], 'phase': 'alive',
                'claim': None, 'owner': None, 'leases': list(document['leases'])}
            self._storage(certificate)
            descendants = set()
            pending = [option(c['child']) for c in current_subobjects.values() if c['child'] is not None]
            while pending:
                child = pending.pop()
                require(child in self.items, 'RT_LIFETIME_CHILD')
                if child in descendants:continue
                descendants.add(child)
                pending.extend(option(e['child']) for e in self.items[child]['subobjects'] if e['child'] is not None)
            require(not any(c['id'] not in descendants and c['phase'] != 'dead' and
                    (c['object'], c['object_generation'], c['address']) ==
                    (certificate['object'], certificate['object_generation'], certificate['address'])
                    for c in self.items.values()), 'RT_LIFETIME_DUPLICATE')
            schedule = definition['normal_order']
            counts = {c['slot']: c['count'] for c in certificate['counts']}
            # Reverse schedule gives construction ordinals, stable across later
            # placement construction. Array elements destroy highest index first.
            ordinals, ordinal = {}, 0
            for slot in reversed(schedule):
                for element in range(counts[slot]):
                    ordinal += 1
                    ordinals[slot, element] = ordinal
            for key, current in sorted(current_subobjects.items()):
                require(key in state['cells'] and state['cells'][key]['phase'] == 'alive' and
                        key in ordinals and type(current['lifetime']) is int and current['lifetime'] > 0,
                        'RT_LIFETIME_SUBOBJECT')
                certificate['subobjects'].append({'slot': key[0], 'element': key[1],
                    'lifetime': current['lifetime'], 'ordinal': ordinals[key], 'child': current['child']})
            self._children(certificate, definition)
            for entry in certificate['subobjects']:
                child=option(entry['child'])
                if child is not None:
                    require(self.items[child]['owner'] is None and self.items[child]['revision']<2**64-1,
                            'RT_LIFETIME_CHILD_OWNED')
            validate_shape('runtime_object_lifetime', certificate)
            require(self.next_id < 2**64-1, 'RT_LIFETIME_RESOURCE')
            self.next_id += 1
            self.items[certificate['id']] = certificate
            for entry in certificate['subobjects']:
                child=option(entry['child'])
                if child is not None:
                    self.items[child]['owner']=some({'kind':'object','id':certificate['id'],
                        'slot':entry['slot'],'element':entry['element']})
                    self.items[child]['revision']+=1
            # Consuming the actual runtime constructor instance prevents replay.
            document['state']['stage'] = 'published'
            return deepcopy(certificate)

    def claim(self, identifier, revision, owner, *, parent_owner=None):
        """Lifetime ends at destructor START; claim is an exclusive owner capability."""
        with self.lock:
            current = self.items.get(identifier)
            require(current is not None and current['revision'] == revision, 'RT_LIFETIME_STALE')
            from .partials import owner_valid
            owner_valid(owner)
            require(current['phase'] == 'alive' and current['claim'] is None,
                    'RT_LIFETIME_CLAIM')
            link=option(current['owner'])
            if link is not None:
                outer=self.items.get(link['id']) if link['kind']=='object' else None
                require(outer is not None and outer['phase']=='destroying' and
                        option(outer['claim'])==parent_owner and parent_owner is not None and
                        parent_owner['thread']==owner['thread'],'RT_LIFETIME_CHILD_OWNED')
            self._storage(current)
            _, definition = self.program(current['module'], current['program'])
            self._children(current, definition)
            present = {(e['slot'], e['element']) for e in current['subobjects']}
            counts = {e['slot']: e['count'] for e in current['counts']}
            for slot in definition['slots']:
                if slot['role'] != 'union_member' and (slot['destructor'] is not None or slot['child_program'] is not None):
                    require(all((slot['id'], e) in present for e in range(counts[slot['id']])),
                            'RT_LIFETIME_DEAD_REQUIRED_CHILD')
            current.update(phase='destroying', claim=some(deepcopy(owner)))
            return deepcopy(current)

    def finish(self, state):
        with self.lock:
            document = state['document']
            seed = option(document['seed'])
            require(seed is not None and seed['kind']=='object', 'RT_LIFETIME_SEED')
            current = self.items.get(seed['certificate'])
            require(current is not None and current['revision'] == seed['revision'] and
                    current['phase'] == 'destroying' and option(current['claim']) == journal_owner(document),
                    'RT_LIFETIME_STALE')
            require(document['state']['stage'] == 'destroyed' and all(
                c['phase'] in {'empty', 'failed', 'destroyed'} for c in state['cells'].values()),
                'RT_LIFETIME_CLEANUP_PENDING')
            require(current['revision'] < 2**64-1, 'RT_LIFETIME_RESOURCE')
            current.update(phase='dead', claim=None, revision=current['revision']+1)
            return deepcopy(current)

    def claim_source(self,module,program,pointer,owner):
        """Actual explicit destructor route: resolve CURRENT typed source pointer.

        This is a trusted source-instruction transition, never snapshot restore.
        Detach current ownership at destructor start; completion history stays.
        """
        with self.lock:
            from .partials import owner_valid
            owner_valid(owner)
            require(getattr(pointer,'domain',None)=='data','RT_LIFETIME_SOURCE_POINTER')
            matches=[c for c in self.items.values() if c['phase']=='alive' and c['claim'] is None and
                (c['object'],c['object_generation'],c['address'])==(pointer.origin,pointer.generation,pointer.address)
                and self.program(c['module'],c['program'])[0]==self.program(module,program)[0]]
            require(len(matches)==1,'RT_LIFETIME_SOURCE_POINTER')
            child=matches[0];self._storage(child)
            _,definition=self.program(child['module'],child['program']);self._children(child,definition)
            link=option(child['owner'])
            if link is not None:
                table=self.items if link['kind']=='object' else self.partials.items
                parent=table.get(link['id'])
                require(parent is not None and parent['phase'] in {'alive','partial','owned'} and
                        parent['revision']<2**64-1 and child['revision']<2**64-1,'RT_LIFETIME_SOURCE_OWNER')
                current=parent['subobjects'] if link['kind']=='object' else parent['current']
                entries=[e for e in current if (e['slot'],e['element'],option(e['child']))==
                         (link['slot'],link['element'],child['id'])]
                require(len(entries)==1,'RT_LIFETIME_SOURCE_OWNER')
                self.ended_owners[child['id']]=(deepcopy(link),deepcopy(entries[0]))
                current.remove(entries[0]);parent['revision']+=1
                child['owner']=None;child['revision']+=1
            return self.claim(child['id'],child['revision'],owner)

    def replace_source(self,old_identifier,new_identifier,*,transparent=False,same_type=False,
                       complete_const=False,overlapping=True,parents_eligible=False):
        """Trusted completed placement construction rejoins the CURRENT owner graph."""
        with self.lock:
            old=self.items.get(old_identifier);new=self.items.get(new_identifier)
            require(old is not None and new is not None and old['phase']=='dead' and new['phase']=='alive' and
                    new['claim'] is None and new['owner'] is None and old_identifier in self.ended_owners and
                    (old['object'],old['object_generation'],old['address'])==
                    (new['object'],new['object_generation'],new['address']) and
                    self.program(old['module'],old['program'])[0]==self.program(new['module'],new['program'])[0],
                    'RT_LIFETIME_SOURCE_REPLACEMENT')
            if transparent:
                require(same_type and not complete_const and not overlapping and parents_eligible,
                        'RT_LIFETIME_NOT_TRANSPARENT')
            link,entry=self.ended_owners[old_identifier]
            table=self.items if link['kind']=='object' else self.partials.items
            parent=table[link['id']];current=parent['subobjects'] if link['kind']=='object' else parent['current']
            require(parent['phase'] in {'alive','partial','owned'} and parent['revision']<2**64-1 and
                    new['revision']<2**64-1 and entry['lifetime']<2**64-1 and
                    not any((e['slot'],e['element'])==(entry['slot'],entry['element']) for e in current),
                    'RT_LIFETIME_SOURCE_REPLACEMENT')
            replacement={**entry,'lifetime':entry['lifetime']+1,'child':some(new_identifier)}
            current.append(replacement);current.sort(key=lambda e:(e['slot'],e['element']))
            parent['revision']+=1;new['owner']=some(deepcopy(link));new['revision']+=1
            if transparent:self.forward[entry['lifetime']]=replacement['lifetime']
            del self.ended_owners[old_identifier]
            return deepcopy(new)

    def replace(self, identifier, revision, slot, element, lifetime, *, transparent=False,
                same_type=False, complete_const=False, overlapping=True, parents_eligible=False,
                child=None):
        """Trusted source placement transition; alias forwarding only [basic.life].

        complete_const refers to the ORIGINAL complete object. overlapping covers
        base/no_unique_address subobjects. Nontransparent aliases need a current
        lifetime/launder proof; pointer numbers alone do not update a certificate.
        """
        with self.lock:
            current = self.items.get(identifier)
            require(current is not None and current['revision'] == revision, 'RT_LIFETIME_STALE')
            require(current['phase'] == 'alive' and current['claim'] is None, 'RT_LIFETIME_CLAIM')
            self._storage(current)
            matches = [e for e in current['subobjects'] if (e['slot'], e['element']) == (slot, element)]
            require(len(matches) == 1 and type(lifetime) is int and lifetime > matches[0]['lifetime'],
                    'RT_LIFETIME_SUBOBJECT')
            if transparent:
                require(same_type and not complete_const and not overlapping and parents_eligible,
                        'RT_LIFETIME_NOT_TRANSPARENT')
                self.forward[matches[0]['lifetime']] = lifetime
            matches[0].update(lifetime=lifetime, child=child)
            require(current['revision'] < 2**64-1, 'RT_LIFETIME_RESOURCE')
            current['revision'] += 1
            return deepcopy(current)

    def snapshots(self):
        with self.lock:return deepcopy(self.items)


def journal_owner(document):
    return {key:document['state'][key] for key in ('thread','activation','generation')}|{'instance':document['id']}


def seed_cells(document, cells, facts, partials=None):
    seed = option(document['seed'])
    if seed is None:return 0, 'constructing'
    partial=seed['kind']=='partial'
    current = (partials or {}).get(seed['builder']) if partial else facts.get(seed['certificate'])
    require(current is not None and current['revision'] == seed['revision'] and
            current['phase'] in ({'owned','cleanup'} if partial else {'destroying'}) and
            option(current['claim']) == journal_owner(document), 'RT_LIFETIME_SEED')
    for before, after in [('module','module'), ('module_generation','module_generation'),
                          ('object','object'), ('object_generation','object_generation'),
                          ('address','object_address'), ('program','program'), ('counts','counts'), ('captures','captures')]:
        require(current[before] == document[after], 'RT_LIFETIME_SEED_OWNER')
    seen = set()
    for entry in current['current'] if partial else current['subobjects']:
        key = entry['slot'], entry['element']
        require(key in cells and key not in seen and entry['ordinal'] > 0, 'RT_LIFETIME_SUBOBJECT')
        seen.add(key)
        cells[key].update(phase='alive', ordinal=entry['ordinal'])
    entries=current['current'] if partial else current['subobjects']
    require(len({entry['ordinal'] for entry in entries}) == len(seen),
            'RT_LIFETIME_SUBOBJECT')
    completed=current['completed'] if partial else entries
    return max((e['ordinal'] for e in completed), default=0), (
        'unwinding' if partial and current['phase']=='cleanup' else 'constructing' if partial else 'alive')
