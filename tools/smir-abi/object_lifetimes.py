"""Independent R029 draft: completed objects, fresh destructor journals.

Sequential transitions plus an atomic registry claim; no guest code is executed.
Object/lifetime/module facts are supplied by the caller's admitted registry, never
read from an untrusted snapshot as authorization. Nested child certificates are
validated by the runtime owner; this reference exercises flat source objects.
"""
from copy import deepcopy
from threading import Lock

from construction import ConstructionJournal
from layout import require


class CompletedObjects:
    def __init__(self, object_fact):
        self.object_fact=object_fact
        self.lock=Lock()
        self.next_id=1
        self.items={}

    def _object(self,object_id,generation,address):
        fact=self.object_fact(object_id)
        require(fact['live'] and fact['generation']==generation and fact['base']<=address<fact['base']+fact['size'],
                'ABI_CC_OBJECT_LIFETIME')
        require(fact['base']>0 and fact['base']+fact['size']<1<<64,'ABI_CC_SOURCE_ONEPAST')
        return fact

    def publish(self,journal,*,object_id,generation,address,module,module_generation,program,leases,lifetimes):
        with self.lock:
            require(journal.stage=='alive','ABI_CC_OBJECT_PUBLICATION')
            fact=self._object(object_id,generation,address)
            require(not journal.children,'ABI_CC_OBJECT_REFERENCE_NESTED_CERTIFICATE')
            subobjects=[]
            for (slot,element),state in journal.states.items():
                if state['phase']!='alive':
                    continue
                descriptor=journal.slots[slot]
                end=address+descriptor['offset']+element*descriptor['stride']+descriptor['stride']
                require(end<=fact['base']+fact['size'],'ABI_CC_OBJECT_EXTENT')
                lifetime=lifetimes.get((slot,element))
                if lifetime is None:
                    # Constructor completion is historical. Its body can have
                    # explicitly ended a member's lifetime before publication.
                    continue
                require(type(lifetime) is int and lifetime>0,'ABI_CC_SUBOBJECT_LIFETIME')
                subobjects.append({'slot':slot,'element':element,'lifetime':lifetime,
                                   'ordinal':state['ordinal'],'child':None})
            require(not any(item['phase']!='dead' and (item['object'],item['object_generation'],item['address'])==
                    (object_id,generation,address) for item in self.items.values()),'ABI_CC_OBJECT_ALREADY_PUBLISHED')
            identifier=self.next_id;self.next_id+=1
            require(identifier<1<<64,'ABI_CC_OBJECT_RESOURCE')
            certificate={'id':identifier,'revision':1,'module':module,'module_generation':module_generation,
                'object':object_id,'object_generation':generation,'address':address,'program':deepcopy(program),
                'counts':[{'slot':slot,'count':count} for slot,count in journal.counts.items()],
                'subobjects':subobjects,'phase':'alive','claim':None,'leases':list(leases)}
            self.items[identifier]=certificate
            journal.stage='published'
            return deepcopy(certificate)

    def claim(self,certificate,program,*,identity):
        with self.lock:
            current=self.items.get(certificate['id'])
            require(current is not None and current==certificate,'ABI_CC_STALE_OBJECT_CERTIFICATE')
            require(current['phase']=='alive' and current['claim'] is None,'ABI_CC_OBJECT_ALREADY_CLAIMED')
            self._object(current['object'],current['object_generation'],current['address'])
            counts={slot['count_source']['some']:entry['count']
                for slot in program['slots'] if slot['count_source'] is not None
                for entry in current['counts'] if entry['slot']==slot['id']}
            journal=ConstructionJournal(program,transition=identity[0],thread=identity[1],activation=identity[2],
                generation=identity[3],instance=identity[4],counts=counts,destruction=True)
            require(current['program']['module']['kind']=='self' and current['program']['id']==program['id'],
                    'ABI_CC_OBJECT_PROGRAM')
            expected={entry['slot']:entry['count'] for entry in current['counts']}
            require(journal.counts==expected,'ABI_CC_OBJECT_COUNTS')
            seen=set()
            for entry in current['subobjects']:
                key=entry['slot'],entry['element']
                require(key in journal.states and key not in seen,'ABI_CC_SUBOBJECT_REFERENCE')
                seen.add(key)
                journal.states[key].update(phase='alive',ordinal=entry['ordinal'])
            journal.ordinal=max((entry['ordinal'] for entry in current['subobjects']),default=0)
            journal.stage='alive'
            journal.seed={'certificate':current['id'],'revision':current['revision']}
            current.update(phase='destroying',claim=identity[4])
            return journal

    def finish(self,journal):
        with self.lock:
            current=self.items[journal.seed['certificate']]
            require(current['phase']=='destroying' and current['claim']==journal.instance and
                    current['revision']==journal.seed['revision'],'ABI_CC_STALE_OBJECT_CERTIFICATE')
            require(journal.stage=='destroyed','ABI_CC_OBJECT_CLEANUP_PENDING')
            # The object's source lifetime has ended on normal or raised destructor
            # completion. Storage release is a distinct owning allocation cleanup.
            require(current['revision']<(1<<64)-1,'ABI_CC_OBJECT_RESOURCE')
            current.update(phase='dead',claim=None,revision=current['revision']+1)
            return deepcopy(current)

    def replace(self,identifier,slot,element,new_lifetime):
        with self.lock:
            current=self.items[identifier]
            require(current['phase']=='alive' and current['claim'] is None,'ABI_CC_OBJECT_ALREADY_CLAIMED')
            self._object(current['object'],current['object_generation'],current['address'])
            matches=[entry for entry in current['subobjects'] if (entry['slot'],entry['element'])==(slot,element)]
            require(len(matches)==1 and type(new_lifetime) is int and new_lifetime>matches[0]['lifetime'],
                    'ABI_CC_SUBOBJECT_LIFETIME')
            require(current['revision']<(1<<64)-1,'ABI_CC_OBJECT_RESOURCE')
            matches[0]['lifetime']=new_lifetime
            current['revision']+=1
            return deepcopy(current)
