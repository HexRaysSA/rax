"""Exact source-reference fixture outcomes, independently of runtime imports."""
import hashlib
import json
from pathlib import Path
from candidate import verify
from layout import ABIError
from nominal import NominalGraph
from .fixtures import checked_context
from .model import SourceRoles


def check():
    root=Path(__file__).resolve().parents[3]/'docs/specifications/smir/portable/conformance/abi/source-roles'
    positive=json.loads((root/'canonical-source-role-graphs.json').read_text())
    document=positive['abi'];context,shapes=checked_context(document,positive['execution_graph'])
    verify(document,context)
    roles=SourceRoles(NominalGraph(document,'main'),lambda owner,r:shapes.describe(r))
    observations=[]
    for probe in positive['probes']:
        kwargs={name:(value['owner'],value['reference']) for name in ('target','type0') if (value:=probe[name]) is not None}
        try:
            roles.check(probe['helper'],probe['nominal'],**kwargs);actual='accepted'
        except ABIError as error:actual=str(error)
        if actual!=probe['expected']:raise ValueError('SOURCE_ROLE_OUTCOME:'+probe['name']+':'+actual)
        observations.append(dict(name=probe['name'],actual=actual))
    invalid=json.loads((root/'reject-unused-builtin-state.json').read_text())
    context,_=checked_context(invalid['abi'],invalid['execution_graph'])
    try:
        verify(invalid['abi'],context);actual='accepted'
    except ABIError as error:actual=str(error)
    if actual!=invalid['expected']:raise ValueError('SOURCE_ROLE_ABI_OUTCOME:'+actual)
    observations.append(dict(name=invalid['case'],actual=actual))
    return dict(observations=observations,accepted=sum(r['actual']=='accepted' for r in observations),
                rejected=sum(r['actual']!='accepted' for r in observations),
                fixtures={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.glob('*.json')},
                scope='Source-only actual ABI reference verification; no helper import, runtime grant, native or portable execution.')


if __name__=='__main__':print(json.dumps(check(),indent=2))
