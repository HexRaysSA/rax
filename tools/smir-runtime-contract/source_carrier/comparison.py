"""Optional draft relation to independently supplied genuine original-v2 owner."""
from dataclasses import dataclass,field
from .bindings import C,check_budget
from .codec import ROOT_NAMES,decode_module
from .source_records import raw_contract
from .errors import need
@dataclass(frozen=True)
class OriginalV2Comparison:
    original_v2_owner:object
    original_v2_stamp:object
    v3_content_digest:str
    constraints:object
    deferred:tuple
    binding:str=field(default='explicit_original_v2_comparison_only',init=False)
    executable:bool=field(default=False,init=False)
    active_v3_verified:bool=field(default=False,init=False)
    original_v3_source_stamp:object=field(default=None,init=False)

def compare_against_original_v2(raw_v3,original_v2_owner,*,budget):
    """Draft relation only; never project v3 roots into a fabricated v2 Context."""
    check_budget(budget);need(type(original_v2_owner)is C.RootContext,'V3_ORIGINAL_OWNER')
    before=C.RootContext.prepare_source_data(original_v2_owner,budget=budget)
    need(original_v2_owner.sections[3]['payload_revision']==2,'V3_ORIGINAL_OWNER_REVISION')
    module=decode_module(raw_v3,budget=budget);root=module.roots[3];need(root['payload_revision']==3,'V3_EXPECTED_REVISION3')
    budget.charge(work=32*(len(raw_v3)+1),copied_bytes=64*(len(raw_v3)+1))
    need(not any(op['op']=='source_journal_observe'for f in root['functions']for b in f['blocks']for op in b['ops']),'V3_OBSERVER_SEMANTICS_UNAVAILABLE')
    need(root['functions']==original_v2_owner.sections[3]['functions'],'V3_ORIGINAL_BODY_MISMATCH')
    for identifier in ROOT_NAMES:
        if identifier==3:continue
        left=module.roots[identifier];right=original_v2_owner.sections[identifier]
        if identifier==2:
            budget.charge(work=512,copied_bytes=4096);left=dict(left);right=dict(right);left['manifest']=dict(left['manifest']);right['manifest']=dict(right['manifest']);left['manifest']['identity']='00'*32;right['manifest']['identity']='00'*32
        need(left==right,'V3_ORIGINAL_ROOT_MISMATCH',str(identifier))
    document=dict(format='draft-source-alias-compiler-constraints',revision=4,draft_sha256='28db5402d408528b02aac917c53bf94f98ffe7d4b0fe49760dd3b0015cc1c029',contract=raw_contract(root['source_contract'],budget=budget),proposed_operations=[])
    constraints=C.run(original_v2_owner,document,budget=budget)
    need(C.RootContext.prepare_source_data(original_v2_owner,budget=budget)is before,'V3_ORIGINAL_OWNER_CHANGED')
    return OriginalV2Comparison(original_v2_owner,before,module.digest,constraints,tuple(sorted(set(constraints.deferred)|{'ORIGINAL_V3_SOURCE_CONTEXT_UNAVAILABLE','STRUCTURAL_V3_NOT_EXECUTION_ADMISSION'})))
