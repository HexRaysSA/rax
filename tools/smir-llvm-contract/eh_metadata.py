"""Exact compiler-private allocation metadata grammar; no ABI admission.

Input is the MDTuple operand view: i32 constants are zero-extended APInt values,
MDString operands are strings. The actual frontend supplies admitted nominal T;
this decoder never infers a type from bytes, spelling or numeric identity.
"""
from canonical import require


def allocation_reference(node):
    """Decode LLVM042 !smir.eh.type revision1; O(1) time/space."""
    require(type(node) is list and len(node) in (4,5), 'E-EH-TYPE-METADATA')
    require(type(node[0]) is int and node[0] == 1 and node[1] == 'nominal',
            'E-EH-TYPE-METADATA')
    mode = node[2]
    require((mode == 'self' and len(node) == 4) or
            (mode == 'dependency' and len(node) == 5), 'E-EH-TYPE-METADATA')
    require(all(type(value) is int and 0 <= value < 2**32 for value in node[3:]),
            'E-EH-TYPE-METADATA')
    module = {'kind':'self'} if mode == 'self' else {'kind':'dependency','slot':node[3]}
    return {'module':module,'id':node[-1]}


class TypeSelectors:
    """Final-function positive RTTI selector assignment; O(N^2 * equality cost).

    Actual equality must resolve admitted ABI nominal identities. This bounded
    reference never invents a source type from a number/string/digest. None is
    catch-all's null RTTI, distinct from every nominal type. Keep symbolic LLVM
    intrinsics until final-function optimization/inlining is finished.
    """
    def __init__(self, ordered_types, nominal_equal):
        require(type(ordered_types) is list and len(ordered_types) <= 1024,
                'E-EH-TYPEID-RESOURCE')
        self.equal, self.representatives = nominal_equal, []
        self.selectors = [self.register(t) for t in ordered_types]

    @staticmethod
    def check(reference):
        if reference is None:
            return
        require(type(reference) is dict and set(reference) == {'module','id'}, 'E-EH-TYPEID-METADATA')
        m = reference['module']
        require(type(m) is dict and (m == {'kind':'self'} or
                set(m) == {'kind','slot'} and m['kind'] == 'dependency' and
                type(m['slot']) is int and 0 <= m['slot'] < 2**32), 'E-EH-TYPEID-METADATA')
        require(type(reference['id']) is int and 0 <= reference['id'] < 2**32,
                'E-EH-TYPEID-METADATA')

    def equivalent(self, left, right):
        if left is None or right is None:
            return left is right
        result = self.equal(left, right)
        require(type(result) is bool, 'E-EH-TYPEID-IDENTITY')
        return result

    def register(self, reference):
        self.check(reference)
        # The registry equality must validate reflexivity from actual admitted
        # metadata too; a new unknown type cannot bypass the resolver.
        require(self.equivalent(reference, reference), 'E-EH-TYPEID-IDENTITY')
        for index, prior in enumerate(self.representatives,1):
            if self.equivalent(reference,prior):
                return index
        require(len(self.representatives) < 1024, 'E-EH-TYPEID-RESOURCE')
        from copy import deepcopy
        self.representatives.append(deepcopy(reference))
        return len(self.representatives)

    def lookup(self, reference):
        self.check(reference)
        for index, prior in enumerate(self.representatives,1):
            if self.equivalent(reference,prior):
                return index
        raise ValueError('E-EH-TYPEID-METADATA')
