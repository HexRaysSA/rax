"""Draft compiler policy. No LLVM emitter or production admission is implemented."""

PIN = '36763294ef639d8a6a4379d81da653dda1c20686'
TRIPLE = 'smir64-unknown-rax'
DATALAYOUT = (
    'e-p:64:64:64:64-i1:8:8-i8:8:8-i16:16:16-i32:32:32-'
    'i64:64:64-i128:128:128-f16:16:16-f32:32:32-f64:64:64-'
    'f128:128:128-v8:8:8-v16:16:16-v32:32:32-v64:64:64-'
    'v128:128:128-v256:256:256-v512:512:512-a:0:64-n8:16:32:64-S128'
    '-pe1:64:64:64:64-P1'
)

DEFAULT_DATA_ADDRESS_SPACE = 0
PROGRAM_ADDRESS_SPACE = 1
ADDRESS_SPACES = (DEFAULT_DATA_ADDRESS_SPACE, PROGRAM_ADDRESS_SPACE)
PROGRAM_POINTER_LAYOUT = dict(size_bits=64, index_bits=64, abi_alignment_bits=64,
                              preferred_alignment_bits=64, null_bits=0,
                              stable_representation=True, external_state=True)
PARAMETERLESS_CARRIERS = ('smir.exception', 'smir.journal', 'smir.stack_mark',
                        'smir.fenv', 'smir.code_binding', 'smir.source_scope')

# Each Instruction.def entry is assigned deliberately. A newly introduced opcode
# fails generation instead of inheriting a catch-all implementation claim.
INSTRUCTION_RULES = {
    'return': 'Ret',
    'branch': 'UncondBr CondBr Switch',
    'integer': 'Add Sub Mul And Or Xor Shl LShr AShr',
    'division': 'UDiv SDiv URem SRem',
    'fp': 'FNeg FAdd FSub FMul FDiv FRem FCmp FPToUI FPToSI UIToFP SIToFP FPTrunc FPExt',
    'memory': 'Alloca Load Store',
    'gep': 'GetElementPtr',
    'atomic': 'Fence AtomicCmpXchg AtomicRMW',
    'integer-cast': 'Trunc ZExt SExt',
    'pointer': 'PtrToInt PtrToAddr IntToPtr BitCast AddrSpaceCast',
    'compare': 'ICmp',
    'phi': 'PHI',
    'call': 'Call',
    'select': 'Select',
    'freeze': 'Freeze',
    'aggregate': 'ExtractElement InsertElement ShuffleVector ExtractValue InsertValue',
    'varargs': 'VAArg',
    'logical-eh': 'Invoke Resume LandingPad',
    'ub': 'Unreachable',
    'reject-block-address': 'IndirectBr CallBr',
    'reject-funclet': 'CleanupRet CatchRet CatchSwitch CleanupPad CatchPad',
    'reject-internal': 'UserOp1 UserOp2',
}

# Required lowering semantics live in the executable recipe registry.
from contracts import RECIPES, OPTIONAL_RULES, attribute_contract, intrinsic_contract

RULES = {
    rule: ('helper' if recipe['helpers'] else 'expansion',
           'Exact CC-L recipe ' + rule + ': ' + ' '.join(recipe['steps']))
    for rule, recipe in RECIPES.items()
}
RULES.update({rule: ('diagnostic', reason) for rule, reason in OPTIONAL_RULES.items()})


def intrinsic_rule(name, target_prefix):
    disposition, diagnostic, binding = intrinsic_contract(name, target_prefix)
    return disposition, diagnostic, binding


def attribute_rule(name):
    return attribute_contract(name)
