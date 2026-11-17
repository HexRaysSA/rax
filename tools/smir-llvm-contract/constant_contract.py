"""Exhaustive retained LLVM24 Constant ValueIDs and ConstantExpr opcode policy."""
import re


BINOPS = {'Add', 'Sub', 'Xor'}
CASTS = {'Trunc', 'PtrToAddr', 'PtrToInt', 'IntToPtr', 'BitCast', 'AddrSpaceCast'}
OTHER = {'GetElementPtr', 'ExtractElement', 'InsertElement', 'ShuffleVector'}
NORMALIZATION = {
    'Add': ('i_add', 'Same width/lane shape; retain nuw/nsw promises.'),
    'Sub': ('i_sub', 'Same width/lane shape; retain nuw/nsw promises.'),
    'Xor': ('i_xor', 'Same width/lane shape, ordered operands and bit shadow.'),
    'Trunc': ('trunc', 'Low destination bits; retained CE cast has no extra flag operand.'),
    'PtrToAddr': ('ptrtoaddr', 'Selected data/code address bits only, no provenance exposure.'),
    'PtrToInt': ('ptrtoint', 'Data AS0 cast uses selected staged exposure. Generic AS1 source-CodeAddress cast observes in-band bits only under LLVM018, without exposure; source observing CODE exposure must be explicit before optimization/staging. Actual semantic kind is not inferred from AS1.'),
    'IntToPtr': ('inttoptr', 'Data AS0 low64/zero extension recovers only already exposed issued authority. Generic AS1 source-CodeAddress conversion creates authority-free bits under LLVM018; observing CODE recovery is a separate exact source operation, never implicit in a ConstantExpr.'),
    'BitCast': ('bitcast', 'Equal logical bit count; exact raw bit shadow/origin fragments.'),
    'AddrSpaceCast': ('copy', 'Identity only within the same independently validated semantic kind in data AS0 or program AS1. Cross-AS conversion needs its separately admitted exact contract; other/native spaces reject. BlockAddress keeps its computed-label diagnostic at every nested constant.'),
    'GetElementPtr': ('constant trunc sext zext i_mul i_add icmp select ptr_offset extract_element insert_element',
        'Known index prefix checked before flatten; symbolic indices use signed/unsigned roundtrip checks and flagged multiply/add. S075 check_base for nonzero original indices even zero byte offset; select original base for all-original-indices-zero. Apply final source inrange AFTER all-zero/strict selection through unflagged offset0/check_base=false, preserving prior ranges; not getAsInstruction default.'),
    'ExtractElement': ('extract_element', 'Exact fixed vector index semantics, out-of-range poison.'),
    'InsertElement': ('insert_element', 'Exact fixed vector index semantics, out-of-range poison.'),
    'ShuffleVector': ('shuffle', 'Exact ordered mask and poison lanes, no host lane convention.'),
}
POLICY = {
    'UndefValue': ('required', 'deterministic-zero-refinement'),
    'PoisonValue': ('required', 'bit-shadow-poison'),
    'ConstantAggregateZero': ('required', 'recursive-typed-zero-except-branded-opaque'),
    'ConstantDataArray': ('required', 'ordered-exact-bits'),
    'ConstantDataVector': ('required', 'ordered-exact-bits'),
    'ConstantInt': ('required', 'exact-APInt-bitvector'),
    'ConstantByte': ('required', 'raw-byte-exact-bits'),
    'ConstantFP': ('required', 'exact-APFloat-payload-no-host-conversion'),
    'ConstantTargetNone': ('private-or-optional', 'private-E-zero-reject-otherwise-E-CONSTANT-TARGET-NONE'),
    'ConstantPointerNull': ('required', 'zero-address-or-code-token-no-authority'),
    'ConstantTokenNone': ('transient-required', 'coroutine-token-elimination-or-E-CONSTANT-RESIDUAL-TOKEN'),
    'ConstantArray': ('required', 'ordered-recursive-fields'),
    'ConstantStruct': ('required', 'ordered-recursive-fields-and-physical-padding'),
    'ConstantVector': ('required', 'ordered-recursive-fixed-lanes'),
    'Function': ('required', 'selected-issued-portable-code-token'),
    'GlobalAlias': ('required', 'selected-compatible-alias-resolution-no-cycles'),
    'GlobalIFunc': ('optional', 'E-CONSTANT-IFUNC'),
    'GlobalVariable': ('required', 'selected-data-or-qualified-TLS-definition'),
    'BlockAddress': ('optional', 'E-CONSTANT-BLOCK-ADDRESS'),
    'ConstantExpr': ('required', 'closed-opcode-DAG-legalization'),
    'DSOLocalEquivalent': ('required', 'selected-function-equivalent-portable-token'),
    'NoCFIValue': ('required', 'selected-function-token-preserve-portable-signature-admission'),
    'ConstantPtrAuth': ('optional', 'E-CONSTANT-PTRAUTH'),
}


def supported(source, method):
    body = re.search(r'bool ConstantExpr::' + method + r'\(unsigned Opcode\) \{(.*?)^\}',
                     source, re.M | re.S)
    if body is None:
        raise ValueError('LLVM constant opcode method drift: ' + method)
    matches = re.findall(r'((?:\s*case Instruction::\w+:\s*)+)return (true|false);', body.group(1))
    return {name for cases, answer in matches if answer == 'true'
            for name in re.findall(r'case Instruction::(\w+):', cases)}


def inventory(llvm):
    source = (llvm / 'llvm/lib/IR/Constants.cpp').read_text()
    if supported(source, 'isSupportedBinOp') != BINOPS or supported(source, 'isSupportedCastOp') != CASTS:
        raise ValueError('LLVM supported ConstantExpr opcode drift')
    value_ids = re.findall(r'^HANDLE_(?:CONSTANT(?:_EXCLUDE_LLVM_C_API)?|GLOBAL_VALUE)\((\w+)\)',
                           (llvm / 'llvm/include/llvm/IR/Value.def').read_text(), re.M)
    if set(value_ids) != POLICY.keys() or len(value_ids) != len(POLICY):
        raise ValueError('LLVM Constant ValueID drift')
    return dict(revision='llvm-constant-contract-v1', implemented=False,
                retained_ce_opcodes=sorted(BINOPS | CASTS | OTHER),
                retained_ce_rows=[dict(opcode=name, disposition='required_with_type_profile_gate',
                    core_operations=NORMALIZATION[name][0].split(), normalization=NORMALIZATION[name][1],
                    implemented=False) for name in sorted(BINOPS | CASTS | OTHER)],
                initializer_profile='INT018REV2/R041/S074 restricted23-op programs; S075 explicit check_base; qualification external',
                removed_binary_ops='UDiv SDiv URem SRem FAdd FSub FMul FDiv FRem And Or LShr AShr Shl Mul'.split(),
                removed_cast_ops='ZExt SExt FPTrunc FPExt UIToFP SIToFP FPToUI FPToSI'.split(),
                constants=[dict(kind=name, disposition=POLICY[name][0], recipe=POLICY[name][1])
                           for name in value_ids],
                semantic_details='constants.md',
                limits='Reference source enumeration is finite; required semantic DAG uses module resource limits, not optional-language fallback.')
