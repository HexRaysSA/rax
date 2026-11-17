#!/usr/bin/env python3
"""Independent bit arithmetic versus actual admitted S074 constant programs.

This is a finite fixture generator, never LLVM production emission/admission.
The SEM fixture builder independently verifies actual ABI/execution/runtime roots
and reserves actual reference Memory objects. Full selected deployment authority
and transactional publication remain RUNTIME/INTEGRATOR responsibilities.
"""
import copy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
from pointer_contract import gep
sys.path.insert(0, str(ROOT / 'tools/smir-format/execution'))
from test_candidate import constant, decl, operation
from test_candidate_initializers import initializer_context
from candidate.initializers import evaluate_initializer
from candidate.type_system import ref


def observe():
    rows = []
    for width in (8, 32, 33, 64, 65, 128):
        for opcode in ('add', 'sub', 'xor'):
            # Fresh actual declared type/layout: a source integer value view,
            # not a fabricated nominal authority or modified shared fixture.
            result_type, layout = 610, 10
            size = (width + 7) // 8
            types = [dict(id=result_type, kind='int', bits=width)]
            layouts = [dict(id=layout, type=ref(result_type), size=size, access_bytes=size,
                            alignment=1, fields=[], element=None, stride=0)]
            operations = [operation('address_of', [decl(0,4)], symbol=ref(1)),
                          operation('ptrtoint', [decl(1,result_type)], [0]),
                          operation('address_of', [decl(2,4)], symbol=ref(2)),
                          operation('ptrtoint', [decl(3,result_type)], [2]),
                          operation('i_'+opcode, [decl(4,result_type)], [3,1], flags=[])]
            context, machine, layout_ref = initializer_context(operations, result_type, layout, types, layouts)
            mutable = lambda: {k:v for k,v in machine.memory.__dict__.items()
                               if k not in {'types','dependencies'}}
            before = copy.deepcopy(mutable())
            result = evaluate_initializer(context, ref(7), layout_ref, memory=machine.memory,
                symbols=machine.symbols, code_pointers=machine.code_pointers)
            a, b = (machine.symbols['self', i].address % (1 << width) for i in (1,2))
            expected = {'add':lambda:b+a, 'sub':lambda:b-a, 'xor':lambda:b^a}[opcode]() % (1 << width)
            actual = int.from_bytes(bytes(byte.bits for byte in result.bytes), 'little')
            if actual != expected or any(byte.poison or byte.undef for byte in result.bytes):
                raise AssertionError(('independent integer/byte mismatch', width, opcode, actual, expected))
            if result.data_exposed != frozenset(machine.symbols['self',i].origin for i in (1,2)):
                raise AssertionError('Exposure set lost actual object identity')
            if mutable() != before:
                raise AssertionError('Private evaluator mutated its input')
            rows.append(dict(width=width, operation=opcode, actual=actual, expected=expected,
                             bytes=len(result.bytes), data_exposures=len(result.data_exposed)))
    # Address-only roundtrip cannot restore provenance; exposing roundtrip can.
    for conversion in ('ptrtoaddr', 'ptrtoint'):
        operations = [operation('address_of',[decl(0,4)],symbol=ref(1)),
                      operation(conversion,[decl(1,5)],[0]),operation('inttoptr',[decl(2,4)],[1])]
        context, machine, layout = initializer_context(operations,4,7)
        result = evaluate_initializer(context,ref(7),layout,memory=machine.memory,
            symbols=machine.symbols,code_pointers=machine.code_pointers)
        pointer = machine.symbols['self',1]
        expected_origin = pointer.origin if conversion == 'ptrtoint' else None
        if result.value.data.address != pointer.address or result.value.data.origin != expected_origin:
            raise AssertionError('Address bits and origin authority were conflated')
        rows.append(dict(operation=conversion, address=pointer.address, origin_restored=expected_origin is not None,
                         data_exposures=len(result.data_exposed)))
    rows.extend(gep_observations())
    return rows


def gep_observations():
    rows = []
    # Exact source nusw index-width/stride normalization into the accepted pure
    # subset. The original index is placement-dependent, not a known APInt.
    for bias in (0, 1 << 64, 1 << 61):
        width, wide = 128, 610
        operations = [operation('address_of',[decl(0,4)],symbol=ref(1)),
            operation('address_of',[decl(1,4)],symbol=ref(2)),
            operation('ptrtoint',[decl(2,wide)],[1]),
            constant(3,wide,bias.to_bytes(16,'little').hex()),
            operation('i_add',[decl(4,wide)],[2,3],flags=[]),
            operation('trunc',[decl(5,5)],[4]),
            operation('sext',[decl(6,wide)],[5]),
            operation('icmp',[decl(7,300)],[4,6],predicate='eq'),
            operation('constant',[decl(8,5)],literal={'kind':'poison'}),
            operation('select',[decl(9,5)],[7,5,8]),
            constant(10,5,(8).to_bytes(8,'little').hex()),
            operation('i_mul',[decl(11,5)],[9,10],flags=['nsw']),
            operation('ptr_offset',[decl(12,4)],[0,11],inbounds=False,check_base=False,
                      nuw=False,nusw=True,inrange=None)]
        context,machine,layout=initializer_context(operations,4,7,[dict(id=wide,kind='int',bits=width)])
        result=evaluate_initializer(context,ref(7),layout,memory=machine.memory,
            symbols=machine.symbols,code_pointers=machine.code_pointers)
        base,index=machine.symbols['self',1].address,machine.symbols['self',2].address+bias
        address,poison=gep(base,[(index,width,8)],flags=['nusw'])
        if (result.value.state=='poison') != poison or not poison and result.value.data.address!=address:
            raise AssertionError(('symbolic GEP normalization',bias,address,poison,result.value))
        rows.append(dict(operation='symbolic_gep_nusw',bias=bias,expected_poison=poison,
                         actual_state=result.value.state))
    # Nonzero original index * zero stride must validate base despite delta0.
    for original_index, new_range in ((0,None),(1,None),(0,(-3,5)),(1,(-3,5))):
        operations=[constant(0,5,(123).to_bytes(8,'little').hex()),
            operation('inttoptr',[decl(1,4)],[0]),constant(2,5,'0000000000000000'),
            operation('ptr_offset',[decl(3,4)],[1,2],inbounds=True,check_base=True,
                      nuw=False,nusw=False,inrange=None),
            constant(4,300,'01' if original_index==0 else '00'),
            operation('select',[decl(5,4)],[4,1,3])]
        if new_range is not None:
            operations.append(operation('ptr_offset',[decl(6,4)],[5,2],inbounds=False,
                check_base=False,nuw=False,nusw=False,
                inrange={'some':dict(lower=new_range[0],upper=new_range[1])}))
        context,machine,layout=initializer_context(operations,4,7)
        result=evaluate_initializer(context,ref(7),layout,memory=machine.memory,
            symbols=machine.symbols,code_pointers=machine.code_pointers)
        _,poison=gep(123,[(original_index,64,0)],flags=['inbounds'])
        if (result.value.state=='poison') != poison:
            raise AssertionError('Original all-zero-index exemption was confused with zero byte offset')
        if not poison and new_range is not None and result.value.data.access_range != (120,128):
            raise AssertionError('All-zero source indices erased new source inrange constraint')
        rows.append(dict(operation='zero_stride_gep',original_index=original_index,
                         new_inrange=new_range,expected_poison=poison,actual_state=result.value.state))
    return rows


def main():
    rows = observe()
    inputs = sorted({str(Path(module.__file__).resolve().relative_to(ROOT))
        for module in sys.modules.values() if isinstance(getattr(module,'__file__',None),str)
        and Path(module.__file__).resolve().is_relative_to(ROOT)
        and not Path(module.__file__).resolve().is_relative_to(Path(__file__).parent)})
    print(json.dumps(dict(cases=rows, loaded_source_inputs=inputs)))


if __name__ == '__main__':
    main()
