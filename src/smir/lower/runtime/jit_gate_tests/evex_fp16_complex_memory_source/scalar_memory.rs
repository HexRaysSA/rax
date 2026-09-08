//! Helper-backed scalar EVEX FP16-complex memory-source coverage.

use super::*;

const PAIR_CORPUS: [u32; 8] = [
    0x0000_8000, // +0, -0
    0x3C00_BC00, // +1, -1
    0x7C00_FC00, // +infinity, -infinity
    0x7E01_7D01, // quiet NaN, signaling NaN
    0x0001_8001, // positive and negative minimum subnormal
    0x7BFF_FBFF, // positive and negative maximum finite
    0x3555_B555, // approximately +1/3 and -1/3
    0x4000_C000, // +2 and -2
];

mod classification;
mod semantics;

#[cfg(target_arch = "x86_64")]
mod native;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ScalarComplexMemoryCase {
    operation: ComplexOperation,
    source1: u8,
    ll: u8,
    control: MaskControl,
}

impl ScalarComplexMemoryCase {
    const fn destination(self) -> u8 {
        0
    }

    const fn mask(self) -> u8 {
        self.control.fields().0
    }

    const fn zeroing(self) -> bool {
        self.control.fields().1
    }

    fn bytes(self) -> [u8; 6] {
        scalar_memory_encoding(
            self.operation,
            self.destination(),
            self.source1,
            self.ll,
            self.mask(),
            self.zeroing(),
            3,
        )
    }

    fn expected_replay(self) -> [u8; 7] {
        scalar_stack_encoding(
            self.operation,
            self.destination(),
            self.source1,
            self.mask(),
            self.zeroing(),
        )
    }

    const fn packed_proxy(self) -> Fp16ComplexMemoryCase {
        Fp16ComplexMemoryCase {
            operation: self.operation,
            width: VecWidth::V128,
            source1: self.source1,
            form: SourceForm::Broadcast,
            control: self.control,
        }
    }
}

fn scalar_memory_encoding(
    operation: ComplexOperation,
    destination: u8,
    source1: u8,
    ll: u8,
    mask: u8,
    zeroing: bool,
    base: u8,
) -> [u8; 6] {
    assert!(destination < 32 && source1 < 32 && base < 16 && destination != source1);
    assert!(ll < 4 && mask < 8 && (!zeroing || mask != 0));
    [
        0x62,
        (if destination & 8 == 0 { 0x80 } else { 0 })
            | 0x40
            | (if base & 8 == 0 { 0x20 } else { 0 })
            | (if destination & 16 == 0 { 0x10 } else { 0 })
            | 0x06,
        (((!source1) & 0x0F) << 3) | 0x04 | operation.pp(),
        (u8::from(zeroing) << 7) | (ll << 5) | (if source1 & 16 == 0 { 0x08 } else { 0 }) | mask,
        operation.opcode() | 1,
        ((destination & 7) << 3) | (base & 7),
    ]
}

fn scalar_stack_encoding(
    operation: ComplexOperation,
    destination: u8,
    source1: u8,
    mask: u8,
    zeroing: bool,
) -> [u8; 7] {
    let mut encoding = scalar_memory_encoding(operation, destination, source1, 0, mask, zeroing, 4);
    encoding[1] |= 0x20;
    [
        encoding[0],
        encoding[1],
        encoding[2],
        encoding[3],
        encoding[4],
        encoding[5],
        0x24,
    ]
}

fn scalar_register_encoding(
    operation: ComplexOperation,
    destination: u8,
    source1: u8,
    source2: u8,
    ll: u8,
    mask: u8,
    zeroing: bool,
) -> [u8; 6] {
    assert!(
        destination < 32
            && source1 < 32
            && source2 < 32
            && destination != source1
            && destination != source2
    );
    assert!(ll < 4 && mask < 8 && (!zeroing || mask != 0));
    [
        0x62,
        (if destination & 8 == 0 { 0x80 } else { 0 })
            | (if source2 & 16 == 0 { 0x40 } else { 0 })
            | (if source2 & 8 == 0 { 0x20 } else { 0 })
            | (if destination & 16 == 0 { 0x10 } else { 0 })
            | 0x06,
        (((!source1) & 0x0F) << 3) | 0x04 | operation.pp(),
        (u8::from(zeroing) << 7) | (ll << 5) | (if source1 & 16 == 0 { 0x08 } else { 0 }) | mask,
        operation.opcode() | 1,
        0xC0 | ((destination & 7) << 3) | (source2 & 7),
    ]
}

fn lift_scalar_bytes(bytes: &[u8]) -> SmirFunction {
    let mut lifter = X86_64Lifter::strict();
    let mut context = LiftContext::new(SourceArch::X86_64);
    let result = lifter
        .lift_insn(PC, bytes, &mut context)
        .unwrap_or_else(|error| panic!("{bytes:02X?}: {error:?}"));
    assert_eq!(result.bytes_consumed, bytes.len(), "{bytes:02X?}");
    assert!(matches!(result.control_flow, ControlFlow::Fallthrough));

    let mut block = SmirBlock::new(BlockId(0), PC);
    block.ops = result.ops;
    block.set_terminator(Terminator::Return { values: Vec::new() });
    let mut function = SmirFunction::new(FunctionId(0), block.id, PC);
    function.add_block(block);
    function.x86_instruction_bytes.insert(
        (BlockId(0), PC),
        X86InstructionBytes::new(bytes).expect("scalar FP16-complex instruction provenance"),
    );
    function
}

fn lift_scalar_case(case: ScalarComplexMemoryCase) -> SmirFunction {
    lift_scalar_bytes(&case.bytes())
}

fn lower_scalar(function: &SmirFunction, case: ScalarComplexMemoryCase) -> (Vec<u8>, usize) {
    let excluded = HashMap::new();
    assert!(is_native_clobber_safe_excluding(function, &excluded, true));
    assert!(!is_native_clobber_safe_excluding(
        function, &excluded, false
    ));
    assert!(!is_x86_aarch64_native_clobber_safe_excluding(
        function, &excluded
    ));
    assert!(uses_x86_native_vectors_excluding(function, &excluded));
    assert!(!x86_native_vector_uses_avx_ymm16_only_excluding(
        function, &excluded
    ));

    let requirements = x86_native_replay_feature_requirements(function, &excluded);
    assert!(requirements.any, "{case:?}");
    assert!(!requirements.all_spans_support_avx_ymm16, "{case:?}");
    assert!(requirements.needs_avx, "{case:?}");
    assert!(requirements.needs_avx512bw, "{case:?}");
    assert!(requirements.needs_avx512fp16, "{case:?}");
    assert!(!requirements.needs_avx512vl, "{case:?}");
    assert!(!requirements.needs_avx512dq, "{case:?}");
    assert!(!requirements.needs_fma, "{case:?}");
    #[cfg(target_arch = "x86_64")]
    assert_eq!(
        x86_native_vector_features_supported_excluding(function, &excluded),
        std::is_x86_feature_detected!("avx512f")
            && std::is_x86_feature_detected!("avx512bw")
            && std::is_x86_feature_detected!("avx512fp16"),
        "{case:?}"
    );
    #[cfg(not(target_arch = "x86_64"))]
    assert!(
        !x86_native_vector_features_supported_excluding(function, &excluded),
        "{case:?}"
    );

    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_mem_helpers(true);
    lowerer.set_preserve_vector_mem_helpers(true);
    lowerer.set_avx_ymm16_vector_state(false);
    lowerer.set_jit_fault_deopt_guards(true);
    let result = lowerer
        .lower_function(function)
        .unwrap_or_else(|error| panic!("{case:?}: scalar FP16-complex memory lowering: {error:?}"));
    assert!(result.relocations.is_empty(), "{case:?}");
    (
        lowerer
            .finalize()
            .expect("finalize helper-backed scalar FP16 complex"),
        result.entry_offset,
    )
}

fn scalar_initial_registers(case: ScalarComplexMemoryCase, ordinal: usize) -> GuestRegs {
    initial_registers(case.packed_proxy(), ordinal)
}

fn scalar_interpreter_success(
    function: &SmirFunction,
    initial: &GuestRegs,
    value: [u64; 8],
    case: ScalarComplexMemoryCase,
) -> GuestRegs {
    interpreter_success(function, initial, value, case.packed_proxy())
}

fn assert_scalar_rejected(name: &str, function: &SmirFunction) {
    assert!(
        sequence(function, true).is_none(),
        "{name}: exact sequence matcher admitted malformed graph"
    );
    assert!(
        !is_native_clobber_safe_excluding(function, &HashMap::new(), true),
        "{name}: clobber gate admitted malformed graph"
    );
}
