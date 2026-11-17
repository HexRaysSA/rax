//! The registry of faults the interpreter can raise.
//!
//! Every way a run ends other than by returning is one of these codes, or the
//! reason token of an explicit `trap` terminator, which the program chooses.
//! The same table is published as `faults-v1.json` in the specification; a
//! test keeps the two identical. In debug builds the interpreter checks each
//! fault it raises against this table.

/// How a fault relates to the program's meaning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultClass {
    /// Defined behaviour: the operation is specified to stop the program.
    Trap,
    /// The program executed undefined behaviour. An engine may stop, as this
    /// one does, but a conforming program never gets here.
    LanguageUb,
    /// A host limit was reached. The program itself is not at fault and the
    /// report carries no location.
    Resource,
}

impl FaultClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trap => "trap",
            Self::LanguageUb => "language_ub",
            Self::Resource => "resource",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultInfo {
    pub code: &'static str,
    pub class: FaultClass,
    pub meaning: &'static str,
}

const fn fault(code: &'static str, class: FaultClass, meaning: &'static str) -> FaultInfo {
    FaultInfo {
        code,
        class,
        meaning,
    }
}

use FaultClass::{LanguageUb, Resource, Trap};

/// Every fault code, grouped by class and sorted by code within each class.
pub const FAULTS: &[FaultInfo] = &[
    fault(
        "allocation_shape",
        Trap,
        "An allocation asked for an alignment that is not a power of two.",
    ),
    fault(
        "code_address_unbound",
        Trap,
        "code_bind was applied to an address with no origin, or to poison or undef.",
    ),
    fault(
        "code_token_invalid",
        Trap,
        "A call went through a code pointer whose bits are no function's token, or code_erase was applied to poison or undef.",
    ),
    fault(
        "code_token_signature",
        Trap,
        "An indirect call's signature differs from the called function's.",
    ),
    fault(
        "code_token_stale",
        Trap,
        "A call went through bits that equal a function's token but carry no origin.",
    ),
    fault(
        "memory_alignment",
        Trap,
        "The address of a memory access is not a multiple of the access's alignment.",
    ),
    fault(
        "memory_bounds",
        Trap,
        "A memory access extends outside the object its pointer originates from.",
    ),
    fault(
        "memory_code_pointer",
        Trap,
        "A non-callable code address was written to memory, which is not supported yet.",
    ),
    fault(
        "memory_lifetime",
        Trap,
        "A memory access touched an object that has ended, or bytes outside their lifetime.",
    ),
    fault(
        "memory_permission",
        Trap,
        "A write went to a read-only object.",
    ),
    fault(
        "service_argument",
        Trap,
        "A runtime service was called with an argument outside the values its catalog entry allows.",
    ),
    fault(
        "source_object_extent",
        Trap,
        "An allocation would not fit below the top of the address space.",
    ),
    fault(
        "pointer_provenance",
        LanguageUb,
        "A memory access went through a pointer that has no origin object.",
    ),
    fault(
        "ub_allocation_size",
        LanguageUb,
        "The size of a stack allocation was poison.",
    ),
    fault(
        "ub_control_value",
        LanguageUb,
        "A branch or switch was decided by poison or undef.",
    ),
    fault(
        "ub_div_zero",
        LanguageUb,
        "Integer division or remainder by zero.",
    ),
    fault(
        "ub_lifetime_size",
        LanguageUb,
        "The size of a lifetime marker was poison.",
    ),
    fault(
        "ub_memcpy_overlap",
        LanguageUb,
        "memcpy source and destination overlap without being identical.",
    ),
    fault(
        "ub_memory_address",
        LanguageUb,
        "A bulk memory operation with a nonzero count was given a poison or undef address.",
    ),
    fault(
        "ub_memory_count",
        LanguageUb,
        "The byte count of a bulk memory operation was poison or undef.",
    ),
    fault(
        "ub_noundef_argument",
        LanguageUb,
        "Poison or undef was passed for a noundef parameter.",
    ),
    fault(
        "ub_noundef_result",
        LanguageUb,
        "Poison or undef was returned as a noundef result.",
    ),
    fault(
        "ub_pointer",
        LanguageUb,
        "A poison pointer was used as the address of an access or as an indirect callee.",
    ),
    fault(
        "ub_poison_divisor",
        LanguageUb,
        "The divisor of an integer division or remainder was poison.",
    ),
    fault(
        "ub_service_argument",
        LanguageUb,
        "A runtime service was called with a poison argument, or was given poison bytes to send out of the program.",
    ),
    fault(
        "ub_signed_div_overflow",
        LanguageUb,
        "Signed division or remainder of the minimum value by -1, or of poison by -1.",
    ),
    fault(
        "ub_unreachable",
        LanguageUb,
        "An unreachable terminator was executed.",
    ),
    fault("frames", Resource, "The call depth limit was exceeded."),
    fault("fuel", Resource, "The step limit was reached."),
    fault(
        "resource_memory",
        Resource,
        "The limit on bytes of live memory objects was exceeded.",
    ),
];

/// The registry entry of a fault code.
pub fn fault_info(code: &str) -> Option<&'static FaultInfo> {
    FAULTS.iter().find(|info| info.code == code)
}

/// Whether `code` is registered with `class`.
pub(crate) fn is_registered(code: &str, class: FaultClass) -> bool {
    fault_info(code).is_some_and(|info| info.class == class)
}

#[cfg(test)]
mod tests {
    use super::{FAULTS, FaultClass, fault_info};

    #[test]
    fn codes_are_unique_tokens_grouped_by_class_and_sorted() {
        let order = |class| {
            [
                FaultClass::Trap,
                FaultClass::LanguageUb,
                FaultClass::Resource,
            ]
            .iter()
            .position(|candidate| *candidate == class)
        };
        for pair in FAULTS.windows(2) {
            assert!(
                (order(pair[0].class), pair[0].code) < (order(pair[1].class), pair[1].code),
                "{} is out of order or repeated",
                pair[1].code
            );
        }
        for info in FAULTS {
            let mut characters = info.code.chars();
            assert!(
                characters
                    .next()
                    .is_some_and(|first| first.is_ascii_lowercase()),
                "{}",
                info.code
            );
            assert!(
                characters.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{}",
                info.code
            );
            assert!(
                info.code.len() <= 63 && info.meaning.ends_with('.'),
                "{}",
                info.code
            );
            assert_eq!(fault_info(info.code), Some(info));
        }
        assert_eq!(fault_info("no_such_fault"), None);
    }

    #[test]
    fn the_published_registry_is_this_table() {
        let published: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../docs/specifications/smir/portable/faults-v1.json"
        ))
        .expect("faults-v1.json is JSON");
        assert_eq!(published["format"], "smir-faults-v1");
        let expected: Vec<serde_json::Value> = FAULTS
            .iter()
            .map(|info| serde_json::json!({"code": info.code, "class": info.class.as_str(), "meaning": info.meaning}))
            .collect();
        assert_eq!(
            published["faults"].as_array().expect("faults array"),
            &expected,
            "regenerate docs/specifications/smir/portable/faults-v1.json from FAULTS"
        );
    }
}
