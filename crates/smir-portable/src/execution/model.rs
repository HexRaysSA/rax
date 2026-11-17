//! Finite execution type and physical-layout models. No host layout is inferred.

use crate::wire::RecordValue;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TypeKind {
    Int(u32),
    Raw(u32),
    Float(FloatFormat),
    DataPtr,
    CodeAddress,
    CodePtr {
        signature: u32,
    },
    Array {
        element: u32,
        count: u64,
    },
    Vector {
        element: u32,
        count: u64,
    },
    Struct {
        fields: Vec<u32>,
    },
    Function {
        params: Vec<u32>,
        results: Vec<u32>,
        param_noundef: Vec<bool>,
        result_noundef: Vec<bool>,
    },
    Exception,
    Fenv,
    StackMark,
    VaList,
    Journal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FloatFormat {
    Binary16,
    Bfloat16,
    Binary32,
    Binary64,
    Binary128,
}

impl FloatFormat {
    pub(crate) fn bits(self) -> u32 {
        match self {
            Self::Binary16 | Self::Bfloat16 => 16,
            Self::Binary32 => 32,
            Self::Binary64 => 64,
            Self::Binary128 => 128,
        }
    }

    pub(crate) fn token(self) -> &'static str {
        match self {
            Self::Binary16 => "binary16",
            Self::Bfloat16 => "bfloat16",
            Self::Binary32 => "binary32",
            Self::Binary64 => "binary64",
            Self::Binary128 => "binary128",
        }
    }
}

impl TypeKind {
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::Int(_) => "int",
            Self::Raw(_) => "raw",
            Self::Float(_) => "float",
            Self::DataPtr => "data_ptr",
            Self::CodeAddress => "code_address",
            Self::CodePtr { .. } => "code_ptr",
            Self::Array { .. } => "array",
            Self::Vector { .. } => "vector",
            Self::Struct { .. } => "struct",
            Self::Function { .. } => "function",
            Self::Exception => "exception",
            Self::Fenv => "fenv",
            Self::StackMark => "stack_mark",
            Self::VaList => "va_list",
            Self::Journal => "journal",
        }
    }

    pub(crate) fn scalar(&self) -> bool {
        matches!(
            self,
            Self::Int(_)
                | Self::Raw(_)
                | Self::Float(_)
                | Self::DataPtr
                | Self::CodePtr { .. }
                | Self::CodeAddress
        )
    }

    pub(super) fn children(&self, by_value: bool) -> &[u32] {
        match self {
            Self::Array { element, .. } | Self::Vector { element, .. } => {
                std::slice::from_ref(element)
            }
            Self::Struct { fields } => fields,
            Self::CodePtr { signature } if !by_value => std::slice::from_ref(signature),
            _ => &[],
        }
    }
}

/// Present by-value leaves. Zero-count arrays have no present opaque child.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct OpaqueSet(pub(super) u8);

impl OpaqueSet {
    pub(crate) fn any(self) -> bool {
        self.0 != 0
    }
    pub(crate) fn contains_exception(self) -> bool {
        self.0 & 1 != 0
    }
    pub(crate) fn contains_journal(self) -> bool {
        self.0 & 2 != 0
    }
    pub(crate) fn contains_stack_mark(self) -> bool {
        self.0 & 4 != 0
    }
    pub(crate) fn contains_va_list(self) -> bool {
        self.0 & 8 != 0
    }
}

pub(super) struct TypeNode {
    pub kind: TypeKind,
    pub raw: RecordValue,
    pub width: u64,
    pub opaque: OpaqueSet,
    pub fenv: bool,
    /// Saturated strictly beyond the frozen 100000-value materialization quota.
    pub value_nodes: u64,
}

#[derive(Debug)]
pub(crate) struct RawMemoryField {
    pub value_index: u32,
    pub bit_offset: u64,
    pub bit_width: u64,
    pub layout: u32,
}

pub(super) struct RawMemoryLayout {
    pub id: u32,
    pub execution_type: u32,
    pub size_bytes: u64,
    pub alignment_bytes: u32,
    pub access_bytes: u64,
    pub fields: Vec<RawMemoryField>,
    pub element: Option<u32>,
    pub stride_bits: u64,
}
