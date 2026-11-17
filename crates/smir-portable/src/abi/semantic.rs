//! Complete nominal/source geometry checks, independent of live provider facts.

use super::{
    layout::{self, Geometry, MAX_OBJECT_BYTES},
    nominal::{Graph, self_id},
    value::*,
};
use crate::{
    Error,
    context::ObjectContext,
    execution::{TypeFacts, TypeKind},
    limits::Budget,
    wire::RecordValue,
};
use std::collections::{BTreeMap, BTreeSet};

const KINDS: &[&str] = &[
    "void",
    "scalar",
    "bitint",
    "enum",
    "pointer",
    "reference",
    "member_pointer",
    "array",
    "vector",
    "complex",
    "record",
    "atomic",
    "function",
    "handle",
    "atomic_flag",
    "snapshot",
];
const FLAGS: &[&str] = &[
    "complete",
    "union",
    "class",
    "trivial_copy",
    "trivial_destroy",
    "polymorphic",
    "noexcept",
    "variadic",
    "nonnull",
    "code",
    "signed_char",
    "flexible",
    "native",
    "scoped",
    "fixed_base",
    "c_linkage",
    "c_compatible",
    "lvalue_ref",
    "rvalue_ref",
];

fn geometry(value: &RecordValue) -> Result<Geometry, Error> {
    Ok(Geometry {
        size: uint(field(value, "size")?)?,
        align: uint(field(value, "align")?)?,
    })
}

pub(crate) fn verify_types(
    graph: &Graph,
    ctx: &ObjectContext,
    types: &TypeFacts,
    budget: &mut Budget,
) -> Result<(), Error> {
    types.assert_context(ctx)?;
    for (identifier, typ) in &graph.types {
        budget.work(1)?;
        let kind = text(field(typ, "kind")?)?;
        require(KINDS.contains(&kind), "ABI_CC_TYPE_KIND")?;
        let input = optional(field(typ, "record_input")?)?;
        let complete = flags(typ, "flags", "complete")?;
        if matches!(kind, "void" | "function") {
            require(
                optional(field(typ, "layout")?)?.is_none(),
                "ABI_CC_NONOBJECT_LAYOUT",
            )?;
        }
        if matches!(kind, "record" | "array") && !complete {
            require(
                optional(field(typ, "layout")?)?.is_none()
                    && input.is_none()
                    && optional(field(typ, "execution")?)?.is_none()
                    && text(field(typ, "representation")?)? == "none",
                "ABI_CC_INCOMPLETE_LAYOUT",
            )?;
        }
        if kind == "array" {
            let elements = list(field(typ, "elements")?)?;
            require(elements.len() == 1, "ABI_CC_ELEMENT_TYPE")?;
            let count = optional(field(typ, "extent")?)?.map(uint).transpose()?;
            require(count.is_none_or(|n| n > 0), "ABI_CC_ARRAY_COUNT")?;
            let element = graph.typ(&elements[0])?;
            let known = count.is_some()
                && flags(element, "flags", "complete")?
                && optional(field(element, "layout")?)?.is_some();
            require(
                complete == known && (!known || optional(field(typ, "layout")?)?.is_some()),
                "ABI_CC_ARRAY_COMPLETENESS",
            )?;
        }
        if kind != "record" || !flags(typ, "flags", "complete")? {
            require(input.is_none(), "ABI_CC_RECORD_INPUT")?;
        } else if text(field(graph.domain(typ)?, "isa")?)? == "portable" {
            require(input.is_some(), "ABI_CC_RECORD_INPUT")?;
        }
        let mut found = BTreeSet::new();
        for flag in list(field(typ, "flags")?)? {
            budget.work(1)?;
            budget.reserve_bytes(64)?;
            let flag = text(flag)?;
            require(
                FLAGS.contains(&flag) && found.insert(flag),
                "ABI_CC_TYPE_KIND",
            )?;
        }
        let categories =
            usize::from(found.contains("lvalue_ref")) + usize::from(found.contains("rvalue_ref"));
        require(
            match kind {
                "reference" => categories == 1,
                "function" => categories <= 1,
                _ => categories == 0,
            },
            "ABI_CC_REFERENCE_CATEGORY",
        )?;
        let qualifiers = list(field(typ, "qualifiers")?)?;
        let mut previous = None;
        for q in qualifiers {
            let q = text(q)?;
            require(
                ["const", "volatile", "restrict"].contains(&q) && previous.is_none_or(|p| p < q),
                "ABI_CC_QUALIFIER",
            )?;
            previous = Some(q);
        }
        let identity = field(typ, "identity")?;
        let language = text(field(identity, "language")?)?;
        let linkage = text(field(identity, "linkage")?)?;
        require(
            ["c23", "cpp23"].contains(&language)
                && ["builtin", "external", "internal", "local", "odr_local"].contains(&linkage)
                && !text(field(identity, "entity")?)?.is_empty(),
            "ABI_CC_NOMINAL_IDENTITY",
        )?;
        require(
            optional(field(identity, "unit")?)?.is_some()
                == matches!(linkage, "internal" | "local"),
            "ABI_CC_NOMINAL_UNIT",
        )?;
        if matches!(
            kind,
            "function"
                | "pointer"
                | "reference"
                | "member_pointer"
                | "array"
                | "vector"
                | "complex"
                | "atomic"
                | "bitint"
        ) {
            require(
                text(field(identity, "entity")?)? == kind
                    && linkage == "builtin"
                    && optional(field(identity, "unit")?)?.is_none(),
                "ABI_CC_CANONICAL_CONSTRUCTOR",
            )?;
        }
        require(
            !found.contains("c_linkage") || (kind == "function" && categories == 0),
            "ABI_CC_C_LINKAGE_KIND",
        )?;
        require(
            !found.contains("c_compatible") || matches!(kind, "record" | "enum"),
            "ABI_CC_C_MIRROR_KIND",
        )?;
        for (flag, allowed) in [
            ("union", kind == "record"), ("class", kind == "record"),
            ("polymorphic", kind == "record"), ("variadic", kind == "function"),
            ("noexcept", kind == "function"), ("code", matches!(kind, "pointer" | "reference")),
            ("flexible", kind == "array"), ("scoped", kind == "enum"),
            ("fixed_base", kind == "enum"), ("signed_char", kind == "scalar"),
        ] {
            require(!found.contains(flag) || allowed, "ABI_CC_TYPE_KIND")?;
        }
        for child in list(field(typ, "elements")?)? {
            budget.work(1)?;
            graph.resolve(child)?;
        }
        let elements = list(field(typ, "elements")?)?;
        if kind == "function" {
            let count = optional(field(typ, "extent")?)?.map(uint).transpose()?;
            require(
                count.is_some_and(|n| n.checked_add(1) == Some(elements.len() as u64))
                    && uint(field(typ, "bits")?)? == 0
                    && !boolean(field(typ, "signed")?)?
                    && list(field(typ, "methods")?)?.is_empty()
                    && list(field(typ, "enumerators")?)?.is_empty(),
                "ABI_CC_SOURCE_SIGNATURE",
            )?;
            for (index, child) in elements.iter().enumerate() {
                budget.work(1)?;
                let child_kind = text(field(graph.typ(child)?, "kind")?)?;
                require(
                    !matches!(child_kind, "function" | "array")
                        && (index + 1 == elements.len() || child_kind != "void"),
                    "ABI_CC_SOURCE_SIGNATURE",
                )?;
            }
        }
        if matches!(kind, "pointer" | "reference") {
            require(elements.len() == 1, "ABI_CC_TYPE_BINDING")?;
            let target = graph.typ(&elements[0])?;
            let code = text(field(target, "kind")?)? == "function";
            require(found.contains("code") == code, "ABI_CC_CODE_SIGNATURE")?;
            if code {
                require(
                    list(field(target, "qualifiers")?)?.is_empty()
                        && !flags(target, "flags", "lvalue_ref")?
                        && !flags(target, "flags", "rvalue_ref")?,
                    "ABI_CC_REF_QUALIFIED_THIS",
                )?;
            }
        }
        for method in list(field(typ, "methods")?)? {
            budget.work(1)?;
            require(
                text(field(graph.typ(field(method, "signature")?)?, "kind")?)? == "function",
                "ABI_CC_METHOD_SIGNATURE",
            )?;
        }
        require(
            list(field(typ, "enumerators")?)?.is_empty() || kind == "enum",
            "ABI_CC_ENUM_DECLARATION",
        )?;
        let complete = found.contains("complete");
        require(
            !complete
                || matches!(kind, "void" | "function")
                || optional(field(typ, "layout")?)?.is_some(),
            "ABI_CC_MISSING_OBJECT_LAYOUT",
        )?;
        let digest = bytes(field(identity, "definition")?)?;
        if complete {
            require(
                digest == graph.fingerprint(*identifier, false, budget)?,
                "ABI_CC_DEFINITION_HASH",
            )?;
        } else {
            require(
                digest == [0; 32] && matches!(kind, "void" | "record" | "array" | "function"),
                "ABI_CC_INCOMPLETE_DECLARATION",
            )?;
        }
        let foreign = text(field(graph.domain(typ)?, "isa")?)? != "portable";
        let execution = optional(field(typ, "execution")?)?;
        let representation = text(field(typ, "representation")?)?;
        require(
            ["none", "value", "storage", "signature", "code_address"].contains(&representation),
            "ABI_CC_TYPE_BINDING",
        )?;
        require(
            representation != "code_address"
                || (matches!(kind, "pointer" | "reference") && found.contains("code")),
            "ABI_CC_TYPE_BINDING",
        )?;
        if kind == "function" {
            require(!foreign || execution.is_none(), "ABI_CC_FUNCTION_DEFAULT")?;
            require(
                execution.is_none() || representation == "signature",
                "ABI_CC_TYPE_BINDING",
            )?;
        }
        if text(field(typ, "representation")?)? == "none" {
            require(
                execution.is_none()
                    && (!complete || matches!(kind, "void" | "function") || foreign),
                "ABI_CC_TYPE_BINDING",
            )?;
            continue;
        }
        let execution = execution.ok_or_else(|| {
            Error::semantic("ABI_CC_TYPE_BINDING", "execution association missing")
        })?;
        let handle = types.type_reference(execution)?;
        let shape = types.kind(handle)?;
        let bits = uint(field(typ, "bits")?)?;
        let elements = list(field(typ, "elements")?)?;
        match kind {
            "pointer" | "reference" => {
                require(bits == 64 && elements.len() == 1, "ABI_CC_TYPE_BINDING")?;
                if found.contains("code") {
                    require(
                        matches!(shape, TypeKind::CodeAddress)
                            && text(field(typ, "representation")?)? == "code_address",
                        "ABI_CC_TYPE_BINDING",
                    )?;
                } else {
                    require(
                        matches!(shape, TypeKind::DataPtr)
                            && text(field(typ, "representation")?)? == "value",
                        "ABI_CC_TYPE_BINDING",
                    )?;
                }
            }
            "handle" => {
                let expected = match text(field(identity, "entity")?)? {
                    "rax.exception_lease" => "exception",
                    "rax.construction_journal" => "journal",
                    "rax.stack_checkpoint" => "stack_mark",
                    _ => "invalid",
                };
                require(
                    bits == 64 && shape.name() == expected,
                    "ABI_CC_HANDLE_BINDING",
                )?;
            }
            "snapshot" => require(
                text(field(identity, "entity")?)? == "rax.fenv_snapshot"
                    && matches!(shape, TypeKind::Fenv),
                "ABI_CC_SNAPSHOT_BINDING",
            )?,
            "member_pointer" => {
                require(
                    elements.len() == 2
                        && text(field(graph.typ(&elements[0])?, "kind")?)? == "record",
                    "ABI_CC_MEMBER_POINTER",
                )?;
                let method = text(field(graph.typ(&elements[1])?, "kind")?)? == "function";
                if method {
                    let TypeKind::Struct { fields } = shape else {
                        return Err(Error::semantic(
                            "ABI_CC_MEMBER_POINTER",
                            "member function pair",
                        ));
                    };
                    require(bits == 128 && fields.len() == 2, "ABI_CC_MEMBER_POINTER")?;
                    for field in fields {
                        require(
                            matches!(types.kind(types.type_handle(*field)?)?, TypeKind::Int(64)),
                            "ABI_CC_MEMBER_POINTER",
                        )?;
                    }
                } else {
                    require(
                        bits == 64 && matches!(shape, TypeKind::Int(64)),
                        "ABI_CC_MEMBER_POINTER",
                    )?;
                }
            }
            "scalar" if text(field(identity, "entity")?)? == "nullptr_t" => require(
                bits == 64
                    && !boolean(field(typ, "signed")?)?
                    && matches!(shape, TypeKind::DataPtr),
                "ABI_CC_TYPE_BINDING",
            )?,
            "bitint" | "enum" => require(
                matches!(shape,TypeKind::Int(n)|TypeKind::Raw(n) if u64::from(*n)==bits),
                "ABI_CC_TYPE_BINDING",
            )?,
            "scalar" => match shape {
                TypeKind::Int(n) | TypeKind::Raw(n) => {
                    require(u64::from(*n) == bits, "ABI_CC_TYPE_BINDING")?
                }
                TypeKind::Float(format) => require(
                    matches!(
                        (bits, format.token()),
                        (32, "binary32") | (64, "binary64") | (128, "binary128")
                    ),
                    "ABI_CC_TYPE_BINDING",
                )?,
                _ => {
                    return Err(Error::semantic(
                        "ABI_CC_TYPE_BINDING",
                        "scalar execution kind",
                    ));
                }
            },
            "record" if text(field(typ, "representation")?)? == "storage" => {
                let size = uint(field(graph.layout_id(*identifier)?, "size")?)?;
                match shape {
                    TypeKind::Raw(n) => require(
                        u64::from(*n)
                            == size.checked_mul(8).ok_or_else(|| {
                                Error::semantic("ABI_CC_STORAGE_BINDING", "source bits")
                            })?,
                        "ABI_CC_STORAGE_BINDING",
                    )?,
                    TypeKind::Array { element, count } => require(
                        *count == size
                            && matches!(
                                types.kind(types.type_handle(*element)?)?,
                                TypeKind::Raw(8)
                            ),
                        "ABI_CC_STORAGE_BINDING",
                    )?,
                    _ => {
                        return Err(Error::semantic(
                            "ABI_CC_STORAGE_BINDING",
                            "record representation",
                        ));
                    }
                }
            }
            "atomic_flag" => require(matches!(shape, TypeKind::Raw(8)), "ABI_CC_FLAG_BINDING")?,
            "atomic" => {
                require(
                    elements.len() == 1
                        && matches!(
                            shape,
                            TypeKind::Int(_)
                                | TypeKind::Float(_)
                                | TypeKind::Raw(_)
                                | TypeKind::DataPtr
                                | TypeKind::CodeAddress
                        ),
                    "ABI_CC_ATOMIC_BINDING",
                )?;
                let base = optional(field(graph.typ(&elements[0])?, "execution")?)?
                    .ok_or_else(|| Error::semantic("ABI_CC_ATOMIC_BINDING", "atomic element"))?;
                require(
                    types.type_equivalent(handle, types.type_reference(base)?, budget)?,
                    "ABI_CC_ATOMIC_BINDING",
                )?;
            }
            "function" => require(
                matches!(shape, TypeKind::Function { .. }),
                "ABI_CC_TYPE_BINDING",
            )?,
            "array" | "vector" | "complex" => {
                require(elements.len() == 1, "ABI_CC_ELEMENT_TYPE")?;
                let element = optional(field(graph.typ(&elements[0])?, "execution")?)?
                    .ok_or_else(|| Error::semantic("ABI_CC_ELEMENT_TYPE", "element execution"))?;
                let element = types.type_reference(element)?;
                match (kind, shape) {
                    (
                        "array",
                        TypeKind::Array {
                            element: actual,
                            count,
                        },
                    )
                    | (
                        "vector",
                        TypeKind::Vector {
                            element: actual,
                            count,
                        },
                    ) => {
                        require(
                            optional(field(typ, "extent")?)?
                                .is_some_and(|value| uint(value).ok() == Some(*count)),
                            "ABI_CC_ELEMENT_BINDING",
                        )?;
                        require(
                            types.type_equivalent(element, types.type_handle(*actual)?, budget)?,
                            "ABI_CC_ELEMENT_BINDING",
                        )?;
                    }
                    ("complex", TypeKind::Struct { fields }) => {
                        require(fields.len() == 2, "ABI_CC_COMPLEX_BINDING")?;
                        for actual in fields {
                            require(
                                types.type_equivalent(
                                    element,
                                    types.type_handle(*actual)?,
                                    budget,
                                )?,
                                "ABI_CC_COMPLEX_BINDING",
                            )?;
                        }
                    }
                    _ => {
                        return Err(Error::semantic(
                            "ABI_CC_TYPE_BINDING",
                            "aggregate execution kind",
                        ));
                    }
                }
            }
            _ => {
                return Err(Error::semantic(
                    "ABI_CC_TYPE_BINDING",
                    "unsupported source representation",
                ));
            }
        }
    }
    storage_cycles(graph, budget)?;
    Ok(())
}

fn storage_cycles(graph: &Graph, budget: &mut Budget) -> Result<(), Error> {
    let mut colors = BTreeMap::<u32, u8>::new();
    for root in graph.types.keys() {
        budget.reserve_bytes(64)?;
        let mut stack = vec![(*root, false)];
        while let Some((identifier, done)) = stack.pop() {
            budget.work(1)?;
            if done {
                colors.insert(identifier, 2);
                continue;
            }
            match colors.get(&identifier) {
                Some(2) => continue,
                Some(1) => {
                    return Err(Error::semantic(
                        "ABI_CC_VALUE_CYCLE",
                        "source storage recursion",
                    ));
                }
                _ => {}
            }
            budget.reserve_bytes(128)?;
            colors.insert(identifier, 1);
            stack.push((identifier, true));
            let typ = graph.typ_id(identifier)?;
            let kind = text(field(typ, "kind")?)?;
            let mut add = |reference: &RecordValue| -> Result<(), Error> {
                budget.edges(1)?;
                budget.reserve_bytes(16)?;
                stack.push((graph.resolve(reference)?, false));
                Ok(())
            };
            if matches!(kind, "atomic" | "array" | "vector" | "complex" | "enum") {
                for child in list(field(typ, "elements")?)? {
                    add(child)?;
                }
            }
            if kind == "record" && optional(field(typ, "layout")?)?.is_some() {
                let layout = graph.layout_id(identifier)?;
                for name in ["fields", "bases"] {
                    for entry in list(field(layout, name)?)? {
                        add(field(entry, "type")?)?;
                    }
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn verify_layouts(graph: &Graph, budget: &mut Budget) -> Result<(), Error> {
    for (identifier, object) in &graph.layouts {
        budget.work(1)?;
        let source = graph.typ_id(self_id(field(object, "type")?)?)?;
        require(
            optional(field(source, "layout")?)?.is_some_and(|v| id(v).ok() == Some(*identifier)),
            "ABI_CC_LAYOUT_BINDING",
        )?;
        let actual = geometry(object)?;
        layout::alignment(actual.align)?;
        layout::alignment(uint(field(object, "nonvirtual_align")?)?)?;
        require(
            actual.size > 0
                && actual.size <= MAX_OBJECT_BYTES
                && actual.size % actual.align == 0
                && uint(field(object, "data_size")?)? <= actual.size
                && uint(field(object, "nonvirtual_size")?)? <= actual.size,
            "ABI_CC_LAYOUT_EXTENT",
        )?;
        let kind = text(field(source, "kind")?)?;
        let foreign = text(field(graph.domain(source)?, "isa")?)? != "portable";
        if !foreign {
            let expected = match kind {
                "scalar" => {
                    let name = text(field(field(source, "identity")?, "entity")?)?;
                    require(
                        layout::integer_name(name)
                            || matches!(name, "float" | "double" | "long double" | "nullptr_t"),
                        "ABI_CC_SCALAR_NAME",
                    )?;
                    let value = layout::scalar(name)
                        .ok_or_else(|| Error::semantic("ABI_CC_SCALAR_NAME", name))?;
                    require(
                        uint(field(source, "bits")?)?
                            == if name == "bool" { 1 } else { value.size * 8 },
                        "ABI_CC_SCALAR_PRECISION",
                    )?;
                    require(
                        boolean(field(source, "signed")?)? == layout::signed_name(name),
                        "ABI_CC_SCALAR_SIGNEDNESS",
                    )?;
                    Some(value)
                }
                "bitint" => Some(layout::bitint(
                    id(field(source, "bits")?)?,
                    boolean(field(source, "signed")?)?,
                )?),
                "pointer" | "reference" | "handle" => Some(Geometry { size: 8, align: 8 }),
                "atomic_flag" => Some(Geometry { size: 1, align: 1 }),
                "snapshot" => Some(Geometry { size: 32, align: 8 }),
                "member_pointer" => {
                    let elements = list(field(source, "elements")?)?;
                    require(elements.len() == 2, "ABI_CC_MEMBER_POINTER")?;
                    Some(Geometry {
                        size: if text(field(graph.typ(&elements[1])?, "kind")?)? == "function" {
                            16
                        } else {
                            8
                        },
                        align: 8,
                    })
                }
                "enum" => Some(verify_enum(graph, source, budget)?),
                "atomic" => {
                    let elements = list(field(source, "elements")?)?;
                    require(elements.len() == 1, "ABI_CC_ATOMIC_TYPE")?;
                    require(
                        !matches!(
                            text(field(graph.typ(&elements[0])?, "kind")?)?,
                            "atomic" | "array"
                        ),
                        "ABI_CC_ATOMIC_TYPE",
                    )?;
                    Some(layout::atomic(geometry(graph.layout(&elements[0])?)?)?)
                }
                "array" | "vector" | "complex" => {
                    let elements = list(field(source, "elements")?)?;
                    require(elements.len() == 1, "ABI_CC_ELEMENT_TYPE")?;
                    let base = graph.typ(&elements[0])?;
                    let base_geometry = geometry(graph.layout(&elements[0])?)?;
                    let count = if kind == "complex" {
                        2
                    } else {
                        uint(optional(field(source, "extent")?)?.ok_or_else(|| {
                            Error::semantic("ABI_CC_ARRAY_COUNT", "missing array count")
                        })?)?
                    };
                    require(count > 0, "ABI_CC_ARRAY_COUNT")?;
                    if kind == "vector" {
                        require(
                            text(field(base, "kind")?)? == "scalar"
                                && [
                                    "char",
                                    "signed char",
                                    "unsigned char",
                                    "short",
                                    "unsigned short",
                                    "int",
                                    "unsigned int",
                                    "long",
                                    "unsigned long",
                                    "long long",
                                    "unsigned long long",
                                    "float",
                                    "double",
                                ]
                                .contains(&text(field(field(base, "identity")?, "entity")?)?),
                            "ABI_CC_VECTOR_ELEMENT",
                        )?;
                        Some(layout::vector(base_geometry, count)?)
                    } else {
                        if kind == "complex" {
                            require(
                                ["float", "double", "long double"]
                                    .contains(&text(field(field(base, "identity")?, "entity")?)?),
                                "ABI_CC_COMPLEX_ELEMENT",
                            )?;
                        }
                        Some(layout::array(base_geometry, count)?)
                    }
                }
                _ => None,
            };
            if let Some(expected) = expected {
                require(actual == expected, "ABI_CC_LAYOUT_POLICY")?;
            }
        }
        if text(field(graph.domain(source)?, "isa")?)? == "portable"
            && text(field(source, "kind")?)? != "record"
        {
            require(
                list(field(object, "fields")?)?.is_empty()
                    && list(field(object, "bases")?)?.is_empty()
                    && list(field(object, "vptrs")?)?.is_empty(),
                "ABI_CC_NONRECORD_LAYOUT",
            )?;
        }
        let mut names = BTreeSet::new();
        for entry in list(field(object, "fields")?)? {
            budget.work(1)?;
            budget.reserve_bytes(128)?;
            require(
                names.insert(text(field(entry, "name")?)?),
                "ABI_CC_FIELD_LAYOUT",
            )?;
            layout::bit_extent(
                uint(field(entry, "offset_bits")?)?,
                uint(field(entry, "width_bits")?)?,
                actual.size,
            )?;
            graph.resolve(field(entry, "type")?)?;
        }
        for base in list(field(object, "bases")?)? {
            budget.work(1)?;
            graph.resolve(field(base, "type")?)?;
            require(
                boolean(field(base, "virtual")?)?
                    == (text(field(field(base, "adjustment")?, "kind")?)? == "virtual"),
                "ABI_CC_BASE_ADJUSTMENT",
            )?;
        }
        for vptr in list(field(object, "vptrs")?)? {
            budget.work(1)?;
            let vcall = list(field(vptr, "vcall_offsets")?)?;
            let vbase = list(field(vptr, "vbase_offsets")?)?;
            let order = list(field(vptr, "component_order")?)?;
            require(
                order.len()
                    == vcall.len().checked_add(vbase.len()).ok_or_else(|| {
                        Error::resource("ABI_CC_VTABLE_COMPONENT_COUNT", "component count")
                    })?,
                "ABI_CC_VTABLE_COMPONENT_COUNT",
            )?;
            let mut calls = 0usize;
            let mut bases = 0usize;
            for component in order {
                budget.work(1)?;
                match text(component)? {
                    "vcall" if calls < vcall.len() => {
                        calls += 1;
                    }
                    "vbase" if bases < vbase.len() => {
                        bases += 1;
                    }
                    _ => {
                        return Err(Error::semantic(
                            "ABI_CC_VTABLE_COMPONENT_KIND",
                            "component kind/count",
                        ));
                    }
                }
            }
            require(
                calls == vcall.len() && bases == vbase.len(),
                "ABI_CC_VTABLE_COMPONENT_COUNT",
            )?;
            let offset = uint(field(vptr, "offset")?)?;
            require(
                offset % 8 == 0 && offset.checked_add(8).is_some_and(|end| end <= actual.size),
                "ABI_CC_VTABLE_LAYOUT",
            )?;
        }
    }
    Ok(())
}

fn verify_enum(
    graph: &Graph,
    source: &RecordValue,
    budget: &mut Budget,
) -> Result<Geometry, Error> {
    let elements = list(field(source, "elements")?)?;
    require(elements.len() == 1, "ABI_CC_ENUM_BASE")?;
    let base = graph.typ(&elements[0])?;
    let kind = text(field(base, "kind")?)?;
    let bits = id(field(source, "bits")?)?;
    let signed = boolean(field(source, "signed")?)?;
    require(
        matches!(kind, "scalar" | "bitint")
            && uint(field(base, "bits")?)? == u64::from(bits)
            && boolean(field(base, "signed")?)? == signed
            && (kind == "bitint"
                || layout::integer_name(text(field(field(base, "identity")?, "entity")?)?)),
        "ABI_CC_ENUM_BASE",
    )?;
    require(bits > 0 && bits <= 65_535, "ABI_CC_ENUM_VALUE")?;
    let mut names = BTreeSet::new();
    let entries = list(field(source, "enumerators")?)?;
    for entry in entries {
        budget.work(1)?;
        budget.reserve_bytes(128)?;
        require(
            names.insert(text(field(entry, "name")?)?),
            "ABI_CC_ENUM_DECLARATION",
        )?;
        let data = bytes(field(entry, "value")?)?;
        require(
            data.len() == (bits as usize).div_ceil(8)
                && (bits % 8 == 0 || data.last().is_some_and(|b| b >> (bits % 8) == 0)),
            "ABI_CC_ENUM_VALUE",
        )?;
    }
    if !flags(source, "flags", "fixed_base")? && !flags(source, "flags", "scoped")? {
        let mut selected = None;
        for (name, width, target_signed) in [
            ("int", 32, true),
            ("unsigned int", 32, false),
            ("long", 64, true),
            ("unsigned long", 64, false),
        ] {
            let mut fits = true;
            for entry in entries {
                let data = bytes(field(entry, "value")?)?;
                budget.work(data.len() as u64)?;
                let negative =
                    signed && (data[((bits - 1) / 8) as usize] & (1 << ((bits - 1) % 8))) != 0;
                if negative && !target_signed {
                    fits = false;
                    break;
                }
                let threshold = if negative {
                    width - 1
                } else {
                    width - u32::from(target_signed)
                };
                budget.work(u64::from(bits.saturating_sub(threshold)))?;
                for bit in threshold..bits {
                    if ((data[(bit / 8) as usize] >> (bit % 8)) & 1 != 0) != negative {
                        fits = false;
                        break;
                    }
                }
                if !fits {
                    break;
                }
            }
            if fits {
                selected = Some(name);
                break;
            }
        }
        require(
            selected == Some(text(field(field(base, "identity")?, "entity")?)?),
            "ABI_CC_ENUM_SELECTION",
        )?;
    }
    geometry(graph.layout(&elements[0])?)
}
