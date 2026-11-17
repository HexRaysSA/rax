//! Foreign declarations, native normalization and retained independent evidence.
//! No native file declarations become code pointers or certificates.

use super::{
    adapter, catches,
    facts::{AbiRequirement, AbiRequirementKind, Tables},
    nominal::Graph,
    value::*,
};
use crate::{
    Error,
    context::{EntityKey, Namespace, ObjectContext},
    limits::Budget,
    wire::RecordValue,
};
use std::collections::{BTreeMap, BTreeSet};

fn requirement(
    out: &mut Vec<AbiRequirement>,
    kind: AbiRequirementKind,
    source: EntityKey,
    path: String,
    budget: &mut Budget,
) -> Result<(), Error> {
    budget.reserve_bytes(256 + path.len())?;
    out.push(AbiRequirement {
        kind,
        source,
        field_path: path,
        dependency: None,
        expected_native_cc: None,
        expected_packet_cc: None,
    });
    Ok(())
}

pub(super) fn verify(
    graph: &Graph,
    ctx: &ObjectContext,
    tables: &Tables,
    requirements: &mut Vec<AbiRequirement>,
    budget: &mut Budget,
) -> Result<(), Error> {
    let mut portable = 0;
    let mut isas = BTreeSet::new();
    let mut personalities = BTreeSet::new();
    require(graph.domains.len() <= 4096, "ABI_CC_DOMAIN_COUNT")?;
    for (identifier, domain) in &graph.domains {
        budget.work(1)?;
        let isa = text(field(domain, "isa")?)?;
        let abi = text(field(domain, "abi")?)?;
        let personality = text(field(domain, "personality")?)?;
        require(
            ["portable", "x86_64", "aarch64"].contains(&isa),
            "ABI_CC_FOREIGN_ISA",
        )?;
        require(
            ["portable", "itanium", "microsoft"].contains(&abi),
            "ABI_CC_FOREIGN_ABI",
        )?;
        if isa == "portable" {
            portable += 1;
            require(
                abi == "portable" && personality == "portable",
                "ABI_CC_FOREIGN_ABI",
            )?;
        } else {
            budget.reserve_bytes(128)?;
            isas.insert(isa);
            personalities.insert(personality);
            require(
                (abi == "itanium" && ["linux", "darwin", "windows"].contains(&personality))
                    || (abi == "microsoft" && personality == "windows"),
                "ABI_CC_FOREIGN_ABI",
            )?;
            requirement(
                requirements,
                AbiRequirementKind::NativeDomain,
                ctx.local(Namespace::Domain, *identifier)?,
                String::new(),
                budget,
            )?;
        }
    }
    require(portable == 1, "ABI_CC_DOMAIN_COUNT")?;
    require(isas.len() <= 1, "ABI_CC_FOREIGN_ISA_SELECTION")?;
    require(
        personalities.len() <= 1,
        "ABI_CC_FOREIGN_PERSONALITY_SELECTION",
    )?;
    for (identifier, typ) in &graph.types {
        if text(field(graph.domain(typ)?, "isa")?)? != "portable" {
            requirement(
                requirements,
                AbiRequirementKind::NativeType,
                ctx.local(Namespace::Nominal, *identifier)?,
                String::new(),
                budget,
            )?;
            if optional(field(typ, "layout")?)?.is_some() {
                requirement(
                    requirements,
                    AbiRequirementKind::NativeLayout,
                    ctx.local(Namespace::Nominal, *identifier)?,
                    "layout".into(),
                    budget,
                )?;
            }
        }
    }
    for recipe in tables.recipes.values() {
        adapter::verify(graph, ctx, recipe, budget)?;
    }
    for binding in tables.personalities.values() {
        verify_personality(graph, ctx, binding, requirements, budget)?;
    }
    for unwind in tables.unwind.values() {
        verify_unwind(graph, ctx, tables, unwind, requirements, budget)?;
    }
    for mapping in tables.catches.values() {
        verify_catch(graph, tables, mapping, budget)?;
    }
    for bridge in tables.bridges.values() {
        verify_bridge(graph, ctx, tables, bridge, requirements, budget)?;
    }
    for object in graph.layouts.values() {
        for vptr in list(field(object, "vptrs")?)? {
            for slot in list(field(vptr, "slots")?)? {
                budget.work(1)?;
                let callable = match ctx
                    .resolve_declaration(Namespace::Symbol, &crate::context::entity_ref(slot)?)?
                {
                    crate::context::DeclaredEntity::Local(key) => {
                        text(field(ctx.entity(key)?, "kind")?)? == "function"
                    }
                    crate::context::DeclaredEntity::Dependency { declaration, .. } => {
                        text(field(declaration, "symbol_kind")?)? == "function"
                    }
                };
                require(callable, "ABI_CC_VTABLE_SLOT")?;
                adapter::symbol(graph, ctx, slot)?;
            }
        }
    }
    Ok(())
}

fn verify_personality(
    graph: &Graph,
    ctx: &ObjectContext,
    binding: &RecordValue,
    requirements: &mut Vec<AbiRequirement>,
    budget: &mut Budget,
) -> Result<(), Error> {
    budget.work(1)?;
    let domain = graph
        .domains
        .get(&id(field(binding, "domain")?)?)
        .ok_or_else(|| Error::semantic("ABI_CC_PERSONALITY_PROFILE", "domain"))?;
    let flavor = text(field(binding, "flavor")?)?;
    let abi = text(field(domain, "abi")?)?;
    let os = text(field(domain, "personality")?)?;
    require(
        match flavor {
            "logical_itanium" => abi == "portable" && os == "portable",
            "guest_itanium_dwarf" => abi == "itanium" && matches!(os, "linux" | "darwin"),
            "guest_itanium_darwin" => abi == "itanium" && os == "darwin",
            "guest_itanium_seh" => abi == "itanium" && os == "windows",
            "guest_msvc_seh3" | "guest_msvc_seh4" => abi == "microsoft" && os == "windows",
            _ => false,
        },
        "ABI_CC_PERSONALITY_PROFILE",
    )?;
    let entry = adapter::symbol(graph, ctx, field(binding, "entry")?)?;
    require(
        entry.domain == id(field(binding, "domain")?)?
            && entry.nominal == graph.resolve(field(binding, "signature")?)?,
        "ABI_CC_PERSONALITY_SIGNATURE",
    )?;
    let signature = graph.typ(field(binding, "signature")?)?;
    require(
        text(field(signature, "kind")?)? == "function"
            && flags(signature, "flags", "native")? == (text(field(domain, "isa")?)? != "portable"),
        "ABI_CC_PERSONALITY_SIGNATURE",
    )?;
    let elements = list(field(signature, "elements")?)?;
    require(!elements.is_empty(), "ABI_CC_PERSONALITY_SIGNATURE")?;
    let result = graph.typ(
        elements
            .last()
            .ok_or_else(|| Error::semantic("ABI_CC_PERSONALITY_SIGNATURE", "result"))?,
    )?;
    require(
        uint(field(result, "bits")?)? == 32,
        "ABI_CC_PERSONALITY_SIGNATURE",
    )?;
    let arguments = &elements[..elements.len() - 1];
    if flavor.starts_with("guest_msvc") || flavor == "guest_itanium_seh" {
        require(arguments.len() == 4, "ABI_CC_PERSONALITY_SIGNATURE")?;
        for argument in arguments {
            let argument = graph.typ(argument)?;
            require(
                text(field(argument, "kind")?)? == "pointer"
                    && uint(field(argument, "bits")?)? == 64,
                "ABI_CC_PERSONALITY_SIGNATURE",
            )?;
        }
    } else {
        require(arguments.len() == 5, "ABI_CC_PERSONALITY_SIGNATURE")?;
        for (argument, bits) in arguments[..3].iter().zip([32, 32, 64]) {
            require(
                uint(field(graph.typ(argument)?, "bits")?)? == bits,
                "ABI_CC_PERSONALITY_SIGNATURE",
            )?;
        }
        for argument in &arguments[3..] {
            require(
                text(field(graph.typ(argument)?, "kind")?)? == "pointer",
                "ABI_CC_PERSONALITY_SIGNATURE",
            )?;
        }
    }
    let mut flags_set = BTreeSet::new();
    for flag in list(field(binding, "flags")?)? {
        let flag = text(flag)?;
        budget.reserve_bytes(64)?;
        require(
            [
                "search_readonly",
                "cleanup_calls",
                "forced_unwind",
                "cross_domain_translation",
            ]
            .contains(&flag)
                && flags_set.insert(flag),
            "ABI_CC_PERSONALITY_PHASE",
        )?;
    }
    require(
        ["search_readonly", "cleanup_calls", "forced_unwind"]
            .iter()
            .all(|flag| flags_set.contains(flag)),
        "ABI_CC_PERSONALITY_PHASE",
    )?;
    if text(field(domain, "isa")?)? != "portable" {
        requirement(
            requirements,
            AbiRequirementKind::NativePersonality,
            ctx.local(Namespace::Personality, id(field(binding, "id")?)?)?,
            String::new(),
            budget,
        )?;
        if let Some(requirement) = requirements.last_mut() {
            requirement.expected_native_cc = Some(native_cc(domain)?);
        }
    }
    Ok(())
}

fn verify_unwind(
    graph: &Graph,
    ctx: &ObjectContext,
    tables: &Tables,
    unwind: &RecordValue,
    requirements: &mut Vec<AbiRequirement>,
    budget: &mut Budget,
) -> Result<(), Error> {
    budget.work(1)?;
    let domain = graph
        .domains
        .get(&id(field(unwind, "domain")?)?)
        .ok_or_else(|| Error::semantic("ABI_CC_UNWIND_PERSONALITY", "domain"))?;
    require(
        matches!(text(field(domain, "isa")?)?, "x86_64" | "aarch64"),
        "ABI_CC_CFI_PROFILE",
    )?;
    require(
        text(field(unwind, "source_format")?)? != "logical",
        "ABI_CC_CFI_PROFILE",
    )?;
    require(
        [
            "dwarf_cfi_lsda",
            "darwin_compact_dwarf",
            "windows_x64_unwind",
            "windows_arm64_unwind",
        ]
        .contains(&text(field(unwind, "source_format")?)?),
        "ABI_CC_CFI_FORMAT",
    )?;
    let personality = tables
        .personalities
        .get(&id(field(unwind, "personality")?)?)
        .ok_or_else(|| Error::semantic("ABI_CC_UNWIND_PERSONALITY", "personality"))?;
    require(
        field(domain, "id")? == field(personality, "domain")?,
        "ABI_CC_UNWIND_PERSONALITY",
    )?;
    let size = uint(field(unwind, "code_size")?)?;
    require(size > 0, "ABI_CC_CODE_EXTENT")?;
    let function = adapter::symbol(graph, ctx, field(unwind, "function")?)?;
    require(
        function.domain == id(field(unwind, "domain")?)?,
        "ABI_CC_CODE_DOMAIN",
    )?;
    if function.local.is_some() {
        if let Some(definition) = optional(field(function.record, "definition")?)? {
            if text(field(definition, "kind")?)? == "native" {
                require(
                    uint(field(definition, "size")?)? == size,
                    "ABI_CC_CODE_EXTENT",
                )?;
            }
        }
    }
    let isa = text(field(domain, "isa")?)?;
    let os = text(field(domain, "personality")?)?;
    let format = text(field(unwind, "source_format")?)?;
    require(
        match os {
            "portable" => format == "logical",
            "linux" => format == "dwarf_cfi_lsda",
            "darwin" => matches!(format, "dwarf_cfi_lsda" | "darwin_compact_dwarf"),
            "windows" => {
                format
                    == if isa == "x86_64" {
                        "windows_x64_unwind"
                    } else {
                        "windows_arm64_unwind"
                    }
            }
            _ => false,
        },
        "ABI_CC_CFI_PROFILE",
    )?;
    let regions = list(field(unwind, "metadata")?)?;
    require(
        format == "logical" || !regions.is_empty(),
        "ABI_CC_MISSING_NATIVE_METADATA",
    )?;
    let key = ctx.local(Namespace::Unwind, id(field(unwind, "id")?)?)?;
    for (index, region) in regions.iter().enumerate() {
        let offset = uint(field(region, "offset")?)?;
        let bytes_count = uint(field(region, "bytes")?)?;
        let range = crate::metadata::storage::declared_metadata_range(
            ctx,
            field(region, "symbol")?,
            offset,
            bytes_count,
            budget,
        )?;
        if let crate::metadata::storage::DeclaredMetadataRange::Local(bytes_range) = range {
            require(
                bytes_range.sha256(budget)? == bytes(field(region, "digest")?)?,
                "ABI_CC_METADATA_DIGEST",
            )?;
        }
        requirement(
            requirements,
            AbiRequirementKind::NativeMetadataBytes,
            key,
            format!("metadata[{index}]"),
            budget,
        )?;
    }
    let pc = match isa {
        "x86_64" => 16,
        "aarch64" => 32,
        _ => return Err(Error::semantic("ABI_CC_FOREIGN_ISA", isa)),
    };
    let mut cursor = 0;
    for row in list(field(unwind, "rows")?)? {
        budget.work(1)?;
        let start = uint(field(row, "start")?)?;
        let end = uint(field(row, "end")?)?;
        require(
            start == cursor && start < end && end <= size,
            "ABI_CC_CFI_COVERAGE",
        )?;
        let cfa = field(row, "cfa")?;
        let base = text(field(cfa, "base")?)?;
        let register = id(field(cfa, "reg")?)?;
        require(["sp", "fp", "register"].contains(&base), "ABI_CC_CFA_RULE")?;
        require(
            if base == "register" {
                register < pc
            } else {
                register == 0
            },
            "ABI_CC_CFA_REGISTER",
        )?;
        recovery(field(row, "return_rule")?, pc, isa, budget)?;
        let mut registers = BTreeSet::new();
        for rule in list(field(row, "registers")?)? {
            budget.work(1)?;
            budget.reserve_bytes(64)?;
            let register = id(field(rule, "reg")?)?;
            require(registers.insert(register), "ABI_CC_CFI_REGISTER")?;
            recovery(field(rule, "rule")?, register, isa, budget)?;
        }
        cursor = end;
    }
    require(cursor == size, "ABI_CC_CFI_COVERAGE")?;
    let mut actions = BTreeMap::new();
    for action in list(field(unwind, "actions")?)? {
        budget.reserve_bytes(128)?;
        require(
            actions.insert(id(field(action, "id")?)?, action).is_none(),
            "ABI_CC_DUPLICATE_UNWIND_ACTION",
        )?;
    }
    for action in actions.values() {
        require(
            ["cleanup", "catch", "terminate"].contains(&text(field(action, "kind")?)?),
            "ABI_CC_UNWIND_ACTION",
        )?;
        if let Some(recipe) = optional(field(action, "recipe")?)? {
            require(
                tables.recipes.contains_key(&id(recipe)?),
                "ABI_CC_ADAPTER_REFERENCE",
            )?;
        }
        if let Some(catch) = optional(field(action, "catch")?)? {
            require(
                tables.catches.contains_key(&id(catch)?),
                "ABI_CC_CATCH_REFERENCE",
            )?;
        }
        let mut current = Some(id(field(action, "id")?)?);
        let mut seen = BTreeSet::new();
        while let Some(identifier) = current {
            budget.work(1)?;
            budget.reserve_bytes(64)?;
            require(seen.insert(identifier), "ABI_CC_UNWIND_ACTION_CYCLE")?;
            let action = actions
                .get(&identifier)
                .ok_or_else(|| Error::semantic("ABI_CC_UNWIND_ACTION_CYCLE", "missing action"))?;
            current = optional(field(action, "next")?)?.map(id).transpose()?;
        }
    }
    for region in list(field(unwind, "regions")?)? {
        budget.work(1)?;
        let start = uint(field(region, "start")?)?;
        let end = uint(field(region, "end")?)?;
        require(start < end && end <= size, "ABI_CC_PROTECTED_REGION")?;
        for action in list(field(region, "actions")?)? {
            require(
                actions.contains_key(&id(action)?),
                "ABI_CC_PROTECTED_REGION",
            )?;
        }
        require(
            uint(field(region, "landing_offset")?)? < size,
            "ABI_CC_LANDING_PAD",
        )?;
        require(
            optional(field(region, "landing_pad")?)?.is_none(),
            "ABI_CC_LANDING_PAD",
        )?;
    }
    requirement(
        requirements,
        AbiRequirementKind::NativeUnwind,
        key,
        String::new(),
        budget,
    )
}

fn recovery(rule: &RecordValue, target: u32, isa: &str, budget: &mut Budget) -> Result<(), Error> {
    budget.work(1)?;
    let scalar = |register: u32| {
        if isa == "x86_64" {
            register <= 16
        } else {
            register <= 32
        }
    };
    let vector = |register: u32| {
        if isa == "x86_64" {
            (17..33).contains(&register)
        } else {
            (64..96).contains(&register)
        }
    };
    require(scalar(target) || vector(target), "ABI_CC_CFI_REGISTER")?;
    match text(field(rule, "kind")?)? {
        "expression" => Err(Error::semantic(
            "ABI_CC_CFI_EXPRESSION_UNSUPPORTED",
            "nonaffine native CFI",
        )),
        "register" => {
            let source = id(field(rule, "reg")?)?;
            require(
                (scalar(target) && scalar(source)) || (vector(target) && vector(source)),
                "ABI_CC_CFI_REGISTER_WIDTH",
            )
        }
        "cfa_offset" => {
            let width = uint(field(rule, "width")?)?;
            require(
                if vector(target) {
                    width == 8 || width == 16
                } else {
                    width == 8
                },
                "ABI_CC_CFI_WIDTH",
            )
        }
        "cfa_value" => require(scalar(target), "ABI_CC_CFI_REGISTER_WIDTH"),
        "same" | "undefined" => Ok(()),
        _ => Err(Error::semantic("ABI_CC_CFI_REGISTER", "recovery kind")),
    }
}

fn verify_catch(
    graph: &Graph,
    tables: &Tables,
    mapping: &RecordValue,
    budget: &mut Budget,
) -> Result<(), Error> {
    budget.work(1)?;
    let thrown = optional(field(mapping, "thrown")?)?
        .map(|r| graph.resolve(r))
        .transpose()?;
    let caught = optional(field(mapping, "caught")?)?
        .map(|r| graph.resolve(r))
        .transpose()?;
    require(
        thrown.is_some() || text(field(mapping, "kind")?)? == "catch_all",
        "ABI_CC_CATCH_TYPE",
    )?;
    let native = optional(field(mapping, "native_caught")?)?
        .map(|r| graph.resolve(r))
        .transpose()?;
    if native.is_some() {
        require(
            optional(field(mapping, "foreign_adapter")?)?.is_some() && caught.is_some(),
            "ABI_CC_FOREIGN_CATCH_ADAPTER",
        )?;
    }
    let relation = if let Some(thrown) = thrown {
        catches::relation(graph, thrown, native.or(caught), budget)?
    } else {
        Some(catches::Relation {
            kind: "catch_all",
            paths: vec![],
        })
    };
    let relation = relation
        .ok_or_else(|| Error::semantic("ABI_CC_CATCH_RELATION", "unmatched caught type"))?;
    require(
        text(field(mapping, "kind")?)? == relation.kind,
        "ABI_CC_CATCH_RELATION",
    )?;
    let path = list(field(mapping, "base_path")?)?;
    if !path.is_empty() {
        budget.reserve_bytes(path.len() * 48)?;
        let path = path
            .iter()
            .map(|s| text(s).map(str::to_owned))
            .collect::<Result<Vec<_>, _>>()?;
        require(relation.paths.contains(&path), "ABI_CC_CATCH_PATH")?;
    }
    let mode = text(field(mapping, "mode")?)?;
    require(["reference", "value"].contains(&mode), "ABI_CC_CATCH_MODE")?;
    for name in ["copy", "destroy", "foreign_adapter"] {
        if let Some(recipe) = optional(field(mapping, name)?)? {
            require(
                tables.recipes.contains_key(&id(recipe)?),
                "ABI_CC_ADAPTER_REFERENCE",
            )?;
        }
    }
    if mode == "value" {
        if let Some(caught) = caught {
            require(
                flags(graph.typ_id(caught)?, "flags", "trivial_copy")?
                    || optional(field(mapping, "copy")?)?.is_some(),
                "ABI_CC_CATCH_COPY_RECIPE",
            )?;
        }
    }
    Ok(())
}

fn verify_bridge(
    graph: &Graph,
    ctx: &ObjectContext,
    tables: &Tables,
    bridge: &RecordValue,
    requirements: &mut Vec<AbiRequirement>,
    budget: &mut Budget,
) -> Result<(), Error> {
    budget.work(1)?;
    let source = id(field(bridge, "source")?)?;
    let target = id(field(bridge, "target")?)?;
    let a = graph
        .domains
        .get(&source)
        .ok_or_else(|| Error::semantic("ABI_CC_BRIDGE_DOMAIN", "source"))?;
    let b = graph
        .domains
        .get(&target)
        .ok_or_else(|| Error::semantic("ABI_CC_BRIDGE_DOMAIN", "target"))?;
    require(source != target, "ABI_CC_BRIDGE_DOMAIN")?;
    require(
        text(field(a, "isa")?)? == "portable" || text(field(b, "isa")?)? == "portable",
        "ABI_CC_FOREIGN_BRIDGE_REQUIRES_PORTABLE",
    )?;
    require(
        tables
            .signatures
            .contains_key(&id(field(bridge, "signature")?)?)
            && tables
                .journals
                .contains_key(&id(field(bridge, "construction")?)?)
            && tables
                .recipes
                .contains_key(&id(field(bridge, "arguments")?)?),
        "ABI_CC_BRIDGE_BINDING",
    )?;
    if let Some(result) = optional(field(bridge, "result")?)? {
        require(
            tables.recipes.contains_key(&id(result)?),
            "ABI_CC_BRIDGE_BINDING",
        )?;
    }
    let personality = tables
        .personalities
        .get(&id(field(bridge, "personality")?)?)
        .ok_or_else(|| Error::semantic("ABI_CC_BRIDGE_UNWIND", "personality"))?;
    let unwind = tables
        .unwind
        .get(&id(field(bridge, "unwind")?)?)
        .ok_or_else(|| Error::semantic("ABI_CC_BRIDGE_UNWIND", "unwind"))?;
    let exceptions = text(field(bridge, "exceptions")?)?;
    if matches!(exceptions, "mapped" | "opaque") {
        require(
            flags(personality, "flags", "cross_domain_translation")?,
            "ABI_CC_EXCEPTION_TRANSLATION",
        )?;
    }
    require(
        field(unwind, "function")? == field(bridge, "entry")?
            && field(unwind, "personality")? == field(bridge, "personality")?,
        "ABI_CC_BRIDGE_UNWIND",
    )?;
    let entry = adapter::symbol(graph, ctx, field(bridge, "entry")?)?;
    let signature = graph.typ_id(entry.nominal)?;
    let elements = list(field(signature, "elements")?)?;
    require(
        text(field(signature, "kind")?)? == "function"
            && flags(signature, "flags", "native")?
            && elements.len() == 2,
        "ABI_CC_BRIDGE_SIGNATURE",
    )?;
    let pointer = graph.typ(&elements[0])?;
    require(
        text(field(pointer, "kind")?)? == "pointer"
            && text(field(graph.typ(&elements[1])?, "kind")?)? == "void",
        "ABI_CC_BRIDGE_SIGNATURE",
    )?;
    let pointed = list(field(pointer, "elements")?)?;
    require(pointed.len() == 1, "ABI_CC_BRIDGE_FRAME_TYPE")?;
    let packet = graph.layout(&pointed[0])?;
    require(
        uint(field(packet, "size")?)? == 80 && uint(field(packet, "align")?)? == 16,
        "ABI_CC_BRIDGE_FRAME_TYPE",
    )?;
    let fields = list(field(packet, "fields")?)?;
    let expected = [
        (0, 32),
        (32, 32),
        (64, 64),
        (128, 64),
        (192, 64),
        (256, 64),
        (320, 64),
        (384, 64),
        (448, 64),
        (512, 32),
        (544, 32),
        (576, 64),
    ];
    require(fields.len() == expected.len(), "ABI_CC_BRIDGE_FRAME_TYPE")?;
    for (field_record, (offset, width)) in fields.iter().zip(expected) {
        require(
            uint(field(field_record, "offset_bits")?)? == offset
                && uint(field(field_record, "width_bits")?)? == width,
            "ABI_CC_BRIDGE_FRAME_TYPE",
        )?;
    }
    let native = if text(field(b, "isa")?)? != "portable" {
        b
    } else {
        a
    };
    require(
        entry.domain == id(field(native, "id")?)?,
        "ABI_CC_BRIDGE_ENTRY",
    )?;
    require(
        ["none", "owner_thread", "attached_thread"].contains(&text(field(bridge, "callbacks")?)?)
            && ["noexcept", "opaque", "mapped"].contains(&exceptions)
            && ["borrowed", "owned", "shared"].contains(&text(field(bridge, "ownership")?)?)
            && ["preserve", "proxy"].contains(&text(field(bridge, "identity")?)?)
            && ["shared", "exclusive", "none"].contains(&text(field(bridge, "aliases")?)?),
        "ABI_CC_BRIDGE_POLICY",
    )?;
    require(
        text(field(bridge, "identity")?)? != "proxy"
            || text(field(bridge, "aliases")?)? != "shared",
        "ABI_CC_UNREPRESENTABLE_ALIAS",
    )?;
    // Exact native CC/packet CC/image boundaries must be established independently
    // at admission. This source record retains all expected native profile facts.
    requirement(
        requirements,
        AbiRequirementKind::ForeignBridge,
        ctx.local(Namespace::Bridge, id(field(bridge, "id")?)?)?,
        String::new(),
        budget,
    )?;
    let cc = native_cc(native)?;
    if let Some(requirement) = requirements.last_mut() {
        requirement.expected_native_cc = Some(cc);
        requirement.expected_packet_cc = Some(match cc {
            "sysv_amd64" => "sysv64_frame",
            "win64" => "win64_frame",
            _ => "aapcs64_frame",
        });
    }
    Ok(())
}

fn native_cc(domain: &RecordValue) -> Result<&'static str, Error> {
    match (
        text(field(domain, "isa")?)?,
        text(field(domain, "personality")?)?,
    ) {
        ("x86_64", "linux" | "darwin") => Ok("sysv_amd64"),
        ("x86_64", "windows") => Ok("win64"),
        ("aarch64", "linux") => Ok("aapcs64"),
        ("aarch64", "darwin") => Ok("aapcs64_darwin"),
        ("aarch64", "windows") => Ok("aapcs64_windows"),
        _ => Err(Error::semantic(
            "ABI_CC_NATIVE_CC",
            "no qualified native calling convention",
        )),
    }
}
