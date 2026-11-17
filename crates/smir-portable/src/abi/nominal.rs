//! Independent rooted nominal-graph normalization, including declaration leaves.
//!
//! Object records and declared expectations are immutable. Dependency projections
//! are consumer expectations; this graph never resolves or certifies providers.

use super::value::*;
use crate::{Error, limits::Budget, wire::RecordValue};
use serde_json::{Map, Value as Json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[derive(Debug)]
pub(crate) struct Graph {
    pub(crate) family: (String, String, u32),
    pub(crate) types: BTreeMap<u32, Arc<RecordValue>>,
    pub(crate) layouts: BTreeMap<u32, Arc<RecordValue>>,
    pub(crate) domains: BTreeMap<u32, Arc<RecordValue>>,
    declarations: BTreeMap<(u32, u32), u32>,
    dependency_slots: BTreeSet<u32>,
}

pub(crate) fn table(
    root: &RecordValue,
    name: &str,
    budget: &mut Budget,
) -> Result<BTreeMap<u32, Arc<RecordValue>>, Error> {
    let mut result = BTreeMap::new();
    for value in list(field(root, name)?)? {
        budget.work(1)?;
        budget.reserve_bytes(128)?;
        let identifier = id(field(value, "id")?)?;
        require(
            identifier != u32::MAX && !result.contains_key(&identifier),
            "ABI_CC_DUPLICATE_ID",
        )?;
        result.insert(identifier, Arc::new(owned(value, budget)?));
    }
    Ok(result)
}

impl Graph {
    pub(crate) fn new(
        abi: &RecordValue,
        symbols: &RecordValue,
        budget: &mut Budget,
    ) -> Result<Self, Error> {
        let manifest = field(symbols, "manifest")?;
        let key = field(manifest, "key")?;
        let namespace = text(field(key, "namespace")?)?;
        let name = text(field(key, "name")?)?;
        budget.work((namespace.len() + name.len()) as u64)?;
        budget.reserve_bytes(
            namespace
                .len()
                .checked_add(name.len())
                .and_then(|n| n.checked_add(128))
                .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "module family"))?,
        )?;
        let mut graph = Self {
            family: (
                namespace.to_owned(),
                name.to_owned(),
                id(field(key, "abi_major")?)?,
            ),
            types: table(abi, "types", budget)?,
            layouts: table(abi, "layouts", budget)?,
            domains: table(abi, "domains", budget)?,
            declarations: BTreeMap::new(),
            dependency_slots: BTreeSet::new(),
        };
        let manifest = field(symbols, "manifest")?;
        let mut slots = BTreeSet::new();
        for dependency in list(field(manifest, "dependencies")?)? {
            budget.work(1)?;
            budget.reserve_bytes(128)?;
            let slot = id(field(dependency, "slot")?)?;
            require(slots.insert(slot), "ABI_CC_DUPLICATE_DEPENDENCY")?;
            let mut identifiers = BTreeSet::new();
            for declaration in list(field(dependency, "declarations")?)? {
                budget.work(1)?;
                budget.reserve_bytes(128)?;
                let identifier = id(field(declaration, "id")?)?;
                require(
                    identifiers.insert(identifier),
                    "ABI_CC_DUPLICATE_DECLARATION",
                )?;
                if text(field(declaration, "kind")?)? == "nominal" {
                    let nominal = optional(field(declaration, "nominal")?)?.ok_or_else(|| {
                        Error::semantic("ABI_CC_UNBOUND_DECLARATION", "nominal expectation missing")
                    })?;
                    let target = self_id(nominal)?;
                    require(graph.types.contains_key(&target), "ABI_CC_TYPE_REFERENCE")?;
                    budget.reserve_bytes(128)?;
                    graph.declarations.insert((slot, identifier), target);
                }
            }
        }
        graph.dependency_slots = slots;
        Ok(graph)
    }

    pub(crate) fn module_reference_exists(&self, reference: &RecordValue) -> Result<bool, Error> {
        Ok(match text(field(reference, "kind")?)? {
            "self" => true,
            "dependency" => self
                .dependency_slots
                .contains(&id(field(reference, "slot")?)?),
            _ => false,
        })
    }

    pub(crate) fn resolve(&self, reference: &RecordValue) -> Result<u32, Error> {
        let identifier = id(field(reference, "id")?)?;
        let module = field(reference, "module")?;
        let result = match text(field(module, "kind")?)? {
            "self" => identifier,
            "dependency" => *self
                .declarations
                .get(&(id(field(module, "slot")?)?, identifier))
                .ok_or_else(|| {
                    Error::semantic("ABI_CC_UNBOUND_DECLARATION", "consumer nominal declaration")
                })?,
            _ => {
                return Err(Error::semantic(
                    "ABI_CC_ENTITY_REFERENCE",
                    "module reference",
                ));
            }
        };
        require(self.types.contains_key(&result), "ABI_CC_TYPE_REFERENCE")?;
        Ok(result)
    }

    pub(crate) fn typ(&self, reference: &RecordValue) -> Result<&RecordValue, Error> {
        self.types
            .get(&self.resolve(reference)?)
            .map(AsRef::as_ref)
            .ok_or_else(|| Error::semantic("ABI_CC_TYPE_REFERENCE", "nominal"))
    }

    pub(crate) fn typ_id(&self, identifier: u32) -> Result<&RecordValue, Error> {
        self.types
            .get(&identifier)
            .map(AsRef::as_ref)
            .ok_or_else(|| Error::semantic("ABI_CC_TYPE_REFERENCE", "nominal"))
    }

    pub(crate) fn layout(&self, reference: &RecordValue) -> Result<&RecordValue, Error> {
        self.layout_id(self.resolve(reference)?)
    }

    pub(crate) fn layout_id(&self, identifier: u32) -> Result<&RecordValue, Error> {
        let layout = optional(field(self.typ_id(identifier)?, "layout")?)?.ok_or_else(|| {
            Error::semantic("ABI_CC_INCOMPLETE_VALUE", "source layout unavailable")
        })?;
        self.layouts
            .get(&id(layout)?)
            .map(AsRef::as_ref)
            .ok_or_else(|| Error::semantic("ABI_CC_LAYOUT_REFERENCE", "object layout"))
    }

    pub(crate) fn domain(&self, typ: &RecordValue) -> Result<&RecordValue, Error> {
        self.domains
            .get(&id(field(typ, "domain")?)?)
            .map(AsRef::as_ref)
            .ok_or_else(|| Error::semantic("ABI_CC_TYPE_DOMAIN", "nominal domain"))
    }

    pub(crate) fn fingerprint(
        &self,
        identifier: u32,
        ignore_top_cv: bool,
        budget: &mut Budget,
    ) -> Result<[u8; 32], Error> {
        self.fingerprint_view(identifier, ignore_top_cv, false, budget)
    }

    fn fingerprint_view(
        &self,
        identifier: u32,
        ignore_top_cv: bool,
        c_view: bool,
        budget: &mut Budget,
    ) -> Result<[u8; 32], Error> {
        let (encoded, _, _) =
            self.normalized_view(identifier, ignore_top_cv, c_view, false, budget)?;
        let mut digest = Sha256::new();
        digest.update(b"SMIR-NOMINAL-SHAPE-V3\0");
        digest.update(encoded);
        Ok(digest.finalize().into())
    }

    /// Complete canonical graph bytes, not a hash equality shortcut. Every
    /// original nominal reference is resolved only through this actual graph.
    pub(crate) fn normalized_view(
        &self,
        identifier: u32,
        ignore_top_cv: bool,
        c_view: bool,
        root_noexcept: bool,
        budget: &mut Budget,
    ) -> Result<(Vec<u8>, bool, bool), Error> {
        let mut keys = vec![(identifier, true)];
        let mut indices = BTreeMap::from([((identifier, true), 0)]);
        budget.reserve_bytes(256)?;
        let mut labels = Vec::new();
        let mut edges = Vec::new();
        let mut cursor = 0;
        let mut c_admissible = true;
        let mut private_scope = false;
        while cursor < keys.len() {
            budget.work(1)?;
            budget.reserve_bytes(512)?;
            let (identifier, definition) = keys[cursor];
            let typ = self.typ_id(identifier)?;
            let kind = text(field(typ, "kind")?)?;
            if matches!(
                text(field(field(typ, "identity")?, "linkage")?)?,
                "internal" | "local"
            ) {
                private_scope = true;
            }
            if c_view {
                if matches!(kind, "reference" | "member_pointer" | "handle" | "snapshot") {
                    c_admissible = false;
                }
                if definition && matches!(kind, "record" | "enum") {
                    if !flags(typ, "flags", "complete")?
                        || (text(field(field(typ, "identity")?, "language")?)? == "cpp23"
                            && !flags(typ, "flags", "c_compatible")?)
                        || !flags(typ, "flags", "trivial_copy")?
                        || !flags(typ, "flags", "trivial_destroy")?
                        || !list(field(typ, "methods")?)?.is_empty()
                        || flags(typ, "flags", "scoped")?
                    {
                        c_admissible = false;
                    }
                    if kind == "record" && optional(field(typ, "layout")?)?.is_some() {
                        let layout = self.layout_id(identifier)?;
                        if list(field(layout, "fields")?)?.is_empty()
                            || !list(field(layout, "bases")?)?.is_empty()
                            || !list(field(layout, "vptrs")?)?.is_empty()
                        {
                            c_admissible = false;
                        }
                        for member in list(field(layout, "fields")?)? {
                            budget.work(1)?;
                            if flags(member, "flags", "no_unique_address")?
                                || flags(member, "flags", "private")?
                                || flags(member, "flags", "protected")?
                            {
                                c_admissible = false;
                            }
                        }
                    }
                }
            }
            let mut label = select(typ, &["kind", "qualifiers"], budget)?;
            label.insert(
                "abi_identity".into(),
                json(field(self.domain(typ)?, "abi_identity")?, budget)?,
            );
            label.insert(
                "identity".into(),
                Json::Object(select(
                    field(typ, "identity")?,
                    &["language", "linkage", "entity", "library", "unit"],
                    budget,
                )?),
            );
            if c_view {
                if let Some(Json::Object(identity)) = label.get_mut("identity") {
                    identity.insert("language".into(), Json::from("c23"));
                    if kind == "scalar" {
                        let entity = text(field(field(typ, "identity")?, "entity")?)?;
                        identity.insert("entity".into(), Json::from(c_alias(entity)));
                    }
                }
            }
            let mut children = Vec::new();
            if !definition && matches!(kind, "record" | "enum") {
                label.insert("node_kind".into(), Json::from("nominal_declaration"));
            } else if !definition {
                label.insert("node_kind".into(), Json::from("nominal_expression"));
                label.extend(select(typ, &["bits", "signed", "extent"], budget)?);
                let mut semantic = json(field(typ, "flags")?, budget)?;
                if let Json::Array(values) = &mut semantic {
                    budget.work(values.len() as u64)?;
                    values.retain(|value| {
                        matches!(
                            value.as_str(),
                            Some(
                                "code"
                                    | "variadic"
                                    | "noexcept"
                                    | "c_linkage"
                                    | "lvalue_ref"
                                    | "rvalue_ref"
                            )
                        ) && !(c_view && value.as_str() == Some("c_linkage"))
                    });
                }
                sort_strings(Some(&mut semantic))?;
                label.insert("semantic_flags".into(), semantic);
                let elements = list(field(typ, "elements")?)?;
                label.insert("element_count".into(), Json::from(elements.len() as u64));
                budget.reserve_bytes(
                    elements
                        .len()
                        .checked_mul(64)
                        .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "expression edges"))?,
                )?;
                for child in elements {
                    budget.work(1)?;
                    children.push((self.resolve(child)?, false));
                }
            } else {
                label.insert("node_kind".into(), Json::from("nominal_definition"));
                label.insert(
                    "element_count".into(),
                    Json::from(list(field(typ, "elements")?)?.len() as u64),
                );
                label.insert(
                    "method_count".into(),
                    Json::from(list(field(typ, "methods")?)?.len() as u64),
                );
                label.insert("has_cpp_class".into(), Json::from(false));
                label.extend(select(
                    typ,
                    &["bits", "signed", "extent", "flags", "enumerators"],
                    budget,
                )?);
                sort_strings(label.get_mut("flags"))?;
                if c_view {
                    if let Some(Json::Array(values)) = label.get_mut("flags") {
                        values.retain(|value| {
                            !matches!(value.as_str(), Some("c_linkage" | "c_compatible"))
                                && !(matches!(kind, "record" | "enum")
                                    && matches!(value.as_str(), Some("class" | "fixed_base")))
                        });
                    }
                }
                let by_value = !matches!(
                    kind,
                    "pointer" | "reference" | "member_pointer" | "function"
                );
                let mut edge_count = list(field(typ, "elements")?)?
                    .len()
                    .checked_add(list(field(typ, "methods")?)?.len())
                    .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "nominal edge count"))?;
                if let Some(input) = optional(field(typ, "record_input")?)? {
                    edge_count = edge_count
                        .checked_add(list(field(input, "fields")?)?.len())
                        .and_then(|n| n.checked_add(list(field(input, "bases").ok()?).ok()?.len()))
                        .ok_or_else(|| {
                            Error::resource("ABI_CC_GRAPH_LIMIT", "source input edge count")
                        })?;
                }
                if let Some(layout_id) = optional(field(typ, "layout")?)? {
                    let layout = self.layouts.get(&id(layout_id)?).ok_or_else(|| {
                        Error::semantic("ABI_CC_LAYOUT_REFERENCE", "nominal edges")
                    })?;
                    edge_count = edge_count
                        .checked_add(list(field(layout, "fields")?)?.len())
                        .and_then(|n| n.checked_add(list(field(layout, "bases").ok()?).ok()?.len()))
                        .ok_or_else(|| {
                            Error::resource("ABI_CC_GRAPH_LIMIT", "layout edge count")
                        })?;
                }
                budget.reserve_bytes(edge_count.checked_mul(64).ok_or_else(|| {
                    Error::resource("ABI_CC_GRAPH_LIMIT", "nominal edge memory")
                })?)?;
                for child in list(field(typ, "elements")?)? {
                    children.push((self.resolve(child)?, by_value));
                }
                let mut methods = Vec::new();
                for method in list(field(typ, "methods")?)? {
                    methods.push(Json::Object(select(
                        method,
                        &["name", "virtual", "slot", "noexcept"],
                        budget,
                    )?));
                    children.push((self.resolve(field(method, "signature")?)?, false));
                }
                label.insert("methods".into(), Json::Array(methods));
                label.insert("input_field_count".into(), Json::from(0));
                label.insert("input_base_count".into(), Json::from(0));
                let source_input = if let Some(input) = optional(field(typ, "record_input")?)? {
                    label.insert(
                        "input_field_count".into(),
                        Json::from(list(field(input, "fields")?)?.len() as u64),
                    );
                    label.insert(
                        "input_base_count".into(),
                        Json::from(list(field(input, "bases")?)?.len() as u64),
                    );
                    let mut source = select(
                        input,
                        &[
                            "revision",
                            "kind",
                            "explicit_align",
                            "pod03",
                            "trivial",
                            "standard_layout",
                            "polymorphic",
                            "dynamic",
                            "empty",
                        ],
                        budget,
                    )?;
                    let mut fields = Vec::new();
                    for entry in list(field(input, "fields")?)? {
                        fields.push(Json::Object(select(
                            entry,
                            &[
                                "name",
                                "bit_width",
                                "explicit_align",
                                "no_unique_address",
                                "anonymous",
                                "access",
                            ],
                            budget,
                        )?));
                        children.push((self.resolve(field(entry, "type")?)?, true));
                    }
                    source.insert("fields".into(), Json::Array(fields));
                    let mut bases = Vec::new();
                    for entry in list(field(input, "bases")?)? {
                        bases.push(Json::Object(select(entry, &["virtual", "access"], budget)?));
                        children.push((self.resolve(field(entry, "type")?)?, true));
                    }
                    source.insert("bases".into(), Json::Array(bases));
                    if c_view {
                        if source.get("kind").and_then(Json::as_str) == Some("class") {
                            source.insert("kind".into(), Json::from("struct"));
                        }
                        for name in [
                            "pod03",
                            "trivial",
                            "standard_layout",
                            "polymorphic",
                            "dynamic",
                            "empty",
                        ] {
                            source.insert(name.into(), Json::from(false));
                        }
                    }
                    Json::Object(source)
                } else {
                    Json::Null
                };
                label.insert("record_input".into(), source_input);
                label.insert("layout".into(), Json::Null);
                label.insert("output_field_count".into(), Json::from(0));
                label.insert("output_base_count".into(), Json::from(0));
                if let Some(layout_id) = optional(field(typ, "layout")?)? {
                    let layout = self.layouts.get(&id(layout_id)?).ok_or_else(|| {
                        Error::semantic("ABI_CC_LAYOUT_REFERENCE", "fingerprint layout")
                    })?;
                    label.insert(
                        "output_field_count".into(),
                        Json::from(list(field(layout, "fields")?)?.len() as u64),
                    );
                    label.insert(
                        "output_base_count".into(),
                        Json::from(list(field(layout, "bases")?)?.len() as u64),
                    );
                    let mut shape = select(
                        layout,
                        &[
                            "size",
                            "align",
                            "data_size",
                            "nonvirtual_size",
                            "nonvirtual_align",
                        ],
                        budget,
                    )?;
                    let mut fields = Vec::new();
                    for entry in list(field(layout, "fields")?)? {
                        let mut item = select(
                            entry,
                            &[
                                "declaration_index",
                                "name",
                                "offset_bits",
                                "width_bits",
                                "flags",
                            ],
                            budget,
                        )?;
                        sort_strings(item.get_mut("flags"))?;
                        fields.push(Json::Object(item));
                    }
                    shape.insert("fields".into(), Json::Array(fields));
                    let mut bases = Vec::new();
                    for entry in list(field(layout, "bases")?)? {
                        bases.push(Json::Object(select(
                            entry,
                            &[
                                "offset",
                                "virtual",
                                "declaration_index",
                                "origin_path",
                                "adjustment",
                            ],
                            budget,
                        )?));
                    }
                    shape.insert("bases".into(), Json::Array(bases));
                    let mut vptrs = Vec::new();
                    for entry in list(field(layout, "vptrs")?)? {
                        let mut item = select(
                            entry,
                            &[
                                "offset",
                                "offset_top",
                                "vcall_offsets",
                                "vbase_offsets",
                                "component_order",
                            ],
                            budget,
                        )?;
                        item.insert(
                            "slot_count".into(),
                            Json::from(list(field(entry, "slots")?)?.len() as u64),
                        );
                        vptrs.push(Json::Object(item));
                    }
                    shape.insert("vptrs".into(), Json::Array(vptrs));
                    label.insert("layout".into(), Json::Object(shape));
                    for entry in list(field(layout, "fields")?)? {
                        children.push((self.resolve(field(entry, "type")?)?, true));
                    }
                    for entry in list(field(layout, "bases")?)? {
                        children.push((self.resolve(field(entry, "type")?)?, true));
                    }
                }
            }
            if cursor == 0 && ignore_top_cv {
                if let Some(Json::Array(values)) = label.get_mut("qualifiers") {
                    values.retain(|value| !matches!(value.as_str(), Some("const" | "volatile")));
                }
            }
            if cursor == 0 && root_noexcept && kind == "function" {
                if let Some(Json::Array(values)) = label.get_mut("flags") {
                    values.retain(|value| value.as_str() != Some("noexcept"));
                }
            }
            budget.edges(children.len())?;
            budget.reserve_bytes(
                children
                    .len()
                    .checked_mul(64)
                    .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "edge bytes"))?,
            )?;
            let mut links = Vec::new();
            for child in children {
                let next = keys.len();
                let index = *indices.entry(child).or_insert_with(|| {
                    keys.push(child);
                    next
                });
                links.push(index);
            }
            labels.push(Json::Object(label));
            edges.push(links);
            cursor += 1;
        }
        Ok((
            canonical_quotient(&labels, &edges, budget)?,
            c_admissible,
            private_scope,
        ))
    }

    pub(crate) fn compatible(
        &self,
        left: u32,
        right: u32,
        ignore_top_cv: bool,
        budget: &mut Budget,
    ) -> Result<bool, Error> {
        self.compatible_view(left, right, ignore_top_cv, false, budget)
    }

    fn compatible_view(
        &self,
        left: u32,
        right: u32,
        ignore_top_cv: bool,
        c_view: bool,
        budget: &mut Budget,
    ) -> Result<bool, Error> {
        budget.reserve_bytes(128)?;
        let mut pending = vec![(left, right)];
        let mut seen = BTreeSet::new();
        while let Some((a_id, b_id)) = pending.pop() {
            budget.work(1)?;
            budget.reserve_bytes(128)?;
            if !seen.insert((a_id, b_id)) {
                continue;
            }
            let a = self.typ_id(a_id)?;
            let b = self.typ_id(b_id)?;
            if field(self.domain(a)?, "abi_identity")? != field(self.domain(b)?, "abi_identity")? {
                return Ok(false);
            }
            let ai = field(a, "identity")?;
            let bi = field(b, "identity")?;
            for name in ["language", "linkage", "entity", "library", "unit"] {
                if c_view && name == "language" {
                    continue;
                }
                if c_view && name == "entity" && text(field(a, "kind")?)? == "scalar" {
                    if c_alias(text(field(ai, name)?)?) != c_alias(text(field(bi, name)?)?) {
                        return Ok(false);
                    }
                } else if field(ai, name)? != field(bi, name)? {
                    return Ok(false);
                }
            }
            for name in ["kind", "bits", "signed"] {
                if field(a, name)? != field(b, name)? {
                    return Ok(false);
                }
            }
            let ignored = ignore_top_cv && (a_id, b_id) == (left, right);
            if !ignored && field(a, "qualifiers")? != field(b, "qualifiers")? {
                return Ok(false);
            }
            let kind = text(field(a, "kind")?)?;
            if matches!(kind, "record" | "enum")
                && flags(a, "flags", "complete")?
                && flags(b, "flags", "complete")?
                && self.fingerprint_view(a_id, ignored, c_view, budget)?
                    != self.fingerprint_view(b_id, ignored, c_view, budget)?
            {
                return Ok(false);
            }
            if !matches!(kind, "record" | "array") {
                let flag_count = list(field(a, "flags")?)?
                    .len()
                    .checked_add(list(field(b, "flags")?)?.len())
                    .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "flag sets"))?;
                budget.work(flag_count as u64)?;
                budget.reserve_bytes(
                    flag_count
                        .checked_mul(128)
                        .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "flag set bytes"))?,
                )?;
                let filtered = |value: &RecordValue| -> Result<BTreeSet<String>, Error> {
                    list(field(value, "flags")?)?
                        .iter()
                        .filter_map(|v| match text(v) {
                            Ok("complete" | "trivial_copy" | "trivial_destroy") => None,
                            Ok("c_linkage" | "c_compatible") if c_view => None,
                            Ok("class" | "fixed_base")
                                if c_view && matches!(kind, "record" | "enum") =>
                            {
                                None
                            }
                            Ok(v) => Some(Ok(v.into())),
                            Err(e) => Some(Err(e)),
                        })
                        .collect()
                };
                if filtered(a)? != filtered(b)? {
                    return Ok(false);
                }
            }
            if kind == "array"
                && optional(field(a, "extent")?)?.is_some()
                && optional(field(b, "extent")?)?.is_some()
                && field(a, "extent")? != field(b, "extent")?
            {
                return Ok(false);
            }
            let ac = list(field(a, "elements")?)?;
            let bc = list(field(b, "elements")?)?;
            if ac.len() != bc.len() {
                return Ok(false);
            }
            budget.edges(ac.len())?;
            budget.reserve_bytes(
                ac.len()
                    .checked_mul(16)
                    .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "type pairs"))?,
            )?;
            for (a, b) in ac.iter().zip(bc) {
                pending.push((self.resolve(a)?, self.resolve(b)?));
            }
        }
        Ok(true)
    }

    pub(crate) fn boundary(
        &self,
        left: u32,
        right: u32,
        budget: &mut Budget,
    ) -> Result<bool, Error> {
        let a = self.typ_id(left)?;
        let b = self.typ_id(right)?;
        if text(field(a, "kind")?)? == "function"
            && text(field(b, "kind")?)? == "function"
            && (flags(a, "flags", "c_linkage")? || flags(b, "flags", "c_linkage")?)
        {
            if !flags(a, "flags", "c_linkage")? || !flags(b, "flags", "c_linkage")? {
                return Ok(false);
            }
            return self.c_boundary(left, right, false, budget);
        }
        if !self.compatible(left, right, false, budget)? {
            return Ok(false);
        }
        let mut pairs = Vec::new();
        if text(field(a, "kind")?)? == "function" {
            let ac = list(field(a, "elements")?)?;
            let bc = list(field(b, "elements")?)?;
            budget.reserve_bytes(
                ac.len()
                    .checked_mul(16)
                    .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "function pairs"))?,
            )?;
            for (a, b) in ac.iter().zip(bc) {
                pairs.push((self.resolve(a)?, self.resolve(b)?));
            }
        } else {
            budget.reserve_bytes(16)?;
            pairs.push((left, right));
        }
        for (a, b) in pairs {
            budget.work(1)?;
            let at = self.typ_id(a)?;
            let bt = self.typ_id(b)?;
            if matches!(text(field(at, "kind")?)?, "void" | "function") {
                continue;
            }
            if !flags(at, "flags", "complete")?
                || !flags(bt, "flags", "complete")?
                || optional(field(at, "layout")?)?.is_none()
                || optional(field(bt, "layout")?)?.is_none()
            {
                return Ok(false);
            }
            let al = self.layout_id(a)?;
            let bl = self.layout_id(b)?;
            if field(al, "size")? != field(bl, "size")?
                || field(al, "align")? != field(bl, "align")?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(crate) fn c_boundary(
        &self,
        left: u32,
        right: u32,
        address_only: bool,
        budget: &mut Budget,
    ) -> Result<bool, Error> {
        if address_only {
            let provider = self.typ_id(right)?;
            if matches!(text(field(provider, "kind")?)?, "void" | "function")
                || !flags(provider, "flags", "complete")?
                || optional(field(provider, "layout")?)?.is_none()
            {
                return Ok(false);
            }
        }
        budget.reserve_bytes(128)?;
        let mut pending = vec![(left, right, !address_only)];
        let mut seen = BTreeSet::new();
        while let Some((a_id, b_id, by_value)) = pending.pop() {
            budget.work(1)?;
            budget.reserve_bytes(128)?;
            if !seen.insert((a_id, b_id, by_value)) {
                continue;
            }
            let a = self.typ_id(a_id)?;
            let b = self.typ_id(b_id)?;
            let kind = text(field(a, "kind")?)?;
            if kind != text(field(b, "kind")?)?
                || matches!(kind, "reference" | "member_pointer" | "handle" | "snapshot")
            {
                return Ok(false);
            }
            let opaque = kind == "record"
                && !by_value
                && (!flags(a, "flags", "complete")? || !flags(b, "flags", "complete")?);
            if opaque {
                continue;
            }
            if by_value && !matches!(kind, "void" | "function") {
                if !flags(a, "flags", "complete")?
                    || !flags(b, "flags", "complete")?
                    || optional(field(a, "layout")?)?.is_none()
                    || optional(field(b, "layout")?)?.is_none()
                {
                    return Ok(false);
                }
                let al = self.layout_id(a_id)?;
                let bl = self.layout_id(b_id)?;
                if field(al, "size")? != field(bl, "size")?
                    || field(al, "align")? != field(bl, "align")?
                {
                    return Ok(false);
                }
            }
            if matches!(kind, "record" | "enum") {
                for value in [a, b] {
                    if !flags(value, "flags", "complete")? {
                        if by_value {
                            return Ok(false);
                        } else {
                            continue;
                        }
                    }
                    if text(field(field(value, "identity")?, "language")?)? == "cpp23"
                        && !flags(value, "flags", "c_compatible")?
                    {
                        return Ok(false);
                    }
                    if !flags(value, "flags", "trivial_copy")?
                        || !flags(value, "flags", "trivial_destroy")?
                        || !list(field(value, "methods")?)?.is_empty()
                        || flags(value, "flags", "scoped")?
                    {
                        return Ok(false);
                    }
                    if kind == "record" {
                        let layout = self.layout_id(id(field(value, "id")?)?)?;
                        if !list(field(layout, "bases")?)?.is_empty()
                            || !list(field(layout, "vptrs")?)?.is_empty()
                            || list(field(layout, "fields")?)?.is_empty()
                        {
                            return Ok(false);
                        }
                        for f in list(field(layout, "fields")?)? {
                            if flags(f, "flags", "no_unique_address")?
                                || flags(f, "flags", "private")?
                                || flags(f, "flags", "protected")?
                            {
                                return Ok(false);
                            }
                        }
                    }
                }
            }
            let ac = list(field(a, "elements")?)?;
            let bc = list(field(b, "elements")?)?;
            if ac.len() != bc.len() {
                return Ok(false);
            }
            budget.edges(ac.len())?;
            budget.reserve_bytes(
                ac.len()
                    .checked_mul(24)
                    .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "C pairs"))?,
            )?;
            for (a, b) in ac.iter().zip(bc) {
                pending.push((
                    self.resolve(a)?,
                    self.resolve(b)?,
                    !matches!(kind, "pointer" | "reference" | "member_pointer"),
                ));
            }
            if kind == "record"
                && optional(field(a, "layout")?)?.is_some()
                && optional(field(b, "layout")?)?.is_some()
            {
                let al = self.layout_id(a_id)?;
                let bl = self.layout_id(b_id)?;
                let af = list(field(al, "fields")?)?;
                let bf = list(field(bl, "fields")?)?;
                if af.len() != bf.len() {
                    return Ok(false);
                }
                budget.edges(af.len())?;
                budget.reserve_bytes(
                    af.len()
                        .checked_mul(24)
                        .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "C fields"))?,
                )?;
                for (a, b) in af.iter().zip(bf) {
                    pending.push((
                        self.resolve(field(a, "type")?)?,
                        self.resolve(field(b, "type")?)?,
                        true,
                    ));
                }
            }
        }
        self.compatible_view(left, right, false, true, budget)
    }
}

fn c_alias(name: &str) -> &str {
    match name {
        "size_t" => "unsigned long",
        "ptrdiff_t" => "long",
        "wint_t" => "unsigned int",
        "wchar_t" => "int",
        "char8_t" => "unsigned char",
        "char16_t" => "unsigned short",
        "char32_t" => "unsigned int",
        other => other,
    }
}

pub(crate) fn self_id(reference: &RecordValue) -> Result<u32, Error> {
    require(
        text(field(field(reference, "module")?, "kind")?)? == "self",
        "ABI_CC_LOCAL_TYPE",
    )?;
    id(field(reference, "id")?)
}

pub(crate) fn self_ref(identifier: u32) -> RecordValue {
    RecordValue::Record(BTreeMap::from([
        ("id".into(), RecordValue::Unsigned(u64::from(identifier))),
        (
            "module".into(),
            RecordValue::Record(BTreeMap::from([(
                "kind".into(),
                RecordValue::Text("self".into()),
            )])),
        ),
    ]))
}

fn sort_strings(value: Option<&mut Json>) -> Result<(), Error> {
    let Some(Json::Array(values)) = value else {
        return Err(Error::semantic("ABI_CC_FLAGS", "flag vector"));
    };
    require(values.iter().all(Json::is_string), "ABI_CC_FLAGS")?;
    values.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    Ok(())
}

fn select(
    value: &RecordValue,
    names: &[&str],
    budget: &mut Budget,
) -> Result<Map<String, Json>, Error> {
    let mut map = Map::new();
    for name in names {
        budget.work(1)?;
        budget.reserve_bytes(128 + name.len())?;
        map.insert((*name).into(), json(field(value, name)?, budget)?);
    }
    Ok(map)
}

pub(crate) fn json(value: &RecordValue, budget: &mut Budget) -> Result<Json, Error> {
    budget.work(1)?;
    budget.reserve_bytes(128)?;
    Ok(match value {
        RecordValue::Unsigned(value) => Json::from(*value),
        RecordValue::Signed(value) => Json::from(*value),
        RecordValue::Boolean(value) => Json::from(*value),
        RecordValue::Text(value) => {
            budget.reserve_bytes(value.len())?;
            Json::from(value.clone())
        }
        RecordValue::Bytes(value) => {
            budget.reserve_bytes(
                value
                    .len()
                    .checked_mul(2)
                    .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "hex bytes"))?,
            )?;
            Json::from(
                value
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
            )
        }
        RecordValue::Vector(values) => {
            budget.edges(values.len())?;
            Json::Array(
                values
                    .iter()
                    .map(|v| json(v, budget))
                    .collect::<Result<_, _>>()?,
            )
        }
        RecordValue::Option(None) => Json::Null,
        RecordValue::Option(Some(value)) => {
            Json::Object(Map::from_iter([("some".into(), json(value, budget)?)]))
        }
        RecordValue::Record(values) => {
            let mut map = Map::new();
            for (name, value) in values {
                budget.reserve_bytes(name.len())?;
                map.insert(name.clone(), json(value, budget)?);
            }
            Json::Object(map)
        }
    })
}

/// Python ensure_ascii=True equivalent for the exact frozen hash preimage.
pub(crate) fn ascii_json(value: &Json, budget: &mut Budget) -> Result<Vec<u8>, Error> {
    fn bound(value: &Json, budget: &mut Budget) -> Result<usize, Error> {
        budget.work(1)?;
        let mut size = 64usize;
        let add =
            match value {
                Json::String(s) => s.len().checked_mul(6),
                Json::Array(values) => {
                    for v in values {
                        size = size
                            .checked_add(bound(v, budget)?)
                            .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "JSON bound"))?;
                    }
                    Some(0)
                }
                Json::Object(values) => {
                    for (k, v) in values {
                        size =
                            size.checked_add(k.len().checked_mul(6).ok_or_else(|| {
                                Error::resource("ABI_CC_GRAPH_LIMIT", "JSON key")
                            })?)
                            .and_then(|n| n.checked_add(16))
                            .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "JSON object"))?;
                        size = size
                            .checked_add(bound(v, budget)?)
                            .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "JSON value"))?;
                    }
                    Some(0)
                }
                _ => Some(0),
            }
            .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "JSON bound"))?;
        size.checked_add(add)
            .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "JSON bound"))
    }
    let cap = bound(value, budget)?
        .checked_mul(2)
        .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "JSON buffers"))?;
    budget.reserve_bytes(cap)?;
    let source = serde_json::to_string(value)
        .map_err(|e| Error::semantic("ABI_CC_CANONICAL", e.to_string()))?;
    budget.work(source.len() as u64)?;
    let mut result = Vec::new();
    for ch in source.chars() {
        if ch.is_ascii() {
            result.push(ch as u8);
        } else {
            for word in ch.encode_utf16(&mut [0; 2]).iter() {
                result.extend_from_slice(format!("\\u{word:04x}").as_bytes());
            }
        }
    }
    Ok(result)
}

/// Bisimulation refinement followed by canonical root BFS; node IDs erased.
pub(crate) fn canonical_quotient(
    labels: &[Json],
    edges: &[Vec<usize>],
    budget: &mut Budget,
) -> Result<Vec<u8>, Error> {
    require(
        !labels.is_empty() && labels.len() == edges.len(),
        "ABI_CC_GRAPH",
    )?;
    let encoded = labels
        .iter()
        .map(|label| ascii_json(label, budget))
        .collect::<Result<Vec<_>, _>>()?;
    budget.reserve_bytes(
        labels
            .len()
            .checked_mul(256)
            .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "quotient indexes"))?,
    )?;
    let height = (usize::BITS - labels.len().max(1).leading_zeros()) as usize * 2 + 2;
    let max_label = encoded.iter().map(Vec::len).max().unwrap_or(0);
    let max_edges = edges.iter().map(Vec::len).max().unwrap_or(0);
    let comparison_work = labels
        .len()
        .checked_mul(height)
        .and_then(|n| n.checked_mul(max_label.checked_add(max_edges)?.checked_add(1)?))
        .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "quotient comparisons"))?;
    budget.work(comparison_work as u64)?;
    let names: BTreeSet<&[u8]> = encoded.iter().map(Vec::as_slice).collect();
    let names: BTreeMap<&[u8], usize> = names
        .into_iter()
        .enumerate()
        .map(|(i, label)| (label, i))
        .collect();
    let mut colors = encoded
        .iter()
        .map(|label| names[label.as_slice()])
        .collect::<Vec<_>>();
    loop {
        budget.work(comparison_work as u64)?;
        budget.work((labels.len() + edges.iter().map(Vec::len).sum::<usize>()) as u64)?;
        let edge_count = edges
            .iter()
            .map(Vec::len)
            .try_fold(0usize, usize::checked_add)
            .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "refinement edges"))?;
        budget.reserve_bytes(
            labels
                .len()
                .checked_mul(256)
                .and_then(|n| edge_count.checked_mul(16).and_then(|m| n.checked_add(m)))
                .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "refinement"))?,
        )?;
        let mut signatures = Vec::new();
        for (label, children) in encoded.iter().zip(edges) {
            require(
                children.iter().all(|index| *index < colors.len()),
                "ABI_CC_GRAPH_EDGE",
            )?;
            signatures.push((
                label.as_slice(),
                children
                    .iter()
                    .map(|index| colors[*index])
                    .collect::<Vec<_>>(),
            ));
        }
        let classes: BTreeSet<_> = signatures.iter().collect();
        let names: BTreeMap<_, _> = classes
            .into_iter()
            .enumerate()
            .map(|(i, sig)| (sig, i))
            .collect();
        let updated = signatures.iter().map(|sig| names[sig]).collect::<Vec<_>>();
        let stable = updated.iter().copied().collect::<BTreeSet<_>>().len()
            == colors.iter().copied().collect::<BTreeSet<_>>().len();
        colors = updated;
        if stable {
            break;
        }
    }
    let mut representatives = BTreeMap::new();
    for (index, color) in colors.iter().enumerate() {
        representatives.entry(*color).or_insert(index);
    }
    let mut order = vec![colors[0]];
    let mut indices = BTreeMap::from([(colors[0], 0)]);
    let mut records = Vec::new();
    let mut cursor = 0;
    while cursor < order.len() {
        budget.work(1)?;
        let node = representatives[&order[cursor]];
        let mut children = Vec::new();
        for child in &edges[node] {
            let next = order.len();
            let index = *indices.entry(colors[*child]).or_insert_with(|| {
                order.push(colors[*child]);
                next
            });
            children.push(Json::from(index as u64));
        }
        reserve_json_clone(&labels[node], budget)?;
        records.push(Json::Object(Map::from_iter([
            ("label".into(), labels[node].clone()),
            ("children".into(), Json::Array(children)),
        ])));
        cursor += 1;
    }
    ascii_json(&Json::Array(records), budget)
}

fn reserve_json_clone(value: &Json, budget: &mut Budget) -> Result<(), Error> {
    budget.work(1)?;
    budget.reserve_bytes(256)?;
    match value {
        Json::String(value) => budget.reserve_bytes(value.len())?,
        Json::Array(values) => {
            for value in values {
                reserve_json_clone(value, budget)?;
            }
        }
        Json::Object(values) => {
            for (key, value) in values {
                budget.reserve_bytes(key.len())?;
                reserve_json_clone(value, budget)?;
            }
        }
        _ => {}
    }
    Ok(())
}
