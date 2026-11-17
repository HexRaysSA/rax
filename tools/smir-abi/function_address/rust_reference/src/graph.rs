//! Raw source validation and V3 projection; no Python/preimage/digest input.

use crate::canonical::{Budget, Result, exact, object, quotient, require, semantic};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const DOMAIN: &[u8] = b"SMIR-NOMINAL-SHAPE-V3\0";
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
const EXPR: &[&str] = &[
    "code",
    "variadic",
    "noexcept",
    "c_linkage",
    "lvalue_ref",
    "rvalue_ref",
];

type Fields = &'static [(&'static str, &'static str)];
fn fields(name: &str) -> Fields {
    match name {
        "fragment" => &[
            ("types", "v:type"),
            ("layouts", "v:layout"),
            ("domains", "v:domain"),
        ],
        "qref" => &[("module", "module"), ("id", "u32")],
        "identity" => &[
            ("language", "token"),
            ("linkage", "token"),
            ("entity", "utf8"),
            ("definition", "digest"),
            ("library", "o:digest"),
            ("unit", "o:digest"),
        ],
        "method" => &[
            ("name", "utf8"),
            ("signature", "qref"),
            ("virtual", "bool"),
            ("slot", "o:u32"),
            ("noexcept", "bool"),
        ],
        "enumerator" => &[("name", "utf8"), ("value", "hex")],
        "type" => &[
            ("id", "u32"),
            ("domain", "u32"),
            ("identity", "identity"),
            ("kind", "token"),
            ("qualifiers", "v:token"),
            ("bits", "u32"),
            ("signed", "bool"),
            ("elements", "v:qref"),
            ("extent", "o:u64"),
            ("representation", "token"),
            ("execution", "o:qref"),
            ("layout", "o:u32"),
            ("flags", "v:token"),
            ("methods", "v:method"),
            ("enumerators", "v:enumerator"),
            ("record_input", "o:input"),
        ],
        "input" => &[
            ("revision", "u32"),
            ("kind", "token"),
            ("explicit_align", "o:u32"),
            ("pod03", "bool"),
            ("trivial", "bool"),
            ("standard_layout", "bool"),
            ("polymorphic", "bool"),
            ("dynamic", "bool"),
            ("empty", "bool"),
            ("fields", "v:input_field"),
            ("bases", "v:input_base"),
        ],
        "input_field" => &[
            ("name", "o:utf8"),
            ("type", "qref"),
            ("bit_width", "o:u64"),
            ("explicit_align", "o:u32"),
            ("no_unique_address", "bool"),
            ("anonymous", "bool"),
            ("access", "token"),
        ],
        "input_base" => &[("type", "qref"), ("virtual", "bool"), ("access", "token")],
        "layout" => &[
            ("id", "u32"),
            ("type", "qref"),
            ("size", "u64"),
            ("align", "u32"),
            ("data_size", "u64"),
            ("nonvirtual_size", "u64"),
            ("nonvirtual_align", "u32"),
            ("fields", "v:field"),
            ("bases", "v:base"),
            ("vptrs", "v:vptr"),
        ],
        "field" => &[
            ("declaration_index", "u32"),
            ("name", "utf8"),
            ("type", "qref"),
            ("offset_bits", "u64"),
            ("width_bits", "u64"),
            ("flags", "v:token"),
        ],
        "base" => &[
            ("type", "qref"),
            ("offset", "u64"),
            ("virtual", "bool"),
            ("declaration_index", "o:u32"),
            ("origin_path", "v:u32"),
            ("adjustment", "adjustment"),
        ],
        "vptr" => &[
            ("offset", "u64"),
            ("offset_top", "i64"),
            ("rtti", "o:qref"),
            ("slots", "v:qref"),
            ("vcall_offsets", "v:i64"),
            ("vbase_offsets", "v:i64"),
            ("component_order", "v:token"),
        ],
        "domain" => &[
            ("id", "u32"),
            ("isa", "token"),
            ("personality", "token"),
            ("abi", "token"),
            ("compiler", "digest"),
            ("runtime", "digest"),
            ("build", "digest"),
            ("library", "digest"),
            ("abi_identity", "digest"),
        ],
        _ => &[],
    }
}
fn text(v: &Value) -> Result<&str> {
    v.as_str().ok_or_else(|| semantic("HASH3_SHAPE"))
}
fn list(v: &Value) -> Result<&Vec<Value>> {
    v.as_array().ok_or_else(|| semantic("HASH3_SHAPE"))
}
fn uint(v: &Value) -> Result<u64> {
    v.as_u64().ok_or_else(|| semantic("HASH3_INTEGER"))
}
fn id(v: &Value) -> Result<u32> {
    let n = uint(v)?;
    require(n < 0xffff_ffff, "HASH3_ID")?;
    Ok(n as u32)
}
fn opt(v: &Value) -> Option<&Value> {
    if v.is_null() { None } else { Some(&v["some"]) }
}
fn has(v: &Value, flag: &str) -> bool {
    v["flags"]
        .as_array()
        .is_some_and(|a| a.iter().any(|f| f.as_str() == Some(flag)))
}
fn alignment(v: &Value) -> Result<()> {
    let n = uint(v)?;
    require(
        n > 0 && n <= 65536 && n.is_power_of_two(),
        "HASH3_ALIGNMENT",
    )
}

fn validate(kind: &str, v: &Value, b: &mut Budget, depth: u64) -> Result<()> {
    b.depth(depth)?;
    b.charge(1, 0, 0)?;
    if let Some(child) = kind.strip_prefix("o:") {
        if v.is_null() {
            return Ok(());
        }
        exact(v, &["some"])?;
        return validate(child, &v["some"], b, depth + 1);
    }
    if let Some(child) = kind.strip_prefix("v:") {
        let rows = list(v)?;
        b.charge(rows.len() as u64, rows.len() as u64, 0)?;
        for value in rows {
            validate(child, value, b, depth + 1)?;
        }
        return Ok(());
    }
    if matches!(kind, "u32" | "u64" | "i64") {
        let valid = match kind {
            "u32" => v.as_u64().is_some_and(|n| n <= u32::MAX as u64),
            "u64" => v.as_u64().is_some(),
            _ => v.as_i64().is_some(),
        };
        return require(valid, "HASH3_INTEGER");
    }
    if kind == "bool" {
        return require(v.is_boolean(), "HASH3_SHAPE");
    }
    if matches!(kind, "token" | "utf8" | "digest" | "hex") {
        let s = text(v)?;
        b.charge(s.len() as u64 * 4, 0, 0)?;
        if kind == "token" {
            require(
                !s.is_empty()
                    && s.bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c)),
                "HASH3_TOKEN",
            )?;
        }
        if matches!(kind, "digest" | "hex") {
            require(
                s.len() % 2 == 0 && s.bytes().all(|c| b"0123456789abcdef".contains(&c)),
                "HASH3_HEX",
            )?;
        }
        if kind == "digest" {
            require(s.len() == 64, "HASH3_DIGEST")?;
        }
        return Ok(());
    }
    if kind == "module" {
        match text(&v["kind"])? {
            "self" => exact(v, &["kind"]),
            "dependency" => {
                exact(v, &["kind", "slot"])?;
                id(&v["slot"])?;
                Ok(())
            }
            _ => Err(semantic("HASH3_VARIANT")),
        }?;
        return Ok(());
    }
    if kind == "adjustment" {
        let rows: Fields = match text(&v["kind"])? {
            "fixed" => &[("kind", "token"), ("offset", "i64")],
            "virtual" => &[
                ("kind", "token"),
                ("vptr_offset", "u64"),
                ("slot_bytes", "i64"),
                ("addend", "i64"),
            ],
            _ => return Err(semantic("HASH3_VARIANT")),
        };
        return validate_fields(v, rows, b, depth);
    }
    let rows = fields(kind);
    require(!rows.is_empty(), "HASH3_INTERNAL_SCHEMA")?;
    validate_fields(v, rows, b, depth)?;
    if kind == "qref" {
        id(&v["id"])?;
    }
    Ok(())
}
fn validate_fields(v: &Value, rows: Fields, b: &mut Budget, depth: u64) -> Result<()> {
    b.charge(rows.len() as u64, rows.len() as u64, rows.len() as u64 * 8)?;
    let names: Vec<_> = rows.iter().map(|(name, _)| *name).collect();
    exact(v, &names)?;
    for (name, kind) in rows {
        validate(kind, &v[*name], b, depth + 1)?;
    }
    Ok(())
}

struct Module<'a> {
    types: BTreeMap<u32, &'a Value>,
    layouts: BTreeMap<u32, &'a Value>,
    domains: BTreeMap<u32, &'a Value>,
}
pub struct Graph<'a> {
    modules: BTreeMap<&'a str, Module<'a>>,
    expectations: BTreeMap<(&'a str, u32, u32), u32>,
}
fn table<'a>(v: &'a Value, b: &mut Budget) -> Result<BTreeMap<u32, &'a Value>> {
    let rows = list(v)?;
    b.charge(rows.len() as u64, 0, rows.len() as u64 * 128)?;
    let mut result = BTreeMap::new();
    for row in rows {
        require(
            result.insert(id(&row["id"])?, row).is_none(),
            "HASH3_DUPLICATE_ID",
        )?;
    }
    Ok(result)
}
impl<'a> Graph<'a> {
    pub fn new(request: &'a Value, b: &mut Budget) -> Result<Self> {
        exact(
            request,
            &[
                "documents",
                "expectations",
                "owner",
                "root",
                "view",
                "ignore_top_cv",
            ],
        )?;
        let docs = request["documents"]
            .as_object()
            .ok_or_else(|| semantic("HASH3_SHAPE"))?;
        b.charge(docs.len() as u64, 0, docs.len() as u64 * 256)?;
        let mut modules = BTreeMap::new();
        for (owner, fragment) in docs {
            require(!owner.is_empty(), "HASH3_OWNER")?;
            validate("fragment", fragment, b, 1)?;
            modules.insert(
                owner.as_str(),
                Module {
                    types: table(&fragment["types"], b)?,
                    layouts: table(&fragment["layouts"], b)?,
                    domains: table(&fragment["domains"], b)?,
                },
            );
        }
        let mut expectations = BTreeMap::new();
        for row in list(&request["expectations"])? {
            exact(row, &["owner", "slot", "declaration", "target"])?;
            let owner = text(&row["owner"])?;
            let slot = id(&row["slot"])?;
            let declaration = id(&row["declaration"])?;
            let target = id(&row["target"])?;
            require(modules.contains_key(owner), "HASH3_OWNER")?;
            require(
                modules[owner].types.contains_key(&target),
                "HASH3_REFERENCE",
            )?;
            b.charge(1, 0, 128)?;
            require(
                expectations
                    .insert((owner, slot, declaration), target)
                    .is_none(),
                "HASH3_EXPECTATION",
            )?;
        }
        let graph = Self {
            modules,
            expectations,
        };
        graph.validate(b)?;
        Ok(graph)
    }
    fn resolve(&self, owner: &str, reference: &Value, b: &mut Budget) -> Result<u32> {
        b.charge(1, 0, 0)?;
        let module = self
            .modules
            .get(owner)
            .ok_or_else(|| semantic("HASH3_OWNER"))?;
        let mut target = id(&reference["id"])?;
        if reference["module"]["kind"] == "dependency" {
            target = *self
                .expectations
                .get(&(owner, id(&reference["module"]["slot"])?, target))
                .ok_or_else(|| semantic("HASH3_UNBOUND_DECLARATION"))?;
        }
        require(module.types.contains_key(&target), "HASH3_REFERENCE")?;
        Ok(target)
    }
    fn typ(&self, owner: &str, reference: &Value, b: &mut Budget) -> Result<&'a Value> {
        Ok(self.modules[owner].types[&self.resolve(owner, reference, b)?])
    }
    fn validate(&self, b: &mut Budget) -> Result<()> {
        let kinds = [
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
        for (owner, module) in &self.modules {
            for item in module.types.values() {
                b.charge(1, 0, 256)?;
                let kind = text(&item["kind"])?;
                require(kinds.contains(&kind), "HASH3_KIND_FLAGS")?;
                let flags = list(&item["flags"])?;
                b.charge(flags.len() as u64, 0, flags.len() as u64 * 64)?;
                let flagset: BTreeSet<_> = flags.iter().map(text).collect::<Result<_>>()?;
                require(
                    flagset.len() == flags.len() && flagset.iter().all(|f| FLAGS.contains(f)),
                    "HASH3_KIND_FLAGS",
                )?;
                require(
                    item["signed"] == false || matches!(kind, "scalar" | "bitint" | "enum"),
                    "HASH3_SIGNEDNESS",
                )?;
                let qualifiers = list(&item["qualifiers"])?;
                let names: Vec<_> = qualifiers.iter().map(text).collect::<Result<_>>()?;
                require(
                    names
                        .iter()
                        .all(|q| ["const", "volatile", "restrict"].contains(q))
                        && names.windows(2).all(|w| w[0] < w[1]),
                    "HASH3_QUALIFIERS",
                )?;
                let domain = module
                    .domains
                    .get(&id(&item["domain"])?)
                    .ok_or_else(|| semantic("HASH3_DOMAIN"))?;
                let identity = &item["identity"];
                require(
                    ["c23", "cpp23"].contains(&text(&identity["language"])?)
                        && !text(&identity["entity"])?.is_empty()
                        && ["builtin", "external", "internal", "local", "odr_local"]
                            .contains(&text(&identity["linkage"])?),
                    "HASH3_IDENTITY",
                )?;
                require(
                    opt(&identity["unit"]).is_some()
                        == ["internal", "local"].contains(&text(&identity["linkage"])?),
                    "HASH3_UNIT",
                )?;
                if [
                    "pointer",
                    "reference",
                    "member_pointer",
                    "function",
                    "array",
                    "vector",
                    "complex",
                    "atomic",
                    "bitint",
                ]
                .contains(&kind)
                {
                    require(
                        identity["entity"] == kind && identity["linkage"] == "builtin",
                        "HASH3_CONSTRUCTOR",
                    )?;
                }
                for (flag, allowed) in [
                    ("union", &["record"][..]),
                    ("class", &["record"][..]),
                    ("polymorphic", &["record"][..]),
                    ("noexcept", &["function"][..]),
                    ("variadic", &["function"][..]),
                    ("c_linkage", &["function"][..]),
                    ("code", &["pointer", "reference"][..]),
                    ("flexible", &["array"][..]),
                    ("scoped", &["enum"][..]),
                    ("fixed_base", &["enum"][..]),
                    ("signed_char", &["scalar"][..]),
                    ("c_compatible", &["record", "enum"][..]),
                ] {
                    require(
                        !has(item, flag) || allowed.contains(&kind),
                        "HASH3_KIND_FLAGS",
                    )?;
                }
                let refs =
                    usize::from(has(item, "lvalue_ref")) + usize::from(has(item, "rvalue_ref"));
                require(
                    if kind == "reference" {
                        refs == 1
                    } else if kind == "function" {
                        refs <= 1
                    } else {
                        refs == 0
                    },
                    "HASH3_REFERENCE_CATEGORY",
                )?;
                require(!has(item, "c_linkage") || refs == 0, "HASH3_KIND_FLAGS")?;
                let elements = list(&item["elements"])?;
                b.charge(elements.len() as u64, 0, elements.len() as u64 * 8)?;
                let children: Vec<_> = elements
                    .iter()
                    .map(|r| self.typ(owner, r, b))
                    .collect::<Result<_>>()?;
                let count = opt(&item["extent"]).map(uint).transpose()?;
                match kind {
                    "pointer" | "reference" | "array" | "vector" | "complex" | "atomic"
                    | "enum" => require(children.len() == 1, "HASH3_ARITY")?,
                    "member_pointer" => require(
                        children.len() == 2 && children[0]["kind"] == "record",
                        "HASH3_ARITY",
                    )?,
                    "function" => {
                        require(
                            count.is_some_and(|n| n == children.len().saturating_sub(1) as u64)
                                && !children.is_empty(),
                            "HASH3_ARITY",
                        )?;
                        require(
                            children[..children.len() - 1].iter().all(|t| {
                                !["void", "function", "array"]
                                    .contains(&t["kind"].as_str().unwrap_or(""))
                            }) && !["function", "array"]
                                .contains(&children.last().unwrap()["kind"].as_str().unwrap_or("")),
                            "HASH3_FUNCTION",
                        )?;
                    }
                    "record" => {}
                    _ => require(children.is_empty(), "HASH3_ARITY")?,
                }
                if !["array", "vector", "function"].contains(&kind) {
                    require(count.is_none(), "HASH3_EXTENT")?;
                }
                if kind == "vector" {
                    require(count.is_some_and(|n| n > 0), "HASH3_EXTENT")?;
                }
                if ["pointer", "reference"].contains(&kind) {
                    require(
                        item["bits"] == 64
                            && has(item, "code") == (children[0]["kind"] == "function"),
                        "HASH3_POINTER",
                    )?;
                }
                if kind == "bitint" {
                    let bits = uint(&item["bits"])?;
                    require(
                        bits >= if item["signed"] == true { 2 } else { 1 } && bits <= 65535,
                        "HASH3_BITINT",
                    )?;
                }
                let complete = has(item, "complete");
                let layout = opt(&item["layout"]).map(id).transpose()?;
                if ["void", "function"].contains(&kind) {
                    require(layout.is_none(), "HASH3_NONOBJECT_LAYOUT")?;
                }
                if ["record", "array"].contains(&kind) && !complete {
                    require(
                        layout.is_none()
                            && item["record_input"].is_null()
                            && item["execution"].is_null()
                            && item["representation"] == "none",
                        "HASH3_INCOMPLETE",
                    )?;
                }
                if kind == "array" {
                    require(count.is_none_or(|n| n > 0), "HASH3_EXTENT")?;
                    require(
                        complete
                            == (count.is_some()
                                && has(children[0], "complete")
                                && opt(&children[0]["layout"]).is_some()),
                        "HASH3_ARRAY_COMPLETENESS",
                    )?;
                }
                require(
                    !complete || ["void", "function"].contains(&kind) || layout.is_some(),
                    "HASH3_LAYOUT_BINDING",
                )?;
                if let Some(lid) = layout {
                    let l = module
                        .layouts
                        .get(&lid)
                        .ok_or_else(|| semantic("HASH3_LAYOUT_BINDING"))?;
                    require(
                        self.resolve(owner, &l["type"], b)? == id(&item["id"])?,
                        "HASH3_LAYOUT_BINDING",
                    )?;
                }
                if kind != "record" {
                    require(
                        item["record_input"].is_null() && list(&item["methods"])?.is_empty(),
                        "HASH3_RECORD_INPUT",
                    )?;
                }
                if kind == "record" && complete && domain["isa"] == "portable" {
                    require(!item["record_input"].is_null(), "HASH3_RECORD_INPUT")?;
                }
                if let Some(input) = opt(&item["record_input"]) {
                    require(
                        input["revision"] == 1
                            && ["struct", "class", "union"].contains(&text(&input["kind"])?),
                        "HASH3_RECORD_INPUT",
                    )?;
                    require(
                        has(item, "union") == (input["kind"] == "union")
                            && has(item, "class") == (input["kind"] == "class")
                            && has(item, "polymorphic") == (input["polymorphic"] == true),
                        "HASH3_RECORD_INPUT",
                    )?;
                    if let Some(a) = opt(&input["explicit_align"]) {
                        alignment(a)?;
                    }
                    for f in list(&input["fields"])? {
                        self.typ(owner, &f["type"], b)?;
                        require(
                            ["public", "protected", "private"].contains(&text(&f["access"])?),
                            "HASH3_ACCESS",
                        )?;
                        if let Some(a) = opt(&f["explicit_align"]) {
                            alignment(a)?;
                        }
                    }
                    for base in list(&input["bases"])? {
                        require(
                            self.typ(owner, &base["type"], b)?["kind"] == "record"
                                && ["public", "protected", "private"]
                                    .contains(&text(&base["access"])?),
                            "HASH3_BASE",
                        )?;
                    }
                }
                if identity["language"] == "c23" {
                    require(list(&item["methods"])?.is_empty(), "HASH3_METHOD")?;
                }
                for method in list(&item["methods"])? {
                    let function = self.typ(owner, &method["signature"], b)?;
                    require(
                        function["kind"] == "function"
                            && opt(&method["slot"]).is_some() == (method["virtual"] == true)
                            && (method["noexcept"] == true) == has(function, "noexcept"),
                        "HASH3_METHOD",
                    )?;
                }
                let enumerators = list(&item["enumerators"])?;
                require(enumerators.is_empty() || kind == "enum", "HASH3_ENUM")?;
                if kind == "enum" {
                    require(
                        ["scalar", "bitint"].contains(&text(&children[0]["kind"])?)
                            && item["bits"] == children[0]["bits"]
                            && item["signed"] == children[0]["signed"],
                        "HASH3_ENUM",
                    )?;
                    let mut seen = BTreeSet::new();
                    let bits = uint(&item["bits"])?;
                    for entry in enumerators {
                        let value = text(&entry["value"])?;
                        let name = text(&entry["name"])?;
                        b.charge((value.len() + name.len()) as u64, 0, 64)?;
                        require(
                            seen.insert(name) && value.len() as u64 == 2 * bits.div_ceil(8),
                            "HASH3_ENUM",
                        )?;
                        if bits % 8 != 0 {
                            require(
                                value.len() >= 2
                                    && u8::from_str_radix(&value[value.len() - 2..], 16)
                                        .map_err(|_| semantic("HASH3_ENUM"))?
                                        < (1u8 << (bits % 8)),
                                "HASH3_ENUM",
                            )?;
                        }
                    }
                }
                require(
                    ["none", "value", "storage", "signature", "code_address"]
                        .contains(&text(&item["representation"])?),
                    "HASH3_REPRESENTATION",
                )?;
                require(
                    item["execution"].is_null() == (item["representation"] == "none"),
                    "HASH3_REPRESENTATION",
                )?;
            }
            for layout in module.layouts.values() {
                let item = self.typ(owner, &layout["type"], b)?;
                require(
                    opt(&item["layout"]) == Some(&layout["id"]),
                    "HASH3_LAYOUT_BINDING",
                )?;
                alignment(&layout["align"])?;
                alignment(&layout["nonvirtual_align"])?;
                let size = uint(&layout["size"])?;
                require(
                    size > 0
                        && size < (1u64 << 61)
                        && size % uint(&layout["align"])? == 0
                        && uint(&layout["data_size"])? <= size
                        && uint(&layout["nonvirtual_size"])? <= size,
                    "HASH3_LAYOUT_EXTENT",
                )?;
                if module.domains[&id(&item["domain"])?]["isa"] == "portable"
                    && item["kind"] != "record"
                {
                    require(
                        ["fields", "bases", "vptrs"]
                            .iter()
                            .all(|k| layout[*k].as_array().is_some_and(Vec::is_empty)),
                        "HASH3_NONRECORD_LAYOUT",
                    )?;
                }
                for field in list(&layout["fields"])? {
                    self.typ(owner, &field["type"], b)?;
                    require(
                        uint(&field["offset_bits"])?
                            .checked_add(uint(&field["width_bits"])?)
                            .is_some_and(|n| n <= 8 * size),
                        "HASH3_FIELD_EXTENT",
                    )?;
                    let flags = list(&field["flags"])?;
                    b.charge(flags.len() as u64, 0, flags.len() as u64 * 64)?;
                    let values: BTreeSet<_> = flags.iter().map(text).collect::<Result<_>>()?;
                    require(
                        values.len() == flags.len()
                            && values.iter().all(|s| {
                                [
                                    "bitfield",
                                    "unnamed",
                                    "anonymous",
                                    "no_unique_address",
                                    "protected",
                                    "private",
                                    "flexible",
                                ]
                                .contains(s)
                            }),
                        "HASH3_FIELD_FLAGS",
                    )?;
                }
                for base in list(&layout["bases"])? {
                    require(
                        self.typ(owner, &base["type"], b)?["kind"] == "record"
                            && uint(&base["offset"])? <= size,
                        "HASH3_BASE",
                    )?;
                }
                for ptr in list(&layout["vptrs"])? {
                    let order = list(&ptr["component_order"])?;
                    require(
                        order.iter().all(|k| k == "vcall" || k == "vbase")
                            && order.iter().filter(|k| *k == "vcall").count()
                                == list(&ptr["vcall_offsets"])?.len()
                            && order.iter().filter(|k| *k == "vbase").count()
                                == list(&ptr["vbase_offsets"])?.len(),
                        "HASH3_VPTR",
                    )?;
                }
            }
            self.value_cycles(owner, b)?;
        }
        Ok(())
    }
    fn value_cycles(&self, owner: &str, b: &mut Budget) -> Result<()> {
        let module = &self.modules[owner];
        let mut done = BTreeSet::new();
        let mut active = BTreeSet::new();
        for root in module.types.keys() {
            b.charge(1, 0, 64)?;
            let mut stack = vec![(*root, false, 1u64)];
            while let Some((current, leave, depth)) = stack.pop() {
                b.charge(1, 0, 128)?;
                if leave {
                    active.remove(&current);
                    done.insert(current);
                    continue;
                }
                if done.contains(&current) {
                    continue;
                }
                require(!active.contains(&current), "HASH3_VALUE_CYCLE")?;
                b.depth(depth)?;
                active.insert(current);
                stack.push((current, true, depth));
                let item = module.types[&current];
                if ["array", "vector", "atomic", "enum", "complex"].contains(&text(&item["kind"])?)
                {
                    for reference in list(&item["elements"])? {
                        b.charge(1, 1, 32)?;
                        stack.push((self.resolve(owner, reference, b)?, false, depth + 1));
                    }
                } else if item["kind"] == "record" {
                    if let Some(lid) = opt(&item["layout"]) {
                        let layout = module.layouts[&id(lid)?];
                        for name in ["fields", "bases"] {
                            for field in list(&layout[name])? {
                                b.charge(1, 1, 32)?;
                                stack.push((
                                    self.resolve(owner, &field["type"], b)?,
                                    false,
                                    depth + 1,
                                ));
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn projection(
        &self,
        owner: &str,
        item: &Value,
        definition: bool,
        b: &mut Budget,
    ) -> Result<(Value, Vec<(u32, bool)>)> {
        b.charge(1, 0, 2048)?;
        let mut identity = serde_json::Map::new();
        for key in ["language", "linkage", "entity", "library", "unit"] {
            identity.insert(key.to_owned(), copied(&item["identity"][key], b)?);
        }
        let mut label = object([
            ("kind", copied(&item["kind"], b)?),
            ("qualifiers", copied(&item["qualifiers"], b)?),
            ("identity", Value::Object(identity)),
            (
                "abi_identity",
                copied(
                    &self.modules[owner].domains[&id(&item["domain"])?]["abi_identity"],
                    b,
                )?,
            ),
        ]);
        let kind = text(&item["kind"])?;
        if !definition && ["record", "enum"].contains(&kind) {
            label["node_kind"] = Value::from("nominal_declaration");
            return Ok((label, Vec::new()));
        }
        for key in ["bits", "signed", "extent"] {
            label[key] = copied(&item[key], b)?;
        }
        let mut edges = Vec::new();
        let elements = list(&item["elements"])?;
        b.charge(
            elements.len() as u64,
            elements.len() as u64,
            elements.len() as u64 * 16,
        )?;
        label["element_count"] = Value::from(elements.len() as u64);
        let child_definition =
            definition && !["pointer", "reference", "member_pointer", "function"].contains(&kind);
        for child in elements {
            edges.push((self.resolve(owner, child, b)?, child_definition));
        }
        if !definition {
            label["node_kind"] = Value::from("nominal_expression");
            label["semantic_flags"] = sorted(&item["flags"], Some(EXPR), b)?;
            return Ok((label, edges));
        }
        label["node_kind"] = Value::from("nominal_definition");
        label["flags"] = sorted(&item["flags"], None, b)?;
        label["enumerators"] = copied(&item["enumerators"], b)?;
        label["has_cpp_class"] = Value::Bool(false);
        let methods = list(&item["methods"])?;
        b.charge(
            methods.len() as u64,
            methods.len() as u64,
            methods.len() as u64 * 256,
        )?;
        let mut method_labels = Vec::new();
        for method in methods {
            method_labels.push(project(
                method,
                &["name", "virtual", "slot", "noexcept"],
                b,
            )?);
            edges.push((self.resolve(owner, &method["signature"], b)?, false));
        }
        label["methods"] = Value::Array(method_labels);
        label["method_count"] = Value::from(methods.len() as u64);
        label["record_input"] = Value::Null;
        label["layout"] = Value::Null;
        for key in [
            "input_field_count",
            "input_base_count",
            "output_field_count",
            "output_base_count",
        ] {
            label[key] = Value::from(0);
        }
        if let Some(input) = opt(&item["record_input"]) {
            let mut input_label = project(
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
                b,
            )?;
            for (name, keys, count) in [
                (
                    "fields",
                    &[
                        "name",
                        "bit_width",
                        "explicit_align",
                        "no_unique_address",
                        "anonymous",
                        "access",
                    ][..],
                    "input_field_count",
                ),
                ("bases", &["virtual", "access"][..], "input_base_count"),
            ] {
                let rows = list(&input[name])?;
                b.charge(rows.len() as u64, rows.len() as u64, rows.len() as u64 * 64)?;
                let mut labels = Vec::new();
                for row in rows {
                    labels.push(project(row, keys, b)?);
                    edges.push((self.resolve(owner, &row["type"], b)?, true));
                }
                input_label[name] = Value::Array(labels);
                label[count] = Value::from(rows.len() as u64);
            }
            label["record_input"] = input_label;
        }
        if let Some(lid) = opt(&item["layout"]) {
            let layout = self.modules[owner].layouts[&id(lid)?];
            let mut layout_label = project(
                layout,
                &[
                    "size",
                    "align",
                    "data_size",
                    "nonvirtual_size",
                    "nonvirtual_align",
                ],
                b,
            )?;
            for (name, keys, count) in [
                (
                    "fields",
                    &["declaration_index", "name", "offset_bits", "width_bits"][..],
                    "output_field_count",
                ),
                (
                    "bases",
                    &[
                        "offset",
                        "virtual",
                        "declaration_index",
                        "origin_path",
                        "adjustment",
                    ][..],
                    "output_base_count",
                ),
            ] {
                let rows = list(&layout[name])?;
                b.charge(rows.len() as u64, rows.len() as u64, rows.len() as u64 * 64)?;
                let mut labels = Vec::new();
                for row in rows {
                    let mut projected = project(row, keys, b)?;
                    if name == "fields" {
                        projected["flags"] = sorted(&row["flags"], None, b)?;
                    }
                    labels.push(projected);
                    edges.push((self.resolve(owner, &row["type"], b)?, true));
                }
                layout_label[name] = Value::Array(labels);
                label[count] = Value::from(rows.len() as u64);
            }
            let rows = list(&layout["vptrs"])?;
            b.charge(rows.len() as u64, 0, rows.len() as u64 * 128)?;
            let mut labels = Vec::new();
            for row in rows {
                let mut projected = project(
                    row,
                    &[
                        "offset",
                        "offset_top",
                        "vcall_offsets",
                        "vbase_offsets",
                        "component_order",
                    ],
                    b,
                )?;
                projected["slot_count"] = Value::from(list(&row["slots"])?.len() as u64);
                labels.push(projected);
            }
            layout_label["vptrs"] = Value::Array(labels);
            label["layout"] = layout_label;
        }
        Ok((label, edges))
    }

    pub fn hash(&self, request: &Value, b: &mut Budget) -> Result<Output> {
        let owner = text(&request["owner"])?;
        validate("qref", &request["root"], b, 1)?;
        let definition = match text(&request["view"])? {
            "DEF" => true,
            "EXPR" => false,
            _ => return Err(semantic("HASH3_VIEW")),
        };
        let ignore = request["ignore_top_cv"]
            .as_bool()
            .ok_or_else(|| semantic("HASH3_VIEW"))?;
        let identifier = self.resolve(owner, &request["root"], b)?;
        b.nodes(1)?;
        b.charge(1, 0, 256)?;
        let mut queue = vec![(identifier, definition, 1u64)];
        let mut indices = BTreeMap::from([((identifier, definition), 0usize)]);
        let mut labels = Vec::new();
        let mut links = Vec::new();
        let mut cursor = 0;
        while cursor < queue.len() {
            b.charge(1, 0, 128)?;
            let (identifier, mode, depth) = queue[cursor];
            let (mut label, children) =
                self.projection(owner, self.modules[owner].types[&identifier], mode, b)?;
            if cursor == 0 && ignore {
                let qualifiers = list(&label["qualifiers"])?;
                b.charge(qualifiers.len() as u64, 0, qualifiers.len() as u64 * 64)?;
                label["qualifiers"] = Value::Array(
                    qualifiers
                        .iter()
                        .filter(|q| **q != "const" && **q != "volatile")
                        .cloned()
                        .collect(),
                );
            }
            b.charge(
                children.len() as u64,
                children.len() as u64,
                children.len() as u64 * 16,
            )?;
            let mut edges = Vec::new();
            for (child, child_mode) in children {
                let key = (child, child_mode);
                let index = if let Some(index) = indices.get(&key) {
                    *index
                } else {
                    b.nodes(queue.len() + 1)?;
                    b.depth(depth + 1)?;
                    b.charge(1, 0, 256)?;
                    let index = queue.len();
                    indices.insert(key, index);
                    queue.push((child, child_mode, depth + 1));
                    index
                };
                edges.push(index);
            }
            labels.push(label);
            links.push(edges);
            cursor += 1;
        }
        let encoded = quotient(&labels, &links, b)?;
        let length = DOMAIN
            .len()
            .checked_add(encoded.len())
            .ok_or_else(|| crate::canonical::resource("HASH3_OUTPUT"))?;
        b.output(length)?;
        b.charge(length as u64, 0, length as u64 + 96)?;
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update(&encoded);
        let mut preimage = Vec::with_capacity(length);
        preimage.extend_from_slice(DOMAIN);
        preimage.extend_from_slice(&encoded);
        let digest = hash.finalize();
        let mut hex = String::with_capacity(64);
        for byte in digest {
            hex.push(b"0123456789abcdef"[(byte >> 4) as usize] as char);
            hex.push(b"0123456789abcdef"[(byte & 15) as usize] as char);
        }
        Ok(Output {
            digest: hex,
            preimage,
            states: labels.len(),
            edges: links.iter().map(Vec::len).sum(),
        })
    }
}

pub struct Output {
    pub digest: String,
    pub preimage: Vec<u8>,
    pub states: usize,
    pub edges: usize,
}

fn copied(value: &Value, b: &mut Budget) -> Result<Value> {
    fn size(v: &Value, b: &mut Budget, depth: u64) -> Result<u64> {
        b.depth(depth)?;
        b.charge(1, 0, 0)?;
        let mut n = 64u64;
        match v {
            Value::String(s) => {
                b.charge(s.len() as u64, 0, 0)?;
                n = n
                    .checked_add(s.len() as u64)
                    .ok_or_else(|| crate::canonical::resource("HASH3_RESOURCE"))?;
            }
            Value::Array(rows) => {
                for row in rows {
                    n = n
                        .checked_add(size(row, b, depth + 1)?)
                        .ok_or_else(|| crate::canonical::resource("HASH3_RESOURCE"))?;
                }
            }
            Value::Object(map) => {
                for (key, value) in map {
                    let child = size(value, b, depth + 1)?;
                    n = n
                        .checked_add(128 + key.len() as u64)
                        .and_then(|n| n.checked_add(child))
                        .ok_or_else(|| crate::canonical::resource("HASH3_RESOURCE"))?;
                }
            }
            _ => {}
        }
        Ok(n)
    }
    let n = size(value, b, 1)?;
    b.charge(n, 0, n)?;
    Ok(value.clone())
}
fn project(value: &Value, keys: &[&str], b: &mut Budget) -> Result<Value> {
    b.charge(keys.len() as u64, 0, keys.len() as u64 * 128)?;
    let mut map = serde_json::Map::new();
    for key in keys {
        map.insert((*key).to_owned(), copied(&value[*key], b)?);
    }
    Ok(Value::Object(map))
}
fn sorted(value: &Value, selected: Option<&[&str]>, b: &mut Budget) -> Result<Value> {
    let rows = list(value)?;
    let bytes: usize = rows.iter().map(|v| v.as_str().map_or(0, str::len)).sum();
    let log = u64::from(usize::BITS - rows.len().max(1).leading_zeros()) + 1;
    b.charge(
        (bytes as u64 + 1) * rows.len() as u64 * log,
        0,
        rows.len() as u64 * 128 + bytes as u64,
    )?;
    let mut names = Vec::new();
    for row in rows {
        let s = text(row)?;
        if selected.is_none_or(|set| set.contains(&s)) {
            names.push(s);
        }
    }
    names.sort_unstable();
    Ok(Value::Array(
        names
            .into_iter()
            .map(|s| Value::String(s.to_owned()))
            .collect(),
    ))
}
