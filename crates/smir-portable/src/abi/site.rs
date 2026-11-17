//! Exact dedicated source-library site selection; no host defaults.

use super::{nominal, value::*};
use crate::{Error, limits::Budget, wire::RecordValue};
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KnownSite {
    pub(crate) identity: [u8; 32],
    pub(crate) source_revision: u32,
}

pub(crate) fn verify(root: &RecordValue, budget: &mut Budget) -> Result<[u8; 32], Error> {
    Ok(verify_profile(root, budget)?.identity)
}

pub(crate) fn verify_profile(root: &RecordValue, budget: &mut Budget) -> Result<KnownSite, Error> {
    let original_site = field(root, "site")?;
    let original_options = list(field(original_site, "options")?)?;
    budget.work(original_options.len() as u64)?;
    budget.edges(original_options.len())?;
    let mut revision = 1;
    let mut found = false;
    for option in original_options {
        budget.work(1)?;
        let name = text(field(option, "name")?)?;
        budget.work(name.len() as u64)?;
        if name == "RAX_PORTABLE_SOURCE_ABI_REVISION" {
            require(
                !found
                    && text(field(option, "state")?)? == "contract"
                    && text(field(option, "value")?)? == "2",
                "ABI_CC_SITE",
            )?;
            found = true;
            revision = 2;
        }
    }
    let source = if revision == 1 {
        include_str!("../../../../docs/specifications/smir/portable/schema/abi/site.json")
    } else {
        include_str!("../../../../docs/specifications/smir/portable/schema/abi/site-raw8-v1.json")
    };
    budget.work(source.len() as u64)?;
    budget.reserve_bytes(
        source
            .len()
            .checked_mul(16)
            .ok_or_else(|| Error::resource("ABI_CC_SITE_LIMIT", "site configuration"))?,
    )?;
    let config: Json = serde_json::from_str(source)
        .map_err(|e| Error::semantic("ABI_CC_SITE_CONFIG", e.to_string()))?;
    let encoded = nominal::ascii_json(&config, budget)?;
    let identity: [u8; 32] = Sha256::digest(encoded).into();
    require(bytes(field(root, "identity")?)? == identity, "ABI_CC_SITE")?;
    let mut options = Vec::new();
    for (key, state) in [("cmake", "cmake"), ("defined_macros", "defined")] {
        for (name, value) in config[key]
            .as_object()
            .ok_or_else(|| Error::semantic("ABI_CC_SITE_CONFIG", key))?
        {
            budget.work(1)?;
            budget.reserve_bytes(512 + name.len() + value.as_str().map_or(0, str::len))?;
            options.push(json!({"name":name,"state":state,"value":value}));
        }
    }
    for name in config["undefined_macros"]
        .as_array()
        .ok_or_else(|| Error::semantic("ABI_CC_SITE_CONFIG", "undefined macros"))?
    {
        budget.work(1)?;
        budget.reserve_bytes(512 + name.as_str().map_or(0, str::len))?;
        options.push(json!({"name":name,"state":"undefined","value":""}));
    }
    if revision == 2 {
        require(
            config["platform_source_abi_revision"] == 2
                && config["source_byte_projection"] == "raw8-v1",
            "ABI_CC_SITE_CONFIG",
        )?;
        budget.work(1)?;
        budget.reserve_bytes(512)?;
        options.push(
            json!({"name":"RAX_PORTABLE_SOURCE_ABI_REVISION","state":"contract","value":"2"}),
        );
    }
    options.sort_by(|a, b| {
        a["name"]
            .as_str()
            .cmp(&b["name"].as_str())
            .then(a["state"].as_str().cmp(&b["state"].as_str()))
    });
    let expected = json!({"llvm":config["llvm"],"cxxabi":"generic_itanium","compatibility":"latest_at_pin",
        "libcxx_abi":1,"namespace":"__1","thread_api":"external","unwinder":"rax_logical_libunwind","options":options});
    require(
        nominal::json(field(root, "site")?, budget)? == expected,
        "ABI_CC_SITE",
    )?;
    Ok(KnownSite {
        identity,
        source_revision: revision,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ErrorClass, Limits};
    use std::collections::BTreeMap;

    fn rv(value: Json) -> RecordValue {
        match value {
            Json::Object(fields) => {
                RecordValue::Record(fields.into_iter().map(|(k, v)| (k, rv(v))).collect())
            }
            Json::Array(values) => RecordValue::Vector(values.into_iter().map(rv).collect()),
            Json::String(value) => RecordValue::Text(value),
            Json::Number(value) => RecordValue::Unsigned(value.as_u64().unwrap()),
            Json::Bool(value) => RecordValue::Boolean(value),
            Json::Null => panic!("unexpected null in exact site fixture"),
        }
    }
    fn root(revision: u32) -> RecordValue {
        let raw = if revision == 1 {
            include_str!("../../../../docs/specifications/smir/portable/schema/abi/site.json")
        } else {
            include_str!(
                "../../../../docs/specifications/smir/portable/schema/abi/site-raw8-v1.json"
            )
        };
        let cfg: Json = serde_json::from_str(raw).unwrap();
        let mut b = Budget::new(&Limits::default());
        let identity = Sha256::digest(nominal::ascii_json(&cfg, &mut b).unwrap()).to_vec();
        let mut options = Vec::new();
        for (key, state) in [("cmake", "cmake"), ("defined_macros", "defined")] {
            for (name, value) in cfg[key].as_object().unwrap() {
                options.push(json!({"name":name,"state":state,"value":value}));
            }
        }
        for name in cfg["undefined_macros"].as_array().unwrap() {
            options.push(json!({"name":name,"state":"undefined","value":""}));
        }
        if revision == 2 {
            options.push(
                json!({"name":"RAX_PORTABLE_SOURCE_ABI_REVISION","state":"contract","value":"2"}),
            );
        }
        options.sort_by(|a, b| {
            a["name"]
                .as_str()
                .cmp(&b["name"].as_str())
                .then(a["state"].as_str().cmp(&b["state"].as_str()))
        });
        let site = json!({"llvm":cfg["llvm"],"cxxabi":"generic_itanium","compatibility":"latest_at_pin","libcxx_abi":1,"namespace":"__1","thread_api":"external","unwinder":"rax_logical_libunwind","options":options});
        RecordValue::Record(BTreeMap::from([
            ("site".into(), rv(site)),
            ("identity".into(), RecordValue::Bytes(identity)),
        ]))
    }
    #[test]
    fn known_original_profiles_and_exact_identities() {
        for (n, want) in [
            (
                1,
                "a8a121228724a418689aa46a1287d3de566bb8a66fdf722749a4ef00927e9c71",
            ),
            (
                2,
                "5d720afc00ef5c4db7d4ff018155be283f7ae39260119c5024e6a17e9acf1de3",
            ),
        ] {
            let known = verify_profile(&root(n), &mut Budget::new(&Limits::default())).unwrap();
            assert_eq!(known.source_revision, n);
            assert_eq!(
                known
                    .identity
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
                want
            );
        }
    }
    #[test]
    fn original_profile_rejects_wrong_identity_unknown_duplicate_state() {
        for kind in ["identity", "unknown", "duplicate", "state"] {
            let mut r = root(2);
            if let RecordValue::Record(ref mut fields) = r {
                if kind == "identity" {
                    fields.insert("identity".into(), RecordValue::Bytes(vec![0; 32]));
                } else if let RecordValue::Record(site) = fields.get_mut("site").unwrap() {
                    if let RecordValue::Vector(options) = site.get_mut("options").unwrap() {
                        let index = options
                            .iter()
                            .position(|o| {
                                text(field(o, "name").unwrap()).unwrap()
                                    == "RAX_PORTABLE_SOURCE_ABI_REVISION"
                            })
                            .unwrap();
                        if kind == "duplicate" {
                            options.push(options[index].clone());
                        } else if let RecordValue::Record(row) = &mut options[index] {
                            row.insert(
                                if kind == "unknown" { "value" } else { "state" }.into(),
                                RecordValue::Text(
                                    if kind == "unknown" { "3" } else { "cmake" }.into(),
                                ),
                            );
                        }
                    }
                }
            }
            assert!(
                verify_profile(&r, &mut Budget::new(&Limits::default())).is_err(),
                "{kind}"
            );
        }
    }
    #[test]
    fn zero_work_edges_or_bytes_refuse_before_site_result() {
        for kind in [0, 1, 2] {
            let mut limits = Limits::default();
            if kind == 0 {
                limits.max_semantic_work = 0;
            } else if kind == 1 {
                limits.max_graph_edges = 0;
            } else {
                limits.max_derived_bytes = 0;
            }
            assert_eq!(
                verify_profile(&root(2), &mut Budget::new(&limits))
                    .unwrap_err()
                    .class(),
                ErrorClass::Resource
            );
        }
    }
    #[test]
    fn actual_byte_free_revision_two_reaches_typed_evidence_gate() {
        // Independently Python-encoded original roots; not a fabricated TypeFacts.
        let bytes = include_bytes!(
            "../../../../docs/specifications/smir/portable/conformance/abi/source-bytes/epoch2-byte-free.smo"
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(bytes)),
            "d3657eda4293e6488b71dc313292ae5f35d6ad70f5c641d76f810afbb1364391"
        );
        let limits = Limits::default();
        let mut budget = Budget::new(&limits);
        let ctx = crate::context::ObjectContext::new(
            crate::decode_object(bytes, limits).unwrap(),
            &mut budget,
        )
        .unwrap();
        let types = crate::execution::verify_types(&ctx, &mut budget).unwrap();
        let error = crate::abi::verify(&ctx, &types, &mut budget)
            .err()
            .expect("new2 must not issue category facts");
        assert_eq!(error.class(), ErrorClass::UnavailableEvidence);
        assert_eq!(error.code(), "ABI_CC_SOURCE_BYTE_EVIDENCE_UNAVAILABLE");
    }
}
