//! Real new-contract validators and admission, without runtime authority.
use crate::{Error, ErrorClass, Limits, context::ObjectContext, limits::Budget};

fn input(name: &str) -> Vec<u8> {
    std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/metadata/function-address-fixtures").join(format!("{name}.smo"))).unwrap()
}

// Run the actual static predicates in their production order. This deliberately
// returns no MetadataFacts and cannot waive the separate coverage predicate.
fn predicates(data: &[u8]) -> Result<(), Error> {
    use crate::metadata::{symbols,linking,requirements,imports,relocations,program};
    let mut budget=Budget::new(&Limits::default());
    let ctx=ObjectContext::new(crate::decode_object(data,Limits::default())?, &mut budget)?;
    let types=crate::execution::verify_types(&ctx,&mut budget)?;
    let abi=crate::abi::verify(&ctx,&types,&mut budget)?;
    symbols::verify_manifest(&ctx,&types,&mut budget)?;
    let symbols=symbols::verify_local(&ctx,&mut budget)?;
    linking::verify_storage(&ctx,&types,&abi,&mut budget)?;
    linking::verify_symbols(&ctx,&types,&abi,&symbols,&mut budget)?;
    linking::verify_exports(&ctx,&types,&abi,&mut budget)?;
    let requirements=requirements::verify(ctx.root(9)?,&mut budget)?;
    imports::verify(&ctx,&types,&abi,&requirements,&mut budget)?;
    relocations::verify(&ctx,&types,&symbols,&mut budget)?;
    program::verify_headers(&ctx,&types,&abi,&mut budget)?;
    Ok(())
}

#[test]
fn actual_new_function_address_static_predicates() {
    let path=std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/metadata/function-address-fixtures/manifest.json");
    let manifest:serde_json::Value=serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let mut failures=Vec::new();
    for (name,case) in manifest["cases"].as_object().unwrap() {
        let data=input(name);
        let result=predicates(&data);
        println!("function-address predicates {name}: {:?}",result.as_ref().err());
        match case["expected"].as_str().unwrap() {
            "static" | "unavailable" => if let Err(e)=result { failures.push(format!("{name}: {e:?}")); },
            "semantic" => match result {
                Ok(())=>failures.push(format!("{name}: invalid input accepted")),
                Err(e)=> {
                    if e.class()!=ErrorClass::Semantic {failures.push(format!("{name}: {e:?}"));}
                    if let Some(code)=case["code"].as_str() {
                        if e.code()!=code {failures.push(format!("{name}: expected {code}, actual {e:?}"));}
                    }
                }
            },
            unknown=>panic!("unknown expectation {unknown}"),
        }
    }
    assert!(failures.is_empty(),"{}",failures.join("\n"));
}

#[test]
fn actual_new_function_address_private_factory_results() {
    for name in ["null-code-address","self-function-address","address-only-declaration",
        "data-address-relocation","tls-address-relocation","dependency-address-expectation",
        "weak-address-conditional","self-import-address"] {
        let result=crate::verify_object(&input(name),Limits::default());
        println!("function-address private factory {name}: {:?}",result.as_ref().err());
        if ["null-code-address","self-function-address","address-only-declaration",
            "data-address-relocation","dependency-address-expectation"].contains(&name) {
            assert!(result.is_ok(),"{name}: {:?}",result.err());
        } else {
            let error=result.err().unwrap_or_else(||panic!("excluded form issued facts: {name}"));
            assert_eq!(error.class(),ErrorClass::UnavailableEvidence,"{name}: {error:?}");
            assert_eq!(error.code(),"P2_METADATA_PROFILE_UNAUDITED","{name}");
        }
    }
}

#[test]
fn actual_address_metadata_retains_obligations_context_and_budget() {
    use crate::metadata::requirements::RuntimeRequirement;
    for (name,requirement) in [
        ("address-only-declaration",RuntimeRequirement::SymbolBinding{symbol:90}),
        ("data-address-relocation",RuntimeRequirement::LeafRelocation{index:0}),
        ("dependency-address-expectation",RuntimeRequirement::Dependency{slot:7}),
    ] {
        let data=input(name);let mut budget=Budget::new(&Limits::default());
        let ctx=ObjectContext::new(crate::decode_object(&data,Limits::default()).unwrap(),&mut budget).unwrap();
        let other=ObjectContext::new(crate::decode_object(&data,Limits::default()).unwrap(),&mut budget).unwrap();
        let types=crate::execution::verify_types(&ctx,&mut budget).unwrap();
        let abi=crate::abi::verify(&ctx,&types,&mut budget).unwrap();
        let metadata=crate::metadata::verify(&ctx,&types,&abi,&mut budget).unwrap();
        assert_eq!(metadata.context_id(),ctx.context_id());
        assert_eq!(metadata.identity(),ctx.identity());
        assert!(metadata.requirements().obligations().contains(&requirement));
        assert_eq!(metadata.assert_context(&other).err().unwrap().class(),ErrorClass::Semantic);
        for edges in [false,true] {
            let mut limits=Limits::default();
            if edges {limits.max_graph_edges=0;} else {limits.max_semantic_work=0;}
            let error=crate::metadata::verify(&ctx,&types,&abi,&mut Budget::new(&limits)).err().unwrap();
            assert_eq!(error.class(),ErrorClass::Resource);
        }
    }
}
