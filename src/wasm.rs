use wasm_bindgen::prelude::*;

use crate::plutus_gen::{self, CircuitConfig, SupportedChips};

/// Compute all estimates for a circuit and return them as a JSON string.
///
/// `chips_json` is a JSON array where each element is either:
/// - a string: `"Native"`,`"Sha256"`, `"Sha512"`, `"Poseidon"`, `"HashToCurve"`, `"Curve25519"`,
///   `"EdwardsJubjub"`, `"WeierstrassBls12381"`, `"WeierstrassSecp256k1"`
/// - an object: `{"type":"P2RDecomposition","n":5}` or
///   `{"type":"Lookup","name":"...","nb_arguments":1,"input_degree":1,"table_degree":1}`
///
/// Returns a JSON-serialized `AllEstimates`.
#[wasm_bindgen]
pub fn estimate(
    chips_json: &str,
    nb_public_inputs: usize,
    nb_committed_instances: usize,
    recursion: bool,
    nb_selectors: usize,
    nb_advice: usize,
    nb_fixed: usize,
    nb_evaluations: usize,
    nb_lookups: usize,
    degree: usize,
) -> String {
    let chips = parse_chips(chips_json);
    let config = CircuitConfig::new(
        nb_selectors,
        nb_advice,
        nb_fixed,
        if nb_evaluations == 0 {
            None
        } else {
            Some(nb_evaluations)
        },
        nb_lookups,
        degree,
        None,
    );
    let result = plutus_gen::all_estimates(
        nb_public_inputs,
        nb_committed_instances,
        recursion,
        config,
        &chips,
    );
    serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_string())
}

fn parse_chips(json: &str) -> Vec<SupportedChips> {
    use serde_json::Value;
    let arr: Vec<Value> = serde_json::from_str(json).unwrap_or_default();
    arr.iter()
        .filter_map(|v| match v {
            Value::String(s) => chip_from_str(s),
            Value::Object(obj) => {
                let t = obj.get("type")?.as_str()?;
                match t {
                    "P2RDecomposition" => {
                        let n = obj.get("n")?.as_u64()? as usize;
                        Some(SupportedChips::P2RDecomposition(n))
                    }
                    "Lookup" => {
                        let name = obj.get("name")?.as_str()?.to_string();
                        let nb_arguments = obj.get("nb_arguments")?.as_u64()? as usize;
                        let input_degree = obj.get("input_degree")?.as_u64()? as usize;
                        let table_degree = obj.get("table_degree")?.as_u64()? as usize;
                        Some(plutus_gen::lookup_chip(
                            name,
                            nb_arguments,
                            input_degree,
                            table_degree,
                        ))
                    }
                    other => chip_from_str(other),
                }
            }
            _ => None,
        })
        .collect()
}

fn chip_from_str(s: &str) -> Option<SupportedChips> {
    match s {
        "Native" => Some(SupportedChips::Native),
        "Sha256" => Some(SupportedChips::Sha256),
        "Sha512" => Some(SupportedChips::Sha512),
        "Poseidon" => Some(SupportedChips::Poseidon),
        "HashToCurve" => Some(SupportedChips::HashToCurve),
        "EdwardsJubjub" => Some(SupportedChips::EdwardsJubjub),
        "Curve25519" => Some(SupportedChips::Curve25519),
        "WeierstrassBls12381" => Some(SupportedChips::WeierstrassBls12381),
        "WeierstrassSecp256k1" => Some(SupportedChips::WeierstrassSecp256k1),
        _ => None,
    }
}
