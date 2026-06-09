/// Writes docs/chip_profiles.json from the live estimator.
///
/// Run with:
///   cargo run --bin dump_profiles
use std::collections::BTreeMap;

use plutus_halo2_verifier_gen::plutus_gen::{SupportedChips, chip_profile};
use strum::IntoEnumIterator;

fn main() {
    let profiles: BTreeMap<String, _> = SupportedChips::iter()
        .map(|chip| (chip.to_string(), chip_profile(chip)))
        .collect();

    let json = serde_json::to_string_pretty(&profiles).expect("serialization failed");
    std::fs::write("docs/chip_profiles.json", &json).expect("write failed");
    eprintln!("Written docs/chip_profiles.json");
}
