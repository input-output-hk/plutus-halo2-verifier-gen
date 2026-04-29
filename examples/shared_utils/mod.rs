use anyhow::{Context as _, Result};
use blstrs::Scalar;
use std::fs::File;

use plutus_halo2_verifier_gen::plutus_gen::{export_proof, export_public_inputs, serialize_proof};

const AIKEN_PROOF_FILE: &str = "./aiken-verifier/submitter/serialized_proof.hex";
const AIKEN_PI_FILE: &str = "./aiken-verifier/submitter/serialized_public_input.hex";

const PLINTH_PROOF_JSON_FILE: &str =
    "./plinth-verifier/plutus-halo2/test/Generic/serialized_proof.json";
const PLINTH_PROOF_HEX_FILE: &str =
    "./plinth-verifier/plutus-halo2/test/Generic/serialized_proof.hex";
const PLINTH_PI_FILE: &str =
    "./plinth-verifier/plutus-halo2/test/Generic/serialized_public_input.hex";

pub fn export_aiken(instance: &[Scalar], proof: &[u8]) -> Result<()> {
    let mut output = File::create(AIKEN_PI_FILE.to_string())
        .context("aiken - failed to create instance file")?;
    export_public_inputs(&instance, &mut output)
        .context("aiken - Failed to export the public inputs")?;

    export_proof(AIKEN_PROOF_FILE.to_string(), proof)
        .context("aiken - hex proof serialization failed")?;

    Ok(())
}

pub fn export_plinth(instance: &[Scalar], proof: &[u8]) -> Result<()> {
    let mut output = File::create(PLINTH_PI_FILE.to_string())
        .context("plinth - failed to create instance file")?;
    export_public_inputs(instance, &mut output)
        .context("plinth - failed to export public inputs")?;

    serialize_proof(PLINTH_PROOF_JSON_FILE.to_string(), proof)
        .context("plinth - json proof serialization failed")?;

    export_proof(PLINTH_PROOF_HEX_FILE.to_string(), proof)
        .context("plinth - hex proof serialization failed")?;

    Ok(())
}
