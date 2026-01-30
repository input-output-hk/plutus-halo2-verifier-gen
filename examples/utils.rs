use anyhow::{Context as _, Result};

use cardhalo::plutus_gen::{
    adjusted_types::CardanoFriendlyBlake2b,
    generate_aiken_verifier, generate_plinth_verifier,
    proof_serialization::{export_proof, export_public_inputs, serialize_proof},
};

use midnight_curves::{Bls12, Fq};
use midnight_proofs::plonk::{ProvingKey, VerifyingKey};
use midnight_proofs::poly::kzg::KZGCommitmentScheme;
use midnight_proofs::poly::kzg::params::ParamsKZG;
use midnight_proofs::transcript::CircuitTranscript;
use std::fs::File;

pub type Params = ParamsKZG<Bls12>;
pub type PCS = KZGCommitmentScheme<Bls12>;
pub type VK = VerifyingKey<Fq, PCS>;
pub type PK = ProvingKey<Fq, PCS>;
pub type CTranscript = CircuitTranscript<CardanoFriendlyBlake2b>;

pub fn export_all(
    proof: Vec<u8>,
    params: Params,
    vk: VK,
    instances: &[&[&[Fq]]],
    invalid_proof: Vec<u8>,
) -> Result<()> {
    let instances_file =
        "./plinth-verifier/plutus-halo2/test/Generic/serialized_public_input.hex".to_string();
    let mut output = File::create(instances_file).context("failed to create instances file")?;
    export_public_inputs(instances, &mut output).context("faield to export public inputs")?;

    serialize_proof(
        "./plinth-verifier/plutus-halo2/test/Generic/serialized_proof.json".to_string(),
        proof.clone(),
    )
    .context("json proof serialization failed")?;

    export_proof(
        "./plinth-verifier/plutus-halo2/test/Generic/serialized_proof.hex".to_string(),
        proof.clone(),
    )
    .context("hex proof serialization failed")?;

    generate_plinth_verifier(&params, &vk, instances)
        .context("Plinth verifier generation failed")?;

    generate_aiken_verifier(
        &params,
        &vk,
        instances,
        Some((proof.clone(), invalid_proof)),
    )
    .context("Aiken verifier generation failed")?;
    export_proof(
        "./aiken-verifier/submitter/serialized_proof.hex".to_string(),
        proof,
    )
    .context("hex proof serialization failed")?;

    let instances_file = "./aiken-verifier/submitter/serialized_public_input.hex".to_string();
    let mut output = File::create(instances_file).context("failed to create instances file")?;
    export_public_inputs(instances, &mut output).context("Failed to export the public inputs")?;

    Ok(())
}

#[allow(dead_code)]
fn main() -> () {
    ()
}
