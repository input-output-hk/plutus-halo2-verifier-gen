use anyhow::{Context as _, Result};

use plutus_halo2_verifier_gen::plutus_gen::{
    ExtractPCS,
    adjusted_types::CardanoFriendlyBlake2b,
    generate_aiken_verifier, generate_plinth_verifier,
    proof_serialization::{export_proof, export_public_inputs, serialize_proof},
};

use blstrs::{Bls12, G1Projective, Scalar};
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::PolynomialCommitmentScheme;
use halo2_proofs::poly::kzg::params::{ParamsKZG, ParamsVerifierKZG};
use halo2_proofs::transcript::CircuitTranscript;
use std::fs::File;

pub type Params = ParamsKZG<Bls12>;
pub type ParamsVK = ParamsVerifierKZG<Bls12>;
pub type CTranscript = CircuitTranscript<CardanoFriendlyBlake2b>;

pub fn export_all<PCS>(
    proof: Vec<u8>,
    params: Params,
    vk: &VerifyingKey<Scalar, PCS>,
    instances: &[&[&[Scalar]]],
    invalid_proof: Vec<u8>,
) -> Result<()>
where
    PCS: PolynomialCommitmentScheme<Scalar, Commitment = G1Projective> + ExtractPCS,
{
    let instances_file =
        "./plinth-verifier/plutus-halo2/test/Generic/serialized_public_input.hex".to_string();
    let mut output = File::create(instances_file).context("failed to create instances file")?;
    export_public_inputs(instances, &mut output).context("failed to export public inputs")?;

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
