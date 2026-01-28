use crate::plutus_gen::extraction::languages::{
    aiken::{emit_verifier_code as emit_verifier_aiken, emit_vk_code as emit_vk_aiken},
    plinth::{emit_verifier_code as emit_verifier_plinth, emit_vk_code as emit_vk_plinth},
};

use crate::plutus_gen::extraction::{ExtractKZG, extract_circuit};
use anyhow::{Context as _, Result};
use midnight_curves::{Bls12, BlsScalar as Scalar, G1Projective};

use midnight_proofs::plonk::VerifyingKey;
use midnight_proofs::poly::commitment::PolynomialCommitmentScheme;
use midnight_proofs::poly::kzg::KZGCommitmentScheme;
use midnight_proofs::poly::kzg::params::ParamsKZG;
use std::path::Path;

pub mod adjusted_types;
pub mod extraction;
pub mod proof_serialization;

/// Generates a Plinth verifier for a specific circuit and saves the generated code
/// to the specified file paths. Uses different KZG type based on used PolynomialCommitmentScheme
///
/// # Arguments
/// * `params` - Parameters for the KZG polynomial commitment scheme
/// * `vk` - Verifying key for the circuit
/// * `instances` - Public inputs to the circuit
/// * `g2_encoder` - Encoding function for G2Affine points
///
/// # Returns
/// * `Result<(), String>` - Ok(()) if the generation is successful, Err(String) otherwise
pub fn generate_plinth_verifier<S>(
    params: &ParamsKZG<Bls12>,
    vk: &VerifyingKey<Scalar, S>,
    instances: &[&[&[Scalar]]],
) -> Result<()>
where
    S: PolynomialCommitmentScheme<Scalar, Commitment = G1Projective> + ExtractKZG,
{
    // static locations of files in plutus directory
    let verifier_template_file = Path::new("plinth-verifier/templates/verification_halo2_kzg.hbs");

    let vk_template_file = Path::new("plinth-verifier/templates/vk_constants.hbs");
    let verifier_generated_file =
        Path::new("plinth-verifier/plutus-halo2/src/Plutus/Crypto/Halo2/Generic/Verifier.hs");
    let vk_generated_file =
        Path::new("plinth-verifier/plutus-halo2/src/Plutus/Crypto/Halo2/Generic/VKConstants.hs");

    // Step 1: extract circuit representation
    let circuit_representation = extract_circuit(params, vk, instances)
        .context("Failed to extract the circuit representation")?;

    // Step 2: extract KZG steps specific to used commitment scheme
    let circuit_representation = KZGCommitmentScheme::extract_kzg_steps(circuit_representation);

    // Step 3: Based on the circuit repr generate Plinth verifier and verification key constants
    // using Handlebars templates
    emit_verifier_plinth(
        verifier_template_file,
        verifier_generated_file,
        &circuit_representation,
    )
    .context("Failed to emit the verifier code for plinth")?;
    emit_vk_plinth(vk_template_file, vk_generated_file, &circuit_representation)
        .context("Failed to emit the verifier key constants for plinth")?;

    Ok(())
}

pub fn generate_aiken_verifier<S>(
    params: &ParamsKZG<Bls12>,
    vk: &VerifyingKey<Scalar, S>,
    instances: &[&[&[Scalar]]],
    test_proofs: Option<(Vec<u8>, Vec<u8>)>,
) -> Result<()>
where
    S: PolynomialCommitmentScheme<Scalar, Commitment = G1Projective> + ExtractKZG,
{
    let circuit_representation = extract_circuit(params, vk, instances)
        .context("Failed to extract the circuit representation")?;
    let circuit_representation = KZGCommitmentScheme::extract_kzg_steps(circuit_representation);

    // static locations of files in aiken directory
    let verifier_template_file = Path::new("aiken-verifier/templates/verification_h2.hbs");

    emit_verifier_aiken(
        verifier_template_file,
        Path::new("aiken-verifier/aiken_halo2/lib/proof_verifier.ak"),
        Some(Path::new("aiken-verifier/templates/profiler.hbs")),
        &circuit_representation,
        test_proofs.map(|(p, invalid_p)| (p, invalid_p, instances[0][0].to_vec())),
    )
    .context("Failed to emit the verifier code for aiken")?;
    emit_vk_aiken(
        Path::new("aiken-verifier/templates/vk_constants.hbs"),
        Path::new("aiken-verifier/aiken_halo2/lib/verifier_key.ak"),
        &circuit_representation,
    )
    .context("Failed to emit the verifier key constants for aiken")?;

    Ok(())
}
