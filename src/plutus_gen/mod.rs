//! Module for generating the Plinth and Aiken verifiers for a given circuit
//! the correct mustashe templates and emitting them to the correct locations.
pub(crate) mod adjusted_types;
pub use adjusted_types::CardanoFriendlyBlake2b;
pub(crate) mod emitters;
pub(crate) mod extraction;
pub use emitters::{
    aiken::{emit_verifier_code as emit_verifier_aiken, emit_vk_code as emit_vk_aiken},
    plinth::{emit_verifier_code as emit_verifier_plinth, emit_vk_code as emit_vk_plinth},
};
pub use extraction::pcs::ExtractPCS;
pub use extraction::pcs::PCSType;
pub use extraction::{CircuitRepresentation, extract_circuit};
pub(crate) mod proof_serialization;
pub use proof_serialization::{
    export_committed_inputs, export_proof, export_public_inputs, serialize_proof,
};

use anyhow::{Context as _, Result};
use std::path::Path;

use midnight_curves::{Bls12, BlsScalar as Scalar, G1Projective};
use midnight_proofs::plonk::VerifyingKey;
use midnight_proofs::poly::commitment::PolynomialCommitmentScheme;
use midnight_proofs::poly::kzg::params::ParamsKZG;

/// Generates a Plinth verifier for a specific circuit and saves the generated
/// code to the specified file paths.
/// Uses different KZG type based on used PolynomialCommitmentScheme.
///
/// # Arguments
/// * `params` - Parameters for the KZG polynomial commitment scheme
/// * `vk` - Verifying key for the circuit
/// * `instance` - Public inputs to the circuit
///
/// # Returns
/// * `Result<(), String>` - Ok(()) if the generation is successful, Err(String) otherwise
pub fn generate_plinth_verifier<PCS>(
    params: &ParamsKZG<Bls12>,
    vk: &VerifyingKey<Scalar, PCS>,
    instance: &[Scalar],
    committed_instances: Option<G1Projective>,
) -> Result<()>
where
    PCS: ExtractPCS + PolynomialCommitmentScheme<Scalar, Commitment = G1Projective>,
{
    // static locations of files in plutus directory
    // let verifier_template_file = Path::new("plinth-verifier/templates/verification_halo2_kzg.hbs");
    let verifier_template_file = match PCS::pcs_type() {
        PCSType::Halo2MultiOpen => {
            Path::new("plinth-verifier/templates/verification_halo2_kzg.hbs")
        }
    };

    let vk_template_file = Path::new("plinth-verifier/templates/vk_constants.hbs");
    let verifier_generated_file =
        Path::new("plinth-verifier/plutus-halo2/src/Plutus/Crypto/Halo2/Generic/Verifier.hs");
    let vk_generated_file =
        Path::new("plinth-verifier/plutus-halo2/src/Plutus/Crypto/Halo2/Generic/VKConstants.hs");

    // Step 1: extract circuit representation
    let circuit_representation = extract_circuit(params, vk, instance, committed_instances)
        .context("Failed to extract the circuit representation")?;

    // Step 2: Based on the circuit repr generate Plinth verifier and verification key constants
    // using Handlebars templates
    emit_verifier_plinth(
        verifier_template_file,
        verifier_generated_file,
        &circuit_representation,
    )
    .context("Failed to emit the verifier code for plutus")?;
    emit_vk_plinth(vk_template_file, vk_generated_file, &circuit_representation)
        .context("Failed to emit the verifier key constants")?;

    Ok(())
}

/// Generates an Aiken verifier for a specific circuit and saves the generated
/// code to the specified file paths.
/// Uses different KZG type based on used PolynomialCommitmentScheme.
///
/// # Arguments
/// * `params` - Parameters for the KZG polynomial commitment scheme
/// * `vk` - Verifying key for the circuit
/// * `instance` - Public inputs to the circuit
///
/// # Returns
/// * `Result<(), String>` - Ok(()) if the generation is successful, Err(String) otherwise
pub fn generate_aiken_verifier<PCS>(
    params: &ParamsKZG<Bls12>,
    vk: &VerifyingKey<Scalar, PCS>,
    instance: &[Scalar],
    committed_instances: Option<G1Projective>,
    test_proofs: Option<(Vec<u8>, Vec<u8>)>,
) -> Result<()>
where
    PCS: ExtractPCS + PolynomialCommitmentScheme<Scalar, Commitment = G1Projective>,
{
    let circuit_representation = extract_circuit(params, vk, instance, committed_instances)
        .context("Failed to extract the circuit representation")?;

    // static locations of files in aiken directory
    let verifier_file = Path::new("aiken-verifier/aiken_halo2/lib/proof_verifier.ak");
    let verifier_template_file = Path::new("aiken-verifier/templates/verification_h2.hbs");
    let profiler_template_file = Path::new("aiken-verifier/templates/profiler.hbs");
    let validator_template_file = Path::new("aiken-verifier/templates/validator.hbs");
    emit_verifier_aiken(
        verifier_template_file,
        verifier_file,
        Some(profiler_template_file),
        Some(validator_template_file),
        &circuit_representation,
        test_proofs.map(|(p, invalid_p)| (p, invalid_p, instance.to_vec(), committed_instances)),
    )
    .context("Failed to emit the verifier code for aiken")?;

    let verification_key_file = Path::new("aiken-verifier/aiken_halo2/lib/verifier_key.ak");
    let vk_template_file = Path::new("aiken-verifier/templates/vk_constants.hbs");
    emit_vk_aiken(
        vk_template_file,
        verification_key_file,
        &circuit_representation,
    )
    .context("Failed to emit the verifier key constants for aiken")?;

    Ok(())
}
