//! Module for generating the Plinth and Aiken verifiers for a given circuit
//! the correct mustashe templates and emitting them to the correct locations.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod adjusted_types;
#[cfg(not(target_arch = "wasm32"))]
pub mod cli;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod emitters;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod extraction;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod proof_serialization;
pub(crate) mod stats;

#[cfg(not(target_arch = "wasm32"))]
pub use adjusted_types::CardanoFriendlyBlake2b;
use anyhow::{Context, Result};
#[cfg(not(target_arch = "wasm32"))]
pub use cli::EstimateCliArguments;
#[cfg(not(target_arch = "wasm32"))]
pub use emitters::{
    aiken::{emit_verifier_code as emit_verifier_aiken, emit_vk_code as emit_vk_aiken},
    plinth::{emit_verifier_code as emit_verifier_plinth, emit_vk_code as emit_vk_plinth},
};
#[cfg(not(target_arch = "wasm32"))]
pub use extraction::pcs::ExtractPCS;
#[cfg(not(target_arch = "wasm32"))]
pub use extraction::pcs::PCSType;
#[cfg(not(target_arch = "wasm32"))]
pub use extraction::{CircuitRepresentation, extract_circuit};
use midnight_curves::{Bls12, BlsScalar as Scalar, G1Projective};
#[cfg(not(target_arch = "wasm32"))]
use midnight_proofs::{
    plonk::VerifyingKey,
    poly::{commitment::PolynomialCommitmentScheme, kzg::params::ParamsKZG},
};
#[cfg(not(target_arch = "wasm32"))]
pub use proof_serialization::{
    export_committed_inputs, export_proof, export_public_inputs, serialize_proof,
};
#[cfg(not(target_arch = "wasm32"))]
pub use stats::compute_verifier_code;
use stats::pcs::H2MO;
pub use stats::{
    AllEstimates, ChipProfile, CircuitConfig, ScalarOps, SupportedChips, all_estimates,
    lookup_chip, proof_size, verifier_stats, vk_size,
};
use std::path::Path;

/// Returns the cost profile for a chip using the H2MO polynomial commitment scheme.
pub fn chip_profile(chip: SupportedChips) -> ChipProfile {
    stats::chip_profile::<H2MO>(chip)
}

/// Generates a Plinth verifier for a specific circuit and saves the generated
/// code to the specified file paths.
/// Uses different KZG type based on used PolynomialCommitmentScheme.
///
/// # Arguments
/// * `params` - Parameters for the KZG polynomial commitment scheme
/// * `vk` - Verifying key for the circuit
/// * `recursion_vks` - Option set to Some if we are doing a recusion,
/// the vector lists any other vks used in the application inside the recursion.
/// * `instance` - Public inputs to the circuit
///
/// # Returns
/// * `Result<(), String>` - Ok(()) if the generation is successful, Err(String) otherwise
#[cfg(not(target_arch = "wasm32"))]
pub fn cost_evaluation<PCS>(
    params: &ParamsKZG<Bls12>,
    vk: &VerifyingKey<Scalar, PCS>,
    recursion_vks: Option<Vec<(String, VerifyingKey<Scalar, PCS>)>>,
    instance: &[Scalar],
    committed_instance: Option<G1Projective>,
    chips: &[SupportedChips],
    config: CircuitConfig,
) -> anyhow::Result<()>
where
    PCS: ExtractPCS + PolynomialCommitmentScheme<Scalar, Commitment = G1Projective>,
{
    use anyhow::Context as _;
    let pis = instance.len();
    let nb_committed_instances = usize::from(committed_instance.is_some());
    let circuit_representation = extract_circuit(
        params,
        vk,
        recursion_vks.clone(),
        instance,
        committed_instance,
    )
    .context("Failed to extract the circuit representation")?;
    let exact = compute_verifier_code(vk, &circuit_representation);
    let estimated = verifier_stats(
        pis,
        nb_committed_instances,
        recursion_vks.is_some(),
        config,
        chips,
    );
    println!("\n\n estimated numbers:\n{:#?}", estimated);
    println!("\n\n exact numbers:\n{:#?}", exact);
    println!(
        "\n\nDifference between exact and estimated numbers:\n{:#?}",
        stats::CircuitStatistics::difference(&exact, &estimated)
    );
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn generate_plinth_verifier<PCS>(
    params: &ParamsKZG<Bls12>,
    vk: &VerifyingKey<Scalar, PCS>,
    recursion_vks: Option<Vec<(String, VerifyingKey<Scalar, PCS>)>>,
    instance: &[Scalar],
    committed_instances: Option<G1Projective>,
) -> Result<()>
where
    PCS: ExtractPCS + PolynomialCommitmentScheme<Scalar, Commitment = G1Projective>,
{
    let verifier_template_file = match PCS::pcs_type() {
        PCSType::Halo2MultiOpen => {
            Path::new("plinth-verifier/templates/verification_halo2_kzg.hbs")
        }
    };

    let vk_template_file = Path::new("plinth-verifier/templates/vk_constants.hbs");
    let test_template_file = Path::new("plinth-verifier/templates/test.hbs");
    let test_plutus_template_file = Path::new("plinth-verifier/templates/generic_vf_plutus.hbs");
    let test_haskell_template_file = Path::new("plinth-verifier/templates/generic_vf_haskell.hbs");
    let test_compiled_template_file =
        Path::new("plinth-verifier/templates/generic_vf_compiled.hbs");
    let verifier_generated_file =
        Path::new("plinth-verifier/plutus-halo2/src/Plutus/Crypto/Halo2/Generic/Verifier.hs");
    let vk_generated_file =
        Path::new("plinth-verifier/plutus-halo2/src/Plutus/Crypto/Halo2/Generic/VKConstants.hs");

    // Step 1: extract circuit representation
    let circuit_representation =
        extract_circuit(params, vk, recursion_vks, instance, committed_instances)
            .context("Failed to extract the circuit representation")?;

    // Step 2: Based on the circuit repr generate Plinth verifier and verification key constants
    // using Handlebars templates
    emit_verifier_plinth(
        verifier_template_file,
        verifier_generated_file,
        test_template_file,
        test_plutus_template_file,
        test_haskell_template_file,
        test_compiled_template_file,
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
/// * `recursion_vks` - Option set to Some if we are doing a recusion,
/// the vector lists any other vks used in the application inside the recursion.
/// * `instance` - Public inputs to the circuit
///
/// # Returns
/// * `Result<(), String>` - Ok(()) if the generation is successful, Err(String) otherwise
#[cfg(not(target_arch = "wasm32"))]
pub fn generate_aiken_verifier<PCS>(
    params: &ParamsKZG<Bls12>,
    vk: &VerifyingKey<Scalar, PCS>,
    recursion_vks: Option<Vec<(String, VerifyingKey<Scalar, PCS>)>>,
    instance: &[Scalar],
    committed_instances: Option<G1Projective>,
    test_proofs: Option<(Vec<u8>, Vec<u8>)>,
) -> Result<()>
where
    PCS: ExtractPCS + PolynomialCommitmentScheme<Scalar, Commitment = G1Projective>,
{
    let circuit_representation =
        extract_circuit(params, vk, recursion_vks, instance, committed_instances)
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
