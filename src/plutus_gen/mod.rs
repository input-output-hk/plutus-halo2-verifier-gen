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

pub(crate) mod stats;
pub use stats::pcs::PcsEstimate;
pub use stats::{compute_verifier_code, estimate_proof_size, estimate_vk_size};

pub(crate) mod proof_serialization;
pub use proof_serialization::{export_proof, export_public_inputs, serialize_proof};

use anyhow::{Context as _, Result};
use std::path::Path;

use blstrs::{Bls12, G1Projective, Scalar};
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::PolynomialCommitmentScheme;
use halo2_proofs::poly::kzg::params::ParamsKZG;

use crate::plutus_gen::stats::pcs::{GWC19, H2MO};
pub use crate::plutus_gen::stats::{SupportedChips, lookup_chip};
use crate::plutus_gen::stats::{circuit_statistics::CircuitStatistics, estimate_verifier_code};

pub fn cost_evaluation<PCS>(
    params: &ParamsKZG<Bls12>,
    vk: &VerifyingKey<Scalar, PCS>,
    instance: &[Scalar],
    chips: &[SupportedChips],
    extra_nb_advice: usize,
    extra_nb_fixed: usize,
    extra_nb_lookups: usize,
    circuit_degree: usize,
) -> Result<()>
where
    PCS: ExtractPCS + PolynomialCommitmentScheme<Scalar, Commitment = G1Projective>,
{
    let pis = instance.len();

    let estimated = match PCS::pcs_type() {
        PCSType::Halo2MultiOpen => estimate_verifier_code::<H2MO>(
            pis,
            extra_nb_advice,
            extra_nb_fixed,
            extra_nb_lookups,
            circuit_degree,
            chips,
        ),
        PCSType::GWC19 => estimate_verifier_code::<GWC19>(
            pis,
            extra_nb_advice,
            extra_nb_fixed,
            extra_nb_lookups,
            circuit_degree,
            chips,
        ),
    };
    println!(
        "Estimating vk size: {}\nEstimating proof size: {}\n{:#?}",
        estimated.vk_size, estimated.proof_size, estimated
    );

    // Step 1: extract circuit representation
    let circuit_representation = extract_circuit(params, vk, instance)
        .context("Failed to extract the circuit representation")?;
    let exact = compute_verifier_code(&vk, &circuit_representation);

    println!(
        "Exact vk size: {}\nexact proof size: {}\n{:#?}",
        exact.vk_size, exact.proof_size, exact
    );
    println!(
        "\nDifference between exact and estimated numbers:\n{:#?}",
        CircuitStatistics::difference(&exact, &estimated)
    );
    Ok(())
}

/// Generates a Plinth verifier for a specific circuit and saves the generated
/// code to the specified file paths.
/// Uses different KZG type based on used PolynomialCommitmentScheme.
///
/// # Arguments
/// * `params` - Parameters for the KZG polynomial commitment scheme
/// * `vk` - Verifying key for the circuit, it can have either GWC19, or halo2 based KZG
/// * `instance` - Public inputs to the circuit
///
/// # Returns
/// * `Result<(), String>` - Ok(()) if the generation is successful, Err(String) otherwise
pub fn generate_plinth_verifier<PCS>(
    params: &ParamsKZG<Bls12>,
    vk: &VerifyingKey<Scalar, PCS>,
    instance: &[Scalar],
) -> Result<()>
where
    PCS: ExtractPCS + PolynomialCommitmentScheme<Scalar, Commitment = G1Projective>,
{
    // static locations of files in plutus directory
    // let verifier_template_file = Path::new("plinth-verifier/templates/verification_halo2_kzg.hbs");
    let verifier_template_file = match PCS::pcs_type() {
        PCSType::GWC19 => Path::new("plinth-verifier/templates/verification_gwc19_kzg.hbs"),
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
    let circuit_representation = extract_circuit(params, vk, instance)
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
/// * `vk` - Verifying key for the circuit, it can have either GWC19, or halo2 based KZG
/// * `instance` - Public inputs to the circuit
///
/// # Returns
/// * `Result<(), String>` - Ok(()) if the generation is successful, Err(String) otherwise
pub fn generate_aiken_verifier<PCS>(
    params: &ParamsKZG<Bls12>,
    vk: &VerifyingKey<Scalar, PCS>,
    instance: &[Scalar],
    test_proofs: Option<(Vec<u8>, Vec<u8>)>,
) -> Result<()>
where
    PCS: ExtractPCS + PolynomialCommitmentScheme<Scalar, Commitment = G1Projective>,
{
    let circuit_representation = extract_circuit(params, vk, instance)
        .context("Failed to extract the circuit representation")?;

    // static locations of files in aiken directory
    let verifier_template_file = match PCS::pcs_type() {
        PCSType::GWC19 => Path::new("aiken-verifier/templates/verification_gwc19.hbs"),
        PCSType::Halo2MultiOpen => Path::new("aiken-verifier/templates/verification_h2.hbs"),
    };
    let verifier_file = Path::new("aiken-verifier/aiken_halo2/lib/proof_verifier.ak");
    let profiler_template_file = Path::new("aiken-verifier/templates/profiler.hbs");
    let validator_template_file = Path::new("aiken-verifier/templates/validator.hbs");
    emit_verifier_aiken(
        verifier_template_file,
        verifier_file,
        Some(profiler_template_file),
        Some(validator_template_file),
        &circuit_representation,
        test_proofs.map(|(p, invalid_p)| (p, invalid_p, instance.to_vec())),
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
