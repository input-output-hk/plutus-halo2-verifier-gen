use blstrs::{Bls12, G2Affine, Scalar};
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::kzg::params::ParamsKZG;
use crate::plutus_gen::code_emitters::{emit_verifier_code, emit_vk_code};
use crate::plutus_gen::extraction::{extract_circuit, KZGScheme};

mod code_emitters;
pub mod extraction;
pub mod proof_serialization;
pub mod adjusted_types;

/// Generates a Plinth verifier for a specific circuit and saves the generated code
/// to the specified file paths.
///
/// # Arguments
/// * `params` - Parameters for the KZG polynomial commitment scheme
/// * `vk` - Verifying key for the circuit
/// * `instances` - Public inputs to the circuit
/// * `verifier_template_file` - File path for the Plinth verifier template
/// * `vk_template_file` - File path for the Plinth verification key template
/// * `verifier_generated_file` - File path where the generated verifier code will be saved
/// * `vk_generated_file` - File path for where the generated verification key will be saved
/// * `g2_encoder` - Encoding function for G2Affine points
///
/// # Returns
/// * `Result<(), String>` - Ok(()) if the generation is successful, Err(String) otherwise
pub fn generate_plinth_verifier(
    params: &ParamsKZG<Bls12>,
    vk: &VerifyingKey<Scalar, KZGScheme>,
    instances: &[&[&[Scalar]]],
    verifier_template_file: String,
    vk_template_file: String,
    verifier_generated_file: String,
    vk_generated_file: String,
    g2_encoder: fn(G2Affine) -> String,
) -> Result<(), String> {
    // Step 1: extract circuit representation
    let circuit_representation =
        extract_circuit(params, vk, instances).map_err(|e| e.to_string())?;

    // Step 2: Based on the circuit repr generate Plinth verifier and verification key constants
    // using Handlebars templates
    emit_verifier_code(
        verifier_template_file,
        verifier_generated_file,
        &circuit_representation,
    )
        .map_err(|e| e.to_string())?;
    emit_vk_code(
        vk_template_file,
        vk_generated_file,
        &circuit_representation,
        g2_encoder,
    )
        .map_err(|e| e.to_string())?;

    Ok(())
}