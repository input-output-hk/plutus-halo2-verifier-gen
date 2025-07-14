use crate::plutus_gen::code_emitters::{emit_verifier_code, emit_vk_code};
use crate::plutus_gen::extraction::{ExtractWitnesses, extract_circuit, WitnessType};
use blstrs::{Bls12, G1Projective, G2Affine, Scalar};
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::PolynomialCommitmentScheme;
use halo2_proofs::poly::kzg::params::ParamsKZG;
use std::path::Path;

pub mod adjusted_types;
mod code_emitters;
pub mod extraction;
pub mod proof_serialization;

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
pub fn generate_plinth_verifier<S>(
    params: &ParamsKZG<Bls12>,
    vk: &VerifyingKey<Scalar, S>,
    instances: &[&[&[Scalar]]],
    g2_encoder: fn(G2Affine) -> String,
) -> Result<(), String>
where
    S: PolynomialCommitmentScheme<Scalar, Commitment=G1Projective> + ExtractWitnesses,
{
    // static locations of files in plutus directory
    let verifier_template_file = match S::witnesses_type() {
        WitnessType::Legacy => Path::new("plutus-verifier/verification.hbs"),
        WitnessType::MultiOpen => Path::new("plutus-verifier/verification_multiopen.hbs"),
    };

    let vk_template_file = Path::new("plutus-verifier/vk_constants.hbs");
    let verifier_generated_file =
        Path::new("plutus-verifier/plutus-halo2/src/Plutus/Crypto/Halo2/Generic/Verifier.hs");
    let vk_generated_file =
        Path::new("plutus-verifier/plutus-halo2/src/Plutus/Crypto/Halo2/Generic/VKConstants.hs");

    // Step 1: extract circuit representation
    let circuit_representation =
        extract_circuit(params, vk, instances).map_err(|e| e.to_string())?;

    // Step 2: extract witnesses specific to used commitment scheme
    let circuit_representation = S::extract_witnesses(circuit_representation);

    // Step 3: Based on the circuit repr generate Plinth verifier and verification key constants
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
