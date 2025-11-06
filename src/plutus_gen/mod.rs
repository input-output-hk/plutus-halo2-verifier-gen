use crate::plutus_gen::code_emitters_aiken::emit_verifier_code as emit_verifier_code_aiken;
use crate::plutus_gen::code_emitters_plutus::{
    emit_verifier_code as emit_verifier_code_plutus, emit_vk_code,
};
use crate::plutus_gen::extraction::{ExtractKZG, KzgType, extract_circuit};
use blstrs::{Bls12, G1Projective, G2Affine, Scalar};
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::PolynomialCommitmentScheme;
use halo2_proofs::poly::kzg::params::ParamsKZG;
use std::path::Path;

pub mod adjusted_types;
mod code_emitters_aiken;
mod code_emitters_plutus;
pub mod extraction;
pub mod proof_serialization;

/// Generates a Plinth verifier for a specific circuit and saves the generated code
/// to the specified file paths. Uses different KZG type based on used PolynomialCommitmentScheme
///
/// # Arguments
/// * `params` - Parameters for the KZG polynomial commitment scheme
/// * `vk` - Verifying key for the circuit, it can have either GWC19, or halo2 based KZG
/// * `instances` - Public inputs to the circuit
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
    S: PolynomialCommitmentScheme<Scalar, Commitment = G1Projective> + ExtractKZG,
{
    // static locations of files in plutus directory
    let verifier_template_file = match S::kzg_type() {
        KzgType::GWC19 => Path::new("plutus-verifier/templates/verification_gwc19_kzg.hbs"),
        KzgType::Halo2MultiOpen => {
            Path::new("plutus-verifier/templates/verification_halo2_kzg.hbs")
        }
    };

    let vk_template_file = Path::new("plutus-verifier/templates/vk_constants.hbs");
    let verifier_generated_file =
        Path::new("plutus-verifier/plutus-halo2/src/Plutus/Crypto/Halo2/Generic/Verifier.hs");
    let vk_generated_file =
        Path::new("plutus-verifier/plutus-halo2/src/Plutus/Crypto/Halo2/Generic/VKConstants.hs");

    // Step 1: extract circuit representation
    let circuit_representation =
        extract_circuit(params, vk, instances).map_err(|e| e.to_string())?;

    // Step 2: extract KZG steps specific to used commitment scheme
    let circuit_representation = S::extract_kzg_steps(circuit_representation);

    // Step 3: Based on the circuit repr generate Plinth verifier and verification key constants
    // using Handlebars templates
    emit_verifier_code_plutus(
        verifier_template_file,
        verifier_generated_file,
        &circuit_representation,
    )
    .map_err(|e| e.to_string())?;
    emit_verifier_code_aiken(
        Path::new("aiken-verifier/templates/verification.hbs"),
        Path::new("aiken-verifier/aiken_halo2/verifier.ak"),
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
