use anyhow::{Context as _, Result, anyhow, bail};
use blstrs::{Base, Bls12, G1Projective, Scalar};
use halo2_proofs::{
    plonk::{
        ProvingKey, VerifyingKey, create_proof, k_from_circuit, keygen_pk, keygen_vk, prepare,
    },
    poly::{
        commitment::Guard, commitment::PolynomialCommitmentScheme, gwc_kzg::GwcKZGCommitmentScheme,
        kzg::KZGCommitmentScheme, kzg::params::ParamsKZG, kzg::params::ParamsVerifierKZG,
    },
    transcript::{CircuitTranscript, Transcript},
};
use log::info;
use plutus_halo2_verifier_gen::kzg_params::get_or_create_kzg_params;
use plutus_halo2_verifier_gen::plutus_gen::extraction::ExtractKZG;
use plutus_halo2_verifier_gen::plutus_gen::generate_aiken_verifier;
use plutus_halo2_verifier_gen::plutus_gen::proof_serialization::export_proof;
use plutus_halo2_verifier_gen::{
    circuits::atms_circuit::{AtmsSignatureCircuit, prepare_test_signatures},
    plutus_gen::{
        adjusted_types::CardanoFriendlyState, generate_plinth_verifier,
        proof_serialization::export_public_inputs, proof_serialization::serialize_proof,
    },
};
use rand::prelude::StdRng;
use rand_core::SeedableRng;
use std::env;
use std::fs::File;

fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::default().filter_or("RUST_LOG", "info"));
    let args: Vec<String> = env::args().collect();

    match &args[1..] {
        [] => compile_atms_circuit::<KZGCommitmentScheme<Bls12>>(),
        [command] if command == "gwc_kzg" => {
            compile_atms_circuit::<GwcKZGCommitmentScheme<Bls12>>()
        }
        _ => {
            println!("Usage:");
            println!("- to run the example: `cargo run --example example_name`");
            println!(
                "- to run the example using the GWC19 version of multi-open KZG, run: `cargo run --example example_name gwc_kzg`"
            );

            bail!("Invalid command line arguments")
        }
    }
}

pub fn compile_atms_circuit<
    S: PolynomialCommitmentScheme<
            Scalar,
            Commitment = G1Projective,
            Parameters = ParamsKZG<Bls12>,
            VerifierParameters = ParamsVerifierKZG<Bls12>,
        > + ExtractKZG,
>() -> Result<()> {
    let seed = [0u8; 32]; // UNSAFE, constant seed is used for testing purposes
    let mut rng: StdRng = SeedableRng::from_seed(seed);

    let num_parties = 6;
    let threshold = 3;
    let msg = Base::from(42u64);

    let (signatures, pks, pks_comm) =
        prepare_test_signatures(num_parties, threshold, msg, &mut rng.clone());

    let circuit = AtmsSignatureCircuit {
        signatures,
        pks,
        pks_comm,
        msg,
        threshold: Base::from(threshold as u64),
    };

    let k: u32 = k_from_circuit(&circuit);
    let kzg_params: ParamsKZG<Bls12> = get_or_create_kzg_params(k, rng.clone())?;
    let vk: VerifyingKey<Scalar, S> = keygen_vk(&kzg_params, &circuit)?;
    let pk: ProvingKey<Scalar, S> = keygen_pk(vk.clone(), &circuit)?;

    // no instances, just dummy 42 to make prover and verifier happy
    let instances: &[&[&[Scalar]]] = &[&[&[pks_comm, msg, Base::from(threshold as u64)]]];
    info!("Public inputs: {:?}", instances);

    let instances_file =
        "./plinth-verifier/plutus-halo2/test/Generic/serialized_public_input.hex".to_string();
    let mut output = File::create(instances_file).context("failed to create instances file")?;
    export_public_inputs(instances, &mut output).context("Failed to export the public inputs")?;

    let mut transcript: CircuitTranscript<CardanoFriendlyState> =
        CircuitTranscript::<CardanoFriendlyState>::init();

    create_proof(
        &kzg_params,
        &pk,
        &[circuit],
        instances,
        &mut rng,
        &mut transcript,
    )
    .context("proof generation should not fail")?;

    let proof = transcript.finalize();

    let mut invalid_proof = proof.clone();
    // index points to bytes of first scalar that is part of the proof
    // this should be safe and not result in malformed encoding exception
    // which is likely for flipping Byte for compressed G1 element
    // atms has 16 G1 elements at the beginning of the proof each 48 bytes long
    let index = 48 * 16 + 2;
    let firs_byte = invalid_proof[index];
    let negated_firs_byte = !firs_byte;
    invalid_proof[index] = negated_firs_byte;

    info!("proof size {:?}", proof.len());

    let mut transcript_verifier: CircuitTranscript<CardanoFriendlyState> =
        CircuitTranscript::<CardanoFriendlyState>::init_from_bytes(&proof);

    let verifier = prepare::<_, S, CircuitTranscript<CardanoFriendlyState>>(
        &vk,
        instances,
        &mut transcript_verifier,
    )
    .context("prepare verification failed")?;

    verifier
        .verify(&kzg_params.verifier_params())
        .map_err(|e| anyhow!("{e:?}"))
        .context("verify failed")?;

    serialize_proof(
        "./plinth-verifier/plutus-halo2/test/Generic/serialized_proof.json".to_string(),
        proof.clone(),
    )
    .context("json proof serialization failed")?;

    generate_plinth_verifier(&kzg_params, &vk, instances)
        .context("Plinth verifier generation failed")?;

    generate_aiken_verifier(
        &kzg_params,
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
