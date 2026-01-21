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
use plutus_halo2_verifier_gen::plutus_gen::generate_aiken_verifier;
use plutus_halo2_verifier_gen::plutus_gen::proof_serialization::export_proof;
use plutus_halo2_verifier_gen::{
    circuits::lookup_table_circuit::LookupTest,
    kzg_params::get_or_create_kzg_params,
    plutus_gen::{
        adjusted_types::CardanoFriendlyBlake2b, extraction::ExtractKZG, generate_plinth_verifier,
        proof_serialization::export_public_inputs, proof_serialization::serialize_proof,
    },
};
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use std::env;
use std::fs::File;
use std::marker::PhantomData;

fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::default().filter_or("RUST_LOG", "info"));
    let args: Vec<String> = env::args().collect();

    match &args[1..] {
        [] => compile_lookup_table_circuit::<KZGCommitmentScheme<Bls12>>(),
        [command] if command == "gwc_kzg" => {
            compile_lookup_table_circuit::<GwcKZGCommitmentScheme<Bls12>>()
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

pub fn compile_lookup_table_circuit<
    S: PolynomialCommitmentScheme<
            Scalar,
            Commitment = G1Projective,
            Parameters = ParamsKZG<Bls12>,
            VerifierParameters = ParamsVerifierKZG<Bls12>,
        > + ExtractKZG,
>() -> Result<()> {
    let seed = [0u8; 32]; // UNSAFE, constant seed is used for testing purposes
    let mut rng: StdRng = SeedableRng::from_seed(seed);

    let circuit = LookupTest::<Scalar> {
        inputs: vec![(42, 8), (53, 7), (12, 8), (46, 8)],
        max_bit_len: 9,
        native_field: PhantomData,
    };

    let k: u32 = k_from_circuit(&circuit);
    let kzg_params: ParamsKZG<Bls12> = get_or_create_kzg_params(k, rng.clone())?;
    let vk: VerifyingKey<Scalar, S> = keygen_vk(&kzg_params, &circuit)?;
    let pk: ProvingKey<Scalar, S> = keygen_pk(vk.clone(), &circuit)?;

    // no instances, just dummy 42 to make prover and verifier happy
    let instances: &[&[&[Scalar]]] =
        &[&[&[Base::from(42u64), Base::from(42u64), Base::from(42u64)]]];
    info!("Public inputs: {:?}", instances);

    let instances_file =
        "./plinth-verifier/plutus-halo2/test/Generic/serialized_public_input.hex".to_string();
    let mut output = File::create(instances_file).context("failed to create instances file")?;
    export_public_inputs(instances, &mut output).context("Failed to export public inputs")?;

    let mut transcript: CircuitTranscript<CardanoFriendlyBlake2b> =
        CircuitTranscript::<CardanoFriendlyBlake2b>::init();

    create_proof(
        &kzg_params,
        &pk,
        &[circuit.clone()],
        instances,
        &mut rng,
        &mut transcript,
    )
    .context("proof generation should not fail")?;

    let proof = transcript.finalize();

    info!("proof size {:?}", proof.len());

    let mut transcript_verifier: CircuitTranscript<CardanoFriendlyBlake2b> =
        CircuitTranscript::<CardanoFriendlyBlake2b>::init_from_bytes(&proof);

    let verifier = prepare::<_, _, CircuitTranscript<CardanoFriendlyBlake2b>>(
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

    // Create invalid proof inputs for testing (with wrong public inputs)
    let mut transcript: CircuitTranscript<CardanoFriendlyBlake2b> =
        CircuitTranscript::<CardanoFriendlyBlake2b>::init();
    create_proof(
        &kzg_params,
        &pk,
        &[circuit.clone()],
        &[&[&[Base::from(1u64), Base::from(1u64), Base::from(1u64)]]],
        &mut rng,
        &mut transcript,
    )
        .context("proof generation should not fail")?;
    let invalid_proof = transcript.finalize();

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
