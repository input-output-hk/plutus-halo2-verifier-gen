use anyhow::{Context as _, Result, anyhow, bail};
use log::info;
use rand::prelude::StdRng;
use rand_core::SeedableRng;
use std::env;
use std::marker::PhantomData;

use blstrs::{Base, Bls12, G1Projective, Scalar};
use halo2_proofs::{
    plonk::{
        ProvingKey, VerifyingKey, create_proof, k_from_circuit, keygen_pk, keygen_vk, prepare,
    },
    poly::{
        commitment::{Guard, PolynomialCommitmentScheme},
        gwc_kzg::GwcKZGCommitmentScheme,
        kzg::{
            KZGCommitmentScheme,
            params::{ParamsKZG, ParamsVerifierKZG},
        },
    },
    transcript::{CircuitTranscript, Transcript},
};

use plutus_halo2_verifier_gen::plutus_gen::{
    CardanoFriendlyBlake2b, ExtractPCS, cost_evaluation, generate_aiken_verifier,
    generate_plinth_verifier,
};
use plutus_halo2_verifier_gen::{
    circuits::lookup_table_circuit::LookupTest, kzg_params::get_or_create_kzg_params,
};

pub type Params = ParamsKZG<Bls12>;
pub type ParamsVK = ParamsVerifierKZG<Bls12>;
pub type CTranscript = CircuitTranscript<CardanoFriendlyBlake2b>;

#[path = "shared_utils/mod.rs"]
mod shared_utils;

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
    PCS: PolynomialCommitmentScheme<
            Scalar,
            Commitment = G1Projective,
            Parameters = Params,
            VerifierParameters = ParamsVK,
        > + ExtractPCS,
>() -> Result<()> {
    let seed = [0u8; 32]; // UNSAFE, constant seed is used for testing purposes
    let mut rng: StdRng = SeedableRng::from_seed(seed);

    let circuit = LookupTest::<Scalar> {
        inputs: vec![(42, 8), (53, 7), (12, 8), (46, 8)],
        max_bit_len: 9,
        native_field: PhantomData,
    };

    let k: u32 = k_from_circuit(&circuit);
    let kzg_params: Params = get_or_create_kzg_params(k, rng.clone())?;
    let vk: VerifyingKey<Scalar, PCS> = keygen_vk(&kzg_params, &circuit)?;
    let pk: ProvingKey<Scalar, PCS> = keygen_pk(vk.clone(), &circuit)?;

    // no instance, just dummy 42 to make prover and verifier happy
    let instance = [Base::from(42u64), Base::from(42u64), Base::from(42u64)];
    info!("Public inputs: {:?}", instance);

    let mut transcript = CTranscript::init();

    create_proof(
        &kzg_params,
        &pk,
        &[circuit.clone()],
        &[&[&instance]],
        &mut rng,
        &mut transcript,
    )
    .context("proof generation should not fail")?;

    let proof = transcript.finalize();

    info!("proof size {:?}", proof.len());

    let mut transcript_verifier = CTranscript::init_from_bytes(&proof);

    let verifier = prepare::<_, PCS, CTranscript>(&vk, &[&[&instance]], &mut transcript_verifier)
        .context("prepare verification failed")?;

    verifier
        .verify(&kzg_params.verifier_params())
        .map_err(|e| anyhow!("{e:?}"))
        .context("verify failed")?;

    // Create invalid proof inputs for testing (with wrong public inputs)
    let mut invalid_transcript = CTranscript::init();
    create_proof(
        &kzg_params,
        &pk,
        &[circuit.clone()],
        &[&[&[Base::from(1u64), Base::from(1u64), Base::from(1u64)]]],
        &mut rng,
        &mut invalid_transcript,
    )
    .context("proof generation should not fail")?;
    let invalid_proof = invalid_transcript.finalize();

    cost_evaluation(&kzg_params, &vk, &instance)?;

    shared_utils::export_plinth(&instance, &proof)?;
    generate_plinth_verifier(&kzg_params, &vk, &instance)
        .context("Plinth verifier generation failed")?;

    shared_utils::export_aiken(&instance, &proof)?;
    generate_aiken_verifier(
        &kzg_params,
        &vk,
        &instance,
        Some((proof.clone(), invalid_proof)),
    )
    .context("Aiken verifier generation failed")?;

    Ok(())
}
