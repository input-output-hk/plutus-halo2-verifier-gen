use anyhow::{Context as _, Result, anyhow, bail};
use ff::Field;
use log::info;
use rand::prelude::StdRng;
use rand_core::SeedableRng;
use std::env;

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
    utils::SerdeFormat,
};

use plutus_halo2_verifier_gen::plutus_gen::{
    CardanoFriendlyBlake2b, ExtractPCS, SupportedChips, cost_evaluation, generate_aiken_verifier,
    generate_plinth_verifier,
};
use plutus_halo2_verifier_gen::{
    circuits::simple_mul_circuit::SimpleMulCircuit, kzg_params::get_or_create_kzg_params,
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
        [] => compile_simple_mul_circuit::<KZGCommitmentScheme<Bls12>>(),
        [command] if command == "gwc_kzg" => {
            compile_simple_mul_circuit::<GwcKZGCommitmentScheme<Bls12>>()
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

fn compile_simple_mul_circuit<
    PCS: PolynomialCommitmentScheme<
            Scalar,
            Commitment = G1Projective,
            Parameters = Params,
            VerifierParameters = ParamsVK,
        > + ExtractPCS,
>() -> Result<()> {
    // Prepare the private and public inputs to the circuit!
    let constant = Scalar::from(7);
    let a = Scalar::from(2);
    let b = Scalar::from(3);
    let c = constant * a.square() * b.square();

    info!("constant: {:?}", constant);

    info!("a: {:?}", a);
    info!("b: {:?}", b);
    info!("c: {:?}", c);

    // Instantiate the circuit with the private inputs.
    let circuit = SimpleMulCircuit::init(constant, a, b, c);

    let seed = [0u8; 32]; // UNSAFE, constant seed is used for testing purposes
    let mut rng: StdRng = SeedableRng::from_seed(seed);

    let k: u32 = k_from_circuit(&circuit);
    let kzg_params: Params = get_or_create_kzg_params(k, rng.clone())?;
    let vk: VerifyingKey<Scalar, PCS> = keygen_vk(&kzg_params, &circuit)?;
    let pk: ProvingKey<Scalar, PCS> = keygen_pk(vk.clone(), &circuit)?;
    info!("vk size: {}", vk.bytes_length(SerdeFormat::Processed));

    let mut transcript = CTranscript::init();

    // no instance, just dummy 42 to make prover and verifier happy
    let instance = [Base::from(42u64), Base::from(42u64), Base::from(42u64)];
    info!("Public inputs: {:?}", instance);

    create_proof(
        &kzg_params,
        &pk,
        &[circuit],
        &[&[&instance]],
        &mut rng,
        &mut transcript,
    )
    .context("proof generation should not fail")?;

    let proof = transcript.finalize();

    info!("proof size {:?}", proof.len());

    let mut invalid_proof = proof.clone();
    // index points to bytes of first scalar that is part of the proof
    // this should be safe and not result in malformed encoding exception
    // which is likely for flipping Byte for compressed G1 element
    // simple mul has 8 G1 elements at the beginning of the proof each 48 bytes long
    let index = 48 * 8 + 2;
    let firs_byte = invalid_proof[index];
    let negated_firs_byte = !firs_byte;
    invalid_proof[index] = negated_firs_byte;

    let mut transcript_verifier = CTranscript::init_from_bytes(&proof);
    let verifier = prepare::<_, PCS, CTranscript>(&vk, &[&[&instance]], &mut transcript_verifier)
        .context("prepare verification failed")?;

    verifier
        .verify(&kzg_params.verifier_params())
        .map_err(|e| anyhow!("{e:?}"))
        .context("verify failed")?;

    let chips: &[SupportedChips] = &[];
    cost_evaluation(&kzg_params, &vk, &instance, chips, 2, 1, 0, 3)?;

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
