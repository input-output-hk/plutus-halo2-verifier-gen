//! The example implements an Atms circuit with lookup argument.
//! The goal is to check how the presence of lookup argument increases verification time of the proof in Plutus.
//! We also test verification time for different number of signatures
//!
//! Plutus verifier cost:
//!       ATMS (k=14, 6/3) + Lookup:
//!   Resources used: ExBudget {exBudgetCPU = ExCPU 10,711,265,484, exBudgetMemory = ExMemory 4,803,169, script size = 15,245}
//!       ATMS (k=17, 90/50) + Lookup:
//!   Resources used: ExBudget {exBudgetCPU = ExCPU 10,733,382,733, exBudgetMemory = ExMemory 4,882,403}, script size = 15,246}
//!       ATMS (k=19, 408/228) + Lookup:
//!   Resources used: ExBudget {exBudgetCPU = ExCPU 10,729,854,984, exBudgetMemory = ExMemory 4,867,856}, script size = 15,245}
//!
//! We can see that the number of rows affects the verifier negligibly.
//! On the other hand, number of advice columns affects the verifier significantly.

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
    circuits::{
        atms_circuit::prepare_test_signatures, atms_with_lookups_circuit::AtmsLookupCircuit,
    },
    plutus_gen::{
        adjusted_types::CardanoFriendlyState, extraction::ExtractKZG, generate_plinth_verifier,
        proof_serialization::export_public_inputs, proof_serialization::serialize_proof,
    },
};
use rand::prelude::StdRng;
use rand_core::SeedableRng;
use std::env;
use std::fs::File;

fn main() {
    env_logger::init_from_env(env_logger::Env::default().filter_or("RUST_LOG", "info"));
    let args: Vec<String> = env::args().collect();

    match &args[1..] {
        [] => {
            compile_atms_lookup_circuit::<KZGCommitmentScheme<Bls12>>();
        }
        [command] if command == "gwc_kzg" => {
            compile_atms_lookup_circuit::<GwcKZGCommitmentScheme<Bls12>>();
        }
        _ => {
            println!("Usage:");
            println!("- to run the example: `cargo run --example example_name`");
            println!(
                "- to run the example using the GWC19 version of multi-open KZG, run: `cargo run --example example_name gwc_kzg`"
            );
        }
    }
}

pub fn compile_atms_lookup_circuit<
    S: PolynomialCommitmentScheme<
            Scalar,
            Commitment = G1Projective,
            Parameters = ParamsKZG<Bls12>,
            VerifierParameters = ParamsVerifierKZG<Bls12>,
        > + ExtractKZG,
>() {
    let seed = [0u8; 32]; // UNSAFE, constant seed is used for testing purposes
    let rng: StdRng = SeedableRng::from_seed(seed);

    const NUM_PARTIES: usize = 6;
    const THRESHOLD: usize = 3;
    // const NUM_PARTIES: usize = 408;
    // const THRESHOLD: usize = 228;
    let msg = Base::from(42u64);

    let (signatures, pks, pks_comm) =
        prepare_test_signatures(NUM_PARTIES, THRESHOLD, msg, &mut rng.clone());

    let circuit = AtmsLookupCircuit {
        // lookup fields
        inputs: vec![(42, 8), (53, 7), (12, 8), (46, 8)],
        max_bit_len: 9,

        // atms fields
        signatures,
        pks,
        pks_comm,
        msg,
        threshold: Base::from(THRESHOLD as u64),
    };

    let k: u32 = k_from_circuit(&circuit);
    let kzg_params: ParamsKZG<Bls12> = ParamsKZG::<Bls12>::unsafe_setup(k, rng.clone());
    let vk: VerifyingKey<Scalar, S> = keygen_vk(&kzg_params, &circuit).unwrap();
    let pk: ProvingKey<Scalar, S> = keygen_pk(vk.clone(), &circuit).unwrap();

    // no instances, just dummy 42 to make prover and verifier happy
    let instances: &[&[&[Scalar]]] = &[&[&[pks_comm, msg, Base::from(THRESHOLD as u64)]]];
    info!("Public inputs: {:?}", instances);

    let instances_file =
        "./plutus-verifier/plutus-halo2/test/Generic/serialized_public_input.hex".to_string();
    let mut output = File::create(instances_file).expect("failed to create instances file");
    export_public_inputs(instances, &mut output);

    let mut transcript: CircuitTranscript<CardanoFriendlyState> =
        CircuitTranscript::<CardanoFriendlyState>::init();

    create_proof(
        &kzg_params,
        &pk,
        &[circuit],
        instances,
        &mut rng.clone(),
        &mut transcript,
    )
    .expect("proof generation should not fail");

    let proof = transcript.finalize();
    info!("proof size {:?}", proof.len());

    let mut transcript_verifier: CircuitTranscript<CardanoFriendlyState> =
        CircuitTranscript::<CardanoFriendlyState>::init_from_bytes(&proof);

    let verifier = prepare::<_, _, CircuitTranscript<CardanoFriendlyState>>(
        &vk,
        instances,
        &mut transcript_verifier,
    )
    .expect("prepare verification failed");

    verifier
        .verify(&kzg_params.verifier_params())
        .expect("verify failed");

    serialize_proof(
        "./plutus-verifier/plutus-halo2/test/Generic/serialized_proof.json".to_string(),
        proof.clone(),
    )
    .expect("json proof serialization failed");

    export_proof(
        "./plutus-verifier/plutus-halo2/test/Generic/serialized_proof.hex".to_string(),
        proof.clone(),
    )
    .expect("hex proof serialization failed");

    generate_plinth_verifier(&kzg_params, &vk, instances)
        .expect("Plinth verifier generation failed");

    generate_aiken_verifier(&kzg_params, &vk, instances, Some(proof))
        .expect("Aiken verifier generation failed");
}
