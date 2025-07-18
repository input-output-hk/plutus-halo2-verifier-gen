use blstrs::{Base, Bls12, G1Projective, Scalar};
use ff::Field;
use halo2_proofs::{
    halo2curves::group::GroupEncoding,
    plonk::{
        ProvingKey, VerifyingKey, create_proof, k_from_circuit, keygen_pk, keygen_vk, prepare,
    },
    poly::{
        commitment::Guard, commitment::PolynomialCommitmentScheme, gwc_kzg::GwcKZGCommitmentScheme,
        kzg::KZGCommitmentScheme, kzg::params::ParamsKZG, kzg::params::ParamsVerifierKZG,
    },
    transcript::{CircuitTranscript, Transcript},
};
use log::{debug, info};
use plutus_halo2_verifier_gen::{
    circuits::simple_mul_circuit::SimpleMulCircuit,
    plutus_gen::{
        adjusted_types::CardanoFriendlyState, extraction::ExtractKZG, generate_plinth_verifier,
        proof_serialization::export_public_inputs, proof_serialization::serialize_proof,
    },
};
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use std::env;
use std::fs::File;

fn main() {
    env_logger::init_from_env(env_logger::Env::default().filter_or("RUST_LOG", "info"));

    let args: Vec<String> = env::args().collect();

    match &args[1..] {
        [] => {
            compile_simple_mul_circuit::<KZGCommitmentScheme<Bls12>>();
        }
        [command] if command == "halo2" => {
            compile_simple_mul_circuit::<KZGCommitmentScheme<Bls12>>();
        }
        [command] if command == "GWC19" => {
            compile_simple_mul_circuit::<GwcKZGCommitmentScheme<Bls12>>();
        }
        _ => {
            println!(
                "usage: to run halo2 KZG variant do not pass any option or pass halo2, to run GWC19 variant pass GWC19"
            )
        }
    }
}

fn compile_simple_mul_circuit<
    S: PolynomialCommitmentScheme<
            Scalar,
            Commitment = G1Projective,
            Parameters = ParamsKZG<Bls12>,
            VerifierParameters = ParamsVerifierKZG<Bls12>,
        > + ExtractKZG,
>() {
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
    debug!("circuit: {:?}", circuit);

    let seed = [0u8; 32]; // UNSAFE, constant seed is used for testing purposes
    let mut rng: StdRng = SeedableRng::from_seed(seed);

    let k: u32 = k_from_circuit(&circuit);
    let params: ParamsKZG<Bls12> = ParamsKZG::<Bls12>::unsafe_setup(k, rng.clone());
    let vk: VerifyingKey<_, S> = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    let pk: ProvingKey<_, S> = keygen_pk(vk.clone(), &circuit).expect("keygen_pk should not fail");

    let mut transcript: CircuitTranscript<CardanoFriendlyState> =
        CircuitTranscript::<CardanoFriendlyState>::init();
    debug!("transcript: {:?}", transcript);

    // no instances, just dummy 42 to make prover and verifier happy
    let instances: &[&[&[Scalar]]] =
        &[&[&[Base::from(42u64), Base::from(42u64), Base::from(42u64)]]];
    info!("Public inputs: {:?}", instances);

    let instances_file =
        "./plutus-verifier/plutus-halo2/test/Generic/serialized_public_input.hex".to_string();
    let mut output = File::create(instances_file).expect("failed to create instances file");
    export_public_inputs(instances, &mut output);

    create_proof(
        &params,
        &pk,
        &[circuit],
        instances,
        &mut rng,
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
        .verify(&params.verifier_params())
        .expect("verify failed");

    serialize_proof(
        "./plutus-verifier/plutus-halo2/test/Generic/serialized_proof.json".to_string(),
        proof,
    )
    .unwrap();

    generate_plinth_verifier(&params, &vk, instances, |a| hex::encode(a.to_bytes()))
        .expect("Plinth verifier generation failed");
}
