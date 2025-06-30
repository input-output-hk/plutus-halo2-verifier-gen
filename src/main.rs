mod circuit;
use crate::circuit::MyCircuit;
use blake2b_simd::State;
use blstrs::{Base, Bls12, Scalar};
use ff::Field;
use halo2_proofs::halo2curves::group::GroupEncoding;
use halo2_proofs::plonk::{ProvingKey, VerifyingKey};
use halo2_proofs::poly::kzg::KZGCommitmentScheme;
use halo2_proofs::poly::kzg::msm::DualMSM;
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, prepare},
    poly::{commitment::Guard, kzg::params::ParamsKZG},
    transcript::{CircuitTranscript, Transcript},
};
use log::info;
use plutus_halo2_verifier_gen::code_gen::extraction::extract_circuit;
use plutus_halo2_verifier_gen::code_gen::proof_serialization::serialize_proof;
use rand::rngs::StdRng;
use rand_core_06::SeedableRng;
use std::{fs::File, io::Write};

fn main() {
    env_logger::init_from_env(env_logger::Env::default().filter_or("RUST_LOG", "info"));

    // The number of rows in our circuit cannot exceed 2^k. Since our example
    // circuit is very small, we can pick a very small value here.
    let k = 4;

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
    let circuit = MyCircuit::init(constant, a, b, c);

    info!("circuit: {:?}", circuit);

    let seed = [0u8; 32]; // Choose a fixed seed for testing
    let mut rng: StdRng = SeedableRng::from_seed(seed);

    // Given the correct public input, our circuit will verify.
    let params: ParamsKZG<Bls12> = ParamsKZG::<Bls12>::unsafe_setup(k, rng.clone());
    let vk: VerifyingKey<_, KZGCommitmentScheme<Bls12>> =
        keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    let pk: ProvingKey<_, KZGCommitmentScheme<Bls12>> =
        keygen_pk(vk.clone(), &circuit).expect("keygen_pk should not fail");

    let mut transcript: CircuitTranscript<State> = CircuitTranscript::<State>::init();
    info!("transcript: {:?}", transcript);

    // no instances, just dummy 42 to make prover and verifier happy
    let instances: &[&[&[Scalar]]] =
        &[&[&[Base::from(42u64), Base::from(42u64), Base::from(42u64)]]];
    info!("Public inputs: {:?}", instances);

    let instances_file = "./serialized_public_input.hex".to_string();
    let mut output = File::create(instances_file).expect("failed to create instances file");
    for instance in instances[0][0].iter() {
        let mut value = instance.to_bytes_le();
        value.reverse();
        let _ = output.write((hex::encode(value) + "\n").as_bytes());
    }

    create_proof(
        &params,
        &pk,
        &[circuit],
        instances,
        &mut rng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    info!("transcript: {:?}", transcript);

    let proof = transcript.finalize();

    let proof_for_export = proof.clone();

    info!("proof size {:?}", proof.len());

    let mut transcript_verifier: CircuitTranscript<State> =
        CircuitTranscript::<State>::init_from_bytes(&proof);
    let verifier: DualMSM<Bls12> =
        prepare(&vk, instances, &mut transcript_verifier).expect("prepare verification failed");

    verifier
        .verify(&params.verifier_params())
        .expect("verify failed");

    serialize_proof("./serialized_proof.json".to_string(), proof_for_export).unwrap();

    let data = extract_circuit(
        &params,
        &vk,
        instances,
        "plutus-verifier/verification.hbs".to_string(),
        "plutus-verifier/vk_constants.hbs".to_string(),
        |a| hex::encode(a.to_bytes()),
    )
    .expect("extracting failed");
    println!("extracted data: {:?}", data);
}
