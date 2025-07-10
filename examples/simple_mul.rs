use blstrs::{Base, Bls12, Scalar};
use ff::Field;
use halo2_proofs::halo2curves::group::GroupEncoding;
use halo2_proofs::plonk::{k_from_circuit, ProvingKey, VerifyingKey};
use halo2_proofs::poly::gwc_kzg::GwcKZGCommitmentScheme;
use halo2_proofs::poly::kzg::msm::DualMSM;
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, prepare},
    poly::{commitment::Guard, kzg::params::ParamsKZG},
    transcript::{CircuitTranscript, Transcript},
};
use log::info;
use plutus_halo2_verifier_gen::circuits::simple_mul_circuit::SimpleMulCircuit;
use plutus_halo2_verifier_gen::plutus_gen::adjusted_types::CardanoFriendlyState;
use plutus_halo2_verifier_gen::plutus_gen::generate_plinth_verifier;
use plutus_halo2_verifier_gen::plutus_gen::proof_serialization::serialize_proof;
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use std::{fs::File, io::Write, path::Path};

fn main() {
    env_logger::init_from_env(env_logger::Env::default().filter_or("RUST_LOG", "info"));

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
    info!("circuit: {:?}", circuit);

    let seed = [0u8; 32]; // Choose a fixed seed for testing
    let mut rng: StdRng = SeedableRng::from_seed(seed);

    let k: u32 = k_from_circuit(&circuit);
    let params: ParamsKZG<Bls12> = ParamsKZG::<Bls12>::unsafe_setup(k, rng.clone());
    let vk: VerifyingKey<_, GwcKZGCommitmentScheme<Bls12>> =
        keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    let pk: ProvingKey<_, GwcKZGCommitmentScheme<Bls12>> =
        keygen_pk(vk.clone(), &circuit).expect("keygen_pk should not fail");

    let mut transcript: CircuitTranscript<CardanoFriendlyState> =
        CircuitTranscript::<CardanoFriendlyState>::init();
    info!("transcript: {:?}", transcript);

    // no instances, just dummy 42 to make prover and verifier happy
    let instances: &[&[&[Scalar]]] =
        &[&[&[Base::from(42u64), Base::from(42u64), Base::from(42u64)]]];
    info!("Public inputs: {:?}", instances);

    let instances_file = "./plutus-verifier/plutus-halo2/test/Generic/serialized_public_input.hex".to_string();
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
    info!("proof size {:?}", proof.len());

    let mut transcript_verifier: CircuitTranscript<CardanoFriendlyState> =
        CircuitTranscript::<CardanoFriendlyState>::init_from_bytes(&proof);
    let verifier: DualMSM<_, _> = prepare::<_, _, CircuitTranscript<CardanoFriendlyState>>(
        &vk,
        instances,
        &mut transcript_verifier,
    )
        .expect("prepare verification failed");

    verifier
        .verify(&params.verifier_params())
        .expect("verify failed");

    serialize_proof("./plutus-verifier/plutus-halo2/test/Generic/serialized_proof.json".to_string(), proof).unwrap();

    generate_plinth_verifier(
        &params,
        &vk,
        instances,
        Path::new("plutus-verifier/verification.hbs"),
        Path::new("plutus-verifier/vk_constants.hbs"),
        Path::new("plutus-verifier/plutus-halo2/src/Plutus/Crypto/Halo2/Generic/Verifier.hs"),
        Path::new("plutus-verifier/plutus-halo2/src/Plutus/Crypto/Halo2/Generic/VKConstants.hs"),
        |a| hex::encode(a.to_bytes()),
    )
        .expect("Plinth verifier generation failed");
}
