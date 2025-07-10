use blstrs::{Base, Bls12, Scalar};
use halo2_proofs::halo2curves::group::GroupEncoding;
use halo2_proofs::plonk::{k_from_circuit, ProvingKey, VerifyingKey};
use halo2_proofs::poly::gwc_kzg::GwcKZGCommitmentScheme;
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, prepare},
    poly::{commitment::Guard, kzg::params::ParamsKZG},
    transcript::{CircuitTranscript, Transcript},
};
use log::info;
use plutus_halo2_verifier_gen::circuits::atms_circuit::{prepare_test_signatures, AtmsSignatureCircuit};
use plutus_halo2_verifier_gen::plutus_gen::adjusted_types::CardanoFriendlyState;
use plutus_halo2_verifier_gen::plutus_gen::generate_plinth_verifier;
use plutus_halo2_verifier_gen::plutus_gen::proof_serialization::serialize_proof;
use rand::prelude::StdRng;
use rand_core::SeedableRng;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() {
    env_logger::init_from_env(env_logger::Env::default().filter_or("RUST_LOG", "trace"));

    compile_atms_circuit();
}

pub fn compile_atms_circuit() {
    let seed = [0u8; 32]; // Choose a fixed seed for testing
    let mut rng: StdRng = SeedableRng::from_seed(seed);

    let num_parties = 90;
    let threshold = 50;
    let msg = Base::from(42u64);

    let (signatures, pks, pks_comm) =
        prepare_test_signatures(num_parties, threshold, msg, &mut rng);

    let circuit = AtmsSignatureCircuit {
        signatures,
        pks,
        pks_comm,
        msg,
        threshold: Base::from(threshold as u64),
    };

    let k: u32 = k_from_circuit(&circuit);
    let kzg_params: ParamsKZG<Bls12> = ParamsKZG::<Bls12>::unsafe_setup(k, rng.clone());
    let vk: VerifyingKey<Scalar, GwcKZGCommitmentScheme<Bls12>> = keygen_vk(&kzg_params, &circuit).unwrap();
    let pk: ProvingKey<Scalar, GwcKZGCommitmentScheme<Bls12>> = keygen_pk(vk.clone(), &circuit).unwrap();

    // no instances, just dummy 42 to make prover and verifier happy
    let instances: &[&[&[Scalar]]] =
        &[&[&[pks_comm, msg, Base::from(threshold as u64)]]];
    info!("Public inputs: {:?}", instances);

    let instances_file = "./plutus-verifier/plutus-halo2/test/Generic/serialized_public_input.hex".to_string();
    let mut output = File::create(instances_file).expect("failed to create instances file");
    for instance in instances[0][0].iter() {
        let mut value = instance.to_bytes_le();
        value.reverse();
        let _ = output.write((hex::encode(value) + "\n").as_bytes());
    }

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

    serialize_proof("./plutus-verifier/plutus-halo2/test/Generic/serialized_proof.json".to_string(), proof).unwrap();

    generate_plinth_verifier(
        &kzg_params,
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
