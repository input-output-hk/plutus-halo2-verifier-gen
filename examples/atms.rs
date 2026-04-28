use anyhow::{Context as _, Result, anyhow};
use log::info;
use rand::prelude::StdRng;
use rand_core::SeedableRng;
use std::fs::File;

use midnight_curves::{Base, Bls12, BlsScalar as Scalar};
use midnight_proofs::{
    plonk::{
        ProvingKey, VerifyingKey, create_proof, k_from_circuit, keygen_pk, keygen_vk, prepare,
    },
    poly::{
        commitment::Guard,
        kzg::{
            KZGCommitmentScheme,
            params::{ParamsKZG, ParamsVerifierKZG},
        },
    },
    transcript::{CircuitTranscript, Transcript},
};

use plutus_halo2_verifier_gen::plutus_gen::{
    CardanoFriendlyBlake2b, export_proof, export_public_inputs, generate_aiken_verifier,
    generate_plinth_verifier, serialize_proof,
};
use plutus_halo2_verifier_gen::{
    circuits::atms_circuit::{AtmsSignatureCircuit, prepare_test_signatures},
    kzg_params::get_or_create_kzg_params,
};

pub type KZG = KZGCommitmentScheme<Bls12>;
pub type Params = ParamsKZG<Bls12>;
pub type ParamsVK = ParamsVerifierKZG<Bls12>;
pub type CTranscript = CircuitTranscript<CardanoFriendlyBlake2b>;

fn main() -> Result<()> {
    env_logger::init();

    let seed = [0u8; 32]; // UNSAFE, constant seed is used for testing purposes
    let rng: StdRng = SeedableRng::from_seed(seed);

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
    let kzg_params: Params = get_or_create_kzg_params(k, rng.clone())?;
    let vk: VerifyingKey<Scalar, KZG> = keygen_vk(&kzg_params, &circuit)?;
    let pk: ProvingKey<Scalar, KZG> = keygen_pk(vk.clone(), &circuit)?;

    // no instances, just dummy 42 to make prover and verifier happy
    let instance = [pks_comm, msg, Base::from(threshold as u64)];
    info!("Public inputs: {:?}", instance);

    let mut transcript = CTranscript::init();

    let nb_committed_instances = 0;
    create_proof(
        &kzg_params,
        &pk,
        &[circuit],
        nb_committed_instances,
        &[&[&instance]],
        &mut rng.clone(),
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

    let mut transcript_verifier = CTranscript::init_from_bytes(&proof);

    let verifier = prepare(&vk, &[&[]], &[&[&instance]], &mut transcript_verifier)
        .context("prepare verification failed")?;

    verifier
        .verify(&kzg_params.verifier_params())
        .map_err(|e| anyhow!("{e:?}"))
        .context("verify failed")?;

    let instance_file =
        "./plinth-verifier/plutus-halo2/test/Generic/serialized_public_input.hex".to_string();
    let mut output = File::create(instance_file).context("failed to create instance file")?;
    export_public_inputs(&instance, &mut output).context("failed to export public inputs")?;

    serialize_proof(
        "./plinth-verifier/plutus-halo2/test/Generic/serialized_proof.json".to_string(),
        proof.clone(),
    )
    .context("json proof serialization failed")?;

    export_proof(
        "./plinth-verifier/plutus-halo2/test/Generic/serialized_proof.hex".to_string(),
        proof.clone(),
    )
    .context("hex proof serialization failed")?;

    generate_plinth_verifier(&kzg_params, &vk, &instance, None)
        .context("Plinth verifier generation failed")?;

    generate_aiken_verifier(
        &kzg_params,
        &vk,
        &instance,
        None,
        Some((proof.clone(), invalid_proof)),
    )
    .context("Aiken verifier generation failed")?;
    export_proof(
        "./aiken-verifier/submitter/serialized_proof.hex".to_string(),
        proof,
    )
    .context("hex proof serialization failed")?;

    let instance_file = "./aiken-verifier/submitter/serialized_public_input.hex".to_string();
    let mut output = File::create(instance_file).context("failed to create instance file")?;
    export_public_inputs(&instance, &mut output).context("Failed to export the public inputs")?;

    Ok(())
}
