use anyhow::{Context as _, Result, anyhow};
use log::info;
use rand::prelude::StdRng;
use rand_core::SeedableRng;
use std::fs::File;
use std::marker::PhantomData;

use midnight_curves::{Base, Bls12, Fq as Scalar};
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
    circuits::lookup_table_circuit::LookupTest, kzg_params::get_or_create_kzg_params,
};

pub type KZG = KZGCommitmentScheme<Bls12>;
pub type Params = ParamsKZG<Bls12>;
pub type ParamsVK = ParamsVerifierKZG<Bls12>;
pub type CTranscript = CircuitTranscript<CardanoFriendlyBlake2b>;

fn main() -> Result<()> {
    env_logger::init();

    let seed = [0u8; 32]; // UNSAFE, constant seed is used for testing purposes
    let mut rng: StdRng = SeedableRng::from_seed(seed);

    let circuit = LookupTest::<Scalar> {
        inputs: vec![(42, 8), (53, 7), (12, 8), (46, 8)],
        max_bit_len: 9,
        native_field: PhantomData,
    };

    let k: u32 = k_from_circuit(&circuit);
    let kzg_params: Params = get_or_create_kzg_params(k, rng.clone())?;
    let vk: VerifyingKey<Scalar, KZG> = keygen_vk(&kzg_params, &circuit)?;
    let pk: ProvingKey<Scalar, KZG> = keygen_pk(vk.clone(), &circuit)?;

    // no instances, just dummy 42 to make prover and verifier happy
    let instances: &[&[&[Scalar]]] =
        &[&[&[Base::from(42u64), Base::from(42u64), Base::from(42u64)]]];
    info!("Public inputs: {:?}", instances);

    let mut transcript = CTranscript::init();

    let nb_committed_instances = 0;
    create_proof(
        &kzg_params,
        &pk,
        &[circuit.clone()],
        nb_committed_instances,
        instances,
        &mut rng,
        &mut transcript,
    )
    .context("proof generation should not fail")?;

    let proof = transcript.finalize();

    info!("proof size {:?}", proof.len());

    let mut transcript_verifier = CTranscript::init_from_bytes(&proof);

    let verifier = prepare(&vk, &[&[]], instances, &mut transcript_verifier)
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
        nb_committed_instances,
        &[&[&[Base::from(1u64), Base::from(1u64), Base::from(1u64)]]],
        &mut rng,
        &mut invalid_transcript,
    )
    .context("proof generation should not fail")?;
    let invalid_proof = invalid_transcript.finalize();

    let instances_file =
        "./plinth-verifier/plutus-halo2/test/Generic/serialized_public_input.hex".to_string();
    let mut output = File::create(instances_file).context("failed to create instances file")?;
    export_public_inputs(instances, &mut output).context("failed to export public inputs")?;

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

    generate_plinth_verifier(&kzg_params, &vk, instances)
        .context("Plinth verifier generation failed")?;

    generate_aiken_verifier(
        &kzg_params,
        &vk,
        instances,
        None,
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
