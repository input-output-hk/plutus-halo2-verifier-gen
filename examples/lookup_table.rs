use anyhow::{Context as _, Result, anyhow};
use cardhalo::{circuits::lookup_table_circuit::LookupTest, kzg_params::get_or_create_kzg_params};
use log::info;
use midnight_curves::{Base, Fq as Scalar};
use midnight_proofs::{
    plonk::{create_proof, k_from_circuit, keygen_pk, keygen_vk, prepare},
    poly::commitment::Guard,
    transcript::Transcript,
};
use rand::rngs::StdRng;
use rand_core::SeedableRng;

use std::marker::PhantomData;

#[path = "./utils.rs"]
mod utils;
use utils::{CTranscript, PCS, PK, Params, VK, export_all};

fn main() -> Result<()> {
    let seed = [0u8; 32]; // UNSAFE, constant seed is used for testing purposes
    let mut rng: StdRng = SeedableRng::from_seed(seed);

    let circuit = LookupTest::<Scalar> {
        inputs: vec![(42, 8), (53, 7), (12, 8), (46, 8)],
        max_bit_len: 9,
        native_field: PhantomData,
    };

    let k: u32 = k_from_circuit(&circuit);
    let params: Params = get_or_create_kzg_params(k, rng.clone())?;
    let vk: VK = keygen_vk(&params, &circuit)?;
    let pk: PK = keygen_pk(vk.clone(), &circuit)?;

    // no instances, just dummy 42 to make prover and verifier happy
    let instances: &[&[&[Scalar]]] =
        &[&[&[Base::from(42u64), Base::from(42u64), Base::from(42u64)]]];
    info!("Public inputs: {:?}", instances);

    let mut transcript = CTranscript::init();

    let nb_committed_instances = 0;
    create_proof(
        &params,
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

    let verifier = prepare::<_, PCS, CTranscript>(&vk, &[&[]], instances, &mut transcript_verifier)
        .context("prepare verification failed")?;

    verifier
        .verify(&params.verifier_params())
        .map_err(|e| anyhow!("{e:?}"))
        .context("verify failed")?;

    // Create invalid proof inputs for testing (with wrong public inputs)
    let mut invalid_transcript = CTranscript::init();
    create_proof(
        &params,
        &pk,
        &[circuit.clone()],
        nb_committed_instances,
        &[&[&[Base::from(1u64), Base::from(1u64), Base::from(1u64)]]],
        &mut rng,
        &mut invalid_transcript,
    )
    .context("proof generation should not fail")?;
    let invalid_proof = invalid_transcript.finalize();

    export_all(proof, params, vk, instances, invalid_proof)
}
