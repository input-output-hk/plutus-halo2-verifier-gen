use anyhow::{Context as _, Result, anyhow};
use ff::Field;
use midnight_curves::{Base, BlsScalar as Scalar};

use midnight_proofs::{
    plonk::{create_proof, k_from_circuit, keygen_pk, keygen_vk, prepare},
    poly::commitment::Guard,
    transcript::Transcript,
};

use cardhalo::{
    circuits::simple_mul_circuit::SimpleMulCircuit, kzg_params::get_or_create_kzg_params,
};
use log::{debug, info};
use rand::rngs::StdRng;
use rand_core::SeedableRng;

#[path = "./utils.rs"]
mod utils;
use utils::{CTranscript, PCS, PK, Params, VK, export_all};

fn main() -> Result<()> {
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
    let params: Params = get_or_create_kzg_params(k, rng.clone())?;
    let vk: VK = keygen_vk(&params, &circuit).context("keygen_vk should not fail")?;
    let pk: PK = keygen_pk(vk.clone(), &circuit).context("keygen_pk should not fail")?;

    let mut transcript = CTranscript::init();
    debug!("transcript: {:?}", transcript);

    // no instances, just dummy 42 to make prover and verifier happy
    let instances: &[&[&[Scalar]]] =
        &[&[&[Base::from(42u64), Base::from(42u64), Base::from(42u64)]]];
    info!("Public inputs: {:?}", instances);

    let nb_committed_instances = 0;
    create_proof(
        &params,
        &pk,
        &[circuit],
        nb_committed_instances,
        instances,
        &mut rng,
        &mut transcript,
    )
    .context("proof generation should not fail")?;

    let proof = transcript.finalize();

    let mut invalid_proof = proof.clone();
    // index points to bytes of first scalar that is part of the proof
    // this should be safe and not result in malformed encoding exception
    // which is likely for flipping Byte for compressed G1 element
    // simple mul has 8 G1 elements at the beginning of the proof each 48 bytes long
    let index = 48 * 8 + 2;
    let firs_byte = invalid_proof[index];
    let negated_firs_byte = !firs_byte;
    invalid_proof[index] = negated_firs_byte;

    info!("proof size {:?}", proof.len());

    let mut transcript_verifier = CTranscript::init_from_bytes(&proof);
    let verifier = prepare::<_, PCS, CTranscript>(&vk, &[&[]], instances, &mut transcript_verifier)
        .context("prepare verification failed")?;

    verifier
        .verify(&params.verifier_params())
        .map_err(|e| anyhow!("{e:?}"))
        .context("verify failed")?;

    export_all(proof, params, vk, instances, invalid_proof)
}
