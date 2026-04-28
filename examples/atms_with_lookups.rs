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

use anyhow::{Context as _, Result, anyhow};
use log::info;
use rand::prelude::StdRng;
use rand_core::SeedableRng;

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

use plutus_halo2_verifier_gen::{
    circuits::{
        atms_circuit::prepare_test_signatures, atms_with_lookups_circuit::AtmsLookupCircuit,
    },
    kzg_params::get_or_create_kzg_params,
    plutus_gen::{CardanoFriendlyBlake2b, generate_aiken_verifier, generate_plinth_verifier},
};

pub type KZG = KZGCommitmentScheme<Bls12>;
pub type Params = ParamsKZG<Bls12>;
pub type ParamsVK = ParamsVerifierKZG<Bls12>;
pub type CTranscript = CircuitTranscript<CardanoFriendlyBlake2b>;

#[path = "shared_utils/mod.rs"]
mod shared_utils;

fn main() -> Result<()> {
    env_logger::init();

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
    let kzg_params: Params = get_or_create_kzg_params(k, rng.clone())?;
    let vk: VerifyingKey<Scalar, KZG> = keygen_vk(&kzg_params, &circuit)?;
    let pk: ProvingKey<Scalar, KZG> = keygen_pk(vk.clone(), &circuit)?;

    // no instances, just dummy 42 to make prover and verifier happy
    let instance = [pks_comm, msg, Base::from(THRESHOLD as u64)];
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
    info!("proof size {:?}", proof.len());

    let mut invalid_proof = proof.clone();
    // index points to bytes of first scalar that is part of the proof
    // this should be safe and not result in malformed encoding exception
    // which is likely for flipping Byte for compressed G1 element
    // atms with lookups has 20 G1 elements at the beginning of the proof each 48 bytes long
    let index = 48 * 20 + 2;
    let firs_byte = invalid_proof[index];
    let negated_firs_byte = !firs_byte;
    invalid_proof[index] = negated_firs_byte;

    let mut transcript_verifier = CTranscript::init_from_bytes(&proof);

    let verifier = prepare(&vk, &[&[]], &[&[&instance]], &mut transcript_verifier)
        .context("prepare verification failed")?;

    verifier
        .verify(&kzg_params.verifier_params())
        .map_err(|e| anyhow!("{e:?}"))
        .context("verify failed")?;

    shared_utils::export_plinth(&instance, None, &proof)?;
    generate_plinth_verifier(&kzg_params, &vk, &instance, None)
        .context("Plinth verifier generation failed")?;

    shared_utils::export_aiken(&instance, None, &proof)?;
    generate_aiken_verifier(
        &kzg_params,
        &vk,
        &instance,
        None,
        Some((proof.clone(), invalid_proof)),
    )
    .context("Aiken verifier generation failed")?;

    Ok(())
}
