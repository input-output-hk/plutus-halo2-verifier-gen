use anyhow::{Context as _, Result, anyhow};
use cardhalo::circuits::atms_circuit::prepare_test_signatures;
use cardhalo::circuits::atms_with_lookups_circuit::AtmsLookupCircuit;
use cardhalo::kzg_params::get_or_create_kzg_params;
use cardhalo::plutus_gen::emit_verifier_aiken;
use cardhalo::plutus_gen::extraction::{extract_circuit, extract_kzg_steps};
use midnight_curves::{Base, Bls12, BlsScalar as Scalar};
use midnight_proofs::plonk::{VerifyingKey, k_from_circuit, keygen_vk};
use midnight_proofs::poly::kzg::KZGCommitmentScheme;
use midnight_proofs::poly::kzg::params::ParamsKZG;
use rand::prelude::StdRng;
use rand_core::SeedableRng;
use std::path::Path;

fn main() -> Result<()> {
    let seed = [0u8; 32];
    let rng: StdRng = SeedableRng::from_seed(seed);
    const NUM_PARTIES: usize = 6;
    const THRESHOLD: usize = 3;
    let msg = Base::from(42u64);

    let (signatures, pks, pks_comm) =
        prepare_test_signatures(NUM_PARTIES, THRESHOLD, msg, &mut rng.clone());

    let circuit = AtmsLookupCircuit {
        inputs: vec![(42, 8), (53, 7), (12, 8), (46, 8)],
        max_bit_len: 9,
        signatures,
        pks,
        pks_comm,
        msg,
        threshold: Base::from(THRESHOLD as u64),
    };

    let k: u32 = k_from_circuit(&circuit);
    let kzg_params: ParamsKZG<Bls12> = get_or_create_kzg_params(k, rng.clone())?;
    let vk: VerifyingKey<Scalar, KZGCommitmentScheme<Bls12>> = keygen_vk(&kzg_params, &circuit)?;

    let instances: &[&[&[Scalar]]] = &[&[&[pks_comm, msg, Base::from(THRESHOLD as u64)]]];

    let circuit_representation = extract_circuit(&kzg_params, &vk, instances)
        .map_err(|e| anyhow!("{e}"))
        .context("Circuit extraction failed")?;

    // Step 2: extract KZG steps specific to used commitment scheme
    let circuit_representation = extract_kzg_steps(circuit_representation);

    emit_verifier_aiken(
        Path::new("aiken-verifier/templates/gates_test.hbs"),
        Path::new("aiken-verifier/aiken_halo2/lib/gates_test.ak"),
        None,
        &circuit_representation,
        None,
    )
    .context("Emitting KZG verification failed")?;

    Ok(())
}
