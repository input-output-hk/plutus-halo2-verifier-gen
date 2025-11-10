use blstrs::{Base, Bls12, Scalar};
use halo2_proofs::plonk::{ProvingKey, VerifyingKey, k_from_circuit, keygen_pk, keygen_vk};
use halo2_proofs::poly::kzg::KZGCommitmentScheme;
use halo2_proofs::poly::kzg::params::ParamsKZG;
use plutus_halo2_verifier_gen::circuits::atms_circuit::prepare_test_signatures;
use plutus_halo2_verifier_gen::circuits::atms_with_lookups_circuit::AtmsLookupCircuit;
use plutus_halo2_verifier_gen::plutus_gen::emit_verifier_code_aiken;
use plutus_halo2_verifier_gen::plutus_gen::extraction::{ExtractKZG, extract_circuit};
use rand::prelude::StdRng;
use rand_core::SeedableRng;
use std::path::Path;

fn main() {
    type KZG = KZGCommitmentScheme<Bls12>;

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
    let kzg_params: ParamsKZG<Bls12> = ParamsKZG::<Bls12>::unsafe_setup(k, rng.clone());
    let vk: VerifyingKey<Scalar, KZG> = keygen_vk(&kzg_params, &circuit).unwrap();
    let pk: ProvingKey<Scalar, KZG> = keygen_pk(vk.clone(), &circuit).unwrap();

    let instances: &[&[&[Scalar]]] = &[&[&[pks_comm, msg, Base::from(THRESHOLD as u64)]]];

    let circuit_representation = extract_circuit(&kzg_params, &vk, instances)
        .map_err(|e| e.to_string())
        .expect("Circuit extraction failed");

    // Step 2: extract KZG steps specific to used commitment scheme
    let circuit_representation = KZG::extract_kzg_steps(circuit_representation);

    emit_verifier_code_aiken(
        Path::new("aiken-verifier/templates/gates_test.hbs"),
        Path::new("aiken-verifier/aiken_halo2/lib/gates_test.ak"),
        &circuit_representation,
    )
    .expect("Emitting KZG verification failed");
}
