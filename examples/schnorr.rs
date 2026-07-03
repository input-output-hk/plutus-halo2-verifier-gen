use anyhow::{Context as _, Result, anyhow};
use group::Group;
use log::{debug, info};
use rand::rngs::StdRng;
use rand_core::SeedableRng;

use midnight_circuits::hash::poseidon::PoseidonChip;
use midnight_circuits::instructions::hash::HashCPU;
use midnight_curves::{Base, Bls12, BlsScalar as Scalar, Fq};
use midnight_curves::{Fr as JubjubScalar, JubjubAffine, JubjubExtended as Jubjub, JubjubSubgroup};
use midnight_proofs::{
    circuit::Value,
    plonk::{
        ProvingKey, VerifyingKey, commit_to_instances, create_proof, k_from_circuit, keygen_pk,
        keygen_vk, prepare,
    },
    poly::commitment::Guard,
    poly::kzg::{
        KZGCommitmentScheme,
        params::{ParamsKZG, ParamsVerifierKZG},
    },
    transcript::{CircuitTranscript, Transcript},
};
use midnight_zk_stdlib::MidnightCircuit;
use midnight_zk_stdlib::Relation;

use plutus_halo2_verifier_gen::{
    circuits::schnorr_circuit::{SchnorrExample, SchnorrSignature, utils::verify},
    kzg_params::get_or_create_kzg_params,
    plutus_gen::{
        CardanoFriendlyBlake2b, CircuitConfig, SupportedChips, cost_evaluation,
        generate_aiken_verifier, generate_plinth_verifier, lookup_chip,
    },
};

pub type KZG = KZGCommitmentScheme<Bls12>;
pub type Params = ParamsKZG<Bls12>;
pub type ParamsVK = ParamsVerifierKZG<Bls12>;
pub type CTranscript = CircuitTranscript<CardanoFriendlyBlake2b>;

#[path = "shared_utils/mod.rs"]
mod shared_utils;

// Returns the affine coordinates of a given Jubjub point.
fn get_coords(point: &JubjubSubgroup) -> (Base, Base) {
    let point: &Jubjub = point.into();
    let point: JubjubAffine = point.into();
    (point.get_u(), point.get_v())
}

fn main() -> Result<()> {
    env_logger::init();

    // Signing and public keys
    let shnorr_sk = JubjubScalar::from(7);
    let schnorr_pk = JubjubSubgroup::generator() * shnorr_sk;

    // Message
    let msg = Fq::from(42);

    // Signature
    let sig = {
        let k = JubjubScalar::from(2);
        let r = JubjubSubgroup::generator() * k;

        let (rx, ry) = get_coords(&r);
        let (pkx, pky) = get_coords(&schnorr_pk);

        let h = PoseidonChip::hash(&[pkx, pky, rx, ry, msg]);
        let e_bytes = h.to_bytes_le();

        let s = {
            let mut buff = [0u8; 64];
            buff[..32].copy_from_slice(&e_bytes);
            let e = JubjubScalar::from_bytes_wide(&buff);
            k - e * shnorr_sk
        };

        SchnorrSignature { s, e_bytes }
    };

    // Sanity check the signature verifies:
    assert!(verify(&sig, &schnorr_pk, msg));

    // Creating proof
    let seed = [0u8; 32]; // UNSAFE, constant seed is used for testing purposes
    let mut rng: StdRng = SeedableRng::from_seed(seed);

    let relation = SchnorrExample;
    let witness = sig;
    debug!(
        "circuit: {:?}",
        SchnorrExample::format_committed_instances(&witness)
    );
    let instance = (schnorr_pk, msg);

    let circuit = MidnightCircuit::new(
        &relation,
        Value::known(instance),
        Value::known(witness.clone()),
        None,
    );
    let k = k_from_circuit(&circuit);
    let params: Params = get_or_create_kzg_params(k, rng.clone())?;
    let vk: VerifyingKey<Scalar, KZG> =
        keygen_vk(&params, &circuit).context("keygen_vk should not fail")?;
    let pk: ProvingKey<Scalar, KZG> =
        keygen_pk(vk.clone(), &circuit).context("keygen_pk should not fail")?;

    let mut transcript = CTranscript::init();
    debug!("transcript: {:?}", transcript);

    let formatted_instance = SchnorrExample::format_instance(&instance).unwrap();
    let formatted_witness = SchnorrExample::format_committed_instances(&witness.clone());
    let committed_signature = commit_to_instances::<_, KZGCommitmentScheme<_>>(
        &params,
        vk.get_domain(),
        &formatted_witness,
    );

    info!("Public inputs: {:?}", formatted_instance);
    let nb_committed_instances = 1;
    create_proof(
        &params,
        &pk,
        &[circuit],
        nb_committed_instances,
        &[&[&formatted_witness, &formatted_instance]],
        &mut transcript,
        &mut rng,
    )
    .context("proof generation should not fail")?;

    let proof = transcript.finalize();

    let mut invalid_proof = proof.clone();
    let index = 48 * 22 + 2;
    let firs_byte = invalid_proof[index];
    let negated_firs_byte = !firs_byte;
    invalid_proof[index] = negated_firs_byte;

    info!("proof size {:?}", proof.len());

    let mut transcript_verifier = CTranscript::init_from_bytes(&proof);
    let verifier = prepare::<_, KZG, CTranscript>(
        &vk,
        &[&[committed_signature]],
        &[&[&formatted_instance]],
        &mut transcript_verifier,
    )
    .context("prepare verification failed")?;

    verifier
        .verify(&params.verifier_params())
        .map_err(|e| anyhow!("{e:?}"))
        .context("verify failed")?;

    let chips = &[
        SupportedChips::EdwardsJubjub,
        SupportedChips::Poseidon,
        lookup_chip("pow2range".to_string(), 1, 0, 0),
    ];
    cost_evaluation(
        &params,
        &vk,
        None,
        &formatted_instance,
        Some(committed_signature),
        chips,
        CircuitConfig::default(),
    )?;

    shared_utils::export_plinth(&formatted_instance, Some(committed_signature), &proof)?;
    generate_plinth_verifier(
        &params,
        &vk,
        None,
        &formatted_instance,
        Some(committed_signature),
    )
    .context("Plinth verifier generation failed")?;

    shared_utils::export_aiken(&formatted_instance, Some(committed_signature), &proof)?;
    generate_aiken_verifier(
        &params,
        &vk,
        None,
        &formatted_instance,
        Some(committed_signature),
        Some((proof.clone(), invalid_proof)),
    )
    .context("Aiken verifier generation failed")?;

    Ok(())
}
