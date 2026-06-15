use anyhow::{Context as _, Result};
use log::info;
use rand::prelude::StdRng;
use rand_core::SeedableRng;
use std::collections::BTreeMap;

use ff::Field;
use group::Group;

use midnight_circuits::{
    hash::poseidon::PoseidonState,
    types::{AssignedNative, Instantiable},
    verifier::{Accumulator, AssignedAccumulator, AssignedVk, BlstrsEmulation, Msm, SelfEmulation},
};
use midnight_curves::{Bls12, BlsScalar as Scalar};
use midnight_proofs::{
    plonk::{ConstraintSystem, create_proof, keygen_pk, keygen_vk_with_k, prepare},
    poly::{
        EvaluationDomain,
        kzg::{
            KZGCommitmentScheme,
            params::{ParamsKZG, ParamsVerifierKZG},
        },
    },
    transcript::{CircuitTranscript, Transcript},
};

use plutus_halo2_verifier_gen::plutus_gen::{
    CardanoFriendlyBlake2b, generate_aiken_verifier, generate_plinth_verifier,
};
use plutus_halo2_verifier_gen::{
    circuits::ivc_circuit::{IvcCircuit, configure_ivc_circuit, from_ivc, new_ivc},
    kzg_params::get_or_create_kzg_params,
};

type S = BlstrsEmulation;
type F = <S as SelfEmulation>::F;
type C = <S as SelfEmulation>::C;
type E = <S as SelfEmulation>::Engine;

pub type KZG = KZGCommitmentScheme<Bls12>;
pub type Params = ParamsKZG<Bls12>;
pub type ParamsVK = ParamsVerifierKZG<Bls12>;
pub type InnerTranscript = PoseidonState<F>;
pub type CTranscript = CardanoFriendlyBlake2b;

#[path = "shared_utils/mod.rs"]
mod shared_utils;

const MAX_RECURSION_DEPTH: usize = 2;

macro_rules! prove_ivc {
    ($i:expr, $TranscriptType:ty, $circuit:expr, $srs:expr, $pk:expr, $public_inputs:expr, $rng:expr) => {{
        // Initialize the transcript
        let mut transcript = CircuitTranscript::<$TranscriptType>::init();
        // Call create_proof
        let res = create_proof::<
            F,
            KZGCommitmentScheme<E>,
            CircuitTranscript<$TranscriptType>,
            IvcCircuit,
        >(
            $srs,
            $pk,
            &[$circuit.clone()],
            1,
            &[&[&[], $public_inputs]],
            &mut $rng,
            &mut transcript,
        );

        // Handle error
        res.unwrap_or_else(|e| panic!("Problem creating the {}-th IVC proof ({:?})", $i, e));

        // Finalize transcript and return proof bytes
        transcript.finalize()
    }};
}

macro_rules! verify_prepare {
    ($i:expr, $TranscriptType:ty, $proof:expr, $vk:expr, $public_inputs:expr) => {{
        // Start a transcript from proof bytes
        let mut transcript = CircuitTranscript::<$TranscriptType>::init_from_bytes($proof);
        // Run prepare
        let dual_msm = prepare::<F, KZGCommitmentScheme<E>, CircuitTranscript<$TranscriptType>>(
            $vk,
            &[&[C::identity()]],
            &[&[$public_inputs]],
            &mut transcript,
        )
        .expect("Verification failed");
        transcript
            .assert_empty()
            .expect("Transcript should be empty");
        dual_msm
    }};
}

fn main() -> Result<()> {
    env_logger::init();
    info!("Starting IVC example");

    let seed = [0u8; 32]; // UNSAFE, constant seed is used for testing purposes
    let rng: StdRng = SeedableRng::from_seed(seed);

    let k: u32 = 19;
    let mut self_cs = ConstraintSystem::default();
    configure_ivc_circuit(&mut self_cs);
    let self_domain = EvaluationDomain::new(self_cs.degree() as u32, k);

    let default_ivc_circuit = new_ivc(self_domain.clone(), self_cs.clone());

    let kzg_params: Params = get_or_create_kzg_params(k, rng.clone())?;
    let vk = keygen_vk_with_k(&kzg_params, &default_ivc_circuit, k).unwrap();
    let pk = keygen_pk(vk.clone(), &default_ivc_circuit).unwrap();

    let mut fixed_bases = BTreeMap::new();
    fixed_bases.insert(String::from("com_instance"), C::identity());
    fixed_bases.extend(midnight_circuits::verifier::fixed_bases::<S>(
        "self_vk", &vk,
    ));
    let fixed_base_names = fixed_bases.keys().cloned().collect::<Vec<_>>();

    // This trivial accumulator must have a single base and scalar of F::ONE, and
    // the base has to be the default point of C. This is because when parsing
    // an empty proof, our transcript gadget places a default point on every
    // `read_point`. Note that the `base` is left untouched on during the
    // handling of genesis, because `scale_by_bit` only modifies the scalars.
    //
    // On the other hand, the scalar has to be F::ONE because it is the value
    // obtained after a `collapse` (the last step before constraining the acc as
    // a public input).
    let trivial_acc = Accumulator::<S>::new(
        Msm::new(&[C::default()], &[F::ONE], &BTreeMap::new()),
        Msm::new(
            &[C::default()],
            &[F::ONE],
            &fixed_base_names
                .iter()
                .map(|name| (name.clone(), F::ZERO))
                .collect(),
        ),
    );

    // Set the previous values for state (to genesis), proof and acc.
    let mut prev_state = F::ZERO;
    let mut prev_proof = vec![];
    let mut prev_acc = trivial_acc.clone();
    let mut proof_acc: Accumulator<S>;

    // Set the state (and acc) that we will prove (they are PI to the proof).
    let mut state = prev_state + F::ONE;
    let mut acc = trivial_acc;

    let mut instance: Vec<Scalar> = AssignedVk::<S>::as_public_input(&vk);
    instance.extend(AssignedNative::<F>::as_public_input(&state));
    instance.extend(AssignedAccumulator::as_public_input(&acc));

    info!("Nb public inputs: {:?}", instance.len());

    // Run the IVC loop.
    for i in 1..=MAX_RECURSION_DEPTH {
        let circuit = from_ivc(
            self_domain.clone(),
            self_cs.clone(),
            vk.clone(),
            prev_state,
            prev_proof.clone(),
            prev_acc.clone(),
        );

        if i > 1 {
            instance = AssignedVk::<S>::as_public_input(&vk);
            instance.extend(AssignedNative::<F>::as_public_input(&state));
            instance.extend(AssignedAccumulator::as_public_input(&acc));
        }

        // Computing the i-th step proof
        let proof = {
            if i < MAX_RECURSION_DEPTH {
                // For the inner IVC steps, we use Poseidon hash as the transcript.
                prove_ivc!(
                    i,
                    InnerTranscript,
                    circuit,
                    &kzg_params,
                    &pk,
                    &instance,
                    rng.clone()
                )
            } else {
                // For the last IVC step, we use Cardano's Blake2b hash as the transcript.
                prove_ivc!(
                    i,
                    CTranscript,
                    circuit,
                    &kzg_params,
                    &pk,
                    &instance,
                    rng.clone()
                )
            }
        };

        if i == 1 {
            info!("proof size {:?}", proof.len());
        }

        // Extracting from the proof the i-th step accumulator, collapsed to a single point
        proof_acc = {
            let dual_msm = if i != MAX_RECURSION_DEPTH {
                // For the inner IVC steps, we use Poseidon hash as the transcript.
                verify_prepare!(i, InnerTranscript, &proof, &vk, &instance)
            } else {
                // For the last IVC step, we use Cardano's Blake2b hash as the transcript.
                verify_prepare!(i, CTranscript, &proof, &vk, &instance)
            };

            assert!(dual_msm.clone().check(&kzg_params.verifier_params()));

            let mut proof_acc: Accumulator<S> = dual_msm.into();
            proof_acc.extract_fixed_bases(&fixed_bases);
            proof_acc.collapse();
            proof_acc
        };

        // Aggregating new accumulator with previous one, and checking both verify successfully.
        let mut accumulated = Accumulator::accumulate(&[proof_acc, acc.clone()]);
        accumulated.collapse();

        assert!(
            accumulated.check(&kzg_params.s_g2().into(), &fixed_bases),
            "IVC acc verification failed"
        );

        // Setting next iteration's witness.
        prev_state = state;
        prev_proof = proof;
        prev_acc = acc;

        // Set the next iteration's public input.
        state += F::ONE;
        acc = accumulated;
    }

    let mut invalid_proof = prev_proof.clone();
    // index points to bytes of first scalar that is part of the proof
    // this should be safe and not result in malformed encoding exception
    // which is likely for flipping Byte for compressed G1 element
    // atms has 42 G1 elements at the beginning of the proof each 48 bytes long
    let index = 48 * 42 + 2;
    let firs_byte = invalid_proof[index];
    let negated_firs_byte = !firs_byte;
    invalid_proof[index] = negated_firs_byte;

    shared_utils::export_plinth(&instance, Some(C::identity()), &prev_proof)?;
    generate_plinth_verifier(
        &kzg_params,
        &vk,
        Some(Vec::new()), // We perform recursion, without inner vks
        &instance,
        Some(C::identity()),
    )
    .context("Plinth verifier generation failed")?;

    shared_utils::export_aiken(&instance, Some(C::identity()), &prev_proof)?;
    generate_aiken_verifier(
        &kzg_params,
        &vk,
        Some(Vec::new()), // We perform recursion, without inner vks
        &instance,
        Some(C::identity()),
        Some((prev_proof.clone(), invalid_proof)),
    )
    .context("Aiken verifier generation failed")?;

    Ok(())
}
