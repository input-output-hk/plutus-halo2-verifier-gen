use anyhow::{Context as _, Result};
use log::info;
use rand::prelude::StdRng;
use rand_core::SeedableRng;
use std::fs::File;
use std::{collections::BTreeMap, time::Instant};

use ff::Field;
use group::Group;

use midnight_circuits::{
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
    CardanoFriendlyBlake2b, export_proof, export_public_inputs, generate_aiken_verifier,
    generate_plinth_verifier, serialize_proof,
};
use plutus_halo2_verifier_gen::{
    circuits::ivc_circuit::{IvcCircuit, configure_ivc_circuit, fromIVC, newIVC},
    kzg_params::get_or_create_kzg_params,
};

pub type KZG = KZGCommitmentScheme<Bls12>;
pub type Params = ParamsKZG<Bls12>;
pub type ParamsVK = ParamsVerifierKZG<Bls12>;
pub type CTranscript = CircuitTranscript<CardanoFriendlyBlake2b>;

type S = BlstrsEmulation;
type F = <S as SelfEmulation>::F;
type C = <S as SelfEmulation>::C;
type E = <S as SelfEmulation>::Engine;

fn main() -> Result<()> {
    env_logger::init();

    let seed = [0u8; 32]; // UNSAFE, constant seed is used for testing purposes
    let rng: StdRng = SeedableRng::from_seed(seed);

    let k: u32 = 19;
    let mut self_cs = ConstraintSystem::default();
    configure_ivc_circuit(&mut self_cs);
    let self_domain = EvaluationDomain::new(self_cs.degree() as u32, k);

    let default_ivc_circuit = newIVC(self_domain.clone(), self_cs.clone());

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

    let mut instances: Vec<Scalar> = AssignedVk::<S>::as_public_input(&vk);
    instances.extend(AssignedNative::<F>::as_public_input(&state));
    instances.extend(AssignedAccumulator::as_public_input(&acc));

    // Run the IVC loop.
    for i in 0..=1 {
        let circuit = fromIVC(
            self_domain.clone(),
            self_cs.clone(),
            vk.clone(),
            prev_state,
            prev_proof.clone(),
            prev_acc.clone(),
        );

        instances = AssignedVk::<S>::as_public_input(&vk);
        instances.extend(AssignedNative::<F>::as_public_input(&state));
        instances.extend(AssignedAccumulator::as_public_input(&acc));

        let start = Instant::now();
        let proof = {
            let mut transcript = CTranscript::init();
            create_proof::<F, KZGCommitmentScheme<E>, CTranscript, IvcCircuit>(
                &kzg_params,
                &pk,
                &[circuit.clone()],
                1,
                &[&[&[], &instances]],
                rng.clone(),
                &mut transcript,
            )
            .unwrap_or_else(|_| panic!("Problem creating the {i}-th IVC proof"));
            transcript.finalize()
        };
        println!("{i}-th IVC proof created in {:?}", start.elapsed());

        proof_acc = {
            let mut transcript = CTranscript::init_from_bytes(&proof);
            let dual_msm = prepare::<F, KZGCommitmentScheme<E>, CTranscript>(
                &vk,
                &[&[C::identity()]],
                &[&[&instances]],
                &mut transcript,
            )
            .expect("Verification failed");

            assert!(dual_msm.clone().check(&kzg_params.verifier_params()));

            let mut proof_acc: Accumulator<S> = dual_msm.into();
            proof_acc.extract_fixed_bases(&fixed_bases);
            proof_acc.collapse();
            proof_acc
        };

        // Prepare the witnesses of the next iteration.
        prev_state = state;
        prev_proof = proof;
        prev_acc = acc.clone();

        // If `acc` satisfies the invariant and `proof` is valid, we know that `state`
        // must be valid. We can asset the validity of both at the same time by
        // accumulating them first.
        let mut accumulated = Accumulator::accumulate(&[proof_acc, acc]);
        accumulated.collapse();

        assert!(
            accumulated.check(&kzg_params.s_g2().into(), &fixed_bases),
            "IVC acc verification failed"
        );

        println!("Asserted validity of state {:?}", state);

        // Set the new goals (public inputs) for the next iteration.
        state += F::ONE;
        acc = accumulated;
    }

    let mut invalid_proof = prev_proof.clone();
    // index points to bytes of first scalar that is part of the proof
    // this should be safe and not result in malformed encoding exception
    // which is likely for flipping Byte for compressed G1 element
    // atms has 16 G1 elements at the beginning of the proof each 48 bytes long
    // TODO
    let index = 48 * 16 + 2;
    let firs_byte = invalid_proof[index];
    let negated_firs_byte = !firs_byte;
    invalid_proof[index] = negated_firs_byte;

    info!("proof size {:?}", prev_proof.len());

    let instances_file =
        "./plinth-verifier/plutus-halo2/test/Generic/serialized_public_input.hex".to_string();
    let mut output = File::create(instances_file).context("failed to create instances file")?;
    export_public_inputs(&[&[&instances]], &mut output)
        .context("failed to export public inputs")?;

    serialize_proof(
        "./plinth-verifier/plutus-halo2/test/Generic/serialized_proof.json".to_string(),
        prev_proof.clone(),
    )
    .context("json proof serialization failed")?;

    export_proof(
        "./plinth-verifier/plutus-halo2/test/Generic/serialized_proof.hex".to_string(),
        prev_proof.clone(),
    )
    .context("hex proof serialization failed")?;

    generate_plinth_verifier(&kzg_params, &vk, None, &[&[&instances]])
        .context("Plinth verifier generation failed")?;

    generate_aiken_verifier(
        &kzg_params,
        &vk,
        None,
        &[&[&instances]],
        None,
        Some((prev_proof.clone(), invalid_proof)),
    )
    .context("Aiken verifier generation failed")?;
    export_proof(
        "./aiken-verifier/submitter/serialized_proof.hex".to_string(),
        prev_proof,
    )
    .context("hex proof serialization failed")?;

    let instances_file = "./aiken-verifier/submitter/serialized_public_input.hex".to_string();
    let mut output = File::create(instances_file).context("failed to create instances file")?;
    export_public_inputs(&[&[&instances]], &mut output)
        .context("Failed to export the public inputs")?;

    Ok(())
}
