use anyhow::{Context as _, Result, anyhow};
use group::Group;
use log::info;
use rand::prelude::StdRng;
use rand_core::SeedableRng;

use midnight_circuits::{
    ecc::{hash_to_curve::HashToCurveGadget, native::EccChip},
    hash::poseidon::PoseidonChip,
    instructions::{
        AssignmentInstructions, PublicInputInstructions, hash_to_curve::HashToCurveCPU,
    },
    types::{AssignedNative, AssignedNativePoint, Instantiable},
};
use midnight_curves::{
    Bls12, BlsScalar as Scalar, G1Projective, JubjubExtended as Jubjub, JubjubSubgroup,
};
use midnight_proofs::{
    circuit::{Layouter, Value},
    plonk::{
        Error, ProvingKey, VerifyingKey, create_proof, k_from_circuit, keygen_pk, keygen_vk,
        prepare,
    },
    poly::commitment::Guard,
    poly::kzg::{KZGCommitmentScheme, params::ParamsKZG},
    transcript::{CircuitTranscript, Transcript},
};
use midnight_zk_stdlib::{MidnightCircuit, Relation, ZkStdLib, ZkStdLibArch};
use plutus_halo2_verifier_gen::{
    kzg_params::get_or_create_kzg_params,
    plutus_gen::{
        CardanoFriendlyBlake2b, CircuitConfig, SupportedChips, cost_evaluation,
        generate_aiken_verifier, generate_plinth_verifier,
    },
};

type F = midnight_curves::Fq;
type KZG = KZGCommitmentScheme<Bls12>;
type Params = ParamsKZG<Bls12>;
type CTranscript = CircuitTranscript<CardanoFriendlyBlake2b>;

#[path = "shared_utils/mod.rs"]
mod shared_utils;

/// Off-circuit alias for the concrete `HashToCurveGadget` type used inside `ZkStdLib`.
/// `HtcGadget::hash_to_curve(&[field_elem])` mirrors the in-circuit `std_lib.hash_to_curve`.
type HtcGadget = HashToCurveGadget<F, Jubjub, AssignedNative<F>, PoseidonChip<F>, EccChip<Jubjub>>;

/// Circuit: prove knowledge of a preimage whose hash-to-curve yields a known point.
/// Instance: P = htc(input)
/// Witness:  input (a base-field element)
///
/// The hash uses Poseidon as a sponge (two squeezes) feeding the SVDW map-to-curve
/// and summing the two mapped points with cofactor clearing — exactly what
/// `std_lib.hash_to_curve` does in-circuit.
#[derive(Clone, Default)]
struct JubjubH2C;

impl Relation for JubjubH2C {
    type Instance = JubjubSubgroup;
    type Witness = F;
    type Error = Error;

    fn format_instance(instance: &Self::Instance) -> Result<Vec<F>, Error> {
        Ok(AssignedNativePoint::<Jubjub>::as_public_input(instance))
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        _instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), Error> {
        // Assign the preimage as a native field element.
        let input: AssignedNative<F> = std_lib.assign(layouter, witness)?;

        // Hash to curve: Poseidon sponge → two squeezes → SVDW map → point addition.
        // Cofactor clearing is applied by the map_to_curve step, so the result is
        // guaranteed to be in the prime-order Jubjub subgroup.
        let h2c = std_lib.hash_to_curve(layouter, &[input])?;

        std_lib.jubjub().constrain_as_public_input(layouter, &h2c)
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            jubjub: true,
            poseidon: true,
            ..ZkStdLibArch::default()
        }
    }

    fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
        Ok(JubjubH2C)
    }
}

fn main() -> Result<()> {
    env_logger::init();

    let seed = [0u8; 32];
    let mut rng: StdRng = SeedableRng::from_seed(seed);

    let witness: F = F::from(42u64);

    // Compute the expected point off-circuit using the same gadget internals.
    // `HtcGadget::hash_to_curve` is the CPU implementation of `HashToCurveCPU`
    // and runs the exact same Poseidon + SVDW + cofactor-clearing logic.
    let instance: JubjubSubgroup = HtcGadget::hash_to_curve(&[witness]);

    let relation = JubjubH2C;
    let circuit = MidnightCircuit::new(
        &relation,
        Value::known(instance),
        Value::known(witness),
        None,
    );
    let k = k_from_circuit(&circuit);
    let params: Params = get_or_create_kzg_params(k, rng.clone())?;
    let vk: VerifyingKey<Scalar, KZG> = keygen_vk(&params, &circuit).context("keygen_vk failed")?;
    let pk: ProvingKey<Scalar, KZG> =
        keygen_pk(vk.clone(), &circuit).context("keygen_pk failed")?;

    let mut transcript = CTranscript::init();
    let formatted_instance = JubjubH2C::format_instance(&instance).unwrap();
    create_proof(
        &params,
        &pk,
        &[circuit],
        1,
        &[&[&[], &formatted_instance]],
        &mut transcript,
        &mut rng,
    )
    .context("proof generation failed")?;
    let proof = transcript.finalize();
    info!("proof size: {}", proof.len());

    let mut transcript_verifier = CTranscript::init_from_bytes(&proof);
    let verifier = prepare::<_, KZG, CTranscript>(
        &vk,
        &[&[G1Projective::identity()]],
        &[&[&&formatted_instance]],
        &mut transcript_verifier,
    )
    .context("prepare failed")?;
    verifier
        .verify(&params.verifier_params())
        .map_err(|e| anyhow!("{e:?}"))
        .context("verify failed")?;

    let mut invalid_proof = proof.clone();
    // index points to bytes of first scalar that is part of the proof
    // this should be safe and not result in malformed encoding exception
    // which is likely for flipping Byte for compressed G1 element
    // simple mul has 24 G1 elements at the beginning of the proof each 48 bytes long
    let index = 48 * 24 + 2;
    let firs_byte = invalid_proof[index];
    let negated_firs_byte = !firs_byte;
    invalid_proof[index] = negated_firs_byte;

    let chips = &[
        SupportedChips::HashToCurve,
        // lookup_chip("pow2range", 1, 0, 0),
    ];
    cost_evaluation(
        &params,
        &vk,
        None,
        &formatted_instance,
        Some(G1Projective::identity()),
        chips,
        CircuitConfig {
            ..Default::default()
        },
    )?;

    shared_utils::export_plinth(&formatted_instance, Some(G1Projective::identity()), &proof)?;
    generate_plinth_verifier(
        &params,
        &vk,
        None,
        &formatted_instance,
        Some(G1Projective::identity()),
    )
    .context("Plinth verifier generation failed")?;

    shared_utils::export_aiken(&formatted_instance, Some(G1Projective::identity()), &proof)?;
    generate_aiken_verifier(
        &params,
        &vk,
        None,
        &formatted_instance,
        Some(G1Projective::identity()),
        Some((proof.clone(), invalid_proof)),
    )
    .context("Aiken verifier generation failed")?;

    Ok(())
}
