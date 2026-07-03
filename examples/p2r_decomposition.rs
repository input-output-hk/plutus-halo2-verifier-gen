use anyhow::{Context as _, Result, anyhow};
use group::Group;
use log::info;
use rand::prelude::StdRng;
use rand_core::SeedableRng;

use midnight_circuits::instructions::{
    AssignmentInstructions, DecompositionInstructions, PublicInputInstructions,
};
use midnight_curves::{Bls12, BlsScalar as Scalar, G1Projective};
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
        CardanoFriendlyBlake2b, CircuitConfig, cost_evaluation, generate_aiken_verifier,
        generate_plinth_verifier,
    },
};

type F = midnight_curves::Fq;
type KZG = KZGCommitmentScheme<Bls12>;
type Params = ParamsKZG<Bls12>;
type CTranscript = CircuitTranscript<CardanoFriendlyBlake2b>;

#[path = "shared_utils/mod.rs"]
mod shared_utils;

/// Toy circuit: range-check a byte value via power-of-2 decomposition.
/// Instance: the byte value as a field element
/// Witness:  a u8 value
#[derive(Clone, Default)]
struct RangeCheck;

const NR_POW2RANGE_COLS: u8 = 4;

impl Relation for RangeCheck {
    type Instance = u8;
    type Witness = u8;
    type Error = Error;

    fn format_instance(instance: &Self::Instance) -> Result<Vec<F>, Error> {
        Ok(vec![F::from(*instance as u64)])
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        _instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), Error> {
        let x = std_lib.assign(layouter, witness.map(|w| F::from(w as u64)))?;
        let _bits = std_lib.assigned_to_le_bits(layouter, &x, Some(8), true)?;
        std_lib.constrain_as_public_input(layouter, &x)
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            nr_pow2range_cols: NR_POW2RANGE_COLS,
            ..ZkStdLibArch::default()
        }
    }

    fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
        Ok(RangeCheck)
    }
}

fn main() -> Result<()> {
    env_logger::init();

    let seed = [0u8; 32];
    let mut rng: StdRng = SeedableRng::from_seed(seed);

    let witness: u8 = 42;
    let instance: u8 = witness;

    let relation = RangeCheck;
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
    let formatted_instance = RangeCheck::format_instance(&instance).unwrap();
    create_proof(
        &params,
        &pk,
        &[circuit],
        0,
        &[&[&[], &formatted_instance]],
        &mut transcript,
        &mut rng,
    )
    .context("proof generation failed")?;
    let proof = transcript.finalize();
    info!("proof size: {}", proof.len());

    let mut invalid_proof = proof.clone();
    // index points to bytes of first scalar that is part of the proof
    // this should be safe and not result in malformed encoding exception
    // which is likely for flipping Byte for compressed G1 element
    // simple mul has 8 G1 elements at the beginning of the proof each 48 bytes long
    let index = 48 * 8 + 2;
    let firs_byte = invalid_proof[index];
    let negated_firs_byte = !firs_byte;
    invalid_proof[index] = negated_firs_byte;

    let mut transcript_verifier = CTranscript::init_from_bytes(&proof);
    let verifier = prepare::<_, KZG, CTranscript>(
        &vk,
        &[&[]],
        &[&[&[], &formatted_instance]],
        &mut transcript_verifier,
    )
    .context("prepare failed")?;
    verifier
        .verify(&params.verifier_params())
        .map_err(|e| anyhow!("{e:?}"))
        .context("verify failed")?;

    let chips = &[];
    cost_evaluation(
        &params,
        &vk,
        None,
        &formatted_instance,
        Some(G1Projective::identity()),
        chips,
        CircuitConfig {
            nb_fixed: 1,
            nr_pow2range_cols: Some(NR_POW2RANGE_COLS as usize),
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
