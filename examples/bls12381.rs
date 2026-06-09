use anyhow::{Context as _, Result, anyhow};
use ff::Field;
use group::Group;
use log::info;
use rand::prelude::StdRng;
use rand_core::SeedableRng;

use midnight_circuits::{
    field::foreign::params::MultiEmulationParams,
    instructions::{
        ArithInstructions, AssignmentInstructions, EccInstructions, PublicInputInstructions,
    },
    types::{AssignedForeignPoint, Instantiable},
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
    plutus_gen::{CardanoFriendlyBlake2b, CircuitConfig, SupportedChips, cost_evaluation},
};

type F = midnight_curves::Fq;
type KZG = KZGCommitmentScheme<Bls12>;
type Params = ParamsKZG<Bls12>;
type CTranscript = CircuitTranscript<CardanoFriendlyBlake2b>;

/// Toy circuit: prove knowledge of two BLS12-381 scalars (a, b) such that P = (a·b)·G.
/// Instance: point P on BLS12-381 G1
/// Witness:  (a, b) — scalar product a·b is computed in-circuit before the MSM
#[derive(Clone, Default)]
struct Bls12381ScalarMul;

impl Relation for Bls12381ScalarMul {
    type Instance = G1Projective;
    type Witness = [F; 2];

    fn format_instance(instance: &Self::Instance) -> Result<Vec<F>, Error> {
        Ok(
            AssignedForeignPoint::<F, G1Projective, MultiEmulationParams>::as_public_input(
                instance,
            ),
        )
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        _instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), Error> {
        let [a_val, b_val] = witness.transpose_array();
        let a = std_lib.assign(layouter, a_val)?;
        let b = std_lib.assign(layouter, b_val)?;
        let scalar = std_lib.mul(layouter, &a, &b, None)?;

        let generator = std_lib
            .bls12_381_curve()
            .assign_fixed(layouter, G1Projective::generator())?;
        let result = std_lib
            .bls12_381_curve()
            .msm(layouter, &[scalar], &[generator])?;
        std_lib
            .bls12_381_curve()
            .constrain_as_public_input(layouter, &result)
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            bls12_381: true,
            ..ZkStdLibArch::default()
        }
    }

    fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
        Ok(Bls12381ScalarMul)
    }
}

fn main() -> Result<()> {
    env_logger::init();

    let seed = [0u8; 32];
    let mut rng: StdRng = SeedableRng::from_seed(seed);

    let a = F::random(&mut rng);
    let b = F::random(&mut rng);
    let instance: G1Projective = G1Projective::generator() * (a * b);

    let relation = Bls12381ScalarMul;
    let circuit = MidnightCircuit::new(
        &relation,
        Value::known(instance),
        Value::known([a, b]),
        None,
    );
    let k = k_from_circuit(&circuit);
    let params: Params = get_or_create_kzg_params(k, rng.clone())?;
    let vk: VerifyingKey<Scalar, KZG> = keygen_vk(&params, &circuit).context("keygen_vk failed")?;
    let pk: ProvingKey<Scalar, KZG> =
        keygen_pk(vk.clone(), &circuit).context("keygen_pk failed")?;

    let mut transcript = CTranscript::init();
    let formatted_instance = Bls12381ScalarMul::format_instance(&instance).unwrap();
    create_proof(
        &params,
        &pk,
        &[circuit],
        1,
        &[&[&[], &formatted_instance]],
        &mut rng,
        &mut transcript,
    )
    .context("proof generation failed")?;
    let proof = transcript.finalize();
    info!("proof size: {}", proof.len());

    let mut transcript_verifier = CTranscript::init_from_bytes(&proof);
    let verifier = prepare::<_, KZG, CTranscript>(
        &vk,
        &[&[G1Projective::identity()]],
        &[&[&formatted_instance]],
        &mut transcript_verifier,
    )
    .context("prepare failed")?;
    verifier
        .verify(&params.verifier_params())
        .map_err(|e| anyhow!("{e:?}"))
        .context("verify failed")?;

    let chips = &[SupportedChips::WeierstrassBls12381];
    cost_evaluation(
        &params,
        &vk,
        None,
        &formatted_instance,
        Some(G1Projective::identity()),
        chips,
        CircuitConfig::default(),
    )?;

    Ok(())
}
