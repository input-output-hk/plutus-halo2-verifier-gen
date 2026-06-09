use anyhow::{Context as _, Result, anyhow};
use group::{Group, ff::PrimeField};
use log::info;
use rand::prelude::StdRng;
use rand_core::SeedableRng;

use midnight_circuits::{
    instructions::{AssignmentInstructions, EccInstructions, PublicInputInstructions},
    types::{AssignedNativePoint, Instantiable},
};
use midnight_curves::{
    Bls12, BlsScalar as Scalar, Fr as JubjubScalar, G1Projective, JubjubExtended as Jubjub,
    JubjubSubgroup,
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

/// Toy circuit: prove knowledge of a Jubjub discrete logarithm.
/// Instance: point P = s·G on the Jubjub subgroup
/// Witness:  scalar s
#[derive(Clone, Default)]
struct JubjubScalarMul;

impl Relation for JubjubScalarMul {
    type Instance = JubjubSubgroup;
    type Witness = JubjubScalar;

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
        let scalar: midnight_circuits::types::AssignedScalarOfNativeCurve<Jubjub> =
            std_lib.jubjub().assign(layouter, witness)?;
        let generator = std_lib
            .jubjub()
            .assign_fixed(layouter, <JubjubSubgroup as Group>::generator())?;

        // scalar multiplication: result = s * G (exposed as public input)
        let result = std_lib
            .jubjub()
            .msm(layouter, &[scalar.clone()], &[generator])?;

        // point doubling: 2 * result
        let doubled = std_lib.jubjub().double(layouter, &result)?;

        // point addition: result + doubled = 3 * result
        let added = std_lib.jubjub().add(layouter, &result, &doubled)?;

        // point negation: -result
        let negated = std_lib.jubjub().negate(layouter, &added)?;

        // multiplication by a constant scalar (no witness needed for the scalar)
        let const_mul =
            std_lib
                .jubjub()
                .mul_by_constant(layouter, JubjubScalar::from(3u64), &negated)?;

        let extra = std_lib.jubjub().mul(layouter, &scalar, &const_mul)?;

        let end =
            std_lib
                .jubjub()
                .mul_by_constant(layouter, JubjubScalar::from_u128(198), &extra)?;

        let x = std_lib.jubjub().x_coordinate(&end);
        let y = std_lib.jubjub().y_coordinate(&end);

        let p = std_lib.jubjub().point_from_coordinates(layouter, &x, &y)?;

        // hash to curve: map a native field element to a Jubjub point
        // let one = std_lib.assign_fixed(layouter, <Jubjub as CircuitCurve>::Base::ONE)?;
        // let _h2c = std_lib.hash_to_curve(layouter, &[one])?;

        std_lib.jubjub().constrain_as_public_input(layouter, &p)
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            jubjub: true,
            // poseidon: true, // required for hash_to_curve
            ..ZkStdLibArch::default()
        }
    }

    fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
        Ok(JubjubScalarMul)
    }
}

fn main() -> Result<()> {
    env_logger::init();

    let seed = [0u8; 32];
    let mut rng: StdRng = SeedableRng::from_seed(seed);

    let witness = JubjubScalar::from(7u64);

    // Mirror the circuit's chain: result=s·G, doubled=2s·G, added=3s·G,
    // negated=-3s·G, const_mul=-9s·G, extra=-9s²·G, end=-1782s²·G
    let g = <JubjubSubgroup as Group>::generator();
    let result = g * witness;
    let added = result + result + result; // 3s·G
    let negated = -added;
    let const_mul = negated * JubjubScalar::from(3u64);
    let extra = const_mul * witness;
    let instance: JubjubSubgroup = extra * JubjubScalar::from_u128(198);

    let relation = JubjubScalarMul;
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
    let formatted_instance = JubjubScalarMul::format_instance(&instance).unwrap();
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

    let chips = &[
        SupportedChips::EdwardsJubjub,
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

    let mut invalid_proof = proof.clone();
    // index points to bytes of first scalar that is part of the proof
    // this should be safe and not result in malformed encoding exception
    // which is likely for flipping Byte for compressed G1 element
    // simple mul has 24 G1 elements at the beginning of the proof each 48 bytes long
    let index = 48 * 24 + 2;
    let firs_byte = invalid_proof[index];
    let negated_firs_byte = !firs_byte;
    invalid_proof[index] = negated_firs_byte;

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
