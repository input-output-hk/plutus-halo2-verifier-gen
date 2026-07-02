use anyhow::{Context as _, Result, anyhow};
use group::Group;
use log::info;
use rand::{prelude::SliceRandom, prelude::StdRng};
use rand_core::SeedableRng;

use ff::Field;
use group::Curve;
use midnight_circuits::{
    field::foreign::{AssignedField, params::MultiEmulationParams as MEP},
    instructions::{
        ArithInstructions, AssignmentInstructions, DecompositionInstructions, EccInstructions,
        PublicInputInstructions, ZeroInstructions,
    },
    testing_utils::ecdsa::{ECDSASig, Ecdsa},
    types::{AssignedForeignPoint, InnerValue, Instantiable},
};
use midnight_curves::{
    Bls12, BlsScalar as Scalar, G1Projective,
    secp256k1::{Fq as Secp256k1Scalar, Secp256k1},
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

const N: usize = 5; // The total number of public keys.
const T: usize = 4; // The threshold of valid signatures.

type PK = Secp256k1;
type MsgHash = Secp256k1Scalar;

/// Toy circuit: prove knowledge of a secp256k1 discrete logarithm.
/// Instance: point P = s·G on secp256k1
/// Witness:  scalar s (foreign field element secp256k1::Fq)
#[derive(Clone, Default)]
struct BitcoinThresholdECDSA;

impl Relation for BitcoinThresholdECDSA {
    type Instance = (MsgHash, [PK; N]);

    type Witness = [(PK, ECDSASig); T];

    fn format_instance((msg_hash, pks): &Self::Instance) -> Result<Vec<F>, Error> {
        Ok([
            AssignedField::<F, Secp256k1Scalar, MEP>::as_public_input(msg_hash),
            pks.iter()
                .flat_map(AssignedForeignPoint::<F, Secp256k1, MEP>::as_public_input)
                .collect::<Vec<_>>(),
        ]
        .into_iter()
        .flatten()
        .collect())
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), Error> {
        let secp256k1_curve = std_lib.secp256k1_curve();
        let secp256k1_scalar = std_lib.secp256k1_scalar();
        let secp256k1_base = secp256k1_curve.base_field_chip();

        // Assign the message hash as a public input.
        let msg_hash = secp256k1_scalar.assign_as_public_input(layouter, instance.unzip().0)?;

        // Assign the PKs and constrain them as public inputs.
        let pks = secp256k1_curve.assign_many(layouter, &instance.unzip().1.transpose_array())?;
        pks.iter()
            .try_for_each(|pk| secp256k1_curve.constrain_as_public_input(layouter, pk))?;

        // Assigned the public keys with known signature asserting they are on the set
        // of public keys.
        let signatures = witness.transpose_array();
        let selected_pks_values = signatures.map(|v| v.map(|(pk, _)| pk));
        let selected_sigs_values = signatures.map(|v| v.map(|(_, s)| s));

        let assigned_selected_pks =
            secp256k1_curve.k_out_of_n_points(layouter, &pks, &selected_pks_values)?;

        // For every i, we need to verify that:
        //   s_i * K_i  =?=  msg_hash * G + r_i * PK_i
        //
        // where K_i is a witnessed point different from the identity and whose
        // x-coordinate equals r_i.
        // We will batch the above equation with some randomness α derived from the
        // signatures with Poseidon. The equation becomes:
        //
        //  \sum_i (α^i * r_i * PK_i - α^i * s_i * K_i) + (sum_i α^i) * msg_hash * G
        //   =?=
        //   id

        // TODO: For now, and because this is a PoC, let alpha be fixed, which should be
        // derived with Poseidon instead.
        let alpha: AssignedField<F, Secp256k1Scalar, _> =
            secp256k1_scalar.assign_fixed(layouter, Secp256k1Scalar::from(42))?;

        let mut alpha_powers: [_; T] = core::array::from_fn(|_| alpha.clone());
        for i in 1..T {
            alpha_powers[i] = secp256k1_scalar.mul(layouter, &alpha_powers[i - 1], &alpha, None)?;
        }

        let neg_s_i_times_alpha_i = selected_sigs_values
            .iter()
            .zip(alpha_powers.iter())
            .map(|(sig_i, alpha_i)| {
                let neg_s_i = secp256k1_scalar.assign(layouter, sig_i.map(|sig| -sig.get_s()))?;
                secp256k1_scalar.mul(layouter, &neg_s_i, alpha_i, None)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let r_i_as_le_bytes = selected_sigs_values
            .iter()
            .map(|sig_i| std_lib.assign_many(layouter, &sig_i.map(|v| v.get_r()).transpose_array()))
            .collect::<Result<Vec<_>, Error>>()?;

        let r_i_as_scalar = r_i_as_le_bytes
            .iter()
            .map(|bytes| secp256k1_scalar.assigned_from_le_bytes(layouter, bytes))
            .collect::<Result<Vec<_>, Error>>()?;

        let r_i_as_base = r_i_as_le_bytes
            .iter()
            .map(|bytes| secp256k1_base.assigned_from_le_bytes(layouter, bytes))
            .collect::<Result<Vec<_>, Error>>()?;

        let r_i_times_alpha_i = r_i_as_scalar
            .iter()
            .zip(alpha_powers.iter())
            .map(|(r_i, alpha_i)| secp256k1_scalar.mul(layouter, r_i, alpha_i, None))
            .collect::<Result<Vec<_>, Error>>()?;

        let k_points = signatures
            .iter()
            .zip(r_i_as_base.iter())
            .map(|(val, r_i)| {
                let k_point_y_val = val.zip(instance.unzip().0).zip(r_i.value()).map(
                    |(((pk_i, sig_i), msg_hash), r_i)| {
                        let gene = Secp256k1::generator();
                        let r_as_scalar = Secp256k1Scalar::from_bytes(&sig_i.get_r()).unwrap();
                        let s_inv = sig_i.get_s().invert().unwrap();
                        let k_point = gene * (s_inv * msg_hash) + pk_i * (s_inv * r_as_scalar);

                        // cpu sanity check
                        assert_eq!(r_i, k_point.to_affine().x);
                        k_point.to_affine().y
                    },
                );

                let y_i = secp256k1_base.assign(layouter, k_point_y_val)?;
                secp256k1_curve.point_from_coordinates(layouter, r_i, &y_i)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let sum_alphas = {
            let terms = alpha_powers
                .iter()
                .map(|alpha_i| (Secp256k1Scalar::ONE, alpha_i.clone()))
                .collect::<Vec<_>>();
            secp256k1_scalar.linear_combination(layouter, &terms, Secp256k1Scalar::ZERO)
        }?;
        let sum_alphas_times_msg_hash =
            secp256k1_scalar.mul(layouter, &sum_alphas, &msg_hash, None)?;

        let gene = secp256k1_curve.assign_fixed(layouter, Secp256k1::generator())?;
        let mut bases = vec![gene];
        bases.extend(assigned_selected_pks);
        bases.extend(k_points);

        let mut scalars = vec![sum_alphas_times_msg_hash];
        scalars.extend(r_i_times_alpha_i);
        scalars.extend(neg_s_i_times_alpha_i);

        let res = secp256k1_curve.msm(layouter, &scalars, &bases)?;

        secp256k1_curve.assert_zero(layouter, &res)
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            secp256k1: true,
            ..ZkStdLibArch::default()
        }
    }

    fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
        Ok(BitcoinThresholdECDSA)
    }
}

fn main() -> Result<()> {
    env_logger::init();

    let seed = [0u8; 32];
    let mut rng: StdRng = SeedableRng::from_seed(seed);

    // Generate a random instance-witness pair.
    let msg_hash = Secp256k1Scalar::random(&mut rng);

    let keys: [_; N] = core::array::from_fn(|_| Ecdsa::keygen(&mut rng));
    let pks = keys.map(|(pk, _)| pk);

    let mut indices: Vec<usize> = (0..N).collect();
    indices.shuffle(&mut rng);

    let mut idxs_of_known_sigs = indices[..T].to_vec();
    idxs_of_known_sigs.sort();

    let signatures: [(PK, ECDSASig); T] = idxs_of_known_sigs
        .into_iter()
        .map(|i| (keys[i].0, Ecdsa::sign(&keys[i].1, &msg_hash, &mut rng)))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    // Sanity check on the generated signatures.
    signatures.iter().for_each(|(pk, sig)| {
        assert!(Ecdsa::verify(pk, &msg_hash, sig));
    });

    let instance = (msg_hash, pks);
    let witness = signatures;

    let relation = BitcoinThresholdECDSA;
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
    let formatted_instance = BitcoinThresholdECDSA::format_instance(&instance).unwrap();
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

    let chips = &[SupportedChips::WeierstrassSecp256k1];
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
