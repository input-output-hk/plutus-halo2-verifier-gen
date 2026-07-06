use anyhow::{Context as _, Result, anyhow};
use log::info;
use rand::prelude::StdRng;
use rand_core::SeedableRng;

use ff::{Field, PrimeField};
use group::Group;
use midnight_circuits::{
    ecc::curves::CircuitCurve,
    field::foreign::{AssignedField, params::MultiEmulationParams as MEP},
    instructions::{
        AssignmentInstructions, DecompositionInstructions, EccInstructions,
        PublicInputInstructions, ZeroInstructions,
    },
    types::{AssignedForeignPoint, Instantiable},
};
use midnight_curves::{
    Bls12, BlsScalar as Scalar, G1Projective,
    p256::{Fp as P256Base, Fq as P256Scalar, P256},
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

type PK = P256;
type MsgHash = P256Scalar;

/// Big-endian canonical byte representation of a `p256` field/scalar element.
fn to_be_bytes<T: PrimeField>(v: &T) -> [u8; 32] {
    v.to_repr().as_ref().try_into().unwrap()
}

/// Inverse of [`to_be_bytes`]. Returns `None` if `be` is not a canonical
/// representative of `T` (e.g. a base-field x-coordinate that happens to
/// exceed the scalar-field modulus).
fn from_be_bytes<T: PrimeField>(be: [u8; 32]) -> Option<T> {
    let mut repr = T::Repr::default();
    repr.as_mut().copy_from_slice(&be);
    Option::from(T::from_repr(repr))
}

/// A minimal ECDSA-over-secp256r1 signature. `r` is stored LE-encoded, as the
/// x-coordinate of the nonce point `R = k*G` (an `P256Base` element)
/// reinterpreted as a `P256Scalar` — the usual ECDSA cross-field trick, valid
/// since secp256r1's base and scalar field moduli are close enough in size.
#[derive(Clone, Copy, Debug)]
struct P256Sig {
    r: [u8; 32],
    s: P256Scalar,
}

/// CPU-side ECDSA over secp256r1, mirroring
/// `midnight_circuits::testing_utils::ecdsa::Ecdsa`, which only supports
/// secp256k1 (k256). There is no P-256 equivalent upstream, so it is
/// reimplemented here for this example.
struct P256Ecdsa;

impl P256Ecdsa {
    fn keygen(rng: &mut StdRng) -> (PK, MsgHash) {
        let sk = P256Scalar::random(&mut *rng);
        let pk = P256::generator() * sk;
        (pk, sk)
    }

    fn sign(sk: &MsgHash, msg_hash: &MsgHash, rng: &mut StdRng) -> P256Sig {
        loop {
            let k = P256Scalar::random(&mut *rng);
            let k_point: P256 = P256::generator() * k;
            let (r_as_base, _) = k_point.coordinates().expect("k*G is never the identity");

            let r_be = to_be_bytes(&r_as_base);
            let r_as_scalar = match from_be_bytes::<P256Scalar>(r_be) {
                Some(v) => v,
                None => continue, // r_as_base happened to exceed the scalar modulus; retry.
            };

            let k_inv = k.invert().unwrap();
            let s = k_inv * (*msg_hash + r_as_scalar * sk);
            if bool::from(s.is_zero()) {
                continue;
            }

            // Big-endian canonical repr -> little-endian storage, matching
            // the convention used throughout this repo's foreign-field code.
            let mut r = r_be;
            r.reverse();
            return P256Sig { r, s };
        }
    }

    fn verify(pk: &PK, msg_hash: &MsgHash, sig: &P256Sig) -> bool {
        let mut r_be = sig.r;
        r_be.reverse();
        let r_as_scalar = from_be_bytes::<P256Scalar>(r_be).expect("valid scalar");
        let r_as_base = from_be_bytes::<P256Base>(r_be).expect("valid base elt");

        let s_inv = sig.s.invert().unwrap();
        let k_point = P256::generator() * (s_inv * msg_hash) + *pk * (s_inv * r_as_scalar);

        match k_point.coordinates() {
            Some((x, _)) => x == r_as_base,
            None => false,
        }
    }
}

/// Toy circuit: prove knowledge of a valid ECDSA signature over secp256r1
/// (NIST P-256) for a public message hash and public key.
/// Instance: message hash and public key `PK` on secp256r1.
/// Witness:  a signature `(r, s)` valid under `PK` for the message hash.
#[derive(Clone, Default)]
struct P256EcdsaVerify;

impl Relation for P256EcdsaVerify {
    type Instance = (MsgHash, PK);

    type Witness = P256Sig;

    type Error = Error;

    fn format_instance((msg_hash, pk): &Self::Instance) -> Result<Vec<F>, Error> {
        Ok([
            AssignedField::<F, P256Scalar, MEP>::as_public_input(msg_hash),
            AssignedForeignPoint::<F, P256, MEP>::as_public_input(pk),
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
        let p256_curve = std_lib.p256();
        let p256_scalar = std_lib.p256().scalar_field_chip();
        let p256_base = std_lib.p256().base_field_chip();

        // Assign the message hash as a public input.
        let msg_hash = p256_scalar.assign_as_public_input(layouter, instance.unzip().0)?;

        // Assign the PK and constrain it as a public input.
        let pk = p256_curve.assign(layouter, instance.unzip().1)?;
        p256_curve.constrain_as_public_input(layouter, &pk)?;

        // Assign the witnessed signature. `-s` is assigned directly (rather
        // than assigning `s` and negating in-circuit) since only `-s` is
        // needed by the verification equation below.
        let r_le_bytes =
            std_lib.assign_many(layouter, &witness.map(|sig| sig.r).transpose_array())?;
        let r_as_scalar = p256_scalar.assigned_from_le_bytes(layouter, &r_le_bytes)?;
        let r_as_base = p256_base.assigned_from_le_bytes(layouter, &r_le_bytes)?;
        let neg_s = p256_scalar.assign(layouter, witness.map(|sig| -sig.s))?;

        // Witness K = R, the nonce point, whose x-coordinate is `r`. Only its
        // y-coordinate needs assigning; `r_as_base` already carries the x.
        let k_point_y_val =
            witness
                .zip(instance.unzip().0)
                .zip(instance.unzip().1)
                .map(|((sig, msg_hash), pk)| {
                    let s_inv = sig.s.invert().unwrap();
                    let mut r_be = sig.r;
                    r_be.reverse();
                    let r_as_scalar = from_be_bytes::<P256Scalar>(r_be).expect("valid scalar");
                    let k_point =
                        P256::generator() * (s_inv * msg_hash) + pk * (s_inv * r_as_scalar);

                    // cpu sanity check
                    let (x, y) = k_point.coordinates().expect("K is never the identity");
                    let mut r_check = to_be_bytes(&x);
                    r_check.reverse();
                    assert_eq!(r_check, sig.r);
                    y
                });
        let y = p256_base.assign(layouter, k_point_y_val)?;
        let k_point = p256_curve.point_from_coordinates(layouter, &r_as_base, &y)?;

        let gene = p256_curve.assign_fixed(layouter, P256::generator())?;

        // Verify: msg_hash*G + r*PK - s*K = id.
        let res = p256_curve.msm(
            layouter,
            &[msg_hash, r_as_scalar, neg_s],
            &[gene, pk, k_point],
        )?;

        p256_curve.assert_zero(layouter, &res)
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            p256: true,
            ..ZkStdLibArch::default()
        }
    }

    fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
        Ok(P256EcdsaVerify)
    }
}

fn main() -> Result<()> {
    env_logger::init();

    let seed = [0u8; 32];
    let mut rng: StdRng = SeedableRng::from_seed(seed);

    // Generate a random instance-witness pair.
    let msg_hash = P256Scalar::random(&mut rng);
    let (pk, sk) = P256Ecdsa::keygen(&mut rng);
    let signature = P256Ecdsa::sign(&sk, &msg_hash, &mut rng);

    // Sanity check on the generated signature.
    assert!(P256Ecdsa::verify(&pk, &msg_hash, &signature));

    let instance = (msg_hash, pk);
    let witness = signature;

    let relation = P256EcdsaVerify;
    let circuit = MidnightCircuit::new(
        &relation,
        Value::known(instance),
        Value::known(witness),
        None,
    );
    let k = k_from_circuit(&circuit);
    let params: Params = get_or_create_kzg_params(k, rng.clone())?;
    let vk: VerifyingKey<Scalar, KZG> = keygen_vk(&params, &circuit).context("keygen_vk failed")?;
    let pk_proving: ProvingKey<Scalar, KZG> =
        keygen_pk(vk.clone(), &circuit).context("keygen_pk failed")?;

    let mut transcript = CTranscript::init();
    let formatted_instance = P256EcdsaVerify::format_instance(&instance).unwrap();
    create_proof(
        &params,
        &pk_proving,
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
        &[&[&formatted_instance]],
        &mut transcript_verifier,
    )
    .context("prepare failed")?;
    verifier
        .verify(&params.verifier_params())
        .map_err(|e| anyhow!("{e:?}"))
        .context("verify failed")?;

    let chips = &[SupportedChips::WeierstrassSecp256r1];
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
